#include "FunctionAnalyzer.h"
#include "BinaryFile.h"
#include "../Disasm/IDisassembler.h"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace ds {

template <typename T>
static T rdle(const uint8_t* p) { T v{}; std::memcpy(&v, p, sizeof(T)); return v; }

// Parse the PE export directory: seed function starts and record names.
void FunctionAnalyzer::collectExports(const BinaryFile& bin,
                                      std::vector<uint64_t>& seeds,
                                      std::vector<std::pair<uint64_t,std::string>>& named) {
    uint32_t edRVA = bin.exportDirRVA();
    if (!edRVA) return;
    // An EAT RVA that points back inside the export directory is a forwarder
    // (an ASCII "DLL.func" string), not code - never seed/name it as a function.
    const uint64_t edEnd = (uint64_t)edRVA + bin.exportDirSize();   // 64-bit: edRVA+size can wrap uint32_t
    auto isForwarder = [&](uint32_t fr) { return fr >= edRVA && fr < edEnd; };
    size_t avail = 0;
    const uint8_t* ed = bin.ptrFromRVA(edRVA, avail);
    if (!ed || avail < 40) return;

    uint32_t numFuncs   = rdle<uint32_t>(ed + 20);
    uint32_t numNames   = rdle<uint32_t>(ed + 24);
    uint32_t funcsRVA   = rdle<uint32_t>(ed + 28);
    uint32_t namesRVA   = rdle<uint32_t>(ed + 32);
    uint32_t ordsRVA    = rdle<uint32_t>(ed + 36);

    size_t a1 = 0, a2 = 0, a3 = 0;
    const uint8_t* funcs = bin.ptrFromRVA(funcsRVA, a1);
    const uint8_t* names = bin.ptrFromRVA(namesRVA, a2);
    const uint8_t* ords  = bin.ptrFromRVA(ordsRVA,  a3);
    if (!funcs) return;

    // EAT entries -> seed addresses.
    for (uint32_t i = 0; i < numFuncs && (size_t)(i + 1) * 4 <= a1; ++i) {
        uint32_t fr = rdle<uint32_t>(funcs + i * 4);
        if (fr && !isForwarder(fr)) seeds.push_back(bin.imageBase() + fr);
    }

    // Name table -> map ordinal->name->address.
    if (names && ords) {
        for (uint32_t i = 0; i < numNames && (size_t)(i + 1) * 4 <= a2; ++i) {
            uint32_t nameRVA = rdle<uint32_t>(names + i * 4);
            uint16_t ord = ((size_t)i * 2 + 2 <= a3) ? rdle<uint16_t>(ords + i * 2) : 0;
            size_t na = 0;
            const uint8_t* np = bin.ptrFromRVA(nameRVA, na);
            if (!np) continue;
            std::string nm((const char*)np, strnlen((const char*)np, std::min<size_t>(na, 256)));
            if (ord < numFuncs && (size_t)(ord + 1) * 4 <= a1) {
                uint32_t fr = rdle<uint32_t>(funcs + ord * 4);
                if (fr && !isForwarder(fr)) named.emplace_back(bin.imageBase() + fr, nm);
            }
        }
    }
}

// Heuristic prologue scan across executable sections.
void FunctionAnalyzer::prologueScan(const BinaryFile& bin, std::vector<uint64_t>& seeds) {
    for (const auto& s : bin.sections()) {
        if (!s.executable) continue;
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(bin.imageBase() + s.virtualAddress, avail);
        if (!p) continue;
        size_t n = std::min<size_t>(avail, (size_t)s.rawSize);
        for (size_t i = 0; i + 4 <= n; ++i) {   // largest read is p[i+3]; i may reach n-4
            // push rbp; mov rbp, rsp           => 55 48 8B EC  (or 48 89 E5)
            // sub rsp, imm8 after push regs    => 48 83 EC xx
            // mov [rsp+x], reg  (MS x64 home)  => 48 89 5C 24 xx / 48 89 4C 24 xx
            bool hit =
                (p[i] == 0x55 && p[i+1] == 0x48 && (p[i+2] == 0x8B && p[i+3] == 0xEC)) ||
                (p[i] == 0x55 && p[i+1] == 0x48 && p[i+2] == 0x89 && p[i+3] == 0xE5) ||
                (p[i] == 0x48 && p[i+1] == 0x83 && p[i+2] == 0xEC) ||
                (p[i] == 0x48 && p[i+1] == 0x89 && (p[i+2] == 0x5C || p[i+2] == 0x4C || p[i+2] == 0x54) && p[i+3] == 0x24);
            if (hit) seeds.push_back(bin.imageBase() + s.virtualAddress + i);
        }
    }
}

std::vector<DiscoveredFunction>
FunctionAnalyzer::analyze(const BinaryFile& bin, IDisassembler& dis,
                          size_t maxFunctions, size_t maxInstrPerFunc) {
    summary_.clear();
    std::vector<DiscoveredFunction> out;
    if (!bin.loaded()) { summary_ = "no binary loaded"; return out; }

    std::vector<uint64_t> seeds;
    std::vector<std::pair<uint64_t,std::string>> named;

    if (bin.entryPoint()) seeds.push_back(bin.imageBase() + bin.entryPoint());
    collectExports(bin, seeds, named);
    size_t exportSeeds = seeds.size();
    prologueScan(bin, seeds);

    std::unordered_map<uint64_t,std::string> nameMap;
    for (auto& n : named) nameMap[n.first] = n.second;

    // Recursive descent: starting from seeds, follow direct calls to find more
    // function entries. We mark every call target + seed as a function start.
    // unordered_set: membership/cap logic is order-independent and the result is
    // sorted into `sorted` below, so hashing is a straight win over a red-black tree.
    std::unordered_set<uint64_t> starts;
    std::unordered_set<uint64_t> visited;
    std::vector<uint64_t> work = seeds;

    // Record the high-confidence seeds (entry + named exports, which are
    // seeds[0..exportSeeds)) up front so the heuristic prologue flood can never
    // crowd them out of `starts` when the maxFunctions cap is reached.
    for (size_t i = 0; i < exportSeeds && starts.size() < maxFunctions; ++i)
        starts.insert(seeds[i]);

    while (!work.empty() && starts.size() < maxFunctions) {
        uint64_t fn = work.back(); work.pop_back();
        if (!starts.insert(fn).second) continue;

        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(fn, avail);
        if (!p) continue;
        size_t window = std::min<size_t>(avail, 8192);

        auto insns = dis.disassemble(p, window, fn, maxInstrPerFunc);
        for (auto& in : insns) {
            if (in.isCall && in.branchTarget) {
                if (!visited.count(in.branchTarget)) {
                    visited.insert(in.branchTarget);
                    // Only follow targets that map into the image.
                    size_t a2 = 0;
                    if (bin.ptrFromVA(in.branchTarget, a2)) work.push_back(in.branchTarget);
                }
            }
            // Stop scanning a function at a return so size estimates stay tight.
            // isRet covers ret/retn/retf (and iret) uniformly across both engines.
            if (in.isRet) break;
        }
    }

    // Build sorted result with size = gap to next start (within reason).
    std::vector<uint64_t> sorted(starts.begin(), starts.end());
    std::sort(sorted.begin(), sorted.end());
    out.reserve(sorted.size());
    for (size_t i = 0; i < sorted.size(); ++i) {
        DiscoveredFunction f;
        f.address = sorted[i];
        uint64_t gap;
        if (i + 1 < sorted.size()) gap = (sorted[i+1] > sorted[i]) ? (sorted[i+1] - sorted[i]) : 0;
        else { size_t avail = 0; bin.ptrFromVA(sorted[i], avail); gap = avail; }  // last fn: remaining mapped bytes
        f.size = (uint32_t)std::min<uint64_t>(gap, 0x4000);
        auto it = nameMap.find(f.address);
        if (it != nameMap.end()) { f.name = it->second; f.isExport = true; }
        else {
            char b[32]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)f.address);
            f.name = b;
        }
        out.push_back(std::move(f));
    }

    char sum[160];
    std::snprintf(sum, sizeof(sum),
                  "%zu functions (%zu export seeds, %zu total seeds) via %s",
                  out.size(), exportSeeds, seeds.size(), dis.engineName());
    summary_ = sum;
    return out;
}

} // namespace ds
