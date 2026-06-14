#include "FunctionAnalyzer.h"
#include "BinaryFile.h"
#include "JvmClass.h"
#include "../Disasm/IDisassembler.h"
#include "../Tabs/DataRef.h"   // instrDataRef(): memory-operand address (pure parse, no UI deps)

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ds {

// Imports that never return: a call to one of these ends the caller's
// fall-through, so function discovery stops scanning there (the bytes after are
// typically padding / unrelated code that must not contribute call targets).
// Exact lowercase names — substring matching would catch GetExitCodeProcess.
static bool isNoreturnImportName(const std::string& name) {
    std::string n; n.reserve(name.size());
    for (char c : name) n.push_back((char)std::tolower((unsigned char)c));
    static const char* kExitFamily[] = {
        "exitprocess", "exit", "_exit", "_o_exit", "quick_exit", "abort",
        "terminateprocess", "rtlexituserprocess", "raiseexception",
        "__fastfail", "_invalid_parameter_noinfo_noreturn", "_cexit",
    };
    for (const char* k : kExitFamily) if (n == k) return true;
    return false;
}

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

// Heuristic prologue scan across executable sections, gated on the image's
// actual CPU (the byte patterns are meaningless on ARM/MIPS/...). Raw blobs
// (machine Unknown) fall back on the 32/64-bit class.
void FunctionAnalyzer::prologueScan(const BinaryFile& bin, std::vector<uint64_t>& seeds) {
    const MachineArch m = bin.machine();
    const bool x64 = m == MachineArch::X64 || (m == MachineArch::Unknown && bin.is64Bit());
    const bool x86 = m == MachineArch::X86 || (m == MachineArch::Unknown && !bin.is64Bit());
    if (!x64 && !x86) return;
    for (const auto& s : bin.sections()) {
        if (!s.executable) continue;
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(bin.imageBase() + s.virtualAddress, avail);
        if (!p) continue;
        size_t n = std::min<size_t>(avail, (size_t)s.rawSize);
        for (size_t i = 0; i + 4 <= n; ++i) {   // largest read is p[i+3]; i may reach n-4
            bool hit = false;
            if (x64) {
                // push rbp; mov rbp, rsp           => 55 48 8B EC  (or 48 89 E5)
                // sub rsp, imm8 after push regs    => 48 83 EC xx
                // mov [rsp+x], reg  (MS x64 home)  => 48 89 5C 24 xx / 48 89 4C 24 xx
                hit =
                    (p[i] == 0x55 && p[i+1] == 0x48 && (p[i+2] == 0x8B && p[i+3] == 0xEC)) ||
                    (p[i] == 0x55 && p[i+1] == 0x48 && p[i+2] == 0x89 && p[i+3] == 0xE5) ||
                    (p[i] == 0x48 && p[i+1] == 0x83 && p[i+2] == 0xEC) ||
                    (p[i] == 0x48 && p[i+1] == 0x89 && (p[i+2] == 0x5C || p[i+2] == 0x4C || p[i+2] == 0x54) && p[i+3] == 0x24);
            } else {
                // 32-bit: push ebp; mov ebp, esp   => 55 8B EC  (Intel) / 55 89 E5 (AT&T-encoded gcc)
                hit =
                    (p[i] == 0x55 && p[i+1] == 0x8B && p[i+2] == 0xEC) ||
                    (p[i] == 0x55 && p[i+1] == 0x89 && p[i+2] == 0xE5);
            }
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

    // Java class: the method table is authoritative — exact starts, exact sizes,
    // real names. The x86 heuristics (descent, prologue scan, .pdata) don't apply.
    if (bin.format() == BinFormat::JavaClass && bin.javaClass()) {
        const JvmClassFile& cf = *bin.javaClass();
        const std::string cls = JvmShortClassName(cf.thisClass);
        std::unordered_map<std::string, int> nameCount;
        for (const auto& m : cf.methods) if (m.codeLength) ++nameCount[m.name];
        for (const auto& m : cf.methods) {
            if (!m.codeLength || out.size() >= maxFunctions) continue;
            DiscoveredFunction f;
            f.address = m.codeOffset;
            f.size    = m.codeLength;
            // Overloads share a name: disambiguate with the pretty signature.
            f.name = (nameCount[m.name] > 1) ? cls + "." + JvmPrettyMethod(m.name, m.descriptor)
                                             : cls + "." + m.name;
            f.isExport = true;   // a real (compiler-recorded) name, not a sub_ guess
            out.push_back(std::move(f));
        }
        std::sort(out.begin(), out.end(),
                  [](const DiscoveredFunction& a, const DiscoveredFunction& b) {
                      return a.address < b.address;
                  });
        char sum[160];
        std::snprintf(sum, sizeof(sum), "%zu methods from the class file (%s)",
                      out.size(), cf.thisClass.c_str());
        summary_ = sum;
        return out;
    }

    std::vector<uint64_t> seeds;
    std::vector<std::pair<uint64_t,std::string>> named;

    if (bin.entryPoint()) seeds.push_back(bin.imageBase() + bin.entryPoint());
    collectExports(bin, seeds, named);

    // .pdata seeding (x64 PE): every RUNTIME_FUNCTION begin is an authoritative
    // function start, and its [begin, end) extent beats the gap-to-next-start
    // size guess. Chained-unwind chunks were already folded by pdataRanges().
    std::unordered_map<uint64_t, uint64_t> sizeHint;       // start -> linker-known size
    {
        auto ranges = bin.pdataRanges();
        for (const auto& [b, e] : ranges) {
            seeds.push_back(b);
            uint64_t len = e - b;
            auto it = sizeHint.find(b);
            if (it == sizeHint.end() || it->second < len) sizeHint[b] = len;
        }
    }
    size_t exportSeeds = seeds.size();                     // entry + exports + pdata: high confidence
    prologueScan(bin, seeds);

    std::map<uint64_t,std::string> nameMap;
    for (auto& n : named) nameMap[n.first] = n.second;

    // IAT slot set (import-thunk tail-call detection) and the exit-family subset
    // (never return: a call/jmp to one of these ends the caller's fall-through).
    std::unordered_set<uint64_t> iatSlots, noretIat;
    for (const auto& im : bin.imports()) {
        iatSlots.insert(im.iatVA);
        if (isNoreturnImportName(im.name)) noretIat.insert(im.iatVA);
    }

    // Recursive descent: starting from seeds, follow direct calls to find more
    // function entries. We mark every call target + seed as a function start.
    std::set<uint64_t> starts;
    std::unordered_set<uint64_t> visited;
    std::vector<uint64_t> work = seeds;

    // Record the high-confidence seeds (entry + named exports + .pdata, which are
    // seeds[0..exportSeeds)) up front so the heuristic prologue flood can never
    // crowd them out of `starts` when the maxFunctions cap is reached.
    for (size_t i = 0; i < exportSeeds && starts.size() < maxFunctions; ++i)
        starts.insert(seeds[i]);

    // Noreturn wrapper propagation (one fixed-point iteration, per the seed set):
    // a function whose FIRST instruction tail-jumps or calls an exit-family
    // import is itself noreturn (CRT exit shims). Calls to these propagate the
    // fall-through cut exactly like direct calls to the import.
    std::unordered_set<uint64_t> noretFuncs;
    if (!noretIat.empty()) {
        for (size_t i = 0; i < seeds.size(); ++i) {
            size_t avail = 0;
            const uint8_t* p = bin.ptrFromVA(seeds[i], avail);
            if (!p) continue;
            Instruction in;
            if (!dis.decodeOne(p, std::min<size_t>(avail, 16), seeds[i], in)) continue;
            const bool xfer = in.isCall || (in.isBranch && in.mnemonic == "jmp");
            if (xfer && noretIat.count(instrDataRef(in))) noretFuncs.insert(seeds[i]);
        }
    }
    // A call/jmp that transfers into the exit family (directly via the IAT, or
    // through a recognized wrapper) never comes back.
    auto isNoreturnTransfer = [&](const Instruction& in) -> bool {
        if (in.branchTarget && noretFuncs.count(in.branchTarget)) return true;
        if (!noretIat.empty() && noretIat.count(instrDataRef(in))) return true;
        return false;
    };

    // `starts` membership can't double as the scan dedup: high-confidence seeds
    // were pre-inserted above, and skipping their scan would lose every call
    // target reachable only from them (e.g. the entry point's callees).
    std::unordered_set<uint64_t> scanned;
    while (!work.empty() && starts.size() < maxFunctions) {
        uint64_t fn = work.back(); work.pop_back();
        if (!scanned.insert(fn).second) continue;
        starts.insert(fn);

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
            // A call into the exit family never returns: the bytes after it are
            // padding / a different function, so stop scanning here (their call
            // targets must not pollute discovery).
            if (in.isCall && isNoreturnTransfer(in)) break;
            // Tail-call: an unconditional jmp to a known function start (an
            // export / entry / pdata seed or an already-discovered function) or
            // through an import thunk ends THIS function; the target is its own
            // function (seeded when it isn't already).
            if (!in.isCall && in.isBranch && in.mnemonic == "jmp") {
                const bool toKnownStart = in.branchTarget &&
                    (starts.count(in.branchTarget) || nameMap.count(in.branchTarget) ||
                     sizeHint.count(in.branchTarget));
                const bool toImport = !iatSlots.empty() && iatSlots.count(instrDataRef(in)) != 0;
                if (toKnownStart || toImport || isNoreturnTransfer(in)) {
                    if (in.branchTarget && !visited.count(in.branchTarget)) {
                        visited.insert(in.branchTarget);
                        size_t a2 = 0;
                        if (bin.ptrFromVA(in.branchTarget, a2)) work.push_back(in.branchTarget);
                    }
                    break;   // function ends at the tail-call
                }
            }
            // Stop scanning a function at a return so size estimates stay tight.
            // isRet covers ret/retn/retf (and iret) uniformly across both engines.
            if (in.isRet) break;
        }
    }

    // Build sorted result with size = gap to next start (within reason). A
    // .pdata extent, when present, overrides the gap guess (it is the linker's
    // own answer, and unlike the gap it isn't inflated by alignment padding).
    std::vector<uint64_t> sorted(starts.begin(), starts.end());
    std::sort(sorted.begin(), sorted.end());
    out.reserve(sorted.size());
    for (size_t i = 0; i < sorted.size(); ++i) {
        DiscoveredFunction f;
        f.address = sorted[i];
        uint64_t gap;
        if (i + 1 < sorted.size()) gap = (sorted[i+1] > sorted[i]) ? (sorted[i+1] - sorted[i]) : 0;
        else { size_t avail = 0; bin.ptrFromVA(sorted[i], avail); gap = avail; }  // last fn: remaining mapped bytes
        if (auto h = sizeHint.find(f.address); h != sizeHint.end())
            f.size = (uint32_t)std::min<uint64_t>(h->second, 0x100000);
        else
            f.size = (uint32_t)std::min<uint64_t>(gap, 0x4000);
        auto it = nameMap.find(f.address);
        if (it != nameMap.end()) { f.name = it->second; f.isExport = true; }
        else {
            char b[32]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)f.address);
            f.name = b;
        }
        out.push_back(std::move(f));
    }

    char sum[200];
    std::snprintf(sum, sizeof(sum),
                  "%zu functions (%zu high-confidence seeds incl. %zu pdata, %zu total seeds) via %s",
                  out.size(), exportSeeds, sizeHint.size(), seeds.size(), dis.engineName());
    summary_ = sum;
    return out;
}

} // namespace ds
