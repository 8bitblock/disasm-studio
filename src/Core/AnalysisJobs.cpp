//
// AnalysisJobs.cpp — see AnalysisJobs.h. Ported (kept faithful) from the
// corresponding synchronous BinaryViewTab passes so they can run off the UI thread.
//
#include "AnalysisJobs.h"

#include "BinaryFile.h"
#include "FunctionAnalyzer.h"
#include "FunctionNamer.h"
#include "AlgoScan.h"
#include "XrefIndex.h"
#include "../Disasm/IDisassembler.h"

#include <algorithm>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>

namespace ds {

std::vector<StrResult> ScanStringsImage(const BinaryFile& bin, size_t cap,
                                        std::atomic<uint32_t>* progress) {
    std::vector<StrResult> out;
    if (!bin.loaded()) return out;
    const std::vector<uint8_t>& d = bin.bytes();
    const uint8_t* data = d.data();
    const size_t   n    = d.size();
    auto toVA = [&](size_t off, uint64_t& va) { return bin.offsetToVA(off, va); };

    // Pull ASCII/UTF-8 runs then UTF-16LE runs out of the buffer, mirroring
    // BinaryViewTab::scanStrings' file path exactly (>= 4 chars, tab counts).
    auto scan = [&]() {
        std::string cur; size_t start = 0;
        for (size_t i = 0; i < n; ++i) {
            // Publish scan progress every 64 KB (cheap relaxed store; cosmetic only).
            if (progress && (i & 0xFFFFu) == 0) progress->store((uint32_t)i, std::memory_order_relaxed);
            unsigned char c = data[i];
            bool printable = (c >= 0x20 && c < 0x7f) || c == '\t';
            if (printable) { if (cur.empty()) start = i; cur.push_back((char)c); }
            else { uint64_t va; if (cur.size() >= 4 && toVA(start, va)) out.push_back({ va, cur, false }); cur.clear(); }
            if (out.size() >= cap) return;
        }
        if (cur.size() >= 4) { uint64_t va; if (toVA(start, va)) out.push_back({ va, cur, false }); }
        for (size_t i = 0; i + 1 < n && out.size() < cap;) {
            size_t j = i; std::string s; size_t start2 = i;
            while (j + 1 < n && (data[j] == '\t' || (data[j] >= 0x20 && data[j] < 0x7f)) && data[j + 1] == 0) { s.push_back((char)data[j]); j += 2; }
            if (s.size() >= 4) { uint64_t va; if (toVA(start2, va)) out.push_back({ va, s, true }); i = j; }
            else ++i;
        }
    };
    scan();

    std::sort(out.begin(), out.end(),
              [](const StrResult& a, const StrResult& b) { return a.address < b.address; });
    // De-duplicate by address (mirrors BinaryViewTab::scanStrings) so overlapping
    // ASCII/UTF-16 runs at one offset don't list the same string twice.
    out.erase(std::unique(out.begin(), out.end(),
              [](const StrResult& a, const StrResult& b) { return a.address == b.address; }),
              out.end());
    return out;
}

void ScanStringsBuffer(const uint8_t* d, size_t n, uint64_t base,
                       std::vector<StrResult>& out, size_t cap) {
    if (!d || !n) return;
    // ASCII/UTF-8 printable runs (tab counts), then UTF-16LE runs — mirrors the file
    // scanner and the original BinaryViewTab::scanStrings live path (va = base + off).
    {
        std::string cur; size_t start = 0;
        for (size_t i = 0; i < n; ++i) {
            unsigned char c = d[i];
            bool printable = (c >= 0x20 && c < 0x7f) || c == '\t';
            if (printable) { if (cur.empty()) start = i; cur.push_back((char)c); }
            else { if (cur.size() >= 4) out.push_back({ base + start, cur, false }); cur.clear(); }
            if (out.size() >= cap) return;
        }
        if (cur.size() >= 4) out.push_back({ base + start, cur, false });
    }
    for (size_t i = 0; i + 1 < n && out.size() < cap;) {
        size_t j = i; std::string s; size_t start2 = i;
        while (j + 1 < n && (d[j] == '\t' || (d[j] >= 0x20 && d[j] < 0x7f)) && d[j + 1] == 0) { s.push_back((char)d[j]); j += 2; }
        if (s.size() >= 4) { out.push_back({ base + start2, s, true }); i = j; }
        else ++i;
    }
}

AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames) {
    AnalyzeOut out;
    if (!bin.loaded()) return out;

    FunctionAnalyzer fa;
    std::vector<DiscoveredFunction> found = fa.analyze(bin, dis);
    out.functions.reserve(found.size());
    for (auto& f : found) out.functions.push_back({ f.address, f.size, f.name, false, std::string() });
    out.summary = fa.lastSummary();

    if (!guessNames || out.functions.empty()) return out;

    // Imports: an IAT-slot / import-target VA -> "dll.func". Restricted to the import
    // map so the guesser never recurses into the sub_ names we're replacing.
    std::unordered_map<uint64_t, std::string> importMap;
    for (const auto& im : bin.imports()) importMap[im.iatVA] = im.dll + "." + im.name;

    std::vector<NamerInput> in;
    in.reserve(out.functions.size());
    for (auto& f : out.functions) in.push_back({ f.address, f.size, false, f.name });

    auto importNameFor = [&importMap](uint64_t va) -> std::string {
        auto it = importMap.find(va);
        return it != importMap.end() ? it->second : std::string();
    };
    auto stringRefFor = [&strings](uint64_t va) -> std::string {
        if (strings.empty()) return std::string();
        auto it = std::lower_bound(strings.begin(), strings.end(), va,
                                   [](const StrResult& s, uint64_t a) { return s.address < a; });
        return (it != strings.end() && it->address == va) ? it->text : std::string();
    };

    uint64_t entryVA = bin.entryPoint() ? bin.imageBase() + bin.entryPoint() : 0;
    FunctionNamer namer;
    std::vector<GuessedName> guesses = namer.name(bin, dis, in, entryVA, importNameFor, stringRefFor);

    int guessed = 0;
    for (size_t i = 0; i < out.functions.size() && i < guesses.size(); ++i) {
        if (!guesses[i].guessed) continue;
        out.functions[i].name    = guesses[i].name;
        out.functions[i].guessed = true;
        out.functions[i].reason  = guesses[i].reason;
        ++guessed;
    }
    if (guessed) {
        char extra[48]; std::snprintf(extra, sizeof(extra), "  (+%d named by heuristics)", guessed);
        out.summary += extra;
    }
    return out;
}

std::vector<ListRowR> BuildListingRows(const BinaryFile& bin, IDisassembler& dis,
                                       const std::vector<uint64_t>& funcStarts,
                                       const std::vector<StrResult>& strings,
                                       int cap, const std::function<bool()>& cancelled,
                                       std::atomic<uint32_t>* progress) {
    std::vector<ListRowR> rows;
    if (!bin.loaded()) return rows;

    std::unordered_set<uint64_t> starts(funcStarts.begin(), funcStarts.end());

    // Strings sorted by address (ScanStringsImage already returns them sorted, but
    // sort an index view defensively so the per-data-section pull is ascending).
    std::vector<int> strOrder(strings.size());
    for (int i = 0; i < (int)strings.size(); ++i) strOrder[i] = i;
    std::sort(strOrder.begin(), strOrder.end(),
              [&](int a, int b) { return strings[a].address < strings[b].address; });

    // Walk sections in VA order so the row vector stays sorted by address (the UI
    // navigation scroll binary-searches it).
    std::vector<const Section*> secs;
    for (const auto& s : bin.sections()) secs.push_back(&s);
    std::sort(secs.begin(), secs.end(),
              [](const Section* a, const Section* b) { return a->virtualAddress < b->virtualAddress; });

    int count = 0;
    unsigned tick = 0;
    for (const Section* sp : secs) {
        const Section& s = *sp;
        uint64_t va = bin.imageBase() + s.virtualAddress;
        if (s.executable) {
            size_t avail = 0;
            const uint8_t* p = bin.ptrFromVA(va, avail);
            if (!p) continue;
            size_t limit = s.rawSize ? std::min<size_t>(avail, (size_t)s.rawSize) : avail;
            size_t off = 0;
            while (off < limit && count < cap) {
                if (cancelled && ((++tick & 0x3FFFu) == 0)) {
                    if (cancelled()) return rows;
                    if (progress) progress->store((uint32_t)count, std::memory_order_relaxed);
                }
                uint64_t a = va + off;
                if (starts.count(a)) rows.push_back({ a, true });   // function divider
                Instruction in;
                bool ok = dis.decodeOne(p + off, limit - off, a, in) && in.length;
                rows.push_back({ a, false });
                ++count;
                off += ok ? in.length : 1;
            }
            if (count >= cap) break;
        } else {
            // Data section: one row per known string literal inside its VA span.
            uint64_t span   = std::max<uint64_t>(s.virtualSize, s.rawSize);
            uint64_t secEnd = va + span;
            for (int oi : strOrder) {
                uint64_t sa = strings[(size_t)oi].address;
                if (sa < va || sa >= secEnd) continue;
                ListRowR r; r.addr = sa; r.strData = true; r.strIdx = oi;
                rows.push_back(r);
            }
        }
    }
    return rows;
}

std::vector<CallEdgeR> BuildCallEdges(const BinaryFile& bin, IDisassembler& dis,
                                      const std::vector<FuncResult>& functions) {
    std::vector<CallEdgeR> edges;
    if (!bin.loaded()) return edges;
    std::unordered_set<uint64_t> fset;
    for (const auto& f : functions) fset.insert(f.address);
    for (const auto& f : functions) {
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(f.address, avail);
        if (!p) continue;
        size_t win = f.size ? std::min<size_t>(avail, f.size) : std::min<size_t>(avail, 4096);
        std::unordered_set<uint64_t> seen;   // de-dup callees per caller
        size_t off = 0; int guard = 0;
        while (off < win && guard++ < 50000) {
            Instruction in;
            if (!dis.decodeOne(p + off, win - off, f.address + off, in) || !in.length) { ++off; continue; }
            if (in.isCall && in.branchTarget && fset.count(in.branchTarget) && seen.insert(in.branchTarget).second)
                edges.push_back({ f.address, in.branchTarget });
            off += in.length;
        }
    }
    return edges;
}

std::vector<AlgoMatch> ScanAlgorithmsJob(const BinaryFile& bin, const XrefIndex* xref,
                                         const std::vector<FuncResult>& functions) {
    return ScanAlgorithms(bin, xref, functions.empty() ? nullptr : &functions);
}

} // namespace ds
