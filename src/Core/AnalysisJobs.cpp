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
#include "CFG.h"
#include "Decompiler.h"
#include "../Disasm/IDisassembler.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace ds {

namespace {

// A multi-megabyte padding run is one string, but must not become a multi-megabyte
// ImGui row (or dominate analysis memory). Consume the whole run and retain a prefix.
// 100k results x 512 bytes keeps the retained text payload near 50 MiB (plus
// vector/string overhead) while preserving enough context for filtering/naming.
constexpr size_t kMaxStoredStringBytes = 512;

struct OffsetString {
    size_t      offset        = 0;
    std::string text;
    bool        wide          = false;
    bool        textTruncated = false;
};

size_t onePastCap(size_t cap) {
    return cap == std::numeric_limits<size_t>::max() ? cap : cap + 1;
}

// Byte length of one printable ASCII/UTF-8 code point, or zero for an invalid or
// non-printable unit. This rejects controls, overlong encodings, surrogates, and
// values beyond U+10FFFF instead of treating arbitrary high bytes as text.
size_t printableUtf8Unit(const uint8_t* p, size_t n) {
    if (!p || !n) return 0;
    const uint8_t c0 = p[0];
    if ((c0 >= 0x20 && c0 < 0x7F) || c0 == '\t') return 1;

    uint32_t cp = 0;
    size_t len = 0;
    if (c0 >= 0xC2 && c0 <= 0xDF) {
        len = 2; cp = c0 & 0x1Fu;
    } else if (c0 >= 0xE0 && c0 <= 0xEF) {
        len = 3; cp = c0 & 0x0Fu;
    } else if (c0 >= 0xF0 && c0 <= 0xF4) {
        len = 4; cp = c0 & 0x07u;
    } else {
        return 0;
    }
    if (n < len) return 0;
    for (size_t i = 1; i < len; ++i) {
        if ((p[i] & 0xC0u) != 0x80u) return 0;
        cp = (cp << 6) | (p[i] & 0x3Fu);
    }
    if ((len == 2 && cp < 0x80u) || (len == 3 && cp < 0x800u)
        || (len == 4 && cp < 0x10000u)) return 0;
    if (cp < 0xA0u || cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) return 0;
    return len;
}

template <class Emit>
void scanNarrow(const uint8_t* d, size_t n, size_t acceptedLimit, Emit&& emit,
                std::atomic<uint32_t>* progress = nullptr) {
    if (!d || !n || acceptedLimit == 0) return;
    size_t accepted = 0;
    for (size_t i = 0; i < n;) {
        if (progress && (i & 0xFFFFu) == 0) {
            const size_t u32max = std::numeric_limits<uint32_t>::max();
            progress->store((uint32_t)std::min(i, u32max), std::memory_order_relaxed);
        }
        const size_t start = i;
        size_t chars = 0;
        size_t storeEnd = start;
        while (i < n) {
            const size_t unit = printableUtf8Unit(d + i, n - i);
            if (!unit) break;
            if (i + unit - start <= kMaxStoredStringBytes) storeEnd = i + unit;
            i += unit;
            ++chars;
        }
        if (chars >= 4) {
            OffsetString s;
            s.offset = start;
            s.text.assign(reinterpret_cast<const char*>(d + start), storeEnd - start);
            s.textTruncated = storeEnd < i;
            if (emit(std::move(s)) && ++accepted >= acceptedLimit) return;
        }
        if (i == start) ++i;
    }
}

// Restrict UTF-16LE discovery to printable ASCII code units. Treating every valid
// non-ASCII pair as UTF-16 creates overwhelming false positives in ordinary narrow
// text/binary data (two ASCII bytes form a plausible CJK code point).
template <class Emit>
void scanWideAscii(const uint8_t* d, size_t n, size_t acceptedLimit, Emit&& emit) {
    if (!d || n < 2 || acceptedLimit == 0) return;
    size_t accepted = 0;
    for (size_t i = 0; i + 1 < n;) {
        const size_t start = i;
        size_t j = i;
        size_t chars = 0;
        std::string text;
        text.reserve(64);
        while (j + 1 < n && d[j + 1] == 0
               && ((d[j] >= 0x20 && d[j] < 0x7F) || d[j] == '\t')) {
            if (text.size() < kMaxStoredStringBytes) text.push_back((char)d[j]);
            j += 2;
            ++chars;
        }
        if (chars >= 4) {
            OffsetString s;
            s.offset = start;
            s.text = std::move(text);
            s.wide = true;
            s.textTruncated = chars > kMaxStoredStringBytes;
            if (emit(std::move(s)) && ++accepted >= acceptedLimit) return;
            i = j;
        } else {
            ++i;
        }
    }
}

template <class T, class Address>
void sortDedupAndCap(std::vector<T>& values, size_t cap, bool& wasTruncated,
                     Address&& address) {
    std::sort(values.begin(), values.end(), [&](const T& a, const T& b) {
        const auto aa = address(a), bb = address(b);
        if (aa != bb) return aa < bb;
        return a.wide < b.wide; // deterministic: prefer narrow at an identical start
    });
    values.erase(std::unique(values.begin(), values.end(), [&](const T& a, const T& b) {
        return address(a) == address(b);
    }), values.end());
    if (values.size() > cap) {
        values.resize(cap);
        wasTruncated = true;
    }
}

} // namespace

std::vector<StrResult> ScanStringsImage(const BinaryFile& bin, size_t cap,
                                        std::atomic<uint32_t>* progress,
                                        bool* truncated) {
    std::vector<StrResult> out;
    if (truncated) *truncated = false;
    if (!bin.loaded()) return out;
    const std::vector<uint8_t>& d = bin.bytes();
    const uint8_t* data = d.data();
    const size_t n = d.size();
    const size_t perKindLimit = onePastCap(cap);

    // Scan each encoding to cap+1 independently, then merge by address. This keeps
    // a narrow-string-heavy image from starving every UTF-16 result at the old cap.
    std::vector<StrResult> narrow, wide;
    narrow.reserve(std::min<size_t>(cap, 4096));
    wide.reserve(std::min<size_t>(cap, 1024));
    auto mappedEmit = [&](std::vector<StrResult>& dst, OffsetString&& s) {
        uint64_t va = 0;
        if (!bin.offsetToVA(s.offset, va)) return false; // overlays do not consume the cap
        dst.push_back({ va, std::move(s.text), s.wide, s.textTruncated });
        return true;
    };
    scanNarrow(data, n, perKindLimit,
               [&](OffsetString&& s) { return mappedEmit(narrow, std::move(s)); }, progress);
    scanWideAscii(data, n, perKindLimit,
                  [&](OffsetString&& s) { return mappedEmit(wide, std::move(s)); });
    if (progress) {
        const size_t u32max = std::numeric_limits<uint32_t>::max();
        progress->store((uint32_t)std::min(n, u32max), std::memory_order_relaxed);
    }

    bool wasTruncated = narrow.size() > cap || wide.size() > cap;
    out.reserve(narrow.size() + wide.size());
    std::move(narrow.begin(), narrow.end(), std::back_inserter(out));
    std::move(wide.begin(), wide.end(), std::back_inserter(out));
    sortDedupAndCap(out, cap, wasTruncated, [](const StrResult& s) { return s.address; });
    if (truncated) *truncated = wasTruncated;
    return out;
}

void ScanStringsBuffer(const uint8_t* d, size_t n, uint64_t base,
                       std::vector<StrResult>& out, size_t cap,
                       bool* truncated) {
    if (truncated) *truncated = false;
    if (!d || !n) return;
    if (out.size() > cap) {
        out.resize(cap);
        if (truncated) *truncated = true;
        return;
    }
    const size_t room = cap - out.size();
    const size_t perKindLimit = onePastCap(room);
    std::vector<OffsetString> found;
    found.reserve(std::min<size_t>(room, 4096));
    // ASCII/UTF-8 printable runs (tab counts), then UTF-16LE runs — mirrors the file
    // scanner and the original BinaryViewTab::scanStrings live path (va = base + off).
    scanNarrow(d, n, perKindLimit, [&](OffsetString&& s) {
        found.push_back(std::move(s)); return true;
    });
    scanWideAscii(d, n, perKindLimit, [&](OffsetString&& s) {
        found.push_back(std::move(s)); return true;
    });

    bool wasTruncated = false;
    sortDedupAndCap(found, room, wasTruncated, [](const OffsetString& s) { return s.offset; });
    out.reserve(out.size() + found.size());
    for (auto& s : found)
        out.push_back({ base + s.offset, std::move(s.text), s.wide, s.textTruncated });
    if (truncated) *truncated = wasTruncated;
}

AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames) {
    AnalyzeOut out;
    if (!bin.loaded()) return out;

    FunctionAnalyzer fa;
    std::vector<DiscoveredFunction> found = fa.analyze(bin, dis);
    out.functions.reserve(found.size());
    for (auto& f : found)
        out.functions.push_back({ f.address, f.size, f.name, false, std::string(), f.isExport });
    out.summary = fa.lastSummary();

    if (!guessNames || out.functions.empty()) return out;

    // Imports: an IAT-slot / import-target VA -> "dll.func". Restricted to the import
    // map so the guesser never recurses into the sub_ names we're replacing.
    std::unordered_map<uint64_t, std::string> importMap;
    for (const auto& im : bin.imports()) importMap[im.iatVA] = im.dll + "." + im.name;

    std::vector<NamerInput> in;
    in.reserve(out.functions.size());
    for (auto& f : out.functions) in.push_back({ f.address, f.size, f.isExport, f.name });

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
            // The instruction budget applies only to executable rows. Keep walking
            // later sections so data-string rows remain navigable even after a very
            // large code section exhausts the 800k instruction cap.
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

DecompResult DecompileRegion(const BinaryFile& bin, IDisassembler& dis,
                             bool x86, uint64_t lo, uint64_t hi,
                             const DecompileNameMap* names,
                             std::string_view signature) {
    if (!bin.loaded() || hi <= lo) return {};
    size_t avail = 0;
    const uint8_t* p = bin.ptrFromVA(lo, avail);
    if (!p) return {};
    // `hi` is already the caller's exclusive bound. The old path added another
    // 16-byte look-ahead (after the caller had added one too), and uint32 overflow
    // could turn a huge interval into a tiny/wrapped decode. Decode only the safe
    // intersection of [lo,hi), mapped bytes, and the per-function budget.
    const uint64_t requested = hi - lo; // hi > lo above, so subtraction is safe
    const size_t win = (size_t)std::min<uint64_t>(
        requested, std::min<uint64_t>((uint64_t)avail, 16384ull));
    if (!win) return {};

    // Base import resolution: IAT slot VA -> "dll.name" (no UI rename map here).
    std::unordered_map<uint64_t, std::string> imports;
    for (const auto& im : bin.imports()) imports[im.iatVA] = im.dll + "." + im.name;

    // Read a short, escaped, quoted C-string literal at `va`, or "" if not printable.
    auto stringAt = [&bin](uint64_t va) -> std::string {
        size_t av = 0;
        const uint8_t* d = bin.ptrFromVA(va, av);
        if (!d) return std::string();
        size_t n = std::min<size_t>(av, 128);
        std::string s;
        for (size_t i = 0; i < n; ++i) {
            unsigned char c = d[i];
            if (c == 0) break;
            if (!((c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r')) return std::string();
            s.push_back((char)c);
        }
        if (s.size() < 3) return std::string();
        std::string q = "\"";
        for (char c : s) {
            if (q.size() > 48) { q += "..."; break; }
            if (c == '"' || c == '\\') q += '\\';
            if (c == '\n') { q += "\\n"; continue; }
            if (c == '\t') { q += "\\t"; continue; }
            if (c == '\r') { q += "\\r"; continue; }
            q += c;
        }
        q += "\"";
        return q;
    };

    ControlFlowGraph g = BuildCFG(p, win, lo, dis, 2000);
    DecompileOptions opt;
    opt.nameFor    = [&imports, names](uint64_t a) -> std::string {
        if (names) {
            auto named = names->find(a);
            if (named != names->end() && !named->second.empty()) return named->second;
        }
        auto it = imports.find(a);
        return it != imports.end() ? it->second : std::string();
    };
    opt.dataRefFor = [&imports, &stringAt, names](uint64_t a) -> std::string {
        if (!a) return std::string();
        if (names) {
            auto named = names->find(a);
            if (named != names->end() && !named->second.empty()) return named->second;
        }
        auto it = imports.find(a);
        if (it != imports.end()) return it->second;
        return stringAt(a);
    };
    opt.x86 = x86;   // gate the arg-header to x86/x64 (avoid spurious args on other arches)
    if (!signature.empty()) opt.signature.assign(signature.data(), signature.size());
    return DecompileWithMap(g, opt);
}

} // namespace ds
