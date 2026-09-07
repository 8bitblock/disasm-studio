//
// AnalysisJobs.cpp — see AnalysisJobs.h. Ported (kept faithful) from the
// corresponding synchronous BinaryViewTab passes so they can run off the UI thread.
//
#include "AnalysisJobs.h"

#include "AddressSpan.h"
#include "BinaryFile.h"
#include "Project.h"
#include "FunctionAnalyzer.h"
#include "FunctionNamer.h"
#include "AlgoScan.h"
#include "XrefIndex.h"
#include "CFG.h"
#include "Decompiler.h"
#include "Demangle.h"
#include "JumpTableResolver.h"
#include "../Disasm/IDisassembler.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iterator>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace ds {

static bool analysisMappedSpan(const BinaryFile& bin, uint64_t address, uint64_t size) {
    if (!size || address > UINT64_MAX - size) return false;
    size_t available = 0;
    return bin.ptrFromVA(address, available) && size <= static_cast<uint64_t>(available);
}

uint64_t DigestCodeDataScope(const CodeDataMap* map) {
    uint64_t digest = 1469598103934665603ull;
    auto value = [&](uint64_t number) {
        for (unsigned shift = 0; shift < 64; shift += 8) {
            digest ^= static_cast<uint8_t>(number >> shift);
            digest *= 1099511628211ull;
        }
    };
    value(1); // scope schema
    value(map ? 1 : 0);
    if (map) {
        value(map->truncated ? 1 : 0);
        value(map->spans.size());
        for (const CodeDataSpan& span : map->spans) {
            value(span.address); value(span.size); value(static_cast<uint8_t>(span.kind));
        }
    }
    return digest;
}

static CodeDataKind projectDataKind(PjDataKind kind) {
    switch (kind) {
        case PjDataKind::Code: return CodeDataKind::Code;
        case PjDataKind::String: return CodeDataKind::String;
        case PjDataKind::PointerTable: return CodeDataKind::PointerTable;
        case PjDataKind::JumpTable: return CodeDataKind::JumpTable;
        case PjDataKind::Data: return CodeDataKind::Data;
    }
    return CodeDataKind::Data;
}

static uint8_t overrideElementWidth(const BinaryFile& bin, const PjDataOverride& span) {
    if (span.kind == PjDataKind::PointerTable) return bin.is64Bit() ? 8 : 4;
    if (span.kind == PjDataKind::JumpTable) return 4;
    const std::string& type = span.type;
    if (type.find("64") != std::string::npos || type == "double") return 8;
    if (type.find("32") != std::string::npos || type == "float") return 4;
    if (type.find("16") != std::string::npos) return 2;
    return 1;
}

static void addOverrideStats(CodeDataStats& stats, const CodeDataSpan& span) {
    stats.executableBytes += span.size;
    switch (span.kind) {
        case CodeDataKind::Code: stats.codeBytes += span.size; break;
        case CodeDataKind::Unknown: stats.unknownBytes += span.size; break;
        case CodeDataKind::String:
            stats.dataBytes += span.size; stats.stringBytes += span.size; break;
        case CodeDataKind::LiteralPool:
            stats.dataBytes += span.size; stats.literalBytes += span.size; break;
        case CodeDataKind::JumpTable:
            stats.dataBytes += span.size; stats.jumpTableBytes += span.size; break;
        case CodeDataKind::PointerTable:
            stats.dataBytes += span.size; stats.pointerTableBytes += span.size; break;
        case CodeDataKind::Padding:
            stats.dataBytes += span.size; stats.paddingBytes += span.size; break;
        case CodeDataKind::Data: stats.dataBytes += span.size; break;
    }
}

std::shared_ptr<const CodeDataMap>
ApplyCodeDataOverrides(const BinaryFile& bin, const std::vector<PjDataOverride>& overrides,
                   std::shared_ptr<const CodeDataMap> input) {
    if (!input || (input->imageRevision && input->imageRevision != bin.imageRevision())) return {};
    if (overrides.empty() && input->scopeDigest) return input;
    auto map = std::make_shared<CodeDataMap>(*input);
    for (const PjDataOverride& decision : overrides) {
        if (!analysisMappedSpan(bin, decision.address, decision.size)) continue;
        const uint64_t decisionEnd = decision.address + decision.size;
        std::vector<CodeDataSpan> next;
        next.reserve(map->spans.size() + 2);
        for (const CodeDataSpan& old : map->spans) {
            if (!old.size || old.address > UINT64_MAX - old.size) continue;
            const uint64_t oldEnd = old.address + old.size;
            if (oldEnd <= decision.address || old.address >= decisionEnd) {
                next.push_back(old);
                continue;
            }
            const uint64_t lo = std::max(old.address, decision.address);
            const uint64_t hi = std::min(oldEnd, decisionEnd);
            if (old.address < lo) {
                CodeDataSpan prefix = old;
                prefix.size = lo - old.address;
                next.push_back(std::move(prefix));
            }
            CodeDataSpan analyst;
            analyst.address = lo;
            analyst.size = hi - lo;
            analyst.kind = projectDataKind(decision.kind);
            analyst.elementWidth = overrideElementWidth(bin, decision);
            analyst.confidence = CodeDataConfidence::High;
            analyst.evidence = "authoritative analyst override";
            if (!decision.type.empty()) analyst.evidence += ": " + decision.type;
            next.push_back(std::move(analyst));
            if (hi < oldEnd) {
                CodeDataSpan suffix = old;
                suffix.address = hi;
                suffix.size = oldEnd - hi;
                next.push_back(std::move(suffix));
            }
        }
        map->spans = std::move(next);
    }

    std::vector<CodeDataSpan> merged;
    merged.reserve(map->spans.size());
    for (CodeDataSpan& span : map->spans) {
        if (!merged.empty()) {
            CodeDataSpan& before = merged.back();
            const bool adjacent = before.address <= UINT64_MAX - before.size &&
                                  before.address + before.size == span.address;
            if (adjacent && before.kind == span.kind &&
                before.elementWidth == span.elementWidth &&
                before.confidence == span.confidence && before.evidence == span.evidence) {
                before.size += span.size;
                continue;
            }
        }
        merged.push_back(std::move(span));
    }
    map->spans = std::move(merged);
    const uint64_t decoded = map->stats.decodedInstructions;
    const uint64_t blocks = map->stats.visitedBlocks;
    map->stats = {};
    map->stats.decodedInstructions = decoded;
    map->stats.visitedBlocks = blocks;
    for (const CodeDataSpan& span : map->spans) addOverrideStats(map->stats, span);
    map->scopeDigest = DigestCodeDataScope(map.get());
    return map;
}

namespace {

// A multi-megabyte padding run is one string, but must not become a multi-megabyte
// ImGui row (or dominate analysis memory). Consume the whole run and retain a prefix.
// 100k results x 512 bytes keeps the retained text payload near 50 MiB (plus
// vector/string overhead) while preserving enough context for filtering/naming.
constexpr size_t kMaxStoredStringBytes = 512;
constexpr size_t kStringScanPollBytes = 64 * 1024;

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

bool pollStringScan(size_t offset, size_t& nextPoll,
                    std::atomic<uint32_t>* progress,
                    const std::function<bool()>& cancelled) {
    if ((!progress && !cancelled) || offset < nextPoll) return false;
    if (progress) {
        const size_t u32max = std::numeric_limits<uint32_t>::max();
        progress->store((uint32_t)std::min(offset, u32max),
                        std::memory_order_relaxed);
    }
    nextPoll = offset > std::numeric_limits<size_t>::max() - kStringScanPollBytes
        ? std::numeric_limits<size_t>::max()
        : offset + kStringScanPollBytes;
    return cancelled && cancelled();
}

template <class Emit>
bool scanNarrow(const uint8_t* d, size_t n, size_t acceptedLimit, Emit&& emit,
                std::atomic<uint32_t>* progress = nullptr,
                const std::function<bool()>& cancelled = {}) {
    if (!d || !n || acceptedLimit == 0) return true;
    size_t accepted = 0;
    size_t nextPoll = (progress || cancelled) ? 0 : std::numeric_limits<size_t>::max();
    for (size_t i = 0; i < n;) {
        if (i >= nextPoll && pollStringScan(i, nextPoll, progress, cancelled)) return false;
        const size_t start = i;
        size_t chars = 0;
        size_t storeEnd = start;
        while (i < n) {
            if (i >= nextPoll && pollStringScan(i, nextPoll, progress, cancelled)) return false;
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
            if (emit(std::move(s)) && ++accepted >= acceptedLimit) return true;
        }
        if (i == start) ++i;
    }
    return true;
}

// Restrict UTF-16LE discovery to printable ASCII code units. Treating every valid
// non-ASCII pair as UTF-16 creates overwhelming false positives in ordinary narrow
// text/binary data (two ASCII bytes form a plausible CJK code point).
template <class Emit>
bool scanWideAscii(const uint8_t* d, size_t n, size_t acceptedLimit, Emit&& emit,
                   const std::function<bool()>& cancelled = {}) {
    if (!d || n < 2 || acceptedLimit == 0) return true;
    size_t accepted = 0;
    size_t nextPoll = cancelled ? 0 : std::numeric_limits<size_t>::max();
    for (size_t i = 0; i + 1 < n;) {
        if (i >= nextPoll && pollStringScan(i, nextPoll, nullptr, cancelled)) return false;
        const size_t start = i;
        size_t j = i;
        size_t chars = 0;
        std::string text;
        text.reserve(64);
        while (j + 1 < n && d[j + 1] == 0
               && ((d[j] >= 0x20 && d[j] < 0x7F) || d[j] == '\t')) {
            if (j >= nextPoll && pollStringScan(j, nextPoll, nullptr, cancelled)) return false;
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
            if (emit(std::move(s)) && ++accepted >= acceptedLimit) return true;
            i = j;
        } else {
            ++i;
        }
    }
    return true;
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
                                        bool* truncated,
                                        const std::function<bool()>& cancelled) {
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
    if (!scanNarrow(data, n, perKindLimit,
                    [&](OffsetString&& s) { return mappedEmit(narrow, std::move(s)); },
                    progress, cancelled))
        return out;
    if (!scanWideAscii(data, n, perKindLimit,
                       [&](OffsetString&& s) { return mappedEmit(wide, std::move(s)); },
                       cancelled))
        return out;
    if (cancelled && cancelled()) return out;
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
    for (auto& s : found) {
        uint64_t address = 0;
        if (!CheckedAddressAdd(base, static_cast<uint64_t>(s.offset), address)) {
            // A live region may legally end at UINT64_MAX. Never wrap an
            // unrepresentable hit to address zero and accidentally grant it
            // authoritative navigation or xref meaning.
            wasTruncated = true;
            continue;
        }
        out.push_back({ address, std::move(s.text), s.wide, s.textTruncated });
    }
    if (truncated) *truncated = wasTruncated;
}

static void ApplyGuessedNames(AnalyzeOut& out, const BinaryFile& bin,
                              IDisassembler& dis,
                              const std::vector<StrResult>& strings,
                              const std::function<bool()>& cancelled = {}) {
    // Imports: an IAT-slot / import-target VA -> "dll.func". Restricted to the import
    // map so the guesser never recurses into the sub_ names we're replacing.
    std::unordered_map<uint64_t, std::string> importMap;
    for (const auto& im : bin.imports())
        if (im.addressKnown) importMap[im.iatVA] = im.dll + "." + DemangleForLabel(im.name);

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

    const bool rawStart = bin.format() == BinFormat::Raw;
    const bool headerEntry = bin.hasEntryPoint();
    const uint64_t startVA = headerEntry ? bin.entryPointVA()
                                         : (rawStart ? bin.imageBase() : 0);
    FunctionNamer namer;
    std::vector<GuessedName> guesses = namer.name(
        bin, dis, in, startVA, rawStart || headerEntry, rawStart,
        importNameFor, stringRefFor, cancelled);

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
}

static AnalyzeOut MaterializeFunctions(std::vector<DiscoveredFunction> found,
                                        std::string summary) {
    AnalyzeOut out;
    out.functions.reserve(found.size());
    for (auto& f : found) {
        FuncResult materialized;
        materialized.address = f.address;
        materialized.size = f.size;
        materialized.name = std::move(f.name);
        materialized.isExport = f.isExport;
        materialized.chunks = std::move(f.chunks);
        materialized.ownershipTruncated = f.ownershipTruncated;
        materialized.seedKind = f.seedKind;
        materialized.boundaryConfidence = f.boundaryConfidence;
        // Recursive descent can prove a function noreturn without an analyst
        // override (for example, a wrapper whose only terminal path reaches a
        // known exit import). Preserve that evidence for later CFG/decompiler
        // jobs; an explicit project override may still replace it downstream.
        materialized.noreturnValid = f.noreturn;
        materialized.noreturn = f.noreturn;
        out.functions.push_back(std::move(materialized));
    }
    out.summary = std::move(summary);
    return out;
}

static bool TryInferClassifierArch(const BinaryFile& bin, Arch& arch) {
    switch (bin.machine()) {
        case MachineArch::X86:     arch = Arch::X86; return true;
        case MachineArch::X64:     arch = Arch::X64; return true;
        case MachineArch::ARM:     arch = Arch::ARM; return true;
        case MachineArch::THUMB:   arch = Arch::THUMB; return true;
        case MachineArch::ARM64:   arch = Arch::ARM64; return true;
        case MachineArch::MIPS:    arch = Arch::MIPS; return true;
        case MachineArch::MIPS64:  arch = Arch::MIPS64; return true;
        case MachineArch::PPC:     arch = Arch::PPC; return true;
        case MachineArch::PPC64:   arch = Arch::PPC64; return true;
        case MachineArch::RISCV:   arch = Arch::RISCV32; return true;
        case MachineArch::RISCV64: arch = Arch::RISCV64; return true;
        case MachineArch::JVM:     arch = Arch::JVM; return true;
        case MachineArch::GML:     arch = Arch::GML; return true;
        case MachineArch::Unknown: return false;
    }
    return false;
}

static std::vector<CodeDataFunctionInput>
ClassifierFunctions(const std::vector<DiscoveredFunction>& functions) {
    std::vector<CodeDataFunctionInput> out;
    size_t count = 0;
    for (const auto& function : functions)
        count += function.chunks.empty() ? 1 : function.chunks.size();
    out.reserve(count);
    for (const auto& function : functions) {
        if (function.chunks.empty()) {
            out.push_back({function.address, function.size});
            continue;
        }
        for (const FunctionChunk& chunk : function.chunks)
            if (chunk.size) out.push_back({chunk.address, chunk.size});
    }
    return out;
}

static std::vector<CodeDataStringInput>
ClassifierStrings(const BinaryFile& bin, const std::vector<StrResult>& strings) {
    std::vector<CodeDataStringInput> out;
    out.reserve(strings.size());
    for (const StrResult& string : strings) {
        const uint64_t unit = string.wide ? 2 : 1;
        if (string.text.size() > UINT64_MAX / unit) continue;
        uint64_t bytes = static_cast<uint64_t>(string.text.size()) * unit;
        if (!bytes) continue;
        // Retain the terminator only when the scanner stored the whole run and the
        // exact mapped bytes confirm it. A 512-byte truncated display prefix must
        // never manufacture a false end for a multi-megabyte printable run.
        if (!string.textTruncated && bytes <= UINT64_MAX - string.address) {
            size_t available = 0;
            const uint8_t* terminator = bin.ptrFromVA(string.address + bytes, available);
            if (terminator && available >= unit && terminator[0] == 0 &&
                (!string.wide || terminator[1] == 0))
                bytes += unit;
        }
        out.push_back({string.address, bytes, string.wide});
    }
    return out;
}

static void ClassifyAndRecoverFunctions(const BinaryFile& bin, IDisassembler& dis,
                                        const DecoderConfig& decoder,
                                        const std::vector<StrResult>& strings,
                                        const std::function<bool()>& cancelled,
                                        FunctionAnalyzer& analyzer,
                                        std::vector<DiscoveredFunction>& found,
                                        CodeDataMap& codeData,
                                        const JumpTableResolver& resolveTable,
                                        const std::vector<uint64_t>& initialSupplemental = {},
                                        const std::vector<uint64_t>& analystSeeds = {},
                                        const FunctionNoreturnDecisionResolver& noreturnDecision = {}) {
    const std::vector<CodeDataStringInput> classifierStrings = ClassifierStrings(bin, strings);
    std::vector<uint64_t> supplemental = initialSupplemental;
    std::unordered_set<uint64_t> supplied;
    supplied.insert(initialSupplemental.begin(), initialSupplemental.end());

    // One feedback rerun is sufficient: pointer/vtable and endbr seeds do not
    // depend on newly reached code. The final classification is rebuilt from the
    // expanded function set so its code spans and data references are current.
    for (int round = 0; round < 2; ++round) {
        codeData = ClassifyCodeData(bin, dis, decoder, ClassifierFunctions(found),
                                    classifierStrings, cancelled);
        if (cancelled && cancelled()) return;
        std::unordered_set<uint64_t> existing;
        existing.reserve(found.size() * 2 + 1);
        for (const auto& function : found) existing.insert(function.address);
        std::vector<uint64_t> newlyRecovered;
        for (const CodeDataFunctionSeed& seed : codeData.functionSeeds)
            if (!existing.count(seed.address) && supplied.insert(seed.address).second)
                newlyRecovered.push_back(seed.address);
        if (newlyRecovered.empty() || round == 1) break;
        supplemental.insert(supplemental.end(), newlyRecovered.begin(), newlyRecovered.end());
        found = analyzer.analyze(bin, dis, decoder.arch, 50000, 4000, cancelled,
                                 supplemental, analystSeeds, resolveTable,
                                 noreturnDecision);
        if (cancelled && cancelled()) return;
    }
}

AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames) {
    if (!bin.loaded()) return {};
    Arch inferredArch{};
    if (!TryInferClassifierArch(bin, inferredArch)) {
        AnalyzeOut refused;
        refused.summary = "analysis refused: Raw/Unknown image requires an explicit architecture";
        return refused;
    }
    DecoderConfig decoder;
    decoder.engine = dis.engine();
    decoder.arch = inferredArch;
    decoder = DecoderConfigForImage(bin, decoder);
    auto resolveTable = [&bin, &dis, &decoder](const Instruction& instruction) {
        JumpTableResolution table = ResolveJumpTable(
            bin, dis, decoder.arch, decoder.byteOrder, instruction);
        ResolvedJumpTable resolved;
        if (table.valid) resolved.targets = std::move(table.targets);
        resolved.truncated = table.truncated;
        resolved.evidence = std::move(table.evidence);
        return resolved;
    };
    FunctionAnalyzer fa;
    std::vector<DiscoveredFunction> found = fa.analyze(
        bin, dis, decoder.arch, 50000, 4000, {}, {}, {}, resolveTable);
    CodeDataMap codeData;
    ClassifyAndRecoverFunctions(bin, dis, decoder, strings, {},
                                fa, found, codeData, resolveTable);
    AnalyzeOut out = MaterializeFunctions(std::move(found), fa.lastSummary());
    codeData.scopeDigest = DigestCodeDataScope(&codeData);
    out.codeData = std::move(codeData);
    out.codeDataValid = true;
    if (!out.summary.empty()) out.summary += "; ";
    out.summary += CodeDataSummary(out.codeData);
    if (guessNames && !out.functions.empty()) ApplyGuessedNames(out, bin, dis, strings);
    return out;
}

AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames,
                                 const DecoderConfig& requestedDecoder,
                                 const std::function<bool()>& cancelled,
                                 const std::vector<uint64_t>& analystSeeds,
                                 const FunctionNoreturnDecisionResolver& noreturnDecision) {
    if (!bin.loaded()) return {};
    const DecoderConfig decoder = DecoderConfigForImage(bin, requestedDecoder);
    auto resolveTable = [&bin, &dis, &decoder](const Instruction& instruction) {
        JumpTableResolution table = ResolveJumpTable(
            bin, dis, decoder.arch, decoder.byteOrder, instruction);
        ResolvedJumpTable resolved;
        if (table.valid) resolved.targets = std::move(table.targets);
        resolved.truncated = table.truncated;
        resolved.evidence = std::move(table.evidence);
        return resolved;
    };
    FunctionAnalyzer fa;
    std::vector<DiscoveredFunction> found = fa.analyze(bin, dis, decoder.arch, 50000, 4000,
                                                       cancelled, {}, analystSeeds,
                                                       resolveTable, noreturnDecision);
    CodeDataMap codeData;
    if (!(cancelled && cancelled()))
        ClassifyAndRecoverFunctions(bin, dis, decoder, strings, cancelled, fa, found,
                                    codeData, resolveTable, {}, analystSeeds,
                                    noreturnDecision);
    AnalyzeOut out = MaterializeFunctions(std::move(found), fa.lastSummary());
    codeData.scopeDigest = DigestCodeDataScope(&codeData);
    out.codeData = std::move(codeData);
    out.codeDataValid = !(cancelled && cancelled());
    if (out.codeDataValid) {
        if (!out.summary.empty()) out.summary += "; ";
        out.summary += CodeDataSummary(out.codeData);
    }
    if (guessNames && !out.functions.empty() && !(cancelled && cancelled()))
        ApplyGuessedNames(out, bin, dis, strings, cancelled);
    return out;
}

AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames,
                                 Arch arch, const std::function<bool()>& cancelled,
                                 const std::vector<uint64_t>& analystSeeds,
                                 const FunctionNoreturnDecisionResolver& noreturnDecision) {
    DecoderConfig decoder;
    decoder.engine = dis.engine();
    decoder.arch = arch;
    return AnalyzeFunctionsNamed(bin, dis, strings, guessNames, decoder, cancelled,
                                 analystSeeds, noreturnDecision);
}

ListingLayout MakeDefaultListingLayout(const BinaryFile& bin) {
    ListingLayout out;
    out.sections.reserve(bin.sections().size());
    for (const Section& s : bin.sections())
        out.sections.push_back({ s.virtualAddress, s.name, s.executable, !s.executable });
    return out;
}

void ReconcileListingLayout(const BinaryFile& bin, ListingLayout& layout) {
    std::vector<ListingSectionState> reconciled;
    reconciled.reserve(bin.sections().size());
    for (const Section& s : bin.sections()) {
        auto it = std::find_if(layout.sections.begin(), layout.sections.end(),
            [&](const ListingSectionState& old) {
                return old.rva == s.virtualAddress && old.name == s.name;
            });
        if (it != layout.sections.end()) reconciled.push_back(*it);
        else reconciled.push_back({ s.virtualAddress, s.name, s.executable, !s.executable });
    }
    layout.sections = std::move(reconciled); // also drops stale sidecar entries
}

static uint64_t ListingAddressRoom(uint64_t address) {
    // Number of representable bytes beginning at address. The mathematical value
    // at VA 0 is 2^64, which cannot fit in uint64_t; UINT64_MAX is the largest
    // describable region and is sufficient for every size_t-backed image here.
    return address == 0 ? UINT64_MAX : UINT64_MAX - address + 1;
}

std::vector<ListingRegionPlan> PlanListingRegions(const BinaryFile& bin,
                                                   const ListingLayout* requested) {
    std::vector<ListingRegionPlan> out;
    if (!bin.loaded()) return out;
    ListingLayout layout = requested ? *requested : MakeDefaultListingLayout(bin);
    ReconcileListingLayout(bin, layout);

    const bool pe = bin.format() == BinFormat::PE32 || bin.format() == BinFormat::PE32Plus;
    if (pe && layout.peHeaderVisible) {
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(bin.imageBase(), avail);
        if (p && avail) {
            const uint64_t mapped = std::min<uint64_t>(avail, ListingAddressRoom(bin.imageBase()));
            out.push_back({ kListingPeHeaderIndex, true, false, layout.peHeaderFolded,
                            "PE Header", bin.imageBase(), mapped, mapped });
        }
    }

    for (uint32_t i = 0; i < (uint32_t)bin.sections().size(); ++i) {
        const Section& s = bin.sections()[i];
        const ListingSectionState& state = layout.sections[i];
        if (!state.visible || s.virtualAddress > std::numeric_limits<uint64_t>::max() - bin.imageBase())
            continue;
        const uint64_t va = bin.imageBase() + s.virtualAddress;
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(va, avail);
        const uint64_t room = ListingAddressRoom(va);
        const uint64_t mapped = p ? std::min<uint64_t>(
            std::min<uint64_t>(avail, s.rawSize ? s.rawSize : avail), room) : 0;
        out.push_back({ i, false, s.executable, state.folded, s.name, va, mapped,
                        std::min<uint64_t>(std::max<uint64_t>(s.virtualSize, s.rawSize), room) });
    }
    std::stable_sort(out.begin(), out.end(), [](const ListingRegionPlan& a, const ListingRegionPlan& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.peHeader && !b.peHeader;
    });
    return out;
}

XrefRangePlan PlanXrefRanges(const BinaryFile& bin, const CodeDataMap* classification,
                              const std::function<bool()>& cancelled) {
    XrefRangePlan plan;
    const CodeDataMap* map = classification;
    if (map && map->imageRevision && map->imageRevision != bin.imageRevision()) map = nullptr;
    // Hostile/synthetic maps cannot silently omit bytes. A malformed partition
    // falls back to unknown coverage; gaps in a valid partial map stay decodable.
    if (map) {
        size_t checkedSpans = 0;
        uint64_t previousLast = 0; bool first = true;
        for (const CodeDataSpan& span : map->spans) {
            if (cancelled && ((++checkedSpans & 0xffu) == 0) && cancelled()) {
                plan.cancelled = true; return plan;
            }
            if (!span.size || span.size - 1 > UINT64_MAX - span.address ||
                (!first && span.address <= previousLast) ||
                static_cast<unsigned>(span.kind) > static_cast<unsigned>(CodeDataKind::Data)) {
                map = nullptr; break;
            }
            previousLast = span.address + span.size - 1; first = false;
        }
    }
    plan.classificationApplied = map != nullptr;
    plan.classificationTruncated = map && map->truncated;
    plan.scopeDigest = DigestCodeDataScope(map);
    auto addCount = [](uint64_t& total, uint64_t size) {
        total = size > UINT64_MAX - total ? UINT64_MAX : total + size;
    };
    size_t ticks = 0;
    for (uint32_t sectionIndex = 0; sectionIndex < bin.sections().size(); ++sectionIndex) {
        if (cancelled && cancelled()) { plan.cancelled = true; return plan; }
        const Section& section = bin.sections()[sectionIndex];
        if (!section.executable || section.virtualAddress > UINT64_MAX - bin.imageBase()) continue;
        const uint64_t base = bin.imageBase() + section.virtualAddress;
        size_t available = 0;
        if (!bin.ptrFromVA(base, available)) continue;
        const uint64_t mapped = ClampAddressableBytes(base, static_cast<size_t>(
            std::min<uint64_t>(available, section.rawSize ? section.rawSize : available)));
        uint64_t offset = 0;
        while (offset < mapped) {
            if (cancelled && ((++ticks & 0xffu) == 0) && cancelled()) {
                plan.cancelled = true; return plan;
            }
            const uint64_t address = base + offset;
            uint64_t count = mapped - offset;
            bool data = false;
            if (map) {
                if (const CodeDataSpan* span = map->find(address)) {
                    count = std::min(count, span->size - (address - span->address));
                    data = CodeDataKindIsData(span->kind);
                } else {
                    auto next = std::lower_bound(map->spans.begin(), map->spans.end(), address,
                        [](const CodeDataSpan& span, uint64_t va) { return span.address < va; });
                    if (next != map->spans.end()) count = std::min(count, next->address - address);
                }
            }
            if (!count) break;
            if (data) addCount(plan.classifiedDataBytes, count);
            else {
                addCount(plan.decodeBytes, count);
                if (!plan.ranges.empty() && plan.ranges.back().sectionIndex == sectionIndex &&
                    plan.ranges.back().size <= UINT64_MAX - plan.ranges.back().address &&
                    plan.ranges.back().address + plan.ranges.back().size == address)
                    plan.ranges.back().size += count;
                else plan.ranges.push_back({address, count, sectionIndex});
            }
            offset += count;
        }
    }
    return plan;
}

std::vector<ListRowR> BuildListingRows(const BinaryFile& bin,
                                       const std::vector<StrResult>& strings,
                                       const std::function<bool()>& cancelled,
                                       std::atomic<uint32_t>* progress,
                                       const ListingLayout* layout,
                                       size_t maxDataBytes,
                                       const CodeDataMap* codeData) {
    std::vector<ListRowR> rows;
    if (!bin.loaded()) return rows;

    // Strings sorted by address (ScanStringsImage already returns them sorted, but
    // sort an index view defensively so the per-data-section pull is ascending).
    std::vector<int> strOrder(strings.size());
    for (int i = 0; i < (int)strings.size(); ++i) strOrder[i] = i;
    std::sort(strOrder.begin(), strOrder.end(),
              [&](int a, int b) { return strings[a].address < strings[b].address; });

    unsigned tick = 0;
    uint64_t mappedProgress = 0;
    size_t dataBudget = maxDataBytes;
    uint32_t nextCodeRegion = 1;
    // A production map is tied to the exact immutable image it inspected.
    // Accept revision zero only for explicit synthetic/test maps.
    const CodeDataMap* currentCodeData = codeData &&
        (!codeData->imageRevision || codeData->imageRevision == bin.imageRevision())
        ? codeData : nullptr;
    const std::vector<ListingRegionPlan> regions = PlanListingRegions(bin, layout);
    for (const ListingRegionPlan& region : regions) {
        ListRowR header;
        header.addr = region.address;
        header.type = ListingRowType::RegionHeader;
        header.sectionIndex = region.sectionIndex;
        header.folded = region.folded;
        header.aux = region.mappedSize;
        rows.push_back(header);
        if (region.folded) continue;

        const uint64_t va = region.address;
        size_t regionDataBudget = static_cast<size_t>(std::min<uint64_t>(
            region.mappedSize, kListingDataBytesPerRegion));

        auto appendStrings = [&](std::vector<ListRowR>& content,
                                 uint64_t begin, uint64_t size) {
            if (region.peHeader || !size) return;
            auto first = std::lower_bound(strOrder.begin(), strOrder.end(), begin,
                [&](int oi, uint64_t address) {
                    return strings[(size_t)oi].address < address;
                });
            for (auto it = first; it != strOrder.end(); ++it) {
                if (cancelled && ((++tick & 0x03FFu) == 0) && cancelled()) return;
                const int oi = *it;
                const uint64_t address = strings[(size_t)oi].address;
                if (address < begin || address - begin >= size) break;
                ListRowR row; row.addr = address; row.strData = true; row.strIdx = oi;
                row.sectionIndex = region.sectionIndex;
                row.dataKind = CodeDataKind::String;
                content.push_back(std::move(row));
            }
        };

        auto appendData = [&](std::vector<ListRowR>& content,
                              uint64_t begin, uint64_t size, CodeDataKind kind,
                              uint8_t requestedWidth, bool includeStrings) {
            if (!size) return;
            const uint64_t allowed64 = std::min<uint64_t>(
                size, std::min<uint64_t>(regionDataBudget, dataBudget));
            const size_t shown = static_cast<size_t>(allowed64);
            regionDataBudget -= shown;
            dataBudget -= shown;
            size_t off = 0;
            while (off < shown) {
                if (cancelled && ((++tick & 0x0FFFu) == 0) && cancelled()) return;
                if (static_cast<uint64_t>(off) > UINT64_MAX - begin) break;
                uint8_t width = requestedWidth == 2 || requestedWidth == 4 || requestedWidth == 8
                              ? requestedWidth : 1;
                const size_t remaining = shown - off;
                size_t chunk = std::min<size_t>(16, remaining);
                if (width > 1) {
                    chunk -= chunk % width;
                    if (!chunk) { width = 1; chunk = std::min<size_t>(16, remaining); }
                }
                ListRowR row;
                row.addr = begin + off;
                row.type = ListingRowType::DataDirective;
                row.sectionIndex = region.sectionIndex;
                row.dataSize = static_cast<uint16_t>(chunk);
                row.dataKind = kind;
                row.dataWidth = width;
                content.push_back(std::move(row));
                off += chunk;
            }
            if (shown < size) {
                ListRowR row;
                if (static_cast<uint64_t>(shown) <= UINT64_MAX - begin) {
                    row.addr = begin + static_cast<uint64_t>(shown);
                    row.type = ListingRowType::DataTruncated;
                    row.sectionIndex = region.sectionIndex;
                    row.aux = size - shown;
                    row.dataKind = kind;
                    row.dataWidth = requestedWidth;
                    content.push_back(std::move(row));
                }
            }
            if (includeStrings) appendStrings(content, begin, size);
        };

        if (region.executable) {
            std::vector<ListRowR> content;
            uint64_t off = 0;
            bool previousWasCode = false;
            uint32_t codeRegion = 0;
            while (off < region.mappedSize) {
                if (cancelled && ((++tick & 0x00FFu) == 0) && cancelled()) return rows;
                if (off > UINT64_MAX - va) break;
                const uint64_t address = va + off;
                CodeDataKind kind = CodeDataKind::Unknown;
                uint8_t width = 1;
                uint64_t spanBytes = region.mappedSize - off;
                if (currentCodeData) {
                    if (const CodeDataSpan* span = currentCodeData->find(address)) {
                        kind = span->kind;
                        width = span->elementWidth;
                        const uint64_t inside = address - span->address;
                        spanBytes = std::min<uint64_t>(spanBytes, span->size - inside);
                    } else {
                        auto next = std::lower_bound(currentCodeData->spans.begin(), currentCodeData->spans.end(), address,
                            [](const CodeDataSpan& span, uint64_t value) {
                                return span.address < value;
                            });
                        if (next != currentCodeData->spans.end() && next->address > address)
                            spanBytes = std::min<uint64_t>(spanBytes, next->address - address);
                    }
                }
                if (!spanBytes) break;
                const bool codeLike = kind == CodeDataKind::Code || kind == CodeDataKind::Unknown;
                if (codeLike) {
                    if (!previousWasCode) {
                        codeRegion = nextCodeRegion++;
                        if (!codeRegion) codeRegion = nextCodeRegion++;
                    }
                    for (uint64_t local = 0; local < spanBytes;) {
                        if (cancelled && ((++tick & 0x00FFu) == 0) && cancelled()) return rows;
                        ListRowR page;
                        page.addr = address + local;
                        page.type = ListingRowType::CodePage;
                        page.sectionIndex = region.sectionIndex;
                        page.aux = std::min<uint64_t>(kListingCodePageBytes, spanBytes - local);
                        page.codeRegion = codeRegion;
                        content.push_back(page);
                        if (!page.aux || local > UINT64_MAX - page.aux) break;
                        local += page.aux;
                    }
                } else {
                    appendData(content, address, spanBytes, kind, width,
                               kind == CodeDataKind::String);
                }
                previousWasCode = codeLike;
                mappedProgress = spanBytes > UINT64_MAX - mappedProgress
                               ? UINT64_MAX : mappedProgress + spanBytes;
                if (progress) progress->store(static_cast<uint32_t>(std::min<uint64_t>(
                    mappedProgress, std::numeric_limits<uint32_t>::max())),
                    std::memory_order_relaxed);
                if (off > UINT64_MAX - spanBytes) break;
                off += spanBytes;
            }
            std::stable_sort(content.begin(), content.end(), [](const ListRowR& a, const ListRowR& b) {
                if (a.addr != b.addr) return a.addr < b.addr;
                if (a.strData != b.strData) return a.strData;
                return static_cast<uint8_t>(a.type) < static_cast<uint8_t>(b.type);
            });
            rows.insert(rows.end(), content.begin(), content.end());
        } else {
            std::vector<ListRowR> content;
            appendData(content, va, region.mappedSize, CodeDataKind::Data, 1,
                       !region.peHeader);
            std::stable_sort(content.begin(), content.end(), [](const ListRowR& a, const ListRowR& b) {
                if (a.addr != b.addr) return a.addr < b.addr;
                if (a.strData != b.strData) return a.strData; // exact string row before same-address db
                return (uint8_t)a.type < (uint8_t)b.type;
            });
            rows.insert(rows.end(), content.begin(), content.end());
        }
    }
    return rows;
}

std::vector<ListRowR> NormalizeListingCodePagesAtRoots(
    const std::vector<ListRowR>& rows,
    const std::vector<uint64_t>& authoritativeRoots) {
    std::vector<uint64_t> roots = authoritativeRoots;
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());

    std::vector<ListRowR> normalized;
    normalized.reserve(rows.size());
    uint32_t nextCodeRegion = 1;
    auto allocateCodeRegion = [&]() {
        const uint32_t allocated = nextCodeRegion;
        ++nextCodeRegion;
        // Reaching this wrap would require more independently represented runs
        // than a vector-backed listing can practically contain. Keep zero
        // reserved even for a hostile synthetic caller.
        if (!nextCodeRegion) nextCodeRegion = 1;
        return allocated ? allocated : nextCodeRegion++;
    };

    for (size_t first = 0; first < rows.size();) {
        if (rows[first].type != ListingRowType::CodePage) {
            normalized.push_back(rows[first++]);
            continue;
        }

        // A production CodePage is always non-empty. Preserve a synthetic empty
        // descriptor rather than silently deleting caller state, but isolate it
        // from every real byte run.
        if (!rows[first].aux) {
            ListRowR empty = rows[first++];
            empty.codeRegion = allocateCodeRegion();
            normalized.push_back(std::move(empty));
            continue;
        }

        const uint64_t runAddress = rows[first].addr;
        uint64_t runBytes = rows[first].aux;
        size_t last = first + 1;
        while (last < rows.size() && rows[last].type == ListingRowType::CodePage &&
               rows[last].codeRegion == rows[first].codeRegion &&
               rows[last].sectionIndex == rows[first].sectionIndex && rows[last].aux) {
            uint64_t expectedAddress = 0;
            if (!CheckedAddressAdd(rows[last - 1].addr, rows[last - 1].aux,
                                   expectedAddress) ||
                rows[last].addr != expectedAddress ||
                runBytes > UINT64_MAX - rows[last].aux)
                break;
            runBytes += rows[last].aux;
            ++last;
        }

        // Offsets avoid an exclusive-end overflow for a valid one-byte page at
        // UINT64_MAX. A root is in the run exactly when subtraction is safe and
        // its offset is below the accumulated byte count.
        std::vector<uint64_t> boundaries{0};
        auto root = std::lower_bound(roots.begin(), roots.end(), runAddress);
        for (; root != roots.end() && *root >= runAddress; ++root) {
            const uint64_t offset = *root - runAddress;
            if (offset >= runBytes) break;
            if (offset && boundaries.back() != offset) boundaries.push_back(offset);
        }

        for (size_t boundary = 0; boundary < boundaries.size(); ++boundary) {
            const uint64_t beginOffset = boundaries[boundary];
            const uint64_t endOffset = boundary + 1 < boundaries.size()
                                     ? boundaries[boundary + 1] : runBytes;
            const uint32_t codeRegion = allocateCodeRegion();
            for (uint64_t offset = beginOffset; offset < endOffset;) {
                const uint64_t remaining = endOffset - offset;
                const uint64_t pageBytes = std::min<uint64_t>(
                    kListingCodePageBytes, remaining);
                ListRowR page = rows[first];
                page.addr = runAddress + offset;
                page.aux = pageBytes;
                page.codeRegion = codeRegion;
                normalized.push_back(std::move(page));
                offset += pageBytes;
            }
        }
        first = last;
    }
    return normalized;
}

size_t LongestReadableLookback(size_t requested,
                               const std::function<bool(size_t)>& readable) {
    if (!requested || !readable) return 0;
    if (readable(requested)) return requested;

    size_t good = 0;
    size_t bad = requested;
    while (good + 1 < bad) {
        const size_t candidate = good + (bad - good) / 2;
        if (readable(candidate)) good = candidate;
        else                     bad = candidate;
    }
    if (!good || !readable(good)) return 0;
    return good;
}

bool ListingDecodeReaches(const uint8_t* bytes, size_t available,
                          uint64_t from, uint64_t target,
                          IDisassembler& dis, size_t maxSteps) {
    if (!bytes || from > target) return false;
    uint64_t address = from;
    size_t offset = 0;
    size_t steps = 0;
    while (address < target && offset < available && steps++ < maxSteps) {
        Instruction instruction;
        const size_t remaining = available - offset;
        const bool decoded = dis.decodeOne(bytes + offset, remaining, address,
                                           instruction) &&
                             instruction.length && instruction.length <= remaining;
        const size_t step = decoded
                          ? static_cast<size_t>(instruction.length)
                          : std::min<size_t>(remaining,
                                std::max<uint32_t>(1, dis.invalidDecodeWidth()));
        if (!step || step > target - address) return false;
        address += static_cast<uint64_t>(step);
        offset += step;
    }
    return address == target;
}

DecodedListingPage DecodeListingCodePage(const uint8_t* bytes, size_t available,
                                         uint64_t address, size_t pageBytes,
                                         uint32_t prefixSkip, size_t lookaheadBytes,
                                         IDisassembler& dis) {
    DecodedListingPage out;
    if (!bytes || !available || !pageBytes) return out;
    const uint64_t room64 = ListingAddressRoom(address);
    const size_t addressRoom = room64 > (uint64_t)std::numeric_limits<size_t>::max()
                             ? std::numeric_limits<size_t>::max() : (size_t)room64;
    const size_t logical = std::min(std::min(available, pageBytes), addressRoom);
    const size_t extended = logical > std::numeric_limits<size_t>::max() - lookaheadBytes
                          ? available : logical + lookaheadBytes;
    const size_t decodeLimit = std::min(std::min(available, extended), addressRoom);
    size_t off = std::min<size_t>(logical, prefixSkip);
    out.instructions.reserve(logical / 2 + 1);
    while (off < logical) {
        if ((uint64_t)off > UINT64_MAX - address) break;
        Instruction in;
        if (!(dis.decodeOne(bytes + off, decodeLimit - off, address + off, in)
              && in.length && in.length <= decodeLimit - off)) {
            in = Instruction{};
            in.address = address + off;
            const size_t step = std::min<size_t>(decodeLimit - off,
                                                 std::max<uint32_t>(1, dis.invalidDecodeWidth()));
            in.length = static_cast<uint32_t>(step);
            char hb[8], ob[8];
            for (size_t k = 0; k < step; ++k) {
                if (k) { in.bytes += ' '; in.operands += ", "; }
                std::snprintf(hb, sizeof(hb), "%02X", bytes[off + k]); in.bytes += hb;
                std::snprintf(ob, sizeof(ob), "0x%02X", bytes[off + k]); in.operands += ob;
            }
            in.mnemonic = "db";
        }
        out.instructions.push_back(std::move(in));
        off += out.instructions.back().length;
    }
    if (off > logical)
        out.nextPrefixSkip = (uint32_t)std::min<size_t>(off - logical, UINT32_MAX);
    else if (prefixSkip > logical)
        out.nextPrefixSkip = prefixSkip - (uint32_t)logical;
    return out;
}

bool ListingInstructionsHaveStart(const std::vector<Instruction>& instructions, uint64_t address) {
    const auto it = std::lower_bound(instructions.begin(), instructions.end(), address,
        [](const Instruction& in, uint64_t value) { return in.address < value; });
    return it != instructions.end() && it->address == address;
}

bool ListingArchNeedsPagePrefix(Arch arch) {
    return ArchIsX86(arch) || arch == Arch::JVM || arch == Arch::GML || arch == Arch::THUMB ||
           arch == Arch::RISCV32 || arch == Arch::RISCV64;
}

size_t ListingArchMaxInstructionBytes(Arch arch) {
    if (arch == Arch::JVM) return 65536;
    if (arch == Arch::GML) return 12;
    if (arch == Arch::THUMB || arch == Arch::RISCV32 || arch == Arch::RISCV64) return 4;
    return ArchIsX86(arch) ? 15 : ListingArchInstructionAlignment(arch);
}

size_t ListingArchInstructionAlignment(Arch arch) {
    if (arch == Arch::THUMB || arch == Arch::RISCV32 || arch == Arch::RISCV64) return 2;
    if (arch == Arch::ARM || arch == Arch::ARM64 || arch == Arch::MIPS ||
        arch == Arch::MIPS64 || arch == Arch::PPC || arch == Arch::PPC64 || arch == Arch::GML)
        return 4;
    return 1;
}

ListingPrefixEstimate EstimateListingPagePrefix(
    const uint8_t* bytes, size_t available, uint64_t windowAddress,
    uint64_t pageAddress, size_t maxInstructionBytes, IDisassembler& dis,
    size_t candidateAlignment) {
    ListingPrefixEstimate out;
    if (!bytes || !available || pageAddress <= windowAddress || !maxInstructionBytes)
        return out;
    maxInstructionBytes = std::min<size_t>(maxInstructionBytes, 15);
    candidateAlignment = std::max<size_t>(1, std::min(candidateAlignment, maxInstructionBytes));

    const uint64_t back64 = pageAddress - windowAddress;
    size_t maxBack = std::min<size_t>(
        maxInstructionBytes, back64 > (uint64_t)std::numeric_limits<size_t>::max()
                           ? std::numeric_limits<size_t>::max() : (size_t)back64);
    maxBack -= maxBack % candidateAlignment;
    if (!maxBack || back64 > available) return out;

    const size_t pageOffset = (size_t)back64;
    const size_t bounded = std::min(available,
        pageOffset > std::numeric_limits<size_t>::max() - maxInstructionBytes
            ? available : pageOffset + maxInstructionBytes);
    const size_t after = bounded > pageOffset ? bounded - pageOffset : 0;
    out.bytesExamined = (uint32_t)std::min<size_t>(maxBack + after, UINT32_MAX);

    // At most 15 candidates and 1+...+15 decode calls for x86. Votes favor the
    // locally most common continuation count; accumulated look-behind breaks ties
    // in favor of paths supported by more bytes, then the smaller skip wins.
    std::vector<uint32_t> votes(maxInstructionBytes + 1, 0);
    std::vector<uint32_t> evidence(maxInstructionBytes + 1, 0);
    const size_t first = pageOffset - maxBack;
    for (size_t candidate = first; candidate < pageOffset; candidate += candidateAlignment) {
        size_t off = candidate;
        bool valid = true;
        while (off < pageOffset) {
            Instruction in;
            ++out.decodeCalls;
            if (!dis.decodeOne(bytes + off, bounded - off, windowAddress + off, in) ||
                !in.length || in.length > bounded - off) {
                valid = false;
                break;
            }
            off += in.length;
        }
        if (!valid || off < pageOffset || off - pageOffset > maxInstructionBytes)
            continue;
        const size_t skip = off - pageOffset;
        ++out.candidates;
        ++votes[skip];
        evidence[skip] += (uint32_t)(pageOffset - candidate);
    }

    for (size_t skip = 1; skip < votes.size(); ++skip) {
        const size_t best = out.prefixSkip;
        if (votes[skip] > votes[best] ||
            (votes[skip] == votes[best] && evidence[skip] > evidence[best]))
            out.prefixSkip = (uint32_t)skip;
    }
    return out;
}

ListingPrefixResult BuildListingPrefixCheckpoints(
    const uint8_t* bytes, size_t available, uint64_t startAddress,
    uint64_t sectionPageBase, uint64_t targetPage, size_t lookaheadBytes,
    IDisassembler& dis, const std::function<bool()>& cancelled,
    std::atomic<uint32_t>* progress) {
    ListingPrefixResult out;
    if (!bytes || startAddress < sectionPageBase || targetPage < startAddress) return out;
    const uint64_t distance64 = targetPage - startAddress;
    if (distance64 > kListingPrefixExactByteCap) return out;
    if (distance64 > available || distance64 > std::numeric_limits<size_t>::max()) return out;
    const size_t distance = (size_t)distance64;
    const uint64_t room64 = ListingAddressRoom(startAddress);
    const size_t addressRoom = room64 > (uint64_t)std::numeric_limits<size_t>::max()
                             ? std::numeric_limits<size_t>::max() : (size_t)room64;
    available = std::min(available, addressRoom);
    if (distance > available) return out;

    const uint64_t baseDelta = startAddress - sectionPageBase;
    uint64_t pageNumber = baseDelta / kListingCodePageBytes;
    if (pageNumber > UINT64_MAX / kListingCodePageBytes) return out;
    uint64_t boundary = sectionPageBase + pageNumber * kListingCodePageBytes;
    if (boundary < startAddress) {
        if (boundary > UINT64_MAX - kListingCodePageBytes) return out;
        boundary += kListingCodePageBytes;
    }
    if (boundary == startAddress && boundary <= targetPage) {
        out.checkpoints.push_back({ boundary, 0 });
        if (boundary <= UINT64_MAX - kListingCodePageBytes)
            boundary += kListingCodePageBytes;
        else if (boundary != targetPage) return out;
    }

    size_t off = 0;
    uint32_t tick = 0;
    while (off < distance) {
        if (((++tick & 0xFFu) == 0) && cancelled && cancelled()) return out;
        const size_t remainingToTarget = distance - off;
        const size_t requested = remainingToTarget > std::numeric_limits<size_t>::max() - lookaheadBytes
                               ? available - off : remainingToTarget + lookaheadBytes;
        const size_t decodeAvail = std::min(available - off, requested);
        Instruction in;
        if (!(dis.decodeOne(bytes + off, decodeAvail, startAddress + off, in) &&
              in.length && in.length <= decodeAvail)) {
            in = Instruction{};
            in.address = startAddress + off;
            in.length = (uint32_t)std::min<size_t>(
                decodeAvail, std::max<uint32_t>(1, dis.invalidDecodeWidth()));
        }
        const size_t next = off + in.length;
        while (boundary <= targetPage) {
            const uint64_t boundaryOffset64 = boundary - startAddress;
            if (boundaryOffset64 > next) break;
            const uint32_t skip = boundaryOffset64 > off && boundaryOffset64 < next
                                ? (uint32_t)std::min<uint64_t>(next - boundaryOffset64, UINT32_MAX)
                                : 0;
            out.checkpoints.push_back({ boundary, skip });
            if (boundary == targetPage) break;
            if (boundary > UINT64_MAX - kListingCodePageBytes) return out;
            boundary += kListingCodePageBytes;
        }
        off = next;
        out.bytesScanned = std::min<uint64_t>(off, distance);
        if (progress) progress->store((uint32_t)std::min<uint64_t>(
            out.bytesScanned, UINT32_MAX), std::memory_order_relaxed);
    }
    if (distance == 0 && out.checkpoints.empty())
        out.checkpoints.push_back({ targetPage, 0 });
    out.complete = !out.checkpoints.empty() &&
                   out.checkpoints.back().address == targetPage;
    return out;
}

std::vector<CallEdgeR> BuildCallEdges(const BinaryFile& bin, IDisassembler& dis,
                                      const std::vector<FuncResult>& functions,
                                      const JumpTableResolver& resolveTable,
                                      const NoreturnCallResolver& resolveNoreturnCall,
                                      const DirectTargetResolver& resolveDirectTarget,
                                      const std::function<bool()>& cancelled) {
    std::vector<CallEdgeR> edges;
    if (!bin.loaded()) return edges;
    const auto stopped = [&] { return cancelled && cancelled(); };
    std::unordered_set<uint64_t> fset;
    size_t seedTick = 0;
    for (const auto& f : functions) {
        if (((seedTick++ & 0x03FFu) == 0) && stopped()) return {};
        fset.insert(f.address);
    }
    struct RecoveringDecoder final : IDisassembler {
        IDisassembler& inner;
        const std::function<bool()>& cancelled;
        size_t cancellationTick = 0;
        RecoveringDecoder(IDisassembler& decoder,
                          const std::function<bool()>& stop)
            : inner(decoder), cancelled(stop) {}
        Engine engine() const override { return inner.engine(); }
        const char* engineName() const override { return inner.engineName(); }
        bool ready() const override { return inner.ready(); }
        std::string_view errorMessage() const override { return inner.errorMessage(); }
        uint32_t invalidDecodeWidth() const override { return inner.invalidDecodeWidth(); }
        uint32_t instructionAlignment() const override { return inner.instructionAlignment(); }
        bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                       Instruction& instruction) override {
            // CFG construction can decode up to 50,000 instructions for one
            // function. Poll within that function so a patch's mandatory image
            // mutation barrier is never forced to wait for the complete sweep.
            if (cancelled && ((cancellationTick++ & 0x00FFu) == 0) && cancelled())
                return false;
            if (inner.decodeOne(data, size, va, instruction) && instruction.length &&
                instruction.length <= size)
                return true;
            if (!data || !size) return false;
            instruction = {};
            instruction.address = va;
            instruction.length = static_cast<uint32_t>(std::min<size_t>(
                size, std::max<uint32_t>(1, inner.invalidDecodeWidth())));
            instruction.mnemonic = "db";
            return true;
        }
        std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                             uint64_t va, size_t cap) override {
            std::vector<Instruction> instructions;
            size_t offset = 0;
            while (offset < size && (!cap || instructions.size() < cap)) {
                Instruction instruction;
                if (!decodeOne(data + offset, size - offset, va + offset, instruction)) break;
                offset += instruction.length;
                instructions.push_back(std::move(instruction));
            }
            return instructions;
        }
    } recovering(dis, cancelled);
    for (const auto& f : functions) {
        if (stopped()) return {};
        std::unordered_set<uint64_t> seen;   // de-dup callees per caller
        std::vector<FunctionChunk> spans = f.chunks;
        if (spans.empty()) spans.push_back({f.address, f.size ? f.size : 4096u});
        std::vector<CFGCodeChunk> chunks;
        chunks.reserve(spans.size());
        for (const FunctionChunk& span : spans) {
            size_t avail = 0;
            const uint8_t* p = bin.ptrFromVA(span.address, avail);
            if (p && span.size)
                chunks.push_back({p, std::min<size_t>(avail, span.size), span.address});
        }
        if (chunks.empty()) continue;
        DirectTargetResolver direct = resolveDirectTarget;
        if (!direct)
            direct = [&bin](const Instruction& instruction, uint64_t& target) {
                return bin.resolveInstructionTarget(instruction, target);
            };
        ControlFlowGraph graph = BuildCFG(chunks, recovering, 50000, resolveTable,
                                          resolveNoreturnCall, direct);
        if (stopped()) return {};
        size_t instructionTick = 0;
        for (const BasicBlock& block : graph.blocks) {
            for (const Instruction& in : block.insns) {
                if (((instructionTick++ & 0x00FFu) == 0) && stopped()) return {};
                uint64_t target = 0;
                if (InstructionIsCall(in) && direct(in, target) &&
                    fset.count(target) && seen.insert(target).second)
                    edges.push_back({ f.address, target });
            }
        }
    }
    return edges;
}

std::vector<AlgoMatch> ScanAlgorithmsJob(const BinaryFile& bin, const XrefIndex* xref,
                                         const std::vector<FuncResult>& functions,
                                         const std::function<bool()>& cancelled) {
    return ScanAlgorithms(bin, xref, functions.empty() ? nullptr : &functions,
                          cancelled);
}

static DecompileABI analystABI(Arch arch, std::string_view spelling) {
    std::string normalized;
    normalized.reserve(spelling.size());
    for (unsigned char c : spelling)
        if (!std::isspace(c)) normalized.push_back(static_cast<char>(std::tolower(c)));
    if (arch == Arch::X64) {
        if (normalized == "win64" || normalized == "msx64" ||
            normalized == "microsoftx64" || normalized == "__fastcall" ||
            normalized == "fastcall" || normalized == "__vectorcall" ||
            normalized == "vectorcall")
            return DecompileABI::Win64;
        if (normalized == "sysv" || normalized == "sysv64" ||
            normalized == "systemv" || normalized == "__sysv_abi")
            return DecompileABI::SysV64;
    } else if (arch == Arch::X86) {
        if (normalized == "cdecl" || normalized == "__cdecl")
            return DecompileABI::X86Cdecl;
        if (normalized == "stdcall" || normalized == "__stdcall")
            return DecompileABI::X86Stdcall;
    }
    return DecompileABI::Unknown;
}

DecompileTarget DecompileTargetForBinary(const BinaryFile& bin, Arch arch,
                                         std::string_view analystCallingConvention) {
    DecompileTarget target;
    target.architecture = arch;
    target.abi = DecompileABI::Unknown;
    if (arch == Arch::X64) {
        if (bin.format() == BinFormat::PE32Plus) target.abi = DecompileABI::Win64;
        else if (bin.format() == BinFormat::ELF || bin.format() == BinFormat::MachO)
            target.abi = DecompileABI::SysV64;
    } else if (arch == Arch::X86) {
        // Both Win32's default C ABI and the 32-bit SysV ABI use the cdecl stack
        // argument shape modeled by this lightweight pass. Per-function stdcall
        // evidence may still refine signatures elsewhere.
        if (bin.format() == BinFormat::PE32 || bin.format() == BinFormat::ELF ||
            bin.format() == BinFormat::MachO)
            target.abi = DecompileABI::X86Cdecl;
    }
    if (bin.format() == BinFormat::Raw && !analystCallingConvention.empty())
        target.abi = analystABI(arch, analystCallingConvention);
    return target;
}

void AddDecompileDiagnostic(DecompResult& result,
                            DecompileDiagnosticKind kind,
                            std::string message) {
    result.complete = false;
    if (result.incompleteReason.empty()) result.incompleteReason = message;
    else if (result.incompleteReason.find(message) == std::string::npos)
        result.incompleteReason += "; " + message;
    for (const DecompileDiagnostic& diagnostic : result.diagnostics)
        if (diagnostic.kind == kind && diagnostic.message == message) return;
    result.diagnostics.push_back({kind, std::move(message)});
}

void PrependDecompileWarning(DecompResult& result) {
    if (result.complete) return;
    const std::string reason = result.incompleteReason.empty()
                             ? "input was only partially analyzed"
                             : result.incompleteReason;
    result.text.insert(0, "// WARNING: incomplete decompilation: " + reason + "\n");
    result.lineVA.insert(result.lineVA.begin(), 0);
    result.lineOrigins.insert(result.lineOrigins.begin(), SourceOrigin{});
}

DecompResult DecompileRegion(const BinaryFile& bin, IDisassembler& dis,
                             const DecoderConfig& decoder,
                             uint64_t lo, uint64_t hi,
                             const DecompileNameMap* names,
                             std::string_view signature,
                             const NoreturnCallResolver& isNoreturnCall,
                             const std::vector<FunctionChunk>* chunks,
                             bool ownershipTruncated,
                             std::string_view analystCallingConvention) {
    constexpr size_t kByteBudget = 16384;
    DecompResult result;
    if (!bin.loaded() || hi <= lo) {
        result.text = "// no mapped function input\n";
        result.lineVA = {0};
        result.lineOrigins = {SourceOrigin{}};
        AddDecompileDiagnostic(result, DecompileDiagnosticKind::MissingChunk,
                               "function input is empty or unmapped");
        PrependDecompileWarning(result);
        return result;
    }

    std::vector<FunctionChunk> requested;
    if (chunks && !chunks->empty()) requested = *chunks;
    else {
        const uint64_t bytes = hi - lo;
        requested.push_back({lo, static_cast<uint32_t>(
            std::min<uint64_t>(bytes, (std::numeric_limits<uint32_t>::max)()))});
    }
    std::stable_sort(requested.begin(), requested.end(), [lo](const auto& a, const auto& b) {
        const bool aEntry = a.size && lo >= a.address && lo - a.address < a.size;
        const bool bEntry = b.size && lo >= b.address && lo - b.address < b.size;
        return aEntry != bEntry ? aEntry : a.address < b.address;
    });

    std::vector<CFGCodeChunk> codeChunks;
    codeChunks.reserve(requested.size() * 2);
    size_t remaining = kByteBudget;
    bool clipped = false;
    for (const FunctionChunk& chunk : requested) {
        if (!remaining) { clipped = true; break; }
        const size_t wanted = std::min<size_t>(chunk.size, remaining);
        if (wanted < chunk.size) clipped = true;
        size_t available = 0;
        const uint8_t* data = bin.ptrFromVA(chunk.address, available);
        const size_t mapped = std::min(available, wanted);
        codeChunks.push_back({data, mapped, chunk.address});
        if (mapped < wanted) {
            uint64_t missingVA = 0;
            if (CheckedAddressAdd(chunk.address, static_cast<uint64_t>(mapped), missingVA))
                codeChunks.push_back({nullptr, wanted - mapped, missingVA});
        }
        remaining -= wanted;
    }

    std::unordered_map<uint64_t, std::string> imports;
    for (const auto& im : bin.imports())
        if (im.addressKnown) imports[im.iatVA] = im.dll + "." + DemangleForLabel(im.name);
    auto stringAt = [&bin](uint64_t va) -> std::string {
        size_t available = 0;
        const uint8_t* data = bin.ptrFromVA(va, available);
        if (!data) return {};
        std::string value;
        for (size_t i = 0, n = std::min<size_t>(available, 128); i < n; ++i) {
            const unsigned char c = data[i];
            if (!c) break;
            if (!((c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r'))
                return {};
            value.push_back(static_cast<char>(c));
        }
        if (value.size() < 3) return {};
        std::string quoted = "\"";
        for (char c : value) {
            if (quoted.size() > 48) { quoted += "..."; break; }
            if (c == '"' || c == '\\') quoted += '\\';
            if (c == '\n') { quoted += "\\n"; continue; }
            if (c == '\t') { quoted += "\\t"; continue; }
            if (c == '\r') { quoted += "\\r"; continue; }
            quoted += c;
        }
        return quoted + '"';
    };

    DecompileOptions options;
    options.target = DecompileTargetForBinary(bin, decoder.arch,
                                               analystCallingConvention);
    options.nameFor = [&imports, names](uint64_t address) -> std::string {
        if (names) if (auto found = names->find(address); found != names->end() &&
                       !found->second.empty()) return found->second;
        if (auto found = imports.find(address); found != imports.end()) return found->second;
        return {};
    };
    options.dataRefFor = [&imports, &stringAt, names](uint64_t address) -> std::string {
        if (names) if (auto found = names->find(address); found != names->end() &&
                       !found->second.empty()) return found->second;
        if (auto found = imports.find(address); found != imports.end()) return found->second;
        return stringAt(address);
    };
    if (!signature.empty()) options.signature.assign(signature.data(), signature.size());
    auto resolveTable = [&bin, &dis, &decoder](const Instruction& instruction) {
        JumpTableResolution table = ResolveJumpTable(
            bin, dis, decoder.arch, decoder.byteOrder, instruction);
        ResolvedJumpTable resolved;
        if (table.valid) resolved.targets = std::move(table.targets);
        resolved.truncated = table.truncated;
        resolved.evidence = std::move(table.evidence);
        return resolved;
    };
    result = DecompileWithMap(codeChunks, dis, options, 2000,
                              resolveTable, isNoreturnCall,
                              [&bin](const Instruction& instruction, uint64_t& target) {
                                  return bin.resolveInstructionTarget(instruction, target);
                              });
    if (clipped)
        AddDecompileDiagnostic(result, DecompileDiagnosticKind::ClippedInput,
                               "function input exceeded the 16 KiB decompilation byte limit");
    if (ownershipTruncated)
        AddDecompileDiagnostic(result, DecompileDiagnosticKind::TruncatedOwnership,
                               "function ownership discovery was truncated");
    PrependDecompileWarning(result);
    return result;
}

} // namespace ds
