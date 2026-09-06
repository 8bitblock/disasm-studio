#include "CodeDataClassifier.h"

#include "AddressSpan.h"
#include "BinaryFile.h"
#include "GameMakerArchive.h"
#include "JumpTableResolver.h"
#include "../Disasm/IDisassembler.h"
#include "InstructionReference.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ds {
namespace {

constexpr uint64_t kMaxPointerScanBytes = 64ull * 1024ull * 1024ull;
constexpr uint64_t kMaxDecodedInstructions = 2'000'000;
constexpr uint64_t kMaxVisitedBlocks = 250'000;
constexpr size_t   kMaxBlockInstructions = 4096;
constexpr size_t   kMaxTableEntries = 1024;
constexpr size_t   kMaxFunctionSeeds = 50'000;
constexpr size_t   kMaxClaims = 250'000;

struct ExecRange {
    uint64_t address = 0;
    uint64_t size = 0;
    uint32_t sectionIndex = 0;
};

struct Claim {
    uint64_t address = 0;
    uint64_t size = 0;
    CodeDataKind kind = CodeDataKind::Unknown;
    uint8_t width = 1;
    CodeDataConfidence confidence = CodeDataConfidence::Low;
    int priority = 0;
    std::string evidence;
};

struct DataReference {
    uint64_t address = 0;
    uint8_t width = 1;
    std::string evidence;
};

static std::string lowerCopy(std::string value) {
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

static bool spanContains(uint64_t address, uint64_t size, uint64_t value) {
    return size && value >= address && value - address < size;
}

static bool spanContainsRange(uint64_t address, uint64_t size,
                              uint64_t value, uint64_t length) {
    if (!length || !spanContains(address, size, value)) return false;
    const uint64_t offset = value - address;
    return length <= size - offset;
}

static uint64_t boundedEnd(uint64_t address, uint64_t size) {
    return size > UINT64_MAX - address ? UINT64_MAX : address + size;
}

static void markTruncated(CodeDataMap& map, std::string reason) {
    map.truncated = true;
    if (reason.empty()) return;
    if (map.truncationReason.empty()) {
        map.truncationReason = std::move(reason);
    } else if (map.truncationReason.find(reason) == std::string::npos) {
        map.truncationReason += "; " + reason;
    }
}

static const ExecRange* rangeFor(const std::vector<ExecRange>& ranges, uint64_t address) {
    auto it = std::upper_bound(ranges.begin(), ranges.end(), address,
        [](uint64_t value, const ExecRange& range) { return value < range.address; });
    if (it == ranges.begin()) return nullptr;
    --it;
    return spanContains(it->address, it->size, address) ? &*it : nullptr;
}

static bool rangeContains(const std::vector<ExecRange>& ranges, uint64_t address,
                          uint64_t length = 1) {
    const ExecRange* range = rangeFor(ranges, address);
    return range && spanContainsRange(range->address, range->size, address, length);
}

static uint8_t pointerWidthFor(Arch arch) {
    switch (arch) {
        case Arch::X64: case Arch::ARM64: case Arch::MIPS64:
        case Arch::PPC64: case Arch::RISCV64: return 8;
        default: return 4;
    }
}

static uint8_t instructionDataWidth(const Instruction& in, uint8_t pointerWidth) {
    const std::string op = lowerCopy(in.operands);
    if (op.find("zmmword") != std::string::npos) return 64;
    if (op.find("ymmword") != std::string::npos) return 32;
    if (op.find("xmmword") != std::string::npos || op.find("oword") != std::string::npos) return 16;
    if (op.find("qword") != std::string::npos) return 8;
    if (op.find("dword") != std::string::npos) return 4;
    if (op.find("word") != std::string::npos) return 2;
    if (op.find("byte") != std::string::npos) return 1;
    // Capstone ARM operands start with the destination register.
    size_t first = op.find_first_not_of(' ');
    if (first != std::string::npos) {
        if (op[first] == 'q') return 16;
        if (op[first] == 'x' || op[first] == 'd') return 8;
        if (op[first] == 'w' || op[first] == 's') return 4;
        if (op[first] == 'h') return 2;
        if (op[first] == 'b') return 1;
    }
    return pointerWidth;
}

static bool TryGetArmLiteralReference(const Instruction& in, Arch arch,
                                      uint64_t& result) {
    result = 0;
    if (!ArchIsArm(arch)) return false;
    const std::string mnemonic = lowerCopy(in.mnemonic);
    const std::string operands = lowerCopy(in.operands);
    const bool pcLoad = (mnemonic == "ldr" || mnemonic == "ldr.w" ||
                         mnemonic == "vldr") && operands.find("[pc") != std::string::npos;
    const bool a64Literal = arch == Arch::ARM64 &&
        ((mnemonic == "ldr" && operands.find('[') == std::string::npos) ||
         mnemonic == "adr");
    if (!pcLoad && !a64Literal) return false;
    const size_t hash = operands.find('#');
    if (hash == std::string::npos) return false;
    const char* p = operands.c_str() + hash + 1;
    char* end = nullptr;
    const int64_t immediate = std::strtoll(p, &end, 0);
    if (!end || end == p) return false;
    if (a64Literal) {
        if (immediate < 0) return false;
        result = static_cast<uint64_t>(immediate);
        return true;
    }
    const uint64_t pipeline = arch == Arch::ARM ? 8 : 4;
    if (in.address > UINT64_MAX - pipeline) return false;
    uint64_t pc = in.address + pipeline;
    if (arch == Arch::THUMB) pc &= ~uint64_t{3};
    if (immediate >= 0) {
        const uint64_t value = static_cast<uint64_t>(immediate);
        if (value > UINT64_MAX - pc) return false;
        result = pc + value;
        return true;
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(immediate + 1)) + 1;
    if (magnitude > pc) return false;
    result = pc - magnitude;
    return true;
}

static bool isUnconditionalTransfer(const Instruction& in) {
    if (InstructionIsUnconditionalBranch(in)) return true;
    if (!in.isBranch || in.isCall || in.isRet) return false;
    const std::string m = lowerCopy(in.mnemonic);
    return m == "jmp" || m == "b" || m == "b.w" || m == "bx" || m == "br" ||
           m == "j" || m == "jr" || m == "goto" || m == "goto_w" ||
           m == "tbb" || m == "tbh";
}

static bool validInstructionAt(const BinaryFile& bin, IDisassembler& dis,
                               const std::vector<ExecRange>& ranges, uint64_t address,
                               Instruction* decoded = nullptr) {
    const ExecRange* range = rangeFor(ranges, address);
    if (!range) return false;
    size_t available = 0;
    const uint8_t* p = bin.ptrFromVA(address, available);
    if (!p || !available) return false;
    const uint64_t rangeLeft = range->size - (address - range->address);
    const size_t limit = static_cast<size_t>(std::min<uint64_t>(
        std::min<uint64_t>(available, rangeLeft), 32));
    Instruction in;
    if (!limit || !dis.decodeOne(p, limit, address, in) || !in.length ||
        in.length > limit || lowerCopy(in.mnemonic) == "db") return false;
    if (decoded) *decoded = std::move(in);
    return true;
}

static bool strictFunctionEntry(const BinaryFile& bin, IDisassembler& dis,
                                const std::vector<ExecRange>& ranges, uint64_t address) {
    Instruction first;
    if (!validInstructionAt(bin, dis, ranges, address, &first)) return false;
    const std::string m = lowerCopy(first.mnemonic);
    const std::string o = lowerCopy(first.operands);
    if (m == "endbr64" || m == "endbr32" || m == "paciasp") return true;
    if ((m == "push" || m == "push.w" || m.rfind("stmdb", 0) == 0) &&
        (o.find("bp") != std::string::npos || o.find("lr") != std::string::npos)) return true;
    if (m == "stp" && o.find("x29") != std::string::npos &&
        o.find("x30") != std::string::npos && o.find("sp") != std::string::npos) return true;
    if (m == "sub" && (o.find("rsp") != std::string::npos ||
                       o.find("esp") != std::string::npos || o.find("sp") != std::string::npos)) return true;
    // Import/export thunks are legitimate indirect-only functions too.
    if (isUnconditionalTransfer(first)) return true;
    return false;
}

static bool readUnsigned(const uint8_t* p, size_t available, uint8_t width,
                         ByteOrder byteOrder, uint64_t& value) {
    value = 0;
    if (!p || (width != 1 && width != 2 && width != 4 && width != 8) || available < width)
        return false;
    if (byteOrder == ByteOrder::Big) {
        for (uint8_t i = 0; i < width; ++i) value = (value << 8) | p[i];
    } else {
        for (uint8_t i = 0; i < width; ++i)
            value |= static_cast<uint64_t>(p[i]) << (static_cast<unsigned>(i) * 8u);
    }
    return true;
}

static bool resolveStoredTarget(const std::vector<ExecRange>& ranges, uint64_t imageBase,
                                uint64_t value, uint64_t& target) {
    if (rangeContains(ranges, value)) { target = value; return true; }
    if (value <= UINT64_MAX - imageBase && rangeContains(ranges, imageBase + value)) {
        target = imageBase + value;
        return true;
    }
    return false;
}

static void mergeClaims(std::vector<Claim>& claims) {
    std::sort(claims.begin(), claims.end(), [](const Claim& a, const Claim& b) {
        if (a.address != b.address) return a.address < b.address;
        if (a.kind != b.kind) return static_cast<uint8_t>(a.kind) < static_cast<uint8_t>(b.kind);
        return a.width < b.width;
    });
    std::vector<Claim> merged;
    merged.reserve(claims.size());
    for (Claim claim : claims) {
        if (!claim.size) continue;
        if (!merged.empty()) {
            Claim& last = merged.back();
            const bool compatible = last.kind == claim.kind && last.width == claim.width &&
                last.confidence == claim.confidence && last.priority == claim.priority &&
                last.evidence == claim.evidence;
            const uint64_t lastEnd = boundedEnd(last.address, last.size);
            if (compatible && claim.address <= lastEnd) {
                const uint64_t claimEnd = boundedEnd(claim.address, claim.size);
                if (claimEnd > lastEnd) last.size = claimEnd - last.address;
                continue;
            }
        }
        merged.push_back(std::move(claim));
    }
    claims = std::move(merged);
}

static bool claimContains(const std::vector<Claim>& claims, uint64_t address) {
    auto it = std::upper_bound(claims.begin(), claims.end(), address,
        [](uint64_t value, const Claim& claim) { return value < claim.address; });
    while (it != claims.begin()) {
        --it;
        if (spanContains(it->address, it->size, address)) return true;
        if (boundedEnd(it->address, it->size) <= address) break;
    }
    return false;
}

static bool codeContains(const std::vector<Claim>& code, uint64_t address) {
    return claimContains(code, address);
}

// Padding scans only move forward through a sorted, disjoint union of stronger
// claims. Keep one cursor per scan instead of binary-searching that same union
// for every executable byte. Returning the covered extent also lets the outer
// scan skip a whole code/string/table span without examining its bytes.
class CoveredClaimCursor {
public:
    CoveredClaimCursor(const std::vector<Claim>& claims, uint64_t start) : claims_(claims) {
        const auto it = std::upper_bound(claims.begin(), claims.end(), start,
            [](uint64_t value, const Claim& claim) { return value < claim.address; });
        next_ = static_cast<size_t>(it - claims.begin());
        if (next_) --next_;
    }

    uint64_t coveredBytesAt(uint64_t address) {
        while (next_ < claims_.size() && claims_[next_].address <= address) {
            const Claim& claim = claims_[next_];
            if (spanContains(claim.address, claim.size, address))
                return claim.size - (address - claim.address);
            ++next_;
        }
        return 0;
    }

private:
    const std::vector<Claim>& claims_;
    size_t next_ = 0;
};

static void addStats(CodeDataStats& stats, const CodeDataSpan& span) {
    switch (span.kind) {
        case CodeDataKind::Code:         stats.codeBytes += span.size; break;
        case CodeDataKind::Unknown:      stats.unknownBytes += span.size; break;
        case CodeDataKind::String:       stats.stringBytes += span.size; stats.dataBytes += span.size; break;
        case CodeDataKind::LiteralPool:  stats.literalBytes += span.size; stats.dataBytes += span.size; break;
        case CodeDataKind::JumpTable:    stats.jumpTableBytes += span.size; stats.dataBytes += span.size; break;
        case CodeDataKind::PointerTable: stats.pointerTableBytes += span.size; stats.dataBytes += span.size; break;
        case CodeDataKind::Padding:      stats.paddingBytes += span.size; stats.dataBytes += span.size; break;
        case CodeDataKind::Data:         stats.dataBytes += span.size; break;
    }
}

static void partitionRanges(const std::vector<ExecRange>& ranges,
                            const std::vector<Claim>& claims, CodeDataMap& out) {
    struct LocalClaim { uint64_t begin = 0, end = 0; size_t claim = 0; };
    struct Event { uint64_t offset = 0; bool start = false; size_t local = 0; };
    for (const ExecRange& range : ranges) {
        std::vector<LocalClaim> local;
        for (size_t i = 0; i < claims.size(); ++i) {
            const Claim& claim = claims[i];
            if (!claim.size) continue;
            if (claim.address >= range.address) {
                const uint64_t offset = claim.address - range.address;
                if (offset >= range.size) continue;
                local.push_back({ offset, std::min<uint64_t>(range.size, offset +
                    std::min<uint64_t>(claim.size, range.size - offset)), i });
            } else if (spanContains(claim.address, claim.size, range.address)) {
                const uint64_t consumed = range.address - claim.address;
                local.push_back({ 0, std::min<uint64_t>(range.size, claim.size - consumed), i });
            }
        }
        std::vector<Event> events;
        events.reserve(local.size() * 2 + 2);
        events.push_back({0, true, SIZE_MAX});
        events.push_back({range.size, false, SIZE_MAX});
        for (size_t i = 0; i < local.size(); ++i) {
            if (local[i].begin >= local[i].end) continue;
            events.push_back({local[i].begin, true, i});
            events.push_back({local[i].end, false, i});
        }
        std::sort(events.begin(), events.end(), [](const Event& a, const Event& b) {
            if (a.offset != b.offset) return a.offset < b.offset;
            return a.start < b.start; // remove ends before adding starts at one boundary
        });
        std::set<std::pair<int, size_t>> active;
        size_t cursor = 0;
        while (cursor < events.size()) {
            const uint64_t at = events[cursor].offset;
            while (cursor < events.size() && events[cursor].offset == at && !events[cursor].start) {
                if (events[cursor].local != SIZE_MAX) {
                    const size_t ci = local[events[cursor].local].claim;
                    active.erase({claims[ci].priority, ci});
                }
                ++cursor;
            }
            while (cursor < events.size() && events[cursor].offset == at && events[cursor].start) {
                if (events[cursor].local != SIZE_MAX) {
                    const size_t ci = local[events[cursor].local].claim;
                    active.insert({claims[ci].priority, ci});
                }
                ++cursor;
            }
            if (cursor >= events.size()) break;
            const uint64_t next = events[cursor].offset;
            if (next <= at) continue;
            CodeDataSpan span;
            span.address = range.address + at;
            span.size = next - at;
            if (!active.empty()) {
                const Claim& claim = claims[active.rbegin()->second];
                span.kind = claim.kind;
                span.elementWidth = claim.width;
                span.confidence = claim.confidence;
                span.evidence = claim.evidence;
            } else {
                span.kind = CodeDataKind::Unknown;
                span.elementWidth = 1;
                span.confidence = CodeDataConfidence::Low;
                span.evidence = "not reached and no strong data evidence";
            }
            if (!out.spans.empty()) {
                CodeDataSpan& last = out.spans.back();
                const bool adjacent = last.address <= UINT64_MAX - last.size &&
                                      last.address + last.size == span.address;
                if (adjacent && last.kind == span.kind &&
                    last.elementWidth == span.elementWidth &&
                    last.confidence == span.confidence && last.evidence == span.evidence) {
                    last.size += span.size;
                    continue;
                }
            }
            out.spans.push_back(std::move(span));
        }
    }
}

} // namespace

const CodeDataSpan* CodeDataMap::find(uint64_t address) const {
    auto it = std::upper_bound(spans.begin(), spans.end(), address,
        [](uint64_t value, const CodeDataSpan& span) { return value < span.address; });
    if (it == spans.begin()) return nullptr;
    --it;
    return spanContains(it->address, it->size, address) ? &*it : nullptr;
}

const char* CodeDataKindName(CodeDataKind kind) {
    switch (kind) {
        case CodeDataKind::Unknown: return "unknown";
        case CodeDataKind::Code: return "reachable code";
        case CodeDataKind::String: return "string";
        case CodeDataKind::LiteralPool: return "literal pool";
        case CodeDataKind::JumpTable: return "jump table";
        case CodeDataKind::PointerTable: return "code-pointer table";
        case CodeDataKind::Padding: return "alignment padding";
        case CodeDataKind::Data: return "data";
    }
    return "unknown";
}

const char* CodeDataConfidenceName(CodeDataConfidence confidence) {
    switch (confidence) {
        case CodeDataConfidence::Low: return "low";
        case CodeDataConfidence::Medium: return "medium";
        case CodeDataConfidence::High: return "high";
    }
    return "low";
}

bool CodeDataKindIsData(CodeDataKind kind) {
    return kind != CodeDataKind::Unknown && kind != CodeDataKind::Code;
}

std::string CodeDataSummary(const CodeDataMap& map) {
    char text[320];
    std::snprintf(text, sizeof(text),
        "code/data map: %llu code, %llu typed data (%llu strings, %llu literals, %llu tables, %llu padding), %llu unknown byte(s); %zu indirect seed(s)%s",
        static_cast<unsigned long long>(map.stats.codeBytes),
        static_cast<unsigned long long>(map.stats.dataBytes),
        static_cast<unsigned long long>(map.stats.stringBytes),
        static_cast<unsigned long long>(map.stats.literalBytes),
        static_cast<unsigned long long>(map.stats.jumpTableBytes + map.stats.pointerTableBytes),
        static_cast<unsigned long long>(map.stats.paddingBytes),
        static_cast<unsigned long long>(map.stats.unknownBytes), map.functionSeeds.size(),
        map.truncated ? " (bounded/truncated)" : "");
    return text;
}

CodeDataMap ClassifyCodeData(const BinaryFile& bin, IDisassembler& dis,
                             const DecoderConfig& requestedDecoder,
                             const std::vector<CodeDataFunctionInput>& functions,
                             const std::vector<CodeDataStringInput>& strings,
                             const std::function<bool()>& cancelled) {
    CodeDataMap out;
    if (!bin.loaded()) return out;
    out.imageRevision = bin.imageRevision();
    const DecoderConfig decoder = DecoderConfigForImage(bin, requestedDecoder);
    const Arch arch = decoder.arch;

    std::vector<ExecRange> ranges;
    ranges.reserve(bin.sections().size());
    for (uint32_t i = 0; i < static_cast<uint32_t>(bin.sections().size()); ++i) {
        const Section& section = bin.sections()[i];
        if (!section.executable || section.virtualAddress > UINT64_MAX - bin.imageBase()) continue;
        const uint64_t address = bin.imageBase() + section.virtualAddress;
        size_t available = 0;
        if (!bin.ptrFromVA(address, available) || !available) continue;
        const uint64_t size = std::min<uint64_t>(available, section.rawSize ? section.rawSize : available);
        if (!size) continue;
        ranges.push_back({address, size, i});
        out.stats.executableBytes += size;
    }
    std::sort(ranges.begin(), ranges.end(), [](const ExecRange& a, const ExecRange& b) {
        return a.address < b.address;
    });
    if (ranges.empty()) return out;

    std::vector<Claim> claims;
    std::vector<Claim> strongDataHints;
    std::vector<DataReference> dataRefs;
    std::unordered_map<uint64_t, std::string> recoveredSeeds;
    auto addSeed = [&](uint64_t address, std::string evidence) {
        if (!rangeContains(ranges, address) || recoveredSeeds.size() >= kMaxFunctionSeeds) return;
        recoveredSeeds.try_emplace(address, std::move(evidence));
    };
    auto addClaim = [&](std::vector<Claim>& dst, uint64_t address, uint64_t size,
                        CodeDataKind kind, uint8_t width, CodeDataConfidence confidence,
                        int priority, std::string evidence) {
        if (!size || !rangeContains(ranges, address)) return;
        const ExecRange* range = rangeFor(ranges, address);
        size = std::min<uint64_t>(size, range->size - (address - range->address));
        if (!size || dst.size() >= kMaxClaims) {
            out.truncated = true;
            if (out.truncationReason.empty()) out.truncationReason = "classification span cap reached";
            return;
        }
        dst.push_back({address, size, kind, static_cast<uint8_t>(width ? width : 1), confidence, priority,
                       std::move(evidence)});
    };

    // Java method extents are authoritative and do not contain native pointer or
    // padding tables. Keeping this path exact also avoids applying little-endian
    // native table heuristics to class-file bytecode operands.
    if (arch == Arch::GML && bin.gameMakerArchive()) {
        const auto& archive = *bin.gameMakerArchive();
        for (uint32_t index : archive.rootCodeIndices) {
            if (cancelled && cancelled()) {
                out.truncated = true;
                out.truncationReason = "GameMaker classification cancelled";
                break;
            }
            if (index >= archive.code.size()) continue;
            const auto& code = archive.code[index];
            // Exact successfully decoded prefixes are bytecode, never native
            // pointers/padding. An unsupported suffix remains unknown.
            addClaim(claims, code.bytecodeOffset, code.decodedLength, CodeDataKind::Code, 4,
                     CodeDataConfidence::High, 100, "validated GameMaker CODE bytecode");
        }
        partitionRanges(ranges, claims, out);
        for (const auto& span : out.spans) addStats(out.stats, span);
        return out;
    }
    if (arch == Arch::JVM) {
        for (const CodeDataFunctionInput& function : functions)
            addClaim(claims, function.address, function.size, CodeDataKind::Code, 1,
                     CodeDataConfidence::High, 100, "class-file method Code attribute");
        partitionRanges(ranges, claims, out);
        for (const CodeDataSpan& span : out.spans) addStats(out.stats, span);
        return out;
    }

    const uint8_t pointerWidth = pointerWidthFor(arch);
    const ByteOrder imageByteOrder = decoder.byteOrder;

    // CET/IBT landing pads are compiler-emitted indirect-entry declarations. A
    // gap scan is byte-bounded, decoder-confirmed, and never resynchronizes from
    // arbitrary one-byte candidates beyond the exact four-byte signature.
    if (arch == Arch::X64 || arch == Arch::X86) {
        const uint8_t last = arch == Arch::X64 ? 0xFA : 0xFB;
        for (const ExecRange& range : ranges) {
            size_t available = 0;
            const uint8_t* p = bin.ptrFromVA(range.address, available);
            const size_t n = static_cast<size_t>(std::min<uint64_t>(available, range.size));
            for (size_t i = 0; i + 4 <= n; ++i) {
                if (cancelled && (i & 0xFFFFu) == 0 && cancelled()) {
                    out.truncated = true; out.truncationReason = "classification cancelled"; break;
                }
                if (p[i] != 0xF3 || p[i + 1] != 0x0F || p[i + 2] != 0x1E || p[i + 3] != last)
                    continue;
                const uint64_t address = range.address + i;
                Instruction decoded;
                if (validInstructionAt(bin, dis, ranges, address, &decoded) &&
                    lowerCopy(decoded.mnemonic) == (arch == Arch::X64 ? "endbr64" : "endbr32"))
                    addSeed(address, arch == Arch::X64 ? "decoder-confirmed endbr64 landing pad" :
                                                       "decoder-confirmed endbr32 landing pad");
                i += 3;
            }
        }
    }

    // Discover aligned vtables/code-pointer arrays throughout the mapped image.
    // Runs inside executable storage need three entries; ordinary data needs two.
    // Isolated relocation-backed strict entries cover common callback globals.
    uint64_t pointerBytesScanned = 0;
    std::unordered_set<uint64_t> tableSlots;
    for (uint32_t si = 0; si < static_cast<uint32_t>(bin.sections().size()); ++si) {
        if (pointerBytesScanned >= kMaxPointerScanBytes) break;
        const Section& section = bin.sections()[si];
        if (section.virtualAddress > UINT64_MAX - bin.imageBase()) continue;
        const uint64_t sectionVA = bin.imageBase() + section.virtualAddress;
        size_t available = 0;
        const uint8_t* p = bin.ptrFromVA(sectionVA, available);
        const uint64_t mapped64 = std::min<uint64_t>(available, section.rawSize ? section.rawSize : available);
        const size_t n = static_cast<size_t>(std::min<uint64_t>(
            mapped64, kMaxPointerScanBytes - pointerBytesScanned));
        pointerBytesScanned += n;
        if (!p || n < pointerWidth) continue;
        size_t runStart = 0;
        std::vector<uint64_t> runTargets;
        auto flushRun = [&](size_t endOffset) {
            const size_t threshold = section.executable ? 3 : 2;
            if (runTargets.size() >= threshold) {
                const uint64_t address = sectionVA + runStart;
                const uint64_t bytes = static_cast<uint64_t>(runTargets.size()) * pointerWidth;
                const std::string evidence = std::to_string(runTargets.size()) +
                    " consecutive aligned values resolve to decoder-valid executable entries";
                addClaim(strongDataHints, address, bytes, CodeDataKind::PointerTable,
                         pointerWidth, CodeDataConfidence::High, 125, evidence);
                for (size_t i = 0; i < runTargets.size(); ++i) {
                    tableSlots.insert(address + static_cast<uint64_t>(i) * pointerWidth);
                    addSeed(runTargets[i], "target of " + std::to_string(runTargets.size()) +
                                             "-entry code-pointer/vtable run");
                }
            }
            runTargets.clear();
            runStart = endOffset;
        };
        const size_t first = static_cast<size_t>((pointerWidth - (sectionVA % pointerWidth)) % pointerWidth);
        runStart = first;
        for (size_t off = first; off + pointerWidth <= n; off += pointerWidth) {
            if (cancelled && (off & 0xFFFFu) == 0 && cancelled()) {
                out.truncated = true; out.truncationReason = "classification cancelled"; break;
            }
            uint64_t value = 0, target = 0;
            const bool candidate = readUnsigned(p + off, n - off, pointerWidth,
                                                imageByteOrder, value) &&
                resolveStoredTarget(ranges, bin.imageBase(), value, target) &&
                validInstructionAt(bin, dis, ranges, target);
            if (candidate) {
                if (runTargets.empty()) runStart = off;
                runTargets.push_back(target);
            } else {
                flushRun(off + pointerWidth);
            }
        }
        flushRun(n);
    }

    for (const auto& relocation : bin.relocations()) {
        const uint64_t slot = relocation.first;
        if (tableSlots.count(slot)) continue;
        size_t available = 0;
        const uint8_t* p = bin.ptrFromVA(slot, available);
        uint64_t value = 0, target = 0;
        if (!readUnsigned(p, available, pointerWidth, imageByteOrder, value) ||
            !resolveStoredTarget(ranges, bin.imageBase(), value, target) ||
            !strictFunctionEntry(bin, dis, ranges, target)) continue;
        addClaim(strongDataHints, slot, pointerWidth, CodeDataKind::PointerTable,
                 pointerWidth, CodeDataConfidence::High, 124,
                 "relocation-backed callback/code pointer to a strict function entry");
        addSeed(target, "relocation-backed callback pointer");
    }
    mergeClaims(strongDataHints);

    // Recursive traversal from all authoritative and recovered roots. Only exact
    // decoded successors are followed. Data hints stop fall-through before an
    // embedded vtable becomes a stream of plausible x86 instructions.
    std::vector<uint64_t> blocks;
    blocks.reserve(functions.size() + recoveredSeeds.size() + 64);
    std::unordered_set<uint64_t> allRoots;
    for (const CodeDataFunctionInput& function : functions)
        if (rangeContains(ranges, function.address)) {
            blocks.push_back(function.address); allRoots.insert(function.address);
        }
    for (const auto& seed : recoveredSeeds) {
        blocks.push_back(seed.first); allRoots.insert(seed.first);
    }
    std::unordered_set<uint64_t> visitedBlocks, visitedInstructions;
    std::vector<Claim> codeClaims;
    std::vector<Claim> tableClaims;
    size_t cancellationTick = 0;
    while (!blocks.empty() && out.stats.decodedInstructions < kMaxDecodedInstructions &&
           visitedBlocks.size() < kMaxVisitedBlocks) {
        if (cancelled && ((++cancellationTick & 0x3FFu) == 0) && cancelled()) {
            out.truncated = true; out.truncationReason = "classification cancelled"; break;
        }
        uint64_t pc = blocks.back(); blocks.pop_back();
        if (!visitedBlocks.insert(pc).second || !rangeContains(ranges, pc) ||
            claimContains(strongDataHints, pc)) continue;
        ++out.stats.visitedBlocks;
        for (size_t local = 0; local < kMaxBlockInstructions; ++local) {
            if (!rangeContains(ranges, pc) || claimContains(strongDataHints, pc)) break;
            if (!visitedInstructions.insert(pc).second) break;
            const ExecRange* range = rangeFor(ranges, pc);
            size_t available = 0;
            const uint8_t* p = bin.ptrFromVA(pc, available);
            if (!p || !available) break;
            const uint64_t rangeLeft = range->size - (pc - range->address);
            const size_t decodeLimit = static_cast<size_t>(std::min<uint64_t>(
                std::min<uint64_t>(available, rangeLeft), 32));
            Instruction in;
            if (!decodeLimit || !dis.decodeOne(p, decodeLimit, pc, in) || !in.length ||
                in.length > decodeLimit || lowerCopy(in.mnemonic) == "db") break;
            addClaim(codeClaims, pc, in.length, CodeDataKind::Code, 1,
                     CodeDataConfidence::High, 100, "reachable by recursive control-flow traversal");
            ++out.stats.decodedInstructions;

            uint64_t ref = 0;
            bool hasRef = TryGetInstrDataRef(in, ref);
            if (!hasRef) hasRef = TryGetInstrImmRef(in, ref);
            if (!hasRef) hasRef = TryGetArmLiteralReference(in, arch, ref);
            if (hasRef && rangeContains(ranges, ref)) {
                dataRefs.push_back({ref, instructionDataWidth(in, pointerWidth),
                    "referenced by instruction at 0x" + [&] {
                        char b[24]; std::snprintf(b, sizeof(b), "%llX", (unsigned long long)pc);
                        return std::string(b);
                    }()});
            }

            uint64_t flowTarget = 0;
            const bool flowTargetValid = bin.resolveInstructionTarget(in, flowTarget);
            const bool unresolvedTransfer = !flowTargetValid &&
                ((in.isBranch && !in.isCall && !in.isRet) ||
                 in.flow.kind == FlowKind::IndirectBranch || in.flow.kind == FlowKind::Switch);
            if (unresolvedTransfer) {
                JumpTableResolution table = ResolveJumpTable(
                    bin, dis, arch, imageByteOrder, in, kMaxTableEntries);
                if (table.valid) {
                    if (table.truncated) {
                        char address[24];
                        std::snprintf(address, sizeof(address), "0x%llX",
                                      static_cast<unsigned long long>(table.tableAddress));
                        markTruncated(out, "jump table at " + std::string(address) +
                            " was truncated: " + (table.evidence.empty()
                                ? std::string("entry cap reached") : table.evidence));
                    }
                    if (!table.targets.empty()) {
                        addClaim(tableClaims, table.tableAddress,
                                 static_cast<uint64_t>(table.targets.size()) * table.entryWidth,
                                 CodeDataKind::JumpTable, table.entryWidth, CodeDataConfidence::High,
                                 140, table.evidence);
                        for (uint64_t target : table.targets) blocks.push_back(target);
                    }
                }
            }
            for (uint64_t target : in.extraTargets)
                if (rangeContains(ranges, target)) blocks.push_back(target);
            if (in.isCall && flowTargetValid && rangeContains(ranges, flowTarget))
                blocks.push_back(flowTarget);

            if (in.isRet) break;
            if (in.isBranch && !in.isCall && flowTargetValid &&
                rangeContains(ranges, flowTarget)) blocks.push_back(flowTarget);
            if (isUnconditionalTransfer(in)) break;
            if (pc > UINT64_MAX - in.length) break;
            const uint64_t next = pc + in.length;
            if (next != pc && allRoots.count(next)) break;
            pc = next;
        }
    }
    if (out.stats.decodedInstructions >= kMaxDecodedInstructions) {
        out.truncated = true; out.truncationReason = "2,000,000-instruction traversal cap reached";
    } else if (visitedBlocks.size() >= kMaxVisitedBlocks) {
        out.truncated = true; out.truncationReason = "250,000-block traversal cap reached";
    }
    mergeClaims(codeClaims);
    mergeClaims(tableClaims);
    claims.insert(claims.end(), codeClaims.begin(), codeClaims.end());
    claims.insert(claims.end(), strongDataHints.begin(), strongDataHints.end());
    claims.insert(claims.end(), tableClaims.begin(), tableClaims.end());

    // Strings inside executable sections become data only when outside proven
    // traversal. Referenced strings receive high confidence; unreferenced scanner
    // findings remain medium-confidence but still require a bounded exact extent.
    std::unordered_set<uint64_t> referenced;
    for (const DataReference& ref : dataRefs) referenced.insert(ref.address);
    for (const CodeDataStringInput& string : strings) {
        if (!string.byteSize || !rangeContains(ranges, string.address) ||
            codeContains(codeClaims, string.address)) continue;
        const bool used = referenced.count(string.address) != 0;
        addClaim(claims, string.address, string.byteSize, CodeDataKind::String,
                 string.wide ? 2 : 1,
                 used ? CodeDataConfidence::High : CodeDataConfidence::Medium,
                 used ? 135 : 118,
                 used ? "printable string referenced by reachable code" :
                        "bounded printable string outside reachable code");
    }

    // Every remaining reachable reference into executable storage is a literal
    // island candidate. Never override bytes already proven reachable as code.
    std::sort(dataRefs.begin(), dataRefs.end(), [](const DataReference& a, const DataReference& b) {
        return a.address < b.address;
    });
    dataRefs.erase(std::unique(dataRefs.begin(), dataRefs.end(), [](const auto& a, const auto& b) {
        return a.address == b.address && a.width == b.width;
    }), dataRefs.end());
    for (const DataReference& ref : dataRefs) {
        if (codeContains(codeClaims, ref.address)) continue;
        addClaim(claims, ref.address, ref.width, CodeDataKind::LiteralPool, ref.width,
                 CodeDataConfidence::High, 130, ref.evidence);
    }

    // Classify common linker padding outside code/tables/strings/literals. NOP and
    // INT3 runs need four bytes; all-zero runs need eight to avoid labelling a
    // single scalar zero as alignment.
    std::vector<Claim> prePadding;
    prePadding.reserve(claims.size());
    for (const Claim& claim : claims)
        prePadding.push_back({claim.address, claim.size, CodeDataKind::Data, 1,
                              CodeDataConfidence::High, 1, {}});
    std::sort(prePadding.begin(), prePadding.end(), [](const Claim& a, const Claim& b) {
        return a.address < b.address;
    });
    std::vector<Claim> covered;
    covered.reserve(prePadding.size());
    for (Claim claim : prePadding) {
        if (!claim.size) continue;
        if (!covered.empty()) {
            Claim& last = covered.back();
            const uint64_t lastEnd = boundedEnd(last.address, last.size);
            if (claim.address <= lastEnd) {
                const uint64_t claimEnd = boundedEnd(claim.address, claim.size);
                if (claimEnd > lastEnd) last.size = claimEnd - last.address;
                continue;
            }
        }
        covered.push_back(std::move(claim));
    }
    prePadding = std::move(covered);
    // ISA-native alignment NOPs are often multi-byte instructions rather than a
    // run of 0x90. Only inspect bytes outside all stronger claims, and require an
    // exact known encoding (or an x86 decoder-confirmed multi-byte NOP).
    for (const ExecRange& range : ranges) {
        size_t available = 0;
        const uint8_t* p = bin.ptrFromVA(range.address, available);
        const size_t n = static_cast<size_t>(std::min<uint64_t>(available, range.size));
        CoveredClaimCursor coverage(prePadding, range.address);
        std::vector<uint8_t> fixedNop;
        if (arch == Arch::ARM64) fixedNop = {0x1F, 0x20, 0x03, 0xD5};
        else if (arch == Arch::ARM) fixedNop = {0x00, 0xF0, 0x20, 0xE3};
        else if (arch == Arch::THUMB) fixedNop = {0x00, 0xBF};
        if (!fixedNop.empty()) {
            for (size_t i = 0; i + fixedNop.size() <= n;) {
                if (const uint64_t covered = coverage.coveredBytesAt(range.address + i)) {
                    const size_t skip = static_cast<size_t>(std::min<uint64_t>(covered, n - i));
                    i += skip;
                    // Retain the original scan's ISA stride even when a string
                    // or literal claim ends between instruction-aligned bytes.
                    i += std::min(n - i, (fixedNop.size() - skip % fixedNop.size()) % fixedNop.size());
                    continue;
                }
                if (std::memcmp(p + i, fixedNop.data(), fixedNop.size()) != 0) {
                    i += std::max<size_t>(1, fixedNop.size());
                    continue;
                }
                size_t end = i;
                while (end + fixedNop.size() <= n &&
                       !coverage.coveredBytesAt(range.address + end) &&
                       std::memcmp(p + end, fixedNop.data(), fixedNop.size()) == 0)
                    end += fixedNop.size();
                addClaim(claims, range.address + i, end - i, CodeDataKind::Padding, 1,
                         CodeDataConfidence::High, 115,
                         std::string(ArchName(arch)) + " alignment NOP instruction(s)");
                i = end;
            }
        } else if (ArchIsX86(arch)) {
            for (size_t i = 0; i < n;) {
                if (const uint64_t covered = coverage.coveredBytesAt(range.address + i)) {
                    i += static_cast<size_t>(std::min<uint64_t>(covered, n - i));
                    continue;
                }
                if (p[i] != 0x0F && p[i] != 0x66) { ++i; continue; }
                size_t end = i;
                while (end < n && !coverage.coveredBytesAt(range.address + end) &&
                       (p[end] == 0x0F || p[end] == 0x66 || p[end] == 0x90)) {
                    Instruction nop;
                    if (!validInstructionAt(bin, dis, ranges, range.address + end, &nop) ||
                        lowerCopy(nop.mnemonic) != "nop") break;
                    end += nop.length;
                }
                if (end - i >= 3)
                    addClaim(claims, range.address + i, end - i, CodeDataKind::Padding, 1,
                             CodeDataConfidence::High, 115,
                             "decoder-confirmed x86 multi-byte NOP alignment run");
                i = end > i ? end : i + 1;
            }
        }
    }
    for (const ExecRange& range : ranges) {
        size_t available = 0;
        const uint8_t* p = bin.ptrFromVA(range.address, available);
        const size_t n = static_cast<size_t>(std::min<uint64_t>(available, range.size));
        CoveredClaimCursor coverage(prePadding, range.address);
        for (size_t i = 0; i < n;) {
            const uint64_t address = range.address + i;
            if (const uint64_t covered = coverage.coveredBytesAt(address)) {
                i += static_cast<size_t>(std::min<uint64_t>(covered, n - i));
                continue;
            }
            const uint8_t value = p[i];
            const bool candidate = value == 0x00 ||
                (ArchIsX86(arch) && (value == 0x90 || value == 0xCC));
            if (!candidate) { ++i; continue; }
            size_t end = i + 1;
            while (end < n && p[end] == value &&
                   !coverage.coveredBytesAt(range.address + end)) ++end;
            const size_t minimum = value == 0 ? 8 : 4;
            if (end - i >= minimum)
                addClaim(claims, address, end - i, CodeDataKind::Padding, 1,
                         CodeDataConfidence::High, 115,
                         value == 0x90 ? "repeated x86 NOP alignment bytes" :
                         value == 0xCC ? "repeated INT3 linker fill" :
                                         "zero-filled alignment run outside reachable code");
            i = end;
        }
    }

    mergeClaims(claims);
    partitionRanges(ranges, claims, out);
    for (const CodeDataSpan& span : out.spans) addStats(out.stats, span);
    for (auto& seed : recoveredSeeds) out.functionSeeds.push_back({seed.first, std::move(seed.second)});
    std::sort(out.functionSeeds.begin(), out.functionSeeds.end(),
              [](const auto& a, const auto& b) { return a.address < b.address; });
    return out;
}

} // namespace ds
