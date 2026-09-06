#include "Core/FirmwareSniffer.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace ds {
namespace {

constexpr uint64_t kFourGiB = 0x100000000ull;
constexpr uint64_t kOneMiB  = 0x00100000ull;

int ConfidenceRank(FirmwareConfidence c) {
    return static_cast<int>(c);
}

FirmwareConfidence MaxConfidence(FirmwareConfidence a, FirmwareConfidence b) {
    return ConfidenceRank(a) >= ConfidenceRank(b) ? a : b;
}

bool Fits(size_t size, uint64_t offset, uint64_t length) {
    return offset <= static_cast<uint64_t>(size) &&
           length <= static_cast<uint64_t>(size) - offset;
}

bool AddU64(uint64_t a, uint64_t b, uint64_t& out) {
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

bool AddSigned(uint64_t base, int64_t displacement, uint64_t& out) {
    if (displacement >= 0)
        return AddU64(base, static_cast<uint64_t>(displacement), out);
    // Avoid negating INT64_MIN.
    const uint64_t magnitude = static_cast<uint64_t>(-(displacement + 1)) + 1;
    if (magnitude > base) return false;
    out = base - magnitude;
    return true;
}

int64_t SignExtend(uint64_t value, unsigned bits) {
    const uint64_t sign = uint64_t{1} << (bits - 1);
    const uint64_t range = uint64_t{1} << bits;
    return value < sign ? static_cast<int64_t>(value)
                        : -static_cast<int64_t>(range - value);
}

uint16_t U16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

uint32_t U32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t U64(const uint8_t* p) {
    return static_cast<uint64_t>(U32(p)) |
           (static_cast<uint64_t>(U32(p + 4)) << 32);
}

std::string Hex(uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
}

FirmwareAddress MakeAddress(uint64_t offset, uint64_t imageBase) {
    FirmwareAddress a;
    a.valid = true;
    a.fileOffset = offset;
    a.virtualAddressValid = AddU64(imageBase, offset, a.virtualAddress);
    return a;
}

bool MapFarTarget(uint64_t linear,
                  size_t size,
                  uint64_t imageBase,
                  uint64_t& offsetOut) {
    // First honor a direct conventional mapping, e.g. an option ROM at C0000h.
    if (linear >= imageBase) {
        const uint64_t delta = linear - imageBase;
        if (delta < static_cast<uint64_t>(size)) {
            offsetOut = delta;
            return true;
        }
    }

    // System BIOS real-mode addresses alias the final (at most) 1 MiB of a
    // top-mapped image. Do not manufacture a 20-bit wrap for >FFFFFh targets.
    if (linear >= kOneMiB || size == 0) return false;
    const uint64_t tailSpan = std::min<uint64_t>(static_cast<uint64_t>(size), kOneMiB);
    const uint64_t lowBase = kOneMiB - tailSpan;
    if (linear < lowBase) return false;
    offsetOut = static_cast<uint64_t>(size) - tailSpan + (linear - lowBase);
    return offsetOut < static_cast<uint64_t>(size);
}

bool IsBiosDate(const uint8_t* p, size_t n) {
    if (n < 8) return false;
    const auto digit = [](uint8_t c) { return c >= '0' && c <= '9'; };
    if (!digit(p[0]) || !digit(p[1]) || p[2] != '/' ||
        !digit(p[3]) || !digit(p[4]) || p[5] != '/' ||
        !digit(p[6]) || !digit(p[7])) return false;
    const unsigned month = (p[0] - '0') * 10u + (p[1] - '0');
    const unsigned day   = (p[3] - '0') * 10u + (p[4] - '0');
    return month >= 1 && month <= 12 && day >= 1 && day <= 31;
}

bool IsPowerOfTwo(size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

bool Checksum8(const uint8_t* p, size_t n) {
    uint8_t sum = 0;
    for (size_t i = 0; i < n; ++i) sum = static_cast<uint8_t>(sum + p[i]);
    return sum == 0;
}

bool Checksum16(const uint8_t* p, size_t n) {
    if ((n & 1u) != 0) return false;
    uint16_t sum = 0;
    for (size_t i = 0; i < n; i += 2)
        sum = static_cast<uint16_t>(sum + U16(p + i));
    return sum == 0;
}

bool IsKnownFfsGuid(const uint8_t* p) {
    // EFI_FIRMWARE_FILE_SYSTEM2_GUID and EFI_FIRMWARE_FILE_SYSTEM3_GUID in
    // their little-endian in-memory encodings.
    static constexpr std::array<uint8_t, 16> ffs2 = {
        0x78,0xE5,0x8C,0x8C, 0x3D,0x8A, 0x1C,0x4F,
        0x99,0x35,0x89,0x61,0x85,0xC3,0x2D,0xD3
    };
    static constexpr std::array<uint8_t, 16> ffs3 = {
        0x7A,0xC0,0x73,0x54, 0xCB,0x3D, 0xCA,0x4D,
        0xBD,0x6F,0x1E,0x96,0x89,0xE7,0x34,0x9A
    };
    return std::equal(ffs2.begin(), ffs2.end(), p) ||
           std::equal(ffs3.begin(), ffs3.end(), p);
}

template <typename Fn>
void ForScanOffsets(size_t size, size_t budget, Fn&& fn) {
    if (size == 0 || budget == 0) return;
    if (size <= budget) {
        for (size_t i = 0; i < size; ++i) fn(i);
        return;
    }
    const size_t head = budget / 2;
    const size_t tail = budget - head;
    for (size_t i = 0; i < head; ++i) fn(i);
    const size_t tailStart = size - tail;
    for (size_t i = tailStart; i < size; ++i) fn(i);
}

struct ResultBuilder {
    FirmwareDetection result;
    const FirmwareSniffOptions& options;

    void evidence(FirmwareConfidence confidence, uint64_t offset, std::string summary) {
        if (result.evidence.size() >= options.maxEvidence) return;
        result.evidence.push_back({confidence, offset, std::move(summary)});
    }

    void landmark(FirmwareLandmarkKind kind,
                  FirmwareAddress location,
                  std::string name,
                  bool code,
                  FirmwareConfidence confidence,
                  std::string why) {
        if (result.landmarks.size() >= options.maxLandmarks) return;
        FirmwareLandmark l;
        l.kind = kind;
        l.location = location;
        l.name = std::move(name);
        l.code = code;
        l.confidence = confidence;
        l.evidence = std::move(why);
        result.landmarks.push_back(std::move(l));
    }
};

FirmwareCpuMode MachineMode(uint16_t machine) {
    if (machine == 0x014c) return FirmwareCpuMode::X86_32;
    if (machine == 0x8664) return FirmwareCpuMode::X86_64;
    if (machine == 0x01c0) return FirmwareCpuMode::ARM_A32;      // IMAGE_FILE_MACHINE_ARM
    if (machine == 0x01c2 || machine == 0x01c4)
        return FirmwareCpuMode::ARM_Thumb;                       // THUMB / ARMNT (Thumb-2)
    if (machine == 0xaa64) return FirmwareCpuMode::ARM_AArch64;
    return FirmwareCpuMode::Unknown;
}

struct ModeCandidate {
    FirmwareCpuMode mode = FirmwareCpuMode::Unknown;
    FirmwareConfidence confidence = FirmwareConfidence::None;
    int priority = 0;
    std::string evidence;
};

struct PeProbe {
    bool valid = false;
    FirmwareCpuMode mode = FirmwareCpuMode::Unknown;
    bool entryResolved = false;
    uint64_t entryOffset = 0;
};

PeProbe ProbePeImage(const uint8_t* data,
                     size_t size,
                     uint64_t imageOffset,
                     uint64_t containerEnd) {
    PeProbe result;
    if (!Fits(size, imageOffset, 0x40) || containerEnd > static_cast<uint64_t>(size) ||
        imageOffset >= containerEnd || data[imageOffset] != 'M' || data[imageOffset + 1] != 'Z')
        return result;
    const uint32_t peRelative = U32(data + imageOffset + 0x3c);
    uint64_t pe = 0;
    if (!AddU64(imageOffset, peRelative, pe) || !Fits(size, pe, 24) ||
        pe + 24 > containerEnd || data[pe] != 'P' || data[pe + 1] != 'E' ||
        data[pe + 2] != 0 || data[pe + 3] != 0) return result;

    const uint16_t machine = U16(data + pe + 4);
    const uint16_t sectionCount = U16(data + pe + 6);
    const uint16_t optionalSize = U16(data + pe + 20);
    const uint64_t optional = pe + 24;
    uint64_t sectionTable = 0;
    uint64_t sectionBytes = 0;
    if (MachineMode(machine) == FirmwareCpuMode::Unknown || sectionCount == 0 || sectionCount > 96 ||
        optionalSize < 64 || !AddU64(optional, optionalSize, sectionTable) ||
        static_cast<uint64_t>(sectionCount) > std::numeric_limits<uint64_t>::max() / 40ull) return result;
    sectionBytes = static_cast<uint64_t>(sectionCount) * 40ull;
    if (!Fits(size, optional, optionalSize) || !Fits(size, sectionTable, sectionBytes) ||
        sectionTable + sectionBytes > containerEnd) return result;
    const uint16_t magic = U16(data + optional);
    if (magic != 0x10b && magic != 0x20b) return result;

    result.valid = true;
    result.mode = MachineMode(machine);
    const uint32_t entryRva = U32(data + optional + 16);
    const uint32_t sizeOfHeaders = U32(data + optional + 60);
    if (entryRva == 0) return result;

    uint64_t candidate = 0;
    if (entryRva < sizeOfHeaders && AddU64(imageOffset, entryRva, candidate) &&
        candidate < containerEnd) {
        result.entryResolved = true;
        result.entryOffset = candidate;
        return result;
    }
    for (uint16_t i = 0; i < sectionCount; ++i) {
        const uint64_t section = sectionTable + static_cast<uint64_t>(i) * 40ull;
        const uint32_t virtualSize = U32(data + section + 8);
        const uint32_t virtualAddress = U32(data + section + 12);
        const uint32_t rawSize = U32(data + section + 16);
        const uint32_t rawOffset = U32(data + section + 20);
        const uint64_t extent = std::max<uint64_t>(virtualSize, rawSize);
        if (entryRva < virtualAddress ||
            static_cast<uint64_t>(entryRva) - virtualAddress >= extent) continue;
        const uint64_t delta = static_cast<uint64_t>(entryRva) - virtualAddress;
        if (delta >= rawSize) return result; // virtual-only entry is not file-backed
        uint64_t rawRelative = 0;
        if (!AddU64(rawOffset, delta, rawRelative) ||
            !AddU64(imageOffset, rawRelative, candidate) || candidate >= containerEnd)
            return result;
        result.entryResolved = true;
        result.entryOffset = candidate;
        return result;
    }
    return result;
}

void ConsiderMode(ModeCandidate& current,
                  FirmwareCpuMode mode,
                  FirmwareConfidence confidence,
                  int priority,
                  const std::string& evidence) {
    if (mode == FirmwareCpuMode::Unknown) return;
    if (priority > current.priority ||
        (priority == current.priority && ConfidenceRank(confidence) > ConfidenceRank(current.confidence))) {
        current = {mode, confidence, priority, evidence};
    } else if (priority == current.priority && confidence == current.confidence && current.mode != mode) {
        // Equally strong conflicting machine evidence must not become a false
        // single-architecture recommendation.
        current = {FirmwareCpuMode::Unknown, FirmwareConfidence::Low, priority,
                   "equally strong firmware-image architecture evidence conflicts"};
    }
}

struct ArmProbeScore {
    FirmwareCpuMode mode = FirmwareCpuMode::Unknown;
    size_t alignment = 0;
    size_t sampleBegin = 0;
    size_t sampleEnd = 0;
    size_t prologues = 0;
    size_t framedPrologues = 0;
    size_t returns = 0;
    size_t calls = 0;
    size_t branches = 0;
    int score = 0;
};

bool BetterArmProbe(const ArmProbeScore& a, const ArmProbeScore& b) {
    if (a.score != b.score) return a.score > b.score;
    const size_t ar = a.framedPrologues + a.returns;
    const size_t br = b.framedPrologues + b.returns;
    return ar != br ? ar > br : a.calls > b.calls;
}

// Score instruction *motifs*, not isolated opcodes. Random data produces an
// occasional branch-looking word; a saved-LR prologue followed by a frame setup
// and a matching return is much rarer and much more useful evidence. Work is
// bounded to deterministic head/tail windows and four alignment hypotheses.
ArmProbeScore ScoreA32(const uint8_t* data, size_t begin, size_t end, size_t align) {
    ArmProbeScore s; s.mode = FirmwareCpuMode::ARM_A32; s.alignment = align;
    s.sampleBegin = begin; s.sampleEnd = end;
    if (end <= begin + align + 4) return s;
    size_t lastPrologue = (std::numeric_limits<size_t>::max)();
    bool lastFramed = false;
    for (size_t off = begin + align; off + 4 <= end; off += 4) {
        const uint32_t w = U32(data + off);
        if (w == 0 || w == 0xffffffffu) continue;
        const bool pushLr = (w & 0x0fff4000u) == 0x092d4000u;
        const bool saveLr = (w & 0x0ffff000u) == 0x052de000u;
        if (pushLr || saveLr) {
            ++s.prologues; lastPrologue = off; lastFramed = false;
        } else if (lastPrologue != (std::numeric_limits<size_t>::max)() &&
                   off - lastPrologue <= 16) {
            // add fp,sp,#imm / mov fp,sp / sub sp,sp,#imm
            const bool frame = (w & 0x0ffff000u) == 0x028db000u ||
                               (w & 0x0ffffff0u) == 0x01a0b00du ||
                               (w & 0x0ffff000u) == 0x024dd000u;
            if (frame && !lastFramed) { ++s.framedPrologues; lastFramed = true; }
        }
        const bool bxLr = (w & 0x0fffffffu) == 0x012fff1eu;
        const bool popPc = (w & 0x0fff8000u) == 0x08bd8000u;
        if (bxLr || popPc) ++s.returns;
        if ((w & 0x0f000000u) == 0x0b000000u) ++s.calls;
        else if ((w & 0x0e000000u) == 0x0a000000u) ++s.branches;
    }
    const size_t pairs = std::min(s.framedPrologues, s.returns);
    s.score = static_cast<int>(pairs * 28 + s.framedPrologues * 12 +
                               s.prologues * 3 + s.returns * 4 +
                               std::min<size_t>(s.calls, 24) +
                               std::min<size_t>(s.branches, 12) / 3);
    return s;
}

ArmProbeScore ScoreA64(const uint8_t* data, size_t begin, size_t end, size_t align) {
    ArmProbeScore s; s.mode = FirmwareCpuMode::ARM_AArch64; s.alignment = align;
    s.sampleBegin = begin; s.sampleEnd = end;
    if (end <= begin + align + 4) return s;
    size_t lastPrologue = (std::numeric_limits<size_t>::max)();
    bool lastFramed = false;
    for (size_t off = begin + align; off + 4 <= end; off += 4) {
        const uint32_t w = U32(data + off);
        if (w == 0 || w == 0xffffffffu) continue;
        // stp x29,x30,[sp,#-imm]!; the immediate is deliberately ignored.
        if ((w & 0xffc07fffu) == 0xa9807bfdu) {
            ++s.prologues; lastPrologue = off; lastFramed = false;
        } else if (w == 0xd503233fu) { // PACIASP commonly precedes the frame save
            lastPrologue = off;
        } else if (lastPrologue != (std::numeric_limits<size_t>::max)() &&
                   off - lastPrologue <= 12 && w == 0x910003fdu && !lastFramed) {
            ++s.framedPrologues; lastFramed = true; // mov x29,sp
        }
        if ((w & 0xfffffc1fu) == 0xd65f0000u) ++s.returns;
        if ((w & 0xfc000000u) == 0x94000000u) ++s.calls;
        else if ((w & 0xfc000000u) == 0x14000000u ||
                 (w & 0xff000010u) == 0x54000000u) ++s.branches;
    }
    const size_t pairs = std::min(s.framedPrologues, s.returns);
    s.score = static_cast<int>(pairs * 30 + s.framedPrologues * 14 +
                               s.prologues * 4 + s.returns * 5 +
                               std::min<size_t>(s.calls, 24) +
                               std::min<size_t>(s.branches, 12) / 3);
    return s;
}

ArmProbeScore ScoreThumb(const uint8_t* data, size_t begin, size_t end, size_t align) {
    ArmProbeScore s; s.mode = FirmwareCpuMode::ARM_Thumb; s.alignment = align;
    s.sampleBegin = begin; s.sampleEnd = end;
    if (end <= begin + align + 2) return s;
    size_t lastPrologue = (std::numeric_limits<size_t>::max)();
    bool lastFramed = false;
    for (size_t off = begin + align; off + 2 <= end; off += 2) {
        const uint16_t h = U16(data + off);
        const uint16_t h2 = off + 4 <= end ? U16(data + off + 2) : 0;
        const bool pushLr16 = (h & 0xff00u) == 0xb500u;
        const bool pushLr32 = h == 0xe92du && (h2 & 0x4000u) != 0;
        if (pushLr16 || pushLr32) {
            ++s.prologues; lastPrologue = off; lastFramed = false;
        } else if (lastPrologue != (std::numeric_limits<size_t>::max)() &&
                   off - lastPrologue <= 12) {
            const bool frame = (h & 0xff80u) == 0xb080u || // sub sp,#imm
                               (h & 0xff00u) == 0xaf00u || // add r7,sp,#imm
                               h == 0x466fu;                // mov r7,sp
            if (frame && !lastFramed) { ++s.framedPrologues; lastFramed = true; }
        }
        if ((h & 0xff00u) == 0xbd00u || h == 0x4770u) ++s.returns;
        if ((h & 0xf800u) == 0xf000u && (h2 & 0xd000u) == 0xd000u) ++s.calls;
        else if ((h & 0xf800u) == 0xe000u ||
                 ((h & 0xf000u) == 0xd000u && (h & 0x0f00u) < 0x0e00u)) ++s.branches;
    }
    const size_t pairs = std::min(s.framedPrologues, s.returns);
    s.score = static_cast<int>(pairs * 30 + s.framedPrologues * 14 +
                               s.prologues * 3 + s.returns * 3 +
                               std::min<size_t>(s.calls, 24) +
                               std::min<size_t>(s.branches, 12) / 3);
    return s;
}

void ProbeArmInstructionMode(const uint8_t* data, size_t size, size_t budget,
                             ModeCandidate& mode, ResultBuilder& out) {
    if (!data || size < 16 || budget == 0) return;
    // Four KiB sub-windows keep container headers/filler from diluting a code
    // island. At most 1 MiB is inspected regardless of the general scan budget.
    const size_t cap = std::min<size_t>({size, budget, 1024u * 1024u});
    std::vector<std::pair<size_t,size_t>> ranges;
    const auto addWindows = [&](size_t begin, size_t length) {
        const size_t end = begin + length;
        for (size_t p = begin; p < end; p += 4096) ranges.push_back({p, std::min(end, p + 4096)});
    };
    if (size <= cap) addWindows(0, size);
    else {
        const size_t head = cap / 2, tail = cap - head;
        addWindows(0, head); addWindows(size - tail, tail);
    }

    ArmProbeScore best, bestA32, bestThumb, bestA64;
    for (const auto& [begin, end] : ranges) {
        for (size_t a = 0; a < 4; ++a) {
            for (ArmProbeScore s : {ScoreA32(data, begin, end, a), ScoreA64(data, begin, end, a)}) {
                ArmProbeScore& perMode = s.mode == FirmwareCpuMode::ARM_A32 ? bestA32 : bestA64;
                if (BetterArmProbe(s, perMode)) perMode = s;
                if (BetterArmProbe(s, best)) best = s;
            }
        }
        for (size_t a = 0; a < 2; ++a) {
            ArmProbeScore s = ScoreThumb(data, begin, end, a);
            if (BetterArmProbe(s, bestThumb)) bestThumb = s;
            if (BetterArmProbe(s, best)) best = s;
        }
    }

    const size_t coherentPairs = std::min(best.framedPrologues, best.returns);
    int alternative = 0;
    if (best.mode != FirmwareCpuMode::ARM_A32) alternative = std::max(alternative, bestA32.score);
    if (best.mode != FirmwareCpuMode::ARM_Thumb) alternative = std::max(alternative, bestThumb.score);
    if (best.mode != FirmwareCpuMode::ARM_AArch64) alternative = std::max(alternative, bestA64.score);
    const int margin = best.score - alternative;
    std::ostringstream scores;
    scores << "A32=" << bestA32.score << ", Thumb=" << bestThumb.score
           << ", AArch64=" << bestA64.score << "; best sampled [+0x"
           << std::hex << std::uppercase << best.sampleBegin << ",+0x" << best.sampleEnd
           << std::dec << "), margin " << margin;
    if (best.framedPrologues < 3 || coherentPairs < 3 || best.score < 100 || margin < 20) {
        // Preserve ambiguity as evidence without changing the editable x64 raw
        // default. Very low/no-signal blobs stay quiet.
        if (best.score >= 20)
            out.evidence(FirmwareConfidence::Low, best.sampleBegin,
                         "ARM instruction-motif probe inconclusive: " + scores.str() +
                         " (requires >=3 framed prologue/return pairs, score>=100, margin>=20)");
        return;
    }
    FirmwareConfidence confidence = FirmwareConfidence::Low;
    if (coherentPairs >= 6 && margin >= 30) confidence = FirmwareConfidence::High;
    else if (coherentPairs >= 3 && margin >= 20) confidence = FirmwareConfidence::Medium;
    std::ostringstream why;
    why << "bounded instruction-motif probe: " << best.framedPrologues
        << " framed prologue(s), " << best.returns << " return(s), "
        << best.calls << " call encoding(s), alignment +" << best.alignment
        << "; " << scores.str();
    ConsiderMode(mode, best.mode, confidence, 25, why.str());
    out.evidence(confidence, 0, std::string(FirmwareCpuModeName(best.mode)) + ": " + why.str());
}

void ScanExecutableMachine(const uint8_t* data,
                           size_t size,
                           uint64_t begin,
                           uint64_t length,
                           size_t scanBudget,
                           ModeCandidate& mode,
                           ResultBuilder& out,
                           size_t& executableIndex) {
    if (!Fits(size, begin, length) || length < 4 || scanBudget == 0) return;
    const size_t regionSize = static_cast<size_t>(length);
    const size_t budget = std::min(regionSize, scanBudget);
    ForScanOffsets(regionSize, budget, [&](size_t relative) {
        const uint64_t absolute = begin + static_cast<uint64_t>(relative);
        if (!Fits(size, absolute, 4)) return;
        FirmwareCpuMode found = FirmwareCpuMode::Unknown;
        const char* form = nullptr;
        if (data[absolute] == 'M' && data[absolute + 1] == 'Z' && Fits(size, absolute, 0x40)) {
            const uint32_t peRel = U32(data + absolute + 0x3c);
            uint64_t pe = 0;
            if (AddU64(absolute, peRel, pe) && Fits(size, pe, 6) &&
                pe >= begin && pe + 6 <= begin + length &&
                data[pe] == 'P' && data[pe + 1] == 'E' && data[pe + 2] == 0 && data[pe + 3] == 0) {
                found = MachineMode(U16(data + pe + 4));
                form = "PE/COFF";
            }
        } else if (data[absolute] == 'V' && data[absolute + 1] == 'Z' &&
                   Fits(size, absolute, 40)) {
            const uint8_t sections = data[absolute + 4];
            const uint8_t subsystem = data[absolute + 5];
            if (sections >= 1 && sections <= 96 && subsystem >= 10 && subsystem <= 13) {
                found = MachineMode(U16(data + absolute + 2));
                form = "TE";
            }
        }
        if (found == FirmwareCpuMode::Unknown) return;

        const std::string why = std::string(form) + " firmware image declares " +
                                FirmwareCpuModeName(found);
        ConsiderMode(mode, found, FirmwareConfidence::High, 60, why);
        out.evidence(FirmwareConfidence::High, absolute, why);
        out.landmark(FirmwareLandmarkKind::EfiImage,
                     FirmwareAddress{true, absolute, false, 0},
                     "uefi_image_" + std::to_string(executableIndex++),
                     false, FirmwareConfidence::High,
                     why + "; image header is a landmark, not an inferred function entry");
    });
}

} // namespace

const char* FirmwareConfidenceName(FirmwareConfidence confidence) {
    switch (confidence) {
        case FirmwareConfidence::None:   return "none";
        case FirmwareConfidence::Low:    return "low";
        case FirmwareConfidence::Medium: return "medium";
        case FirmwareConfidence::High:   return "high";
    }
    return "none";
}

const char* FirmwareKindName(FirmwareKind kind) {
    switch (kind) {
        case FirmwareKind::None:                 return "unknown";
        case FirmwareKind::LegacyBios:           return "legacy BIOS";
        case FirmwareKind::UefiFirmware:         return "UEFI firmware";
        case FirmwareKind::PciOptionRom:         return "PCI option ROM";
        case FirmwareKind::IntelFlashDescriptor: return "Intel flash image";
    }
    return "hybrid firmware";
}

const char* FirmwareCpuModeName(FirmwareCpuMode mode) {
    switch (mode) {
        case FirmwareCpuMode::Unknown:   return "unknown";
        case FirmwareCpuMode::X86Real16: return "x86-16 real mode";
        case FirmwareCpuMode::X86_32:    return "x86";
        case FirmwareCpuMode::X86_64:    return "x64";
        case FirmwareCpuMode::ARM_A32:   return "ARM (A32)";
        case FirmwareCpuMode::ARM_Thumb: return "Thumb/Thumb-2";
        case FirmwareCpuMode::ARM_AArch64: return "AArch64";
    }
    return "unknown";
}

FirmwareJump ResolveFirmwareX86Jump(const uint8_t* data,
                                    size_t size,
                                    uint64_t fileOffset,
                                    uint64_t imageBase,
                                    FirmwareCpuMode mode) {
    FirmwareJump result;
    if (!data || !Fits(size, fileOffset, 1)) return result;
    result.source = MakeAddress(fileOffset, imageBase);

    uint64_t cursor = fileOffset;
    bool operandOverride = false;
    if (data[cursor] == 0x66) {
        operandOverride = true;
        ++cursor;
        if (!Fits(size, cursor, 1)) return FirmwareJump{};
    }

    const uint8_t opcode = data[cursor];
    uint64_t targetOffset = 0;
    uint64_t instructionEnd = 0;
    const auto resolveRelative = [&](uint64_t length, int64_t displacement) {
        if (!AddU64(fileOffset, length, instructionEnd)) return false;
        if (mode == FirmwareCpuMode::X86Real16) {
            uint64_t endVa = 0;
            if (!AddU64(imageBase, instructionEnd, endVa)) {
                // The file-relative target remains useful even when a caller
                // supplied an overflowing virtual mapping; only the VA is then
                // withheld by MakeAddress().
                return AddSigned(instructionEnd, displacement, targetOffset) &&
                       targetOffset < static_cast<uint64_t>(size);
            }
            // Near transfers update IP, so a rel16 crossing FFFFh wraps within
            // the current 64-KiB code-segment window.  This is common at the
            // reset vector and differs from plain file-offset addition.
            const uint16_t endIp = static_cast<uint16_t>(endVa & 0xffffu);
            const uint16_t targetIp = static_cast<uint16_t>(
                static_cast<int64_t>(endIp) + displacement);
            const uint64_t targetVa = (endVa & ~0xffffull) | targetIp;
            if (targetVa < imageBase) return false;
            targetOffset = targetVa - imageBase;
            return targetOffset < static_cast<uint64_t>(size);
        }
        return AddSigned(instructionEnd, displacement, targetOffset) &&
               targetOffset < static_cast<uint64_t>(size);
    };
    if (opcode == 0xEB) {
        if (!Fits(size, cursor, 2)) return FirmwareJump{};
        const uint64_t length = (cursor - fileOffset) + 2;
        result.recognized = true;
        result.form = "short relative";
        result.instructionLength = static_cast<uint8_t>(length);
        const int64_t displacement = SignExtend(data[cursor + 1], 8);
        if (resolveRelative(length, displacement)) {
            result.targetResolved = true;
        }
    } else if (opcode == 0xE9) {
        const bool default32 = mode == FirmwareCpuMode::X86_32 || mode == FirmwareCpuMode::X86_64;
        // In 64-bit mode E9 always carries rel32; 66 does not select rel16.
        const bool displacement32 = mode == FirmwareCpuMode::X86_64
            ? true : (operandOverride ? !default32 : default32);
        const uint64_t immediateSize = displacement32 ? 4 : 2;
        if (!Fits(size, cursor, 1 + immediateSize)) return FirmwareJump{};
        const uint64_t length = (cursor - fileOffset) + 1 + immediateSize;
        result.recognized = true;
        result.form = "near relative";
        result.instructionLength = static_cast<uint8_t>(length);
        int64_t displacement = 0;
        if (displacement32)
            displacement = SignExtend(U32(data + cursor + 1), 32);
        else
            displacement = SignExtend(U16(data + cursor + 1), 16);
        if (resolveRelative(length, displacement)) {
            result.targetResolved = true;
        }
    } else if (opcode == 0xEA && mode != FirmwareCpuMode::X86_64) {
        const bool default32 = mode == FirmwareCpuMode::X86_32;
        const bool offset32 = operandOverride ? !default32 : default32;
        const uint64_t offsetSize = offset32 ? 4 : 2;
        if (!Fits(size, cursor, 1 + offsetSize + 2)) return FirmwareJump{};
        const uint64_t length = (cursor - fileOffset) + 1 + offsetSize + 2;
        result.recognized = true;
        result.form = "far immediate";
        result.instructionLength = static_cast<uint8_t>(length);
        const uint64_t offsetPart = offset32 ? U32(data + cursor + 1)
                                             : U16(data + cursor + 1);
        const uint16_t segment = U16(data + cursor + 1 + offsetSize);
        uint64_t segmentBase = static_cast<uint64_t>(segment) << 4;
        uint64_t linear = 0;
        if (AddU64(segmentBase, offsetPart, linear) &&
            MapFarTarget(linear, size, imageBase, targetOffset)) {
            result.targetResolved = true;
            result.evidence = "far target " + Hex(segment) + ":" + Hex(offsetPart) +
                              " aliases file offset " + Hex(targetOffset);
        } else {
            result.evidence = "far target is outside the supplied image mapping";
        }
    } else {
        return FirmwareJump{};
    }

    if (result.targetResolved) {
        result.target = MakeAddress(targetOffset, imageBase);
        if (result.evidence.empty())
            result.evidence = result.form + " target resolves inside the image at " + Hex(targetOffset);
    } else if (result.evidence.empty()) {
        result.evidence = result.form + " target is outside the supplied image";
    }
    return result;
}

FirmwareDetection SniffFirmware(const uint8_t* data,
                                size_t size,
                                const FirmwareSniffOptions& options) {
    ResultBuilder out{{}, options};
    FirmwareDetection& result = out.result;
    if (!data || size == 0) return result;
    result.scanTruncated = size > options.maxScanBytes;

    const bool topMappingPossible = options.useTopOf4GiBMapping &&
                                    static_cast<uint64_t>(size) <= kFourGiB;
    const uint64_t topBase = topMappingPossible ? kFourGiB - static_cast<uint64_t>(size) : 0;
    ModeCandidate mode;

    // Independent of container recognition: a flat raw firmware/code blob can
    // still receive an evidence-scored editable ARM-mode preselection.
    ProbeArmInstructionMode(data, size, options.maxScanBytes, mode, out);

    // ---- UEFI firmware volumes --------------------------------------------
    size_t fvIndex = 0;
    size_t executableIndex = 0;
    ForScanOffsets(size, options.maxScanBytes, [&](size_t signatureOffset) {
        if (result.firmwareVolumes.size() >= options.maxFirmwareVolumes || signatureOffset < 0x28)
            return;
        if (!Fits(size, signatureOffset, 4) ||
            data[signatureOffset] != '_' || data[signatureOffset + 1] != 'F' ||
            data[signatureOffset + 2] != 'V' || data[signatureOffset + 3] != 'H') return;

        const uint64_t base = static_cast<uint64_t>(signatureOffset) - 0x28;
        if (!Fits(size, base, 0x38)) return;
        const uint64_t length = U64(data + base + 0x20);
        const uint16_t headerLength = U16(data + base + 0x30);
        const uint16_t extHeader = U16(data + base + 0x34);
        const uint8_t reserved = data[base + 0x36];
        const uint8_t revision = data[base + 0x37];
        // A PI length is 64-bit, but a larger-than-4-GiB x86 firmware volume is
        // not a credible raw image for this detector and is usually hostile
        // arithmetic. Truncated, otherwise sane volumes below that ceiling are
        // retained at medium confidence.
        if (length < 0x38 || length > kFourGiB ||
            headerLength < 0x38 || headerLength > length ||
            (headerLength & 1u) != 0 || !Fits(size, base, headerLength)) return;
        if (extHeader != 0 && (extHeader < 0x38 || extHeader >= length || (extHeader & 3u) != 0))
            return;

        FirmwareVolumeInfo fv;
        fv.fileOffset = base;
        fv.length = length;
        fv.headerLength = headerLength;
        fv.revision = revision;
        fv.complete = Fits(size, base, length);
        fv.checksumValid = Checksum16(data + base, headerLength);
        fv.knownFileSystemGuid = IsKnownFfsGuid(data + base + 0x10);

        // A bounded walk only needs to establish that the block map terminates
        // within the declared header. It does not trust block-count products.
        for (uint64_t p = base + 0x38; p + 8 <= base + headerLength; p += 8) {
            if (U32(data + p) == 0 && U32(data + p + 4) == 0) {
                fv.blockMapTerminated = true;
                break;
            }
        }
        const bool strict = fv.complete && fv.checksumValid && fv.blockMapTerminated &&
                            revision == 2 && reserved == 0;
        fv.confidence = strict ? FirmwareConfidence::High : FirmwareConfidence::Medium;
        result.firmwareVolumes.push_back(fv);
        result.kinds |= FirmwareKind::UefiFirmware;
        result.confidence = MaxConfidence(result.confidence, fv.confidence);

        std::string why = "_FVH with sane " + std::to_string(headerLength) +
                          "-byte header and " + std::to_string(length) + "-byte volume";
        if (fv.checksumValid) why += "; header checksum is valid";
        if (!fv.complete) why += "; declared volume is truncated";
        out.evidence(fv.confidence, base, why);
        out.landmark(FirmwareLandmarkKind::FirmwareVolume,
                     FirmwareAddress{true, base, false, 0},
                     "uefi_fv_" + std::to_string(fvIndex++), false,
                     fv.confidence, why);
        if (fv.complete)
            ScanExecutableMachine(data, size, base, length, options.maxScanBytes,
                                  mode, out, executableIndex);
    });

    // ---- PCI option ROMs ---------------------------------------------------
    size_t romIndex = 0;
    ForScanOffsets(size, options.maxScanBytes, [&](size_t romOffsetSize) {
        if (result.optionRoms.size() >= options.maxOptionRoms) return;
        const uint64_t romOffset = static_cast<uint64_t>(romOffsetSize);
        if (!Fits(size, romOffset, 0x1a) || data[romOffset] != 0x55 || data[romOffset + 1] != 0xaa)
            return;

        const bool efi = U32(data + romOffset + 4) == 0x00000ef1u;
        const uint64_t headerUnits = efi ? U16(data + romOffset + 2)
                                         : data[romOffset + 2];
        const uint16_t pcirRel = U16(data + romOffset + 0x18);
        uint64_t pcir = 0;
        if (headerUnits == 0 || !AddU64(romOffset, pcirRel, pcir) ||
            !Fits(size, pcir, 0x16) ||
            data[pcir] != 'P' || data[pcir + 1] != 'C' ||
            data[pcir + 2] != 'I' || data[pcir + 3] != 'R') return;
        const uint16_t pcirLength = U16(data + pcir + 0x0a);
        const uint16_t imageUnits = U16(data + pcir + 0x10);
        const uint64_t units = imageUnits != 0 ? imageUnits : headerUnits;
        if (pcirRel < 0x1a || pcirLength < 0x16 || !Fits(size, pcir, pcirLength) ||
            units > std::numeric_limits<uint64_t>::max() / 512ull) return;
        const uint64_t declaredSize = units * 512ull;
        uint64_t pcirEndRel = 0;
        if (declaredSize < 0x1a || !AddU64(pcirRel, pcirLength, pcirEndRel) ||
            pcirEndRel > declaredSize) return;

        PciOptionRomInfo rom;
        rom.fileOffset = romOffset;
        rom.declaredSize = declaredSize;
        rom.pcirOffset = pcir;
        rom.vendorId = U16(data + pcir + 4);
        rom.deviceId = U16(data + pcir + 6);
        rom.pcirLength = pcirLength;
        rom.codeType = data[pcir + 0x14];
        rom.lastImage = (data[pcir + 0x15] & 0x80u) != 0;
        rom.efiImage = efi && rom.codeType == 0x03;
        if (efi) {
            rom.efiMachine = U16(data + romOffset + 0x0a);
            rom.efiImageOffset = U16(data + romOffset + 0x16);
            rom.efiCompressionType = U16(data + romOffset + 0x0c);
        }
        rom.complete = Fits(size, romOffset, declaredSize);
        rom.checksumValid = rom.complete && Checksum8(data + romOffset,
                                                       static_cast<size_t>(declaredSize));
        rom.confidence = rom.complete ? FirmwareConfidence::High : FirmwareConfidence::Medium;
        result.optionRoms.push_back(rom);
        result.kinds |= FirmwareKind::PciOptionRom;
        result.confidence = MaxConfidence(result.confidence, rom.confidence);

        std::string why = "55 AA header and bounded PCIR metadata declare " +
                          std::to_string(declaredSize) + " bytes, code type " +
                          Hex(rom.codeType);
        if (rom.checksumValid) why += "; image checksum is valid";
        if (!rom.complete) why += "; declared image is truncated";
        out.evidence(rom.confidence, romOffset, why);

        const bool standalone = romOffset == 0;
        const uint64_t romMapBase = options.optionRomBase;
        FirmwareAddress headerAddress = standalone ? MakeAddress(romOffset, romMapBase)
                                                   : FirmwareAddress{true, romOffset, false, 0};
        out.landmark(FirmwareLandmarkKind::PciRomHeader, headerAddress,
                     "pci_option_rom_" + std::to_string(romIndex), false,
                     rom.confidence, why);
        FirmwareAddress pcirAddress = standalone ? MakeAddress(pcir, romMapBase)
                                                 : FirmwareAddress{true, pcir, false, 0};
        out.landmark(FirmwareLandmarkKind::PcirData, pcirAddress,
                     "pcir_" + std::to_string(romIndex), false,
                     rom.confidence, "PCI data structure");

        if (rom.codeType == 0x00) {
            ConsiderMode(mode, FirmwareCpuMode::X86Real16, FirmwareConfidence::High,
                         standalone ? 90 : 45,
                         "PCIR code type 0 identifies a PC-AT compatible IA-32 option ROM");
            if (Fits(size, romOffset, 4)) {
                const uint64_t init = romOffset + 3;
                FirmwareJump first = ResolveFirmwareX86Jump(data, size, init, romMapBase,
                                                             FirmwareCpuMode::X86Real16);
                uint64_t finalOffset = init;
                std::vector<FirmwareJump> chain;
                std::vector<uint64_t> seen;
                for (size_t depth = 0; depth < options.maxJumpDepth; ++depth) {
                    FirmwareJump jump = depth == 0 ? first :
                        ResolveFirmwareX86Jump(data, size, finalOffset, romMapBase,
                                               FirmwareCpuMode::X86Real16);
                    if (!jump.recognized || !jump.targetResolved) break;
                    chain.push_back(jump);
                    finalOffset = jump.target.fileOffset;
                    if (std::find(seen.begin(), seen.end(), finalOffset) != seen.end()) break;
                    seen.push_back(finalOffset);
                }
                const FirmwareAddress entryAddress = standalone
                    ? MakeAddress(finalOffset, romMapBase)
                    : FirmwareAddress{true, finalOffset, false, 0};
                out.landmark(FirmwareLandmarkKind::BootEntry, entryAddress,
                             "pci_init_" + std::to_string(romIndex), true,
                             rom.confidence, chain.empty() ? "legacy option-ROM initialization entry"
                                                          : "resolved legacy option-ROM initialization jump");
                if (standalone && (!result.entry.detected ||
                    ConfidenceRank(rom.confidence) > ConfidenceRank(result.entry.confidence))) {
                    result.entry.detected = true;
                    result.entry.location = entryAddress;
                    result.entry.mode = FirmwareCpuMode::X86Real16;
                    result.entry.confidence = rom.confidence;
                    result.entry.evidence = chain.empty()
                        ? "PCIR code-type 0 initialization entry at header + 3"
                        : "PCIR code-type 0 initialization jump resolved inside the ROM";
                    result.entry.jumpChain = std::move(chain);
                }
            }
        } else if (rom.efiImage) {
            const FirmwareCpuMode imageMode = MachineMode(rom.efiMachine);
            ConsiderMode(mode, imageMode, FirmwareConfidence::High, standalone ? 80 : 55,
                         "EFI option-ROM header declares machine " + Hex(rom.efiMachine));
            uint64_t imageOffset = 0;
            if (AddU64(romOffset, rom.efiImageOffset, imageOffset) &&
                imageOffset < static_cast<uint64_t>(size) &&
                rom.efiImageOffset < rom.declaredSize) {
                FirmwareAddress imageAddress = standalone
                    ? MakeAddress(imageOffset, romMapBase)
                    : FirmwareAddress{true, imageOffset, false, 0};
                out.landmark(FirmwareLandmarkKind::EfiImage, imageAddress,
                             "pci_efi_image_" + std::to_string(romIndex),
                             false,
                             FirmwareConfidence::High,
                             rom.efiCompressionType == 0
                                 ? "uncompressed EFI image header offset and PCIR code type agree"
                                 : "EFI image is compressed; location is structural, not a code seed");
                uint64_t containerEnd = 0;
                const bool containerValid = AddU64(romOffset, rom.declaredSize, containerEnd) &&
                                            containerEnd <= static_cast<uint64_t>(size);
                const PeProbe pe = rom.efiCompressionType == 0 && containerValid
                    ? ProbePeImage(data, size, imageOffset, containerEnd) : PeProbe{};
                const bool machineAgrees = pe.valid && pe.mode == imageMode;
                if (standalone && machineAgrees && pe.entryResolved &&
                    (!result.entry.detected || ConfidenceRank(FirmwareConfidence::High) >
                                               ConfidenceRank(result.entry.confidence))) {
                    const FirmwareAddress entryAddress = MakeAddress(pe.entryOffset, romMapBase);
                    out.landmark(FirmwareLandmarkKind::BootEntry, entryAddress,
                                 "pci_efi_entry_" + std::to_string(romIndex), true,
                                 FirmwareConfidence::High,
                                 "file-backed PE/COFF entry RVA resolved inside the option ROM");
                    result.entry.detected = true;
                    result.entry.location = entryAddress;
                    result.entry.mode = imageMode;
                    result.entry.confidence = FirmwareConfidence::High;
                    result.entry.evidence =
                        "EFI option-ROM PCIR/header machine agrees with a bounded PE/COFF entry";
                    result.entry.jumpChain.clear();
                }
            }
        }
        ++romIndex;
    });

    // ---- Intel flash descriptors ------------------------------------------
    size_t descriptorIndex = 0;
    const auto parseDescriptor = [&](size_t signatureOffsetSize) {
        if (result.flashDescriptors.size() >= options.maxFlashDescriptors || signatureOffsetSize < 0x10)
            return;
        const uint64_t signatureOffset = static_cast<uint64_t>(signatureOffsetSize);
        if (!Fits(size, signatureOffset, 4) || U32(data + signatureOffset) != 0x0ff0a55au)
            return;
        const uint64_t base = signatureOffset - 0x10;
        // The descriptor signature is defined at +10h from the bottom of flash;
        // requiring a 4-KiB-aligned candidate base rejects arbitrary occurrences.
        if ((base & 0xfffull) != 0 || !Fits(size, base, 0x18)) return;

        IntelFlashDescriptorInfo descriptor;
        descriptor.fileOffset = base;
        const uint32_t flmap0 = U32(data + base + 0x14);
        const uint64_t regionRel = static_cast<uint64_t>((flmap0 >> 16) & 0xffu) * 16ull;
        uint64_t regionTable = 0;
        const bool pointerValid = AddU64(base, regionRel, regionTable) &&
                                  regionRel >= 0x20 && regionRel < 0x1000 &&
                                  Fits(size, regionTable, 8);
        if (pointerValid) {
            const uint32_t descriptorRegion = U32(data + regionTable);
            const uint64_t descriptorBase = static_cast<uint64_t>(descriptorRegion & 0x7fffu) << 12;
            const uint64_t descriptorLimit =
                (static_cast<uint64_t>((descriptorRegion >> 16) & 0x7fffu) << 12) | 0xfffull;
            uint64_t absoluteDescriptor = 0;
            descriptor.mapValid = descriptorBase == 0 && descriptorBase <= descriptorLimit &&
                                  AddU64(base, descriptorBase, absoluteDescriptor) &&
                                  absoluteDescriptor <= static_cast<uint64_t>(size) &&
                                  descriptorLimit - descriptorBase <
                                      static_cast<uint64_t>(size) - absoluteDescriptor;
        }
        descriptor.regionTableOffset = descriptor.mapValid ? regionTable : 0;
        if (descriptor.mapValid) {
            const uint32_t bios = U32(data + regionTable + 4); // FLREG1: BIOS region
            const uint64_t regionBase = static_cast<uint64_t>(bios & 0x7fffu) << 12;
            const uint64_t regionLimit = (static_cast<uint64_t>((bios >> 16) & 0x7fffu) << 12) | 0xfffull;
            uint64_t absoluteRegion = 0;
            if (regionBase <= regionLimit && AddU64(base, regionBase, absoluteRegion) &&
                absoluteRegion <= static_cast<uint64_t>(size) &&
                regionLimit - regionBase < static_cast<uint64_t>(size) - absoluteRegion) {
                descriptor.biosRegionValid = true;
                descriptor.biosRegionOffset = absoluteRegion;
                descriptor.biosRegionSize = regionLimit - regionBase + 1;
            }
        }
        descriptor.confidence = descriptor.mapValid ? FirmwareConfidence::High
                                                    : FirmwareConfidence::Medium;
        result.flashDescriptors.push_back(descriptor);
        result.kinds |= FirmwareKind::IntelFlashDescriptor;
        result.confidence = MaxConfidence(result.confidence, descriptor.confidence);

        std::string why = "Intel descriptor signature 0FF0A55A at descriptor + 10h";
        if (descriptor.mapValid) why += "; FLMAP0 region-table pointer is bounded";
        else why += "; descriptor map is not trusted";
        out.evidence(descriptor.confidence, base, why);
        const FirmwareAddress descriptorAddress{true, base, false, 0};
        out.landmark(FirmwareLandmarkKind::FlashDescriptor, descriptorAddress,
                     "intel_flash_descriptor_" + std::to_string(descriptorIndex), false,
                     descriptor.confidence, why);
        if (descriptor.biosRegionValid) {
            const FirmwareAddress biosAddress{true, descriptor.biosRegionOffset, false, 0};
            out.landmark(FirmwareLandmarkKind::BiosRegion, biosAddress,
                         "bios_region_" + std::to_string(descriptorIndex), false,
                         FirmwareConfidence::High, "bounded BIOS region from FLREG1");
        }
        ++descriptorIndex;
    };
    // Intel defines the signature at flash-bottom + 10h. This fixed check is
    // useful even when the configurable pattern-scan budget is zero.
    if (Fits(size, 0x10, 4)) parseDescriptor(0x10);
    ForScanOffsets(size, options.maxScanBytes, [&](size_t signatureOffsetSize) {
        if (signatureOffsetSize != 0x10) parseDescriptor(signatureOffsetSize);
    });

    // ---- Top-of-4-GiB reset vector and legacy BIOS corroboration -----------
    bool resetRecognized = false;
    bool resetResolved = false;
    bool resetProgresses = false;
    bool biosDate = false;
    bool wholeChecksum = false;
    bool biosShape = false;
    if (size >= 16 && topMappingPossible) {
        const uint64_t resetOffset = static_cast<uint64_t>(size) - 16;
        FirmwareJump first = ResolveFirmwareX86Jump(data, size, resetOffset, topBase,
                                                     FirmwareCpuMode::X86Real16);
        resetRecognized = first.recognized;
        resetResolved = first.targetResolved;
        resetProgresses = resetResolved && first.target.fileOffset != resetOffset;
        biosDate = Fits(size, resetOffset + 5, 8) && IsBiosDate(data + resetOffset + 5, 8);
        const bool checksumBudgeted = size <= options.maxScanBytes;
        wholeChecksum = checksumBudgeted && Checksum8(data, size);
        biosShape = (size % 0x10000u) == 0 && IsPowerOfTwo(size / 0x10000u);

        if (resetRecognized) {
            std::vector<FirmwareJump> chain;
            uint64_t finalOffset = resetOffset;
            std::vector<uint64_t> seen{resetOffset};
            for (size_t depth = 0; depth < options.maxJumpDepth; ++depth) {
                FirmwareJump jump = depth == 0 ? first :
                    ResolveFirmwareX86Jump(data, size, finalOffset, topBase,
                                           FirmwareCpuMode::X86Real16);
                if (!jump.recognized || !jump.targetResolved) break;
                chain.push_back(jump);
                finalOffset = jump.target.fileOffset;
                if (std::find(seen.begin(), seen.end(), finalOffset) != seen.end()) break;
                seen.push_back(finalOffset);
            }

            FirmwareConfidence resetConfidence = resetProgresses ? FirmwareConfidence::Medium
                                                                 : FirmwareConfidence::Low;
            if (resetProgresses && (biosDate || wholeChecksum ||
                result.has(FirmwareKind::UefiFirmware) ||
                result.has(FirmwareKind::IntelFlashDescriptor)))
                resetConfidence = FirmwareConfidence::High;

            const FirmwareAddress resetAddress = MakeAddress(resetOffset, topBase);
            std::string resetWhy = "x86 reset-vector instruction at FFFFFFF0h";
            if (resetResolved) resetWhy += " resolves inside the top-mapped image";
            else resetWhy += " is recognized but its target is not mapped";
            out.evidence(resetConfidence, resetOffset, resetWhy);
            out.landmark(FirmwareLandmarkKind::ResetVector, resetAddress,
                         "reset_vector", true, resetConfidence, resetWhy);

            const FirmwareAddress finalAddress = MakeAddress(finalOffset, topBase);
            out.landmark(FirmwareLandmarkKind::BootEntry, finalAddress,
                         "firmware_boot_entry", true, resetConfidence,
                         chain.empty() ? "reset vector itself; target was not resolved"
                                       : "final target of bounded reset jump chain");
            result.entry.detected = true;
            result.entry.location = finalAddress;
            result.entry.mode = FirmwareCpuMode::X86Real16;
            result.entry.confidence = resetConfidence;
            result.entry.evidence = resetWhy;
            result.entry.jumpChain = std::move(chain);
            ConsiderMode(mode, FirmwareCpuMode::X86Real16, resetConfidence, 100,
                         "execution begins at the x86 architectural reset vector in real mode");
        }

        unsigned legacyScore = 0;
        if (resetProgresses) legacyScore += 2;
        else if (resetRecognized) legacyScore += 1;
        if (biosDate) legacyScore += 2;
        if (wholeChecksum) legacyScore += 1;
        if (biosShape) legacyScore += 1;

        // A modern UEFI image also has an x86 reset vector. Only label it as a
        // legacy BIOS when legacy-specific date/checksum corroboration remains.
        const bool modernContainer = result.has(FirmwareKind::UefiFirmware) ||
                                     result.has(FirmwareKind::IntelFlashDescriptor);
        const bool legacySpecific = biosDate || (wholeChecksum && !modernContainer);
        if (legacyScore >= 3 && legacySpecific) {
            const FirmwareConfidence c = legacyScore >= 5 ? FirmwareConfidence::High
                                                          : FirmwareConfidence::Medium;
            result.kinds |= FirmwareKind::LegacyBios;
            result.confidence = MaxConfidence(result.confidence, c);
            std::string why = "legacy BIOS layout corroborated by ";
            if (biosDate) why += "MM/DD/YY tail date";
            if (biosDate && wholeChecksum) why += " and ";
            if (wholeChecksum) why += "whole-image 8-bit checksum";
            out.evidence(c, resetOffset, why);
        }
    }

    // The mapping becomes a recommendation only after system-firmware evidence
    // exists; arbitrary raw files do not get silently mapped to 4 GiB.
    if (topMappingPossible && (resetProgresses ||
        result.has(FirmwareKind::IntelFlashDescriptor))) {
        result.recommendedImageBaseValid = true;
        result.recommendedImageBase = topBase;
        result.mappingEvidence = "image end aligned to 4 GiB so file offset size-16 maps to FFFFFFF0h";
    } else if (result.has(FirmwareKind::PciOptionRom) &&
               !result.optionRoms.empty() && result.optionRoms.front().fileOffset == 0) {
        uint64_t mappingEnd = 0;
        if (AddU64(options.optionRomBase, static_cast<uint64_t>(size), mappingEnd)) {
            result.recommendedImageBaseValid = true;
            result.recommendedImageBase = options.optionRomBase;
            result.mappingEvidence = "conventional standalone PCI option-ROM analysis base C0000h";
        }
    }

    // Structural records discovered before the mapping decision retain only a
    // file offset. Once a whole-image mapping is justified, enrich those
    // landmarks without changing their original evidence or confidence.
    if (result.recommendedImageBaseValid) {
        for (FirmwareLandmark& landmark : result.landmarks) {
            if (!landmark.location.valid || landmark.location.virtualAddressValid) continue;
            landmark.location.virtualAddressValid = AddU64(result.recommendedImageBase,
                                                            landmark.location.fileOffset,
                                                            landmark.location.virtualAddress);
        }
    }

    if (mode.mode != FirmwareCpuMode::Unknown || mode.priority != 0) {
        result.architecture.mode = mode.mode;
        result.architecture.confidence = mode.confidence;
        result.architecture.evidence = mode.evidence;
    }

    // Primary kind is a presentation choice; all corroborating flags remain.
    if (result.has(FirmwareKind::UefiFirmware))
        result.primaryKind = FirmwareKind::UefiFirmware;
    else if (result.has(FirmwareKind::LegacyBios))
        result.primaryKind = FirmwareKind::LegacyBios;
    else if (result.has(FirmwareKind::PciOptionRom))
        result.primaryKind = FirmwareKind::PciOptionRom;
    else if (result.has(FirmwareKind::IntelFlashDescriptor))
        result.primaryKind = FirmwareKind::IntelFlashDescriptor;

    // Multiple independent format structures raise an otherwise medium result,
    // but never repair a malformed individual record.
    unsigned kindCount = 0;
    for (FirmwareKind k : {FirmwareKind::LegacyBios, FirmwareKind::UefiFirmware,
                           FirmwareKind::PciOptionRom, FirmwareKind::IntelFlashDescriptor})
        if (result.has(k)) ++kindCount;
    if (kindCount >= 2) result.confidence = MaxConfidence(result.confidence,
                                                          FirmwareConfidence::High);
    return result;
}

} // namespace ds
