#include "PeUnpack.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <map>
#include <sstream>
#include <unordered_map>

namespace ds {
namespace {

constexpr size_t kMaxCapture = 512u * 1024u * 1024u;
constexpr uint16_t kMaxSections = 96;
constexpr size_t kMaxImports = 16384;
constexpr size_t kMaxName = 512;
constexpr uint32_t kSectionHeaderSize = 40;
constexpr uint32_t kImportDescriptorSize = 20;
constexpr uint32_t kPageSize = 0x1000;
constexpr uint32_t kMinFileAlignment = 0x200;
constexpr uint32_t kMaxFileAlignment = 0x10000;

template <class T>
bool get(const std::vector<uint8_t>& b, uint64_t off, T& out) {
    if (off > b.size() || sizeof(T) > b.size() - static_cast<size_t>(off)) return false;
    std::memcpy(&out, b.data() + static_cast<size_t>(off), sizeof(T));
    return true;
}

template <class T>
bool put(std::vector<uint8_t>& b, uint64_t off, T value) {
    if (off > b.size() || sizeof(T) > b.size() - static_cast<size_t>(off)) return false;
    std::memcpy(b.data() + static_cast<size_t>(off), &value, sizeof(T));
    return true;
}

bool add64(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > (std::numeric_limits<uint64_t>::max)() - b) return false;
    out = a + b;
    return true;
}

bool alignUp(uint64_t v, uint64_t a, uint64_t& out) {
    if (!a || (a & (a - 1)) != 0) return false;
    const uint64_t mask = a - 1;
    if (v > (std::numeric_limits<uint64_t>::max)() - mask) return false;
    out = (v + mask) & ~mask;
    return true;
}

void issue(PeUnpackResult& r, PeUnpackSeverity severity,
           const char* code, const std::string& message) {
    if (r.issues.size() >= 256) return;
    r.issues.push_back({ severity, code, message });
}

struct Header {
    uint32_t pe = 0;
    uint32_t coff = 0;
    uint32_t opt = 0;
    uint32_t sec = 0;
    uint16_t sectionCount = 0;
    uint16_t optSize = 0;
    uint16_t characteristics = 0;
    bool is64 = false;
    uint64_t preferredBase = 0;
    uint32_t sectionAlign = 0;
    uint32_t fileAlign = 0;
    uint32_t sizeImage = 0;
    uint32_t sizeHeaders = 0;
    uint32_t numberDirs = 0;
    uint32_t physicalDirs = 0;
    uint32_t dirOff = 0;
};

struct Sec {
    uint32_t headerOff = 0;
    char name[9]{};
    uint32_t virtualSize = 0;
    uint32_t rva = 0;
    uint32_t oldRawSize = 0;
    uint32_t characteristics = 0;
    uint32_t newRawOff = 0;
    uint32_t newRawSize = 0;
    uint32_t copySize = 0;
};

bool parseHeader(const std::vector<uint8_t>& b, Header& h, PeUnpackResult& r) {
    uint16_t mz = 0, magic = 0;
    uint32_t peSig = 0;
    if (!get(b, 0, mz) || mz != 0x5A4D) {
        issue(r, PeUnpackSeverity::Error, "not-pe", "The capture does not begin with an MZ header.");
        return false;
    }
    uint64_t ntEnd = 0;
    if (!get(b, 0x3c, h.pe) || !add64(h.pe, 24, ntEnd) || ntEnd > b.size()) {
        issue(r, PeUnpackSeverity::Error, "bad-pe-offset", "The PE header offset is outside the capture.");
        return false;
    }
    // Avoid relying on the aliasing trick above; calculate the 32-bit offsets
    // only after the bounded 64-bit check.
    uint64_t coff64 = static_cast<uint64_t>(h.pe) + 4;
    uint64_t opt64 = coff64 + 20;
    if (opt64 > UINT32_MAX) return false;
    h.coff = static_cast<uint32_t>(coff64);
    h.opt = static_cast<uint32_t>(opt64);
    if (!get(b, h.pe, peSig) || peSig != 0x00004550 ||
        !get(b, h.coff + 2, h.sectionCount) ||
        !get(b, h.coff + 16, h.optSize) ||
        !get(b, h.coff + 18, h.characteristics)) {
        issue(r, PeUnpackSeverity::Error, "truncated-pe", "The NT/COFF header is truncated.");
        return false;
    }
    if (!h.sectionCount || h.sectionCount > kMaxSections) {
        issue(r, PeUnpackSeverity::Error, "section-count", "The PE section count is zero or exceeds the safety cap.");
        return false;
    }
    if (!get(b, h.opt, magic) || (magic != 0x10b && magic != 0x20b)) {
        issue(r, PeUnpackSeverity::Error, "optional-magic", "Only PE32 and PE32+ captures can be rebuilt.");
        return false;
    }
    h.is64 = magic == 0x20b;
    const uint32_t minOpt = h.is64 ? 112u : 96u;
    if (h.optSize < minOpt || h.opt > b.size() || h.optSize > b.size() - h.opt) {
        issue(r, PeUnpackSeverity::Error, "optional-size", "The optional header is truncated or too small.");
        return false;
    }
    if (h.is64) {
        if (!get(b, h.opt + 24, h.preferredBase) || !get(b, h.opt + 108, h.numberDirs)) return false;
        h.dirOff = h.opt + 112;
    } else {
        uint32_t base32 = 0;
        if (!get(b, h.opt + 28, base32) || !get(b, h.opt + 92, h.numberDirs)) return false;
        h.preferredBase = base32;
        h.dirOff = h.opt + 96;
    }
    const uint32_t dirWithinOpt = h.dirOff - h.opt;
    const uint32_t physicallyPresent = h.optSize > dirWithinOpt
        ? (h.optSize - dirWithinOpt) / 8u : 0u;
    h.physicalDirs = physicallyPresent;
    if (h.numberDirs > physicallyPresent) {
        issue(r, PeUnpackSeverity::Warning, "directory-count",
              "NumberOfRvaAndSizes exceeded the optional header and was clamped.");
        h.numberDirs = physicallyPresent;
    }
    if (!get(b, h.opt + 32, h.sectionAlign) || !get(b, h.opt + 36, h.fileAlign) ||
        !get(b, h.opt + 56, h.sizeImage) || !get(b, h.opt + 60, h.sizeHeaders)) return false;
    const bool powersOfTwo = h.fileAlign && h.sectionAlign &&
        (h.fileAlign & (h.fileAlign - 1)) == 0 &&
        (h.sectionAlign & (h.sectionAlign - 1)) == 0;
    const bool smallSectionAlignment = h.sectionAlign < kPageSize;
    const bool fileAlignmentValid = smallSectionAlignment
        ? h.fileAlign == h.sectionAlign
        : h.fileAlign >= kMinFileAlignment && h.fileAlign <= kMaxFileAlignment &&
          h.fileAlign <= h.sectionAlign;
    if (!powersOfTwo || !fileAlignmentValid || h.sectionAlign > (64u << 20)) {
        issue(r, PeUnpackSeverity::Error, "alignment", "The PE file/section alignment is invalid.");
        return false;
    }
    uint64_t sec64 = static_cast<uint64_t>(h.opt) + h.optSize;
    uint64_t secEnd = sec64 + static_cast<uint64_t>(h.sectionCount) * kSectionHeaderSize;
    if (sec64 > UINT32_MAX || secEnd > b.size()) {
        issue(r, PeUnpackSeverity::Error, "section-table", "The PE section table is truncated.");
        return false;
    }
    h.sec = static_cast<uint32_t>(sec64);
    if (!h.sizeHeaders || h.sizeHeaders > b.size() || h.sizeHeaders < secEnd ||
        (h.sizeHeaders & (h.fileAlign - 1)) != 0 || !h.sizeImage ||
        (h.sizeImage & (h.sectionAlign - 1)) != 0) {
        issue(r, PeUnpackSeverity::Error, "image-layout",
              "SizeOfHeaders/SizeOfImage is inconsistent with the aligned PE header layout.");
        return false;
    }
    if (!h.sizeImage || h.sizeImage > b.size()) {
        issue(r, PeUnpackSeverity::Warning, "short-capture", "The capture is shorter than SizeOfImage; readable sections will still be salvaged.");
    }
    return true;
}

bool dataDir(const std::vector<uint8_t>& b, const Header& h, uint32_t index,
             uint32_t& rva, uint32_t& size) {
    rva = size = 0;
    if (index >= h.numberDirs || index >= 16) return false;
    uint64_t off = static_cast<uint64_t>(h.dirOff) + index * 8ull;
    return get(b, off, rva) && get(b, off + 4, size);
}

void clearDir(std::vector<uint8_t>& b, const Header& h, uint32_t index) {
    if (index >= h.numberDirs || index >= 16) return;
    const uint64_t off = static_cast<uint64_t>(h.dirOff) + index * 8ull;
    put<uint32_t>(b, off, 0);
    put<uint32_t>(b, off + 4, 0);
}

bool mappedSpan(const std::vector<uint8_t>& b, uint32_t rva, uint64_t n) {
    return rva <= b.size() && n <= b.size() - static_cast<size_t>(rva);
}

std::vector<Sec> parseSections(const std::vector<uint8_t>& b, const Header& h,
                               PeUnpackResult& r) {
    std::vector<Sec> out;
    out.reserve(h.sectionCount);
    uint64_t firstSectionRva = 0;
    if (!alignUp(h.sizeHeaders, h.sectionAlign, firstSectionRva) || firstSectionRva > UINT32_MAX) {
        issue(r, PeUnpackSeverity::Error, "section-layout", "The first section RVA cannot be represented safely.");
        return {};
    }
    std::vector<std::pair<uint64_t, uint64_t>> spans;
    spans.reserve(h.sectionCount);
    for (uint16_t i = 0; i < h.sectionCount; ++i) {
        Sec s;
        s.headerOff = h.sec + i * kSectionHeaderSize;
        std::memcpy(s.name, b.data() + s.headerOff, 8);
        if (!get(b, s.headerOff + 8, s.virtualSize) || !get(b, s.headerOff + 12, s.rva) ||
            !get(b, s.headerOff + 16, s.oldRawSize) || !get(b, s.headerOff + 36, s.characteristics)) {
            issue(r, PeUnpackSeverity::Error, "section-header", "A section header is truncated.");
            return {};
        }
        uint64_t wanted = std::max<uint64_t>(s.virtualSize, s.oldRawSize);
        uint64_t virtualEnd = 0;
        if ((s.rva & (h.sectionAlign - 1)) != 0 || s.rva < firstSectionRva ||
            !add64(s.rva, wanted, virtualEnd) || virtualEnd > h.sizeImage) {
            issue(r, PeUnpackSeverity::Error, "section-layout",
                  std::string("Section ") + s.name + " has an unaligned or out-of-image virtual span.");
            return {};
        }
        if (wanted) spans.emplace_back(s.rva, virtualEnd);
        if (s.rva >= b.size()) {
            issue(r, PeUnpackSeverity::Warning, "unreadable-section",
                  std::string("Section ") + s.name + " is outside the captured mapping and was emitted virtual-only.");
            wanted = 0;
        } else {
            wanted = std::min<uint64_t>(wanted, b.size() - s.rva);
        }
        s.copySize = static_cast<uint32_t>(std::min<uint64_t>(wanted, UINT32_MAX));
        out.push_back(s);
    }
    std::sort(spans.begin(), spans.end());
    for (size_t i = 1; i < spans.size(); ++i) {
        if (spans[i].first < spans[i - 1].second) {
            issue(r, PeUnpackSeverity::Error, "section-overlap",
                  "Section virtual ranges overlap; reconstruction was refused.");
            return {};
        }
    }
    return out;
}

uint64_t ptrValue(const std::vector<uint8_t>& b, uint32_t rva, bool is64) {
    uint64_t v = 0;
    if (is64) get(b, rva, v);
    else { uint32_t x = 0; get(b, rva, x); v = x; }
    return v;
}

bool putPtr(std::vector<uint8_t>& b, uint32_t rva, bool is64, uint64_t v) {
    if (!is64 && v > UINT32_MAX) return false;
    return is64 ? put<uint64_t>(b, rva, v) : put<uint32_t>(b, rva, static_cast<uint32_t>(v));
}

bool normalizeRelocs(std::vector<uint8_t>& work, const Header& h, uint64_t runtimeBase,
                     PeUnpackResult& r) {
    if (runtimeBase == h.preferredBase) return true;
    uint32_t rrva = 0, rsize = 0;
    if (!dataDir(work, h, 5, rrva, rsize) || !rrva || rsize < 8 || !mappedSpan(work, rrva, rsize)) {
        issue(r, PeUnpackSeverity::Warning, "relocs-missing",
              "Relocations were unavailable; the output remains based at the captured runtime address.");
        return false;
    }
    const uint64_t delta = runtimeBase - h.preferredBase; // unsigned subtraction is deliberate modulo pointer width
    uint64_t at = rrva, end = static_cast<uint64_t>(rrva) + rsize;
    uint32_t fixed = 0;
    bool unsupported = false;
    while (at + 8 <= end) {
        uint32_t page = 0, block = 0;
        if (!get(work, at, page) || !get(work, at + 4, block) || block < 8 || (block & 1) || block > end - at) {
            issue(r, PeUnpackSeverity::Warning, "relocs-malformed", "Relocation blocks are malformed; runtime-base fallback was used.");
            return false;
        }
        const uint32_t count = (block - 8) / 2;
        for (uint32_t i = 0; i < count; ++i) {
            uint16_t e = 0;
            get(work, at + 8 + i * 2ull, e);
            const uint16_t type = e >> 12;
            const uint64_t target64 = static_cast<uint64_t>(page) + (e & 0xfffu);
            if (type == 0) continue;
            if (target64 > UINT32_MAX) { unsupported = true; continue; }
            const uint32_t target = static_cast<uint32_t>(target64);
            if (h.is64 && type == 10 && mappedSpan(work, target, 8)) {
                uint64_t v = 0; get(work, target, v); put<uint64_t>(work, target, v - delta); ++fixed;
            } else if (!h.is64 && type == 3 && mappedSpan(work, target, 4)) {
                uint32_t v = 0; get(work, target, v);
                put<uint32_t>(work, target, v - static_cast<uint32_t>(delta)); ++fixed;
            } else unsupported = true;
        }
        at += block;
    }
    if (at != end) {
        issue(r, PeUnpackSeverity::Warning, "relocs-malformed",
              "The relocation directory has trailing partial data; runtime-base fallback was used.");
        return false;
    }
    if (unsupported) {
        issue(r, PeUnpackSeverity::Warning, "relocs-unsupported",
              "Unsupported or out-of-range relocation entries forced runtime-base fallback.");
        return false;
    }
    r.repairs.relocationEntriesNormalized = fixed;
    if (!fixed) {
        issue(r, PeUnpackSeverity::Warning, "relocs-empty", "No applicable relocation entries were normalized; runtime-base fallback was used.");
        return false;
    }
    return true;
}

bool validAsciiZ(const std::vector<uint8_t>& work, uint32_t rva, bool allowEmpty = false) {
    if (!mappedSpan(work, rva, 1)) return false;
    size_t p = rva, count = 0;
    while (p < work.size() && count <= kMaxName && work[p] &&
           std::isprint(static_cast<unsigned char>(work[p]))) { ++p; ++count; }
    return (allowEmpty || count != 0) && count <= kMaxName &&
           p < work.size() && work[p] == 0;
}

bool validImportSymbol(const std::vector<uint8_t>& work, uint64_t thunk, bool is64) {
    const uint64_t ordinalFlag = is64 ? 0x8000000000000000ull : 0x80000000ull;
    if (thunk & ordinalFlag) return (thunk & ~(ordinalFlag | 0xffffull)) == 0;
    if (thunk > UINT32_MAX || !mappedSpan(work, static_cast<uint32_t>(thunk), 3)) return false;
    return validAsciiZ(work, static_cast<uint32_t>(thunk) + 2);
}

bool readThunkTable(const std::vector<uint8_t>& work, uint32_t rva, bool is64,
                    std::vector<uint64_t>& thunks, size_t maxEntries = kMaxImports) {
    thunks.clear();
    const uint32_t ptr = is64 ? 8u : 4u;
    if (!rva) return false;
    for (size_t i = 0; i < maxEntries; ++i) {
        const uint64_t at = static_cast<uint64_t>(rva) + static_cast<uint64_t>(i) * ptr;
        if (at > UINT32_MAX || !mappedSpan(work, static_cast<uint32_t>(at), ptr)) return false;
        const uint64_t thunk = ptrValue(work, static_cast<uint32_t>(at), is64);
        if (!thunk) return !thunks.empty();
        if (!validImportSymbol(work, thunk, is64)) return false;
        thunks.push_back(thunk);
    }
    return false;
}

size_t importDescriptorLimit(const std::vector<uint8_t>& work, uint32_t irva,
                             uint32_t isize) {
    if (!irva || isize < kImportDescriptorSize || irva >= work.size()) return 0;
    const uint64_t captured = work.size() - static_cast<size_t>(irva);
    const uint64_t bounded = std::min<uint64_t>(isize, captured);
    return static_cast<size_t>(std::min<uint64_t>(bounded / kImportDescriptorSize, 4096));
}

bool sectionBackedSpan(const std::vector<Sec>& secs, uint32_t rva, uint32_t size);

void restoreImports(std::vector<uint8_t>& work, const Header& h,
                    const std::vector<Sec>& secs, PeUnpackResult& r) {
    uint32_t irva = 0, isize = 0;
    if (!dataDir(work, h, 1, irva, isize)) return;
    const size_t descriptorCount = importDescriptorLimit(work, irva, isize);
    const uint32_t ptr = h.is64 ? 8u : 4u;
    size_t remainingImports = kMaxImports;
    for (size_t d = 0; d < descriptorCount; ++d) {
        const uint64_t off = static_cast<uint64_t>(irva) + d * kImportDescriptorSize;
        uint32_t oft = 0, name = 0, ft = 0;
        get(work, off, oft); get(work, off + 12, name); get(work, off + 16, ft);
        if (!oft && !name && !ft) break;
        if (!oft || !ft || oft == ft || !validAsciiZ(work, name)) continue;

        std::vector<uint64_t> thunks;
        if (!remainingImports || !readThunkTable(work, oft, h.is64, thunks, remainingImports)) continue;
        const uint64_t fullSpan = static_cast<uint64_t>(thunks.size() + 1) * ptr;
        if (fullSpan > UINT32_MAX || !mappedSpan(work, ft, fullSpan) ||
            !sectionBackedSpan(secs, oft, static_cast<uint32_t>(fullSpan)) ||
            !sectionBackedSpan(secs, ft, static_cast<uint32_t>(fullSpan))) continue;

        // All source entries, the terminating null, and the full destination
        // range are validated before the first byte is changed.
        for (size_t i = 0; i < thunks.size(); ++i)
            putPtr(work, ft + static_cast<uint32_t>(i * ptr), h.is64, thunks[i]);
        putPtr(work, ft + static_cast<uint32_t>(thunks.size() * ptr), h.is64, 0);
        put<uint32_t>(work, off + 4, 0); // stale binding timestamp
        put<uint32_t>(work, off + 8, 0); // stale forwarder chain
        r.repairs.importSlotsRestored += static_cast<uint32_t>(thunks.size());
        remainingImports -= thunks.size();
    }
}

uint64_t repairedImagePointer(uint64_t v, uint64_t runtimeBase, uint64_t outputBase,
                              uint32_t imageSize, bool& repaired, bool& valid) {
    repaired = false;
    valid = v == 0;
    if (!v) return 0;
    if (v >= runtimeBase && v - runtimeBase < imageSize) {
        uint64_t out = outputBase + (v - runtimeBase);
        repaired = out != v; valid = true; return out;
    }
    if (v >= outputBase && v - outputBase < imageSize) { valid = true; return v; }
    return 0;
}

void clearGuardCf(std::vector<uint8_t>& work, const Header& h) {
    uint16_t dllChars = 0;
    if (get(work, h.opt + 70, dllChars))
        put<uint16_t>(work, h.opt + 70, static_cast<uint16_t>(dllChars & ~0x4000u));
}

void repairLoadConfig(std::vector<uint8_t>& work, const Header& h, uint64_t runtimeBase,
                      uint64_t outputBase, PeUnpackResult& r) {
    uint32_t lrva = 0, lsize = 0;
    if (!dataDir(work, h, 10, lrva, lsize) || (!lrva && !lsize)) return;
    if (!lrva || lsize < 4 || !mappedSpan(work, lrva, 4)) {
        clearDir(work, h, 10);
        clearGuardCf(work, h);
        issue(r, PeUnpackSeverity::Warning, "load-config-invalid", "An invalid load-config directory was cleared.");
        return;
    }
    uint32_t declared = 0; get(work, lrva, declared);
    const uint32_t usable = std::min<uint32_t>(declared, lsize);
    if (usable < (h.is64 ? 0x60u : 0x40u) || !mappedSpan(work, lrva, usable)) {
        clearDir(work, h, 10);
        clearGuardCf(work, h);
        issue(r, PeUnpackSeverity::Warning, "load-config-invalid", "An invalid load-config directory was cleared.");
        return;
    }
    struct Field { uint32_t off; bool count; };
    const Field fields64[] = {{0x58,false},{0x70,false},{0x78,false},{0x80,false},{0x88,true}};
    const Field fields32[] = {{0x3c,false},{0x48,false},{0x4c,false},{0x50,false},{0x54,true}};
    const Field* fields = h.is64 ? fields64 : fields32;
    const size_t fieldCount = 5;
    bool cfgInvalid = false;
    for (size_t i = 0; i < fieldCount; ++i) {
        const uint32_t width = h.is64 ? 8u : 4u;
        if (fields[i].off + width > usable) continue;
        if (fields[i].count) continue;
        const uint32_t at = lrva + fields[i].off;
        const uint64_t old = ptrValue(work, at, h.is64);
        bool repaired = false, valid = false;
        const uint64_t now = repairedImagePointer(old, runtimeBase, outputBase, h.sizeImage, repaired, valid);
        if (!valid) { putPtr(work, at, h.is64, 0); ++r.repairs.loadConfigPointersCleared; if (i >= 1) cfgInvalid = true; }
        else if (repaired && putPtr(work, at, h.is64, now)) ++r.repairs.loadConfigPointersRepaired;
    }
    if (cfgInvalid) {
        const uint32_t countOff = h.is64 ? 0x88u : 0x54u;
        const uint32_t flagsOff = h.is64 ? 0x90u : 0x58u;
        if (countOff + (h.is64 ? 8u : 4u) <= usable) putPtr(work, lrva + countOff, h.is64, 0);
        if (flagsOff + 4 <= usable) put<uint32_t>(work, lrva + flagsOff, 0);
        clearGuardCf(work, h);
        issue(r, PeUnpackSeverity::Warning, "cfg-cleared", "Invalid Guard CF image pointers were cleared conservatively.");
    }
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool sectionBackedSpan(const std::vector<Sec>& secs, uint32_t rva, uint32_t size) {
    for (const Sec& s : secs) {
        if (rva < s.rva) continue;
        const uint64_t offset = static_cast<uint64_t>(rva) - s.rva;
        if (offset <= s.copySize && size <= static_cast<uint64_t>(s.copySize) - offset)
            return true;
    }
    return false;
}

bool validImportText(const std::string& text, bool allowEmpty = false) {
    if ((!allowEmpty && text.empty()) || text.size() > kMaxName) return false;
    return std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return c != 0 && std::isprint(c) != 0;
    });
}

bool validImport(const PeUnpackImport& im, uint64_t base, const Header& h,
                 const std::vector<uint8_t>& work, const std::vector<Sec>& secs) {
    const uint32_t ptr = h.is64 ? 8u : 4u;
    if (!validImportText(im.dll) || !validImportText(im.name, im.byOrdinal) ||
        (!im.byOrdinal && im.name.empty()) || im.slotVA < base) return false;
    const uint64_t rva64 = im.slotVA - base;
    if (rva64 > UINT32_MAX || rva64 >= h.sizeImage || ptr > h.sizeImage - rva64 ||
        (rva64 & (ptr - 1)) != 0) return false;
    const uint32_t rva = static_cast<uint32_t>(rva64);
    return mappedSpan(work, rva, ptr) && sectionBackedSpan(secs, rva, ptr);
}

struct ImportRun {
    std::string dll;
    uint32_t firstThunk = 0;
    std::vector<PeUnpackImport> imports;
    uint32_t iltRva = 0;
    uint32_t nameRva = 0;
};

struct ExistingImportDesc {
    uint32_t originalFirstThunk = 0;
    uint32_t nameRva = 0;
    uint32_t firstThunk = 0;
    uint32_t thunkCount = 0;
};

std::vector<ExistingImportDesc> existingImportDescriptors(const std::vector<uint8_t>& work,
                                                           const Header& h,
                                                           const std::vector<Sec>& secs) {
    std::vector<ExistingImportDesc> out;
    uint32_t irva = 0, isize = 0;
    if (!dataDir(work, h, 1, irva, isize)) return out;
    const size_t descriptorCount = importDescriptorLimit(work, irva, isize);
    const uint32_t ptr = h.is64 ? 8u : 4u;
    size_t remainingImports = kMaxImports;
    for (size_t i = 0; i < descriptorCount; ++i) {
        const uint64_t at = static_cast<uint64_t>(irva) + i * kImportDescriptorSize;
        ExistingImportDesc d;
        get(work, at, d.originalFirstThunk);
        get(work, at + 12, d.nameRva);
        get(work, at + 16, d.firstThunk);
        if (!d.originalFirstThunk && !d.nameRva && !d.firstThunk) break;
        if (!d.originalFirstThunk || !d.nameRva || !d.firstThunk ||
            !validAsciiZ(work, d.nameRva) || !remainingImports) continue;
        std::vector<uint64_t> thunks;
        if (!readThunkTable(work, d.originalFirstThunk, h.is64, thunks, remainingImports)) continue;
        const uint64_t fullSpan = static_cast<uint64_t>(thunks.size() + 1) * ptr;
        if (fullSpan > UINT32_MAX || !mappedSpan(work, d.firstThunk, fullSpan) ||
            !sectionBackedSpan(secs, d.originalFirstThunk, static_cast<uint32_t>(fullSpan)) ||
            !sectionBackedSpan(secs, d.firstThunk, static_cast<uint32_t>(fullSpan))) continue;
        d.thunkCount = static_cast<uint32_t>(thunks.size());
        remainingImports -= thunks.size();
        out.push_back(d);
    }
    return out;
}

bool coveredByExisting(uint32_t slot, const std::vector<ExistingImportDesc>& existing,
                       uint32_t ptr) {
    for (const auto& d : existing) {
        const uint64_t end = static_cast<uint64_t>(d.firstThunk) +
            static_cast<uint64_t>(d.thunkCount) * ptr;
        if (slot >= d.firstThunk && slot < end) return true;
    }
    return false;
}

std::vector<ImportRun> makeRuns(const PeUnpackOptions& o, const Header& h,
                                const std::vector<uint8_t>& work,
                                const std::vector<Sec>& secs,
                                const std::vector<ExistingImportDesc>& existing,
                                PeUnpackResult& r) {
    std::vector<PeUnpackImport> imports;
    imports.reserve(std::min(o.observedImports.size(), kMaxImports));
    const uint32_t ptr = h.is64 ? 8u : 4u;
    for (const auto& im : o.observedImports) {
        if (imports.size() >= kMaxImports) break;
        if (!validImport(im, o.runtimeImageBase, h, work, secs)) {
            issue(r, PeUnpackSeverity::Warning, "import-rejected", "An observed import with invalid bounds, captured backing, or naming was ignored.");
            continue;
        }
        const uint32_t slot = static_cast<uint32_t>(im.slotVA - o.runtimeImageBase);
        if (!coveredByExisting(slot, existing, ptr)) imports.push_back(im);
    }
    std::sort(imports.begin(), imports.end(), [](const auto& a, const auto& b) {
        if (a.slotVA != b.slotVA) return a.slotVA < b.slotVA;
        return lower(a.dll) < lower(b.dll);
    });
    imports.erase(std::unique(imports.begin(), imports.end(), [](const auto& a, const auto& b) {
        return a.slotVA == b.slotVA;
    }), imports.end());
    std::vector<ImportRun> runs;
    for (const auto& im : imports) {
        const uint32_t slot = static_cast<uint32_t>(im.slotVA - o.runtimeImageBase);
        if (runs.empty() || lower(runs.back().dll) != lower(im.dll) ||
            runs.back().imports.back().slotVA + ptr != im.slotVA) {
            runs.push_back({ im.dll, slot, {im} });
        } else runs.back().imports.push_back(im);
    }
    return runs;
}

bool addImportSection(std::vector<uint8_t>& work, std::vector<Sec>& secs, Header& h,
                      const PeUnpackOptions& o, PeUnpackResult& r) {
    const std::vector<ExistingImportDesc> existing = existingImportDescriptors(work, h, secs);
    std::vector<ImportRun> runs = makeRuns(o, h, work, secs, existing, r);
    if (runs.empty()) return true;
    if (h.physicalDirs < 2) {
        issue(r, PeUnpackSeverity::Warning, "import-no-directory-room",
              "Observed imports could not be rebuilt because the optional header has no import-directory slot.");
        return false;
    }
    if (h.sectionCount >= kMaxSections) return false;
    const uint64_t newHeader = static_cast<uint64_t>(h.sec) + h.sectionCount * 40ull;
    if (newHeader + 40 > h.sizeHeaders || newHeader + 40 > work.size()) {
        issue(r, PeUnpackSeverity::Warning, "import-no-header-room", "Observed imports could not be rebuilt because the PE header has no section-table room.");
        return false;
    }
    uint64_t maxEnd = std::max<uint64_t>(h.sizeImage, work.size());
    for (const Sec& s : secs) maxEnd = std::max<uint64_t>(maxEnd, static_cast<uint64_t>(s.rva) + std::max(s.virtualSize, s.copySize));
    uint64_t sectionRva64 = 0;
    if (!alignUp(maxEnd, h.sectionAlign, sectionRva64) || sectionRva64 > UINT32_MAX ||
        sectionRva64 >= kMaxCapture) {
        issue(r, PeUnpackSeverity::Warning, "import-section-range",
              "There is no bounded virtual-address range for a rebuilt import section.");
        return false;
    }
    const uint32_t sectionRva = static_cast<uint32_t>(sectionRva64);
    std::vector<uint8_t> payload((existing.size() + runs.size() + 1) * kImportDescriptorSize, 0);
    auto append = [&](const void* p, size_t n, size_t alignment = 1) -> uint32_t {
        while (payload.size() % alignment) payload.push_back(0);
        const uint32_t off = static_cast<uint32_t>(payload.size());
        const uint8_t* q = static_cast<const uint8_t*>(p);
        payload.insert(payload.end(), q, q + n);
        return off;
    };
    std::unordered_map<std::string, uint32_t> dllNames;
    std::map<std::pair<std::string,uint16_t>, uint32_t> symbolNames;
    for (auto& run : runs) {
        std::string key = lower(run.dll);
        auto dit = dllNames.find(key);
        if (dit == dllNames.end()) {
            uint32_t off = append(run.dll.c_str(), run.dll.size() + 1);
            const uint64_t nameRva = static_cast<uint64_t>(sectionRva) + off;
            if (nameRva > UINT32_MAX) return false;
            dit = dllNames.emplace(key, static_cast<uint32_t>(nameRva)).first;
        }
        run.nameRva = dit->second;
    }
    const uint32_t ptr = h.is64 ? 8u : 4u;
    for (auto& run : runs) {
        std::vector<uint64_t> thunks;
        for (const auto& im : run.imports) {
            uint64_t thunk = 0;
            if (im.byOrdinal) thunk = (h.is64 ? 0x8000000000000000ull : 0x80000000ull) | im.ordinal;
            else {
                auto key = std::make_pair(im.name, static_cast<uint16_t>(0));
                auto it = symbolNames.find(key);
                if (it == symbolNames.end()) {
                    uint16_t hint = 0;
                    uint32_t noff = append(&hint, sizeof(hint), 2);
                    append(im.name.c_str(), im.name.size() + 1);
                    const uint64_t nameRva = static_cast<uint64_t>(sectionRva) + noff;
                    if (nameRva > UINT32_MAX) return false;
                    it = symbolNames.emplace(key, static_cast<uint32_t>(nameRva)).first;
                }
                thunk = it->second;
            }
            thunks.push_back(thunk);
        }
        thunks.push_back(0);
        while (payload.size() % ptr) payload.push_back(0);
        const uint32_t iltOff = static_cast<uint32_t>(payload.size());
        for (uint64_t thunk : thunks) {
            if (h.is64) append(&thunk, 8);
            else { uint32_t x = static_cast<uint32_t>(thunk); append(&x, 4); }
        }
        const uint64_t iltRva = static_cast<uint64_t>(sectionRva) + iltOff;
        if (iltRva > UINT32_MAX) return false;
        run.iltRva = static_cast<uint32_t>(iltRva);
        for (size_t i = 0; i < run.imports.size(); ++i) {
            const uint32_t slot = run.firstThunk + static_cast<uint32_t>(i * ptr);
            const uint64_t thunk = thunks[i];
            if (!putPtr(work, slot, h.is64, thunk)) return false;
        }
    }
    for (size_t i = 0; i < existing.size(); ++i) {
        const uint32_t d = static_cast<uint32_t>(i * 20);
        put<uint32_t>(payload, d, existing[i].originalFirstThunk);
        put<uint32_t>(payload, d + 12, existing[i].nameRva);
        put<uint32_t>(payload, d + 16, existing[i].firstThunk);
    }
    for (size_t i = 0; i < runs.size(); ++i) {
        const uint32_t d = static_cast<uint32_t>((existing.size() + i) * 20);
        put<uint32_t>(payload, d, runs[i].iltRva);
        put<uint32_t>(payload, d + 12, runs[i].nameRva);
        put<uint32_t>(payload, d + 16, runs[i].firstThunk);
    }
    Sec s;
    s.headerOff = static_cast<uint32_t>(newHeader);
    std::memcpy(s.name, ".dsimp", 6);
    s.rva = sectionRva;
    s.virtualSize = static_cast<uint32_t>(payload.size());
    s.copySize = s.virtualSize;
    s.characteristics = 0xC0000040u;
    // Temporarily append payload to the mapped work at its RVA; the common disk
    // layout pass below treats it like every other section.
    const uint64_t payloadEnd = static_cast<uint64_t>(s.rva) + payload.size();
    if (payloadEnd > kMaxCapture || payloadEnd > UINT32_MAX) {
        issue(r, PeUnpackSeverity::Warning, "import-section-cap",
              "The rebuilt import section would exceed the image safety cap.");
        return false;
    }
    if (work.size() < payloadEnd) work.resize(static_cast<size_t>(payloadEnd), 0);
    std::copy(payload.begin(), payload.end(), work.begin() + s.rva);
    std::fill(work.begin() + s.headerOff, work.begin() + s.headerOff + 40, uint8_t{0});
    std::copy(s.name, s.name + 8, work.begin() + s.headerOff);
    put<uint32_t>(work, s.headerOff + 8, s.virtualSize);
    put<uint32_t>(work, s.headerOff + 12, s.rva);
    put<uint32_t>(work, s.headerOff + 36, s.characteristics);
    secs.push_back(s);
    ++h.sectionCount;
    put<uint16_t>(work, h.coff + 2, h.sectionCount);
    if (h.numberDirs < 2) {
        h.numberDirs = 2;
        put<uint32_t>(work, h.is64 ? h.opt + 108 : h.opt + 92, h.numberDirs);
    }
    const uint64_t dd = static_cast<uint64_t>(h.dirOff) + 8;
    put<uint32_t>(work, dd, sectionRva);
    put<uint32_t>(work, dd + 4, static_cast<uint32_t>((existing.size() + runs.size() + 1) * 20));
    uint32_t minIat = UINT32_MAX;
    uint64_t maxIat = 0;
    for (const auto& d : existing) {
        minIat = std::min(minIat, d.firstThunk);
        maxIat = std::max(maxIat, static_cast<uint64_t>(d.firstThunk) +
                         static_cast<uint64_t>(d.thunkCount + 1) * ptr);
    }
    for (const auto& run : runs) {
        minIat = std::min(minIat, run.firstThunk);
        maxIat = std::max(maxIat, static_cast<uint64_t>(run.firstThunk) +
                         static_cast<uint64_t>(run.imports.size() + 1) * ptr);
        r.repairs.importsRebuilt += static_cast<uint32_t>(run.imports.size());
    }
    if (h.physicalDirs > 12 && minIat != UINT32_MAX && maxIat <= UINT32_MAX && maxIat >= minIat) {
        if (h.numberDirs < 13) {
            h.numberDirs = 13;
            put<uint32_t>(work, h.is64 ? h.opt + 108 : h.opt + 92, h.numberDirs);
        }
        const uint64_t iatdd = static_cast<uint64_t>(h.dirOff) + 12 * 8ull;
        put<uint32_t>(work, iatdd, minIat);
        put<uint32_t>(work, iatdd + 4, static_cast<uint32_t>(maxIat - minIat));
    }
    r.repairs.importRunsRebuilt = static_cast<uint32_t>(runs.size());
    return true;
}

bool diskLayout(const std::vector<uint8_t>& work, const Header& h,
                std::vector<Sec>& secs, const PeUnpackOptions& o, PeUnpackResult& r) {
    uint64_t headers = 0;
    const uint64_t minHeaders = static_cast<uint64_t>(h.sec) + h.sectionCount * 40ull;
    if (!alignUp(std::max<uint64_t>(h.sizeHeaders, minHeaders), h.fileAlign, headers) || headers > kMaxCapture) return false;
    uint64_t cursor = headers;
    for (Sec& s : secs) {
        uint32_t used = s.copySize;
        if (o.trimZeroTails && used && mappedSpan(work, s.rva, used)) {
            while (used && work[static_cast<size_t>(s.rva) + used - 1] == 0) --used;
        }
        uint64_t raw = 0;
        if (used && (!alignUp(used, h.fileAlign, raw) || raw > UINT32_MAX)) return false;
        if (cursor > UINT32_MAX || cursor + raw > kMaxCapture) return false;
        s.newRawOff = used ? static_cast<uint32_t>(cursor) : 0;
        s.newRawSize = static_cast<uint32_t>(raw);
        cursor += raw;
    }
    r.image.assign(static_cast<size_t>(cursor), 0);
    const size_t headerCopy = std::min<size_t>(r.image.size(), std::min<size_t>(work.size(), static_cast<size_t>(headers)));
    std::copy_n(work.begin(), headerCopy, r.image.begin());
    uint64_t imageEnd = headers;
    uint64_t codeSize = 0, initializedSize = 0, uninitializedSize = 0;
    for (const Sec& s : secs) {
        put<uint32_t>(r.image, s.headerOff + 8, s.virtualSize);
        put<uint32_t>(r.image, s.headerOff + 12, s.rva);
        put<uint32_t>(r.image, s.headerOff + 16, s.newRawSize);
        put<uint32_t>(r.image, s.headerOff + 20, s.newRawOff);
        put<uint32_t>(r.image, s.headerOff + 24, 0); // COFF reloc/line tables are not meaningful in an image dump
        put<uint32_t>(r.image, s.headerOff + 28, 0);
        put<uint16_t>(r.image, s.headerOff + 32, 0);
        put<uint16_t>(r.image, s.headerOff + 34, 0);
        put<uint32_t>(r.image, s.headerOff + 36, s.characteristics);
        if (s.newRawSize && mappedSpan(work, s.rva, s.copySize)) {
            const size_t n = std::min<size_t>(s.copySize, s.newRawSize);
            std::copy_n(work.begin() + s.rva, n, r.image.begin() + s.newRawOff);
        }
        uint64_t end = static_cast<uint64_t>(s.rva) + std::max(s.virtualSize, s.newRawSize);
        imageEnd = std::max(imageEnd, end);
        if (s.characteristics & 0x20u) codeSize += s.newRawSize;
        if (s.characteristics & 0x40u) initializedSize += s.newRawSize;
        if (s.characteristics & 0x80u)
            uninitializedSize += std::max<uint32_t>(s.virtualSize, s.newRawSize) - s.newRawSize;
    }
    uint64_t sizeImage = 0;
    if (!alignUp(imageEnd, h.sectionAlign, sizeImage) || sizeImage > UINT32_MAX) return false;
    put<uint32_t>(r.image, h.opt + 56, static_cast<uint32_t>(sizeImage));
    put<uint32_t>(r.image, h.opt + 60, static_cast<uint32_t>(headers));
    put<uint32_t>(r.image, h.opt + 4, static_cast<uint32_t>(std::min<uint64_t>(codeSize, UINT32_MAX)));
    put<uint32_t>(r.image, h.opt + 8, static_cast<uint32_t>(std::min<uint64_t>(initializedSize, UINT32_MAX)));
    put<uint32_t>(r.image, h.opt + 12, static_cast<uint32_t>(std::min<uint64_t>(uninitializedSize, UINT32_MAX)));
    r.repairs.sectionsRebuilt = static_cast<uint32_t>(secs.size());
    return true;
}

std::string makeReport(const PeUnpackResult& r) {
    std::ostringstream s;
    s << "DisasmStudio adaptive PE unpack report\n"
      << "result: " << (r.success ? "reconstructed" : "failure artifact only") << "\n"
      << "architecture: " << (r.is64 ? "PE32+" : "PE32") << "\n"
      << "preferred base: 0x" << std::hex << r.preferredImageBase << "\n"
      << "output base: 0x" << r.outputImageBase << "\n"
      << "entry RVA: 0x" << r.entryRVA << std::dec << "\n"
      << "sections rebuilt: " << r.repairs.sectionsRebuilt << "\n"
      << "relocations normalized: " << r.repairs.relocationEntriesNormalized << "\n"
      << "intact IAT slots restored: " << r.repairs.importSlotsRestored << "\n"
      << "observed imports rebuilt: " << r.repairs.importsRebuilt << " in "
      << r.repairs.importRunsRebuilt << " run(s)\n"
      << "load-config pointers repaired/cleared: " << r.repairs.loadConfigPointersRepaired
      << "/" << r.repairs.loadConfigPointersCleared << "\n";
    for (const auto& i : r.issues) {
        const char* sev = i.severity == PeUnpackSeverity::Error ? "error" :
                          i.severity == PeUnpackSeverity::Warning ? "warning" : "info";
        s << sev << " [" << i.code << "]: " << i.message << "\n";
    }
    return s.str();
}

} // namespace

PeUnpackResult RebuildMappedPe(const std::vector<uint8_t>& mappedImage,
                               const PeUnpackOptions& options) {
    PeUnpackResult r;
    if (options.retainRawMappedImage) {
        if (mappedImage.size() <= kMaxCapture) r.rawMappedImage = mappedImage;
        else r.rawMappedImage.assign(mappedImage.begin(), mappedImage.begin() + kMaxCapture);
    }
    r.repairs.failureArtifactOnly = true;
    if (mappedImage.empty() || mappedImage.size() > kMaxCapture) {
        issue(r, PeUnpackSeverity::Error, "capture-size", "The mapped image is empty or exceeds the 512 MiB reconstruction cap.");
        r.report = makeReport(r); return r;
    }
    Header h;
    if (!parseHeader(mappedImage, h, r)) { r.report = makeReport(r); return r; }
    r.is64 = h.is64;
    r.preferredImageBase = h.preferredBase;
    if ((!h.is64 && options.runtimeImageBase > UINT32_MAX) || !options.runtimeImageBase) {
        issue(r, PeUnpackSeverity::Error, "runtime-base", "The runtime image base is invalid for this PE architecture.");
        r.report = makeReport(r); return r;
    }
    uint64_t runtimeEnd = 0, preferredEnd = 0;
    if (!add64(options.runtimeImageBase, h.sizeImage, runtimeEnd) ||
        !add64(h.preferredBase, h.sizeImage, preferredEnd) ||
        (!h.is64 && (runtimeEnd > 0x100000000ull || preferredEnd > 0x100000000ull))) {
        issue(r, PeUnpackSeverity::Error, "image-address-range",
              "The preferred or runtime PE image range overflows its architecture's address space.");
        r.report = makeReport(r); return r;
    }
    std::vector<uint8_t> work = mappedImage;
    // Persist any parser-side clamp so subsequent writers and the emitted PE
    // agree on how many directory slots are actually present.
    put<uint32_t>(work, h.is64 ? h.opt + 108 : h.opt + 92, h.numberDirs);
    std::vector<Sec> secs = parseSections(work, h, r);
    if (secs.size() != h.sectionCount) { r.report = makeReport(r); return r; }

    uint32_t headerEntry = 0;
    if (!get(work, h.opt + 16, headerEntry)) {
        issue(r, PeUnpackSeverity::Error, "entry-truncated", "The PE entry-point field is truncated.");
        r.report = makeReport(r); return r;
    }
    if (options.hasOep) {
        if (options.oepVA < options.runtimeImageBase ||
            (!h.is64 && options.oepVA > UINT32_MAX) ||
            options.oepVA - options.runtimeImageBase >= h.sizeImage ||
            options.oepVA - options.runtimeImageBase >= mappedImage.size() ||
            options.oepVA - options.runtimeImageBase > UINT32_MAX) {
            issue(r, PeUnpackSeverity::Error, "oep-range", "The selected OEP is outside the captured PE image.");
            r.report = makeReport(r); return r;
        }
        r.entryRVA = static_cast<uint32_t>(options.oepVA - options.runtimeImageBase);
    } else {
        r.entryRVA = headerEntry;
        if (r.entryRVA && (r.entryRVA >= h.sizeImage || r.entryRVA >= mappedImage.size())) {
            issue(r, PeUnpackSeverity::Error, "entry-range",
                  "The captured PE entry point is outside the mapped image.");
            r.report = makeReport(r); return r;
        }
    }
    if (r.entryRVA || options.hasOep) {
        auto owner = std::find_if(secs.begin(), secs.end(), [&](const Sec& s) {
            return r.entryRVA >= s.rva &&
                   static_cast<uint64_t>(r.entryRVA) - s.rva < s.copySize;
        });
        if (owner == secs.end()) {
            issue(r, PeUnpackSeverity::Error, options.hasOep ? "oep-section" : "entry-section",
                  options.hasOep
                      ? "The selected OEP is not contained by a captured section."
                      : "The captured PE entry point is not backed by a captured section.");
            r.report = makeReport(r); return r;
        }
        // Runtime unpackers commonly make a formerly writable data section
        // executable. Reflect the approved OEP rather than preserving a stale
        // on-disk non-executable characteristic.
        owner->characteristics |= 0x60000020u; // code | execute | read
        put<uint32_t>(work, owner->headerOff + 36, owner->characteristics);
    }

    bool normalized = false;
    if (options.normalizeRelocations) {
        if (options.runtimeImageBase == h.preferredBase) {
            // No relocation mutation is required, so avoid an image-sized
            // transactional copy merely to discover a zero delta.
            normalized = true;
        } else {
            // A malformed table may be discovered after valid-looking early blocks.
            // Normalize transactionally so runtime-base fallback never retains a
            // half-normalized image.
            std::vector<uint8_t> relocated = work;
            normalized = normalizeRelocs(relocated, h, options.runtimeImageBase, r);
            if (normalized) work.swap(relocated);
            else r.repairs.relocationEntriesNormalized = 0;
        }
    }
    r.outputImageBase = normalized ? h.preferredBase : options.runtimeImageBase;
    if (h.is64) put<uint64_t>(work, h.opt + 24, r.outputImageBase);
    else put<uint32_t>(work, h.opt + 28, static_cast<uint32_t>(r.outputImageBase));
    r.repairs.imageBaseChanged = r.outputImageBase != h.preferredBase;
    if (!normalized && r.outputImageBase != h.preferredBase) {
        uint16_t dllChars = 0;
        if (get(work, h.opt + 70, dllChars)) put<uint16_t>(work, h.opt + 70, static_cast<uint16_t>(dllChars & ~0x40u));
    }
    if (options.restoreIntactImports) restoreImports(work, h, secs, r);
    if (options.repairLoadConfig) repairLoadConfig(work, h, options.runtimeImageBase, r.outputImageBase, r);

    if (options.rebuildObservedImports && !options.observedImports.empty()) {
        // The synthetic section also rewrites live IAT slots. Stage every byte
        // and header mutation so a late cap/layout failure cannot leak a
        // partially rebuilt import graph into the otherwise valid dump.
        std::vector<uint8_t> importWork = work;
        std::vector<Sec> importSecs = secs;
        Header importHeader = h;
        if (addImportSection(importWork, importSecs, importHeader, options, r)) {
            work.swap(importWork);
            secs.swap(importSecs);
            h = importHeader;
        } else {
            issue(r, PeUnpackSeverity::Warning, "imports-partial", "The PE was dumped, but observed-import reconstruction was incomplete.");
        }
    }
    if (r.repairs.importSlotsRestored || r.repairs.importsRebuilt)
        clearDir(work, h, 11); // binding timestamps/addresses are stale after either repair path
    if (options.hasOep) {
        put<uint32_t>(work, h.opt + 16, r.entryRVA);
        r.repairs.entryPointChanged = headerEntry != r.entryRVA;
    }

    uint32_t secOff = 0, secSize = 0;
    if (dataDir(work, h, 4, secOff, secSize) && (secOff || secSize)) {
        clearDir(work, h, 4);
        r.repairs.securityDirectoryCleared = true;
        issue(r, PeUnpackSeverity::Info, "signature-cleared", "The invalidated Authenticode directory was cleared.");
    }
    uint32_t debugRva = 0, debugSize = 0;
    if (dataDir(work, h, 6, debugRva, debugSize) && (debugRva || debugSize)) {
        clearDir(work, h, 6);
        issue(r, PeUnpackSeverity::Info, "debug-cleared",
              "The debug directory was cleared because its disk file pointers became stale after section repacking.");
    }
    uint32_t symbolTable = 0, symbolCount = 0;
    get(work, h.coff + 8, symbolTable);
    get(work, h.coff + 12, symbolCount);
    put<uint32_t>(work, h.coff + 8, 0);
    put<uint32_t>(work, h.coff + 12, 0);
    if (symbolTable || symbolCount)
        issue(r, PeUnpackSeverity::Info, "coff-symbols-cleared",
              "Stale COFF symbol-table file offsets were cleared from the rebuilt image.");
    uint32_t oldChecksum = 0;
    if (get(work, h.opt + 64, oldChecksum)) {
        put<uint32_t>(work, h.opt + 64, 0);
        r.repairs.checksumCleared = oldChecksum != 0;
    }
    if (!diskLayout(work, h, secs, options, r)) {
        r.image.clear();
        issue(r, PeUnpackSeverity::Error, "disk-layout", "The rebuilt disk layout would overflow a PE field or the safety cap.");
        r.report = makeReport(r); return r;
    }
    r.success = true;
    r.repairs.failureArtifactOnly = false;
    r.report = makeReport(r);
    return r;
}

} // namespace ds
