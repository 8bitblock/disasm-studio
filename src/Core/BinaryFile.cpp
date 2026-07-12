#include "BinaryFile.h"
#include "JvmClass.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace ds {

namespace {
// C++20's filesystem::path has a native char8_t constructor. Build a u8string
// explicitly instead of using the deprecated filesystem::u8path compatibility
// shim, while keeping this Core module portable and free of Win32 APIs.
std::filesystem::path PathFromUtf8(const std::string& path) {
    std::u8string u8(path.size(), u8'\0');
    if (!path.empty()) std::memcpy(u8.data(), path.data(), path.size());
    return std::filesystem::path(u8);
}

std::string Utf8FromPath(const std::filesystem::path& path) {
    const std::u8string u8 = path.u8string();
    std::string out(u8.size(), '\0');
    if (!u8.empty()) std::memcpy(out.data(), u8.data(), u8.size());
    return out;
}

// Store a durable spelling after a successful open. In particular, a binary
// supplied as a relative startup argument must still reopen after the process
// working directory changes or the path is written to the recents index.
std::string DurableUtf8Path(const std::filesystem::path& openedPath) {
    std::error_code ec;
    std::filesystem::path absolute = std::filesystem::absolute(openedPath, ec);
    if (ec) absolute = openedPath;
    std::error_code canonicalEc;
    std::filesystem::path canonical = std::filesystem::weakly_canonical(absolute, canonicalEc);
    if (!canonicalEc) absolute = std::move(canonical);
    else absolute = absolute.lexically_normal();
    return Utf8FromPath(absolute);
}
} // namespace

void BinaryFile::clear() {
    ++imageRevision_;
    path_.clear();
    data_.clear();
    sections_.clear();
    hash_ = 0; hashValid_ = false;   // recompute the sidecar key for the next file
    format_    = BinFormat::Unknown;
    machine_   = MachineArch::Unknown;
    is64_      = true;
    mappedImage_ = false;
    mappedBase_  = 0;
    imageBase_ = 0;
    entryRVA_  = 0;
    exportRVA_ = 0;
    exportSize_= 0;
    importRVA_ = 0;
    importSize_= 0;
    relocRVA_  = 0;
    relocSize_ = 0;
    exceptRVA_ = 0;
    exceptSize_= 0;
    overlayOffset_ = 0;
    overlaySize_   = 0;
    securityOff_   = 0;
    securitySize_  = 0;
    clrRva_        = 0;
    clrSize_       = 0;
    sizeOfHeaders_ = 0;
    exports_.clear();
    imports_.clear();
    relocs_.clear();
    javaClass_.reset();
}

const char* BinaryFile::formatName() const {
    switch (format_) {
        case BinFormat::PE32:     return "PE32 (x86)";
        case BinFormat::PE32Plus: return "PE32+ (x64)";
        case BinFormat::ELF:      return "ELF";
        case BinFormat::MachO:    return "Mach-O";
        case BinFormat::JavaClass: return "Java class";
        case BinFormat::Raw:      return "Raw";
        default:                  return "Unknown";
    }
}

bool BinaryFile::load(const std::string& path) {
    clear();
    // All public paths are UTF-8 (Win32 dialogs and command-line startup both
    // convert at the boundary). A char8_t filesystem path preserves non-ASCII
    // file names on Windows instead of sending UTF-8 bytes through the active
    // ANSI codepage.
    const std::filesystem::path fsPath = PathFromUtf8(path);
    std::ifstream f(fsPath, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    if (n <= 0) return false;
    f.seekg(0);
    data_.resize(static_cast<size_t>(n));
    if (!f.read(reinterpret_cast<char*>(data_.data()), n)) { clear(); return false; }
    path_ = DurableUtf8Path(fsPath);

    uint32_t magic = 0;
    if (data_.size() >= 4) std::memcpy(&magic, data_.data(), 4);

    if (data_.size() >= 2 && data_[0] == 'M' && data_[1] == 'Z') {
        if (!parsePE() && !initializeRawLayout(0)) { clear(); return false; }
    } else if (data_.size() >= 4 && std::memcmp(data_.data(), "\x7F""ELF", 4) == 0) {
        if (!parseELF() && !initializeRawLayout(0)) { clear(); return false; }
    } else if (magic == 0xFEEDFACEu || magic == 0xFEEDFACFu) {   // Mach-O thin (LE)
        if (!parseMachO() && !initializeRawLayout(0)) { clear(); return false; }
    } else if (IsJavaClassImage(data_.data(), data_.size())) {   // 0xCAFEBABE
        if (!parseJavaClass() && !initializeRawLayout(0)) { clear(); return false; }
    } else {
        if (!initializeRawLayout(0)) { clear(); return false; }
    }
    return true;
}

bool BinaryFile::initializeRawLayout(uint64_t base, bool mappedImage) {
    if (data_.empty()) return false;
    const uint64_t lastOffset = static_cast<uint64_t>(data_.size() - 1);
    if (lastOffset > std::numeric_limits<uint64_t>::max() - base) return false;

    // A structured parser may have populated part of its model before rejecting
    // the image. A Raw fallback must not expose those stale sections/directories.
    format_       = BinFormat::Raw;
    machine_      = MachineArch::Unknown; // the Open-as-Raw dialog owns arch selection
    is64_         = true;
    mappedImage_  = mappedImage;
    mappedBase_   = mappedImage ? base : 0;
    imageBase_    = base;
    entryRVA_     = 0;                    // no fabricated header entry point
    exportRVA_    = 0; exportSize_ = 0;
    importRVA_    = 0; importSize_ = 0;
    relocRVA_     = 0; relocSize_  = 0;
    exceptRVA_    = 0; exceptSize_ = 0;
    overlayOffset_= 0; overlaySize_= 0;
    securityOff_  = 0; securitySize_ = 0;
    clrRva_       = 0; clrSize_ = 0;
    sizeOfHeaders_= 0;
    sections_.clear();
    exports_.clear();
    imports_.clear();
    relocs_.clear();
    javaClass_.reset();

    Section raw;
    raw.name            = ".raw";
    raw.virtualAddress  = 0;
    raw.virtualSize     = static_cast<uint64_t>(data_.size());
    raw.rawOffset       = 0;
    raw.rawSize         = static_cast<uint64_t>(data_.size());
    raw.characteristics = 0x60000020u; // code | execute | read (synthetic)
    raw.executable      = true;
    sections_.push_back(std::move(raw));
    return true;
}

bool BinaryFile::loadRaw(const std::string& path, uint64_t base) {
    clear();
    const std::filesystem::path fsPath = PathFromUtf8(path);
    std::ifstream f(fsPath, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    if (n <= 0) return false;
    f.seekg(0);
    data_.resize(static_cast<size_t>(n));
    if (!f.read(reinterpret_cast<char*>(data_.data()), n)) { clear(); return false; }
    if (!initializeRawLayout(base)) { clear(); return false; }
    path_ = DurableUtf8Path(fsPath);
    return true;
}

bool BinaryFile::loadFromMemory(std::vector<uint8_t> bytes, uint64_t base, const std::string& name) {
    clear();
    if (bytes.size() < 0x40) return false;
    data_ = std::move(bytes);
    path_ = name;
    // A live PE mapping: parse the headers but locate section data by RVA and force
    // the runtime base. Anything else is treated as a flat blob mapped at `base`.
    if (data_[0] == 'M' && data_[1] == 'Z') {
        mappedImage_ = true;
        mappedBase_  = base;
        if (parsePE()) return true;     // parsePE honours mappedImage_/mappedBase_
        // Not a valid PE after all: fall back to one clean flat mapping below.
    }
    if (!initializeRawLayout(base, true)) { clear(); return false; }
    return true;
}

uint64_t BinaryFile::contentHash() const {
    if (hashValid_) return hash_;   // pristine value, cached before any writeImage() patch
    // FNV-1a, 64-bit. Mixes the length in so two blobs that differ only by
    // trailing zero padding still hash differently.
    uint64_t h = 1469598103934665603ull;
    for (uint8_t b : data_) { h ^= b; h *= 1099511628211ull; }
    h ^= data_.size(); h *= 1099511628211ull;
    hash_ = h; hashValid_ = true;
    return h;
}

// Overwrite up to n bytes of the in-memory image so the disassembly reflects an
// applied or reverted patch. Maps the VA to a file offset; bytes() / ptrFromVA
// then return the patched view. contentHash() is intentionally left untouched
// (it is cached from the pristine file at load).
size_t BinaryFile::writeImage(uint64_t va, const uint8_t* in, size_t n) {
    uint64_t off = 0;
    if (!in || !n || !vaToOffset(va, off)) return 0;
    size_t w = 0;
    for (; w < n && (size_t)off + w < data_.size(); ++w) data_[(size_t)off + w] = in[w];
    if (w) ++imageRevision_;
    return w;
}

template <typename T>
static T rd(const std::vector<uint8_t>& d, size_t off) {
    T v{};
    // No-overflow bound: `off + sizeof(T)` can wrap when off is near SIZE_MAX (a
    // hostile e_shoff/e_lfanew), letting a wild memcpy slip past the guard. Test the
    // two halves separately so the add never happens.
    if (off <= d.size() && sizeof(T) <= d.size() - off) std::memcpy(&v, d.data() + off, sizeof(T));
    return v;
}

bool BinaryFile::parsePE() {
    const uint32_t e_lfanew = rd<uint32_t>(data_, 0x3C);
    // Widen before the add so a hostile e_lfanew near UINT32_MAX cannot wrap the
    // bound check and let the memcmp below read far past the buffer.
    if (static_cast<uint64_t>(e_lfanew) + 4 > data_.size()) return false;
    if (std::memcmp(data_.data() + e_lfanew, "PE\0\0", 4) != 0) return false;

    const size_t coff = static_cast<size_t>(e_lfanew) + 4;
    switch (rd<uint16_t>(data_, coff + 0)) {     // COFF Machine field
        case 0x014C: machine_ = MachineArch::X86;   break;
        case 0x8664: machine_ = MachineArch::X64;   break;
        case 0x01C0: case 0x01C2: case 0x01C4: machine_ = MachineArch::ARM; break; // ARM / Thumb / ARMNT
        case 0xAA64: machine_ = MachineArch::ARM64; break;
        case 0x0166: case 0x0266: case 0x0366: case 0x0466: machine_ = MachineArch::MIPS; break; // R4000/MIPS variants
        case 0x01F0: case 0x01F1: machine_ = MachineArch::PPC; break;   // PowerPC / PowerPCFP
        case 0x5032: machine_ = MachineArch::RISCV;   break;            // RISC-V 32
        case 0x5064: machine_ = MachineArch::RISCV64; break;            // RISC-V 64
        default:     machine_ = MachineArch::Unknown; break;
    }
    const uint16_t numSections = rd<uint16_t>(data_, coff + 2);
    const uint16_t optSize     = rd<uint16_t>(data_, coff + 16);
    const size_t opt = coff + 20;
    if (opt > data_.size() || optSize > data_.size() - opt || optSize < 64) return false;
    const uint16_t magic = rd<uint16_t>(data_, opt);
    size_t dataDirRel = 0; // optional-header-relative data-directory array offset

    if (magic == 0x20B) {        // PE32+
        format_   = BinFormat::PE32Plus;
        is64_     = true;
        entryRVA_ = rd<uint32_t>(data_, opt + 16);
        imageBase_= rd<uint64_t>(data_, opt + 24);
        dataDirRel= 112;
    } else if (magic == 0x10B) { // PE32
        format_   = BinFormat::PE32;
        is64_     = false;
        entryRVA_ = rd<uint32_t>(data_, opt + 16);
        imageBase_= rd<uint32_t>(data_, opt + 28);
        dataDirRel= 96;
    } else {
        return false;
    }

    // For a live process mapping the header's preferred ImageBase is irrelevant under
    // ASLR — the module is actually at mappedBase_. Override before parseImports/Relocs
    // so every resolved VA (IAT slots, reloc targets) is a real runtime address.
    if (mappedImage_) imageBase_ = mappedBase_;

    // SizeOfHeaders is at the same offset in PE32 and PE32+. The optional
    // header bound above makes this a declared, file-backed field rather than
    // bytes borrowed from the section table of a truncated header.
    sizeOfHeaders_ = rd<uint32_t>(data_, opt + 60);

    // Data directory: [0] export, [1] import, [5] base relocations. Only read a
    // directory slot the header actually declares (NumberOfRvaAndSizes sits in
    // the 4 bytes immediately before the array); out-of-range slots stay 0 so
    // parseImports/parseRelocs no-op rather than aliasing the section table.
    const uint32_t numDirs = dataDirRel <= optSize
                           ? rd<uint32_t>(data_, opt + dataDirRel - 4) : 0u;
    auto dir = [&](uint32_t i, uint32_t fieldOffset) -> uint32_t {
        const uint64_t rel = static_cast<uint64_t>(dataDirRel) +
                             static_cast<uint64_t>(i) * 8 + fieldOffset;
        if (i >= numDirs || rel + sizeof(uint32_t) > optSize) return 0u;
        return rd<uint32_t>(data_, opt + static_cast<size_t>(rel));
    };
    exportRVA_  = dir(0, 0);  exportSize_ = dir(0, 4);
    importRVA_  = dir(1, 0);  importSize_ = dir(1, 4);
    exceptRVA_  = dir(3, 0);  exceptSize_ = dir(3, 4);  // [3] exception (.pdata RUNTIME_FUNCTIONs)
    securityOff_= dir(4, 0);  securitySize_ = dir(4, 4); // [4] security: FILE OFFSET, not RVA
    relocRVA_   = dir(5, 0);  relocSize_  = dir(5, 4);
    clrRva_     = dir(14, 0); clrSize_ = dir(14, 4);  // [14] CLR/COM descriptor (.NET)

    size_t sec = opt + optSize;
    for (uint16_t i = 0; i < numSections; ++i, sec += 40) {
        if (sec + 40 > data_.size()) break;
        Section s;
        char name[9] = {0};
        std::memcpy(name, data_.data() + sec, 8);
        s.name            = name;
        s.virtualSize     = rd<uint32_t>(data_, sec + 8);
        s.virtualAddress  = rd<uint32_t>(data_, sec + 12);
        if (mappedImage_) {
            // In a process mapping the raw data lives at the section's RVA (and the
            // whole virtual extent is present, zero-filled), so address it by RVA.
            s.rawOffset = s.virtualAddress;
            s.rawSize   = s.virtualSize ? s.virtualSize : rd<uint32_t>(data_, sec + 16);
        } else {
            s.rawSize   = rd<uint32_t>(data_, sec + 16);
            s.rawOffset = rd<uint32_t>(data_, sec + 20);
        }
        s.characteristics = rd<uint32_t>(data_, sec + 36);
        s.executable      = (s.characteristics & 0x20000000u) != 0; // IMAGE_SCN_MEM_EXECUTE
        sections_.push_back(s);
    }

    // A malformed SizeOfHeaders may extend over the first section's file bytes.
    // Header RVA mapping must remain one-to-one, so stop it at the earliest
    // file-backed section offset as well as at EOF. Offset zero is included:
    // the mapping routines treat a section with rawSize > 0 / rawOffset == 0
    // as owning those bytes, so retaining a simultaneous header mapping would
    // break VA<->offset inversion. For mapped images
    // rawOffset is the section RVA, giving the equivalent in-memory boundary.
    uint64_t effectiveHeaders = std::min<uint64_t>(sizeOfHeaders_, data_.size());
    for (const Section& s : sections_) {
        if (!s.rawSize) continue;
        effectiveHeaders = std::min(effectiveHeaders, s.rawOffset);
    }
    sizeOfHeaders_ = static_cast<uint32_t>(effectiveHeaders);

    // PE overlay: anything in the file past the end of all section raw data (and
    // past the headers, so a sectionless PE doesn't claim the whole file). Only
    // meaningful for an on-disk load — a live mapping repurposes rawOffset as the
    // RVA above, so end-of-raw-data math would be nonsense there. Each section's
    // end is clamped to the file size so a hostile rawOffset/rawSize can't wrap
    // 64-bit math or push `end` past EOF and invent a negative-sized overlay.
    if (!mappedImage_) {
        uint64_t end = static_cast<uint64_t>(sec);   // end of the section table
        if (end > data_.size()) end = data_.size();
        for (const Section& s : sections_) {
            uint64_t e = (s.rawOffset <= data_.size() && s.rawSize <= data_.size() - s.rawOffset)
                             ? s.rawOffset + s.rawSize
                             : static_cast<uint64_t>(data_.size());
            if (e > end) end = e;
        }
        if (data_.size() > end) {
            overlayOffset_ = end;
            overlaySize_   = data_.size() - end;
        }
    }

    parseExports();   // needs sections_ for RVA translation / code classification
    parseImports();
    parseRelocs();
    return true;
}

// IMAGE_EXPORT_DIRECTORY + EAT/name/ordinal tables. The export model retains
// ordinal-only entries, multiple names for one ordinal (aliases), forwarded
// exports, and non-code/data exports. Every table and string walk is bounded by
// mapped bytes plus a hard row cap so hostile counts cannot allocate or spin
// without limit. Name bytes remain views into data_ until the final bounded
// rows are materialized, so repeated pointers cannot multiply 4 KiB strings
// into gigabytes of temporary and result storage.
void BinaryFile::parseExports() {
    exports_.clear();
    if (!exportRVA_) return;

    size_t dirAvail = 0;
    const uint8_t* dir = ptrFromRVA(exportRVA_, dirAvail);
    if (!dir || dirAvail < 40) return;

    uint32_t ordinalBase = 0, numberOfFunctions = 0, numberOfNames = 0;
    uint32_t functionsRVA = 0, namesRVA = 0, ordinalsRVA = 0;
    std::memcpy(&ordinalBase,       dir + 16, 4);
    std::memcpy(&numberOfFunctions, dir + 20, 4);
    std::memcpy(&numberOfNames,     dir + 24, 4);
    std::memcpy(&functionsRVA,      dir + 28, 4);
    std::memcpy(&namesRVA,          dir + 32, 4);
    std::memcpy(&ordinalsRVA,       dir + 36, 4);
    if (!numberOfFunctions || !functionsRVA) return;

    constexpr size_t kMaxExportRows       = 200000;
    constexpr size_t kMaxString           = 4096;
    constexpr size_t kMaxStoredStringBytes= 8 * 1024 * 1024;
    constexpr size_t kMaxStringScanBytes  = 16 * 1024 * 1024;

    size_t eatAvail = 0;
    const uint8_t* eatBytes = ptrFromRVA(functionsRVA, eatAvail);
    if (!eatBytes) return;
    const size_t functionCount = std::min<size_t>(
        static_cast<size_t>(std::min<uint64_t>(numberOfFunctions, kMaxExportRows)),
        eatAvail / sizeof(uint32_t));
    if (!functionCount) return;

    std::vector<uint32_t> eat(functionCount);
    std::memcpy(eat.data(), eatBytes, functionCount * sizeof(uint32_t));
    std::vector<std::vector<std::string_view>> aliases(functionCount);

    // Require a terminator within mapped data and the cap. Malformed names are
    // ignored instead of leaking an arbitrary section tail into the UI.
    size_t scannedStringBytes = 0;
    auto stringAt = [&](uint32_t rva, size_t extraLimit) -> std::string_view {
        size_t avail = 0;
        const uint8_t* p = ptrFromRVA(rva, avail);
        if (!p) return {};
        if (scannedStringBytes >= kMaxStringScanBytes) return {};
        const size_t remainingWork = kMaxStringScanBytes - scannedStringBytes;
        const size_t limit = std::min({avail, extraLimit, remainingWork});
        size_t n = 0;
        while (n < limit) {
            ++scannedStringBytes; // charge every inspected byte, including NUL
            if (!p[n]) return std::string_view(reinterpret_cast<const char*>(p), n);
            ++n;
        }
        return {};
    };

    // A hostile table often repeats one long name RVA for every row. Cache the
    // bounded scan, then dedupe aliases by (ordinal, text), including identical
    // strings stored at different RVAs. string_views are safe because data_ is
    // immutable for the duration of this parse.
    std::unordered_map<uint32_t, std::string_view> nameCache;
    nameCache.reserve(std::min<size_t>(numberOfNames, kMaxExportRows));
    auto cachedNameAt = [&](uint32_t rva) -> std::string_view {
        auto [it, inserted] = nameCache.try_emplace(rva);
        if (inserted) it->second = stringAt(rva, kMaxString);
        return it->second;
    };
    struct AliasKey {
        uint32_t ordinalIndex;
        std::string_view name;
        bool operator==(const AliasKey&) const = default;
    };
    struct AliasKeyHash {
        size_t operator()(const AliasKey& key) const noexcept {
            const size_t h1 = std::hash<uint32_t>{}(key.ordinalIndex);
            const size_t h2 = std::hash<std::string_view>{}(key.name);
            return h1 ^ (h2 + static_cast<size_t>(0x9e3779b9u) + (h1 << 6) + (h1 >> 2));
        }
    };
    std::unordered_set<AliasKey, AliasKeyHash> seenAliases;
    seenAliases.reserve(std::min<size_t>(numberOfNames, kMaxExportRows));
    std::unordered_set<uint64_t> seenAliasPointers;
    seenAliasPointers.reserve(std::min<size_t>(numberOfNames, kMaxExportRows));

    size_t namesAvail = 0, ordinalsAvail = 0;
    const uint8_t* nameTable = namesRVA ? ptrFromRVA(namesRVA, namesAvail) : nullptr;
    const uint8_t* ordinalTable = ordinalsRVA ? ptrFromRVA(ordinalsRVA, ordinalsAvail) : nullptr;
    if (nameTable && ordinalTable) {
        const size_t nameCount = std::min<size_t>({
            static_cast<size_t>(std::min<uint64_t>(numberOfNames, kMaxExportRows)),
            namesAvail / sizeof(uint32_t), ordinalsAvail / sizeof(uint16_t)
        });
        for (size_t i = 0; i < nameCount; ++i) {
            uint32_t nameRVA = 0;
            uint16_t ordinalIndex = 0;
            std::memcpy(&nameRVA, nameTable + i * 4, 4);
            std::memcpy(&ordinalIndex, ordinalTable + i * 2, 2);
            if (ordinalIndex >= functionCount || !eat[ordinalIndex]) continue;
            const uint64_t pointerKey = (static_cast<uint64_t>(ordinalIndex) << 32) | nameRVA;
            if (!seenAliasPointers.insert(pointerKey).second) continue;
            const std::string_view name = cachedNameAt(nameRVA);
            if (!name.empty() && seenAliases.insert({ordinalIndex, name}).second)
                aliases[ordinalIndex].push_back(name);
        }
    }

    const uint64_t exportEnd = static_cast<uint64_t>(exportRVA_) + exportSize_;
    auto targetIsCode = [&](uint32_t rva) {
        for (const Section& section : sections_) {
            if (!section.executable || rva < section.virtualAddress) continue;
            const uint64_t span = std::max(section.virtualSize, section.rawSize);
            if (static_cast<uint64_t>(rva) - section.virtualAddress < span) return true;
        }
        return false;
    };

    exports_.reserve(std::min(kMaxExportRows, functionCount + seenAliases.size()));
    size_t storedStringBytes = 0;
    for (size_t i = 0; i < functionCount; ++i) {
        if (exports_.size() >= kMaxExportRows) break;
        const uint32_t rva = eat[i];
        if (!rva) continue;                         // an unassigned ordinal gap

        const bool forwarded = exportSize_ && rva >= exportRVA_ &&
                               static_cast<uint64_t>(rva) < exportEnd;
        std::string_view forwarder;
        if (forwarded) {
            const size_t inDirectory = static_cast<size_t>(exportEnd - rva);
            forwarder = stringAt(rva, std::min(kMaxString, inDirectory));
        }
        const uint64_t va = imageBase_ <= std::numeric_limits<uint64_t>::max() - rva
                          ? imageBase_ + rva : 0;
        size_t targetAvail = 0;
        const bool mapped = !forwarded && va != 0 && ptrFromRVA(rva, targetAvail) != nullptr;
        const bool isCode = mapped && targetIsCode(rva);
        auto append = [&](std::string_view name, bool includeForwarder = true) -> bool {
            if (exports_.size() >= kMaxExportRows) return false;
            const std::string_view storedForwarder = includeForwarder ? forwarder : std::string_view{};
            const size_t rowStringBytes = name.size() + storedForwarder.size();
            if (rowStringBytes > kMaxStoredStringBytes - storedStringBytes) return false;
            Export ex;
            ex.ordinal   = static_cast<uint64_t>(ordinalBase) + i;
            ex.rva       = rva;
            ex.va        = va;
            if (!name.empty()) ex.name.assign(name.data(), name.size());
            if (!storedForwarder.empty())
                ex.forwarder.assign(storedForwarder.data(), storedForwarder.size());
            ex.forwarded = forwarded;
            ex.mapped    = mapped;
            ex.isCode    = isCode;
            exports_.push_back(std::move(ex));
            storedStringBytes += rowStringBytes;
            return true;
        };
        if (aliases[i].empty()) {
            if (!append({})) append({}, false); // metadata-only row after string-budget exhaustion
        }
        else {
            bool emittedAlias = false;
            for (const std::string_view alias : aliases[i]) {
                if (!append(alias)) break;
                emittedAlias = true;
            }
            // Preserve the exported ordinal/target even when a hostile alias
            // set exhausts the aggregate string budget.
            if (!emittedAlias && !append({})) append({}, false);
        }
    }
}

// IMAGE_IMPORT_DESCRIPTOR walk: resolve each IAT slot to "DLL.function".
void BinaryFile::parseImports() {
    if (!importRVA_) return;
    const bool pe64    = (format_ == BinFormat::PE32Plus);
    const uint32_t pSz = pe64 ? 8u : 4u;
    const uint64_t ord = pe64 ? 0x8000000000000000ull : 0x80000000ull;

    for (uint32_t desc = 0; desc < 0x10000; desc += 20) {
        size_t av = 0;
        const uint8_t* d = ptrFromRVA((uint64_t)importRVA_ + desc, av);
        if (!d || av < 20) break;
        uint32_t oft, nameRVA, iatRVA;
        std::memcpy(&oft, d + 0, 4); std::memcpy(&nameRVA, d + 12, 4); std::memcpy(&iatRVA, d + 16, 4);
        if (!oft && !nameRVA && !iatRVA) break;   // null terminator descriptor

        std::string dll;
        if (size_t na = 0; const uint8_t* np = ptrFromRVA(nameRVA, na))
            for (size_t k = 0; k < na && k < 128 && np[k]; ++k) dll.push_back((char)np[k]);

        uint32_t ilt = oft ? oft : iatRVA;        // bound imports: OFT may be 0
        for (uint32_t k = 0; k < 50000; ++k) {
            size_t ta = 0;
            const uint8_t* tp = ptrFromRVA((uint64_t)ilt + (uint64_t)k * pSz, ta);
            if (!tp || ta < pSz) break;
            uint64_t thunk = 0; std::memcpy(&thunk, tp, pSz);
            if (!thunk) break;                    // end of this DLL's thunk array
            uint64_t iatVA = imageBase_ + iatRVA + (uint64_t)k * pSz;
            std::string fn;
            if (thunk & ord) { char b[24]; std::snprintf(b, sizeof(b), "#%u", (unsigned)(thunk & 0xFFFF)); fn = b; }
            else {
                uint32_t hn = (uint32_t)(thunk & 0x7FFFFFFF);
                if (size_t ha = 0; const uint8_t* hp = ptrFromRVA(hn, ha))
                    for (size_t z = 2; z < ha && z < 130 && hp[z]; ++z) fn.push_back((char)hp[z]);
            }
            if (!fn.empty()) imports_.push_back({ iatVA, dll, fn });
            if (imports_.size() > 100000) return;
        }
    }
}

// IMAGE_BASE_RELOCATION blocks -> (VA, type) pairs.
void BinaryFile::parseRelocs() {
    if (!relocRVA_) return;
    for (uint32_t off = 0; off + 8 <= relocSize_ && relocs_.size() < 200000; ) {
        size_t av = 0;
        const uint8_t* b = ptrFromRVA((uint64_t)relocRVA_ + off, av);
        if (!b || av < 8) break;
        uint32_t pageRVA, blockSize;
        std::memcpy(&pageRVA, b, 4); std::memcpy(&blockSize, b + 4, 4);
        if (blockSize < 8 || blockSize > av) break;
        uint32_t entries = (blockSize - 8) / 2;
        for (uint32_t e = 0; e < entries; ++e) {
            uint16_t v; std::memcpy(&v, b + 8 + e * 2, 2);
            int type = v >> 12;
            if (type != 0) relocs_.emplace_back(imageBase_ + pageRVA + (v & 0xFFF), type);   // skip ABSOLUTE padding
        }
        off += blockSize;
    }
}

// x64 .pdata: an array of 12-byte RUNTIME_FUNCTION { BeginAddress, EndAddress,
// UnwindData } RVAs. Two kinds of entry describe a CONTINUATION of an earlier
// function rather than a new one and are skipped:
//   - UnwindData with bit 0 set points at a parent RUNTIME_FUNCTION directly;
//   - an UNWIND_INFO whose flags carry UNW_FLAG_CHAININFO (0x4).
// Bounded + clamped like every other table walk (a hostile size/RVA must not
// spin or read wild).
std::vector<std::pair<uint64_t, uint64_t>> BinaryFile::pdataRanges() const {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (!exceptRVA_ || exceptSize_ < 12) return out;
    if (format_ != BinFormat::PE32Plus || machine_ != MachineArch::X64) return out;
    const uint32_t count = std::min<uint32_t>(exceptSize_ / 12, 200000);
    out.reserve(std::min<uint32_t>(count, 4096));
    for (uint32_t i = 0; i < count; ++i) {
        size_t av = 0;
        const uint8_t* p = ptrFromRVA((uint64_t)exceptRVA_ + (uint64_t)i * 12, av);
        if (!p || av < 12) break;
        uint32_t begin = 0, end = 0, unwind = 0;
        std::memcpy(&begin, p, 4); std::memcpy(&end, p + 4, 4); std::memcpy(&unwind, p + 8, 4);
        if (!begin || end <= begin) continue;             // hostile/empty range
        if (unwind & 1) continue;                         // chained: parent RUNTIME_FUNCTION ref
        size_t ua = 0;
        if (const uint8_t* u = ptrFromRVA(unwind, ua); u && ua >= 1 && ((u[0] >> 3) & 0x4))
            continue;                                     // UNW_FLAG_CHAININFO: continuation chunk
        out.emplace_back(imageBase_ + begin, imageBase_ + end);
    }
    return out;
}

// ------------------------------------------------------------- Java class --
// imageBase_ stays 0 and every section maps identity (virtualAddress ==
// rawOffset == file offset), so VA == file offset throughout: ptrFromVA /
// vaToOffset / offsetToVA line up, and JvmDisassembler's bci math
// (va - method code start) is exact. Each method body becomes its own
// executable section (the listing walks executable sections, so dividers and
// function discovery land on real method starts); one whole-file data section
// at the end backs hex / string-scan / byte-search views for the rest.
bool BinaryFile::parseJavaClass() {
    auto cf = std::make_shared<JvmClassFile>(ParseJavaClass(data_.data(), data_.size()));
    if (!cf->ok) return false;
    format_    = BinFormat::JavaClass;
    machine_   = MachineArch::JVM;
    is64_      = false;
    imageBase_ = 0;
    javaClass_ = cf;

    const std::string cls = JvmShortClassName(cf->thisClass);
    uint64_t entryMain = 0, entryClinit = 0, entryFirst = 0;
    for (const auto& m : cf->methods) {
        if (!m.codeLength) continue;                      // abstract / native: no body
        if ((uint64_t)m.codeOffset + m.codeLength > data_.size()) continue;
        Section s;
        s.name           = cls + "." + m.name;
        s.virtualAddress = m.codeOffset;
        s.virtualSize    = m.codeLength;
        s.rawOffset      = m.codeOffset;
        s.rawSize        = m.codeLength;
        s.executable     = true;
        sections_.push_back(std::move(s));
        if (!entryFirst) entryFirst = m.codeOffset;
        if (!entryMain && m.name == "main" && (m.accessFlags & JVM_ACC_STATIC))
            entryMain = m.codeOffset;
        if (!entryClinit && m.name == "<clinit>") entryClinit = m.codeOffset;
    }
    entryRVA_ = entryMain ? entryMain : entryClinit ? entryClinit : entryFirst;

    Section all;
    all.name           = "classfile";
    all.virtualAddress = 0;
    all.virtualSize    = data_.size();
    all.rawOffset      = 0;
    all.rawSize        = data_.size();
    all.executable     = false;
    sections_.push_back(std::move(all));                  // last: method sections win per-VA lookups
    return true;
}

const Section* BinaryFile::firstCodeSection() const {
    for (const auto& s : sections_) if (s.executable) return &s;
    return sections_.empty() ? nullptr : &sections_.front();
}

const uint8_t* BinaryFile::ptrFromRVA(uint64_t rva, size_t& availOut) const {
    // rva is 64-bit so callers walking import/reloc tables (rva + k*stride) can't
    // wrap a 32-bit add and alias an earlier in-bounds slot; ptrFromVA bounds-checks.
    if (rva > std::numeric_limits<uint64_t>::max() - imageBase_) {
        availOut = 0;
        return nullptr;
    }
    return ptrFromVA(imageBase_ + rva, availOut);
}

const uint8_t* BinaryFile::ptrFromVA(uint64_t va, size_t& availOut) const {
    availOut = 0;
    if (format_ == BinFormat::Raw) {
        if (va < imageBase_) return nullptr;
        const uint64_t off = va - imageBase_;
        if (off < data_.size()) { availOut = data_.size() - (size_t)off; return data_.data() + off; }
        return nullptr;
    }
    if (va < imageBase_) return nullptr;   // below the image base -> not mapped
    const uint64_t rva = va - imageBase_;
    for (const auto& s : sections_) {
        // No-wrap containment: `base + size` overflows on 64-bit ELF/Mach-O fields.
        if (rva >= s.virtualAddress && rva - s.virtualAddress < s.virtualSize) {
            const uint64_t delta = rva - s.virtualAddress;
            if (delta >= s.rawSize) return nullptr; // in virtual padding
            // A malformed image can claim a rawOffset/rawSize past EOF; clamp the
            // returned base and the reported span to the bytes actually present.
            const uint64_t fileOff = s.rawOffset + delta;
            if (fileOff >= data_.size()) return nullptr;
            availOut = (size_t)std::min<uint64_t>(s.rawSize - delta, data_.size() - fileOff);
            return data_.data() + fileOff;
        }
    }
    // PE headers are mapped 1:1 (RVA == file offset), but only for the span
    // explicitly declared by SizeOfHeaders and actually present in the image.
    // This lets legitimate header-resident directories resolve without turning
    // the virtual gap before the first section into file-backed memory.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        rva < sizeOfHeaders_ && rva < data_.size()) {
        availOut = static_cast<size_t>(std::min<uint64_t>(
            static_cast<uint64_t>(sizeOfHeaders_) - rva, data_.size() - rva));
        return data_.data() + static_cast<size_t>(rva);
    }
    return nullptr;
}

bool BinaryFile::offsetToVA(uint64_t off, uint64_t& vaOut) const {
    if (format_ == BinFormat::Raw) {
        if (off >= data_.size()) return false;
        if (off > std::numeric_limits<uint64_t>::max() - imageBase_) return false;
        vaOut = imageBase_ + off;   // Raw: VA space == file space
        return true;
    }
    // Find the section whose raw data contains this offset and remap to its RVA.
    for (const auto& s : sections_) {
        if (!s.rawSize) continue;
        if (off >= s.rawOffset && off - s.rawOffset < s.rawSize) {   // no-wrap containment
            vaOut = imageBase_ + s.virtualAddress + (off - s.rawOffset);
            return true;
        }
    }
    // Only the PE header bytes declared by SizeOfHeaders map 1:1. Using the
    // first section's raw offset here would accidentally bless padding or a
    // malformed section-table gap as header data.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        off < sizeOfHeaders_ && off < data_.size()) {
        vaOut = imageBase_ + off;
        return true;
    }
    return false;
}

bool BinaryFile::vaToOffset(uint64_t va, uint64_t& offOut) const {
    if (format_ == BinFormat::Raw) {
        if (va < imageBase_) return false;
        uint64_t off = va - imageBase_;
        if (off >= data_.size()) return false;
        offOut = off; return true;
    }
    if (va < imageBase_) return false;     // below the image base -> not mapped
    const uint64_t rva = va - imageBase_;
    for (const auto& s : sections_) {
        if (!s.rawSize) continue;
        if (rva >= s.virtualAddress && rva - s.virtualAddress < s.virtualSize) {   // no-wrap containment
            uint64_t delta = rva - s.virtualAddress;
            if (delta >= s.rawSize) return false;        // in virtual (zero-filled) padding
            uint64_t off = s.rawOffset + delta;
            if (off >= data_.size()) return false;
            offOut = off; return true;
        }
    }
    // Header bytes explicitly declared by SizeOfHeaders map 1:1 (RVA == file
    // offset) for PE only. The gap up to the first section RVA remains unmapped.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        rva < sizeOfHeaders_ && rva < data_.size()) {
        offOut = rva;
        return true;
    }
    return false;
}

// --------------------------------------------------------------------- ELF --
// LE ELF32/ELF64. imageBase_ is kept at 0 and each section's virtualAddress
// holds the absolute sh_addr, so the shared ptrFromVA/vaToOffset math (rva ==
// va - imageBase_) lines up with the disassembly.
bool BinaryFile::parseELF() {
    if (data_.size() < 0x40) return false;
    const uint8_t ei_class = data_[4];   // 1 = 32-bit, 2 = 64-bit
    const uint8_t ei_data  = data_[5];   // 1 = little-endian
    if (ei_data != 1) return false;      // big-endian not supported by this loader
    const bool elf64 = (ei_class == 2);
    is64_      = elf64;
    format_    = BinFormat::ELF;
    imageBase_ = 0;

    switch (rd<uint16_t>(data_, 18)) {   // e_machine
        case 0x03: machine_ = MachineArch::X86;   break;
        case 0x3E: machine_ = MachineArch::X64;   break;
        case 0x28: machine_ = MachineArch::ARM;   break;
        case 0xB7: machine_ = MachineArch::ARM64; break;
        case 0x08: machine_ = elf64 ? MachineArch::MIPS64 : MachineArch::MIPS; break;  // EM_MIPS
        case 0x14: machine_ = MachineArch::PPC;   break;                                // EM_PPC
        case 0x15: machine_ = MachineArch::PPC64; break;                                // EM_PPC64
        case 0xF3: machine_ = elf64 ? MachineArch::RISCV64 : MachineArch::RISCV; break; // EM_RISCV
        default:   machine_ = elf64 ? MachineArch::X64 : MachineArch::X86; break;
    }

    uint64_t e_shoff; uint16_t e_shentsize, e_shnum, e_shstrndx;
    if (elf64) {
        entryRVA_   = rd<uint64_t>(data_, 24);
        e_shoff     = rd<uint64_t>(data_, 40);
        e_shentsize = rd<uint16_t>(data_, 58);
        e_shnum     = rd<uint16_t>(data_, 60);
        e_shstrndx  = rd<uint16_t>(data_, 62);
    } else {
        entryRVA_   = rd<uint32_t>(data_, 24);
        e_shoff     = rd<uint32_t>(data_, 32);
        e_shentsize = rd<uint16_t>(data_, 46);
        e_shnum     = rd<uint16_t>(data_, 48);
        e_shstrndx  = rd<uint16_t>(data_, 50);
    }
    if (!e_shoff || !e_shnum || e_shnum > 4096) {
        // No usable section header table (fully stripped binary). Fall back to the
        // program header table and synthesize a Section per PT_LOAD segment so the
        // image still maps + disassembles.
        uint64_t e_phoff; uint16_t e_phentsize, e_phnum;
        if (elf64) { e_phoff = rd<uint64_t>(data_, 32); e_phentsize = rd<uint16_t>(data_, 54); e_phnum = rd<uint16_t>(data_, 56); }
        else       { e_phoff = rd<uint32_t>(data_, 28); e_phentsize = rd<uint16_t>(data_, 42); e_phnum = rd<uint16_t>(data_, 44); }
        if (e_phoff && e_phnum && e_phnum <= 4096) {
            for (uint16_t i = 0; i < e_phnum; ++i) {
                size_t base = (size_t)e_phoff + (size_t)i * e_phentsize;
                if (base > data_.size() || e_phentsize > data_.size() - base) break;  // no-wrap
                uint32_t p_type = rd<uint32_t>(data_, base + 0);
                if (p_type != 1 /*PT_LOAD*/) continue;
                uint64_t p_offset, p_vaddr, p_filesz, p_memsz; uint32_t p_flags;
                if (elf64) { p_flags = rd<uint32_t>(data_, base + 4); p_offset = rd<uint64_t>(data_, base + 8);
                             p_vaddr = rd<uint64_t>(data_, base + 16); p_filesz = rd<uint64_t>(data_, base + 32); p_memsz = rd<uint64_t>(data_, base + 40); }
                else       { p_offset = rd<uint32_t>(data_, base + 4); p_vaddr = rd<uint32_t>(data_, base + 8);
                             p_filesz = rd<uint32_t>(data_, base + 16); p_memsz = rd<uint32_t>(data_, base + 20); p_flags = rd<uint32_t>(data_, base + 24); }
                Section s;
                s.virtualAddress = p_vaddr;
                s.virtualSize    = p_memsz;
                s.rawOffset      = p_offset;
                s.rawSize        = p_filesz;
                s.executable     = (p_flags & 0x1 /*PF_X*/) != 0;
                sections_.push_back(std::move(s));
            }
        }
        return !sections_.empty() || entryRVA_ != 0;
    }

    auto shField = [&](uint16_t i, size_t off32, size_t off64) -> uint64_t {
        size_t base = (size_t)e_shoff + (size_t)i * e_shentsize;
        return elf64 ? rd<uint64_t>(data_, base + off64) : rd<uint32_t>(data_, base + off32);
    };
    // String table for section names (section header index e_shstrndx).
    uint64_t strOff = (e_shstrndx < e_shnum) ? (elf64 ? rd<uint64_t>(data_, (size_t)e_shoff + (size_t)e_shstrndx * e_shentsize + 24)
                                                      : rd<uint32_t>(data_, (size_t)e_shoff + (size_t)e_shstrndx * e_shentsize + 16))
                                             : 0;
    for (uint16_t i = 0; i < e_shnum; ++i) {
        size_t base = (size_t)e_shoff + (size_t)i * e_shentsize;
        if (base > data_.size() || e_shentsize > data_.size() - base) break;  // no-wrap
        uint32_t sh_name  = rd<uint32_t>(data_, base + 0);
        uint32_t sh_type  = rd<uint32_t>(data_, base + 4);
        uint64_t sh_flags = elf64 ? rd<uint64_t>(data_, base + 8)  : rd<uint32_t>(data_, base + 8);
        uint64_t sh_addr  = shField(i, 12, 16);
        uint64_t sh_off   = shField(i, 16, 24);
        uint64_t sh_size  = shField(i, 20, 32);
        if (sh_addr == 0 && !(sh_flags & 0x2 /*SHF_ALLOC*/)) continue;   // skip non-loaded (.symtab, .strtab, ...)
        Section s;
        if (strOff) { char nm[33] = {0}; for (int k = 0; k < 32; ++k) { uint8_t c = (uint8_t)rd<uint8_t>(data_, (size_t)strOff + sh_name + k); if (!c) break; nm[k] = (char)c; } s.name = nm; }
        s.virtualAddress  = sh_addr;
        s.virtualSize     = sh_size;
        s.rawOffset       = sh_off;
        s.rawSize         = (sh_type == 8 /*SHT_NOBITS*/) ? 0 : sh_size;   // .bss has no file bytes
        s.executable      = (sh_flags & 0x4 /*SHF_EXECINSTR*/) != 0;
        s.characteristics = (uint32_t)sh_flags;
        sections_.push_back(std::move(s));
    }
    return true;
}

// ------------------------------------------------------------------ Mach-O --
// Thin little-endian Mach-O (32/64). Like ELF, imageBase_ stays 0 and sections
// carry absolute VM addresses.
bool BinaryFile::parseMachO() {
    if (data_.size() < 0x20) return false;
    uint32_t magic = rd<uint32_t>(data_, 0);
    const bool macho64 = (magic == 0xFEEDFACFu);
    is64_      = macho64;
    format_    = BinFormat::MachO;
    imageBase_ = 0;

    switch (rd<uint32_t>(data_, 4)) {   // cputype
        case 0x00000007: machine_ = MachineArch::X86;   break;
        case 0x01000007: machine_ = MachineArch::X64;   break;
        case 0x0000000C: machine_ = MachineArch::ARM;   break;
        case 0x0100000C: machine_ = MachineArch::ARM64; break;
        case 0x00000012: machine_ = MachineArch::PPC;   break;   // CPU_TYPE_POWERPC
        case 0x01000012: machine_ = MachineArch::PPC64; break;   // CPU_TYPE_POWERPC64
        default:         machine_ = macho64 ? MachineArch::X64 : MachineArch::X86; break;
    }

    uint32_t ncmds = rd<uint32_t>(data_, 16);
    size_t   lc    = macho64 ? 32 : 28;     // first load command follows the header
    uint64_t textVmaddr = 0, textFileoff = 0; bool haveText = false;
    uint64_t entryFileoff = 0; bool haveMain = false;

    for (uint32_t c = 0; c < ncmds && lc + 8 <= data_.size(); ++c) {
        uint32_t cmd     = rd<uint32_t>(data_, lc + 0);
        uint32_t cmdsize = rd<uint32_t>(data_, lc + 4);
        if (cmdsize < 8) break;

        if (cmd == 0x19 /*LC_SEGMENT_64*/ || cmd == 0x01 /*LC_SEGMENT*/) {
            const bool seg64 = (cmd == 0x19);
            char seg[17] = {0}; for (int k = 0; k < 16; ++k) seg[k] = (char)rd<uint8_t>(data_, lc + 8 + k);
            uint64_t vmaddr  = seg64 ? rd<uint64_t>(data_, lc + 24) : rd<uint32_t>(data_, lc + 24);
            uint64_t fileoff = seg64 ? rd<uint64_t>(data_, lc + 40) : rd<uint32_t>(data_, lc + 32);
            uint32_t initprot= seg64 ? rd<uint32_t>(data_, lc + 60) : rd<uint32_t>(data_, lc + 44);
            uint32_t nsects  = seg64 ? rd<uint32_t>(data_, lc + 64) : rd<uint32_t>(data_, lc + 48);
            const bool segExec = (initprot & 0x4 /*VM_PROT_EXECUTE*/) != 0;
            if (std::strcmp(seg, "__TEXT") == 0 && !haveText) { textVmaddr = vmaddr; textFileoff = fileoff; haveText = true; }

            size_t sbase = lc + (seg64 ? 72 : 56);
            size_t sstride = seg64 ? 80 : 68;
            for (uint32_t i = 0; i < nsects && sbase <= data_.size() && sstride <= data_.size() - sbase; ++i, sbase += sstride) {
                char sect[17] = {0}; for (int k = 0; k < 16; ++k) sect[k] = (char)rd<uint8_t>(data_, sbase + k);
                uint64_t addr = seg64 ? rd<uint64_t>(data_, sbase + 32) : rd<uint32_t>(data_, sbase + 32);
                uint64_t size = seg64 ? rd<uint64_t>(data_, sbase + 40) : rd<uint32_t>(data_, sbase + 36);
                uint32_t offv = seg64 ? rd<uint32_t>(data_, sbase + 48) : rd<uint32_t>(data_, sbase + 40);
                uint32_t flags= seg64 ? rd<uint32_t>(data_, sbase + 64) : rd<uint32_t>(data_, sbase + 56);
                Section s;
                s.name           = sect;
                s.virtualAddress = addr;
                s.virtualSize    = size;
                s.rawOffset      = offv;
                s.rawSize        = (offv == 0 && std::strcmp(seg, "__TEXT") != 0) ? 0 : size;
                // S_ATTR_PURE_INSTRUCTIONS (0x80000000) / S_ATTR_SOME_INSTRUCTIONS (0x400), or exec segment.
                s.executable     = segExec || (flags & 0x80000000u) || (flags & 0x400u) || std::strcmp(sect, "__text") == 0;
                s.characteristics= flags;
                sections_.push_back(std::move(s));
            }
        } else if (cmd == 0x80000028u /*LC_MAIN*/) {
            entryFileoff = rd<uint64_t>(data_, lc + 8);   // entryoff (file offset)
            haveMain = true;
        }
        lc += cmdsize;
    }

    entryRVA_ = 0;
    if (haveMain && haveText && entryFileoff >= textFileoff)
        entryRVA_ = textVmaddr + (entryFileoff - textFileoff);  // entryoff (file) -> VA
    if (!entryRVA_ && !sections_.empty())                       // fall back to first exec section
        for (const auto& s : sections_) if (s.executable) { entryRVA_ = s.virtualAddress; break; }
    return !sections_.empty() || entryRVA_ != 0;
}

} // namespace ds
