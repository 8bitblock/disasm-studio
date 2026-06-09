#include "BinaryFile.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace ds {

void BinaryFile::clear() {
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
    imports_.clear();
    relocs_.clear();
}

const char* BinaryFile::formatName() const {
    switch (format_) {
        case BinFormat::PE32:     return "PE32 (x86)";
        case BinFormat::PE32Plus: return "PE32+ (x64)";
        case BinFormat::ELF:      return "ELF";
        case BinFormat::MachO:    return "Mach-O";
        case BinFormat::Raw:      return "Raw";
        default:                  return "Unknown";
    }
}

bool BinaryFile::load(const std::string& path) {
    clear();
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    if (n <= 0) return false;
    f.seekg(0);
    data_.resize(static_cast<size_t>(n));
    if (!f.read(reinterpret_cast<char*>(data_.data()), n)) { clear(); return false; }
    path_ = path;

    uint32_t magic = 0;
    if (data_.size() >= 4) std::memcpy(&magic, data_.data(), 4);

    if (data_.size() >= 2 && data_[0] == 'M' && data_[1] == 'Z') {
        if (!parsePE()) format_ = BinFormat::Raw;
    } else if (data_.size() >= 4 && std::memcmp(data_.data(), "\x7F""ELF", 4) == 0) {
        if (!parseELF()) format_ = BinFormat::Raw;
    } else if (magic == 0xFEEDFACEu || magic == 0xFEEDFACFu) {   // Mach-O thin (LE)
        if (!parseMachO()) format_ = BinFormat::Raw;
    } else {
        format_ = BinFormat::Raw;
    }
    return true;
}

bool BinaryFile::loadRaw(const std::string& path, uint64_t base) {
    clear();
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    if (n <= 0) return false;
    f.seekg(0);
    data_.resize(static_cast<size_t>(n));
    if (!f.read(reinterpret_cast<char*>(data_.data()), n)) { clear(); return false; }
    path_      = path;
    format_    = BinFormat::Raw;
    imageBase_ = base;
    entryRVA_  = 0;        // raw blobs have no entry; views start at base
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
        // Not a valid PE after all: fall back to raw.
        sections_.clear(); imports_.clear(); relocs_.clear();
        mappedImage_ = false;
    }
    format_    = BinFormat::Raw;
    imageBase_ = base;
    entryRVA_  = 0;
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
    const uint16_t magic = rd<uint16_t>(data_, opt);
    size_t dataDir = 0; // offset of the data-directory array

    if (magic == 0x20B) {        // PE32+
        format_   = BinFormat::PE32Plus;
        is64_     = true;
        entryRVA_ = rd<uint32_t>(data_, opt + 16);
        imageBase_= rd<uint64_t>(data_, opt + 24);
        dataDir   = opt + 112;
    } else if (magic == 0x10B) { // PE32
        format_   = BinFormat::PE32;
        is64_     = false;
        entryRVA_ = rd<uint32_t>(data_, opt + 16);
        imageBase_= rd<uint32_t>(data_, opt + 28);
        dataDir   = opt + 96;
    } else {
        return false;
    }

    // For a live process mapping the header's preferred ImageBase is irrelevant under
    // ASLR — the module is actually at mappedBase_. Override before parseImports/Relocs
    // so every resolved VA (IAT slots, reloc targets) is a real runtime address.
    if (mappedImage_) imageBase_ = mappedBase_;

    // Data directory: [0] export, [1] import, [5] base relocations. Only read a
    // directory slot the header actually declares (NumberOfRvaAndSizes sits in
    // the 4 bytes immediately before the array); out-of-range slots stay 0 so
    // parseImports/parseRelocs no-op rather than aliasing the section table.
    const uint32_t numDirs = rd<uint32_t>(data_, dataDir - 4);
    auto dir = [&](uint32_t i, uint32_t off) -> uint32_t {
        return (i < numDirs) ? rd<uint32_t>(data_, dataDir + off) : 0u;
    };
    exportRVA_  = dir(0, 0);  exportSize_ = dir(0, 4);
    importRVA_  = dir(1, 8);  importSize_ = dir(1, 12);
    relocRVA_   = dir(5, 40); relocSize_  = dir(5, 44);

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
    parseImports();   // needs sections_ for RVA translation
    parseRelocs();
    return true;
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

const Section* BinaryFile::firstCodeSection() const {
    for (const auto& s : sections_) if (s.executable) return &s;
    return sections_.empty() ? nullptr : &sections_.front();
}

const uint8_t* BinaryFile::ptrFromRVA(uint64_t rva, size_t& availOut) const {
    // rva is 64-bit so callers walking import/reloc tables (rva + k*stride) can't
    // wrap a 32-bit add and alias an earlier in-bounds slot; ptrFromVA bounds-checks.
    return ptrFromVA(imageBase_ + rva, availOut);
}

const uint8_t* BinaryFile::ptrFromVA(uint64_t va, size_t& availOut) const {
    availOut = 0;
    if (format_ == BinFormat::Raw) {
        const uint64_t off = (va >= imageBase_) ? va - imageBase_ : va;
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
    return nullptr;
}

bool BinaryFile::offsetToVA(uint64_t off, uint64_t& vaOut) const {
    if (format_ == BinFormat::Raw) {
        if (off >= data_.size()) return false;
        vaOut = imageBase_ + off;   // Raw: VA space == file space
        return true;
    }
    // Find the section whose raw data contains this offset and remap to its RVA.
    uint64_t firstRaw = 0; bool haveFirst = false;
    for (const auto& s : sections_) {
        if (!s.rawSize) continue;
        if (!haveFirst || s.rawOffset < firstRaw) { firstRaw = s.rawOffset; haveFirst = true; }
        if (off >= s.rawOffset && off - s.rawOffset < s.rawSize) {   // no-wrap containment
            vaOut = imageBase_ + s.virtualAddress + (off - s.rawOffset);
            return true;
        }
    }
    // Bytes before the first section's raw data are the PE headers, which map
    // 1:1 (file offset == RVA). Only PE keeps imageBase_ as the real load base
    // with that header mapping; for ELF/Mach-O an uncovered offset has no VA.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        haveFirst && off < firstRaw) { vaOut = imageBase_ + off; return true; }
    return false;
}

bool BinaryFile::vaToOffset(uint64_t va, uint64_t& offOut) const {
    if (format_ == BinFormat::Raw) {
        uint64_t off = (va >= imageBase_) ? va - imageBase_ : va;
        if (off >= data_.size()) return false;
        offOut = off; return true;
    }
    if (va < imageBase_) return false;     // below the image base -> not mapped
    const uint64_t rva = va - imageBase_;
    uint64_t firstRaw = 0; bool haveFirst = false;
    for (const auto& s : sections_) {
        if (!s.rawSize) continue;
        if (!haveFirst || s.rawOffset < firstRaw) { firstRaw = s.rawOffset; haveFirst = true; }
        if (rva >= s.virtualAddress && rva - s.virtualAddress < s.virtualSize) {   // no-wrap containment
            uint64_t delta = rva - s.virtualAddress;
            if (delta >= s.rawSize) return false;        // in virtual (zero-filled) padding
            uint64_t off = s.rawOffset + delta;
            if (off >= data_.size()) return false;
            offOut = off; return true;
        }
    }
    // Header bytes ahead of the first section's RAW data map 1:1 (RVA == file
    // offset) for PE only. Bound on firstRaw (matching offsetToVA), NOT firstVA:
    // the gap [firstRaw, firstVA) is virtual padding with no file backing, so a
    // patch aimed there must not resolve to unrelated section bytes.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        haveFirst && rva < firstRaw && rva < data_.size()) { offOut = rva; return true; }
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
