// Focused bounded ELF metadata regressions: REL/RELA, PLT/GOT linkage,
// DT_NEEDED, GNU symbol versions, and initialization/finalization entries.

#include "Core/BinaryFile.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

template <typename T>
static void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

struct Strings {
    std::vector<uint8_t> bytes{0};
    uint32_t add(const char* text) {
        const uint32_t offset = static_cast<uint32_t>(bytes.size());
        const size_t length = std::strlen(text) + 1;
        bytes.insert(bytes.end(), text, text + length);
        return offset;
    }
};

static void copyAt(std::vector<uint8_t>& out, size_t offset,
                   const std::vector<uint8_t>& bytes) {
    std::memcpy(out.data() + offset, bytes.data(), bytes.size());
}

static constexpr size_t kElf64ShOff = 0x800;
static std::vector<uint8_t> buildElf64() {
    std::vector<uint8_t> b(0xC00, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 2; b[5] = 1; b[6] = 1;
    put<uint16_t>(b, 16, 3);       // ET_DYN
    put<uint16_t>(b, 18, 0x3E);    // EM_X86_64
    put<uint32_t>(b, 20, 1);
    put<uint64_t>(b, 24, 0);       // legitimate zero VA entry/section mapping
    put<uint64_t>(b, 40, kElf64ShOff);
    put<uint16_t>(b, 52, 64);
    put<uint16_t>(b, 58, 64);
    put<uint16_t>(b, 60, 16);
    put<uint16_t>(b, 62, 13);

    Strings dynstr;
    const uint32_t nFoo = dynstr.add("foo");
    const uint32_t nPuts = dynstr.add("puts");
    const uint32_t nNeeded = dynstr.add("libneeded.so");
    const uint32_t nDef = dynstr.add("VER_DEF");
    const uint32_t nLibc = dynstr.add("libc.so.6");
    const uint32_t nGlibc = dynstr.add("GLIBC_2.2");
    copyAt(b, 0x480, dynstr.bytes);

    Strings shstr;
    const uint32_t sText = shstr.add(".text");
    const uint32_t sDynstr = shstr.add(".dynstr");
    const uint32_t sDynsym = shstr.add(".dynsym");
    const uint32_t sRelaPlt = shstr.add(".rela.plt");
    const uint32_t sPlt = shstr.add(".plt");
    const uint32_t sGotPlt = shstr.add(".got.plt");
    const uint32_t sDynamic = shstr.add(".dynamic");
    const uint32_t sVersym = shstr.add(".gnu.version");
    const uint32_t sVerdef = shstr.add(".gnu.version_d");
    const uint32_t sVerneed = shstr.add(".gnu.version_r");
    const uint32_t sInitArray = shstr.add(".init_array");
    const uint32_t sFiniArray = shstr.add(".fini_array");
    const uint32_t sShstr = shstr.add(".shstrtab");
    const uint32_t sRelDyn = shstr.add(".rel.dyn");
    const uint32_t sGot = shstr.add(".got");
    copyAt(b, 0x600, shstr.bytes);

    auto sh = [&](size_t index, uint32_t name, uint32_t type, uint64_t flags,
                  uint64_t address, uint64_t offset, uint64_t size,
                  uint32_t link = 0, uint32_t info = 0,
                  uint64_t alignment = 1, uint64_t entrySize = 0) {
        const size_t p = kElf64ShOff + index * 64;
        put<uint32_t>(b, p, name); put<uint32_t>(b, p + 4, type);
        put<uint64_t>(b, p + 8, flags); put<uint64_t>(b, p + 16, address);
        put<uint64_t>(b, p + 24, offset); put<uint64_t>(b, p + 32, size);
        put<uint32_t>(b, p + 40, link); put<uint32_t>(b, p + 44, info);
        put<uint64_t>(b, p + 48, alignment); put<uint64_t>(b, p + 56, entrySize);
    };
    sh(1, sText,      1,  0x6, 0x00, 0x100, 0x40, 0, 0, 16);
    sh(2, sDynstr,    3,  0,   0,    0x480, dynstr.bytes.size());
    sh(3, sDynsym,    11, 0,   0,    0x500, 3 * 24, 2, 1, 8, 24);
    sh(4, sRelaPlt,   4,  0,   0,    0x560, 24, 3, 6, 8, 24);
    sh(5, sPlt,       1,  0x6, 0x40, 0x140, 0x20, 0, 0, 16, 16);
    sh(6, sGotPlt,    1,  0x3, 0x80, 0x160, 0x18, 0, 0, 8, 8);
    sh(7, sDynamic,   6,  0x3, 0x100,0x300, 6 * 16, 2, 0, 8, 16);
    sh(8, sVersym,    0x6fffffff, 0, 0, 0x590, 3 * 2, 3, 0, 2, 2);
    sh(9, sVerdef,    0x6ffffffd, 0, 0, 0x5A0, 28, 2);
    sh(10,sVerneed,   0x6ffffffe, 0, 0, 0x5C0, 32, 2);
    sh(11,sInitArray, 14, 0x3, 0xC0, 0x190, 16, 0, 0, 8, 8);
    sh(12,sFiniArray, 15, 0x3, 0xD0, 0x1A0, 8, 0, 0, 8, 8);
    sh(13,sShstr,     3,  0,   0,    0x600, shstr.bytes.size());
    sh(14,sRelDyn,    9,  0,   0,    0x580, 16, 3, 0, 8, 16);
    sh(15,sGot,       1,  0x3, 0xA0, 0x178, 16, 0, 0, 8, 0); // infer 8-byte slots

    // Dynamic symbols: defined foo at VA zero and undefined puts.
    auto sym = [&](size_t index, uint32_t name, uint16_t section,
                   uint64_t value, uint64_t size) {
        const size_t p = 0x500 + index * 24;
        put<uint32_t>(b, p, name); b[p + 4] = 0x12; // GLOBAL | FUNC
        put<uint16_t>(b, p + 6, section);
        put<uint64_t>(b, p + 8, value); put<uint64_t>(b, p + 16, size);
    };
    sym(1, nFoo, 1, 0, 16);
    sym(2, nPuts, 0, 0, 0);

    // One RELA PLT/GOT relocation and one REL relocation whose target is VA 0.
    put<uint64_t>(b, 0x560, 0x80);
    put<uint64_t>(b, 0x568, (uint64_t{2} << 32) | 7u);
    put<uint64_t>(b, 0x570, static_cast<uint64_t>(-4ll));
    put<uint64_t>(b, 0x580, 0);
    put<uint64_t>(b, 0x588, (uint64_t{1} << 32) | 8u);

    // DT_NEEDED, direct init/fini, and an init array already represented by SHT.
    auto dynamic = [&](size_t index, int64_t tag, uint64_t value) {
        put<uint64_t>(b, 0x300 + index * 16, static_cast<uint64_t>(tag));
        put<uint64_t>(b, 0x308 + index * 16, value);
    };
    dynamic(0, 1, nNeeded);
    dynamic(1, 12, 0);       // DT_INIT at valid VA zero
    dynamic(2, 13, 0x20);
    dynamic(3, 25, 0xC0);
    dynamic(4, 27, 16);
    dynamic(5, 0, 0);

    // Version index 2 defines foo; hidden index 3 is required by puts.
    put<uint16_t>(b, 0x590, 0);
    put<uint16_t>(b, 0x592, 2);
    put<uint16_t>(b, 0x594, 0x8003);
    put<uint16_t>(b, 0x5A0, 1); put<uint16_t>(b, 0x5A2, 0);
    put<uint16_t>(b, 0x5A4, 2); put<uint16_t>(b, 0x5A6, 1);
    put<uint32_t>(b, 0x5A8, 0x12345678); put<uint32_t>(b, 0x5AC, 20);
    put<uint32_t>(b, 0x5B0, 0); put<uint32_t>(b, 0x5B4, nDef);
    put<uint32_t>(b, 0x5B8, 0);
    put<uint16_t>(b, 0x5C0, 1); put<uint16_t>(b, 0x5C2, 1);
    put<uint32_t>(b, 0x5C4, nLibc); put<uint32_t>(b, 0x5C8, 16);
    put<uint32_t>(b, 0x5CC, 0); put<uint32_t>(b, 0x5D0, 0xCAFEBABE);
    put<uint16_t>(b, 0x5D4, 0); put<uint16_t>(b, 0x5D6, 3);
    put<uint32_t>(b, 0x5D8, nGlibc); put<uint32_t>(b, 0x5DC, 0);

    put<uint64_t>(b, 0x190, 0);     // valid zero initializer target
    put<uint64_t>(b, 0x198, 0x20);
    put<uint64_t>(b, 0x1A0, 0x30);
    b[0x100] = b[0x120] = b[0x130] = 0xC3;
    return b;
}

static constexpr size_t kElf32ShOff = 0x300;
static std::vector<uint8_t> buildElf32Rel() {
    std::vector<uint8_t> b(0x500, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 1; b[5] = 1; b[6] = 1;
    put<uint16_t>(b, 16, 1); put<uint16_t>(b, 18, 3); put<uint32_t>(b, 20, 1);
    put<uint32_t>(b, 32, static_cast<uint32_t>(kElf32ShOff));
    put<uint16_t>(b, 40, 52); put<uint16_t>(b, 46, 40);
    put<uint16_t>(b, 48, 8); put<uint16_t>(b, 50, 7);

    Strings str;
    const uint32_t nFoo = str.add("foo32");
    copyAt(b, 0x140, str.bytes);
    Strings shstr;
    const uint32_t sText = shstr.add(".text");
    const uint32_t sStr = shstr.add(".strtab");
    const uint32_t sSym = shstr.add(".symtab");
    const uint32_t sRel = shstr.add(".rel.text");
    const uint32_t sGot = shstr.add(".got");
    const uint32_t sInit = shstr.add(".init_array");
    const uint32_t sNames = shstr.add(".shstrtab");
    copyAt(b, 0x220, shstr.bytes);

    auto sh = [&](size_t index, uint32_t name, uint32_t type, uint32_t flags,
                  uint32_t offset, uint32_t size, uint32_t alignment,
                  uint32_t link = 0, uint32_t info = 0, uint32_t entrySize = 0) {
        const size_t p = kElf32ShOff + index * 40;
        put<uint32_t>(b, p, name); put<uint32_t>(b, p + 4, type);
        put<uint32_t>(b, p + 8, flags); put<uint32_t>(b, p + 12, 0);
        put<uint32_t>(b, p + 16, offset); put<uint32_t>(b, p + 20, size);
        put<uint32_t>(b, p + 24, link); put<uint32_t>(b, p + 28, info);
        put<uint32_t>(b, p + 32, alignment); put<uint32_t>(b, p + 36, entrySize);
    };
    sh(1, sText, 1, 0x6, 0x100, 0x20, 16);
    sh(2, sStr,  3, 0,   0x140, str.bytes.size(), 1);
    sh(3, sSym,  2, 0,   0x180, 2 * 16, 4, 2, 1, 16);
    sh(4, sRel,  9, 0,   0x1C0, 8, 4, 3, 1, 8);
    sh(5, sGot,  1, 0x3, 0x1D0, 4, 4);
    sh(6, sInit, 14,0x3, 0x1D4, 4, 4, 0, 0, 4);
    sh(7, sNames,3, 0,   0x220, shstr.bytes.size(), 1);

    put<uint32_t>(b, 0x190, nFoo);
    put<uint32_t>(b, 0x194, 0);
    put<uint32_t>(b, 0x198, 4);
    b[0x19C] = 0x12;
    put<uint16_t>(b, 0x19E, 1);
    put<uint32_t>(b, 0x1C0, 0);
    put<uint32_t>(b, 0x1C4, (1u << 8) | 2u);
    put<uint32_t>(b, 0x1D4, 0); // unresolved but explicit zero, not a sentinel
    b[0x100] = 0xC3;
    return b;
}

// Minimal sectionless ELF64 whose one PT_LOAD owns the complete file. Variants
// below corrupt individual extents while retaining an otherwise valid header.
static std::vector<uint8_t> buildElf64ProgramOnly() {
    std::vector<uint8_t> b(0x100, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 2; b[5] = 1; b[6] = 1;
    put<uint16_t>(b, 16, 2);       // ET_EXEC
    put<uint16_t>(b, 18, 0x3E);    // EM_X86_64
    put<uint32_t>(b, 20, 1);
    put<uint64_t>(b, 24, 0x400080);
    put<uint64_t>(b, 32, 64);      // program headers immediately after ELF header
    put<uint16_t>(b, 52, 64);
    put<uint16_t>(b, 54, 56);
    put<uint16_t>(b, 56, 1);
    put<uint32_t>(b, 64, 1);       // PT_LOAD
    put<uint32_t>(b, 68, 5);       // PF_R | PF_X
    put<uint64_t>(b, 72, 0);
    put<uint64_t>(b, 80, 0x400000);
    put<uint64_t>(b, 96, b.size());
    put<uint64_t>(b, 104, b.size());
    put<uint64_t>(b, 112, 0x1000);
    b[0x80] = 0xC3;
    return b;
}

static void putElf64Load(std::vector<uint8_t>& bytes, size_t index,
                         uint64_t fileOffset, uint64_t virtualAddress,
                         uint64_t fileSize, uint64_t memorySize,
                         uint32_t flags = 5) {
    const size_t p = 64 + index * 56;
    put<uint32_t>(bytes, p, 1);             // PT_LOAD
    put<uint32_t>(bytes, p + 4, flags);
    put<uint64_t>(bytes, p + 8, fileOffset);
    put<uint64_t>(bytes, p + 16, virtualAddress);
    put<uint64_t>(bytes, p + 24, virtualAddress);
    put<uint64_t>(bytes, p + 32, fileSize);
    put<uint64_t>(bytes, p + 40, memorySize);
    put<uint64_t>(bytes, p + 48, 0x1000);
}

static void declareElf64ProgramHeaders(std::vector<uint8_t>& bytes,
                                       uint16_t count) {
    put<uint64_t>(bytes, 32, 64);
    put<uint16_t>(bytes, 54, 56);
    put<uint16_t>(bytes, 56, count);
}

template <typename T>
static void putOrder(std::vector<uint8_t>& bytes, size_t offset, T value,
                     bool bigEndian) {
    if (!bigEndian) {
        put<T>(bytes, offset, value);
        return;
    }
    for (size_t i = 0; i < sizeof(T); ++i) {
        const size_t shift = (sizeof(T) - 1 - i) * 8;
        bytes[offset + i] = static_cast<uint8_t>(
            (static_cast<uint64_t>(value) >> shift) & 0xffu);
    }
}

// A complete, sectionless ELF32 executable. This is intentionally a genuine
// PT_LOAD mapping rather than a little-endian fixture with EI_DATA flipped.
static std::vector<uint8_t> buildElf32ProgramOnly(uint16_t machine,
                                                   uint32_t flags,
                                                   bool bigEndian) {
    std::vector<uint8_t> b(0x100, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 1; b[5] = bigEndian ? 2 : 1; b[6] = 1;
    putOrder<uint16_t>(b, 16, 2, bigEndian);       // ET_EXEC
    putOrder<uint16_t>(b, 18, machine, bigEndian);
    putOrder<uint32_t>(b, 20, 1, bigEndian);
    putOrder<uint32_t>(b, 24, 0x10080, bigEndian);
    putOrder<uint32_t>(b, 28, 52, bigEndian);      // e_phoff
    putOrder<uint32_t>(b, 36, flags, bigEndian);   // e_flags
    putOrder<uint16_t>(b, 40, 52, bigEndian);
    putOrder<uint16_t>(b, 42, 32, bigEndian);
    putOrder<uint16_t>(b, 44, 1, bigEndian);

    putOrder<uint32_t>(b, 52, 1, bigEndian);       // PT_LOAD
    putOrder<uint32_t>(b, 56, 0, bigEndian);
    putOrder<uint32_t>(b, 60, 0x10000, bigEndian);
    putOrder<uint32_t>(b, 64, 0x10000, bigEndian);
    putOrder<uint32_t>(b, 68, static_cast<uint32_t>(b.size()), bigEndian);
    putOrder<uint32_t>(b, 72, 0x120, bigEndian);   // bounded virtual padding
    putOrder<uint32_t>(b, 76, 5, bigEndian);       // PF_R | PF_X
    putOrder<uint32_t>(b, 80, 0x1000, bigEndian);
    // PPC `blr` at the declared entry; other feature fixtures only need a
    // mapped executable byte stream.
    b[0x80] = 0x4e; b[0x81] = 0x80; b[0x82] = 0x00; b[0x83] = 0x20;
    return b;
}

static bool loadBytes(BinaryFile& binary, const std::vector<uint8_t>& bytes,
                      const char* leaf) {
    const std::filesystem::path path = std::filesystem::temp_directory_path() / leaf;
    {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        stream.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }
    const bool ok = binary.load(path.string());
    std::error_code ec;
    std::filesystem::remove(path, ec);
    return ok;
}

static const BinaryFile::Export* exported(const BinaryFile& bin, const char* name) {
    const auto it = std::find_if(bin.exports().begin(), bin.exports().end(),
        [&](const auto& row) { return row.name == name; });
    return it == bin.exports().end() ? nullptr : &*it;
}
static const BinaryFile::Import* imported(const BinaryFile& bin, const char* name) {
    const auto it = std::find_if(bin.imports().begin(), bin.imports().end(),
        [&](const auto& row) { return row.name == name; });
    return it == bin.imports().end() ? nullptr : &*it;
}
static const Section* sectionNamed(const BinaryFile& bin, const char* name) {
    const auto it = std::find_if(bin.sections().begin(), bin.sections().end(),
        [&](const auto& row) { return row.name == name; });
    return it == bin.sections().end() ? nullptr : &*it;
}

int main() {
    // Big-endian ELF metadata is decoded in the image's declared order. The
    // mapping and both translation directions agree on the same PPC PT_LOAD.
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildElf32ProgramOnly(0x14, 0, true),
                        "ds_elf32_be_ppc.bin"));
        CHECK(bin.format() == BinFormat::ELF && !bin.is64Bit() &&
              bin.bigEndian() && bin.machine() == MachineArch::PPC);
        CHECK(bin.hasEntryPoint() && bin.entryPointVA() == 0x10080);
        size_t available = 0;
        const uint8_t* entry = bin.ptrFromVA(0x10080, available);
        CHECK(entry && available >= 4 && entry[0] == 0x4e && entry[3] == 0x20);
        uint64_t offset = UINT64_MAX, va = UINT64_MAX;
        CHECK(bin.vaToOffset(0x10080, offset) && offset == 0x80);
        CHECK(bin.offsetToVA(0x84, va) && va == 0x10084);
        CHECK(bin.ptrFromVA(0x10100, available) == nullptr); // virtual-only tail
    }

    // EM_ARM carries Thumb state in bit zero of e_entry. Canonical address zero
    // remains a present, executable entry rather than falling back to a sentinel.
    {
        auto bytes = buildElf32ProgramOnly(0x28, 0, false);
        put<uint32_t>(bytes, 24, 1);  // Thumb bit + canonical VA zero
        put<uint32_t>(bytes, 60, 0);  // PT_LOAD p_vaddr
        put<uint32_t>(bytes, 64, 0);  // PT_LOAD p_paddr
        BinaryFile thumb;
        CHECK(loadBytes(thumb, bytes, "ds_elf32_thumb_zero_entry.bin"));
        CHECK(thumb.format() == BinFormat::ELF &&
              thumb.machine() == MachineArch::THUMB);
        CHECK(thumb.hasEntryPoint() && thumb.entryPointVA() == 0);
        size_t available = 0;
        CHECK(thumb.ptrFromVA(0, available) != nullptr && available != 0);
    }

    // ELF e_flags, including a clear bit, are authoritative decoder metadata.
    {
        BinaryFile rvc;
        CHECK(loadBytes(rvc, buildElf32ProgramOnly(0xF3, 0x1, false),
                        "ds_elf32_rvc.bin"));
        CHECK(rvc.machine() == MachineArch::RISCV &&
              rvc.elfDecoderMetadata().present &&
              rvc.elfDecoderMetadata().flags == 0x1 &&
              rvc.elfDecoderMetadata().riscvCompressed &&
              !rvc.elfDecoderMetadata().mipsMicro);

        BinaryFile baseRv;
        CHECK(loadBytes(baseRv, buildElf32ProgramOnly(0xF3, 0, false),
                        "ds_elf32_base_rv.bin"));
        CHECK(baseRv.elfDecoderMetadata().present &&
              !baseRv.elfDecoderMetadata().riscvCompressed);

        BinaryFile microMips;
        CHECK(loadBytes(microMips,
                        buildElf32ProgramOnly(0x08, 0x02000000u, false),
                        "ds_elf32_micromips.bin"));
        CHECK(microMips.machine() == MachineArch::MIPS &&
              microMips.elfDecoderMetadata().present &&
              microMips.elfDecoderMetadata().mipsMicro &&
              !microMips.elfDecoderMetadata().riscvCompressed);
    }

    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildElf64(), "ds_elf_metadata64.bin"));
        CHECK(bin.format() == BinFormat::ELF && bin.is64Bit());
        CHECK(bin.elfRelocationTables().size() == 2 && !bin.elfRelocationsTruncated());
        const auto& rela = bin.elfRelocationTables()[0];
        CHECK(rela.valid && rela.complete && rela.hasAddends && rela.entries.size() == 1);
        CHECK(rela.entries[0].offset == 0x80 && rela.entries[0].targetValid &&
              rela.entries[0].targetMapped && rela.entries[0].symbolName == "puts" &&
              rela.entries[0].type == 7 && rela.entries[0].addend == -4 &&
              rela.entries[0].symbolValid && rela.entries[0].pltRelated &&
              rela.entries[0].gotRelated);
        const auto& rel = bin.elfRelocationTables()[1];
        CHECK(rel.valid && rel.complete && !rel.hasAddends && rel.entries.size() == 1);
        CHECK(rel.entries[0].targetValid && rel.entries[0].targetVA == 0 &&
              rel.entries[0].targetMapped && rel.entries[0].symbolDefined &&
              rel.entries[0].symbolValid && rel.entries[0].symbolValue == 0 &&
              rel.entries[0].symbolName == "foo");

        CHECK(bin.elfDynamic().present && bin.elfDynamic().valid &&
              bin.elfDynamic().terminated && !bin.elfDynamic().truncated);
        CHECK(bin.elfDynamic().dependencies.size() == 1 &&
              bin.elfDynamic().dependencies[0].stringValid &&
              bin.elfDynamic().dependencies[0].name == "libneeded.so");

        CHECK(bin.elfVersions().definitions.size() == 1 &&
              bin.elfVersions().definitions[0].valid &&
              bin.elfVersions().definitions[0].name == "VER_DEF");
        CHECK(bin.elfVersions().requirements.size() == 1 &&
              bin.elfVersions().requirements[0].valid &&
              bin.elfVersions().requirements[0].file == "libc.so.6" &&
              bin.elfVersions().requirements[0].name == "GLIBC_2.2");
        CHECK(bin.elfVersions().symbols.size() == 3);
        const auto* foo = exported(bin, "foo");
        const auto* puts = imported(bin, "puts");
        CHECK(foo && foo->va == 0 && foo->mapped && foo->elfVersionIndex == 2 &&
              foo->elfVersion == "VER_DEF" && foo->elfVersionDefined);
        CHECK(puts && puts->elfVersionIndex == 3 && puts->elfVersionHidden &&
              puts->elfVersion == "GLIBC_2.2");

        CHECK(bin.elfLinkageSections().size() == 3 && !bin.elfLinkageTruncated());
        const auto gotPlt = std::find_if(bin.elfLinkageSections().begin(),
            bin.elfLinkageSections().end(), [](const auto& row) { return row.name == ".got.plt"; });
        const auto plt = std::find_if(bin.elfLinkageSections().begin(),
            bin.elfLinkageSections().end(), [](const auto& row) { return row.name == ".plt"; });
        const auto got = std::find_if(bin.elfLinkageSections().begin(),
            bin.elfLinkageSections().end(), [](const auto& row) { return row.name == ".got"; });
        CHECK(gotPlt != bin.elfLinkageSections().end() && gotPlt->slots.size() == 3 &&
              gotPlt->slots[0].relocationValid);
        CHECK(plt != bin.elfLinkageSections().end() && plt->slots.size() == 2 &&
              plt->slots[1].relocationValid);
        CHECK(got != bin.elfLinkageSections().end() && got->entrySize == 8 &&
              got->slots.size() == 2);

        const auto& initializers = bin.elfInitializers();
        CHECK(!initializers.truncated && initializers.entries.size() == 5);
        CHECK(std::any_of(initializers.entries.begin(), initializers.entries.end(),
            [](const auto& row) { return row.kind == BinaryFile::ElfInitializerKind::Init &&
                                        row.addressValid && row.address == 0 && row.addressMapped; }));
        CHECK(std::any_of(initializers.entries.begin(), initializers.entries.end(),
            [](const auto& row) { return row.kind == BinaryFile::ElfInitializerKind::InitArray &&
                                        row.slotValid && row.slotVA == 0xC0 &&
                                        row.addressValid && row.address == 0; }));
    }

    // ELF32 ET_REL offsets resolve through the loader's synthetic section VAs;
    // raw zero values remain explicit and are marked as relocation-dependent.
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildElf32Rel(), "ds_elf_metadata32_rel.bin"));
        CHECK(bin.format() == BinFormat::ELF && !bin.is64Bit());
        const Section* text = sectionNamed(bin, ".text");
        const Section* init = sectionNamed(bin, ".init_array");
        CHECK(text && init && text->virtualAddress != init->virtualAddress);
        CHECK(bin.elfRelocationTables().size() == 1 &&
              bin.elfRelocationTables()[0].entries.size() == 1);
        const auto& relocation = bin.elfRelocationTables()[0].entries[0];
        CHECK(text && relocation.targetValid && relocation.targetVA == text->virtualAddress &&
              relocation.targetMapped && relocation.symbolValue == text->virtualAddress &&
              relocation.symbolName == "foo32" && relocation.type == 2);
        CHECK(bin.elfLinkageSections().size() == 1 &&
              bin.elfLinkageSections()[0].slots.size() == 1 &&
              bin.elfLinkageSections()[0].slots[0].addressValid);
        CHECK(bin.elfInitializers().entries.size() == 1);
        CHECK(init && bin.elfInitializers().entries[0].slotVA == init->virtualAddress &&
              bin.elfInitializers().entries[0].addressValid &&
              bin.elfInitializers().entries[0].address == 0 &&
              bin.elfInitializers().entries[0].requiresRelocation);
    }

    // Independent hostile-table failures remain visible without discarding the
    // valid ELF/section/symbol model or accepting partial records as complete.
    {
        auto bytes = buildElf64();
        put<uint64_t>(bytes, kElf64ShOff + 4 * 64 + 24, UINT64_MAX);
        put<uint64_t>(bytes, 0x300 + 5 * 16, 1); // replace DT_NULL
        put<uint64_t>(bytes, 0x308 + 5 * 16, UINT64_MAX);
        put<uint32_t>(bytes, 0x5B0, UINT32_MAX); // hostile verdef next
        put<uint64_t>(bytes, kElf64ShOff + 11 * 64 + 32, 17); // partial pointer tail
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "ds_elf_metadata_hostile.bin"));
        CHECK(bin.format() == BinFormat::ELF && exported(bin, "foo") && imported(bin, "puts"));
        CHECK(!bin.elfRelocationTables().empty() && !bin.elfRelocationTables()[0].valid &&
              bin.elfRelocationTables()[0].truncated && bin.elfRelocationsTruncated());
        CHECK(bin.elfDynamic().present && !bin.elfDynamic().terminated &&
              bin.elfDynamic().truncated);
        CHECK(bin.elfVersions().definitionsTruncated);
        CHECK(bin.elfInitializers().truncated);
    }

    // Sectionless images are accepted only from fully bounded PT_LOAD records,
    // and a declared non-zero entry must resolve to executable file backing.
    {
        BinaryFile valid;
        CHECK(loadBytes(valid, buildElf64ProgramOnly(), "ds_elf_program_only.bin"));
        CHECK(valid.format() == BinFormat::ELF && valid.sections().size() == 1);
        size_t available = 0;
        CHECK(valid.ptrFromVA(0x400080, available) != nullptr && available != 0);

        auto expectRejected = [&](std::vector<uint8_t> bytes, const char* leaf) {
            BinaryFile rejected;
            CHECK(!loadBytes(rejected, bytes, leaf));
            CHECK(!rejected.loaded() && rejected.format() == BinFormat::Unknown);
            CHECK(rejected.machine() == MachineArch::Unknown);
        };

        auto outsideFile = buildElf64ProgramOnly();
        put<uint64_t>(outsideFile, 72, 0xF0); // p_offset
        put<uint64_t>(outsideFile, 96, 0x40); // p_filesz crosses EOF
        put<uint64_t>(outsideFile, 104, 0x40);
        expectRejected(std::move(outsideFile), "ds_elf_bad_file_extent.bin");

        auto fileszLarger = buildElf64ProgramOnly();
        put<uint64_t>(fileszLarger, 96, 0x80);
        put<uint64_t>(fileszLarger, 104, 0x40); // p_filesz > p_memsz
        expectRejected(std::move(fileszLarger), "ds_elf_bad_mem_extent.bin");

        auto mixedSegments = buildElf64ProgramOnly();
        declareElf64ProgramHeaders(mixedSegments, 2);
        putElf64Load(mixedSegments, 1, 0xF0, 0x500000, 0x40, 0x40);
        expectRejected(std::move(mixedSegments), "ds_elf_mixed_bad_load.bin");

        auto emptyPlusReal = buildElf64ProgramOnly();
        declareElf64ProgramHeaders(emptyPlusReal, 2);
        putElf64Load(emptyPlusReal, 1, UINT64_MAX, UINT64_MAX, 0, 0);
        BinaryFile ignoresEmpty;
        CHECK(loadBytes(ignoresEmpty, emptyPlusReal, "ds_elf_empty_plus_real_load.bin"));
        CHECK(ignoresEmpty.sections().size() == 1 &&
              ignoresEmpty.sections()[0].name == "PT_LOAD0");

        auto emptyOnly = buildElf64ProgramOnly();
        putElf64Load(emptyOnly, 0, UINT64_MAX, UINT64_MAX, 0, 0);
        expectRejected(std::move(emptyOnly), "ds_elf_empty_load_only.bin");

        auto wrappedVirtual = buildElf64ProgramOnly();
        put<uint64_t>(wrappedVirtual, 80, UINT64_MAX - 0x10);
        put<uint64_t>(wrappedVirtual, 104, 0x100);
        expectRejected(std::move(wrappedVirtual), "ds_elf_wrapped_virtual_extent.bin");

        auto elf32OutsideAddressSpace = buildElf32ProgramOnly(0x03, 0, false);
        put<uint32_t>(elf32OutsideAddressSpace, 24, 0);          // no entry gate
        put<uint32_t>(elf32OutsideAddressSpace, 60, 0xFFFFFF00); // p_vaddr
        put<uint32_t>(elf32OutsideAddressSpace, 64, 0xFFFFFF00); // p_paddr
        put<uint32_t>(elf32OutsideAddressSpace, 72, 0x200);      // crosses 2^32
        expectRejected(std::move(elf32OutsideAddressSpace),
                       "ds_elf32_outside_address_space.bin");

        auto truncatedProgramHeaders = buildElf64ProgramOnly();
        put<uint16_t>(truncatedProgramHeaders, 54, 0xC0); // one entry fits
        put<uint16_t>(truncatedProgramHeaders, 56, 2);    // but two declared
        expectRejected(std::move(truncatedProgramHeaders),
                       "ds_elf_truncated_program_headers.bin");

        auto unmappedEntry = buildElf64ProgramOnly();
        put<uint64_t>(unmappedEntry, 24, 0x500000);
        expectRejected(std::move(unmappedEntry), "ds_elf_unmapped_entry.bin");

        auto headerOnly = buildElf64ProgramOnly();
        put<uint16_t>(headerOnly, 56, 0); // no program or section mappings
        expectRejected(std::move(headerOnly), "ds_elf_header_only.bin");
    }

    // For a process image with both tables, validated PT_LOAD records own VA
    // translation while section headers continue to supply bounded metadata.
    // A malformed second load segment cannot hide behind otherwise-valid
    // allocated sections.
    {
        auto bytes = buildElf64();
        declareElf64ProgramHeaders(bytes, 1);
        putElf64Load(bytes, 0, 0x100, 0x400000, 0x40, 0x40);
        put<uint64_t>(bytes, 24, 0x400000);

        BinaryFile authoritative;
        CHECK(loadBytes(authoritative, bytes, "ds_elf_sections_with_load.bin"));
        CHECK(authoritative.sections().size() == 1 &&
              authoritative.sections()[0].name == "PT_LOAD0");
        size_t available = 0;
        const uint8_t* entry = authoritative.ptrFromVA(0x400000, available);
        CHECK(entry && available == 0x40 && entry[0] == 0xC3);
        CHECK(authoritative.ptrFromVA(0, available) == nullptr);
        uint64_t offset = UINT64_MAX, va = UINT64_MAX;
        CHECK(authoritative.vaToOffset(0x400000, offset) && offset == 0x100);
        CHECK(authoritative.offsetToVA(0x100, va) && va == 0x400000);
        CHECK(authoritative.elfDynamic().present &&
              authoritative.elfRelocationTables().size() == 2 &&
              exported(authoritative, "foo") != nullptr);

        auto hostile = buildElf64();
        declareElf64ProgramHeaders(hostile, 2);
        putElf64Load(hostile, 0, 0x100, 0x400000, 0x40, 0x40);
        putElf64Load(hostile, 1, hostile.size() - 0x10, 0x500000, 0x40, 0x40);
        BinaryFile rejected;
        CHECK(!loadBytes(rejected, hostile, "ds_elf_sections_bad_load.bin"));
        CHECK(!rejected.loaded() && rejected.format() == BinFormat::Unknown);
    }

    if (!g_fail) std::puts("ALL ELF METADATA TESTS PASSED");
    return g_fail ? 1 : 0;
}
