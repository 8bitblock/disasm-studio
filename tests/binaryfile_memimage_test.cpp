//
// binaryfile_memimage_test.cpp
// Unit-tests BinaryFile::loadFromMemory — parsing a PE image as it appears already
// MAPPED in a live process (section data at its RVA, runtime base overriding the
// header's preferred ImageBase). No Windows/ImGui/Zydis needed.
//
// Compile + run (MSVC dev shell), from the repo root:
//   cl /nologo /std:c++20 /EHsc /D_CRT_SECURE_NO_WARNINGS /I src ^
//      tests\binaryfile_memimage_test.cpp src\Core\BinaryFile.cpp
//
#include "Core/BinaryFile.h"

#include <cstdint>
#include <cstdio>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { b[off] = (uint8_t)v; b[off+1] = (uint8_t)(v>>8); }
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { for (int i=0;i<4;++i) b[off+i]=(uint8_t)(v>>(8*i)); }
static void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) { for (int i=0;i<8;++i) b[off+i]=(uint8_t)(v>>(8*i)); }

int main() {
    const uint64_t runtimeBase   = 0x7FF000000000ull;  // where the module is mapped now
    const uint64_t preferredBase = 0x140000000ull;     // header's preferred base (ASLR moved it)
    const uint32_t textRVA  = 0x1000;
    const uint32_t textVSize = 0x100;
    const uint32_t entryRVA = 0x1000;

    // Build a minimal PE32+ image laid out the way the loader maps it (raw == RVA).
    std::vector<uint8_t> img(0x1100, 0);
    img[0] = 'M'; img[1] = 'Z';
    const uint32_t e_lfanew = 0x80;
    put32(img, 0x3C, e_lfanew);
    img[e_lfanew+0]='P'; img[e_lfanew+1]='E'; img[e_lfanew+2]=0; img[e_lfanew+3]=0;

    const size_t coff = e_lfanew + 4;
    put16(img, coff + 0, 0x8664);   // Machine = AMD64
    put16(img, coff + 2, 1);        // NumberOfSections
    put16(img, coff + 16, 240);     // SizeOfOptionalHeader (PE32+ with 16 data dirs)

    const size_t opt = coff + 20;
    put16(img, opt + 0, 0x020B);        // Magic = PE32+
    put32(img, opt + 16, entryRVA);     // AddressOfEntryPoint
    put64(img, opt + 24, preferredBase);// ImageBase (preferred — must be overridden)
    put32(img, opt + 108, 16);          // NumberOfRvaAndSizes
    // data directories (opt+112 .. +112+128) left zero -> no imports/exports/relocs

    const size_t sec = opt + 240;       // section table
    const char* nm = ".text";
    for (int i = 0; i < 5; ++i) img[sec + i] = (uint8_t)nm[i];
    put32(img, sec + 8,  textVSize);    // VirtualSize
    put32(img, sec + 12, textRVA);      // VirtualAddress
    put32(img, sec + 16, 0x200);        // SizeOfRawData (file) — irrelevant for a mapping
    put32(img, sec + 20, 0x400);        // PointerToRawData (file) — irrelevant for a mapping
    put32(img, sec + 36, 0x60000020);   // CODE | EXECUTE | READ

    // Recognizable mapped section bytes at the section's RVA (== buffer offset).
    img[textRVA + 0] = 0xAA; img[textRVA + 1] = 0xBB; img[textRVA + 2] = 0xCC;

    BinaryFile bf;
    CHECK(bf.loadFromMemory(img, runtimeBase, "test.dll"), "loadFromMemory returns true");
    CHECK(bf.isMappedImage(), "isMappedImage() true");
    CHECK(bf.format() == BinFormat::PE32Plus, "format is PE32+");
    CHECK(bf.machine() == MachineArch::X64, "machine is X64");
    CHECK(bf.is64Bit(), "is64Bit true");
    CHECK(bf.imageBase() == runtimeBase, "imageBase() == runtime base (not the preferred base)");
    CHECK(bf.entryPoint() == entryRVA, "entryPoint() == AddressOfEntryPoint RVA");
    CHECK(bf.sections().size() == 1, "one section parsed");
    if (!bf.sections().empty()) {
        const Section& s = bf.sections()[0];
        CHECK(s.executable, "section is executable");
        CHECK(s.virtualAddress == textRVA, "section RVA");
        CHECK(s.rawOffset == textRVA, "mapped section rawOffset == RVA");
    }

    // ptrFromVA at the runtime VA returns the mapped section bytes.
    size_t avail = 0;
    const uint8_t* p = bf.ptrFromVA(runtimeBase + textRVA, avail);
    CHECK(p != nullptr, "ptrFromVA resolves the section VA");
    if (p) {
        CHECK(avail >= 3, "available span covers the section");
        CHECK(p[0] == 0xAA && p[1] == 0xBB && p[2] == 0xCC, "mapped bytes read back at the RVA");
    }

    // VA<->offset round-trips (offset == RVA for a mapping).
    uint64_t off = 0, va = 0;
    CHECK(bf.vaToOffset(runtimeBase + textRVA, off) && off == textRVA, "vaToOffset -> RVA offset");
    CHECK(bf.offsetToVA(textRVA, va) && va == runtimeBase + textRVA, "offsetToVA -> runtime VA");

    // A non-PE buffer falls back to a flat blob mapped at base.
    {
        std::vector<uint8_t> blob(0x80, 0x90);
        BinaryFile raw;
        CHECK(raw.loadFromMemory(blob, runtimeBase, "blob"), "loadFromMemory(non-PE) true");
        CHECK(raw.format() == BinFormat::Raw, "non-PE -> Raw");
        CHECK(raw.isMappedImage(), "non-PE memory image retains live-mapping provenance");
        CHECK(raw.imageBase() == runtimeBase, "raw imageBase == base");
        CHECK(raw.sections().size() == 1 && raw.sections()[0].executable &&
              raw.sections()[0].rawSize == blob.size(),
              "non-PE memory image exposes one complete executable raw section");
        size_t av2 = 0;
        const uint8_t* rp = raw.ptrFromVA(runtimeBase, av2);
        CHECK(rp && rp[0] == 0x90, "raw ptrFromVA reads the blob");
    }

    if (g_fail == 0) std::printf("binaryfile_memimage_test: all checks passed\n");
    else             std::printf("binaryfile_memimage_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
