// Tests for BinaryFile's PE resource-directory parser (data directory [2]):
// the three-level Type -> Name -> Language tree, string (named) type entries,
// leaf metadata (RVA/size/codepage/va/fileOffset), and hostile-input bounds.
//
// Build (VS dev shell, from project root):
//   cl /std:c++20 /EHsc /I src tests\binaryfile_resources_test.cpp ^
//      src\Core\BinaryFile.cpp src\Core\JvmClass.cpp

#include "Core/BinaryFile.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    std::memcpy(b.data() + off, &v, sizeof(v));
}
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    std::memcpy(b.data() + off, &v, sizeof(v));
}
static void putstr(std::vector<uint8_t>& b, size_t off, const char* s, size_t cap) {
    std::memset(b.data() + off, 0, cap);
    std::memcpy(b.data() + off, s, std::min(std::strlen(s), cap - 1));
}
static void pututf16(std::vector<uint8_t>& b, size_t off, const char* s) {
    for (size_t i = 0; s[i]; ++i) put16(b, off + i * 2, (uint16_t)(uint8_t)s[i]);
}

// .rsrc lives at RVA 0x2000 / file offset 0x400. A resource-relative offset `o`
// (as used inside the directory) maps to file offset 0x400 + o.
static size_t rsrc(size_t o) { return 0x400 + o; }

// A PE32 whose resource tree holds three leaves:
//   RT_MANIFEST (24) / name 1  / lang 1033 -> XML text at RVA 0x2200
//   RT_VERSION  (16) / name 1  / lang 1033 -> blob     at RVA 0x2280
//   "CUSTOM"(named)  / name 101/ lang 0    -> 8 bytes  at RVA 0x2300 (cp 1252)
static std::vector<uint8_t> buildPE32Resources() {
    std::vector<uint8_t> b(0x800, 0);
    b[0] = 'M'; b[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    put32(b, 0x3C, pe);
    put32(b, pe, 0x00004550);                    // PE\0\0

    const size_t coff = pe + 4;
    put16(b, coff + 0, 0x014C);                  // x86
    put16(b, coff + 2, 2);                       // .text + .rsrc
    put16(b, coff + 16, 0xE0);
    put16(b, coff + 18, 0x2102);                 // executable image, DLL

    const size_t opt = coff + 20;                // 0x98
    put16(b, opt + 0, 0x10B);
    put32(b, opt + 16, 0x1000);                  // entry RVA
    put32(b, opt + 28, 0x400000);                // image base
    put32(b, opt + 56, 0x3000);                  // size of image
    put32(b, opt + 60, 0x200);                   // size of headers
    put32(b, opt + 92, 16);                      // NumberOfRvaAndSizes
    put32(b, opt + 112, 0x2000);                 // data dir [2] resource RVA
    put32(b, opt + 116, 0x400);                  // resource size

    const size_t text = opt + 0xE0;              // 0x178
    putstr(b, text, ".text", 8);
    put32(b, text + 8, 0x200);
    put32(b, text + 12, 0x1000);
    put32(b, text + 16, 0x200);
    put32(b, text + 20, 0x200);
    put32(b, text + 36, 0x60000020u);            // CODE|EXECUTE|READ

    const size_t rs = text + 40;                 // 0x1A0
    putstr(b, rs, ".rsrc", 8);
    put32(b, rs + 8, 0x400);
    put32(b, rs + 12, 0x2000);
    put32(b, rs + 16, 0x400);
    put32(b, rs + 20, 0x400);
    put32(b, rs + 36, 0x40000040u);              // initialized data, read

    // Resource tree (offsets relative to rsrc base 0x2000).
    // Root: 1 named + 2 id entries.
    put16(b, rsrc(0x00) + 12, 1);                // named
    put16(b, rsrc(0x00) + 14, 2);                // id
    put32(b, rsrc(0x10) + 0, 0x80000000u | 0x100); // named type "CUSTOM" (string at 0x100)
    put32(b, rsrc(0x10) + 4, 0x80000000u | 0x060); //   -> subdir A
    put32(b, rsrc(0x18) + 0, 16);                // type RT_VERSION
    put32(b, rsrc(0x18) + 4, 0x80000000u | 0x030); //   -> subdir B
    put32(b, rsrc(0x20) + 0, 24);                // type RT_MANIFEST
    put32(b, rsrc(0x20) + 4, 0x80000000u | 0x048); //   -> subdir C

    // Subdir B (RT_VERSION) name level -> name id 1
    put16(b, rsrc(0x30) + 14, 1);
    put32(b, rsrc(0x40) + 0, 1);
    put32(b, rsrc(0x40) + 4, 0x80000000u | 0x078); // -> lang dir B2
    // Subdir C (RT_MANIFEST) name level -> name id 1
    put16(b, rsrc(0x48) + 14, 1);
    put32(b, rsrc(0x58) + 0, 1);
    put32(b, rsrc(0x58) + 4, 0x80000000u | 0x090); // -> lang dir C2
    // Subdir A (CUSTOM) name level -> name id 101
    put16(b, rsrc(0x60) + 14, 1);
    put32(b, rsrc(0x70) + 0, 101);
    put32(b, rsrc(0x70) + 4, 0x80000000u | 0x0A8); // -> lang dir A2

    // Lang dir B2 -> lang 1033 -> data entry DB
    put16(b, rsrc(0x78) + 14, 1);
    put32(b, rsrc(0x88) + 0, 1033);
    put32(b, rsrc(0x88) + 4, 0x0C0);             // leaf (high bit clear)
    // Lang dir C2 -> lang 1033 -> data entry DC
    put16(b, rsrc(0x90) + 14, 1);
    put32(b, rsrc(0xA0) + 0, 1033);
    put32(b, rsrc(0xA0) + 4, 0x0D0);
    // Lang dir A2 -> lang 0 -> data entry DA
    put16(b, rsrc(0xA8) + 14, 1);
    put32(b, rsrc(0xB8) + 0, 0);
    put32(b, rsrc(0xB8) + 4, 0x0E0);

    // Data entries (OffsetToData is an absolute RVA).
    put32(b, rsrc(0xC0) + 0, 0x2280); put32(b, rsrc(0xC0) + 4, 0x40); // DB version
    put32(b, rsrc(0xD0) + 0, 0x2200); put32(b, rsrc(0xD0) + 4, 0x1A); // DC manifest (26 bytes)
    put32(b, rsrc(0xE0) + 0, 0x2300); put32(b, rsrc(0xE0) + 4, 8);
    put32(b, rsrc(0xE0) + 8, 1252);                                    // DA custom codepage

    // Type name string "CUSTOM" (2-byte length in UTF-16 units + chars).
    put16(b, rsrc(0x100), 6);
    pututf16(b, rsrc(0x100) + 2, "CUSTOM");

    // Payloads.
    putstr(b, rsrc(0x200), "<assembly>hi</assembly>", 0x1B);           // RVA 0x2200
    put32(b, rsrc(0x280), 0xFEEF04BD);                                 // RVA 0x2280 (version-ish)
    for (int i = 0; i < 8; ++i) b[rsrc(0x300) + i] = (uint8_t)(i + 1); // RVA 0x2300
    return b;
}

static bool loadBytes(BinaryFile& bin, const std::vector<uint8_t>& bytes, const char* path) {
    {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size());
    }
    const bool ok = bin.load(path);
    std::remove(path);
    return ok;
}

static const BinaryFile::Resource* findType(const BinaryFile& bin, uint32_t typeId) {
    for (const auto& r : bin.resources())
        if (!r.typeNamed && r.typeId == typeId) return &r;
    return nullptr;
}

int main() {
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildPE32Resources(), "res_complete.bin"));
        CHECK(bin.format() == BinFormat::PE32);
        CHECK(bin.resourceDirRVA() == 0x2000);
        CHECK(bin.resourceDirSize() == 0x400);

        const auto& res = bin.resources();
        CHECK(res.size() == 3);

        const BinaryFile::Resource* man = findType(bin, 24);
        CHECK(man != nullptr);
        if (man) {
            CHECK(!man->typeNamed && man->typeId == 24);
            CHECK(!man->nameNamed && man->nameId == 1 && man->langId == 1033);
            CHECK(man->dataRVA == 0x2200 && man->dataSize == 0x1A);
            CHECK(man->va == 0x402200 && man->mapped);
            CHECK(man->fileOffset == 0x600);      // 0x400 + (0x2200 - 0x2000)
        }

        const BinaryFile::Resource* ver = findType(bin, 16);
        CHECK(ver != nullptr);
        if (ver) {
            CHECK(ver->dataRVA == 0x2280 && ver->va == 0x402280);
            CHECK(ver->nameId == 1 && ver->langId == 1033 && ver->mapped);
            CHECK(ver->fileOffset == 0x680);
        }

        // The named type.
        const BinaryFile::Resource* custom = nullptr;
        for (const auto& r : res) if (r.typeNamed) custom = &r;
        CHECK(custom != nullptr);
        if (custom) {
            CHECK(custom->typeName == "CUSTOM");
            CHECK(custom->nameId == 101 && custom->langId == 0);
            CHECK(custom->dataRVA == 0x2300 && custom->dataSize == 8);
            CHECK(custom->codePage == 1252 && custom->va == 0x402300);
        }
    }

    // No resource directory -> empty, no crash.
    {
        auto bytes = buildPE32Resources();
        put32(bytes, 0x98 + 112, 0);
        put32(bytes, 0x98 + 116, 0);
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "res_none.bin"));
        CHECK(bin.resources().empty());
        CHECK(bin.resourceDirRVA() == 0);
    }

    // A self-referential subdirectory (a level-1 entry pointing back at the root)
    // must terminate via the depth/visited caps rather than recurse forever.
    {
        auto bytes = buildPE32Resources();
        put32(bytes, rsrc(0x18) + 4, 0x80000000u | 0x000); // RT_VERSION name-dir -> root
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "res_cycle.bin"));
        CHECK(bin.resources().size() <= 100000);           // bounded, returned
    }

    // A hostile id count is clamped to the bytes actually mapped from the dir.
    {
        auto bytes = buildPE32Resources();
        put16(bytes, rsrc(0x00) + 12, 0);        // named
        put16(bytes, rsrc(0x00) + 14, 0xFFFF);   // absurd id count
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "res_hostile.bin"));
        CHECK(bin.resources().size() < 100000);  // no hang / overflow
    }

    if (!g_fail) std::printf("ALL PE RESOURCE TESTS PASSED\n");
    return g_fail ? 1 : 0;
}
