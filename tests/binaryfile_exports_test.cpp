// Focused tests for BinaryFile's complete PE export model: named aliases,
// ordinal-only slots, forwarders, data exports, and hostile table counts.
//
// Build (VS dev shell, from project root):
//   cl /std:c++20 /EHsc /I src tests\binaryfile_exports_test.cpp ^
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
static size_t rdataOff(uint32_t rva) { return 0x400u + (rva - 0x2000u); }

static std::vector<uint8_t> buildPE32Exports() {
    std::vector<uint8_t> b(0x800, 0);
    b[0] = 'M'; b[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    put32(b, 0x3C, pe);
    put32(b, pe, 0x00004550);                    // PE\0\0

    const size_t coff = pe + 4;
    put16(b, coff + 0, 0x014C);                  // x86
    put16(b, coff + 2, 2);                       // .text + .rdata
    put16(b, coff + 16, 0xE0);
    put16(b, coff + 18, 0x2102);                 // executable image, DLL, 32-bit

    const size_t opt = coff + 20;
    put16(b, opt + 0, 0x10B);
    put32(b, opt + 16, 0x1000);                  // entry RVA
    put32(b, opt + 28, 0x400000);                // image base
    put32(b, opt + 32, 0x1000);
    put32(b, opt + 36, 0x200);
    put32(b, opt + 56, 0x3000);
    put32(b, opt + 60, 0x200);
    put32(b, opt + 92, 16);                      // NumberOfRvaAndSizes
    put32(b, opt + 96, 0x2000);                  // export directory RVA
    put32(b, opt + 100, 0x100);                  // [0x2000,0x2100): forwarder range

    const size_t text = opt + 0xE0;
    putstr(b, text, ".text", 8);
    put32(b, text + 8, 0x200);
    put32(b, text + 12, 0x1000);
    put32(b, text + 16, 0x200);
    put32(b, text + 20, 0x200);
    put32(b, text + 36, 0x60000020u);             // CODE|EXECUTE|READ

    const size_t rdata = text + 40;
    putstr(b, rdata, ".rdata", 8);
    put32(b, rdata + 8, 0x400);
    put32(b, rdata + 12, 0x2000);
    put32(b, rdata + 16, 0x400);
    put32(b, rdata + 20, 0x400);
    put32(b, rdata + 36, 0x40000040u);            // initialized data, read

    const size_t ed = rdataOff(0x2000);
    put32(b, ed + 16, 7);                         // ordinal base
    put32(b, ed + 20, 4);                         // EAT slots
    put32(b, ed + 24, 4);                         // named rows (two aliases)
    put32(b, ed + 28, 0x2040);                    // EAT
    put32(b, ed + 32, 0x2050);                    // name pointer table
    put32(b, ed + 36, 0x2060);                    // name ordinal table

    // #7 has two aliases, #8 is ordinal-only, #9 forwards, #10 exports data.
    put32(b, rdataOff(0x2040) + 0, 0x1010);
    put32(b, rdataOff(0x2040) + 4, 0x1020);
    put32(b, rdataOff(0x2040) + 8, 0x2080);
    put32(b, rdataOff(0x2040) + 12, 0x2180);

    put32(b, rdataOff(0x2050) + 0, 0x2120);
    put32(b, rdataOff(0x2050) + 4, 0x2130);
    put32(b, rdataOff(0x2050) + 8, 0x2140);
    put32(b, rdataOff(0x2050) + 12, 0x2150);
    put16(b, rdataOff(0x2060) + 0, 0);
    put16(b, rdataOff(0x2060) + 2, 0);            // alias -> same ordinal index
    put16(b, rdataOff(0x2060) + 4, 2);
    put16(b, rdataOff(0x2060) + 6, 3);

    putstr(b, rdataOff(0x2080), "OTHER.Real", 16);
    putstr(b, rdataOff(0x2120), "AliasA", 16);
    putstr(b, rdataOff(0x2130), "AliasB", 16);
    putstr(b, rdataOff(0x2140), "Forwarded", 16);
    putstr(b, rdataOff(0x2150), "DataThing", 16);
    return b;
}

// Export metadata is allowed to live in the file-backed PE headers. This uses
// the small free span after the two section headers and before SizeOfHeaders.
static std::vector<uint8_t> buildHeaderBackedExports() {
    auto b = buildPE32Exports();
    constexpr size_t opt = 0x98;
    put32(b, opt + 96, 0x1C8);                  // export directory in headers
    put32(b, opt + 100, 0x28);

    constexpr size_t ed = 0x1C8;
    put32(b, ed + 16, 1);                       // ordinal base
    put32(b, ed + 20, 1);                       // functions
    put32(b, ed + 24, 1);                       // names
    put32(b, ed + 28, 0x1F0);                  // EAT (just outside dir range)
    put32(b, ed + 32, 0x1F4);                  // name pointer table
    put32(b, ed + 36, 0x1F8);                  // ordinal table
    put32(b, 0x1F0, 0x1010);
    put32(b, 0x1F4, 0x1FA);
    put16(b, 0x1F8, 0);
    std::memcpy(b.data() + 0x1FA, "Head", 5);  // includes terminator at 0x1FE
    return b;
}

// SizeOfOptionalHeader ends immediately before the data-directory array. The
// first eight section-name bytes deliberately resemble an export directory
// entry; they must never be read as one.
static std::vector<uint8_t> buildTruncatedOptionalHeader() {
    auto b = buildPE32Exports();
    constexpr size_t coff = 0x84;
    constexpr size_t opt = 0x98;
    put16(b, coff + 2, 1);
    put16(b, coff + 16, 0x60);
    const size_t sec = opt + 0x60;
    std::memset(b.data() + sec, 0, 40);
    put32(b, sec + 0, 0x2000);                  // fake export RVA in section name
    put32(b, sec + 4, 0x100);                   // fake export size in section name
    put32(b, sec + 8, 0x400);
    put32(b, sec + 12, 0x2000);
    put32(b, sec + 16, 0x400);
    put32(b, sec + 20, 0x400);
    put32(b, sec + 36, 0x40000040u);
    return b;
}

static std::vector<uint8_t> buildRepeatedAliasBomb() {
    constexpr uint32_t kNames = 200000;
    constexpr uint32_t namesRVA = 0x2100;
    constexpr uint32_t ordinalsRVA = 0xC6000;
    constexpr uint32_t longNameRVA = 0x128000;
    auto b = buildPE32Exports();
    b.resize(0x130000, 0);

    constexpr size_t opt = 0x98;
    const size_t rdata = opt + 0xE0 + 40;
    const uint32_t rdataSize = static_cast<uint32_t>(b.size() - 0x400);
    put32(b, opt + 56, 0x140000);
    put32(b, rdata + 8, rdataSize);
    put32(b, rdata + 16, rdataSize);

    const size_t ed = rdataOff(0x2000);
    put32(b, ed + 20, 1);
    put32(b, ed + 24, kNames);
    put32(b, ed + 28, 0x2040);
    put32(b, ed + 32, namesRVA);
    put32(b, ed + 36, ordinalsRVA);
    put32(b, rdataOff(0x2040), 0x1010);
    for (uint32_t i = 0; i < kNames; ++i) {
        put32(b, rdataOff(namesRVA) + static_cast<size_t>(i) * 4, longNameRVA);
        put16(b, rdataOff(ordinalsRVA) + static_cast<size_t>(i) * 2, 0);
    }
    const size_t nameOff = rdataOff(longNameRVA);
    std::memset(b.data() + nameOff, 'A', 4095);
    b[nameOff + 4095] = 0;
    return b;
}

static std::vector<uint8_t> buildDistinctAliasBudget() {
    constexpr uint32_t kNames = 4100;
    constexpr uint32_t kNameBytes = 2049;       // 2048 chars + NUL; 4096 fill 8 MiB exactly
    constexpr uint32_t namesRVA = 0x2100;
    constexpr uint32_t ordinalsRVA = 0x7000;
    constexpr uint32_t stringsRVA = 0xA000;
    const uint32_t rdataEndRVA = stringsRVA + kNames * kNameBytes + 0x1000;
    auto b = buildPE32Exports();
    b.resize(rdataOff(rdataEndRVA), 0);

    constexpr size_t opt = 0x98;
    const size_t rdata = opt + 0xE0 + 40;
    const uint32_t rdataSize = static_cast<uint32_t>(b.size() - 0x400);
    put32(b, opt + 56, rdataEndRVA + 0x1000);
    put32(b, rdata + 8, rdataSize);
    put32(b, rdata + 16, rdataSize);

    const size_t ed = rdataOff(0x2000);
    put32(b, ed + 20, 2);
    put32(b, ed + 24, kNames);
    put32(b, ed + 28, 0x2040);
    put32(b, ed + 32, namesRVA);
    put32(b, ed + 36, ordinalsRVA);
    put32(b, rdataOff(0x2040), 0x1010);
    put32(b, rdataOff(0x2040) + 4, 0x2080);     // forwarded ordinal after budget exhaustion
    putstr(b, rdataOff(0x2080), "OTHER.BudgetFallback", 32);
    for (uint32_t i = 0; i < kNames; ++i) {
        const uint32_t nameRVA = stringsRVA + i * kNameBytes;
        put32(b, rdataOff(namesRVA) + static_cast<size_t>(i) * 4, nameRVA);
        put16(b, rdataOff(ordinalsRVA) + static_cast<size_t>(i) * 2, 0);
        const size_t off = rdataOff(nameRVA);
        std::memset(b.data() + off, 'B', kNameBytes - 1);
        char prefix[32]{};
        const int prefixLen = std::snprintf(prefix, sizeof(prefix), "alias_%08u", i);
        if (prefixLen > 0) std::memcpy(b.data() + off, prefix, static_cast<size_t>(prefixLen));
        b[off + kNameBytes - 1] = 0;
    }
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

int main() {
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildPE32Exports(), "exports_complete.bin"));
        CHECK(bin.format() == BinFormat::PE32);
        CHECK(bin.isDll() && (bin.fileCharacteristics() & 0x2000u));
        const auto& ex = bin.exports();
        CHECK(ex.size() == 5);                     // four ordinals, one extra alias row

        CHECK(ex[0].ordinal == 7 && ex[0].name == "AliasA");
        CHECK(ex[1].ordinal == 7 && ex[1].name == "AliasB");
        CHECK(ex[0].rva == 0x1010 && ex[0].va == 0x401010 && ex[0].mapped && ex[0].isCode);
        CHECK(ex[1].isCode && !ex[1].forwarded);

        CHECK(ex[2].ordinal == 8 && ex[2].name.empty());
        CHECK(ex[2].rva == 0x1020 && ex[2].va == 0x401020 && ex[2].isCode);

        CHECK(ex[3].ordinal == 9 && ex[3].name == "Forwarded");
        CHECK(ex[3].forwarded && !ex[3].isCode && ex[3].forwarder == "OTHER.Real");

        CHECK(ex[4].ordinal == 10 && ex[4].name == "DataThing");
        CHECK(!ex[4].forwarded && ex[4].mapped && !ex[4].isCode);
        CHECK(ex[4].rva == 0x2180 && ex[4].va == 0x402180);
    }

    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildHeaderBackedExports(), "exports_headers.bin"));
        CHECK(bin.exports().size() == 1);
        if (bin.exports().size() == 1) {
            CHECK(bin.exports()[0].name == "Head");
            CHECK(bin.exports()[0].va == 0x401010);
            CHECK(bin.exports()[0].mapped && bin.exports()[0].isCode);
        }
        size_t avail = 0;
        CHECK(bin.ptrFromRVA(0x1C8, avail) != nullptr && avail == 0x38);
    }

    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildTruncatedOptionalHeader(), "exports_truncated_opt.bin"));
        CHECK(bin.format() == BinFormat::PE32);
        CHECK(bin.exportDirRVA() == 0);
        CHECK(bin.exportDirSize() == 0);
        CHECK(bin.exports().empty());
    }

    // All 200k rows repeat one 4095-byte name pointer for the same ordinal.
    // The parser should scan/cache it once and expose one unique alias row.
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildRepeatedAliasBomb(), "exports_alias_bomb.bin"));
        CHECK(bin.exports().size() == 1);
        if (bin.exports().size() == 1) CHECK(bin.exports()[0].name.size() == 4095);
    }

    // Distinct aliases cannot exceed the aggregate stored-string budget even
    // though every individual name is within the per-string limit.
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildDistinctAliasBudget(), "exports_string_budget.bin"));
        size_t storedBytes = 0;
        for (const auto& ex : bin.exports()) storedBytes += ex.name.size() + ex.forwarder.size();
        CHECK(storedBytes <= 8u * 1024u * 1024u);
        CHECK(!bin.exports().empty());
        CHECK(bin.exports().size() < 4100);
        CHECK(bin.exports().back().forwarded);
        CHECK(bin.exports().back().ordinal == 8);
        CHECK(bin.exports().back().forwarder.empty()); // bounded metadata-only fallback row
    }

    // A hostile count is clamped both by the hard cap and by EAT bytes mapped
    // from the requested RVA. Here only one uint32_t remains in the section.
    {
        auto bytes = buildPE32Exports();
        const size_t ed = rdataOff(0x2000);
        put32(bytes, ed + 20, 0xFFFFFFFFu);
        put32(bytes, ed + 24, 0xFFFFFFFFu);
        put32(bytes, ed + 28, 0x23FC);
        put32(bytes, ed + 32, 0);                  // absent name tables must not map RVA 0
        put32(bytes, ed + 36, 0);
        put32(bytes, rdataOff(0x23FC), 0x900000); // valid EAT row, target outside the image
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "exports_hostile.bin"));
        CHECK(bin.exports().size() == 1);
        CHECK(bin.exports()[0].ordinal == 7);
        CHECK(bin.exports()[0].name.empty());
        CHECK(!bin.exports()[0].mapped && !bin.exports()[0].isCode);
    }

    {
        auto bytes = buildPE32Exports();
        put32(bytes, 0x98 + 96, 0);                // no export directory
        put32(bytes, 0x98 + 100, 0);
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "exports_none.bin"));
        CHECK(bin.exports().empty());
    }

    if (!g_fail) std::printf("ALL PE EXPORT TESTS PASSED\n");
    return g_fail ? 1 : 0;
}
