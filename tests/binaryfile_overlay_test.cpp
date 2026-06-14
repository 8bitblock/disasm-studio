//
// binaryfile_overlay_test.cpp
// Tests for PE overlay tracking in src/Core/BinaryFile.cpp (parsePE): the file
// bytes appended past the end of every section's raw data (installers, SFX
// archives, and Java launchers like launch4j/jpackage stash payloads there).
//
// Pins:
//   - A PE whose file ends exactly at the last section's raw end has NO overlay.
//   - Appended bytes are reported with the exact offset/size.
//   - A hostile rawOffset/rawSize past EOF is clamped (no wrapped math, no
//     negative-sized overlay, never an offset past EOF).
//   - A live process mapping (loadFromMemory) never reports an overlay --
//     rawOffset is repurposed as the RVA there, so end-of-raw math is nonsense.
//   - The security data directory [4] (Authenticode cert table) round-trips as
//     a FILE OFFSET + size (needed to carve a trailing cert off a payload scan).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\binaryfile_overlay_test.cpp src\Core\BinaryFile.cpp
//   .\binaryfile_overlay_test.exe
//
#include "Core/BinaryFile.h"
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

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
static void putstr(std::vector<uint8_t>& b, size_t off, const char* s, size_t cap) {
    std::memset(b.data() + off, 0, cap);
    std::memcpy(b.data() + off, s, std::min(std::strlen(s), cap));
}

// Minimal thin PE32 (same shape as binaryfile_pe_va_test): one ".text" section
// at RVA 0x1000 / file offset 0x400 / raw size 0x200, so the section raw data
// ends at 0x600. `fileSize` controls how much (if any) trails it as overlay.
// `rawSize`/`rawOff` let a test inject hostile section values.
static std::vector<uint8_t> buildPE32(size_t fileSize, uint32_t rawSize = 0x200, uint32_t rawOff = 0x400) {
    std::vector<uint8_t> b(fileSize, 0);
    b[0] = 'M'; b[1] = 'Z';
    const uint32_t e_lfanew = 0x80;
    put32(b, 0x3C, e_lfanew);
    put32(b, e_lfanew, 0x00004550);              // "PE\0\0"

    const size_t coff = e_lfanew + 4;            // 0x84
    put16(b, coff + 0,  0x014C);                 // Machine = IMAGE_FILE_MACHINE_I386
    put16(b, coff + 2,  1);                      // NumberOfSections
    put16(b, coff + 16, 0xE0);                   // SizeOfOptionalHeader (standard PE32)
    put16(b, coff + 18, 0x102);                  // Characteristics (executable, 32-bit)

    const size_t opt = coff + 20;                // 0x98
    put16(b, opt + 0,  0x10B);                   // Magic = PE32
    put32(b, opt + 16, 0x1000);                  // AddressOfEntryPoint
    put32(b, opt + 28, 0x400000);                // ImageBase (PE32 slot)
    put32(b, opt + 32, 0x1000);                  // SectionAlignment
    put32(b, opt + 36, 0x200);                   // FileAlignment
    put32(b, opt + 56, 0x2000);                  // SizeOfImage
    put32(b, opt + 60, 0x400);                   // SizeOfHeaders
    put32(b, opt + 92, 16);                      // NumberOfRvaAndSizes

    const size_t sec = opt + 0xE0;               // 0x178: section table follows the opt header
    putstr(b, sec + 0,  ".text", 8);
    put32(b, sec + 8,  0x1000);                  // VirtualSize
    put32(b, sec + 12, 0x1000);                  // VirtualAddress
    put32(b, sec + 16, rawSize);                 // SizeOfRawData
    put32(b, sec + 20, rawOff);                  // PointerToRawData
    put32(b, sec + 36, 0x60000020u);             // Characteristics: CODE|EXECUTE|READ
    return b;
}

static bool loadBytes(BinaryFile& bf, const std::vector<uint8_t>& bytes, const char* tmp) {
    { std::ofstream f(tmp, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
    bool ok = bf.load(tmp);
    std::remove(tmp);
    return ok;
}

int main() {
    // --- 1. exact-size PE: file ends at the section raw end -> no overlay ---
    {
        BinaryFile bf;
        CHECK(loadBytes(bf, buildPE32(0x600), "ovl_exact.bin"));
        CHECK(bf.format() == BinFormat::PE32);
        CHECK(!bf.hasOverlay());
        CHECK(bf.overlayOffset() == 0);
        CHECK(bf.overlaySize() == 0);
        CHECK(bf.securityDirOffset() == 0 && bf.securityDirSize() == 0);
    }

    // --- 2. appended bytes -> overlay with exact offset/size ---
    {
        auto bytes = buildPE32(0x600 + 0x123);
        for (size_t i = 0; i < 0x123; ++i) bytes[0x600 + i] = (uint8_t)i;   // payload
        BinaryFile bf;
        CHECK(loadBytes(bf, bytes, "ovl_appended.bin"));
        CHECK(bf.hasOverlay());
        CHECK(bf.overlayOffset() == 0x600);
        CHECK(bf.overlaySize()   == 0x123);
        // Overlay bytes are reachable through bytes() but have no VA.
        uint64_t va = 0;
        CHECK(!bf.offsetToVA(0x600, va));
    }

    // --- 3a. hostile rawSize past EOF: clamped to file size -> no overlay ---
    {
        BinaryFile bf;
        CHECK(loadBytes(bf, buildPE32(0x700, /*rawSize=*/0xFFFFFFF0u), "ovl_hostile_size.bin"));
        CHECK(!bf.hasOverlay());           // clamp -> end == fileSize, nothing past it
        CHECK(bf.overlaySize() == 0);
    }

    // --- 3b. hostile rawOffset near UINT32_MAX: 64-bit clamp, no wrap ---
    {
        BinaryFile bf;
        CHECK(loadBytes(bf, buildPE32(0x700, /*rawSize=*/0x200, /*rawOff=*/0xFFFFFFF0u), "ovl_hostile_off.bin"));
        CHECK(!bf.hasOverlay());
        CHECK(bf.overlayOffset() == 0);
    }

    // --- 3c. hostile section, file still has trailing data past the headers:
    //         the bogus section clamps to EOF, so no overlay is invented ---
    {
        auto bytes = buildPE32(0x900, /*rawSize=*/0xFFFFFFF0u);
        BinaryFile bf;
        CHECK(loadBytes(bf, bytes, "ovl_hostile_trail.bin"));
        CHECK(!bf.hasOverlay());
    }

    // --- 4. mapped image (loadFromMemory): never an overlay ---
    {
        auto bytes = buildPE32(0x600 + 0x80);            // would be an overlay on disk
        BinaryFile bf;
        CHECK(bf.loadFromMemory(bytes, 0x7FF600000000ull, "live.dll"));
        CHECK(bf.isMappedImage());
        CHECK(!bf.hasOverlay());
        CHECK(bf.overlayOffset() == 0 && bf.overlaySize() == 0);
    }

    // --- 5. security directory [4] round-trips as file offset + size ---
    {
        auto bytes = buildPE32(0x600 + 0x100);
        const size_t opt = 0x84 + 20;
        const size_t dataDir = opt + 96;                 // PE32 data-directory array
        put32(bytes, dataDir + 4 * 8,     0x650);        // [4].VirtualAddress = FILE OFFSET
        put32(bytes, dataDir + 4 * 8 + 4, 0xB0);         // [4].Size
        BinaryFile bf;
        CHECK(loadBytes(bf, bytes, "ovl_secdir.bin"));
        CHECK(bf.securityDirOffset() == 0x650);
        CHECK(bf.securityDirSize()   == 0xB0);
        CHECK(bf.hasOverlay());                          // cert region still counts as file overlay
        CHECK(bf.overlayOffset() == 0x600);
    }

    // --- 6. raw load: overlay stays zero ---
    {
        std::vector<uint8_t> blob(0x100, 0xCC);
        const char* tmp = "ovl_raw.bin";
        { std::ofstream f(tmp, std::ios::binary); f.write((const char*)blob.data(), (std::streamsize)blob.size()); }
        BinaryFile bf;
        CHECK(bf.loadRaw(tmp, 0x10000));
        std::remove(tmp);
        CHECK(!bf.hasOverlay());
    }

    if (g_fail == 0) std::printf("ALL OVERLAY TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
