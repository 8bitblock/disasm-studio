//
// binaryfile_pe_va_test.cpp
// Off-target regression test for the PE VA<->file-offset mapping in
// src/Core/BinaryFile.cpp (ptrFromVA / vaToOffset / offsetToVA).
//
// Pins two correctness fixes:
//   (#2) A VA *below* imageBase_ must be "not mapped". The old code did
//        `rva = (va >= imageBase_) ? va - imageBase_ : va`, so a sub-base VA was
//        reinterpreted as an RVA and could resolve onto a real section.
//   (#3) vaToOffset's PE header-region 1:1 mapping must be bounded by the first
//        section's RAW offset (firstRaw), matching offsetToVA -- NOT by its
//        virtual address (firstVA). The gap [firstRaw, firstVA) is virtual
//        padding with no file backing; the old firstVA gate mapped it onto
//        unrelated section bytes (a patch-to-file hazard).
//
// Builds a minimal, byte-accurate PE32 in memory: imageBase 0x400000, one
// ".text" section at RVA 0x1000 / file offset 0x400, SizeOfHeaders 0x400. So
// firstRaw = 0x400, firstVA = 0x1000, and [0x400,0x1000) is the header gap.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\binaryfile_pe_va_test.cpp src\Core\BinaryFile.cpp
//   .\binaryfile_pe_va_test.exe
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

// Minimal thin PE32: DOS header -> "PE\0\0" -> COFF -> optional header (PE32) ->
// one section. File is 0x600 bytes so the section raw data [0x400,0x600) exists.
static std::vector<uint8_t> buildPE32() {
    std::vector<uint8_t> b(0x600, 0);
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
    put32(b, opt + 60, 0x400);                   // SizeOfHeaders (== firstRaw)
    put32(b, opt + 92, 16);                      // NumberOfRvaAndSizes (data dirs all zero)

    const size_t sec = opt + 0xE0;               // 0x178: section table follows the opt header
    putstr(b, sec + 0,  ".text", 8);
    put32(b, sec + 8,  0x1000);                  // VirtualSize
    put32(b, sec + 12, 0x1000);                  // VirtualAddress (firstVA)
    put32(b, sec + 16, 0x200);                   // SizeOfRawData
    put32(b, sec + 20, 0x400);                   // PointerToRawData (firstRaw)
    put32(b, sec + 36, 0x60000020u);             // Characteristics: CODE|EXECUTE|READ

    b[0x400] = 0x90;                             // sentinel at the section's first raw byte
    return b;
}

int main() {
    auto bytes = buildPE32();
    const std::string tmp = "pe32_va_test.bin";
    { std::ofstream f(tmp, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }

    BinaryFile bf;
    CHECK(bf.load(tmp));
    CHECK(bf.format() == BinFormat::PE32);
    CHECK(bf.machine() == MachineArch::X86);
    CHECK(!bf.is64Bit());
    CHECK(bf.sections().size() == 1);
    if (bf.sections().size() == 1) {
        const Section& s = bf.sections()[0];
        CHECK(s.virtualAddress == 0x1000);
        CHECK(s.rawOffset == 0x400);
        CHECK(s.executable);
    }

    const uint64_t base = 0x400000;
    uint64_t off = 0, va = 0; size_t avail = 0;

    // --- normal section VA<->offset (must be unchanged) ---
    CHECK(bf.vaToOffset(base + 0x1000, off) && off == 0x400);
    CHECK(bf.vaToOffset(base + 0x1050, off) && off == 0x450);
    CHECK(bf.offsetToVA(0x400, va) && va == base + 0x1000);          // inverse
    CHECK(bf.offsetToVA(0x450, va) && va == base + 0x1050);
    const uint8_t* p = bf.ptrFromVA(base + 0x1000, avail);
    CHECK(p != nullptr && avail >= 1 && p[0] == 0x90);              // points at section raw bytes

    // --- PE header region maps 1:1 (rva < firstRaw == 0x400) ---
    CHECK(bf.vaToOffset(base + 0x200, off) && off == 0x200);
    CHECK(bf.offsetToVA(0x200, va) && va == base + 0x200);

    // --- FIX #3: a VA in the header gap [firstRaw,firstVA) = [0x400,0x1000) has no
    //     file backing; vaToOffset must REFUSE it (old firstVA gate returned 0x500). ---
    CHECK(!bf.vaToOffset(base + 0x500, off));
    CHECK(bf.ptrFromVA(base + 0x500, avail) == nullptr);

    // --- FIX #2: a VA below the image base is not mapped; the old code reinterpreted
    //     it as an RVA and mapped 0x1000 straight onto the .text section. ---
    CHECK(!bf.vaToOffset(0x1000, off));
    CHECK(bf.ptrFromVA(0x1000, avail) == nullptr);

    std::remove(tmp.c_str());

    if (g_fail == 0) std::printf("ALL PE32 VA-MAPPING TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
