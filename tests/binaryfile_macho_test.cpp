//
// binaryfile_macho_test.cpp
// Off-target regression test for the 32-bit Mach-O segment parsing in
// src/Core/BinaryFile.cpp (parseMachO).
//
// Pins the bug fixed when initprot/nsects were read from the wrong 32-bit
// segment_command offsets (lc+48/lc+52 instead of lc+44/lc+48). With the bug,
// nsects came from the segment `flags` slot (0), so NO sections were produced
// for a thin 32-bit Mach-O and VA<->offset translation broke. This builds a
// minimal, byte-accurate 32-bit Mach-O in memory, writes it to a temp file,
// loads it, and asserts the __text section is parsed and maps correctly.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\binaryfile_macho_test.cpp src\Core\BinaryFile.cpp
//   .\binaryfile_macho_test.exe
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

static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    std::memcpy(b.data() + off, &v, 4);
}
static void putstr(std::vector<uint8_t>& b, size_t off, const char* s, size_t cap) {
    std::memset(b.data() + off, 0, cap);
    std::memcpy(b.data() + off, s, std::min(std::strlen(s), cap));
}

// Construct a minimal thin 32-bit Mach-O: header + one LC_SEGMENT("__TEXT")
// carrying one section ("__text") at VA 0x1000, file offset 0x100.
static std::vector<uint8_t> buildMacho32() {
    // 0x200 bytes so the __text section's raw data (file offset 0x100..0x1FF) is
    // actually present — vaToOffset refuses offsets past EOF (it backs patching).
    std::vector<uint8_t> b(0x200, 0);
    // mach_header (32-bit, 28 bytes)
    put32(b, 0,  0xFEEDFACEu);   // magic (thin 32-bit, LE)
    put32(b, 4,  0x00000007u);   // cputype = CPU_TYPE_X86
    put32(b, 8,  3);             // cpusubtype
    put32(b, 12, 2);             // filetype = MH_EXECUTE
    put32(b, 16, 1);             // ncmds
    put32(b, 20, 56 + 68);       // sizeofcmds (segment_command + 1 section)
    put32(b, 24, 0);             // flags

    // LC_SEGMENT at offset 28 (segment_command, 56 bytes)
    const size_t lc = 28;
    put32(b, lc + 0,  0x01);             // cmd = LC_SEGMENT
    put32(b, lc + 4,  56 + 68);          // cmdsize
    putstr(b, lc + 8, "__TEXT", 16);     // segname[16]
    put32(b, lc + 24, 0x1000);           // vmaddr
    put32(b, lc + 28, 0x1000);           // vmsize
    put32(b, lc + 32, 0);                // fileoff
    put32(b, lc + 36, 0x200);            // filesize
    put32(b, lc + 40, 0x7);              // maxprot
    put32(b, lc + 44, 0x5);              // initprot (EXECUTE|READ)  <-- correct 32-bit offset
    put32(b, lc + 48, 1);                // nsects = 1               <-- correct 32-bit offset
    put32(b, lc + 52, 0);                // flags

    // section (32-bit, 68 bytes) at lc + 56 = 84
    const size_t sec = lc + 56;
    putstr(b, sec + 0,  "__text", 16);   // sectname[16]
    putstr(b, sec + 16, "__TEXT", 16);   // segname[16]
    put32(b, sec + 32, 0x1000);          // addr
    put32(b, sec + 36, 0x100);           // size
    put32(b, sec + 40, 0x100);           // offset (file)
    put32(b, sec + 44, 4);               // align
    put32(b, sec + 48, 0);               // reloff
    put32(b, sec + 52, 0);               // nreloc
    put32(b, sec + 56, 0x80000400u);     // flags: PURE_INSTRUCTIONS|SOME_INSTRUCTIONS
    return b;
}

int main() {
    auto bytes = buildMacho32();
    const std::string tmp = "macho32_test.bin";
    { std::ofstream f(tmp, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }

    BinaryFile bf;
    CHECK(bf.load(tmp));
    CHECK(bf.format() == BinFormat::MachO);
    CHECK(bf.machine() == MachineArch::X86);
    CHECK(!bf.is64Bit());

    // The crux of the fix: with the old offsets nsects==0 and this is empty.
    CHECK(bf.sections().size() == 1);
    if (bf.sections().size() == 1) {
        const Section& s = bf.sections()[0];
        CHECK(s.name == "__text");
        CHECK(s.virtualAddress == 0x1000);
        CHECK(s.rawOffset == 0x100);
        CHECK(s.executable);
    }

    // VA<->offset translation must work off the parsed section.
    uint64_t off = 0;
    CHECK(bf.vaToOffset(0x1000, off) && off == 0x100);
    CHECK(bf.vaToOffset(0x1050, off) && off == 0x150);
    uint64_t va = 0;
    CHECK(bf.offsetToVA(0x100, va) && va == 0x1000);

    std::remove(tmp.c_str());

    if (g_fail == 0) std::printf("ALL MACH-O 32-BIT PARSE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
