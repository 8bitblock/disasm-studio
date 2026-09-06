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
#include <utility>
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
    CHECK(!bf.bigEndian());
    CHECK(!bf.hasEntryPoint()); // no LC_MAIN: an executable section is not a header entry

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

    // A structurally valid thin Mach-O for an unsupported CPU must not inherit
    // x86 merely because its header is 32-bit. Normal loading safely exposes it
    // as Raw so the analyst can choose an architecture explicitly.
    auto unsupportedBytes = buildMacho32();
    put32(unsupportedBytes, 4, 0x00000006u); // historical MC680x0 CPU type
    const std::string unsupportedTmp = "macho32_unsupported_cpu.bin";
    {
        std::ofstream f(unsupportedTmp, std::ios::binary);
        f.write(reinterpret_cast<const char*>(unsupportedBytes.data()),
                static_cast<std::streamsize>(unsupportedBytes.size()));
    }
    BinaryFile unsupported;
    CHECK(!unsupported.load(unsupportedTmp));
    CHECK(!unsupported.loaded());
    CHECK(unsupported.format() == BinFormat::Unknown);
    CHECK(unsupported.machine() == MachineArch::Unknown);
    std::remove(unsupportedTmp.c_str());

    // CPU_ARCH_ABI64 must agree with the thin Mach-O magic width.
    auto contradictoryBytes = buildMacho32();
    put32(contradictoryBytes, 4, 0x01000007u); // CPU_TYPE_X86_64 in MH_MAGIC
    const std::string contradictoryTmp = "macho32_contradictory_cpu_width.bin";
    {
        std::ofstream f(contradictoryTmp, std::ios::binary);
        f.write(reinterpret_cast<const char*>(contradictoryBytes.data()),
                static_cast<std::streamsize>(contradictoryBytes.size()));
    }
    BinaryFile contradictory;
    CHECK(!contradictory.load(contradictoryTmp));
    CHECK(contradictory.loadError() == BinaryLoadError::MalformedMachO);
    CHECK(!contradictory.loaded() && contradictory.machine() == MachineArch::Unknown);
    std::remove(contradictoryTmp.c_str());

    auto expectMalformedMapping = [](std::vector<uint8_t> malformed,
                                     const char* path) {
        {
            std::ofstream f(path, std::ios::binary);
            f.write(reinterpret_cast<const char*>(malformed.data()),
                    static_cast<std::streamsize>(malformed.size()));
        }
        BinaryFile image;
        CHECK(!image.load(path));
        CHECK(image.loadError() == BinaryLoadError::MalformedMachO);
        CHECK(!image.loaded());
        std::remove(path);
    };

    // Load-command and section framing is mapping authority, not optional
    // metadata: no valid prefix may survive any of these truncations.
    {
        auto malformed = buildMacho32();
        put32(malformed, 20, 0x1000); // sizeofcmds overruns the slice
        expectMalformedMapping(std::move(malformed), "macho32_sizeofcmds_overrun.bin");
    }
    {
        auto malformed = buildMacho32();
        put32(malformed, 16, 2); // declares a second command outside sizeofcmds
        expectMalformedMapping(std::move(malformed), "macho32_ncmds_mismatch.bin");
    }
    {
        auto malformed = buildMacho32();
        put32(malformed, 20, 56);      // command table ends before section row
        put32(malformed, 28 + 4, 56);  // segment cmdsize has no declared row bytes
        expectMalformedMapping(std::move(malformed), "macho32_section_row_truncated.bin");
    }
    {
        auto malformed = buildMacho32();
        constexpr size_t sec = 28 + 56;
        put32(malformed, sec + 40, 0x1F0); // only 16 file bytes remain for size 0x100
        expectMalformedMapping(std::move(malformed), "macho32_section_payload_truncated.bin");
    }

    std::remove(tmp.c_str());

    if (g_fail == 0) std::printf("ALL MACH-O 32-BIT PARSE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
