#include "Disasm/Assembler.h"
#include "Core/PatchCompiler.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace ds;
static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

static void checkEncoding(Arch arch, ByteOrder order, const char* source,
                          const std::vector<uint8_t>& expected) {
    DecoderConfig machine;
    machine.arch = arch;
    machine.byteOrder = order;
    const auto assembled = Assemble(machine, source, 0x1000);
    if (!assembled.ok) std::fprintf(stderr, "%s: %s\n", ArchName(arch), assembled.error.c_str());
    CHECK(assembled.ok && assembled.bytes == expected && assembled.count == 1);
    std::vector<uint8_t> fill;
    CHECK(ArchitectureNopFill(machine, expected.size() * 2, fill));
    std::vector<uint8_t> padded = expected;
    CHECK(PadWithArchitectureNops(machine, padded, expected.size() * 2));
    CHECK(fill == padded);
    PatchCtx context; context.machine = machine; context.siteVA = 0x1000;
    const auto compiled = CompilePatch(PatchLang::Asm, source, context);
    CHECK(compiled.ok && compiled.bytes == expected);
}

int main() {
    checkEncoding(Arch::X86, ByteOrder::Little, "nop", {0x90});
    checkEncoding(Arch::X64, ByteOrder::Little, "nop", {0x90});
    checkEncoding(Arch::ARM, ByteOrder::Little, "nop", {0x00,0xF0,0x20,0xE3});
    checkEncoding(Arch::ARM, ByteOrder::Big, "nop", {0xE3,0x20,0xF0,0x00});
    checkEncoding(Arch::THUMB, ByteOrder::Little, "nop", {0x00,0xBF});
    checkEncoding(Arch::THUMB, ByteOrder::Big, "nop", {0xBF,0x00});
    checkEncoding(Arch::ARM64, ByteOrder::Little, "nop", {0x1F,0x20,0x03,0xD5});

    DecoderConfig machine;
    machine.arch = Arch::ARM64;
    machine.byteOrder = ByteOrder::Big;
    std::vector<uint8_t> fill;
    CHECK(ArchitectureNopFill(machine, 4, fill) && fill == std::vector<uint8_t>({0xD5,0x03,0x20,0x1F}));
    const auto bigA64 = Assemble(machine, "nop", 0x1000);
    // Some pinned Keystone builds cannot create a big-endian A64 engine. They
    // must explicitly reject it, never return success with little-endian bytes.
    CHECK(bigA64.ok ? bigA64.bytes == fill : bigA64.error.find("configuration") != std::string::npos);

    machine.arch = Arch::X64;
    CHECK(!Assemble(machine, "nop", 0).ok);
    CHECK(!ArchitectureNopFill(machine, 1, fill) && fill.empty());
    machine.byteOrder = ByteOrder::Little;
    CHECK(!Assemble(machine, "", 0).ok);
    CHECK(!Assemble(machine, std::string("nop\0int3", 8), 0).ok);
    CHECK(!Assemble(machine, "nop; this_is_invalid", 0).ok);
    CHECK(!Assemble(machine, "   ", 0).ok);
    machine.arch = Arch::THUMB;
    machine.features.armMClass = true;
    CHECK(!PatchAssemblerAvailable(machine));
    CHECK(!Assemble(machine, "nop", 0).ok);
    CHECK(ArchitectureNopFill(machine, 2, fill));
    machine.arch = Arch::ARM;
    CHECK(!ArchitectureNopFill(machine, 4, fill));
    machine.features.armMClass = false;
    std::vector<uint8_t> split{0x00,0x00};
    CHECK(!PadWithArchitectureNops(machine, split, 6));
    CHECK(split == std::vector<uint8_t>({0x00,0x00}));
    machine.arch = Arch::MIPS;
    CHECK(!Assemble(machine, "nop", 0).ok);
    CHECK(!ArchitectureNopFill(machine, 4, fill));
    std::printf("assembler_encoding_test: %s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
