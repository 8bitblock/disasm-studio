#include "Core/InstructionBytePattern.h"
#include <cstdio>

using namespace ds;
static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)

static Instruction instruction(const char* bytes, uint32_t length, uint64_t address = 0) {
    Instruction in; in.bytes = bytes; in.length = length; in.address = address; return in;
}

static void expect(const char* bytes, uint32_t length, Arch arch, const char* wanted) {
    std::string pattern, error;
    CHECK(InstructionBytePattern(instruction(bytes, length), arch, true, pattern, error));
    if (pattern != wanted) { std::printf("Expected [%s], got [%s] (%s)\n", wanted, pattern.c_str(), error.c_str()); ++failures; }
}

int main() {
    // Encoded relative spans include prefixed rel16/32, REX, short branches and loops.
    expect("E8 12 34 56 78", 5, Arch::X64, "E8 ?? ?? ?? ??");
    expect("48 E8 12 34 56 78", 6, Arch::X64, "48 E8 ?? ?? ?? ??");
    expect("66 E8 12 34 56 78", 6, Arch::X64, "66 E8 ?? ?? ?? ??");
    expect("66 E8 12 34", 4, Arch::X86, "66 E8 ?? ??");
    expect("E9 12 34", 3, Arch::X86_16, "E9 ?? ??");
    expect("66 E9 12 34 56 78", 6, Arch::X86_16, "66 E9 ?? ?? ?? ??");
    expect("0F 85 12 34 56 78", 6, Arch::X64, "0F 85 ?? ?? ?? ??");
    expect("75 FE", 2, Arch::X64, "75 ??");
    expect("67 E3 10", 3, Arch::X64, "67 E3 ??");
    expect("E2 FA", 2, Arch::X86, "E2 ??");

    // Address displacement can precede a literal value. Preserve the stored 10.
    expect("C7 05 56 34 12 00 0A 00 00 00", 10, Arch::X86, "C7 05 ?? ?? ?? ?? 0A 00 00 00");
    expect("C7 05 56 34 12 00 0A 00 00 00", 10, Arch::X64, "C7 05 ?? ?? ?? ?? 0A 00 00 00");
    expect("48 8B 05 12 34 56 78", 7, Arch::X64, "48 8B 05 ?? ?? ?? ??");
    expect("FF 15 12 34 56 78", 6, Arch::X64, "FF 15 ?? ?? ?? ??");
    expect("A1 56 34 12 00", 5, Arch::X86, "A1 ?? ?? ?? ??");
    expect("48 A1 56 34 12 00 00 00 00 00", 10, Arch::X64, "48 A1 ?? ?? ?? ?? ?? ?? ?? ??");
    expect("8B 04 25 56 34 12 00", 7, Arch::X64, "8B 04 25 ?? ?? ?? ??");

    // Register-dependent field offsets, TLS offsets, and constants are stable.
    expect("01 8C 86 7C 01 00 00", 7, Arch::X86, "01 8C 86 7C 01 00 00");
    expect("48 8B 45 F8", 4, Arch::X64, "48 8B 45 F8");
    expect("B8 0A 00 00 00", 5, Arch::X86, "B8 0A 00 00 00");
    expect("83 F8 0A", 3, Arch::X64, "83 F8 0A");
    expect("64 A1 30 00 00 00", 6, Arch::X86, "64 A1 30 00 00 00");
    expect("FF D0", 2, Arch::X64, "FF D0");

    std::string pattern, error;
    CHECK(InstructionBytePattern(instruction("ab cd\tEf\n01", 4), Arch::ARM64, false, pattern, error));
    CHECK(pattern == "AB CD EF 01");
    CHECK(!InstructionBytePattern(instruction("AB CD EF 01", 4), Arch::ARM64, true, pattern, error));
    CHECK(pattern.empty() && !error.empty());
    CHECK(!InstructionBytePattern(instruction("E8 00", 2), Arch::X64, true, pattern, error));
    CHECK(!InstructionBytePattern(instruction("90 90", 2), Arch::X64, true, pattern, error));
    CHECK(!InstructionBytePattern(instruction("90 ...", 4), Arch::X64, false, pattern, error));
    CHECK(!InstructionBytePattern(instruction("9090", 2), Arch::X64, false, pattern, error));
    CHECK(!InstructionBytePattern(instruction("90", 2), Arch::X64, false, pattern, error));
    CHECK(!InstructionBytePattern(instruction("90 90", 1), Arch::X64, false, pattern, error));
    CHECK(!InstructionBytePattern(instruction("", 0), Arch::X64, false, pattern, error));

    std::vector<Instruction> rows = {instruction("90", 1, 0), instruction("EB FE", 2, 1), instruction("C3", 1, 20)};
    CHECK(InstructionSelectionBytePattern(rows, Arch::X64, true, pattern, error));
    CHECK(pattern == "90 EB ??\nC3");
    rows[1].bytes = "?? ??";
    CHECK(!InstructionSelectionBytePattern(rows, Arch::X64, false, pattern, error) && pattern.empty());
    rows = {instruction("90", 1, 1), instruction("90", 1, 1)};
    CHECK(!InstructionSelectionBytePattern(rows, Arch::X64, false, pattern, error) && pattern.empty());
    rows = {instruction("90", 1, UINT64_MAX), instruction("90", 1, 0)};
    CHECK(!InstructionSelectionBytePattern(rows, Arch::X64, false, pattern, error) && pattern.empty());
    CHECK(!InstructionSelectionBytePattern({}, Arch::X64, false, pattern, error) && pattern.empty());
    rows = {instruction("90", 1, 0), instruction("90", static_cast<uint32_t>(kInstructionPatternByteLimit), 1)};
    CHECK(!InstructionSelectionBytePattern(rows, Arch::X64, false, pattern, error) && pattern.empty());
    std::printf("Instruction byte patterns: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
