//
// instr_dataref_test.cpp
// Off-target unit test for instrDataRef() (src/Tabs/DataRef.h): the helper that
// extracts the data address an instruction references, used for inline string
// comments and xref matching. Header-only, so no .cpp deps are needed.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\instr_dataref_test.cpp
//   .\instr_dataref_test.exe
//
#include "Tabs/DataRef.h"

#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static Instruction mk(const char* mnem, const char* ops, uint64_t addr, uint32_t len,
                      bool branch = false, bool call = false) {
    Instruction in;
    in.mnemonic = mnem; in.operands = ops; in.address = addr; in.length = len;
    in.isBranch = branch; in.isCall = call;
    return in;
}

int main() {
    // Absolute direct memory operand (Zydis resolves RIP-relative to absolute):
    // the displacement inside the brackets IS the data ref.
    CHECK(instrDataRef(mk("lea", "rcx, [0x140002000]",  0x1000, 7)) == 0x140002000ull);
    CHECK(instrDataRef(mk("mov", "eax, [0x140002000]",  0x4000, 8)) == 0x140002000ull);
    CHECK(instrDataRef(mk("mov", "byte ptr [0x140002000], al", 0x4100, 8)) == 0x140002000ull);

    // Indirect call/jmp through a memory slot (IAT) IS a real data ref - the slot.
    CHECK(instrDataRef(mk("call", "qword ptr [0x140003000]", 0x6000, 6, true, true))  == 0x140003000ull);
    CHECK(instrDataRef(mk("jmp",  "qword ptr [0x140003000]", 0x6010, 6, true, false)) == 0x140003000ull);

    // Segment-prefixed absolute operand: skip the "xx:" prefix, take the address.
    CHECK(instrDataRef(mk("mov", "rax, fs:[0x140005000]", 0x6100, 9)) == 0x140005000ull);

    // RIP-relative symbolic form (Capstone): ref = next_ip + signed disp.
    CHECK(instrDataRef(mk("mov", "rax, [rip + 0x20]", 0x2000, 7)) == 0x2000 + 7 + 0x20);
    CHECK(instrDataRef(mk("lea", "rcx, [rip - 0x10]", 0x3000, 7)) == 0x3000 + 7 - 0x10);

    // Register-based memory is dynamic - NOT a static data ref. In particular a
    // stored immediate must not be mistaken for the operand address (wrong-spot bug).
    CHECK(instrDataRef(mk("mov", "dword ptr [rbp-0x4], 0x140002000", 0x8000, 7)) == 0);
    CHECK(instrDataRef(mk("mov", "[rax*8+0x140004000], rcx", 0x8010, 8)) == 0);
    CHECK(instrDataRef(mk("mov", "rax, [rsp+0x20]", 0x8020, 5)) == 0);

    // A bare immediate constant (no memory operand) is NOT a data ref.
    CHECK(instrDataRef(mk("mov", "rax, 0x140002000", 0x5000, 10)) == 0);
    CHECK(instrDataRef(mk("cmp", "eax, 0x140002000", 0x5010, 6))  == 0);

    // Relative branch/call targets have no bracket - handled via branchTarget, not here.
    CHECK(instrDataRef(mk("call", "0x140003000", 0x6200, 5, true, true)) == 0);
    CHECK(instrDataRef(mk("jmp",  "0x140003000", 0x6210, 5, true, false)) == 0);
    CHECK(instrDataRef(mk("jne",  "0x140003000", 0x6220, 6, true, false)) == 0);

    // No operands / register-only: no data ref.
    CHECK(instrDataRef(mk("ret", "", 0x9000, 1, true, false)) == 0);
    CHECK(instrDataRef(mk("xor", "eax, eax", 0x9010, 2)) == 0);

    // ---- instrImmRef(): the "mov reg, offset str" / "push offset str" idioms ----
    CHECK(instrImmRef(mk("mov",    "esi, 0x140002000", 0xA000, 5)) == 0x140002000ull);  // mov reg, imm
    CHECK(instrImmRef(mk("movabs", "rax, 0x140002000", 0xA010, 10)) == 0x140002000ull); // 64-bit absolute
    CHECK(instrImmRef(mk("push",   "0x140002000",      0xA020, 5)) == 0x140002000ull);  // push imm
    CHECK(instrImmRef(mk("mov", "dword ptr [rbp-0x4], 0x140002000", 0xA030, 7)) == 0);  // memory dst -> instrDataRef's job
    CHECK(instrImmRef(mk("lea", "rcx, [0x140002000]", 0xA040, 7)) == 0);                // has '[' -> instrDataRef's job
    CHECK(instrImmRef(mk("mov", "eax, 0x5",  0xA050, 5)) == 0);                          // small constant, not an address
    CHECK(instrImmRef(mk("cmp", "eax, 0x140002000", 0xA060, 6)) == 0);                   // cmp isn't a load/push
    CHECK(instrImmRef(mk("mov", "rax, rbx",  0xA070, 3)) == 0);                          // register source, not an imm
    CHECK(instrImmRef(mk("add", "eax, 0x140002000", 0xA080, 6)) == 0);                   // add isn't a load/push

    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("instr_dataref_test: all checks passed\n");
    return 0;
}
