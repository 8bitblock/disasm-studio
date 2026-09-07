//
// dataflow_decomp_test.cpp
// Off-target unit test for the data-flow decompiler pre-pass (src/Core/DataFlow.cpp)
// wired into src/Core/Decompiler.cpp. A MockDisassembler replays canned x86-64
// instruction streams (the real engines can't run here); we BuildCFG + Decompile
// and assert the named/propagated/dead-code-eliminated output.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\dataflow_decomp_test.cpp ^
//      src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
//   .\dataflow_decomp_test.exe
//
#include "Core/CFG.h"
#include "Core/Decompiler.h"
#include "Core/DataFlow.h"
#include "Disasm/IDisassembler.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

struct MockDisassembler : IDisassembler {
    std::unordered_map<uint64_t, Instruction> at;
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "mock"; }
    bool decodeOne(const uint8_t*, size_t, uint64_t va, Instruction& out) override {
        auto it = at.find(va); if (it == at.end()) return false; out = it->second; return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* d, size_t n, uint64_t va, size_t maxI) override {
        std::vector<Instruction> v; uint64_t a = va;
        while (!maxI || v.size() < maxI) { Instruction in; if (!decodeOne(d, n, a, in) || !in.length) break; v.push_back(in); a += in.length; }
        return v;
    }
};

static Instruction mk(uint64_t addr, uint32_t len, const char* mnem, const char* ops,
                      bool branch = false, bool ret = false, uint64_t target = 0) {
    Instruction in;
    in.address = addr; in.length = len; in.mnemonic = mnem; in.operands = ops;
    in.isCall = (std::string(mnem) == "call");
    in.isBranch = branch || in.isCall; in.isRet = ret; in.branchTarget = target;
    return in;
}

static TypedOperand regOp(const char* name, uint16_t width, OperandAccess access) {
    TypedOperand operand;
    operand.kind = OperandKind::Register;
    operand.registerName = name;
    operand.widthBits = width;
    operand.access = access;
    return operand;
}

static TypedOperand immOp(uint64_t bits, uint16_t width, bool isSigned = false) {
    TypedOperand operand;
    operand.kind = OperandKind::Immediate;
    operand.immediate = bits;
    operand.widthBits = width;
    operand.immediateSigned = isSigned;
    operand.access = OperandAccess::Read;
    return operand;
}

static std::string decompile(const std::vector<Instruction>& ins, const DecompileOptions& opt = {}) {
    MockDisassembler dis;
    uint64_t base = ins.front().address;
    uint64_t end  = ins.back().address + ins.back().length;
    for (auto& in : ins) dis.at[in.address] = in;
    std::vector<uint8_t> buf((size_t)(end - base) + 16, 0);
    ControlFlowGraph g = BuildCFG(buf.data(), buf.size(), base, dis, 2000);
    return Decompile(g, opt);
}
static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

int main() {
    // 1) Copy/constant propagation + naming + dead-assignment elimination.
    //    mov rax, rcx ; mov rbx, [rax+8] ; mov rax, rbx ; ret
    //    rcx is argument a1; rax/rbx temporaries are propagated/eliminated.
    {
        std::string out = decompile({
            mk(0x1000, 3, "mov", "rax, rcx"),
            mk(0x1003, 4, "mov", "rbx, qword ptr [rax + 8]"),
            mk(0x1007, 3, "mov", "rax, rbx"),
            mk(0x100A, 1, "ret", "", true, true),
        });
        CHECK(has(out, "*(a1 + 8)"));   // rcx named a1, rax copy propagated into the load
        CHECK(!has(out, "rax"));        // raw register names gone
        CHECK(!has(out, "rbx"));
        CHECK(!has(out, "rcx"));
        if (g_fail) std::printf("--- test1 ---\n%s\n", out.c_str());
    }

    // 2) Constant from xor, recovered as the return value.
    //    xor eax, eax ; ret  ->  return 0;
    {
        std::string out = decompile({
            mk(0x1000, 2, "xor", "eax, eax"),
            mk(0x1002, 1, "ret", "", true, true),
        });
        CHECK(has(out, "return 0;"));
        if (g_fail) std::printf("--- test2 ---\n%s\n", out.c_str());
    }

    // 3) Named operands in a recovered condition.
    //    cmp rcx, rdx ; jne else ; (then) mov rax,1 ; (else) mov rax,2 ; ret
    {
        std::string out = decompile({
            mk(0x1000, 3, "cmp", "rcx, rdx"),
            mk(0x1003, 2, "jne", "0x100A", true, false, 0x100A),
            mk(0x1005, 5, "mov", "rax, 1"),
            mk(0x100A, 5, "mov", "rax, 2"),
            mk(0x100F, 1, "ret", "", true, true),
        });
        CHECK(has(out, "a1"));          // rcx -> a1
        CHECK(has(out, "a2"));          // rdx -> a2
        CHECK(has(out, "if ("));        // a real if was structured
        CHECK(!has(out, "rcx") && !has(out, "rdx"));
        if (g_fail) std::printf("--- test3 ---\n%s\n", out.c_str());
    }

    // 4) Pointer-typed local declaration (used as a memory base) + store.
    //    mov rax, rcx ; mov qword ptr [rax], rdx ; ret   (rcx=a1 ptr, rdx=a2)
    {
        std::string out = decompile({
            mk(0x1000, 3, "mov", "rax, rcx"),
            mk(0x1003, 3, "mov", "qword ptr [rax], rdx"),
            mk(0x1006, 1, "ret", "", true, true),
        });
        CHECK(has(out, "*(a1) = a2;"));  // store through the propagated pointer
        if (g_fail) std::printf("--- test4 ---\n%s\n", out.c_str());
    }

    // 6) for-loop reconstruction from a counting loop.
    //    mov ecx,0 ; (header) cmp ecx,edx ; jge end ; add eax,ecx ; inc ecx ; jmp header ; end: ret
    {
        std::string out = decompile({
            mk(0x1000, 5, "mov", "ecx, 0"),
            mk(0x1005, 2, "cmp", "ecx, edx"),
            mk(0x1007, 2, "jge", "0x100F", true, false, 0x100F),
            mk(0x1009, 2, "add", "eax, ecx"),
            mk(0x100B, 2, "inc", "ecx"),
            mk(0x100D, 2, "jmp", "0x1005", true, false, 0x1005),
            mk(0x100F, 1, "ret", "", true, true),
        });
        CHECK(has(out, "for (; "));     // while+increment folded into a for
        CHECK(has(out, "++) {"));
        CHECK(!has(out, "while ("));
        if (g_fail) std::printf("--- test6 ---\n%s\n", out.c_str());
    }

    // 7) Return-value recovery: mov eax, 7 ; ret  ->  return 7;
    {
        std::string out = decompile({
            mk(0x1000, 5, "mov", "eax, 7"),
            mk(0x1005, 1, "ret", "", true, true),
        });
        CHECK(has(out, "return 7;"));
        if (g_fail) std::printf("--- test7 ---\n%s\n", out.c_str());
    }

    // 8) One-operand multiply is modeled (not dropped to __asm).
    //    mov eax, 3 ; mul ecx ; ret  ->  return 3 * <ecx>;
    {
        std::string out = decompile({
            mk(0x1000, 5, "mov", "eax, 3"),
            mk(0x1005, 2, "mul", "ecx"),
            mk(0x1007, 1, "ret", "", true, true),
        });
        CHECK(has(out, "3 * "));
        CHECK(!has(out, "__asm"));
        if (g_fail) std::printf("--- test8 ---\n%s\n", out.c_str());
    }

    // 9) One-operand divide keeps native unsigned width and the high:low
    //    dividend explicit (Python `/` and `//` have different semantics).
    //    Quotient only: xor edx,edx ; div ecx ; ret -> udiv32(...).
    {
        std::string out = decompile({
            mk(0x1000, 2, "xor", "edx, edx"),
            mk(0x1002, 2, "div", "ecx"),
            mk(0x1004, 1, "ret", "", true, true),
        });
        CHECK(has(out, "udiv32("));
        CHECK(!has(out, " / "));
        CHECK(!has(out, "__asm"));
        if (g_fail) std::printf("--- test9 ---\n%s\n", out.c_str());
    }
    //    Remainder used: xor edx,edx ; div ecx ; mov eax,edx ; ret -> urem32(...).
    {
        std::string out = decompile({
            mk(0x1000, 2, "xor", "edx, edx"),
            mk(0x1002, 2, "div", "ecx"),
            mk(0x1004, 2, "mov", "eax, edx"),
            mk(0x1006, 1, "ret", "", true, true),
        });
        CHECK(has(out, "urem32("));
        CHECK(!has(out, " % "));
        CHECK(!has(out, "__asm"));
        if (g_fail) std::printf("--- test9b ---\n%s\n", out.c_str());
    }

    // 10) String/data-ref resolution: lea of a string constant.
    //     lea rax, [0x140005000] ; ret  ->  return "hello";
    {
        DecompileOptions opt;
        opt.dataRefFor = [](uint64_t a) -> std::string { return a == 0x140005000ull ? "\"hello\"" : std::string(); };
        std::string out = decompile({
            mk(0x1000, 7, "lea", "rax, [0x140005000]"),
            mk(0x1007, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "return \"hello\";"));
        if (g_fail) std::printf("--- test10 ---\n%s\n", out.c_str());
    }

    // 11) Indirect call through a resolved IAT slot.
    //     call qword ptr [0x140008000] ; ret  ->  kernel32.Foo();
    {
        DecompileOptions opt;
        opt.dataRefFor = [](uint64_t a) -> std::string { return a == 0x140008000ull ? "kernel32.Foo" : std::string(); };
        std::string out = decompile({
            mk(0x1000, 6, "call", "qword ptr [0x140008000]", true, false, 0),
            mk(0x1006, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "kernel32.Foo()"));
        CHECK(!has(out, "(*"));    // not rendered as a raw indirect call
        if (g_fail) std::printf("--- test11 ---\n%s\n", out.c_str());
    }

    // 12) Partial-register write is sound: clearing al must not zero all of rax.
    //     mov rax, rcx ; mov al, 0 ; ret   ->  return must be rax (a1 w/ low byte), not 0.
    {
        std::string out = decompile({
            mk(0x1000, 3, "mov", "rax, rcx"),
            mk(0x1003, 2, "mov", "al, 0"),
            mk(0x1005, 1, "ret", "", true, true),
        });
        CHECK(has(out, "LOBYTE("));     // partial write rendered as a low-byte assignment
        CHECK(!has(out, "return 0;"));  // NOT collapsed to a full-register zero
        if (g_fail) std::printf("--- test12 ---\n%s\n", out.c_str());
    }

    // 13) movzx makes the source width explicit (so a later wide read isn't wrong).
    {
        std::string out = decompile({
            mk(0x1000, 3, "movzx", "eax, byte ptr [rcx]"),
            mk(0x1003, 1, "ret", "", true, true),
        });
        CHECK(has(out, "(unsigned __int8)"));
        if (g_fail) std::printf("--- test13 ---\n%s\n", out.c_str());
    }

    // 14) A store through an aliasing pointer invalidates a tracked stack slot.
    //     [rbp-8]=1 ; rcx=&[rbp-8] ; *rcx=2 ; rax=[rbp-8] ; ret  -> return the slot, not the stale 1.
    {
        std::string out = decompile({
            mk(0x1000, 8, "mov", "qword ptr [rbp - 8], 1"),
            mk(0x1008, 4, "lea", "rcx, [rbp - 8]"),
            mk(0x100C, 3, "mov", "qword ptr [rcx], 2"),
            mk(0x100F, 4, "mov", "rax, qword ptr [rbp - 8]"),
            mk(0x1013, 1, "ret", "", true, true),
        });
        CHECK(!has(out, "return 1;"));      // must NOT inline the pre-store constant
        CHECK(has(out, "local_"));          // reads the (invalidated) stack-slot variable
        if (g_fail) std::printf("--- test14 ---\n%s\n", out.c_str());
    }

    // 5) Legacy fallback: deepDataFlow off keeps the raw register lift.
    {
        DecompileOptions opt; opt.deepDataFlow = false;
        std::string out = decompile({
            mk(0x1000, 3, "mov", "rax, rcx"),
            mk(0x1003, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "rax = rcx;"));   // unchanged legacy behavior
        if (g_fail) std::printf("--- test5 ---\n%s\n", out.c_str());
    }

    // 15) Folded-constant comment: const-prop reduces the return expression to
    //     pure arithmetic on constants -> the value is spelled out as a comment.
    //     mov ecx, 0x1000 ; lea eax, [ecx + 0x234] ; ret
    {
        std::string out = decompile({
            mk(0x1000, 5, "mov", "ecx, 0x1000"),
            mk(0x1005, 4, "lea", "eax, [ecx + 0x234]"),
            mk(0x1009, 1, "ret", "", true, true),
        });
        CHECK(has(out, "0x1000 + 0x234"));      // the folded expression is shown
        CHECK(has(out, "/* = 0x1234 */"));      // ...with its computed value
        if (g_fail) std::printf("--- test15 ---\n%s\n", out.c_str());
    }
    //     A bare constant gets no redundant "/* = */" comment.
    {
        std::string out = decompile({
            mk(0x1000, 5, "mov", "eax, 7"),
            mk(0x1005, 1, "ret", "", true, true),
        });
        CHECK(has(out, "return 7;"));
        CHECK(!has(out, "/* ="));
        if (g_fail) std::printf("--- test15b ---\n%s\n", out.c_str());
    }

    // 16) Win64 call-argument recovery: a string marshalled into rcx must appear
    //     AT the call site (and not be dead-code-eliminated).
    //     lea rcx, [str] ; call printf   ->   printf("hello")
    {
        DecompileOptions opt;
        opt.nameFor    = [](uint64_t a) -> std::string { return a == 0x2000ull ? "printf" : std::string(); };
        opt.dataRefFor = [](uint64_t a) -> std::string { return a == 0x140005000ull ? "\"hello\"" : std::string(); };
        std::string out = decompile({
            mk(0x1000, 7, "lea",  "rcx, [0x140005000]"),
            mk(0x1007, 5, "call", "", true, false, 0x2000),
            mk(0x100C, 1, "ret",  "", true, true),
        }, opt);
        CHECK(has(out, "printf(\"hello\")"));   // the string is shown where it is passed
        if (g_fail) std::printf("--- test16 ---\n%s\n", out.c_str());
    }

    // 17) Win64 multiple contiguous args (rcx, rdx), one an immediate, one a string.
    //     mov rcx, 1 ; lea rdx, [str] ; call foo   ->   foo(1, "hi")
    {
        DecompileOptions opt;
        opt.target = { Arch::X64, DecompileABI::Win64 };
        opt.nameFor    = [](uint64_t a) -> std::string { return a == 0x2000ull ? "foo" : std::string(); };
        opt.dataRefFor = [](uint64_t a) -> std::string { return a == 0x140005000ull ? "\"hi\"" : std::string(); };
        std::string out = decompile({
            mk(0x1000, 7, "mov",  "rcx, 1"),
            mk(0x1007, 7, "lea",  "rdx, [0x140005000]"),
            mk(0x100E, 5, "call", "", true, false, 0x2000),
            mk(0x1013, 1, "ret",  "", true, true),
        }, opt);
        CHECK(has(out, "foo(1, \"hi\")"));
        if (g_fail) std::printf("--- test17 ---\n%s\n", out.c_str());
    }

    // 18) Contiguity guard: a value in r8 with NO value in rcx/rdx must NOT
    //     fabricate a gap argument — the call stays nullary.
    //     mov r8, 5 ; call foo   ->   foo()
    {
        DecompileOptions opt;
        opt.nameFor = [](uint64_t a) -> std::string { return a == 0x2000ull ? "foo" : std::string(); };
        std::string out = decompile({
            mk(0x1000, 7, "mov",  "r8, 5"),
            mk(0x1007, 5, "call", "", true, false, 0x2000),
            mk(0x100C, 1, "ret",  "", true, true),
        }, opt);
        CHECK(has(out, "foo()"));
        CHECK(!has(out, "foo(5"));   // r8 alone is not arg1
        if (g_fail) std::printf("--- test18 ---\n%s\n", out.c_str());
    }

    // 19) x86 cdecl push-chain recovery: args are the pushes since frame setup,
    //     in call order (cdecl pushes right-to-left, so the LAST push is arg1).
    //     push ebp ; mov ebp,esp ; push "world" ; push "hello" ; call foo
    //       ->  foo("hello", "world")
    {
        DecompileOptions opt;
        opt.target = { Arch::X86, DecompileABI::X86Cdecl };
        opt.nameFor    = [](uint64_t a) -> std::string { return a == 0x2000ull ? "foo" : std::string(); };
        opt.dataRefFor = [](uint64_t a) -> std::string {
            if (a == 0x404000ull) return "\"world\"";
            if (a == 0x404010ull) return "\"hello\"";
            return std::string();
        };
        std::string out = decompile({
            mk(0x1000, 1, "push", "ebp"),
            mk(0x1001, 2, "mov",  "ebp, esp"),         // frame setup -> clears the saved-ebp push
            mk(0x1003, 5, "push", "0x404000"),         // "world" (pushed first)
            mk(0x1008, 5, "push", "0x404010"),         // "hello" (pushed last -> first arg)
            mk(0x100D, 5, "call", "", true, false, 0x2000),
            mk(0x1012, 1, "ret",  "", true, true),
        }, opt);
        CHECK(has(out, "foo(\"hello\", \"world\")"));
        if (g_fail) std::printf("--- test19 ---\n%s\n", out.c_str());
    }

    // 20) Kill switch: callArgs=false restores the bare `callee()` form (and the
    //     unread marshalling def is then dead — string disappears, legacy behavior).
    {
        DecompileOptions opt; opt.callArgs = false;
        opt.nameFor    = [](uint64_t a) -> std::string { return a == 0x2000ull ? "printf" : std::string(); };
        opt.dataRefFor = [](uint64_t a) -> std::string { return a == 0x140005000ull ? "\"hello\"" : std::string(); };
        std::string out = decompile({
            mk(0x1000, 7, "lea",  "rcx, [0x140005000]"),
            mk(0x1007, 5, "call", "", true, false, 0x2000),
            mk(0x100C, 1, "ret",  "", true, true),
        }, opt);
        CHECK(has(out, "printf()"));
        CHECK(!has(out, "printf(\"hello\")"));
        if (g_fail) std::printf("--- test20 ---\n%s\n", out.c_str());
    }

    // 21) Three-operand IMUL uses the second operand as the multiplicand; it is
    // not misparsed as a two-operand read/modify/write form or dropped to asm.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Auto };
        std::string out = decompile({
            mk(0x1000, 4, "imul", "eax, ecx, 3"),
            mk(0x1004, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "a1 * 3"));
        CHECK(!has(out, "__asm { imul"));
    }

    // 22) A flag-only branch use keeps the arithmetic definition live. Calls
    // invalidate earlier cmp provenance, so a later Jcc is rendered honestly.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Auto };
        std::string out = decompile({
            mk(0x1000, 3, "mov", "r10, rcx"),
            mk(0x1003, 4, "add", "r10, 1"),
            mk(0x1007, 2, "jne", "0x100B", true, false, 0x100B),
            mk(0x1009, 2, "jmp", "0x100C", true, false, 0x100C),
            mk(0x100B, 1, "nop", ""),
            mk(0x100C, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "a1 + 1")); // reaching definition is retained/folded into the flag consumer

        opt.nameFor = [](uint64_t a) { return a == 0x2000 ? std::string("clobber_flags") : std::string(); };
        out = decompile({
            mk(0x1000, 3, "cmp", "rcx, rdx"),
            mk(0x1003, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1008, 2, "je", "0x100C", true, false, 0x100C),
            mk(0x100A, 2, "jmp", "0x100D", true, false, 0x100D),
            mk(0x100C, 1, "nop", ""),
            mk(0x100D, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "je_cc"));
        CHECK(!has(out, "a1 == a2"));
    }

    // 23) Signed and unsigned branch mnemonics remain distinct in emitted C.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Auto };
        std::string u = decompile({
            mk(0x1000, 3, "cmp", "rcx, rdx"),
            mk(0x1003, 2, "jb", "0x1007", true, false, 0x1007),
            mk(0x1005, 2, "jmp", "0x1008", true, false, 0x1008),
            mk(0x1007, 1, "nop", ""), mk(0x1008, 1, "ret", "", true, true),
        }, opt);
        std::string s = decompile({
            mk(0x1000, 3, "cmp", "rcx, rdx"),
            mk(0x1003, 2, "jl", "0x1007", true, false, 0x1007),
            mk(0x1005, 2, "jmp", "0x1008", true, false, 0x1008),
            mk(0x1007, 1, "nop", ""), mk(0x1008, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(u, "uint64_t"));
        CHECK(has(s, "int64_t"));
        CHECK(!has(s, "uint64_t"));
    }

    // 24) RIP-relative data references use next-IP semantics and preserve a
    // valid resolved address of zero.
    {
        bool queriedZero = false;
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Auto };
        opt.dataRefFor = [&](uint64_t address) {
            queriedZero |= address == 0;
            return address == 0 ? std::string("zero_global") : std::string();
        };
        Instruction lea = mk(0, 7, "lea", "rax, [rip - 7]");
        lea.typedOperands.push_back(regOp("rax", 64, OperandAccess::Write));
        TypedOperand memory; memory.kind = OperandKind::Memory; memory.pcRelative = true;
        memory.baseRegister = "rip"; memory.displacement = -7; memory.displacementValid = true;
        memory.widthBits = 64; memory.access = OperandAccess::Read;
        lea.typedOperands.push_back(memory);
        std::string out = decompile({ lea, mk(7, 1, "ret", "", true, true) }, opt);
        CHECK(queriedZero);
        CHECK(has(out, "zero_global"));
    }

    // 25) Decoder-owned typed operands are authoritative. Deliberately bogus
    // display text must neither change the lifted value nor collapse a real
    // three-operand IMUL into the two-operand form.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        Instruction mov = mk(0x1000, 5, "mov", "eax, 99");
        mov.typedOperands = { regOp("eax", 32, OperandAccess::Write), immOp(7, 32) };
        Instruction imul = mk(0x1005, 4, "imul", "eax, 123");
        imul.typedOperands = {
            regOp("eax", 32, OperandAccess::Write),
            regOp("ecx", 32, OperandAccess::Read),
            immOp(3, 32)
        };
        std::string out = decompile({ mov, imul, mk(0x1009, 1, "ret", "", true, true) }, opt);
        CHECK(has(out, "a1 * 3"));
        CHECK(!has(out, "99"));
        CHECK(!has(out, "123"));
        CHECK(!has(out, "__asm { imul"));
    }

    // 26) Comparison width comes from the typed operands, independent of the
    // formatted spelling, and signed/unsigned predicates retain distinct casts.
    {
        auto branchOutput = [&](const char* branch) {
            Instruction cmp = mk(0x1000, 3, "cmp", "rax, rdx");
            cmp.typedOperands = {
                regOp("eax", 32, OperandAccess::Read),
                regOp("edx", 32, OperandAccess::Read)
            };
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            return decompile({
                cmp,
                mk(0x1003, 2, branch, "0x1007", true, false, 0x1007),
                mk(0x1005, 2, "jmp", "0x1008", true, false, 0x1008),
                mk(0x1007, 1, "nop", ""),
                mk(0x1008, 1, "ret", "", true, true),
            }, opt);
        };
        const std::string signedOut = branchOutput("jl");
        const std::string unsignedOut = branchOutput("jb");
        CHECK(has(signedOut, "int32_t"));
        CHECK(!has(signedOut, "int64_t"));
        CHECK(has(unsignedOut, "uint32_t"));
        CHECK(!has(unsignedOut, "uint64_t"));
    }

    // 27) Signed minimum immediates are formatted without negating LLONG_MIN,
    // and width-bounded constant folding rejects arithmetic overflow.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        Instruction minMov = mk(0x1000, 10, "mov", "rax, 1");
        minMov.typedOperands = {
            regOp("rax", 64, OperandAccess::Write),
            immOp(0x8000000000000000ull, 64, true)
        };
        std::string out = decompile({ minMov, mk(0x100A, 1, "ret", "", true, true) }, opt);
        CHECK(has(out, "-0x8000000000000000"));

        Instruction overflowing = mk(0x2000, 4, "imul", "eax, 1, 1");
        overflowing.typedOperands = {
            regOp("eax", 32, OperandAccess::Write),
            immOp(0xFFFFFFFFu, 32),
            immOp(2, 32)
        };
        out = decompile({ overflowing, mk(0x2004, 1, "ret", "", true, true) }, opt);
        CHECK(!has(out, "/* ="));
    }

    // 28) Sign-extension state mutations explicitly consume the accumulator.
    // Their source definition may be folded into the expression, but it must
    // never disappear as an untracked/stale RAX/RDX value.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        std::string out = decompile({
            mk(0x1000, 2, "mov", "eax, ecx"),
            mk(0x1002, 2, "cdqe", ""),
            mk(0x1004, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "(int64_t)(int32_t)(a1)"));

        out = decompile({
            mk(0x2000, 2, "mov", "eax, ecx"),
            mk(0x2002, 2, "cqo", ""),
            mk(0x2004, 3, "mov", "rax, rdx"),
            mk(0x2007, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "(int64_t)(a1) >> 63"));
    }

    // 29) An unmodelled instruction kills decoder-reported outputs only. An
    // unrelated propagated value survives, while the written register cannot
    // leak its stale pre-instruction constant into later pseudocode.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        Instruction mystery = mk(0x100A, 3, "mystery", "ebx");
        mystery.typedOperands = { regOp("ebx", 32, OperandAccess::Write) };
        mystery.registersWritten = { "ebx" };
        std::string out = decompile({
            mk(0x1000, 5, "mov", "eax, 1"),
            mk(0x1005, 5, "mov", "ebx, 2"),
            mystery,
            mk(0x100D, 3, "mov", "dword ptr [rcx], eax"),
            mk(0x1010, 2, "mov", "eax, ebx"),
            mk(0x1012, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "*(a1) = 1"));
        CHECK(!has(out, "return 2"));
        CHECK(has(out, "__asm { mystery ebx }"));
    }

    // 30) Flag consumers that are ordinary instructions (setcc/cmovcc), rather
    // than CFG terminators, keep every reaching definition used by cmp/test.
    // DCE must not erase the arithmetic that supplies their condition inputs.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        std::string out = decompile({
            mk(0x1000, 3, "mov",   "r10, rcx"),
            mk(0x1003, 4, "add",   "r10, 1"),
            mk(0x1007, 3, "cmp",   "r10, rdx"),
            mk(0x100A, 4, "setl",  "r10b"),
            mk(0x100E, 4, "movzx", "eax, r10b"),
            mk(0x1012, 1, "ret",   "", true, true),
        }, opt);
        CHECK(has(out, "a1 + 1"));
        CHECK(has(out, "int64_t"));
        CHECK(has(out, "a2"));
        CHECK(!has(out, "setl_cc"));

        out = decompile({
            mk(0x2000, 3, "mov",   "r10, rcx"),
            mk(0x2003, 4, "add",   "r10, 1"),
            mk(0x2007, 3, "test",  "r10, r10"),
            mk(0x200A, 4, "cmovne", "r10, rdx"),
            mk(0x200E, 3, "mov",   "rax, r10"),
            mk(0x2011, 1, "ret",   "", true, true),
        }, opt);
        CHECK(has(out, "a1 + 1"));
        CHECK(has(out, "!= 0"));
        CHECK(has(out, "a2"));
        CHECK(!has(out, "cmovne_cc"));
    }

    // 31) Flag provenance is per flag: INC replaces ZF/SF/OF but preserves CF.
    // An unrelated INC must therefore leave JB attached to the preceding CMP.
    {
        DecompileOptions opt; opt.target = { Arch::X86, DecompileABI::Unknown };
        std::string out = decompile({
            mk(0x3000, 2, "cmp", "eax, ebx"),
            mk(0x3002, 2, "inc", "ecx"),
            mk(0x3004, 2, "jb",  "0x3008", true, false, 0x3008),
            mk(0x3006, 2, "jmp", "0x3009", true, false, 0x3009),
            mk(0x3008, 1, "nop", ""), mk(0x3009, 1, "ret", "", true, true),
        }, opt);
        CHECK(!has(out, "jb_cc"));
        CHECK(has(out, "uint32_t"));

        // If INC mutates a CMP operand, the physical CF still survives but its
        // printable expression names the now-changed value. Fall back honestly.
        out = decompile({
            mk(0x3100, 2, "cmp", "ecx, eax"),
            mk(0x3102, 2, "inc", "ecx"),
            mk(0x3104, 2, "jb",  "0x3108", true, false, 0x3108),
            mk(0x3106, 2, "jmp", "0x3109", true, false, 0x3109),
            mk(0x3108, 1, "nop", ""), mk(0x3109, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "jb_cc"));
    }

    // 32) Flag-preserving writes cannot leave stale printable operands behind.
    // This covers register aliases and memory aliasing between CMP and Jcc.
    {
        DecompileOptions opt; opt.target = { Arch::X86, DecompileABI::Unknown };
        std::string out = decompile({
            mk(0x3200, 2, "cmp", "eax, ebx"),
            mk(0x3202, 3, "mov", "ax, 7"),
            mk(0x3205, 2, "jb",  "0x3209", true, false, 0x3209),
            mk(0x3207, 2, "jmp", "0x320A", true, false, 0x320A),
            mk(0x3209, 1, "nop", ""), mk(0x320A, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "jb_cc"));

        out = decompile({
            mk(0x3300, 3, "cmp", "dword ptr [eax], 1"),
            mk(0x3303, 3, "mov", "dword ptr [eax], 2"),
            mk(0x3306, 2, "je",  "0x330A", true, false, 0x330A),
            mk(0x3308, 2, "jmp", "0x330B", true, false, 0x330B),
            mk(0x330A, 1, "nop", ""), mk(0x330B, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "je_cc"));

        // The lightweight (deepDataFlow=false) path uses the same condition
        // renderer and canonicalizes partial-register aliases too.
        opt.deepDataFlow = false;
        out = decompile({
            mk(0x3400, 2, "cmp", "eax, ebx"),
            mk(0x3402, 3, "mov", "ax, 7"),
            mk(0x3405, 2, "jb",  "0x3409", true, false, 0x3409),
            mk(0x3407, 2, "jmp", "0x340A", true, false, 0x340A),
            mk(0x3409, 1, "nop", ""), mk(0x340A, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "jb_cc"));
    }

    // 33) ADD/SUB carry/borrow and signed-overflow predicates are modeled from
    // width-aware flag components; none are fabricated as a result-vs-zero test.
    {
        auto arithmeticBranch = [&](const char* arithmetic, const char* branch, uint64_t base) {
            DecompileOptions opt; opt.target = { Arch::X86, DecompileABI::Unknown };
            return decompile({
                mk(base,     2, arithmetic, "eax, ebx"),
                mk(base + 2, 2, branch, "target", true, false, base + 6),
                mk(base + 4, 2, "jmp", "done", true, false, base + 7),
                mk(base + 6, 1, "nop", ""), mk(base + 7, 1, "ret", "", true, true),
            }, opt);
        };
        const std::string addUnsigned = arithmeticBranch("add", "jb", 0x3500);
        const std::string subUnsigned = arithmeticBranch("sub", "jb", 0x3600);
        const std::string addSigned   = arithmeticBranch("add", "jl", 0x3700);
        const std::string subSigned   = arithmeticBranch("sub", "jl", 0x3800);
        CHECK(!has(addUnsigned, "jb_cc") && has(addUnsigned, "uint32_t"));
        CHECK(!has(subUnsigned, "jb_cc") && has(subUnsigned, "uint32_t"));
        CHECK(!has(addSigned, "jl_cc") && has(addSigned, "int32_t"));
        CHECK(!has(subSigned, "jl_cc") && has(subSigned, "int32_t"));

        // The source value of add eax,eax is overwritten along with the result;
        // without an explicit snapshot, carry/overflow must remain unresolved.
        DecompileOptions opt; opt.target = { Arch::X86, DecompileABI::Unknown };
        const std::string selfAdd = decompile({
            mk(0x3860, 2, "add", "eax, eax"),
            mk(0x3862, 2, "jb", "target", true, false, 0x3866),
            mk(0x3864, 2, "jmp", "done", true, false, 0x3867),
            mk(0x3866, 1, "nop", ""), mk(0x3867, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(selfAdd, "jb_cc"));
    }

    // 34) Decoder-reported unknown flag writers invalidate every component.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        Instruction mystery = mk(0x3903, 2, "mystery", "r10");
        mystery.typedOperands = { regOp("r10", 64, OperandAccess::Read) };
        mystery.flagsWritten = SemanticFlagBit(SemanticFlag::Carry) |
            SemanticFlagBit(SemanticFlag::Zero) | SemanticFlagBit(SemanticFlag::Sign) |
            SemanticFlagBit(SemanticFlag::Overflow) | SemanticFlagBit(SemanticFlag::Parity);
        std::string out = decompile({
            mk(0x3900, 3, "cmp", "rcx, rdx"), mystery,
            mk(0x3905, 2, "jl", "0x3909", true, false, 0x3909),
            mk(0x3907, 2, "jmp", "0x390A", true, false, 0x390A),
            mk(0x3909, 1, "nop", ""), mk(0x390A, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(out, "jl_cc"));
        CHECK(!has(out, "a1 <"));
    }

    // 35) The implicit call result follows the exact target width, which in
    // turn controls local declaration inference (EAX/int vs RAX/__int64).
    {
        auto callResult = [&](Arch architecture, uint64_t base) {
            DecompileOptions opt; opt.target = { architecture, DecompileABI::Unknown };
            opt.nameFor = [](uint64_t) { return std::string("callee"); };
            return decompile({
                mk(base, 5, "call", "callee", true, false, base + 0x100),
                mk(base + 5, 1, "ret", "", true, true),
            }, opt);
        };
        const std::string x86 = callResult(Arch::X86, 0x3A00);
        const std::string x64 = callResult(Arch::X64, 0x3B00);
        CHECK(has(x86, "\n    int v"));
        CHECK(!has(x86, "\n    __int64 v"));
        CHECK(has(x64, "\n    __int64 v"));
    }

    // A read-modify-write expression refers to the old destination value.
    // After the assignment is printed, caching that expression would repeat
    // the operation at later uses instead of reading the updated variable.
    {
        DecompileOptions opt;
        opt.target = { Arch::X64, DecompileABI::Win64 };
        struct SelfUpdate {
            const char* mnemonic;
            const char* operands;
            const char* assignment;
        };
        const SelfUpdate cases[] = {
            { "not", "rcx", "a1 = ~(a1);" },
            { "neg", "rcx", "a1 = -(a1);" },
            { "imul", "rcx, rdx", "a1 = a1 * a2;" },
            { "imul", "rcx, rcx, 3", "a1 = a1 * 3;" },
            // ECX/CL share the RCX dependency despite different operand widths.
            { "movsx", "ecx, cl", "a1 = (__int8)a1;" },
        };
        for (const SelfUpdate& test : cases) {
            const std::string out = decompile({
                mk(0, 4, test.mnemonic, test.operands),
                mk(4, 3, "mov", "rax, rcx"),
                mk(7, 1, "ret", "", true, true),
            }, opt);
            CHECK(has(out, test.assignment));
            CHECK(has(out, "return a1;"));
            const size_t assignment = out.find(test.assignment);
            if (assignment != std::string::npos)
                CHECK(out.find(test.assignment, assignment + 1) == std::string::npos);
            if (!has(out, "return a1;"))
                std::printf("--- self update %s %s ---\n%s\n", test.mnemonic, test.operands, out.c_str());
        }

        // Copy propagation can carry the old RCX dependency through RAX. The
        // guard must follow that dependency when the expression returns to RCX.
        const std::string copiedBack = decompile({
            mk(0x3C00, 3, "mov", "rax, rcx"),
            mk(0x3C03, 3, "neg", "rax"),
            mk(0x3C06, 3, "mov", "rcx, rax"),
            mk(0x3C09, 3, "mov", "rax, rcx"),
            mk(0x3C0C, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(copiedBack, "a1 = -(a1);"));
        CHECK(has(copiedBack, "return a1;"));
        CHECK(!has(copiedBack, "return -(a1);"));

        // An updated argument is still a known call argument. Dropping its
        // environment entry would turn consume(a1) into consume() and let DCE
        // erase the update that supplies the call's actual input.
        constexpr uint64_t consumeAddress = 0x5000;
        opt.nameFor = [](uint64_t address) {
            return address == consumeAddress ? std::string("consume") : std::string();
        };
        const SelfUpdate callUpdates[] = {
            { "neg", "rcx", "a1 = -(a1);" },
            { "lea", "rcx, [rcx + 8]", "a1 = (a1 + 8);" },
        };
        for (const SelfUpdate& test : callUpdates) {
            const std::string out = decompile({
                mk(0x3CC0, 4, test.mnemonic, test.operands),
                mk(0x3CC4, 5, "call", "consume", true, false, consumeAddress),
                mk(0x3CC9, 1, "ret", "", true, true),
            }, opt);
            CHECK(has(out, test.assignment));
            CHECK(has(out, "consume(a1)"));
            CHECK(!has(out, "consume()"));
        }

        // A changed destination is safe to inline when its source is another
        // unchanged location; do not disable useful expression propagation.
        const std::string otherRoot = decompile({
            mk(0x3D00, 3, "mov", "rax, rcx"),
            mk(0x3D03, 3, "neg", "rax"),
            mk(0x3D06, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(otherRoot, "return -(a1);"));
        CHECK(!has(otherRoot, "a1 = "));

        // Constant-rooted updates have no mutable dependency and still collapse
        // into a single return with their existing folded-value explanation.
        const std::string constants = decompile({
            mk(0x3E00, 5, "mov", "eax, 7"),
            mk(0x3E05, 2, "neg", "eax"),
            mk(0x3E07, 2, "not", "eax"),
            mk(0x3E09, 3, "imul", "eax, eax, 3"),
            mk(0x3E0C, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(constants, "return ~(-(7)) * 3;"));
        CHECK(has(constants, "/* = 0x12 */"));
        CHECK(!has(constants, " = ~"));
    }

    // Native scalar shifts have operand-width and count-mask semantics that
    // differ from an untyped C compound shift. Intel SDM Vol. 2B,
    // SAL/SAR/SHL/SHR specifies a five-bit count (six for a 64-bit operand),
    // logical SHR versus sign-filling SAR, and unchanged flags at count zero.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        auto shiftResult = [&](const char* mnemonic, const char* destination,
                               uint16_t bits, uint64_t count) {
            Instruction shift = mk(0x4003, 3, mnemonic, "display spelling deliberately ignored");
            shift.typedOperands = {
                regOp(destination, bits, OperandAccess::ReadWrite), immOp(count, 8)
            };
            return decompile({
                mk(0x4000, 3, "mov", "rax, rcx"), shift,
                mk(0x4006, 1, "ret", "", true, true),
            }, opt);
        };
        const std::string logical = shiftResult("shr", "eax", 32, 1);
        const std::string arithmetic = shiftResult("sar", "eax", 32, 1);
        CHECK(has(logical, "(uint64_t)((uint32_t)(a1)) >> 1"));
        CHECK(has(arithmetic, "(int64_t)((int32_t)(a1)) >> 1"));
        CHECK(has(arithmetic, "(uint32_t)(")); // EAX's result zero-extends into RAX.
        CHECK(!has(logical, ">>=") && !has(arithmetic, ">>="));

        // 33 masks to one at dword width but remains 33 at qword width.
        CHECK(has(shiftResult("shr", "eax", 32, 33), " >> 1"));
        CHECK(has(shiftResult("shr", "rax", 64, 33), " >> 33"));
        CHECK(has(shiftResult("sal", "eax", 32, 33), " << 1"));
        CHECK(has(shiftResult("shr", "eax", 32, 32), "return (uint32_t)(a1);"));
        CHECK(has(shiftResult("shr", "rax", 64, 64), "return a1;"));
        CHECK(has(shiftResult("shl", "rax", 64, 63), "(uint64_t)(a1) << 63"));

        // Byte/word counts still use five bits, even beyond operand width.
        // Widening the calculation to 64 bits avoids promoted-int UB for SHL
        // while the output cast models native truncation and partial writes.
        const std::string byteLeft = shiftResult("shl", "al", 8, 31);
        const std::string wordRight = shiftResult("sar", "ax", 16, 31);
        const std::string highByte = shiftResult("shr", "ah", 8, 1);
        CHECK(has(byteLeft, "LOBYTE(") && has(byteLeft, "(uint64_t)((uint8_t)(a1)) << 31"));
        CHECK(has(wordRight, "LOWORD(") && has(wordRight, "(int64_t)((int16_t)(a1)) >> 31"));
        CHECK(has(highByte, "BYTE1(") && has(highByte, "(uint8_t)(a1 >> 8)"));

        Instruction variable = mk(0x4103, 2, "shr", "rax, cl");
        variable.typedOperands = { regOp("rax", 64, OperandAccess::ReadWrite),
                                  regOp("cl", 8, OperandAccess::Read) };
        const std::string variableOut = decompile({
            mk(0x4100, 3, "mov", "rax, rdx"), variable,
            mk(0x4105, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(variableOut, "& 63"));
        variable.typedOperands = { regOp("eax", 32, OperandAccess::ReadWrite),
                                  regOp("cl", 8, OperandAccess::Read) };
        CHECK(has(decompile({ mk(0x4100, 3, "mov", "rax, rdx"), variable,
                              mk(0x4105, 1, "ret", "", true, true) }, opt), "& 31"));

        const std::string memory = decompile({
            mk(0x4180, 3, "shr", "dword ptr [rcx], 33"),
            mk(0x4183, 1, "ret", "", true, true),
        }, opt);
        CHECK(has(memory, "*(a1) = (uint32_t)("));
        CHECK(has(memory, "(uint64_t)((uint32_t)(*(a1))) >> 1"));

        auto flagsAcrossShift = [&](const char* operands) {
            return decompile({
                mk(0x4200, 3, "cmp", "rcx, rdx"),
                mk(0x4203, 3, "shl", operands),
                mk(0x4206, 2, "jb", "target", true, false, 0x420A),
                mk(0x4208, 2, "jmp", "done", true, false, 0x420B),
                mk(0x420A, 1, "nop", ""), mk(0x420B, 1, "ret", "", true, true),
            }, opt);
        };
        CHECK(!has(flagsAcrossShift("r8d, 32"), "jb_cc"));
        CHECK(!has(flagsAcrossShift("cl, 32"), "jb_cc"));
        CHECK(!has(flagsAcrossShift("rcx, 64"), "jb_cc"));
        CHECK(has(flagsAcrossShift("r8d, 1"), "jb_cc"));
        if (g_fail) std::printf("--- native shifts ---\n%s\n%s\n%s\n", logical.c_str(), arithmetic.c_str(), highByte.c_str());
    }

    // Unknown operations still read real registers and stack memory. A raw
    // consumer must retain its setup even if no later C expression uses it.
    {
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        Instruction unknown = mk(3, 2, "opaque_consume", "rcx");
        unknown.typedOperands = { regOp("rcx", 64, OperandAccess::Read) };
        const std::string direct = decompile({ mk(0, 3, "mov", "rcx, 7"), unknown,
            mk(5, 2, "xor", "eax, eax"), mk(7, 1, "ret", "", true, true) }, opt);
        CHECK(has(direct, " = 7;"));
        CHECK(has(direct, "opaque_consume rcx"));

        unknown.operands = "";
        unknown.typedOperands.clear();
        unknown.registersRead = { "rcx" }; // implicit decoder input
        CHECK(has(decompile({ mk(0, 3, "mov", "rcx, 7"), unknown,
            mk(5, 2, "xor", "eax, eax"), mk(7, 1, "ret", "", true, true) }, opt), " = 7;"));

        TypedOperand memory;
        memory.kind = OperandKind::Memory; memory.access = OperandAccess::Read;
        memory.widthBits = 32; memory.baseRegister = "rbp";
        memory.displacement = -8; memory.displacementValid = true;
        unknown.operands = "dword ptr [rbp - 8]";
        unknown.typedOperands = { memory }; unknown.registersRead.clear();
        CHECK(has(decompile({ mk(0, 3, "mov", "dword ptr [rbp - 8], 7"), unknown,
            mk(5, 2, "xor", "eax, eax"), mk(7, 1, "ret", "", true, true) }, opt), " = 7;"));

        // Incomplete access metadata is a conservative barrier, not proof
        // that this unknown operation preserves cached register constants.
        unknown.typedOperands = { regOp("rcx", 64, OperandAccess::None) };
        unknown.operands = "rcx";
        const std::string incomplete = decompile({ mk(0, 3, "mov", "rcx, 7"), unknown,
            mk(5, 3, "mov", "rax, rcx"), mk(8, 1, "ret", "", true, true) }, opt);
        CHECK(!has(incomplete, "return 7;"));
    }

    // Decoder flag masks describe independent flag lifetimes. A CF-only
    // unsupported writer preserves a preceding signed comparison's SF/OF.
    {
        Instruction writer = mk(3, 2, "opaque_carry", "r10");
        writer.typedOperands = { regOp("r10", 64, OperandAccess::Read) };
        writer.flagsWritten = SemanticFlagBit(SemanticFlag::Carry);
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        const std::string output = decompile({ mk(0, 3, "cmp", "rcx, rdx"), writer,
            mk(5, 2, "jl", "9", true, false, 9), mk(7, 2, "jmp", "10", true, false, 10),
            mk(9, 1, "nop", ""), mk(10, 1, "ret", "", true, true) }, opt);
        CHECK(!has(output, "jl_cc"));
        CHECK(has(output, "int64_t"));
    }

    // Typed operation records retain origin, width, alias slices, sign,
    // memory/address distinctions and ABI boundaries independently of text.
    {
        Instruction load = mk(0, 4, "movsx", "presentation deliberately ignored");
        load.typedOperands = { regOp("eax", 32, OperandAccess::Write),
                               regOp("ah", 8, OperandAccess::Read) };
        const auto operation = LiftInstructionSemantics(load, Arch::X64, DecompileABI::Win64);
        CHECK(operation.sourceVA == 0 && operation.sourceLength == 4);
        CHECK(operation.opcode == IntermediateOpcode::SignExtend && operation.widthBits == 32);
        CHECK(operation.signedness == IntermediateSignedness::Signed);
        CHECK(operation.operands[0].reg.zeroExtendsStorage);
        CHECK(operation.operands[1].reg.offsetBits == 8 && operation.operands[1].reg.storage == "rax");
        CHECK(!DescribeRegisterSlice("eax", 32, Arch::X86).zeroExtendsStorage);
        Instruction repeated = mk(0, 2, "movsb", "");
        repeated.prefixes = { InstructionPrefix::Rep };
        repeated.registersRead = { "rsi", "rdi", "rcx" };
        repeated.registersWritten = repeated.registersRead;
        const auto repeatedEffects = LiftInstructionSemantics(repeated, Arch::X64);
        CHECK(repeatedEffects.repeated && repeatedEffects.readsMemory && repeatedEffects.writesMemory && repeatedEffects.unknownMemoryEffects);

        Instruction address = mk(4, 3, "lea", "rax, [rcx + 8]");
        TypedOperand memory; memory.kind = OperandKind::Memory;
        memory.access = OperandAccess::Read; memory.baseRegister = "rcx";
        memory.displacement = 8; memory.displacementValid = true;
        address.typedOperands = { regOp("rax", 64, OperandAccess::Write), memory };
        const auto lea = LiftInstructionSemantics(address, Arch::X64);
        CHECK(lea.operands[1].addressOnly && !lea.readsMemory && !lea.writesMemory);
        CHECK(std::find(lea.registersRead.begin(), lea.registersRead.end(), "rcx") != lea.registersRead.end());
        address.mnemonic = "mov";
        CHECK(LiftInstructionSemantics(address, Arch::X64).readsMemory);

        const auto call = LiftInstructionSemantics(mk(7, 5, "call", "callee"), Arch::X64, DecompileABI::SysV64);
        CHECK(call.callingConvention == DecompileABI::SysV64 && call.unknownMemoryEffects && call.unknownFlagEffects);
        CHECK(LiftInstructionSemantics(load, Arch::ARM64).opcode == IntermediateOpcode::Unknown);

        ControlFlowGraph graph;
        graph.blocks.emplace_back();
        graph.blocks[0].insns = { load, mk(4, 1, "ret", "", true, true) };
        graph.blocks[0].isReturn = true;
        graph.blocks[0].transferIndex = 1;
        const auto result = AnalyzeDataFlow(graph, {}, {}, true, Arch::X64, DecompileABI::Win64);
        CHECK(result.ok && result.blockOperations.size() == 1);
        CHECK(result.blockOperations[0].size() == 2);
        CHECK(result.blockOperations[0][0].sourceVA == 0);
        CHECK(result.blockOperations[0][1].opcode == IntermediateOpcode::Return);
    }

    // Prefix effects survive rendering, and modern direct-target metadata is
    // authoritative even when a legacy decoder target field is absent.
    {
        Instruction atomic = mk(0, 4, "add", "dword ptr [rcx], 1");
        atomic.prefixes = { InstructionPrefix::Lock };
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Win64 };
        const std::string output = decompile({ atomic, mk(4, 1, "ret", "", true, true) }, opt);
        CHECK(has(output, "__asm { lock add dword ptr [rcx], 1 };"));
        Instruction call = mk(0, 5, "call", "display_only");
        call.flow = { FlowKind::DirectCall, true, 0x1234 };
        opt.nameFor = [](uint64_t address) { return address == 0x1234 ? "semantic_callee" : "wrong_target"; };
        CHECK(has(decompile({ call, mk(5, 1, "ret", "", true, true) }, opt), "semantic_callee("));
    }

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("dataflow_decomp_test: all checks passed\n");
    return 0;
}
