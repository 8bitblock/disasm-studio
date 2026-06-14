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

    // 9) One-operand divide is modeled as quotient (and remainder when used).
    //    quotient only: xor edx,edx ; div ecx ; ret  -> return v / ecx (remainder dead).
    {
        std::string out = decompile({
            mk(0x1000, 2, "xor", "edx, edx"),
            mk(0x1002, 2, "div", "ecx"),
            mk(0x1004, 1, "ret", "", true, true),
        });
        CHECK(has(out, " / "));
        CHECK(!has(out, "__asm"));
        if (g_fail) std::printf("--- test9 ---\n%s\n", out.c_str());
    }
    //    remainder used: xor edx,edx ; div ecx ; mov eax,edx ; ret  -> return uses %.
    {
        std::string out = decompile({
            mk(0x1000, 2, "xor", "edx, edx"),
            mk(0x1002, 2, "div", "ecx"),
            mk(0x1004, 2, "mov", "eax, edx"),
            mk(0x1006, 1, "ret", "", true, true),
        });
        CHECK(has(out, " % "));
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

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("dataflow_decomp_test: all checks passed\n");
    return 0;
}
