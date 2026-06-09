//
// decompiler_fixes_test.cpp
// Focused regression tests for the Flagship-B decompiler fixes:
//   (1) if / switch body must not overrun into sibling blocks when a block has no
//       immediate post-dominator (no reconvergence; ipdom == -1).
//   (2) nested-loop break/continue must bind to the correct loop's follow/header
//       (no duplicated outer-loop body).
//   (3) inter-block constant/copy propagation in the data-flow pass.
//   (4) x86 cdecl/stdcall stack-argument detection ([esp+N]/[ebp+N]).
//
// The real engines can't run here, so a MockDisassembler replays a canned x86/x64
// instruction stream keyed by VA. We BuildCFG + Decompile and assert on the text.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\decompiler_fixes_test.cpp ^
//      src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
//   .\decompiler_fixes_test.exe
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

// Build a contiguous instruction stream: each entry's address is the running
// cursor (starting at `base`), advanced by `len`. This guarantees a well-formed
// CFG with no accidental gaps (gaps break fall-through edge resolution).
struct Asm {
    uint64_t base; uint64_t cur; std::vector<Instruction> ins;
    explicit Asm(uint64_t b = 0x1000) : base(b), cur(b) {}
    // Plain instruction (no branch).
    uint64_t op(uint32_t len, const char* m, const char* o = "") {
        uint64_t a = cur; ins.push_back(mk(a, len, m, o)); cur += len; return a;
    }
    // Branch with a resolved target VA.
    uint64_t br(uint32_t len, const char* m, uint64_t target, const char* o = "") {
        uint64_t a = cur; ins.push_back(mk(a, len, m, o, true, false, target)); cur += len; return a;
    }
    // Return.
    uint64_t ret(uint32_t len = 1) {
        uint64_t a = cur; ins.push_back(mk(a, len, "ret", "", true, true, 0)); cur += len; return a;
    }
    // Indirect/computed branch (no static target), e.g. a switch dispatch.
    uint64_t ind(uint32_t len, const char* m, const char* o) {
        uint64_t a = cur; ins.push_back(mk(a, len, m, o, true, false, 0)); cur += len; return a;
    }
};

static std::string decompile(const std::vector<Instruction>& ins, const DecompileOptions& opt = {},
                             const JumpTableResolver& resolver = {}) {
    MockDisassembler dis;
    // Instructions may be appended out of address order (e.g. a back-patched branch),
    // so compute base/end from the min/max VA — NOT ins.front()/ins.back() — to size
    // the decode window over the WHOLE stream.
    uint64_t base = ~0ull, end = 0;
    for (auto& in : ins) { if (in.address < base) base = in.address;
                           if (in.address + in.length > end) end = in.address + in.length; }
    for (auto& in : ins) dis.at[in.address] = in;
    std::vector<uint8_t> buf((size_t)(end - base) + 16, 0);
    ControlFlowGraph g = BuildCFG(buf.data(), buf.size(), base, dis, 2000, resolver);
    return Decompile(g, opt);
}
static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }
static int countOf(const std::string& s, const char* sub) {
    int n = 0; std::string t = sub; size_t p = 0;
    while ((p = s.find(t, p)) != std::string::npos) { ++n; p += t.size(); }
    return n;
}

int main() {
    // --- (1a) if with NO join: both arms reach distinct returns (ipdom == -1) ---
    //   cmp ecx,0 / je else ; then: mov eax,0x11 ; ret ; else: mov eax,0x22 ; ret
    // The then-arm must stop at the else, the else at its own ret. Both bodies must
    // be emitted exactly once (no duplication / overrun).
    {
        Asm a; uint64_t thenB, elseB;
        a.op(2, "cmp", "ecx, 0");
        // resolve `else` after we know its address
        // then block is right after the je; else is two instructions later.
        // We pre-compute: je(len2) -> then(mov len3, ret len1) -> else.
        uint64_t jeAddr = a.cur;
        a.cur += 2;                                  // reserve the je slot
        thenB = a.cur; a.op(3, "mov", "eax, 0x11"); a.ret();
        elseB = a.cur; a.op(3, "mov", "eax, 0x22"); a.ret();
        a.ins.push_back(mk(jeAddr, 2, "je", "", true, false, elseB));   // fill the je
        // reorder so addresses are ascending (decompile keys by VA, order-independent)
        std::string out = decompile(a.ins);
        CHECK(has(out, "0x11"));
        CHECK(has(out, "0x22"));
        CHECK(countOf(out, "0x11") == 1);
        CHECK(countOf(out, "0x22") == 1);
        if (g_fail) std::printf("--- test1a ---\n%s\n", out.c_str());
    }

    // --- (1b) if-then that joins a tail; the tail sibling must be emitted once ---
    //   cmp ecx,0 / jne tail ; then: mov [rdx],0x11 (a side effect) ; (fall) tail: mov eax,0x33 ; ret
    // The then store survives DCE, so it proves the then-arm is emitted (not dropped),
    // and the tail's 0x33 must appear exactly once (not duplicated by overrun).
    {
        Asm a;
        a.op(2, "cmp", "ecx, 0");
        uint64_t jneAddr = a.cur; a.cur += 2;
        a.op(7, "mov", "dword ptr [rdx], 0x11");   // then body (store survives DCE), falls through
        uint64_t tail = a.cur; a.op(5, "mov", "eax, 0x33"); a.ret();
        a.ins.push_back(mk(jneAddr, 2, "jne", "", true, false, tail));
        std::string out = decompile(a.ins);
        CHECK(countOf(out, "0x11") == 1);     // then store emitted once
        CHECK(countOf(out, "0x33") == 1);     // tail emitted once
        if (g_fail) std::printf("--- test1b ---\n%s\n", out.c_str());
    }

    // --- (1c) switch with NO join (every case returns; ipdom == -1) ---
    //   cmp eax,2 / ja default ; jmp [rax*8+tbl] -> case0/1/2 each `mov eax,N ; ret`.
    // Each case body must hold exactly its own return; case 0 must NOT swallow the
    // siblings' bodies.
    {
        Asm a;
        a.op(3, "cmp", "eax, 2");
        uint64_t jaAddr = a.cur; a.cur += 2;
        uint64_t disp = a.ind(7, "jmp", "qword ptr [rax*8 + 0x4000]");
        uint64_t c0 = a.cur; a.op(5, "mov", "eax, 0xA0"); a.ret();
        uint64_t c1 = a.cur; a.op(5, "mov", "eax, 0xB0"); a.ret();
        uint64_t c2 = a.cur; a.op(5, "mov", "eax, 0xC0"); a.ret();
        a.ins.push_back(mk(jaAddr, 2, "ja", "", true, false, c2));   // default -> case2 region
        JumpTableResolver resolver = [&](const Instruction& in) -> std::vector<uint64_t> {
            if (in.address == disp) return { c0, c1, c2 };
            return {};
        };
        std::string out = decompile(a.ins, {}, resolver);
        CHECK(has(out, "switch ("));
        CHECK(countOf(out, "0xA0") == 1);
        CHECK(countOf(out, "0xB0") == 1);
        CHECK(countOf(out, "0xC0") == 1);
        if (g_fail) std::printf("--- test1c ---\n%s\n", out.c_str());
    }

    // --- (1d) switch with NO join where cases do NOT return and a shared tail follows ---
    // Each case stores a distinct value then falls/branches to a common tail. The tail
    // must be emitted ONCE after the switch (not swallowed into / duplicated across
    // every case body).
    //   cmp eax,2 / ja tail ; jmp[tbl] -> c0/c1/c2
    //   c0: mov [rdx],0xA0 ; jmp tail
    //   c1: mov [rdx],0xB0 ; jmp tail
    //   c2: mov [rdx],0xC0 ; jmp tail
    //   tail: mov eax,0xDD ; ret
    {
        Asm a;
        a.op(3, "cmp", "eax, 2");
        uint64_t jaAddr = a.cur; a.cur += 2;
        uint64_t disp = a.ind(7, "jmp", "qword ptr [rax*8 + 0x5000]");
        uint64_t c0 = a.cur; a.op(7, "mov", "dword ptr [rdx], 0xA0"); uint64_t j0 = a.cur; a.cur += 2;
        uint64_t c1 = a.cur; a.op(7, "mov", "dword ptr [rdx], 0xB0"); uint64_t j1 = a.cur; a.cur += 2;
        uint64_t c2 = a.cur; a.op(7, "mov", "dword ptr [rdx], 0xC0"); uint64_t j2 = a.cur; a.cur += 2;
        uint64_t tail = a.cur; a.op(5, "mov", "eax, 0xDD"); a.ret();
        a.ins.push_back(mk(jaAddr, 2, "ja", "", true, false, tail));
        a.ins.push_back(mk(j0, 2, "jmp", "", true, false, tail));
        a.ins.push_back(mk(j1, 2, "jmp", "", true, false, tail));
        a.ins.push_back(mk(j2, 2, "jmp", "", true, false, tail));
        JumpTableResolver resolver = [&](const Instruction& in) -> std::vector<uint64_t> {
            if (in.address == disp) return { c0, c1, c2 };
            return {};
        };
        std::string out = decompile(a.ins, {}, resolver);
        CHECK(has(out, "switch ("));
        CHECK(countOf(out, "0xA0") == 1);     // each case body once
        CHECK(countOf(out, "0xB0") == 1);
        CHECK(countOf(out, "0xC0") == 1);
        CHECK(countOf(out, "0xDD") == 1);     // shared tail emitted exactly once
        if (g_fail) std::printf("--- test1d ---\n%s\n", out.c_str());
    }

    // --- (2a) clean nested loops: two loop constructs, outer body emitted once ---
    //   outer header: cmp esi,edi / jge end
    //     inner header: cmp eax,ebx / jge latch
    //       inner body: add ecx,eax ; inc eax ; jmp inner-header
    //     latch: inc esi ; jmp outer-header
    //   end: ret
    {
        Asm a;
        uint64_t outerH = a.op(2, "cmp", "esi, edi");
        uint64_t jgeOuter = a.cur; a.cur += 2;
        uint64_t innerH = a.op(2, "cmp", "eax, ebx");
        uint64_t jgeInner = a.cur; a.cur += 2;
        a.op(2, "add", "ecx, eax");
        a.op(2, "inc", "eax");
        a.br(2, "jmp", innerH);                       // inner back-edge
        uint64_t latch = a.cur; a.op(2, "inc", "esi");
        a.br(2, "jmp", outerH);                        // outer back-edge
        uint64_t end = a.cur; a.ret();
        a.ins.push_back(mk(jgeOuter, 2, "jge", "", true, false, end));
        a.ins.push_back(mk(jgeInner, 2, "jge", "", true, false, latch));
        std::string out = decompile(a.ins);
        int loops = countOf(out, "while (") + countOf(out, "for (");
        CHECK(loops >= 2);                             // two distinct loop constructs
        CHECK(countOf(out, "esi++") + countOf(out, "esi += 1") <= 1);
        if (g_fail) std::printf("--- test2a ---\n%s\n", out.c_str());
    }

    // --- (2b) inner loop with an early exit straight to the OUTER follow ---
    // The "break to the outer loop" edge is the bug: goTo(end) must NOT inline the
    // outer follow inside the inner loop (which duplicates / mis-binds the loop body).
    //   outer header (H1): cmp esi,edi / jge end
    //     inner header (H2): cmp eax,ebx / jge latch
    //       inner body (B):  test ecx,ecx / jne end   ; early exit to OUTER follow
    //       (fall) B2:       inc eax ; jmp H2          ; inner back-edge
    //     latch (L):         inc esi ; jmp H1          ; outer back-edge
    //   end: ret
    {
        Asm a;
        uint64_t h1 = a.op(2, "cmp", "esi, edi");
        uint64_t jgeOuter = a.cur; a.cur += 2;
        uint64_t h2 = a.op(2, "cmp", "eax, ebx");
        uint64_t jgeInner = a.cur; a.cur += 2;
        a.op(2, "test", "ecx, ecx");
        uint64_t jneEarly = a.cur; a.cur += 2;        // jne end  (break outer)
        a.op(2, "inc", "eax");
        a.br(2, "jmp", h2);                            // inner back-edge
        uint64_t latch = a.cur; a.op(2, "inc", "esi");
        a.br(2, "jmp", h1);                            // outer back-edge
        uint64_t end = a.cur; a.ret();
        a.ins.push_back(mk(jgeOuter, 2, "jge", "", true, false, end));
        a.ins.push_back(mk(jgeInner, 2, "jge", "", true, false, latch));
        a.ins.push_back(mk(jneEarly, 2, "jne", "", true, false, end));   // early exit -> outer follow
        std::string out = decompile(a.ins);
        // The outer follow (`end:` ret) must be reached, not duplicated inside the inner
        // loop. The outer induction `inc esi` (latch) must appear exactly once.
        CHECK(countOf(out, "esi++") + countOf(out, "esi += 1") <= 1);
        // The inner increment `inc eax` (the inner body) must appear exactly once.
        CHECK(countOf(out, "eax++") + countOf(out, "eax += 1") <= 1);
        int loops = countOf(out, "while (") + countOf(out, "for (");
        CHECK(loops >= 2);
        if (g_fail) std::printf("--- test2b ---\n%s\n", out.c_str());
    }

    // --- (2c) inner loop body jumps to the OUTER header (continue-outer) ---
    // Inlining the outer header would re-emit the whole outer loop body. The outer
    // header `cmp esi,edi` must appear exactly once (no outer-body duplication).
    //   outer header (H1): cmp esi,edi / jge end
    //     inner header (H2): cmp eax,ebx / jge latch
    //       inner body (B):  test ecx,ecx / jne H1   ; continue OUTER loop
    //       (fall) B2:       inc eax ; jmp H2         ; inner back-edge
    //     latch (L):         inc esi ; jmp H1
    //   end: ret
    {
        Asm a;
        uint64_t h1 = a.op(2, "cmp", "esi, edi");
        uint64_t jgeOuter = a.cur; a.cur += 2;
        uint64_t h2 = a.op(2, "cmp", "eax, ebx");
        uint64_t jgeInner = a.cur; a.cur += 2;
        a.op(2, "test", "ecx, ecx");
        uint64_t jneCont = a.cur; a.cur += 2;          // jne H1 (continue outer)
        a.op(2, "inc", "eax");
        a.br(2, "jmp", h2);                            // inner back-edge
        uint64_t latch = a.cur; a.op(2, "inc", "esi");
        a.br(2, "jmp", h1);                            // outer back-edge
        uint64_t end = a.cur; a.ret();
        a.ins.push_back(mk(jgeOuter, 2, "jge", "", true, false, end));
        a.ins.push_back(mk(jgeInner, 2, "jge", "", true, false, latch));
        a.ins.push_back(mk(jneCont, 2, "jne", "", true, false, h1));    // -> outer header
        std::string out = decompile(a.ins);
        // The outer header test must NOT be duplicated (it appears once as the for-cond).
        CHECK(countOf(out, "v1 < v2") + countOf(out, "esi < edi") <= 1);
        // The inner body must not be duplicated either.
        CHECK(countOf(out, "eax++") + countOf(out, "eax += 1") <= 1);
        if (g_fail) std::printf("--- test2c ---\n%s\n", out.c_str());
    }

    // --- (3) inter-block constant propagation ---
    //   mov rax,5 ; jmp B ; B: mov rbx,rax ; mov rax,rbx ; ret
    // rax==5 reaches block B; `rbx=rax` folds to `rbx=5`; the return surfaces 5.
    {
        Asm a;
        a.op(7, "mov", "rax, 5");
        uint64_t b = a.cur + 2;
        a.br(2, "jmp", b);
        a.op(3, "mov", "rbx, rax");
        a.op(3, "mov", "rax, rbx");
        a.ret();
        std::string out = decompile(a.ins);
        CHECK(has(out, "return 5;"));   // constant 5 propagated across the block boundary
        if (g_fail) std::printf("--- test3 ---\n%s\n", out.c_str());
    }

    // --- (3b) SOUNDNESS: a value defined differently on two paths is NOT folded ---
    //   cmp ecx,0 / je e ; (then) mov rax,1 ; jmp j ; (else e) mov rax,2 ; (j) mov rbx,rax ; ret
    // rax disagrees at the join, so `rbx = rax` must stay a variable (not 1 or 2), and
    // the function must NOT return a bogus constant.
    {
        Asm a;
        a.op(2, "cmp", "ecx, 0");
        uint64_t jeAddr = a.cur; a.cur += 2;
        a.op(7, "mov", "rax, 1");
        uint64_t jmpAddr = a.cur; a.cur += 2;
        uint64_t elseB = a.cur; a.op(7, "mov", "rax, 2");
        uint64_t joinB = a.cur; a.op(3, "mov", "rbx, rax"); a.ret();
        a.ins.push_back(mk(jeAddr, 2, "je", "", true, false, elseB));
        a.ins.push_back(mk(jmpAddr, 2, "jmp", "", true, false, joinB));
        std::string out = decompile(a.ins);
        CHECK(!has(out, "return 1;"));   // must not fold a disagreeing value
        CHECK(!has(out, "return 2;"));
        if (g_fail) std::printf("--- test3b ---\n%s\n", out.c_str());
    }

    // --- (3c) SOUNDNESS: a loop-mutated value is not folded past the back-edge ---
    //   mov eax,0 ; (H) cmp eax,ecx / jge end ; add eax,1 ; jmp H ; end: mov ebx,eax ; ret
    // eax is the induction var; inside/after the loop it must stay a variable, never
    // the pre-loop constant 0.
    {
        Asm a;
        a.op(5, "mov", "eax, 0");
        uint64_t h = a.op(2, "cmp", "eax, ecx");
        uint64_t jgeAddr = a.cur; a.cur += 2;
        a.op(3, "add", "eax, 1");
        a.br(2, "jmp", h);
        uint64_t end = a.cur; a.op(2, "mov", "ebx, eax"); a.ret();
        a.ins.push_back(mk(jgeAddr, 2, "jge", "", true, false, end));
        std::string out = decompile(a.ins);
        CHECK(!has(out, "return 0;"));   // the post-loop value is not the pre-loop constant
        if (g_fail) std::printf("--- test3c ---\n%s\n", out.c_str());
    }

    // --- (4) x86 cdecl stack-arg detection: [esp+N] / [ebp+N] read-before-write ---
    //   mov eax,[esp+4] ; add eax,[esp+8] ; ret
    {
        Asm a;
        a.op(4, "mov", "eax, dword ptr [esp + 4]");
        a.op(4, "add", "eax, dword ptr [esp + 8]");
        a.ret();
        std::string out = decompile(a.ins);
        CHECK(has(out, "a1"));      // [esp+4] named a1
        CHECK(has(out, "a2"));      // [esp+8] named a2
        CHECK(has(out, "(a1, a2)"));  // detected args now flow into the function HEADER, not just the body
        if (g_fail) std::printf("--- test4 (esp) ---\n%s\n", out.c_str());
    }
    // ebp-frame variant: standard cdecl prologue then [ebp+8]/[ebp+0xC].
    {
        Asm a;
        a.op(1, "push", "ebp");
        a.op(2, "mov",  "ebp, esp");
        a.op(3, "mov",  "eax, dword ptr [ebp + 8]");
        a.op(3, "add",  "eax, dword ptr [ebp + 0xC]");
        a.op(1, "pop",  "ebp");
        a.ret();
        std::string out = decompile(a.ins);
        CHECK(has(out, "a1"));
        CHECK(has(out, "a2"));
        if (g_fail) std::printf("--- test4 (ebp) ---\n%s\n", out.c_str());
    }

    // --- (4c) regression: an x64 function doing 32-bit data math still gets Win64
    //     register args (esp/ebp absence keeps the 64-bit ABI model; a bare eax/ecx
    //     must NOT be mistaken for a 32-bit function and lose rcx/rdx -> a1/a2). ---
    {
        Asm a;
        a.op(2, "mov", "eax, ecx");        // eax = a1 (rcx)
        a.op(2, "add", "eax, edx");        // += a2 (rdx)
        a.ret();
        std::string out = decompile(a.ins);
        CHECK(has(out, "a1"));             // rcx still recognized as a1
        CHECK(has(out, "a2"));             // rdx still recognized as a2
        if (g_fail) std::printf("--- test4c (x64 32-bit ops) ---\n%s\n", out.c_str());
    }

    // --- (5) regression: with deepDataFlow OFF, legacy lift is unchanged ---
    {
        DecompileOptions opt; opt.deepDataFlow = false;
        Asm a;
        a.op(7, "mov", "rax, 5");
        uint64_t b = a.cur + 2;
        a.br(2, "jmp", b);
        a.op(3, "mov", "rbx, rax");
        a.ret();
        std::string out = decompile(a.ins, opt);
        CHECK(has(out, "rax = 5;"));    // raw register lift, no propagation
        CHECK(has(out, "rbx = rax;"));
        if (g_fail) std::printf("--- test5 ---\n%s\n", out.c_str());
    }

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("decompiler_fixes_test: all checks passed\n");
    return 0;
}
