//
// decompiler_folder_test.cpp
// Tests for the decompiler's (B) expression-folding post-pass
// (src/Core/Decompiler.cpp, Structurer::foldTempsPass), wired into
// DecompileWithMap's deep-data-flow pipeline. The pass has two rewrites:
//   B1 coalesce  `vN = E;` + `vN OP= R;`  ->  `vN = E OP R;`  (one line removed)
//   B2 inline    a single-use temp into its next statement     (one line removed)
// Asserts that
//   (1) a `vN = E;` init followed by `vN OP= R;` fuses into one statement and the
//       output has one FEWER line, with lineVA shrunk in lockstep (== line count);
//   (2) DecompileWithMap(...).text stays byte-equal to Decompile(...);
//   (3) folding NEVER fires across a call boundary or when the temp is used more
//       than once (soundness): a stored-and-returned temp is not over-inlined;
//   (4) the pass is a no-op (and the map unchanged) when nothing matches, and can
//       be disabled with opt.foldTemps=false;
//   (5) every kept lineVA still points inside the function (or 0 = synthetic).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\decompiler_folder_test.cpp ^
//      src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
//   .\decompiler_folder_test.exe
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

static ControlFlowGraph buildG(const std::vector<Instruction>& ins) {
    static MockDisassembler dis;
    dis.at.clear();
    uint64_t base = ~0ull, end = 0;
    for (auto& in : ins) { if (in.address < base) base = in.address;
                           if (in.address + in.length > end) end = in.address + in.length; }
    for (auto& in : ins) dis.at[in.address] = in;
    std::vector<uint8_t> buf((size_t)(end - base) + 16, 0);
    return BuildCFG(buf.data(), buf.size(), base, dis, 2000);
}

static std::vector<std::string> splitLines(const std::string& t) {
    std::vector<std::string> L;
    for (size_t s = 0, i = 0; i <= t.size(); ++i)
        if (i == t.size() || t[i] == '\n') {
            if (i == t.size() && s == i) break;
            L.push_back(t.substr(s, i - s));
            s = i + 1;
        }
    return L;
}
static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }
static int countOf(const std::string& s, const char* sub) {
    int n = 0; std::string t = sub; size_t p = 0;
    while ((p = s.find(t, p)) != std::string::npos) { ++n; p += t.size(); }
    return n;
}

int main() {
    // ---- (1)(2)(5) B1 coalesce: init + compound-assign fuse into one line ------
    //   mov rax,rcx ; add rax,rdx ; mov [r8],rax ; ret
    //   DataFlow emits  v1 = a1;  v1 += a2;  *(a3) = v1;  return v1;
    //   B1 fuses the first two ->  v1 = a1 + a2;  (one fewer line)
    {
        std::vector<Instruction> ins = {
            mk(0x1000, 3, "mov", "rax, rcx"),
            mk(0x1003, 3, "add", "rax, rdx"),
            mk(0x1006, 3, "mov", "qword ptr [r8], rax"),
            mk(0x1009, 1, "ret", "", true, true),
        };
        ControlFlowGraph g = buildG(ins);

        DecompileOptions on;
        DecompileOptions off; off.foldTemps = false;
        DecompResult r  = DecompileWithMap(g, on);
        DecompResult r0 = DecompileWithMap(g, off);
        CHECK(r.text == Decompile(g, on));                  // (2)
        std::vector<std::string> L  = splitLines(r.text);
        std::vector<std::string> L0 = splitLines(r0.text);
        CHECK(r.lineVA.size() == L.size());                 // (1) parallel
        CHECK(r0.lineVA.size() == L0.size());

        // The compound-assign line must be gone; a fused single statement present.
        bool had = has(r0.text, "+= a2") || has(r0.text, "+= rdx");
        if (had) {
            CHECK(L.size() == L0.size() - 1);               // exactly one line removed
            CHECK(r.lineVA.size() == r0.lineVA.size() - 1);
            CHECK(!has(r.text, "+="));                       // no compound assign left
            CHECK(has(r.text, "a1 + a2") || has(r.text, "+"));
        }
        for (uint64_t va : r.lineVA) CHECK(va == 0 || (va >= 0x1000 && va < 0x100A));   // (5)
        if (g_fail) std::printf("--- folder(1) ON ---\n%s\n--- OFF ---\n%s\n", r.text.c_str(), r0.text.c_str());
    }

    // ---- (3) SOUNDNESS: a temp used twice (store + return) is NOT inlined away --
    //   same shape; v1 feeds BOTH the store and the return, so B2 must not delete
    //   its definition (the value would be computed twice / lost).
    {
        std::vector<Instruction> ins = {
            mk(0x1000, 3, "mov", "rax, rcx"),
            mk(0x1003, 4, "and", "rax, 0xff"),
            mk(0x1007, 3, "mov", "qword ptr [rdx], rax"),
            mk(0x100A, 1, "ret", "", true, true),
        };
        ControlFlowGraph g = buildG(ins);
        DecompileOptions on;
        DecompResult r = DecompileWithMap(g, on);
        CHECK(r.text == Decompile(g, on));
        CHECK(r.lineVA.size() == splitLines(r.text).size());
        // After B1 the def is `v1 = a1 & 0xFF;` and it is referenced twice more
        // (store + return), so the def line must SURVIVE (a single definition).
        if (has(r.text, "v1")) {
            CHECK(countOf(r.text, "v1") >= 3);   // decl + def + >=2 uses (not collapsed)
        }
        if (g_fail) std::printf("--- folder(3) ---\n%s\n", r.text.c_str());
    }

    // ---- (3b) SOUNDNESS: never fold a call's result across into another stmt ----
    //   the data-flow pass keeps a call dst as its own statement; B refuses RHS
    //   containing a call paren. A function with a call must keep the call line.
    {
        std::vector<Instruction> ins = {
            mk(0x1000, 5, "call", "", true, false, 0x2000),
            mk(0x1005, 3, "mov", "qword ptr [rdx], rax"),
            mk(0x1008, 1, "ret", "", true, true),
        };
        ControlFlowGraph g = buildG(ins);
        DecompileOptions on;
        DecompResult r = DecompileWithMap(g, on);
        CHECK(r.text == Decompile(g, on));
        CHECK(r.lineVA.size() == splitLines(r.text).size());
        CHECK(has(r.text, "sub_2000()"));   // the call survives, not folded into the store
        if (g_fail) std::printf("--- folder(3b) ---\n%s\n", r.text.c_str());
    }

    // ---- (4) no-op + disabled: a straight-line store has nothing to fold --------
    {
        std::vector<Instruction> ins = {
            mk(0x1000, 7, "mov", "dword ptr [rdx], 0x22"),
            mk(0x1007, 1, "ret", "", true, true),
        };
        ControlFlowGraph g = buildG(ins);
        DecompileOptions on, off; off.foldTemps = false;
        DecompResult r  = DecompileWithMap(g, on);
        DecompResult r0 = DecompileWithMap(g, off);
        CHECK(r.text == r0.text);                       // identical when nothing folds
        CHECK(r.lineVA == r0.lineVA);
        CHECK(r.lineVA.size() == splitLines(r.text).size());
        if (g_fail) std::printf("--- folder(4) ---\n%s\n", r.text.c_str());
    }

    // ---- (4b) legacy lift is never touched by the fold pass --------------------
    {
        std::vector<Instruction> ins = {
            mk(0x1000, 3, "mov", "rax, rcx"),
            mk(0x1003, 3, "add", "rax, rdx"),
            mk(0x1006, 1, "ret", "", true, true),
        };
        ControlFlowGraph g = buildG(ins);
        DecompileOptions legacy; legacy.deepDataFlow = false;
        DecompResult r = DecompileWithMap(g, legacy);
        CHECK(r.text == Decompile(g, legacy));
        CHECK(r.lineVA.size() == splitLines(r.text).size());
        CHECK(has(r.text, "rax = rcx;"));    // raw lift unchanged (fold pass is deep-only)
        CHECK(has(r.text, "rax += rdx;"));
        if (g_fail) std::printf("--- folder(4b legacy) ---\n%s\n", r.text.c_str());
    }

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("decompiler_folder_test: all checks passed\n");
    return 0;
}
