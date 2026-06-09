//
// decompiler_switch_test.cpp
// Off-target unit test for jump-table -> switch/case recovery added to
// src/Core/CFG.cpp (BuildCFG jump-table resolver) and src/Core/Decompiler.cpp
// (Term::Switch emission).
//
// The disassembler engines can't run here, so a tiny MockDisassembler replays a
// hand-built instruction stream that models a classic switch dispatch:
//
//     cmp eax, 2
//     jbe default                 ; bounds check
//     jmp [rax*8 + 0x4000]        ; indirect dispatch (jump table)
//   case0: jmp join
//   case1: jmp join
//   case2: jmp join
//   default: mov eax, 99 ; jmp join
//   join:  ret
//
// It asserts (1) BuildCFG marks the dispatch block as a switch with the resolved
// case targets + successors, and (2) Decompile emits a real `switch (rax) {
// case 0: ... }` instead of a bare `goto`.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\decompiler_switch_test.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp
//   .\decompiler_switch_test.exe
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

// Replays a canned instruction stream keyed by virtual address. BuildCFG only
// needs decodeOne; the byte buffer it is handed is ignored (we look up by VA).
struct MockDisassembler : IDisassembler {
    std::unordered_map<uint64_t, Instruction> at;
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "mock"; }
    bool decodeOne(const uint8_t*, size_t, uint64_t va, Instruction& out) override {
        auto it = at.find(va);
        if (it == at.end()) return false;
        out = it->second;
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* d, size_t n, uint64_t va, size_t maxI) override {
        std::vector<Instruction> v; uint64_t a = va;
        while ((!maxI || v.size() < maxI)) {
            Instruction in; if (!decodeOne(d, n, a, in) || !in.length) break;
            v.push_back(in); a += in.length;
        }
        return v;
    }
};

static Instruction mk(uint64_t addr, uint32_t len, const char* mnem, const char* ops,
                      bool branch, bool uncond, bool ret, uint64_t target) {
    Instruction in;
    in.address = addr; in.length = len; in.mnemonic = mnem; in.operands = ops;
    in.isBranch = branch; in.isRet = ret; in.branchTarget = target;
    // isUncond is derived in CFG from the mnemonic ("jmp"); nothing to set here.
    (void)uncond;
    return in;
}

int main() {
    const uint64_t base = 0x1000;
    const uint64_t kDefault = 0x1012;   // mov eax,99
    const uint64_t kJoin    = 0x1019;   // ret
    const uint64_t kCase0 = 0x100C, kCase1 = 0x100E, kCase2 = 0x1010;

    MockDisassembler dis;
    auto add = [&](const Instruction& in) { dis.at[in.address] = in; };
    add(mk(0x1000, 3, "cmp", "eax, 2",                       false, false, false, 0));
    add(mk(0x1003, 2, "jbe", "0x1012",                       true,  false, false, kDefault));
    add(mk(0x1005, 7, "jmp", "qword ptr [rax*8 + 0x4000]",   true,  true,  false, 0)); // switch dispatch
    add(mk(0x100C, 2, "jmp", "0x1019",                       true,  true,  false, kJoin)); // case 0
    add(mk(0x100E, 2, "jmp", "0x1019",                       true,  true,  false, kJoin)); // case 1
    add(mk(0x1010, 2, "jmp", "0x1019",                       true,  true,  false, kJoin)); // case 2
    add(mk(0x1012, 5, "mov", "eax, 99",                      false, false, false, 0));      // default body
    add(mk(0x1017, 2, "jmp", "0x1019",                       true,  true,  false, kJoin));
    add(mk(0x1019, 1, "ret", "",                             true,  false, true,  0));      // join

    // The dispatch instruction's table resolves to the three case bodies.
    JumpTableResolver resolver = [&](const Instruction& in) -> std::vector<uint64_t> {
        if (in.address == 0x1005) return { kCase0, kCase1, kCase2 };
        return {};
    };

    std::vector<uint8_t> dummy(0x40, 0); // BuildCFG decodes [base, base+size); size must span the stream
    ControlFlowGraph g = BuildCFG(dummy.data(), dummy.size(), base, dis, 2000, resolver);

    // 1) The dispatch block is recognized as a switch with the right case targets.
    const BasicBlock* sw = nullptr;
    for (const auto& b : g.blocks) if (b.start == 0x1005) sw = &b;
    CHECK(sw != nullptr);
    if (sw) {
        CHECK(sw->isSwitch);
        CHECK(sw->caseTargets.size() == 3);
        CHECK(sw->caseTargets.size() == 3 && sw->caseTargets[0] == kCase0
              && sw->caseTargets[1] == kCase1 && sw->caseTargets[2] == kCase2);
        CHECK(sw->succ.size() == 3);   // one successor per case
    }

    // Sanity: without a resolver, the same dispatch stays a plain (target-less) jmp.
    ControlFlowGraph g0 = BuildCFG(dummy.data(), dummy.size(), base, dis, 2000);
    for (const auto& b : g0.blocks) if (b.start == 0x1005) CHECK(!b.isSwitch);

    // 2) The decompiler emits switch/case with the recovered selector.
    std::string out = Decompile(g);
    auto has = [&](const char* s) { return out.find(s) != std::string::npos; };
    CHECK(has("switch ("));
    CHECK(has("switch (rax)"));   // selector recovered from [rax*8 + ...]
    CHECK(has("case 0:"));
    CHECK(has("case 1:"));
    CHECK(has("case 2:"));
    CHECK(has("break;"));
    CHECK(!has("goto loc_0;"));   // the old behavior for an unresolved indirect jmp

    // 3) Regression: a switch whose cases do NOT reconverge (every case returns, so the
    //    dispatch block has no immediate post-dominator, ipdom == -1). Previously the
    //    case-body emission used the wrong stop bound and let case 0 overrun, swallowing
    //    the sibling cases' bodies. Each `return N` must now appear exactly once, each in
    //    its own case.
    {
        const uint64_t b2 = 0x2000;
        const uint64_t d0 = 0x2005, d1 = 0x200B, d2 = 0x2011;   // case bodies: mov eax,N ; ret
        MockDisassembler dis2;
        auto add2 = [&](const Instruction& in) { dis2.at[in.address] = in; };
        add2(mk(0x2000, 5, "jmp", "qword ptr [rax*8 + 0x9000]", true, true, false, 0)); // dispatch
        add2(mk(d0, 5, "mov", "eax, 0x11", false, false, false, 0)); add2(mk(d0 + 5, 1, "ret", "", true, false, true, 0));
        add2(mk(d1, 5, "mov", "eax, 0x22", false, false, false, 0)); add2(mk(d1 + 5, 1, "ret", "", true, false, true, 0));
        add2(mk(d2, 5, "mov", "eax, 0x33", false, false, false, 0)); add2(mk(d2 + 5, 1, "ret", "", true, false, true, 0));
        JumpTableResolver r2 = [&](const Instruction& in) -> std::vector<uint64_t> {
            if (in.address == b2) return { d0, d1, d2 };
            return {};
        };
        std::vector<uint8_t> dummy2(0x20, 0);
        ControlFlowGraph g2 = BuildCFG(dummy2.data(), dummy2.size(), b2, dis2, 2000, r2);
        std::string o2 = Decompile(g2);
        auto count = [&](const char* s) { int n = 0; size_t p = 0, L = std::string(s).size();
            while ((p = o2.find(s, p)) != std::string::npos) { ++n; p += L; } return n; };
        CHECK(count("0x11") == 1);   // case 0 body once
        CHECK(count("0x22") == 1);   // case 1 body once (not swallowed by case 0)
        CHECK(count("0x33") == 1);   // case 2 body once
        if (g_fail) std::printf("--- no-join switch ---\n%s\n", o2.c_str());
    }

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n--- decompiler output ---\n%s\n", g_fail, out.c_str()); return 1; }
    std::printf("decompiler_switch_test: all checks passed\n");
    return 0;
}
