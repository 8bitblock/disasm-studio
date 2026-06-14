//
// funcannotate_test.cpp
// Unit test for the per-function annotation engine (src/Core/FuncAnnotate.cpp).
// A MockDisassembler replays canned x86/x64 instruction streams; we BuildCFG +
// AnnotateFunction and assert the inferred convention/frame/branch/loop/call
// annotations (and that everything carries confidence + evidence).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\funcannotate_test.cpp ^
//      src\Core\FuncAnnotate.cpp src\Core\CFG.cpp
//   .\funcannotate_test.exe
//
#include "Core/CFG.h"
#include "Core/FuncAnnotate.h"
#include "Core/ApiInfo.h"
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

static FuncAnnotations annotate(const std::vector<Instruction>& ins, AnnotateOptions opt = {}) {
    MockDisassembler dis;
    uint64_t base = ins.front().address;
    uint64_t end  = ins.back().address + ins.back().length;
    for (auto& in : ins) dis.at[in.address] = in;
    std::vector<uint8_t> buf((size_t)(end - base) + 16, 0);
    ControlFlowGraph g = BuildCFG(buf.data(), buf.size(), base, dis, 2000);
    return AnnotateFunction(g, opt);
}

static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

// First note of a kind whose text contains `sub` ("" = any text).
static const FnNote* findNote(const FuncAnnotations& a, NoteKind k, const char* sub = "") {
    for (const FnNote& n : a.notes)
        if (n.kind == k && (!*sub || has(n.text, sub))) return &n;
    return nullptr;
}

int main() {
    // 1) Prologue / frame pointer / frame size + epilogue, and the honesty contract
    //    (every note has evidence and an in-range confidence).
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 1, "push", "rbp"),
            mk(0x1001, 3, "mov",  "rbp, rsp"),
            mk(0x1004, 4, "sub",  "rsp, 0x40"),
            mk(0x1008, 4, "mov",  "qword ptr [rbp - 8], rcx"),
            mk(0x100C, 4, "mov",  "rax, qword ptr [rbp - 8]"),
            mk(0x1010, 1, "leave", ""),
            mk(0x1011, 1, "ret",  "", true, true),
        });
        CHECK(a.hasFramePointer);
        CHECK(a.frameBytes == 0x40);
        CHECK(findNote(a, NoteKind::Prologue, "frame pointer") != nullptr);
        CHECK(findNote(a, NoteKind::Prologue, "0x40") != nullptr);
        CHECK(findNote(a, NoteKind::Epilogue) != nullptr);
        // var_8: one write (store of rcx), one read (reload).
        bool foundLocal = false;
        for (const StackSlot& s : a.stack)
            if (!s.isArg && s.offset == -8) { foundLocal = true; CHECK(s.writes == 1); CHECK(s.reads == 1); CHECK(has(s.name, "var_8")); }
        CHECK(foundLocal);
        // rcx read before write -> Microsoft x64 arg evidence.
        CHECK(has(a.convention, "Microsoft x64"));
        CHECK(a.convConfidence > 0.4f && a.convConfidence < 1.0f);
        CHECK(!a.convEvidence.empty());
        CHECK(!a.args.empty() && has(a.args[0], "rcx"));
        for (const FnNote& n : a.notes) {
            CHECK(!n.evidence.empty());
            CHECK(n.confidence > 0.0f && n.confidence <= 1.0f);
        }
        CHECK(!a.summary.empty());
    }

    // 2) x86-32 stdcall via `ret imm` + stack args.
    {
        AnnotateOptions o; o.x64 = false;
        FuncAnnotations a = annotate({
            mk(0x1000, 1, "push", "ebp"),
            mk(0x1001, 2, "mov",  "ebp, esp"),
            mk(0x1003, 3, "mov",  "eax, dword ptr [ebp + 8]"),
            mk(0x1006, 3, "add",  "eax, dword ptr [ebp + 0xC]"),
            mk(0x1009, 1, "pop",  "ebp"),
            mk(0x100A, 3, "ret",  "0x8", true, true),
        }, o);
        CHECK(has(a.convention, "stdcall"));
        CHECK(has(a.convention, "0x8"));
        CHECK(a.convConfidence >= 0.8f);
        CHECK(has(a.convEvidence, "ret 0x8"));
        int args = 0;
        for (const StackSlot& s : a.stack) if (s.isArg) ++args;
        CHECK(args == 2);   // [ebp+8] and [ebp+0xC]
    }

    // 3) Branch meaning in plain language (cmp + jl, signed).
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "cmp", "eax, 0x10"),
            mk(0x1003, 2, "jl",  "0x100A", true, false, 0x100A),
            mk(0x1005, 5, "mov", "eax, 1"),
            mk(0x100A, 1, "ret", "", true, true),
        });
        const FnNote* n = findNote(a, NoteKind::Branch);
        CHECK(n != nullptr);
        if (n) {
            CHECK(has(n->text, "jumps to 0x100A"));
            CHECK(has(n->text, "eax < 0x10"));
            CHECK(has(n->text, "signed"));
            CHECK(has(n->evidence, "cmp eax, 0x10"));
        }
    }

    // 4) strcmp-style call: result checked, and the branch explained in
    //    success/failure language ("Jumps ... if strcmp result is non-zero").
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) { return va == 0x2000 ? std::string("msvcrt.strcmp") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 2, "test", "eax, eax"),
            mk(0x1007, 2, "jne",  "0x1010", true, false, 0x1010),
            mk(0x1009, 5, "mov",  "eax, 1"),
            mk(0x100E, 1, "ret",  "", true, true),
            mk(0x1010, 1, "ret",  "", true, true),
        }, o);
        const FnNote* ru = findNote(a, NoteKind::RetUse);
        CHECK(ru != nullptr);
        if (ru) CHECK(has(ru->text, "checked"));
        const FnNote* br = findNote(a, NoteKind::Branch);
        CHECK(br != nullptr);
        if (br) {
            CHECK(has(br->text, "strcmp"));
            CHECK(has(br->text, "non-zero"));
            CHECK(has(br->text, "differ"));
        }
        // Function-level pattern: performs string comparison.
        const FnNote* p = findNote(a, NoteKind::Pattern, "comparison");
        CHECK(p != nullptr);
        if (p) CHECK(p->va == 0);
    }

    // 5) Return value ignored (overwritten before any read).
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) { return va == 0x2000 ? std::string("foo") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 5, "mov",  "eax, 7"),
            mk(0x100A, 1, "ret",  "", true, true),
        }, o);
        const FnNote* ru = findNote(a, NoteKind::RetUse);
        CHECK(ru != nullptr);
        if (ru) CHECK(has(ru->text, "not used"));
    }

    // 6) Loop detection + loop-phrased condition + XOR-decode pattern.
    //    for (rcx = 0; rcx < 0x10; ++rcx) buf[rcx] ^= 0x5A;
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 2, "xor", "ecx, ecx"),
            mk(0x1002, 4, "cmp", "rcx, 0x10"),
            mk(0x1006, 2, "jge", "0x1011", true, false, 0x1011),
            mk(0x1008, 4, "xor", "byte ptr [rax + rcx], 0x5A"),
            mk(0x100C, 3, "inc", "rcx"),
            mk(0x100F, 2, "jmp", "0x1002", true, false, 0x1002),
            mk(0x1011, 1, "ret", "", true, true),
        });
        CHECK(findNote(a, NoteKind::Loop, "loop start") != nullptr);
        const FnNote* p = findNote(a, NoteKind::Pattern, "XOR");
        CHECK(p != nullptr);
        if (p) {
            CHECK(p->confidence < 0.9f);          // a guess, not a fact
            CHECK(has(p->evidence, "0x1008"));    // evidence names the xor instruction
        }
        CHECK(has(a.summary, "loop"));
    }

    // 7) Loop condition phrased as "continues while" when the latch is conditional.
    //    do { --rax } while (rax != 0)
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "dec", "rax"),
            mk(0x1003, 4, "test", "rax, rax"),
            mk(0x1007, 2, "jne", "0x1000", true, false, 0x1000),
            mk(0x1009, 1, "ret", "", true, true),
        });
        const FnNote* n = findNote(a, NoteKind::Loop, "continues while");
        CHECK(n != nullptr);
        if (n) CHECK(has(n->text, "rax != 0"));
    }

    // 8) Indirect + virtual call patterns.
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "mov",  "rax, qword ptr [rcx]"),
            mk(0x1003, 3, "call", "qword ptr [rax + 0x10]", true, false, 0),
            mk(0x1006, 2, "call", "rdx", true, false, 0),
            mk(0x1008, 1, "ret",  "", true, true),
        });
        const FnNote* v = findNote(a, NoteKind::VirtualCall);
        CHECK(v != nullptr);
        if (v) {
            CHECK(has(v->text, "slot +0x10"));
            CHECK(has(v->text, "this"));          // object pointer is rcx
            CHECK(v->confidence < 0.8f);          // heuristic, not fact
        }
        CHECK(findNote(a, NoteKind::IndirectCall) != nullptr);   // call rdx
    }

    // 9) Call-argument sniffing with a string literal (x64).
    {
        AnnotateOptions o;
        o.nameFor   = [](uint64_t va) { return va == 0x2000 ? std::string("kernel32.lstrcmpA") : std::string(); };
        o.stringFor = [](uint64_t va) { return va == 0x5000 ? std::string("password") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 7, "mov",  "rcx, 0x5000"),
            mk(0x1007, 3, "mov",  "rdx, rbx"),
            mk(0x100A, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x100F, 1, "ret",  "", true, true),
        }, o);
        const FnNote* c = findNote(a, NoteKind::Call);
        CHECK(c != nullptr);
        if (c) {
            CHECK(has(c->text, "rcx=\"password\""));
            CHECK(has(c->evidence, "lstrcmpA"));
        }
    }

    // 10) x86 push-argument sniffing.
    {
        AnnotateOptions o; o.x64 = false;
        o.nameFor   = [](uint64_t va) { return va == 0x2000 ? std::string("msvcrt.printf") : std::string(); };
        o.stringFor = [](uint64_t va) { return va == 0x5000 ? std::string("hello %s") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "push", "0x5000"),
            mk(0x1005, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x100A, 3, "add",  "esp, 4"),
            mk(0x100D, 1, "ret",  "", true, true),
        }, o);
        const FnNote* c = findNote(a, NoteKind::Call);
        CHECK(c != nullptr);
        if (c) CHECK(has(c->text, "arg1=\"hello %s\""));
    }

    // 11) Vtable pointer store (lea code-pointer + store to [obj+0]).
    {
        AnnotateOptions o;
        o.looksLikeVtable = [](uint64_t va) { return va == 0x3000; };
        FuncAnnotations a = annotate({
            mk(0x1000, 7, "lea", "rax, [rip + 0x1FF9]"),    // -> 0x1000+7+0x1FF9 = 0x3000
            mk(0x1007, 3, "mov", "qword ptr [rcx], rax"),
            mk(0x100A, 1, "ret", "", true, true),
        }, o);
        const FnNote* v = findNote(a, NoteKind::Vtable);
        CHECK(v != nullptr);
        if (v) {
            CHECK(has(v->text, "0x3000"));
            CHECK(has(v->text, "construction"));
        }
    }

    // 12) Switch dispatch (hand-built CFG, since the mock has no jump-table memory).
    {
        ControlFlowGraph g; g.funcStart = 0x1000;
        BasicBlock b; b.start = 0x1000; b.end = 0x1007;
        b.insns = { mk(0x1000, 7, "jmp", "qword ptr [rax*8 + 0x4000]", true, false, 0) };
        b.isSwitch = true; b.caseTargets = { 0x1100, 0x1200, 0x1300 };
        g.blocks.push_back(b);
        FuncAnnotations a = AnnotateFunction(g, {});
        const FnNote* n = findNote(a, NoteKind::Switch);
        CHECK(n != nullptr);
        if (n) CHECK(has(n->text, "3 case(s)"));
    }

    // 13) Register lifetimes: rbx written then read later.
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "mov", "rbx, 0x1234"),
            mk(0x1005, 3, "mov", "rax, rbx"),
            mk(0x1008, 1, "ret", "", true, true),
        });
        bool foundRbx = false;
        for (const RegLifetime& r : a.regs)
            if (r.reg == "rbx") { foundRbx = true; CHECK(r.firstVA == 0x1000); CHECK(r.lastVA == 0x1005); CHECK(r.writes == 1); CHECK(r.reads == 1); }
        CHECK(foundRbx);
    }

    // 14) Function-level API patterns: input reading + timers.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) -> std::string {
            if (va == 0x2000) return "kernel32.ReadConsoleA";
            if (va == 0x2100) return "kernel32.GetTickCount";
            return {};
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 5, "call", "0x2100", true, false, 0x2100),
            mk(0x100A, 1, "ret",  "", true, true),
        }, o);
        CHECK(findNote(a, NoteKind::Pattern, "user input") != nullptr);
        CHECK(findNote(a, NoteKind::Pattern, "timer") != nullptr);
    }

    // 15) ApiPurpose (moved to Core/ApiInfo.h) sanity.
    CHECK(has(ApiPurpose("kernel32.CreateFileW"), "file"));
    CHECK(has(ApiPurpose("msvcrt.strcmp"), "compare"));
    CHECK(ApiPurpose("totally_unknown_api").empty());

    // 16) NoteKindName covers every kind with a non-"?" label.
    for (int k = 0; k <= (int)NoteKind::Pattern; ++k)
        CHECK(std::string(NoteKindName((NoteKind)k)) != "?");

    if (g_fail == 0) std::printf("funcannotate_test: ALL PASS\n");
    else             std::printf("funcannotate_test: %d FAIL\n", g_fail);
    return g_fail ? 1 : 0;
}
