//
// decompiler_linemap_test.cpp
// Tests for DecompileWithMap (src/Core/Decompiler.cpp): the per-line source-VA
// map backing pseudocode -> assembly navigation. Asserts that
//   (1) DecompileWithMap(...).text is byte-identical to Decompile(...) (the
//       string path is a pure forward), in both legacy and deep data-flow modes;
//   (2) lineVA has exactly one entry per '\n'-line of text (incl. after the
//       deep-mode for-loop reconstruction erases the hoisted step line);
//   (3) legacy mode tags statement lines with their INSTRUCTION address and
//       return lines with the ret's address;
//   (4) deep mode preserves exact instruction origins through propagation/DCE;
//   (5) the synthetic function header / braces carry VA 0.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\decompiler_linemap_test.cpp ^
//      src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
//   .\decompiler_linemap_test.exe
//
#include "Core/CFG.h"
#include "Core/Decompiler.h"
#include "Disasm/IDisassembler.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <utility>
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

struct Asm {
    uint64_t base; uint64_t cur; std::vector<Instruction> ins;
    explicit Asm(uint64_t b = 0x1000) : base(b), cur(b) {}
    uint64_t op(uint32_t len, const char* m, const char* o = "") {
        uint64_t a = cur; ins.push_back(mk(a, len, m, o)); cur += len; return a;
    }
    uint64_t br(uint32_t len, const char* m, uint64_t target, const char* o = "") {
        uint64_t a = cur; ins.push_back(mk(a, len, m, o, true, false, target)); cur += len; return a;
    }
    uint64_t ret(uint32_t len = 1) {
        uint64_t a = cur; ins.push_back(mk(a, len, "ret", "", true, true, 0)); cur += len; return a;
    }
};

static ControlFlowGraph buildG(const std::vector<Instruction>& ins) {
    static MockDisassembler dis;   // reused per call; reset the map
    dis.at.clear();
    uint64_t base = ~0ull, end = 0;
    for (auto& in : ins) { if (in.address < base) base = in.address;
                           if (in.address + in.length > end) end = in.address + in.length; }
    for (auto& in : ins) dis.at[in.address] = in;
    std::vector<uint8_t> buf((size_t)(end - base) + 16, 0);
    return BuildCFG(buf.data(), buf.size(), base, dis, 2000);
}

// Split on '\n', dropping the empty segment after a trailing '\n' (the
// DecompResult::lineVA convention).
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

// Find the index of the first line containing `sub`, or -1.
static int lineWith(const std::vector<std::string>& L, const char* sub) {
    for (size_t i = 0; i < L.size(); ++i) if (L[i].find(sub) != std::string::npos) return (int)i;
    return -1;
}

int main() {
    // ---- straight-line function: mov / store / ret -------------------------
    //   0x1000 mov eax, 0x11        (3)
    //   0x1003 mov [rdx], 0x22      (7)   <- store survives deep DCE
    //   0x100A ret                  (1)
    {
        Asm a;
        uint64_t movA  = a.op(3, "mov", "eax, 0x11");
        uint64_t movB  = a.op(7, "mov", "dword ptr [rdx], 0x22");
        uint64_t retA  = a.ret();
        ControlFlowGraph g = buildG(a.ins);

        for (bool deep : { false, true }) {
            DecompileOptions opt; opt.deepDataFlow = deep;
            DecompResult r = DecompileWithMap(g, opt);
            // (1) the string entry point is a pure forward
            CHECK(r.text == Decompile(g, opt));
            // (2) one VA per line
            std::vector<std::string> L = splitLines(r.text);
            CHECK(!L.empty());
            CHECK(r.lineVA.size() == L.size());
            CHECK(r.lineOrigins.size() == L.size());
            // (5) header + opening brace are synthetic
            CHECK(r.lineVA[0] == 0);                       // "__int64 sub_1000(...)"
            CHECK(lineWith(L, "{") >= 0);
            CHECK(r.lineVA[(size_t)lineWith(L, "{")] == 0);
            // statement / return lines are tagged
            int sLine = lineWith(L, "0x22");
            int rLine = lineWith(L, "return");
            CHECK(sLine >= 0 && rLine >= 0);
            if (deep) {
                // Deep propagation/DCE must retain the exact instruction which
                // emitted each surviving statement, not merely its block start.
                if (sLine >= 0) {
                    CHECK(r.lineVA[(size_t)sLine] == movB);
                    CHECK(r.lineOrigins[(size_t)sLine].granularity ==
                          SourceOriginGranularity::Instruction);
                }
            } else {
                // (3) legacy: exact instruction addresses
                if (sLine >= 0) CHECK(r.lineVA[(size_t)sLine] == movB);
                int s0 = lineWith(L, "0x11");
                CHECK(s0 >= 0);
                if (s0 >= 0) CHECK(r.lineVA[(size_t)s0] == movA);
            }
            if (rLine >= 0) CHECK(r.lineVA[(size_t)rLine] == retA);
        }
    }

    // ---- if/else: branch lines carry the Jcc address ------------------------
    //   cmp ecx,0 / je else ; then: mov [rdx],0x11 ; ret ; else: mov [rdx],0x22 ; ret
    {
        Asm a;
        a.op(2, "cmp", "ecx, 0");
        uint64_t jeAddr = a.cur; a.cur += 2;       // reserve the je slot
        uint64_t thenStore = a.op(7, "mov", "dword ptr [rdx], 0x11"); a.ret();
        uint64_t elseB = a.cur;
        uint64_t elseStore = a.op(7, "mov", "dword ptr [rdx], 0x22"); a.ret();
        a.ins.push_back(mk(jeAddr, 2, "je", "", true, false, elseB));
        ControlFlowGraph g = buildG(a.ins);

        for (bool deep : { false, true }) {
            DecompileOptions opt; opt.deepDataFlow = deep;
            DecompResult r = DecompileWithMap(g, opt);
            CHECK(r.text == Decompile(g, opt));
            std::vector<std::string> L = splitLines(r.text);
            CHECK(r.lineVA.size() == L.size());
            int ifLine = lineWith(L, "if (");
            CHECK(ifLine >= 0);
            // The if's terminator is the je (last insn of the entry block).
            if (ifLine >= 0) CHECK(r.lineVA[(size_t)ifLine] == jeAddr);
            // Both arms' stores retain their exact instruction origins in both
            // lifters, including after deep propagation and structuring.
            const std::pair<const char*, uint64_t> stores[] = {
                { "0x11", thenStore }, { "0x22", elseStore }
            };
            for (const auto& [k, expectedVA] : stores) {
                int s = lineWith(L, k);
                CHECK(s >= 0);
                if (s >= 0) {
                    CHECK(r.lineVA[(size_t)s] == expectedVA);
                    CHECK(r.lineOrigins[(size_t)s].granularity ==
                          SourceOriginGranularity::Instruction);
                }
            }
        }
    }

    // ---- counted loop (deep): for-reconstruction keeps the vectors parallel --
    //   xor ecx,ecx ; loop: mov [rdx],ecx ; inc ecx ; cmp ecx,10 ; jl loop ; ret
    {
        Asm a;
        a.op(2, "xor", "ecx, ecx");
        uint64_t loop = a.cur;
        a.op(7, "mov", "dword ptr [rdx], ecx");
        a.op(2, "inc", "ecx");
        a.op(3, "cmp", "ecx, 10");
        a.br(2, "jl", loop);
        a.ret();
        ControlFlowGraph g = buildG(a.ins);

        DecompileOptions opt; opt.deepDataFlow = true;
        DecompResult r = DecompileWithMap(g, opt);
        CHECK(r.text == Decompile(g, opt));
        std::vector<std::string> L = splitLines(r.text);
        CHECK(r.lineVA.size() == L.size());     // (2) survives reconstructForLoops' erase
        // Also re-check in legacy mode (no reconstruction path).
        DecompileOptions lopt; lopt.deepDataFlow = false;
        DecompResult lr = DecompileWithMap(g, lopt);
        CHECK(lr.text == Decompile(g, lopt));
        CHECK(lr.lineVA.size() == splitLines(lr.text).size());
    }

    // ---- degenerate inputs ---------------------------------------------------
    {
        ControlFlowGraph empty;
        DecompResult r = DecompileWithMap(empty, {});
        CHECK(r.text == "// no code\n");
        CHECK(r.lineVA.size() == 1 && r.lineVA[0] == 0);
        CHECK(Decompile(empty, {}) == r.text);
    }

    // VA zero is a real source location, not the synthetic-line sentinel. The
    // validity-bearing origin survives both C emission and the Python transform.
    {
        MockDisassembler dis;
        dis.at[0] = mk(0, 1, "mov", "rax, 1");
        dis.at[1] = mk(1, 1, "ret", "", true, true, 0);
        std::vector<uint8_t> bytes(2);
        ControlFlowGraph g = BuildCFG(bytes.data(), bytes.size(), 0, dis, 20);
        DecompileOptions opt; opt.deepDataFlow = false;
        opt.target = { Arch::X64, DecompileABI::Auto };
        DecompResult r = DecompileWithMap(g, opt);
        std::vector<std::string> lines = splitLines(r.text);
        CHECK(r.lineOrigins.size() == lines.size());
        int movLine = lineWith(lines, "rax = 1");
        CHECK(movLine >= 0);
        if (movLine >= 0) {
            CHECK(r.lineVA[(size_t)movLine] == 0);
            CHECK(r.lineOrigins[(size_t)movLine].valid);
            CHECK(r.lineOrigins[(size_t)movLine].va == 0);
            CHECK(r.lineOrigins[(size_t)movLine].granularity == SourceOriginGranularity::Instruction);
        }
        CHECK(!r.lineOrigins.empty() && !r.lineOrigins[0].valid &&
              r.lineOrigins[0].granularity == SourceOriginGranularity::Synthetic); // header is synthetic
        DecompResult py = DecompileToPython(r);
        CHECK(py.lineOrigins.size() == splitLines(py.text).size());
        bool sawRealZero = false;
        for (const SourceOrigin& origin : py.lineOrigins)
            sawRealZero |= origin.valid && origin.va == 0 &&
                           origin.granularity == SourceOriginGranularity::Instruction;
        CHECK(sawRealZero);
    }

    // Instruction/decode budgets publish incompleteness instead of silently
    // making the partial graph look authoritative.
    {
        MockDisassembler dis;
        dis.at[0x4000] = mk(0x4000, 1, "nop", "");
        dis.at[0x4001] = mk(0x4001, 1, "ret", "", true, true, 0);
        std::vector<uint8_t> bytes(2);
        ControlFlowGraph g = BuildCFG(bytes.data(), bytes.size(), 0x4000, dis, 1);
        CHECK(!g.complete);
        CHECK(!g.incompleteReason.empty());
        CHECK(g.decodedInstructions == 1 && g.decodedBytes == 1);
        DecompResult r = DecompileWithMap(g);
        CHECK(!r.complete && r.incompleteReason == g.incompleteReason);
        CHECK(!r.diagnostics.empty() &&
              r.diagnostics[0].kind == DecompileDiagnosticKind::InstructionLimit);

        MockDisassembler stopped;
        stopped.at[0x4100] = mk(0x4100, 1, "nop", "");
        ControlFlowGraph partial = BuildCFG(bytes.data(), bytes.size(), 0x4100, stopped, 20);
        DecompResult decodeFailure = DecompileWithMap(partial);
        CHECK(!decodeFailure.diagnostics.empty() &&
              decodeFailure.diagnostics[0].kind == DecompileDiagnosticKind::DecodeFailure);
    }

    // Noncontiguous chunks link only through explicit targets. Even physically
    // adjacent chunks do not gain an invented fallthrough edge.
    {
        MockDisassembler dis;
        dis.at[0x5000] = mk(0x5000, 1, "jmp", "0x7000", true, false, 0x7000);
        dis.at[0x7000] = mk(0x7000, 1, "mov", "eax, 7");
        dis.at[0x7001] = mk(0x7001, 1, "ret", "", true, true, 0);
        uint8_t a[1] = {}, b[2] = {};
        std::vector<CFGCodeChunk> chunks = { { a, sizeof(a), 0x5000 }, { b, sizeof(b), 0x7000 } };
        ControlFlowGraph g = BuildCFG(chunks, dis, 20);
        CHECK(g.complete);
        CHECK(g.blocks.size() >= 2 && g.blocks[0].succ.size() == 1);
        DecompileOptions opt; opt.target = { Arch::X64, DecompileABI::Auto };
        DecompResult r = DecompileWithMap(chunks, dis, opt, 20);
        CHECK(r.text.find("7") != std::string::npos);

        MockDisassembler adjacent;
        adjacent.at[0x8000] = mk(0x8000, 1, "nop", "");
        adjacent.at[0x8001] = mk(0x8001, 1, "ret", "", true, true, 0);
        uint8_t c[1] = {}, d[1] = {};
        ControlFlowGraph noFall = BuildCFG(std::vector<CFGCodeChunk>{
            { c, sizeof(c), 0x8000 }, { d, sizeof(d), 0x8001 } }, adjacent, 20);
        const BasicBlock* first = nullptr;
        for (const BasicBlock& block : noFall.blocks) if (block.start == 0x8000) first = &block;
        CHECK(first && first->succ.empty());

        // The first supplied chunk is the logical entry even when a cold chunk
        // has a numerically lower address.
        MockDisassembler reordered;
        reordered.at[0x7000] = mk(0x7000, 1, "ret", "", true, true, 0);
        reordered.at[0x1000] = mk(0x1000, 1, "ret", "", true, true, 0);
        ControlFlowGraph entryFirst = BuildCFG(std::vector<CFGCodeChunk>{
            { d, sizeof(d), 0x7000 }, { c, sizeof(c), 0x1000 } }, reordered, 20);
        CHECK(!entryFirst.blocks.empty() && entryFirst.blocks[0].start == 0x7000);

        adjacent.at[0x8000] = mk(0x8000, 1, "jmp", "0x9000", true, false, 0x9000);
        ControlFlowGraph missing = BuildCFG(std::vector<CFGCodeChunk>{ { c, sizeof(c), 0x8000 } }, adjacent, 20);
        CHECK(!missing.complete && !missing.incompleteReason.empty());
        DecompResult missingResult = DecompileWithMap(missing);
        CHECK(!missingResult.diagnostics.empty() &&
              missingResult.diagnostics[0].kind == DecompileDiagnosticKind::MissingChunk);
    }

    // Unsupported execution prefixes retain complete operations and exact
    // instruction origins in both lifters. Raw consumers keep their input
    // setup live, including a definition at VA zero, through DCE.
    {
        Instruction setup = mk(0, 3, "mov", "rcx, 7");
        Instruction locked = mk(3, 4, "add", "dword ptr [rcx], 1");
        locked.prefixes = { InstructionPrefix::Lock };
        TypedOperand memory; memory.kind = OperandKind::Memory;
        memory.access = OperandAccess::ReadWrite; memory.baseRegister = "rcx"; memory.widthBits = 32;
        TypedOperand immediate; immediate.kind = OperandKind::Immediate;
        immediate.access = OperandAccess::Read; immediate.widthBits = 8; immediate.immediate = 1;
        locked.typedOperands = { memory, immediate };
        Instruction repeated = mk(7, 2, "movsb", "");
        repeated.prefixes = { InstructionPrefix::Rep };
        repeated.registersRead = { "rcx", "rsi", "rdi" };
        repeated.registersWritten = repeated.registersRead;
        const auto graph = buildG({setup, locked, repeated, mk(9, 2, "xor", "eax, eax"), mk(11, 1, "ret", "", true, true)});
        for (bool deep : {false, true}) {
            DecompileOptions options; options.deepDataFlow = deep;
            options.target = {Arch::X64, DecompileABI::Win64};
            const auto result = DecompileWithMap(graph, options);
            const auto lines = splitLines(result.text);
            CHECK(result.text == Decompile(graph, options));
            CHECK(result.lineOrigins.size() == lines.size());
            for (const auto& expected : std::vector<std::pair<std::string, uint64_t>>{
                     {" = 7;", 0}, {"__asm { lock add dword ptr [rcx], 1 };", 3}, {"__asm { rep movsb };", 7}}) {
                const int line = lineWith(lines, expected.first.c_str());
                CHECK(line >= 0);
                if (line >= 0) {
                    CHECK(result.lineOrigins[line].valid && result.lineOrigins[line].va == expected.second);
                    CHECK(result.lineOrigins[line].granularity == SourceOriginGranularity::Instruction);
                }
            }
            const auto python = DecompileToPython(result);
            CHECK(python.lineOrigins.size() == splitLines(python.text).size());
            for (uint64_t source : {uint64_t{3}, uint64_t{7}}) {
                bool found = false;
                for (const auto& origin : python.lineOrigins) found |= origin.valid && origin.va == source;
                CHECK(found);
            }
        }
    }

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("decompiler_linemap_test: all checks passed\n");
    return 0;
}
