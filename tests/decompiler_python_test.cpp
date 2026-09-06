//
// decompiler_python_test.cpp
// Tests for DecompileToPython (src/Core/Decompiler.cpp): the pure C->Python
// pseudocode translation behind the Pseudocode view's language selector.
// Asserts that
//   (1) a synthetic, exactly-shaped pseudo-C result translates to the expected
//       Python text (def/if/while True/match, no braces, decls dropped,
//       *(X) -> mem[X], x-- -> x -= 1, integer casts kept as sN/uN,
//       pointer casts stripped, partial writes made valid, switch-break dropped);
//   (2) the per-line VA map stays PARALLEL (lineVA.size() == line count) and
//       statement lines keep their source VA across the translation;
//   (3) goto/label/asm/swap/for-step special forms translate as documented;
//   (4) a full BuildCFG -> DecompileWithMap -> DecompileToPython pipeline run
//       (legacy + deep) emits no brace-only lines and keeps the map parallel —
//       and the C result itself is untouched (Decompile stays byte-identical).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\decompiler_python_test.cpp ^
//      src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
//   .\decompiler_python_test.exe
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

static TypedOperand regOp(const char* name, uint16_t width, OperandAccess access) {
    TypedOperand operand;
    operand.kind = OperandKind::Register;
    operand.registerName = name;
    operand.widthBits = width;
    operand.access = access;
    return operand;
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

static int lineWith(const std::vector<std::string>& L, const char* sub) {
    for (size_t i = 0; i < L.size(); ++i) if (L[i].find(sub) != std::string::npos) return (int)i;
    return -1;
}

static std::string trimmed(const std::string& l) {
    size_t a = l.find_first_not_of(" \t");
    size_t b = l.find_last_not_of(" \t");
    return a == std::string::npos ? std::string() : l.substr(a, b - a + 1);
}

int main(int argc, char** argv) {
    std::string logicalFixture;
    // ---- (1)+(2) exact translation of a synthetic pseudo-C result ----------
    {
        DecompResult c;
        c.text =
            "__int64 foo(a1, a2)\n"
            "{\n"
            "    __int64 v0;\n"
            "\n"
            "    v0 = *(a1 + 8);\n"
            "    if (v0 == 0) {\n"
            "        return 0;\n"
            "    }\n"
            "    while (1) {\n"
            "        v0--;\n"
            "        if (v0 <= 0) break;\n"
            "    }\n"
            "    switch (a2) {\n"
            "    case 0:\n"
            "        v0 = 1;\n"
            "        break;\n"
            "    case 1:\n"
            "        v0 = 2;\n"
            "        break;\n"
            "    }\n"
            "    return v0;\n"
            "}\n";
        c.lineVA.assign(22, 0);
        c.lineVA[4]  = 0x1010;   // "v0 = *(a1 + 8);"
        c.lineVA[5]  = 0x1014;   // "if (v0 == 0) {"
        c.lineVA[20] = 0x1040;   // "return v0;"

        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());                       // (2) parallel
        CHECK(!L.empty());
        CHECK(L[0] == "def foo(a1, a2):");
        for (const auto& l : L) {                                  // no braces survive
            std::string t = trimmed(l);
            CHECK(t != "{" && t != "}");
        }
        CHECK(lineWith(L, "__int64 v0") < 0);                      // decl dropped
        int s = lineWith(L, "v0 = mem[a1 + 8]");                   // deref rewrite
        CHECK(s >= 0);
        if (s >= 0) CHECK(py.lineVA[(size_t)s] == 0x1010);         // (2) VA preserved
        int fi = lineWith(L, "if v0 == 0:");
        CHECK(fi >= 0);
        if (fi >= 0) CHECK(py.lineVA[(size_t)fi] == 0x1014);
        CHECK(lineWith(L, "while True:") >= 0);
        CHECK(lineWith(L, "v0 -= 1") >= 0);                        // v0-- rewrite
        int stop = lineWith(L, "if v0 <= 0:");
        CHECK(stop >= 0 && (size_t)(stop + 1) < L.size());
        if (stop >= 0 && (size_t)(stop + 1) < L.size()) CHECK(trimmed(L[(size_t)stop + 1]) == "break");
        int m = lineWith(L, "match a2:");
        int c0 = lineWith(L, "case 0:");
        CHECK(m >= 0 && c0 >= 0 && c0 > m);
        if (m >= 0 && c0 >= 0) {                                   // case indented INTO the match
            size_t mi = L[m].find_first_not_of(' ');
            size_t ci = L[c0].find_first_not_of(' ');
            CHECK(ci > mi);
        }
        // The case-ending breaks are dropped (match has no fallthrough); the only
        // break left is the loop's structured break checked above.
        int nBreak = 0;
        for (const auto& l : L) if (trimmed(l) == "break") ++nBreak;
        CHECK(nBreak == 1);
        int rv = lineWith(L, "return v0");
        CHECK(rv >= 0);
        if (rv >= 0) CHECK(py.lineVA[(size_t)rv] == 0x1040);
    }

    // ---- (3) special forms: goto/label/asm/swap/cast/for-step --------------
    {
        DecompResult c;
        c.text =
            "__int64 bar(a1)\n"
            "{\n"
            "    if ((int64_t)a1 < (int64_t)0) goto loc_2000; /* tail */\n"
            "loc_1234:\n"
            "    swap(rax, rbx);\n"
            "    __asm { cpuid };\n"
            "    for (; i < 10; i++) {\n"
            "        x += i;\n"
            "    }\n"
            "    rax = rdx:rax / rcx;\n"
            "    goto loc_1234;\n"
            "}\n";
        c.lineVA.assign(12, 0);
        c.lineVA[6] = 0x1100;   // the for header

        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        int guard = lineWith(L, "if s64(a1) < s64(0):");
        CHECK(guard >= 0 && (size_t)(guard + 1) < L.size());
        if (guard >= 0 && (size_t)(guard + 1) < L.size())
            CHECK(trimmed(L[(size_t)guard + 1]) == "goto_label(\"loc_2000\")  # tail");
        CHECK(lineWith(L, "# loc_1234:") >= 0);                        // label -> marker comment
        CHECK(lineWith(L, "rax, rbx = rbx, rax") >= 0);                // swap -> tuple assign
        CHECK(lineWith(L, "asm('cpuid')") >= 0);                       // unmodelled instruction
        int w = lineWith(L, "while i < 10:");
        int b = lineWith(L, "x += i");
        int st = lineWith(L, "i += 1");
        CHECK(w >= 0 && b >= 0 && st >= 0);
        if (w >= 0 && b >= 0 && st >= 0) {
            CHECK(b == w + 1 && st == b + 1);                          // step re-materialized at body end
            CHECK(L[st].find_first_not_of(' ') == L[b].find_first_not_of(' '));
            CHECK(py.lineVA[(size_t)w] == 0x1100);
        }
        CHECK(lineWith(L, "(rdx, rax) / rcx") >= 0);                   // generic source division stays generic
        CHECK(lineWith(L, "goto_label(\"loc_1234\")") >= 0);         // explicit direct-flow placeholder
    }

    // ---- (4) full pipeline: CFG -> C -> Python, legacy + deep --------------
    //   cmp ecx,0 / je else ; then: mov [rdx],0x11 ; ret ; else: xor eax,eax ; ret
    {
        std::vector<Instruction> ins;
        ins.push_back(mk(0x1000, 2, "cmp", "ecx, 0"));
        ins.push_back(mk(0x1002, 2, "je", "", true, false, 0x100C));
        ins.push_back(mk(0x1004, 7, "mov", "dword ptr [rdx], 0x11"));
        ins.push_back(mk(0x100B, 1, "ret", "", true, true, 0));
        ins.push_back(mk(0x100C, 2, "xor", "eax, eax"));
        ins.push_back(mk(0x100E, 1, "ret", "", true, true, 0));
        ControlFlowGraph g = buildG(ins);

        for (bool deep : { false, true }) {
            DecompileOptions opt; opt.deepDataFlow = deep;
            DecompResult c = DecompileWithMap(g, opt);
            CHECK(c.text == Decompile(g, opt));                        // C path untouched
            DecompResult py = DecompileToPython(c);
            std::vector<std::string> L = splitLines(py.text);
            CHECK(!L.empty());
            CHECK(py.lineVA.size() == L.size());
            CHECK(L[0].rfind("def ", 0) == 0);
            CHECK(L[0].back() == ':');
            for (const auto& l : L) {
                std::string t = trimmed(l);
                CHECK(t != "{" && t != "}");
                CHECK(t.empty() || t.back() != ';');                   // no C statement endings
            }
            CHECK(lineWith(L, "if ") >= 0);
            CHECK(lineWith(L, "return") >= 0);
            // every kept VA points inside the function (or 0 = synthetic)
            for (uint64_t va : py.lineVA) CHECK(va == 0 || (va >= 0x1000 && va < 0x1010));
        }
    }

    // An external taken edge and a live fallthrough arm are still one source-level
    // decision. Keep the fallthrough call visibly inside an explicit else instead
    // of rendering it as unrelated code after a one-line goto guard:
    //
    //   test eax, eax
    //   jnz  0x123456
    //   call 0x6543321
    //
    // The condition/arm scaffolding maps to the consuming JNZ, while the call
    // retains its own instruction origin. The TEST is represented by the JNZ's
    // recovered condition and therefore does not acquire a separate output line.
    {
        constexpr uint64_t kBase = 0x4000;
        constexpr uint64_t kExternalTarget = 0x123456;
        constexpr uint64_t kCallTarget = 0x6543321;
        constexpr uint64_t kTestVA = kBase;
        constexpr uint64_t kBranchVA = kBase + 2;
        constexpr uint64_t kCallVA = kBase + 8;

        Instruction tested = mk(kTestVA, 2, "test", "eax, eax");
        tested.typedOperands = {
            regOp("eax", 32, OperandAccess::Read),
            regOp("eax", 32, OperandAccess::Read),
        };
        std::vector<Instruction> ins = {
            tested,
            mk(kBranchVA, 6, "jnz",  "0x123456", true, false, kExternalTarget),
            mk(kCallVA,   5, "call", "0x6543321", true, false, kCallTarget),
        };
        DecompileOptions opt;
        opt.deepDataFlow = false; // keep the architectural EAX spelling requested by the analyst
        DecompResult py = DecompileToPython(DecompileWithMap(buildG(ins), opt));
        const std::string expected =
            "def sub_4000():\n"
            "    if eax != 0:\n"
            "        goto_label(\"loc_123456\")\n"
            "    else:\n"
            "        sub_6543321()\n";
        if (py.text != expected)
            std::printf("--- external-branch Python ---\n%s--- expected ---\n%s", py.text.c_str(), expected.c_str());
        CHECK(py.text == expected);

        const std::vector<std::string> lines = splitLines(py.text);
        CHECK(py.lineVA.size() == lines.size());
        CHECK(py.lineOrigins.size() == lines.size());
        CHECK(lines.size() == 5);
        if (lines.size() == 5 && py.lineOrigins.size() == 5) {
            const uint64_t expectedVA[] = { 0, kBranchVA, kBranchVA, kBranchVA, kCallVA };
            for (size_t i = 0; i < 5; ++i) {
                CHECK(py.lineVA[i] == expectedVA[i]);
                CHECK(py.lineOrigins[i].valid == (i != 0));
                if (i != 0) {
                    CHECK(py.lineOrigins[i].va == expectedVA[i]);
                    CHECK(py.lineOrigins[i].granularity ==
                          SourceOriginGranularity::Instruction);
                }
            }
        }
        int callLines = 0;
        for (const std::string& line : lines)
            if (trimmed(line) == "sub_6543321()") ++callLines;
        CHECK(callLines == 1); // the fallthrough block must not be emitted again after else
    }

    // A pre-tested polling loop can leave the supplied function through an
    // external taken edge. Loop reconstruction consumes the header JNZ to form
    // `while`, but must retain that external destination exactly once after the
    // loop. Exercise both lifters because the deep pass may rename the tested
    // accumulator and keep the call as a value-producing expression.
    {
        constexpr uint64_t kBase = 0x4200;
        constexpr uint64_t kExternalTarget = 0x123456;
        constexpr uint64_t kPollTarget = 0x6543321;
        constexpr uint64_t kBranchVA = kBase + 2;
        constexpr uint64_t kCallVA = kBase + 8;

        Instruction tested = mk(kBase, 2, "test", "eax, eax");
        tested.typedOperands = {
            regOp("eax", 32, OperandAccess::Read),
            regOp("eax", 32, OperandAccess::Read),
        };
        std::vector<Instruction> ins = {
            tested,
            mk(kBranchVA, 6, "jnz", "0x123456", true, false, kExternalTarget),
            mk(kCallVA, 5, "call", "0x6543321", true, false, kPollTarget),
            mk(kBase + 13, 2, "jmp", "0x4200", true, false, kBase),
        };

        for (bool deep : { false, true }) {
            DecompileOptions opt;
            opt.deepDataFlow = deep;
            opt.conditionGloss = false;
            opt.nameFor = [](uint64_t va) {
                return va == kPollTarget ? std::string("poll") : std::string();
            };
            DecompResult py = DecompileToPython(DecompileWithMap(buildG(ins), opt));
            const std::vector<std::string> lines = splitLines(py.text);
            CHECK(py.lineVA.size() == lines.size());
            CHECK(py.lineOrigins.size() == lines.size());

            int pollLine = -1, gotoLine = -1;
            int pollCount = 0, gotoCount = 0;
            for (size_t i = 0; i < lines.size(); ++i) {
                if (lines[i].find("poll(") != std::string::npos) {
                    ++pollCount;
                    pollLine = static_cast<int>(i);
                }
                if (trimmed(lines[i]) == "goto_label(\"loc_123456\")") {
                    ++gotoCount;
                    gotoLine = static_cast<int>(i);
                }
            }
            CHECK(lineWith(lines, "while ") >= 0);
            CHECK(pollCount == 1 && pollLine >= 0);
            CHECK(gotoCount == 1 && gotoLine > pollLine); // external edge is post-loop, never duplicated
            if (pollLine >= 0 && static_cast<size_t>(pollLine) < py.lineOrigins.size()) {
                CHECK(py.lineVA[static_cast<size_t>(pollLine)] == kCallVA);
                CHECK(py.lineOrigins[static_cast<size_t>(pollLine)].valid);
                CHECK(py.lineOrigins[static_cast<size_t>(pollLine)].va == kCallVA);
                CHECK(py.lineOrigins[static_cast<size_t>(pollLine)].granularity ==
                      SourceOriginGranularity::Instruction);
            }
            if (gotoLine >= 0 && static_cast<size_t>(gotoLine) < py.lineOrigins.size()) {
                CHECK(py.lineVA[static_cast<size_t>(gotoLine)] == kBranchVA);
                CHECK(py.lineOrigins[static_cast<size_t>(gotoLine)].valid);
                CHECK(py.lineOrigins[static_cast<size_t>(gotoLine)].va == kBranchVA);
                CHECK(py.lineOrigins[static_cast<size_t>(gotoLine)].granularity ==
                      SourceOriginGranularity::Instruction);
            }
        }
    }

    // ---- degenerate input ----------------------------------------------------
    {
        DecompResult c{ "// no code\n", { 0 } };
        DecompResult py = DecompileToPython(c);
        CHECK(py.text == "# no code\n");
        CHECK(py.lineVA.size() == 1 && py.lineVA[0] == 0);
    }

    // ---- folded-constant comments convert to Python # comments -------------
    {
        DecompResult c;
        c.text =
            "__int64 foo()\n"
            "{\n"
            "    v0 = (0x1000 + 0x234); /* = 0x1234 */\n"
            "    return (0x1000 + 0x234); /* = 0x1234 */\n"
            "}\n";
        c.lineVA = { 0, 0, 0x1005, 0x1009, 0 };
        DecompResult py = DecompileToPython(c);
        auto L = splitLines(py.text);
        int a = lineWith(L, "v0 = (0x1000 + 0x234)");
        int r = lineWith(L, "return (0x1000 + 0x234)");
        CHECK(a >= 0 && L[a].find("# = 0x1234") != std::string::npos);
        CHECK(r >= 0 && L[r].find("# = 0x1234") != std::string::npos);
        CHECK(py.text.find("/*") == std::string::npos);   // no C comments survive
        CHECK(py.lineVA.size() == L.size());              // map stays parallel
        if (a >= 0) CHECK(py.lineVA[(size_t)a] == 0x1005);
        if (r >= 0) CHECK(py.lineVA[(size_t)r] == 0x1009);
    }

    // ---- C constants true/false/NULL/nullptr -> Python literals --------------
    //   word-boundary safe: a variable named `truth` / `null_ptr` is untouched.
    {
        DecompResult c;
        c.text =
            "__int64 foo()\n"
            "{\n"
            "    a = true;\n"
            "    b = false;\n"
            "    c = (p != NULL);\n"
            "    d = nullptr;\n"
            "    truth = a;\n"
            "    null_ptr = b;\n"
            "    return c;\n"
            "}\n";
        c.lineVA.assign(9, 0);
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        CHECK(lineWith(L, "a = True") >= 0);
        CHECK(lineWith(L, "b = False") >= 0);
        CHECK(lineWith(L, "c = (p is not None)") >= 0);
        CHECK(lineWith(L, "d = None") >= 0);
        // word-boundary: identifiers that merely CONTAIN the keyword are preserved.
        CHECK(lineWith(L, "truth = a") >= 0);
        CHECK(lineWith(L, "null_ptr = b") >= 0);
        CHECK(py.text.find("True_ptr") == std::string::npos);
        CHECK(py.text.find("Truth") == std::string::npos);
    }

    // ---- engine condition-gloss (/* ... */) becomes a Python # comment --------
    //   The deep decompiler appends a heuristic gloss to a simple `if`; the Python
    //   transform must turn it into a trailing `# ...` and keep the map parallel.
    {
        DecompResult c;
        c.text =
            "__int64 foo(a1)\n"
            "{\n"
            "    if (a1 >= 5) { /* a1 at least 5 */\n"
            "        return 1;\n"
            "    }\n"
            "    return 0;\n"
            "}\n";
        c.lineVA = { 0, 0, 0x1003, 0x1007, 0, 0x100A, 0 };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        int ix = lineWith(L, "if a1 >= 5:");
        CHECK(ix >= 0);
        if (ix >= 0) {
            CHECK(L[ix].find("# a1 at least 5") != std::string::npos);
            CHECK(py.lineVA[(size_t)ix] == 0x1003);
        }
        CHECK(py.text.find("/*") == std::string::npos);   // no C comment survives
    }

    // ---- emitter-native casts + indirect calls become Python-style expressions --
    {
        DecompResult c;
        c.text =
            "__int64 calls(a1, a2)\n"
            "{\n"
            "    v0 = (unsigned __int8)*(a1);\n"
            "    v1 = (__int16)*(a1 + 2);\n"
            "    v2 = (*a2)(v0);\n"
            "    v3 = (**(a1 + 8))(v1);\n"
            "    return v3;\n"
            "}\n";
        c.lineVA = { 0, 0, 0x2000, 0x2004, 0x2008, 0x200C, 0x2010, 0 };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        CHECK(lineWith(L, "v0 = u8(mem[a1])") >= 0);
        CHECK(lineWith(L, "v1 = s16(mem[a1 + 2])") >= 0);
        CHECK(lineWith(L, "v2 = a2(v0)") >= 0);
        CHECK(lineWith(L, "v3 = mem[a1 + 8](v1)") >= 0);
        CHECK(py.text.find("__int8") == std::string::npos);
        CHECK(py.text.find("__int16") == std::string::npos);
        CHECK(py.text.find("(*") == std::string::npos);
    }

    // Every explicit fixed-width integer cast has a stable Python intrinsic.
    // Python integers are unbounded, so dropping any of these changes native
    // truncation/sign-extension semantics even when the output still parses.
    {
        DecompResult c;
        c.text =
            "int widths(x)\n"
            "{\n"
            "    a = (uint8_t)x;\n"
            "    b = (uint16_t)x;\n"
            "    c = (uint32_t)x;\n"
            "    d = (uint64_t)x;\n"
            "    e = (int8_t)x;\n"
            "    f = (int16_t)x;\n"
            "    g = (int32_t)x;\n"
            "    h = (int64_t)x;\n"
            "    return h;\n"
            "}\n";
        c.lineVA.resize(splitLines(c.text).size(), 0);
        c.lineOrigins.resize(c.lineVA.size());
        for (size_t i = 2; i <= 9; ++i) {
            c.lineVA[i] = 0x2800 + i;
            c.lineOrigins[i] = { c.lineVA[i], true,
                                 SourceOriginGranularity::Instruction };
        }
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        const char* expected[] = {
            "a = u8(x)", "b = u16(x)", "c = u32(x)", "d = u64(x)",
            "e = s8(x)", "f = s16(x)", "g = s32(x)", "h = s64(x)",
        };
        for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
            int line = lineWith(L, expected[i]);
            CHECK(line >= 0);
            if (line >= 0) {
                CHECK(py.lineOrigins[(size_t)line].valid);
                CHECK(py.lineOrigins[(size_t)line].va == 0x2802 + i);
            }
        }
        CHECK(py.lineVA.size() == L.size());
        CHECK(py.lineOrigins.size() == L.size());
    }

    // ---- typed headers and empty suites remain usable Python pseudocode --------
    {
        DecompResult c;
        c.text =
            "int typed(void (*callback)(int, int), const char *argv[], int, Widget *, ...)\n"
            "{\n"
            "    while (1) {\n"
            "    }\n"
            "    switch (argc) {\n"
            "    case 0:\n"
            "        break;\n"
            "    default:\n"
            "        // no work\n"
            "        break;\n"
            "    }\n"
            "}\n";
        c.lineVA = { 0, 0, 0x3000, 0x3000, 0x3010, 0x3010,
                     0x3014, 0x3010, 0x3018, 0x301C, 0x3010, 0 };
        c.lineOrigins.resize(c.lineVA.size());
        for (size_t i = 0; i < c.lineVA.size(); ++i)
            if (c.lineVA[i])
                c.lineOrigins[i] = {c.lineVA[i], true,
                                    SourceOriginGranularity::Instruction};
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        CHECK(!L.empty() && L[0] == "def typed(callback, argv, a3, a4, *args):");
        CHECK(lineWith(L, "case _:") >= 0);

        // Every suite header must have a real (non-comment) indented body. This
        // catches empty spin loops and switch cases whose synthetic C break is
        // intentionally removed for Python match semantics.
        for (size_t i = 0; i < L.size(); ++i) {
            std::string h = trimmed(L[i]);
            size_t hash = h.find("  # ");
            if (hash != std::string::npos) h.resize(hash);
            if (h.empty() || h[0] == '#' || h.back() != ':') continue;
            size_t hi = L[i].find_first_not_of(' ');
            size_t j = i + 1;
            while (j < L.size()) {
                std::string b = trimmed(L[j]);
                if (!b.empty() && b[0] != '#') break;
                ++j;
            }
            CHECK(j < L.size());
            if (j < L.size()) CHECK(L[j].find_first_not_of(' ') > hi);
        }
        int wp = lineWith(L, "while True:");
        CHECK(wp >= 0 && (size_t)(wp + 1) < L.size() && trimmed(L[(size_t)wp + 1]) == "pass");
        if (wp >= 0 && (size_t)(wp + 1) < py.lineOrigins.size())
            CHECK(!py.lineOrigins[(size_t)wp + 1].valid);
        int c0 = lineWith(L, "case 0:");
        CHECK(c0 >= 0 && (size_t)(c0 + 1) < L.size() && trimmed(L[(size_t)c0 + 1]) == "pass");
        if (c0 >= 0) CHECK(py.lineVA[(size_t)c0 + 1] == 0x3010); // synthetic pass maps to case/header VA
        if (c0 >= 0 && (size_t)(c0 + 1) < py.lineOrigins.size())
            CHECK(!py.lineOrigins[(size_t)c0 + 1].valid);
    }

    // Empty match repair creates both a wildcard arm and pass. Their legacy VA
    // may retain the match-header address, but both source origins are synthetic.
    {
        DecompResult c;
        c.text = "int empty_switch(int x)\n{\n    switch (x) {\n    }\n}\n";
        c.lineVA = {0, 0, 0x3050, 0x3050, 0};
        c.lineOrigins = {
            {}, {}, {0x3050, true, SourceOriginGranularity::Instruction},
            {0x3050, true, SourceOriginGranularity::Instruction}, {},
        };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> lines = splitLines(py.text);
        int wildcard = lineWith(lines, "case _:");
        CHECK(wildcard >= 0 && (size_t)(wildcard + 1) < lines.size());
        if (wildcard >= 0 && (size_t)(wildcard + 1) < py.lineOrigins.size()) {
            CHECK(!py.lineOrigins[(size_t)wildcard].valid);
            CHECK(!py.lineOrigins[(size_t)wildcard + 1].valid);
        }
    }

    // A void parameter list is empty, and dropping the only C declaration must
    // not leave the function's Python suite empty.
    {
        DecompResult c{
            "void empty(void)\n"
            "{\n"
            "    __int64 v0;\n"
            "}\n",
            { 0, 0, 0, 0 }
        };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        CHECK(L.size() == 2);
        if (L.size() == 2) {
            CHECK(L[0] == "def empty():");
            CHECK(L[1] == "    pass");
        }
    }

    // The deep emitter really produces Microsoft-width casts for movzx/movsx.
    // Python must retain the integer width/sign as uN/sN intrinsics rather than
    // silently dropping the cast as it does for display-only pointer casts.
    {
        for (bool zeroExtend : { true, false }) {
            const uint64_t base = zeroExtend ? 0x4000 : 0x4100;
            std::vector<Instruction> ins;
            ins.push_back(mk(base, 3, zeroExtend ? "movzx" : "movsx",
                             "eax, byte ptr [rcx]"));
            ins.push_back(mk(base + 3, 1, "ret", "", true, true, 0));
            ControlFlowGraph g = buildG(ins);
            DecompileOptions opt;
            DecompResult c = DecompileWithMap(g, opt);
            CHECK(c.text.find(zeroExtend ? "(unsigned __int8)" : "(__int8)") !=
                  std::string::npos);
            DecompResult py = DecompileToPython(c);
            std::vector<std::string> L = splitLines(py.text);
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            CHECK(py.text.find("__int8") == std::string::npos);
            CHECK(lineWith(L, zeroExtend ? "u8(mem[a1])" : "s8(mem[a1])") >= 0);
        }
    }

    // The conservative/raw lifter must preserve MOVZX versus MOVSX too. Memory
    // size qualifiers choose the source cast but are not themselves expressions.
    {
        struct RawExtendCase {
            uint64_t base;
            const char* mnemonic;
            const char* operand;
            const char* cCast;
            const char* python;
            const char* qualifier;
        };
        const RawExtendCase cases[] = {
            { 0x4120, "movzx", "eax, byte ptr [rcx]", "(unsigned __int8)*(rcx)",
              "u8(mem[rcx])", "byte ptr" },
            { 0x4140, "movsx", "eax, byte ptr [rcx]", "(__int8)*(rcx)",
              "s8(mem[rcx])", "byte ptr" },
            { 0x4160, "movzx", "eax, word ptr [rcx]", "(unsigned __int16)*(rcx)",
              "u16(mem[rcx])", "word ptr" },
            { 0x4180, "movsx", "eax, word ptr [rcx]", "(__int16)*(rcx)",
              "s16(mem[rcx])", "word ptr" },
        };
        for (const RawExtendCase& test : cases) {
            DecompileOptions opt;
            opt.deepDataFlow = false;
            DecompResult c = DecompileWithMap(buildG({
                mk(test.base, 4, test.mnemonic, test.operand),
                mk(test.base + 4, 1, "ret", "", true, true, 0),
            }), opt);
            CHECK(c.text.find(test.cCast) != std::string::npos);
            DecompResult py = DecompileToPython(c);
            std::vector<std::string> L = splitLines(py.text);
            const int extended = lineWith(L, test.python);
            CHECK(extended >= 0);
            CHECK(py.text.find(test.qualifier) == std::string::npos);
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            if (extended >= 0) {
                CHECK(py.lineOrigins[(size_t)extended].valid);
                CHECK(py.lineOrigins[(size_t)extended].va == test.base);
            }
        }
    }

    // Signed and unsigned native comparisons carry materially different integer
    // semantics. The Python display keeps the exact operand width in sN/uN
    // intrinsics, including through the full CFG/data-flow/structuring path.
    {
        for (bool isUnsigned : { true, false }) {
            const uint64_t base = isUnsigned ? 0x4200 : 0x4300;
            const char* branch = isUnsigned ? "jb" : "jl";
            std::vector<Instruction> ins = {
                mk(base,     3, "cmp", "ecx, edx"),
                mk(base + 3, 2, branch, "target", true, false, base + 7),
                mk(base + 5, 2, "jmp", "done", true, false, base + 8),
                mk(base + 7, 1, "nop", ""),
                mk(base + 8, 1, "ret", "", true, true, 0),
            };
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            opt.conditionGloss = false;
            DecompResult c = DecompileWithMap(buildG(ins), opt);
            DecompResult py = DecompileToPython(c);
            std::vector<std::string> L = splitLines(py.text);
            const char* comparison = isUnsigned
                ? "u32(a1) < u32(a2)" : "s32(a1) < s32(a2)";
            int condition = lineWith(L, comparison);
            CHECK(condition >= 0);
            if (condition < 0)
                std::printf("--- %s comparison C ---\n%s--- Python ---\n%s",
                            isUnsigned ? "unsigned" : "signed", c.text.c_str(), py.text.c_str());
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            if (condition >= 0) {
                CHECK(py.lineOrigins[(size_t)condition].valid);
                CHECK(py.lineOrigins[(size_t)condition].va == base + 3);
                CHECK(py.lineOrigins[(size_t)condition].granularity ==
                      SourceOriginGranularity::Instruction);
            }
        }
    }

    // Equality and zero-flag consumers must compare the architectural slice that
    // CMP/TEST actually read. Canonicalizing AL/AH/AX/EAX to the full RAX value
    // without a width bound changes JE/JNE whenever untouched upper bits differ.
    {
        struct EqualityCase {
            uint64_t base;
            const char* lhs;
            const char* rhs;
            uint16_t width;
            const char* branch;
            const char* cComparison;
            const char* pyComparison;
        };
        const EqualityCase cases[] = {
            { 0x4320, "al",  "dl",  8,  "je",
              "(uint8_t)(a1) == (uint8_t)(a2)", "u8(a1) == u8(a2)" },
            { 0x4340, "ah",  "dh",  8,  "jne",
              "(uint8_t)(a1 >> 8) != (uint8_t)(a2 >> 8)",
              "u8(a1 >> 8) != u8(a2 >> 8)" },
            { 0x4360, "ax",  "dx",  16, "je",
              "(uint16_t)(a1) == (uint16_t)(a2)", "u16(a1) == u16(a2)" },
            { 0x4380, "eax", "edx", 32, "jne",
              "(uint32_t)(a1) != (uint32_t)(a2)", "u32(a1) != u32(a2)" },
        };
        for (const EqualityCase& test : cases) {
            Instruction compare = mk(test.base + 3, 2, "cmp",
                                     (std::string(test.lhs) + ", " + test.rhs).c_str());
            compare.typedOperands = {
                regOp(test.lhs, test.width, OperandAccess::Read),
                regOp(test.rhs, test.width, OperandAccess::Read),
            };
            std::vector<Instruction> ins = {
                mk(test.base,     3, "mov", "rax, rcx"),
                compare,
                mk(test.base + 5, 2, test.branch, "target", true, false, test.base + 9),
                mk(test.base + 7, 2, "jmp", "done", true, false, test.base + 10),
                mk(test.base + 9, 1, "nop", ""),
                mk(test.base + 10, 1, "ret", "", true, true, 0),
            };
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            opt.conditionGloss = false;
            DecompResult c = DecompileWithMap(buildG(ins), opt);
            const bool hasCComparison = c.text.find(test.cComparison) != std::string::npos;
            CHECK(hasCComparison);
            if (!hasCComparison)
                std::printf("--- width-bounded equality C (%s) ---\n%s",
                            test.lhs, c.text.c_str());
            DecompResult py = DecompileToPython(c);
            std::vector<std::string> L = splitLines(py.text);
            const int condition = lineWith(L, test.pyComparison);
            CHECK(condition >= 0);
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            if (condition >= 0) {
                CHECK(py.lineOrigins[(size_t)condition].valid);
                CHECK(py.lineOrigins[(size_t)condition].va == test.base + 5);
            }
        }

        Instruction tested = mk(0x43A3, 2, "test", "al, al");
        tested.typedOperands = {
            regOp("al", 8, OperandAccess::Read),
            regOp("al", 8, OperandAccess::Read),
        };
        std::vector<Instruction> testIns = {
            mk(0x43A0, 3, "mov", "rax, rcx"), tested,
            mk(0x43A5, 2, "jne", "target", true, false, 0x43A9),
            mk(0x43A7, 2, "jmp", "done", true, false, 0x43AA),
            mk(0x43A9, 1, "nop", ""),
            mk(0x43AA, 1, "ret", "", true, true, 0),
        };
        DecompileOptions opt;
        opt.target = { Arch::X64, DecompileABI::Win64 };
        opt.conditionGloss = false;
        DecompResult testC = DecompileWithMap(buildG(testIns), opt);
        CHECK(testC.text.find("(uint8_t)(a1) != 0") != std::string::npos);
        DecompResult testPy = DecompileToPython(testC);
        std::vector<std::string> testLines = splitLines(testPy.text);
        CHECK(lineWith(testLines, "if u8(a1) != 0:") >= 0);

        Instruction setCompare = mk(0x43C3, 3, "cmp", "ax, dx");
        setCompare.typedOperands = {
            regOp("ax", 16, OperandAccess::Read),
            regOp("dx", 16, OperandAccess::Read),
        };
        Instruction setEqual = mk(0x43C6, 3, "sete", "al");
        setEqual.typedOperands = { regOp("al", 8, OperandAccess::Write) };
        std::vector<Instruction> setIns = {
            mk(0x43C0, 3, "mov", "rax, rcx"), setCompare, setEqual,
            mk(0x43C9, 1, "ret", "", true, true, 0),
        };
        opt.foldTemps = false;
        DecompResult setC = DecompileWithMap(buildG(setIns), opt);
        CHECK(setC.text.find("(uint16_t)(a1) == (uint16_t)(a2)") != std::string::npos);
        DecompResult setPy = DecompileToPython(setC);
        std::vector<std::string> setLines = splitLines(setPy.text);
        const int setLine = lineWith(setLines, "u16(a1) == u16(a2)");
        CHECK(setLine >= 0);
        if (setLine >= 0) {
            CHECK(setLines[(size_t)setLine].find("& ~0xFF") != std::string::npos);
            CHECK(setPy.lineOrigins[(size_t)setLine].valid);
            CHECK(setPy.lineOrigins[(size_t)setLine].va == 0x43C6);
        }
    }

    // Partial-register writes are read/modify/writes of the full variable.
    // Function-call lvalues such as `LOBYTE(v) = x` are invalid Python, so each
    // width is lowered to an explicit mask plus a bounded uN value.
    {
        struct PartialCase {
            const char* operand;
            const char* forbidden;
            const char* mask;
            const char* narrowed;
            const char* shifted;
        };
        const PartialCase cases[] = {
            { "al, 0x12",   "LOBYTE(", "& ~0xFF",   "| u8(0x12)",  nullptr },
            { "ax, 0x1234", "LOWORD(", "& ~0xFFFF", "| u16(0x1234)", nullptr },
            { "ah, 0x34",   "BYTE1(",  "& ~0xFF00", "u8(0x34)",    "<< 8" },
        };
        uint64_t base = 0x4400;
        for (const PartialCase& test : cases) {
            std::vector<Instruction> ins = {
                mk(base,     3, "mov", "rax, rcx"),
                mk(base + 3, 3, "mov", test.operand),
                mk(base + 6, 1, "ret", "", true, true, 0),
            };
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            opt.foldTemps = false;
            DecompResult py = DecompileToPython(DecompileWithMap(buildG(ins), opt));
            std::vector<std::string> L = splitLines(py.text);
            int update = lineWith(L, test.mask);
            CHECK(update >= 0);
            CHECK(py.text.find(test.forbidden) == std::string::npos);
            if (update >= 0) {
                CHECK(L[(size_t)update].find(test.narrowed) != std::string::npos);
                if (test.shifted) CHECK(L[(size_t)update].find(test.shifted) != std::string::npos);
                CHECK(py.lineOrigins[(size_t)update].valid);
                CHECK(py.lineOrigins[(size_t)update].va == base + 3);
            }
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            base += 0x20;
        }

        // setcc is another real producer of an 8-bit partial lvalue.
        std::vector<Instruction> setcc = {
            mk(0x4480, 3, "mov", "rax, rcx"),
            mk(0x4483, 3, "cmp", "rdx, r8"),
            mk(0x4486, 3, "setl", "al"),
            mk(0x4489, 1, "ret", "", true, true, 0),
        };
        DecompileOptions opt;
        opt.target = { Arch::X64, DecompileABI::Win64 };
        opt.foldTemps = false;
        DecompResult py = DecompileToPython(DecompileWithMap(buildG(setcc), opt));
        std::vector<std::string> L = splitLines(py.text);
        int update = lineWith(L, "& ~0xFF");
        CHECK(update >= 0);
        CHECK(py.text.find("LOBYTE(") == std::string::npos);
        if (update >= 0) {
            CHECK(L[(size_t)update].find("| u8(") != std::string::npos);
            CHECK(L[(size_t)update].find("s64(a2) < s64(a3)") != std::string::npos);
            CHECK(py.lineOrigins[(size_t)update].valid &&
                  py.lineOrigins[(size_t)update].va == 0x4486);
        }
        CHECK(py.lineVA.size() == L.size());
        CHECK(py.lineOrigins.size() == L.size());
    }


    // Compound and increment/decrement forms need the same valid full-variable
    // lowering as a simple partial assignment; prefix/postfix spelling must not
    // leak an invalid function-call lvalue into Python.
    {
        DecompResult c;
        c.text =
            "int partial_updates(v, x)\n"
            "{\n"
            "    LOBYTE(v) += x;\n"
            "    LOWORD(v)--;\n"
            "    ++BYTE1(v);\n"
            "    return v;\n"
            "}\n";
        c.lineVA = { 0, 0, 0x44A0, 0x44A1, 0x44A2, 0x44A3, 0 };
        c.lineOrigins.resize(c.lineVA.size());
        for (size_t i = 2; i <= 5; ++i)
            c.lineOrigins[i] = { c.lineVA[i], true,
                                 SourceOriginGranularity::Instruction };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        const int lowByte = lineWith(L, "(v & ~0xFF) | u8(u8(v) + x)");
        const int lowWord = lineWith(L, "(v & ~0xFFFF) | u16(u16(v) - 1)");
        const int highByte = lineWith(L, "(v & ~0xFF00) | (u8(u8(v >> 8) + 1) << 8)");
        CHECK(lowByte >= 0 && lowWord >= 0 && highByte >= 0);
        CHECK(py.text.find("LOBYTE(") == std::string::npos);
        CHECK(py.text.find("LOWORD(") == std::string::npos);
        CHECK(py.text.find("BYTE1(") == std::string::npos);
        CHECK(py.lineVA.size() == L.size());
        CHECK(py.lineOrigins.size() == L.size());
        if (lowByte >= 0) CHECK(py.lineOrigins[(size_t)lowByte].va == 0x44A0);
        if (lowWord >= 0) CHECK(py.lineOrigins[(size_t)lowWord].va == 0x44A1);
        if (highByte >= 0) CHECK(py.lineOrigins[(size_t)highByte].va == 0x44A2);
    }

    // Loads, stores, and address formation retain their distinct source-like
    // spellings. Cover both data-flow lowering and the conservative legacy path.
    {
        DecompileOptions deep;
        deep.target = { Arch::X64, DecompileABI::Win64 };
        std::vector<Instruction> storeIns = {
            mk(0x4500, 4, "mov", "qword ptr [rcx + rdx * 8], r8"),
            mk(0x4504, 1, "ret", "", true, true, 0),
        };
        DecompResult storePy = DecompileToPython(DecompileWithMap(buildG(storeIns), deep));
        std::vector<std::string> storeLines = splitLines(storePy.text);
        int store = lineWith(storeLines, "mem[a1 + a2 * 8] = a3");
        CHECK(store >= 0);
        if (store >= 0) {
            CHECK(storePy.lineOrigins[(size_t)store].valid);
            CHECK(storePy.lineOrigins[(size_t)store].va == 0x4500);
        }
        CHECK(storePy.lineVA.size() == storeLines.size());
        CHECK(storePy.lineOrigins.size() == storeLines.size());

        DecompileOptions legacy;
        legacy.deepDataFlow = false;
        std::vector<Instruction> addressIns = {
            mk(0x4520, 4, "lea", "rax, [rcx + 8]"),
            mk(0x4524, 1, "ret", "", true, true, 0),
        };
        DecompResult addressPy = DecompileToPython(DecompileWithMap(buildG(addressIns), legacy));
        std::vector<std::string> addressLines = splitLines(addressPy.text);
        int address = lineWith(addressLines, "rax = addr(rcx + 8)");
        CHECK(address >= 0);
        if (address >= 0) {
            CHECK(addressPy.lineOrigins[(size_t)address].valid);
            CHECK(addressPy.lineOrigins[(size_t)address].va == 0x4520);
        }

        std::vector<Instruction> nestedIns = {
            mk(0x4540, 3, "mov", "rax, qword ptr [rcx]"),
            mk(0x4543, 4, "mov", "rax, qword ptr [rax + 8]"),
            mk(0x4547, 1, "ret", "", true, true, 0),
        };
        DecompResult nestedPy = DecompileToPython(DecompileWithMap(buildG(nestedIns), deep));
        std::vector<std::string> nestedLines = splitLines(nestedPy.text);
        CHECK(lineWith(nestedLines, "mem[mem[a1] + 8]") >= 0);
        CHECK(nestedPy.lineVA.size() == nestedLines.size());
        CHECK(nestedPy.lineOrigins.size() == nestedLines.size());
    }

    // dataRefFor may return analyst-authored/free-form names. Spaces and hyphens
    // cannot be emitted as bare Python (`license-key` would misleadingly subtract),
    // so retain the exact identity through an explicit symbolic-reference helper.
    {
        const char* symbols[] = { "license key", "license-key", "class\"\\key!" };
        const char* expectedRefs[] = {
            "symbol_ref(\"license key\")",
            "symbol_ref(\"license-key\")",
            "symbol_ref(\"class\\\"\\\\key!\")",
        };
        for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
            const uint64_t base = 0x45A0 + i * 0x20;
            const uint64_t address = 0x140005000ull + i * 0x1000;
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            opt.dataRefFor = [address, symbol = std::string(symbols[i])](uint64_t candidate) {
                return candidate == address ? symbol : std::string();
            };
            const std::string operand = "rax, [" + std::to_string(address) + "]";
            DecompResult c = DecompileWithMap(buildG({
                mk(base, 7, "lea", operand.c_str()),
                mk(base + 7, 1, "ret", "", true, true, 0),
            }), opt);
            DecompResult py = DecompileToPython(c);
            std::vector<std::string> L = splitLines(py.text);
            const int symbolLine = lineWith(L, expectedRefs[i]);
            CHECK(symbolLine >= 0);
            CHECK(py.text.find("return license key") == std::string::npos);
            CHECK(py.text.find("return license-key") == std::string::npos);
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            if (symbolLine >= 0) {
                CHECK(py.lineOrigins[(size_t)symbolLine].valid);
                CHECK(py.lineOrigins[(size_t)symbolLine].va >= base);
                CHECK(py.lineOrigins[(size_t)symbolLine].va <= base + 7);
            }
        }
    }

    // Quote-shaped callback text is trusted only when it is exactly one valid
    // string literal. Trailing statements and malformed escapes remain inert,
    // identity-preserving symbol references instead of becoming Python code.
    {
        struct QuotedDataRefCase {
            uint64_t base;
            uint64_t address;
            const char* token;
            const char* expectedReturn;
            bool symbolic;
        };
        const QuotedDataRefCase cases[] = {
            { 0x4600, 0x140009000ull, "\"hello\\nworld\"",
              "return \"hello\\nworld\"", false },
            { 0x4620, 0x14000A000ull, "\"x\"; bogus; \"y\"",
              "return symbol_ref(\"\\\"x\\\"; bogus; \\\"y\\\"\")", true },
            { 0x4640, 0x14000B000ull, "\"\\x\"",
              "return symbol_ref(\"\\\"\\\\x\\\"\")", true },
        };
        for (const QuotedDataRefCase& test : cases) {
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            opt.dataRefFor = [&test](uint64_t candidate) {
                return candidate == test.address ? std::string(test.token) : std::string();
            };
            const std::string operand = "rax, [" + std::to_string(test.address) + "]";
            DecompResult py = DecompileToPython(DecompileWithMap(buildG({
                mk(test.base, 7, "lea", operand.c_str()),
                mk(test.base + 7, 1, "ret", "", true, true, 0),
            }), opt));
            std::vector<std::string> L = splitLines(py.text);
            const int returned = lineWith(L, test.expectedReturn);
            CHECK(returned >= 0);
            if (returned < 0)
                std::printf("--- quoted dataRef token %s ---\n%s", test.token, py.text.c_str());
            CHECK(L.size() == 2); // one def plus one inert return expression
            CHECK((py.text.find("symbol_ref(") != std::string::npos) == test.symbolic);
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            if (returned >= 0) {
                CHECK(trimmed(L[(size_t)returned]) == test.expectedReturn);
                CHECK(py.lineOrigins[(size_t)returned].valid);
                CHECK(py.lineOrigins[(size_t)returned].va >= test.base);
                CHECK(py.lineOrigins[(size_t)returned].va <= test.base + 7);
            }
            for (const std::string& line : L) {
                CHECK(trimmed(line) != "bogus");
                CHECK(trimmed(line).rfind("bogus;", 0) != 0);
            }
        }
    }

    // Indirect calls remain ordinary Python call expressions. Computed jumps are
    // explicitly distinguished from direct-label placeholders and keep an
    // expression operand rather than quoting it as if it were a label.
    {
        std::vector<Instruction> callIns = {
            mk(0x4600, 3, "mov", "rax, rcx"),
            mk(0x4603, 2, "call", "rax", true, false, 0),
            mk(0x4605, 1, "ret", "", true, true, 0),
        };
        DecompileOptions opt;
        opt.target = { Arch::X64, DecompileABI::Win64 };
        opt.foldTemps = false;
        DecompResult callPy = DecompileToPython(DecompileWithMap(buildG(callIns), opt));
        std::vector<std::string> callLines = splitLines(callPy.text);
        CHECK(lineWith(callLines, "a1()") >= 0);
        CHECK(callPy.text.find("(*") == std::string::npos);
        CHECK(callPy.lineVA.size() == callLines.size());
        CHECK(callPy.lineOrigins.size() == callLines.size());

        std::vector<Instruction> jumpIns = {
            mk(0x4620, 2, "jmp", "rax", true, false, 0),
        };
        DecompResult jumpPy = DecompileToPython(DecompileWithMap(buildG(jumpIns), opt));
        std::vector<std::string> jumpLines = splitLines(jumpPy.text);
        int jump = lineWith(jumpLines, "indirect_jump(rax)");
        CHECK(jump >= 0);
        CHECK(jumpPy.text.find("goto_label") == std::string::npos);
        if (jump >= 0) {
            CHECK(jumpPy.lineOrigins[(size_t)jump].valid);
            CHECK(jumpPy.lineOrigins[(size_t)jump].va == 0x4620);
        }
        CHECK(jumpPy.lineVA.size() == jumpLines.size());
        CHECK(jumpPy.lineOrigins.size() == jumpLines.size());
    }

    // Native DIV/IDIV are not Python floor division. The high and low halves of
    // the dividend, signedness, and native width stay explicit in udivN/sdivN and
    // uremN/sremN intrinsics. Both statements map back to the one instruction.
    {
        struct DivisionCase {
            uint64_t base;
            const char* tag;
            const char* mnemonic;
            const char* operand;
            const char* low;
            const char* high;
            const char* quotientIntrinsic;
            const char* remainderIntrinsic;
        };
        const DivisionCase cases[] = {
            { 0x4680, "4680", "div",  "cl",  "al",  "ah",  "udiv8",  "urem8" },
            { 0x46A0, "46A0", "idiv", "cl",  "al",  "ah",  "sdiv8",  "srem8" },
            { 0x46C0, "46C0", "div",  "cx",  "ax",  "dx",  "udiv16", "urem16" },
            { 0x46E0, "46E0", "idiv", "cx",  "ax",  "dx",  "sdiv16", "srem16" },
            { 0x4700, "4700", "div",  "ecx", "eax", "edx", "udiv32", "urem32" },
            { 0x4720, "4720", "idiv", "rcx", "rax", "rdx", "sdiv64", "srem64" },
        };
        for (const DivisionCase& test : cases) {
            std::vector<Instruction> ins = {
                mk(test.base, 2, test.mnemonic, test.operand),
                mk(test.base + 2, 1, "ret", "", true, true, 0),
            };
            DecompileOptions opt;
            opt.deepDataFlow = false;
            DecompResult py = DecompileToPython(DecompileWithMap(buildG(ins), opt));
            std::vector<std::string> L = splitLines(py.text);
            const std::string hiName = "local_div_hi_" + std::string(test.tag);
            const std::string loName = "local_div_lo_" + std::string(test.tag);
            const std::string srcName = "local_div_src_" + std::string(test.tag);
            const std::string args = "(" + hiName + ", " + loName + ", " + srcName + ")";
            const std::string quotient = std::string(test.low) + " = " +
                                         test.quotientIntrinsic + args;
            const std::string remainder = std::string(test.high) + " = " +
                                          test.remainderIntrinsic + args;
            const int hiSnapshot = lineWith(L, (hiName + " = " + test.high).c_str());
            const int loSnapshot = lineWith(L, (loName + " = " + test.low).c_str());
            const int srcSnapshot = lineWith(L, (srcName + " = " + test.operand).c_str());
            const int q = lineWith(L, quotient.c_str());
            const int rem = lineWith(L, remainder.c_str());
            CHECK(hiSnapshot >= 0 && loSnapshot >= 0 && srcSnapshot >= 0);
            CHECK(q >= 0 && rem >= 0 && q != rem);
            CHECK(hiSnapshot < q && loSnapshot < q && srcSnapshot < q);
            CHECK(hiSnapshot < rem && loSnapshot < rem && srcSnapshot < rem);
            CHECK(py.text.find(" // ") == std::string::npos);
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            const int mapped[] = { hiSnapshot, loSnapshot, srcSnapshot, q, rem };
            for (int line : mapped) {
                if (line < 0) continue;
                CHECK(py.lineOrigins[(size_t)line].valid);
                CHECK(py.lineOrigins[(size_t)line].va == test.base);
            }
        }

        // Raw memory operands use their qualifier only to select the intrinsic
        // width. The qualifier itself must not survive as invalid Python syntax.
        struct MemoryDivisionCase {
            uint64_t base;
            const char* tag;
            const char* mnemonic;
            const char* operand;
            const char* quotient;
            const char* remainder;
        };
        const MemoryDivisionCase memoryCases[] = {
            { 0x47C0, "47C0", "div",  "byte ptr [rcx]", "udiv8",  "urem8" },
            { 0x47E0, "47E0", "idiv", "word ptr [rcx]", "sdiv16", "srem16" },
        };
        for (const MemoryDivisionCase& test : memoryCases) {
            DecompileOptions opt;
            opt.deepDataFlow = false;
            DecompResult py = DecompileToPython(DecompileWithMap(buildG({
                mk(test.base, 3, test.mnemonic, test.operand),
                mk(test.base + 3, 1, "ret", "", true, true, 0),
            }), opt));
            std::vector<std::string> L = splitLines(py.text);
            const std::string hi = "local_div_hi_" + std::string(test.tag);
            const std::string lo = "local_div_lo_" + std::string(test.tag);
            const std::string src = "local_div_src_" + std::string(test.tag);
            const std::string args = "(" + hi + ", " + lo + ", " + src + ")";
            const int source = lineWith(L, (src + " = mem[rcx]").c_str());
            const int q = lineWith(L, (std::string(test.quotient) + args).c_str());
            const int rem = lineWith(L, (std::string(test.remainder) + args).c_str());
            CHECK(source >= 0 && q >= 0 && rem >= 0);
            CHECK(py.text.find("byte ptr") == std::string::npos);
            CHECK(py.text.find("word ptr") == std::string::npos);
            if (source >= 0) {
                CHECK(py.lineOrigins[(size_t)source].valid);
                CHECK(py.lineOrigins[(size_t)source].va == test.base);
            }
        }

        // Deep data flow must not widen the architecturally special r/m8 and
        // r/m16 forms. Their quotient/remainder land in partial registers, so
        // the Python result combines the intrinsic with the same valid full-
        // variable mask lowering tested above.
        struct DeepDivisionCase {
            uint64_t base;
            const char* tag;
            const char* mnemonic;
            const char* operand;
            const char* quotient;
            const char* remainder;
            const char* mask;
            bool highByteRemainder;
        };
        const DeepDivisionCase deepCases[] = {
            { 0x4740, "4743", "div",  "cl", "udiv8",  "urem8",  "& ~0xFF",   true },
            { 0x4760, "4763", "idiv", "cl", "sdiv8",  "srem8",  "& ~0xFF",   true },
            { 0x4780, "4783", "div",  "cx", "udiv16", "urem16", "& ~0xFFFF", false },
            { 0x47A0, "47A3", "idiv", "cx", "sdiv16", "srem16", "& ~0xFFFF", false },
        };
        for (const DeepDivisionCase& test : deepCases) {
            std::vector<Instruction> ins = {
                mk(test.base,     3, "test", "rcx, rcx"),
                mk(test.base + 3, 2, test.mnemonic, test.operand),
            };
            if (test.highByteRemainder) {
                ins.push_back(mk(test.base + 5, 1, "ret", "", true, true, 0));
            } else {
                // Consume both AX and DX so quotient and remainder survive DCE.
                ins.push_back(mk(test.base + 5, 3, "add", "rax, rdx"));
                ins.push_back(mk(test.base + 8, 1, "ret", "", true, true, 0));
            }
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            opt.foldTemps = false;
            DecompResult py = DecompileToPython(DecompileWithMap(buildG(ins), opt));
            std::vector<std::string> L = splitLines(py.text);
            const std::string hi = "local_div_hi_" + std::string(test.tag);
            const std::string lo = "local_div_lo_" + std::string(test.tag);
            const std::string src = "local_div_src_" + std::string(test.tag);
            const std::string args = "(" + hi + ", " + lo + ", " + src + ")";
            const int hiSnapshot = lineWith(L, (hi + " =").c_str());
            const int loSnapshot = lineWith(L, (lo + " =").c_str());
            const int srcSnapshot = lineWith(L, (src + " =").c_str());
            int q = lineWith(L, (std::string(test.quotient) + args).c_str());
            int rem = lineWith(L, (std::string(test.remainder) + args).c_str());
            CHECK(hiSnapshot >= 0 && loSnapshot >= 0 && srcSnapshot >= 0);
            CHECK(q >= 0 && rem >= 0 && q != rem);
            CHECK(hiSnapshot < q && loSnapshot < q && srcSnapshot < q);
            CHECK(hiSnapshot < rem && loSnapshot < rem && srcSnapshot < rem);
            CHECK(py.lineVA.size() == L.size());
            CHECK(py.lineOrigins.size() == L.size());
            if (q >= 0 && rem >= 0) {
                CHECK(L[(size_t)q].find(test.mask) != std::string::npos);
                CHECK(L[(size_t)rem].find(test.highByteRemainder ? "& ~0xFF00" : test.mask) !=
                      std::string::npos);
                if (test.highByteRemainder)
                    CHECK(L[(size_t)rem].find("<< 8") != std::string::npos);
                CHECK(py.lineOrigins[(size_t)q].valid &&
                      py.lineOrigins[(size_t)q].va == test.base + 3);
                CHECK(py.lineOrigins[(size_t)rem].valid &&
                      py.lineOrigins[(size_t)rem].va == test.base + 3);
            }
            const int snapshots[] = { hiSnapshot, loSnapshot, srcSnapshot };
            for (int line : snapshots) {
                if (line < 0) continue;
                CHECK(py.lineOrigins[(size_t)line].valid);
                CHECK(py.lineOrigins[(size_t)line].va == test.base + 3);
            }
        }
    }

    // ---- analyst names, declarations, call targets, and compact operators ----
    // User labels are intentionally free-form in the UI. The Python display must
    // keep qualified imports readable while making invalid definitions/calls safe.
    {
        DecompResult c;
        c.text =
            "struct Result check password(int value, long value, DWORD, int lambda, ...)\n"
            "{\n"
            "    int local = 7;\n"
            "    int first = 1, second = helper(1, 2);\n"
            "    int unused, kept = 9;\n"
            "    const char *ptr = (const char *)*(base);\n"
            "    void (*callback)(int);\n"
            "    DWORD scratch; /* reserved */\n"
            "    r0 = check password(local);\n"
            "    r1 = kernel32.CreateFileW(ptr);\n"
            "    r2 = ns::worker(local);\n"
            "    r3 = module!ordinal(local);\n"
            "    r4 = 123-start(local);\n"
            "    r5 = !predicate(local);\n"
            "    r6 = left&&!right||other;\n"
            "    r7 = obj->ready(local);\n"
            "    r8 = read/file(local);\n"
            "    r9 = left&&predicate(local);\n"
            "    literal = 'x&&y->z';\n"
            "    return r0;\n"
            "}\n";
        c.lineVA.resize(21);
        for (size_t i = 0; i < c.lineVA.size(); ++i) c.lineVA[i] = 0x5000 + i;
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        CHECK(!L.empty() && L[0] ==
              "def check_password(value, value_2, a3, lambda_, *args):  # symbol: check password");
        CHECK(lineWith(L, "local = 7") >= 0);
        int first = lineWith(L, "first = 1");
        int second = lineWith(L, "second = helper(1, 2)");
        CHECK(first >= 0 && second == first + 1);
        CHECK(lineWith(L, "kept = 9") >= 0);
        CHECK(lineWith(L, "unused") < 0);
        CHECK(lineWith(L, "ptr = mem[base]") >= 0);
        CHECK(lineWith(L, "callback") < 0);                  // uninitialized function-pointer decl dropped
        CHECK(lineWith(L, "# reserved") >= 0);               // useful comment on a dropped decl survives
        CHECK(lineWith(L, "r0 = check_password(local)") >= 0);
        CHECK(lineWith(L, "r1 = kernel32.CreateFileW(ptr)") >= 0); // dotted import spelling preserved
        CHECK(lineWith(L, "r2 = ns.worker(local)") >= 0);     // C++ scope becomes a Python qualifier
        CHECK(lineWith(L, "r3 = module_ordinal(local)") >= 0);
        CHECK(lineWith(L, "r4 = _123_start(local)") >= 0);
        CHECK(lineWith(L, "r5 = not predicate(local)") >= 0);
        CHECK(lineWith(L, "r6 = int(bool(left and not right or other))") >= 0);
        CHECK(lineWith(L, "r7 = obj.ready(local)") >= 0);
        CHECK(lineWith(L, "r8 = read_file(local)") >= 0);
        CHECK(lineWith(L, "r9 = int(bool(left and predicate(local)))") >= 0);
        CHECK(lineWith(L, "literal = 'x&&y->z'") >= 0);       // operator text in a char literal is opaque
        int local = lineWith(L, "local = 7");
        if (local >= 0) CHECK(py.lineVA[(size_t)local] == 0x5002);
        if (first >= 0 && second >= 0) {
            CHECK(py.lineVA[(size_t)first] == 0x5003);
            CHECK(py.lineVA[(size_t)second] == 0x5003);
        }
    }

    // Already-valid identifiers, including meaningful trailing underscores,
    // remain byte-for-byte unchanged and do not gain an "original symbol" note.
    {
        DecompResult c{
            "int valid_name_(int arg_)\n"
            "{\n"
            "    return arg_;\n"
            "}\n",
            { 0, 0, 0x5100, 0 }
        };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(!L.empty() && L[0] == "def valid_name_(arg_):");
        CHECK(py.text.find("# symbol:") == std::string::npos);
        CHECK(py.lineVA.size() == L.size());
    }

    // ---- nested else-if becomes elif without swallowing trailing statements ---
    {
        DecompResult c;
        c.text =
            "int choose(a, b)\n"
            "{\n"
            "    if (a) {\n"
            "        return 1;\n"
            "    }\n"
            "    else {\n"
            "        if (b) {\n"
            "            return 2;\n"
            "        }\n"
            "        else {\n"
            "            return 3;\n"
            "        }\n"
            "    }\n"
            "}\n";
        c.lineVA = { 0, 0, 0x6000, 0x6004, 0x6000, 0x6000, 0x6010,
                     0x6014, 0x6010, 0x6010, 0x6018, 0x6010, 0x6000, 0 };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        int ei = lineWith(L, "elif b:");
        CHECK(ei >= 0);
        if (ei >= 0) {
            CHECK(L[(size_t)ei].find_first_not_of(' ') == 4);
            CHECK(py.lineVA[(size_t)ei] == 0x6010);
        }
        CHECK(lineWith(L, "        if b:") < 0);
        CHECK(lineWith(L, "    else:") >= 0); // nested conditional's final else is retained
    }

    // Do not fold an else whose nested if is followed by another outer-suite
    // statement; doing so would incorrectly make that statement conditional.
    {
        DecompResult c{
            "int keep_nested(a)\n"
            "{\n"
            "    if (a) {\n"
            "        return 1;\n"
            "    }\n"
            "    else {\n"
            "        if (b) {\n"
            "            use();\n"
            "        }\n"
            "        cleanup();\n"
            "    }\n"
            "}\n",
            std::vector<uint64_t>(12, 0)
        };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(lineWith(L, "elif b:") < 0);
        CHECK(lineWith(L, "        if b:") >= 0);
        CHECK(lineWith(L, "        cleanup()") >= 0);
        CHECK(py.lineVA.size() == L.size());
    }

    // A continue in the generic Python while form of a C for-loop must execute
    // the hoisted step first, just as the original for-loop does.
    {
        DecompResult c{
            "int loop()\n"
            "{\n"
            "    for (; i < 10; i++) {\n"
            "        if (skip) continue;\n"
            "        consume(i);\n"
            "    }\n"
            "}\n",
            { 0, 0, 0x7000, 0x7004, 0x7008, 0x700C, 0 }
        };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        int iff = lineWith(L, "if skip:");
        CHECK(iff >= 0 && (size_t)(iff + 2) < L.size());
        if (iff >= 0 && (size_t)(iff + 2) < L.size()) {
            CHECK(trimmed(L[(size_t)iff + 1]) == "i += 1");
            CHECK(trimmed(L[(size_t)iff + 2]) == "continue");
            CHECK(py.lineVA[(size_t)iff + 1] == 0x7000);
            CHECK(py.lineVA[(size_t)iff + 2] == 0x7004);
        }
        int steps = 0;
        for (const std::string& l : L) if (trimmed(l) == "i += 1") ++steps;
        CHECK(steps == 2); // continue path + normal bottom-of-loop path
    }

    // ---- source-style expressions: explicit predicates, None, literals, named casts ----
    {
        DecompResult c;
        c.text =
            "int pythonic(void *p, int flags)\n"
            "{\n"
            "    Widget local = (Widget *)p;\n"
            "    mask = 0xFFULL;\n"
            "    mode = 077u;\n"
            "    ratio = 1.5f;\n"
            "    text = L\"wide\";\n"
            "    missing = (p == NULL);\n"
            "    present = (p != nullptr);\n"
            "    negated = !flags == 1;\n"
            "    grouped = (Widget) + 1;\n"
            "    if (flags != 0) {\n"
            "        use(local);\n"
            "    }\n"
            "    if ((flags & 4) == 0) return 0;\n"
            "    return 1;\n"
            "}\n";
        c.lineVA.resize(splitLines(c.text).size(), 0);
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        CHECK(lineWith(L, "local = p") >= 0);
        CHECK(lineWith(L, "mask = 0xFF") >= 0);
        CHECK(lineWith(L, "mode = 0o77") >= 0);
        CHECK(lineWith(L, "ratio = 1.5") >= 0);
        CHECK(lineWith(L, "text = \"wide\"") >= 0);
        CHECK(lineWith(L, "missing = (p is None)") >= 0);
        CHECK(lineWith(L, "present = (p is not None)") >= 0);
        CHECK(lineWith(L, "negated = (not flags) == 1") >= 0);
        CHECK(lineWith(L, "grouped = (Widget) + 1") >= 0);
        CHECK(lineWith(L, "if flags != 0:") >= 0);
        int masked = lineWith(L, "if (flags & 4) == 0:");
        CHECK(masked >= 0 && (size_t)(masked + 1) < L.size());
        if (masked >= 0 && (size_t)(masked + 1) < L.size())
            CHECK(trimmed(L[(size_t)masked + 1]) == "return 0");
        CHECK(py.text.find("Widget local") == std::string::npos);
        CHECK(py.text.find("ULL") == std::string::npos);
        CHECK(py.text.find("NULL") == std::string::npos);
    }

    // ---- conservative source-level for/range recovery -----------------------
    // An unknown native signed bound keeps its explicit comparison casts. The
    // initializer and loop header remain independently navigable.
    {
        // Full CFG/data-flow path: ecx=0; while (ecx<edx) { eax+=ecx; ecx++; }
        std::vector<Instruction> ins;
        ins.push_back(mk(0x7800, 5, "mov", "ecx, 0"));
        ins.push_back(mk(0x7805, 2, "cmp", "ecx, edx"));
        ins.push_back(mk(0x7807, 2, "jge", "0x780F", true, false, 0x780F));
        ins.push_back(mk(0x7809, 2, "add", "eax, ecx"));
        ins.push_back(mk(0x780B, 2, "inc", "ecx"));
        ins.push_back(mk(0x780D, 2, "jmp", "0x7805", true, false, 0x7805));
        ins.push_back(mk(0x780F, 1, "ret", "", true, true, 0));
        ControlFlowGraph g = buildG(ins);
        DecompResult c = DecompileWithMap(g);
        CHECK(c.text.find("for (; ") != std::string::npos);
        CHECK(c.text.find("(int32_t)") != std::string::npos);
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        const int loopLine = lineWith(L, "while s32(");
        CHECK(loopLine > 0);
        if (loopLine > 0) {
            CHECK(L[(size_t)loopLine - 1].find("= 0") != std::string::npos);
            CHECK(py.lineOrigins[(size_t)loopLine - 1].valid);
            CHECK(py.lineOrigins[(size_t)loopLine - 1].va == 0x7800);
            CHECK(py.lineOrigins[(size_t)loopLine].valid);
            CHECK(py.lineOrigins[(size_t)loopLine].va == 0x7807);
        }
        CHECK(lineWith(L, " in range(") < 0);
        CHECK(py.lineVA.size() == L.size());
        for (uint64_t va : py.lineVA) CHECK(va == 0 || (va >= 0x7800 && va < 0x7810));
    }

    {
        DecompResult c;
        c.text =
            "int ranges()\n"
            "{\n"
            "    int i = 0;\n"
            "    for (; i < 10; i++) {\n"
            "        consume(i);\n"
            "    }\n"
            "    int j = 10;\n"
            "    for (; j >= 0; j -= 2) {\n"
            "        if (skip(j)) continue;\n"
            "        consume(j);\n"
            "    }\n"
            "}\n";
        std::vector<std::string> C = splitLines(c.text);
        c.lineVA.resize(C.size(), 0);
        c.lineOrigins.resize(C.size());
        int ii = lineWith(C, "int i = 0;");
        int ij = lineWith(C, "int j = 10;");
        int ci = lineWith(C, "for (; i < 10;");
        int cj = lineWith(C, "for (; j >= 0;");
        CHECK(ii >= 0 && ij >= 0 && ci >= 0 && cj >= 0);
        if (ii >= 0) {
            c.lineVA[(size_t)ii] = 0x7FF0;
            c.lineOrigins[(size_t)ii] = { 0x7FF0, true, SourceOriginGranularity::Instruction };
        }
        if (ij >= 0) {
            c.lineVA[(size_t)ij] = 0x8008;
            c.lineOrigins[(size_t)ij] = { 0x8008, true, SourceOriginGranularity::Instruction };
        }
        if (ci >= 0) {
            c.lineVA[(size_t)ci] = 0x8000;
            c.lineOrigins[(size_t)ci] = { 0x8000, true, SourceOriginGranularity::Instruction };
        }
        if (cj >= 0) {
            c.lineVA[(size_t)cj] = 0x8010;
            c.lineOrigins[(size_t)cj] = { 0x8010, true, SourceOriginGranularity::Instruction };
        }

        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        int ri = lineWith(L, "for i in range(10):");
        int rj = lineWith(L, "for j in range(10, -1, -2):");
        CHECK(ri >= 0 && rj >= 0);
        if (ri >= 0) {
            CHECK(py.lineVA[(size_t)ri] == 0x8000);
            CHECK(ri > 0 && trimmed(L[(size_t)ri - 1]) == "# init: i = 0");
            if (ri > 0) CHECK(py.lineOrigins[(size_t)ri - 1].valid &&
                              py.lineOrigins[(size_t)ri - 1].va == 0x7FF0);
        }
        if (rj >= 0) {
            CHECK(py.lineVA[(size_t)rj] == 0x8010);
            CHECK(rj > 0 && trimmed(L[(size_t)rj - 1]) == "# init: j = 10");
            if (rj > 0) CHECK(py.lineOrigins[(size_t)rj - 1].valid &&
                              py.lineOrigins[(size_t)rj - 1].va == 0x8008);
        }
        for (const std::string& line : L) {
            CHECK(trimmed(line) != "i = 0");
            CHECK(trimmed(line) != "j = 10");
        }
        CHECK(lineWith(L, "i += 1") < 0);
        CHECK(lineWith(L, "j -= 2") < 0);
        int skip = lineWith(L, "if skip(j):");
        CHECK(skip >= 0 && (size_t)(skip + 1) < L.size());
        if (skip >= 0 && (size_t)(skip + 1) < L.size())
            CHECK(trimmed(L[(size_t)skip + 1]) == "continue");
    }

    // range() leaves the induction variable at its last yielded value, unlike a
    // C for-loop's final boundary value. Keep the explicit while when later code
    // observes that variable.
    {
        DecompResult c{
            "int observed_counter()\n"
            "{\n"
            "    i = 0;\n"
            "    for (; i < 3; i++) {\n"
            "        consume(i);\n"
            "    }\n"
            "    return i;\n"
            "}\n",
            std::vector<uint64_t>(8, 0)
        };
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(lineWith(L, "for i in range") < 0);
        CHECK(lineWith(L, "i = 0") >= 0);
        CHECK(lineWith(L, "while i < 3:") >= 0);
        CHECK(lineWith(L, "i += 1") >= 0);
        CHECK(lineWith(L, "return i") >= 0);
        CHECK(py.lineVA.size() == L.size());
    }

    // A nested header can carry the decompiler's trailing condition gloss. It
    // still counts as a nested block when proving that the range bound is stable.
    {
        DecompResult c;
        c.text =
            "int changing_bound(flag)\n"
            "{\n"
            "    limit = 5;\n"
            "    i = 0;\n"
            "    for (; i < limit; i++) {\n"
            "        if (flag) { /* flag is set */\n"
            "            use(i);\n"
            "        }\n"
            "        limit--;\n"
            "    }\n"
            "}\n";
        c.lineVA.resize(splitLines(c.text).size(), 0);
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(lineWith(L, "for i in range") < 0);
        CHECK(lineWith(L, "while i < limit:") >= 0);
        CHECK(lineWith(L, "limit -= 1") >= 0);
        CHECK(lineWith(L, "i += 1") >= 0);
        CHECK(py.lineVA.size() == L.size());
    }

    // Adjacent C labels share a body; Python expresses the same case set with an
    // OR-pattern rather than an empty, non-falling-through match arm.
    {
        DecompResult c;
        c.text =
            "int grouped_case(x)\n"
            "{\n"
            "    switch (x) {\n"
            "    case 0:\n"
            "\n"
            "    case 1:\n"
            "        use(x);\n"
            "        break;\n"
            "    default:\n"
            "        break;\n"
            "    }\n"
            "}\n";
        c.lineVA.resize(splitLines(c.text).size(), 0);
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        int grouped = lineWith(L, "case 0 | 1:");
        size_t body = grouped < 0 ? L.size() : (size_t)grouped + 1;
        while (body < L.size() && trimmed(L[body]).empty()) ++body;
        CHECK(grouped >= 0 && body < L.size());
        if (body < L.size()) CHECK(trimmed(L[body]) == "use(x)");
        CHECK(lineWith(L, "case 0:") < 0);
        CHECK(py.lineVA.size() == L.size());
    }

    // Representative "closest to source" golden. This deliberately combines
    // the display features analysts use together: typed parameters/declarations,
    // conservative range recovery, width-preserving memory access, explicit predicates,
    // a direct call, and an exact source-origin map.
    {
        DecompResult c;
        c.text =
            "int closest(const unsigned char *buf, int count)\n"
            "{\n"
            "    int total = 0;\n"
            "    int i = 0;\n"
            "    for (; i < count; i++) {\n"
            "        total += (unsigned __int8)*(buf + i);\n"
            "    }\n"
            "    if (total == 0) {\n"
            "        return false;\n"
            "    }\n"
            "    return check(total);\n"
            "}\n";
        c.lineVA = { 0, 0, 0x9000, 0x9004, 0x9008, 0x900C,
                     0, 0x9010, 0x9014, 0, 0x9018, 0 };
        c.lineOrigins.resize(c.lineVA.size());
        const std::pair<size_t, uint64_t> mapped[] = {
            { 2, 0x9000 }, { 3, 0x9004 }, { 4, 0x9008 },
            { 5, 0x900C }, { 7, 0x9010 }, { 8, 0x9014 }, { 10, 0x9018 },
        };
        for (const auto& [line, va] : mapped)
            c.lineOrigins[line] = { va, true, SourceOriginGranularity::Instruction };

        DecompResult py = DecompileToPython(c);
        const std::string expected =
            "def closest(buf, count):\n"
            "    total = 0\n"
            "    # init: i = 0\n"
            "    for i in range(count):\n"
            "        total += u8(mem[buf + i])\n"
            "    if total == 0:\n"
            "        return False\n"
            "    return check(total)\n";
        CHECK(py.text == expected);
        std::vector<std::string> lines = splitLines(py.text);
        CHECK(py.lineVA.size() == lines.size());
        CHECK(py.lineOrigins.size() == lines.size());
        const uint64_t expectedVA[] = { 0, 0x9000, 0x9004, 0x9008, 0x900C,
                                        0x9010, 0x9014, 0x9018 };
        CHECK(lines.size() == sizeof(expectedVA) / sizeof(expectedVA[0]));
        if (lines.size() == sizeof(expectedVA) / sizeof(expectedVA[0])) {
            for (size_t i = 0; i < lines.size(); ++i) {
                CHECK(py.lineVA[i] == expectedVA[i]);
                CHECK(py.lineOrigins[i].valid == (i != 0));
                if (i != 0) {
                    CHECK(py.lineOrigins[i].va == expectedVA[i]);
                    CHECK(py.lineOrigins[i].granularity ==
                          SourceOriginGranularity::Instruction);
                }
            }
        }
        const int init = lineWith(lines, "# init: i = 0");
        const int header = lineWith(lines, "for i in range(count):");
        CHECK(init >= 0 && header == init + 1);
        if (init >= 0) CHECK(py.lineOrigins[(size_t)init].valid &&
                             py.lineOrigins[(size_t)init].va == 0x9004);
        if (header >= 0) CHECK(py.lineOrigins[(size_t)header].valid &&
                               py.lineOrigins[(size_t)header].va == 0x9008);
    }

    // Completeness warnings precede the C header. Python must keep the warning as
    // a synthetic comment and still recognize the first non-comment line as the
    // function header. Exercise every structured diagnostic kind, including a
    // real instruction origin at VA zero.
    {
        const DecompileDiagnosticKind kinds[] = {
            DecompileDiagnosticKind::ClippedInput,
            DecompileDiagnosticKind::InstructionLimit,
            DecompileDiagnosticKind::DecodeFailure,
            DecompileDiagnosticKind::MissingChunk,
            DecompileDiagnosticKind::TruncatedOwnership,
            DecompileDiagnosticKind::Other,
        };
        for (DecompileDiagnosticKind kind : kinds) {
            DecompResult c;
            c.text = "// WARNING: incomplete decompilation: fixture\n"
                     "int warned_zero(void)\n"
                     "{\n"
                     "    return 0;\n"
                     "}\n";
            c.lineVA = {0, 0, 0, 0, 0};
            c.lineOrigins = {
                {},
                {0, true, SourceOriginGranularity::Instruction},
                {},
                {0, true, SourceOriginGranularity::Instruction},
                {},
            };
            c.complete = false;
            c.incompleteReason = "fixture";
            c.diagnostics.push_back({kind, "fixture"});
            DecompResult py = DecompileToPython(c);
            std::vector<std::string> lines = splitLines(py.text);
            CHECK(lineWith(lines, "# WARNING: incomplete decompilation: fixture") == 0);
            CHECK(lineWith(lines, "def warned_zero():") == 1);
            CHECK(py.lineVA.size() == lines.size());
            CHECK(py.lineOrigins.size() == lines.size());
            CHECK(!py.lineOrigins[0].valid);
            CHECK(py.lineOrigins[1].valid && py.lineOrigins[1].va == 0);
            CHECK(!py.complete && py.diagnostics.size() == 1 &&
                  py.diagnostics[0].kind == kind);
        }
    }

    // A break-only case must stay distinct from the next case. Dropping its C
    // break cannot turn the two labels into a shared Python match arm.
    {
        DecompResult c;
        c.text =
            "int distinct_cases(x)\n"
            "{\n"
            "    switch (x) {\n"
            "    case 0:\n"
            "        break;\n"
            "    case 1:\n"
            "        use(x);\n"
            "        break;\n"
            "    case 2:\n"
            "    case 3:\n"
            "        other(x);\n"
            "        break;\n"
            "    }\n"
            "}\n";
        c.lineVA.resize(splitLines(c.text).size(), 0);
        c.lineOrigins.resize(c.lineVA.size());
        c.lineOrigins[3] = {0, true, SourceOriginGranularity::Instruction};
        const DecompResult py = DecompileToPython(c);
        const std::vector<std::string> lines = splitLines(py.text);
        const int empty = lineWith(lines, "case 0:");
        CHECK(empty >= 0 && (size_t)(empty + 1) < lines.size());
        if (empty >= 0 && (size_t)(empty + 1) < lines.size()) {
            CHECK(trimmed(lines[(size_t)empty + 1]) == "pass");
            CHECK(py.lineOrigins[(size_t)empty].valid &&
                  py.lineOrigins[(size_t)empty].va == 0);
            CHECK(!py.lineOrigins[(size_t)empty + 1].valid);
        }
        CHECK(lineWith(lines, "case 1:") >= 0);
        CHECK(lineWith(lines, "case 0 | 1:") < 0);
        CHECK(lineWith(lines, "case 2 | 3:") >= 0);
        CHECK(py.lineVA.size() == lines.size());
        CHECK(py.lineOrigins.size() == lines.size());
    }

    // The step materialized before either form of continue inherits the for
    // header's available source origin, independently of the continue's origin.
    // A real header at VA zero must remain valid in both map representations.
    for (const bool conditional : {false, true}) {
        DecompResult c;
        c.text = "int continue_origin()\n{\n"
                 "    for (; i < 10; i++) {\n";
        c.text += conditional ? "        if (skip) continue;\n" : "        continue;\n";
        c.text += "    }\n}\n";
        c.lineVA = {0, 0, 0, 4, 0, 0};
        c.lineOrigins = {{}, {}, {0, true, SourceOriginGranularity::Instruction},
                         {4, true, SourceOriginGranularity::Instruction}, {}, {}};
        const DecompResult py = DecompileToPython(c);
        const std::vector<std::string> lines = splitLines(py.text);
        CHECK(py.lineVA.size() == lines.size());
        CHECK(py.lineOrigins.size() == lines.size());
        int steps = 0;
        for (size_t i = 0; i < lines.size(); ++i) {
            if (trimmed(lines[i]) == "i += 1") {
                ++steps;
                CHECK(py.lineVA[i] == 0);
                CHECK(py.lineOrigins[i].valid && py.lineOrigins[i].va == 0);
                CHECK(py.lineOrigins[i].granularity == SourceOriginGranularity::Instruction);
            }
            if (trimmed(lines[i]) == "continue") {
                CHECK(py.lineVA[i] == 4);
                CHECK(py.lineOrigins[i].valid && py.lineOrigins[i].va == 4);
            }
        }
        CHECK(steps == 2);
    }

    // Fixed-width casts can change a bound's sign and make a counter wrap at
    // the boundary. A range is safe only when these operations are proven inert.
    {
        struct TypedRangeCase {
            const char* type;
            const char* start;
            const char* comparison;
            const char* stop;
            const char* step;
            bool safeRange;
        };
        const TypedRangeCase cases[] = {
            {"uint32_t", "0", "<", "limit", "i++", false},
            {"uint32_t", "0", "<", "-1", "i++", false},
            {"int8_t", "0x80", "<", "0", "i++", false},
            {"uint8_t", "250", "<=", "255", "i++", false},
            {"int8_t", "-120", ">=", "-128", "i--", false},
            {"uint8_t", "250", "<", "255", "i += 2", false},
            {"int64_t", "0", "<=", "9223372036854775807", "i++", false},
            {"uint64_t", "0", "<=", "0xFFFFFFFFFFFFFFFF", "i++", false},
            {"uint8_t", "250", "<", "255", "i++", true},
            {"int8_t", "-120", ">", "-128", "i--", true},
        };
        for (const TypedRangeCase& test : cases) {
            DecompResult c;
            c.text = "int typed_range()\n{\n    i = " + std::string(test.start) + ";\n";
            c.text += "    for (; (" + std::string(test.type) + ")i " + test.comparison +
                      " (" + test.type + ")" + test.stop + "; " + test.step + ") {\n";
            c.text += "        consume(i);\n    }\n}\n";
            c.lineVA.resize(splitLines(c.text).size(), 0);
            c.lineOrigins.resize(c.lineVA.size());
            c.lineOrigins[3] = {0, true, SourceOriginGranularity::Instruction};
            const std::string original = c.text;
            const DecompResult py = DecompileToPython(c);
            const std::vector<std::string> lines = splitLines(py.text);
            const int range = lineWith(lines, "for i in range(");
            CHECK((range >= 0) == test.safeRange);
            if (!test.safeRange) {
                const int loop = lineWith(lines, "while ");
                CHECK(loop >= 0);
                if (loop >= 0) {
                    CHECK(lines[(size_t)loop].find("i)") != std::string::npos);
                    CHECK(py.lineOrigins[(size_t)loop].valid &&
                          py.lineOrigins[(size_t)loop].va == 0);
                }
            }
            CHECK(c.text == original);
            CHECK(py.lineVA.size() == lines.size());
            CHECK(py.lineOrigins.size() == lines.size());
        }
    }

    // Expression lowering must preserve native operators, symbol values, and
    // the pre-exchange address of an xchg memory operand. These all originate
    // in the native lifters, rather than requiring arbitrary handwritten C.
    {
        auto unchangedC = [](const DecompResult& c, const DecompResult& before) {
            CHECK(c.text == before.text);
            CHECK(c.lineVA == before.lineVA);
            CHECK(c.lineOrigins.size() == before.lineOrigins.size());
            if (c.lineOrigins.size() == before.lineOrigins.size()) {
                for (size_t i = 0; i < c.lineOrigins.size(); ++i) {
                    CHECK(c.lineOrigins[i].va == before.lineOrigins[i].va);
                    CHECK(c.lineOrigins[i].valid == before.lineOrigins[i].valid);
                    CHECK(c.lineOrigins[i].granularity == before.lineOrigins[i].granularity);
                }
            }
            CHECK(c.complete == before.complete);
            CHECK(c.incompleteReason == before.incompleteReason);
        };
        auto sameExpressionOrigin = [](const DecompResult& c, const char* cExpression,
                                       const DecompResult& py, const char* pyExpression) {
            const std::vector<std::string> cLines = splitLines(c.text);
            const std::vector<std::string> pyLines = splitLines(py.text);
            const int source = lineWith(cLines, cExpression);
            const int output = lineWith(pyLines, pyExpression);
            CHECK(source >= 0);
            CHECK(output >= 0);
            CHECK(py.lineVA.size() == pyLines.size());
            CHECK(py.lineOrigins.size() == pyLines.size());
            if (source >= 0 && output >= 0 &&
                (size_t)source < c.lineOrigins.size() &&
                (size_t)output < py.lineOrigins.size()) {
                CHECK(py.lineVA[(size_t)output] == c.lineVA[(size_t)source]);
                CHECK(py.lineOrigins[(size_t)output].va == c.lineOrigins[(size_t)source].va);
                CHECK(py.lineOrigins[(size_t)output].valid == c.lineOrigins[(size_t)source].valid);
                CHECK(py.lineOrigins[(size_t)output].granularity == c.lineOrigins[(size_t)source].granularity);
            }
            return output;
        };

        // Python assignment targets are evaluated left to right. Updating rax
        // before assigning mem[rax] silently changes the native xchg address.
        // The memory destination must be assigned before the register changes.
        struct ExchangeCase {
            uint64_t base;
            const char* operands;
            const char* expected;
        };
        const ExchangeCase exchanges[] = {
            { 0,      "rax, [rax]", "mem[rax], rax = rax, mem[rax]" },
            { 0x9000, "[rax], rax", "mem[rax], rax = rax, mem[rax]" },
            { 0x9020, "rax, [rbx + rax * 8 + 0x10]",
              "mem[rbx + rax * 8 + 0x10], rax = rax, mem[rbx + rax * 8 + 0x10]" },
            { 0x9040, "[rbx + rax * 8 + 0x10], rax",
              "mem[rbx + rax * 8 + 0x10], rax = rax, mem[rbx + rax * 8 + 0x10]" },
            { 0x9060, "eax, dword ptr [rax]", "mem[rax], eax = eax, mem[rax]" },
            { 0x9080, "rax, rbx", "rax, rbx = rbx, rax" },
        };
        for (const ExchangeCase& test : exchanges) {
            DecompileOptions opt;
            opt.deepDataFlow = false;
            const ControlFlowGraph graph = buildG({
                mk(test.base, 4, "xchg", test.operands),
                mk(test.base + 4, 1, "ret", "", true, true, 0),
            });
            const DecompResult c = DecompileWithMap(graph, opt);
            const DecompResult before = c;
            const DecompResult py = DecompileToPython(c);
            unchangedC(c, before);
            CHECK(Decompile(graph, opt) == before.text);
            const int exchanged = sameExpressionOrigin(c, "swap(", py, test.expected);
            if (exchanged >= 0 && (size_t)exchanged < py.lineOrigins.size()) {
                CHECK(py.lineOrigins[(size_t)exchanged].valid);
                CHECK(py.lineOrigins[(size_t)exchanged].va == test.base);
                CHECK(py.lineOrigins[(size_t)exchanged].granularity == SourceOriginGranularity::Instruction);
                if (!test.base) CHECK(py.lineVA[(size_t)exchanged] == 0);
            }
            CHECK(py.text.find("rax, mem[rax] =") == std::string::npos);
        }

        // Deep data flow spells native NOT as ~(value). The callable-name
        // sanitizer must retain the complement operator instead of treating ~
        // as an invalid function name and inventing a call to _(value).
        {
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            const ControlFlowGraph graph = buildG({
                mk(0x90A0, 3, "not", "rcx"),
                mk(0x90A3, 3, "mov", "rax, rcx"),
                mk(0x90A6, 1, "ret", "", true, true, 0),
            });
            const DecompResult c = DecompileWithMap(graph, opt);
            const DecompResult before = c;
            const DecompResult py = DecompileToPython(c);
            unchangedC(c, before);
            CHECK(Decompile(graph, opt) == before.text);
            sameExpressionOrigin(c, "~(a1)", py, "~(a1)");
            CHECK(c.text.find("return a1;") != std::string::npos);
            CHECK(c.text.find("return ~(a1);") == std::string::npos);
            sameExpressionOrigin(c, "return a1;", py, "return a1");
            CHECK(py.text.find("return ~(a1)") == std::string::npos);
            CHECK(py.text.find("_(a1)") == std::string::npos);
        }

        // Uppercase global symbols are real values. Successive NEG/NOT lifts
        // produce nested groups that must not be mistaken for a C type cast.
        for (const char* symbol : { "MAGIC", "checksum_t" }) {
            constexpr uint64_t address = 0x140005000ull;
            DecompileOptions opt;
            opt.target = { Arch::X64, DecompileABI::Win64 };
            opt.dataRefFor = [symbol](uint64_t candidate) {
                return candidate == address ? std::string(symbol) : std::string();
            };
            const std::string operands = "rax, [" + std::to_string(address) + "]";
            const ControlFlowGraph graph = buildG({
                mk(0x90C0, 7, "lea", operands.c_str()),
                mk(0x90C7, 3, "neg", "rax"),
                mk(0x90CA, 3, "not", "rax"),
                mk(0x90CD, 1, "ret", "", true, true, 0),
            });
            const DecompResult c = DecompileWithMap(graph, opt);
            const DecompResult before = c;
            const DecompResult py = DecompileToPython(c);
            const std::string expression = "~(-(" + std::string(symbol) + "))";
            unchangedC(c, before);
            CHECK(Decompile(graph, opt) == before.text);
            sameExpressionOrigin(c, expression.c_str(), py, expression.c_str());
        }

        // Cast recognition also has to distinguish a grouped symbolic value
        // before a comma, closing parenthesis, or subscript from a real cast.
        // Fixed-width integer conversions remain explicit after this repair.
        {
            DecompResult c;
            const char* lines[] = {
                "int grouped_values(void *ptr)",
                "{",
                "    value = ~(-(MAGIC));",
                "    pair = helper((MAGIC), (checksum_t));",
                "    nested = helper((MAGIC));",
                "    item = *(table + (MAGIC));",
                "    fixed = (uint32_t)(~(MAGIC));",
                "    handle = (HANDLE)ptr;",
                "    qualified = (const Widget *)ptr;",
                "    nested_cast = (uint32_t)(int8_t)value;",
                "    labelled_call = module~function(ptr);",
                "    complemented_call = ~helper(ptr);",
                "    return pair;",
                "}",
            };
            for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); ++i) {
                c.text += std::string(lines[i]) + "\n";
                const bool statement = i >= 2 && i + 1 < sizeof(lines) / sizeof(lines[0]);
                const uint64_t va = statement ? (i - 2) * 4 : 0;
                c.lineVA.push_back(va);
                c.lineOrigins.push_back({ va, statement,
                    statement ? SourceOriginGranularity::Instruction
                              : SourceOriginGranularity::Synthetic });
            }
            const DecompResult before = c;
            const DecompResult py = DecompileToPython(c);
            unchangedC(c, before);
            const std::pair<const char*, const char*> expected[] = {
                { "value = ~(-(MAGIC));", "value = ~(-(MAGIC))" },
                { "pair = helper((MAGIC), (checksum_t));", "pair = helper((MAGIC), (checksum_t))" },
                { "nested = helper((MAGIC));", "nested = helper((MAGIC))" },
                { "item = *(table + (MAGIC));", "item = mem[table + (MAGIC)]" },
                { "fixed = (uint32_t)(~(MAGIC));", "fixed = u32(~(MAGIC))" },
                { "handle = (HANDLE)ptr;", "handle = ptr" },
                { "qualified = (const Widget *)ptr;", "qualified = ptr" },
                { "nested_cast = (uint32_t)(int8_t)value;", "nested_cast = u32(s8(value))" },
                { "labelled_call = module~function(ptr);", "labelled_call = module_function(ptr)" },
                { "complemented_call = ~helper(ptr);", "complemented_call = ~helper(ptr)" },
            };
            for (const auto& expression : expected)
                sameExpressionOrigin(c, expression.first, py, expression.second);
            const int atZero = lineWith(splitLines(py.text), "value = ~(-(MAGIC))");
            if (atZero >= 0 && (size_t)atZero < py.lineOrigins.size()) {
                CHECK(py.lineVA[(size_t)atZero] == 0);
                CHECK(py.lineOrigins[(size_t)atZero].valid);
                CHECK(py.lineOrigins[(size_t)atZero].va == 0);
                CHECK(py.lineOrigins[(size_t)atZero].granularity == SourceOriginGranularity::Instruction);
            }
        }
    }

    // Logical values must be 0/1 even when their operands are non-boolean.
    // Python's operand-returning and/or still provide the right lazy evaluation
    // once their result is normalized. Keep source maps and quoted data intact.
    {
        DecompResult c;
        c.text =
            "int logical_values(left, right, consume)\n"
            "{\n"
            "    both = left && right;\n"
            "    either = left || right;\n"
            "    scaled = (left || right) * 3;\n"
            "    mixed = left && right || left;\n"
            "    nested = consume(left && right, right || left);\n"
            "    combined = (left || right) && (right || left);\n"
            "    if (left && right) {\n"
            "        either += left || right;\n"
            "    }\n"
            "    text = \"and or && ||\";\n"
            "    return consume(both, either, scaled, mixed, nested, combined, text);\n"
            "}\n";
        const auto source = splitLines(c.text);
        c.lineVA.resize(source.size());
        c.lineOrigins.resize(source.size());
        for (size_t i = 2; i + 1 < source.size(); ++i) {
            c.lineVA[i] = (i - 2) * 4;
            c.lineOrigins[i] = {c.lineVA[i], true, SourceOriginGranularity::Instruction};
        }
        const DecompResult before = c;
        const DecompResult py = DecompileToPython(c);
        logicalFixture += py.text;
        const auto lines = splitLines(py.text);
        const std::pair<const char*, const char*> expected[] = {
            {"both =", "both = int(bool(left and right))"},
            {"either =", "either = int(bool(left or right))"},
            {"scaled =", "scaled = (int(bool(left or right))) * 3"},
            {"mixed =", "mixed = int(bool(left and right or left))"},
            {"nested =", "nested = consume(int(bool(left and right)), int(bool(right or left)))"},
            {"combined =", "combined = int(bool((int(bool(left or right))) and (int(bool(right or left)))))"},
            {"if (left", "if left and right:"},
            {"either +=", "either += int(bool(left or right))"},
            {"text =", "text = \"and or && ||\""},
        };
        for (const auto& test : expected) {
            const int original = lineWith(source, test.first);
            const int output = lineWith(lines, test.second);
            CHECK(original >= 0 && output >= 0);
            if (original >= 0 && output >= 0) {
                CHECK(py.lineVA[(size_t)output] == c.lineVA[(size_t)original]);
                CHECK(py.lineOrigins[(size_t)output].valid);
                CHECK(py.lineOrigins[(size_t)output].va == c.lineOrigins[(size_t)original].va);
            }
        }
        CHECK(py.lineVA.size() == lines.size() && py.lineOrigins.size() == lines.size());
        CHECK(c.text == before.text && c.lineVA == before.lineVA);
        const int atZero = lineWith(lines, "both = int(bool(left and right))");
        if (atZero >= 0) CHECK(py.lineOrigins[(size_t)atZero].valid &&
                              py.lineOrigins[(size_t)atZero].va == 0);

        for (const char* operation : {"&&", "||"}) {
            DecompResult calls;
            calls.text = std::string("int logical_") + (operation[0] == '&' ? "and" : "or") +
                "(first, second)\n{\n    return first() " + operation + " second();\n}\n";
            const auto transformed = DecompileToPython(calls);
            logicalFixture += transformed.text;
            CHECK(transformed.text.find(std::string("return int(bool(first() ") +
                (operation[0] == '&' ? "and" : "or") + " second()))") != std::string::npos);
        }
    }

    // Native shift lifting makes source width, signedness, result narrowing,
    // and the architectural count mask explicit. Keep all of those casts when
    // displaying Python: unbounded Python integers otherwise hide wrong results.
    {
        DecompResult c;
        c.text =
            "int native_shift_values(a1, a2, consume)\n"
            "{\n"
            "    logical32 = (uint32_t)((uint64_t)((uint32_t)(a1)) >> 1);\n"
            "    arithmetic32 = (uint32_t)((int64_t)((int32_t)(a1)) >> 1);\n"
            "    byteleft = (uint8_t)((uint64_t)((uint8_t)(a1)) << 31);\n"
            "    wordsar = (uint16_t)((int64_t)((int16_t)(a1)) >> 31);\n"
            "    dynamic64 = (uint64_t)((uint64_t)(a2) >> ((a1) & 63));\n"
            "    highbyte = (uint8_t)((uint64_t)((uint8_t)(a1 >> 8)) >> 1);\n"
            "    return consume(logical32, arithmetic32, byteleft, wordsar, dynamic64, highbyte);\n"
            "}\n";
        const auto source = splitLines(c.text);
        c.lineVA.resize(source.size());
        c.lineOrigins.resize(source.size());
        for (size_t i = 2; i + 1 < source.size(); ++i)
            c.lineOrigins[i] = {i * 4, true, SourceOriginGranularity::Instruction};
        const auto py = DecompileToPython(c);
        logicalFixture += py.text;
        const auto lines = splitLines(py.text);
        CHECK(lineWith(lines, "logical32 = u32(u64(u32(a1)) >> 1)") >= 0);
        CHECK(lineWith(lines, "arithmetic32 = u32(s64(s32(a1)) >> 1)") >= 0);
        CHECK(lineWith(lines, "byteleft = u8(u64(u8(a1)) << 31)") >= 0);
        CHECK(lineWith(lines, "wordsar = u16(s64(s16(a1)) >> 31)") >= 0);
        CHECK(lineWith(lines, "dynamic64 = u64(u64(a2) >> ((a1) & 63))") >= 0);
        CHECK(lineWith(lines, "highbyte = u8(u64(u8(a1 >> 8)) >> 1)") >= 0);
        CHECK(py.lineVA.size() == lines.size() && py.lineOrigins.size() == lines.size());
    }

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    // Optional output lets the behavior check execute the actual transformed
    // fixture under Python; the ordinary Core runner continues to use no args.
    if (argc == 2 && std::string(argv[1]) == "--emit-logical-fixture") {
        std::printf("%s", logicalFixture.c_str());
        return 0;
    }
    std::printf("decompiler_python_test: all checks passed\n");
    return 0;
}
