//
// decompiler_python_test.cpp
// Tests for DecompileToPython (src/Core/Decompiler.cpp): the pure C->Python
// pseudocode translation behind the Pseudocode view's language selector.
// Asserts that
//   (1) a synthetic, exactly-shaped pseudo-C result translates to the expected
//       Python text (def/if/while True/match, no braces, decls dropped,
//       *(X) -> mem[X], x-- -> x -= 1, casts stripped, switch-break dropped);
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

static int lineWith(const std::vector<std::string>& L, const char* sub) {
    for (size_t i = 0; i < L.size(); ++i) if (L[i].find(sub) != std::string::npos) return (int)i;
    return -1;
}

static std::string trimmed(const std::string& l) {
    size_t a = l.find_first_not_of(" \t");
    size_t b = l.find_last_not_of(" \t");
    return a == std::string::npos ? std::string() : l.substr(a, b - a + 1);
}

int main() {
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
        CHECK(lineWith(L, "if v0 <= 0: break") >= 0);              // one-liner if
        int m = lineWith(L, "match a2:");
        int c0 = lineWith(L, "case 0:");
        CHECK(m >= 0 && c0 >= 0 && c0 > m);
        if (m >= 0 && c0 >= 0) {                                   // case indented INTO the match
            size_t mi = L[m].find_first_not_of(' ');
            size_t ci = L[c0].find_first_not_of(' ');
            CHECK(ci > mi);
        }
        // The case-ending breaks are dropped (match has no fallthrough); the only
        // break left is the loop's, which lives on the one-liner `if` checked above.
        int nBreak = 0;
        for (const auto& l : L) if (trimmed(l) == "break") ++nBreak;
        CHECK(nBreak == 0);
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
        CHECK(lineWith(L, "if a1 < 0: goto loc_2000  # tail") >= 0);   // cast stripped, comment kept
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
        CHECK(lineWith(L, "(rdx, rax) // rcx") >= 0);                  // pair + integer division
        CHECK(lineWith(L, "goto loc_1234") >= 0);                      // bare goto survives
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
        CHECK(lineWith(L, "c = (p != None)") >= 0);
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
        CHECK(lineWith(L, "v0 = mem[a1]") >= 0);
        CHECK(lineWith(L, "v1 = mem[a1 + 2]") >= 0);
        CHECK(lineWith(L, "v2 = (a2)(v0)") >= 0);
        CHECK(lineWith(L, "v3 = (mem[a1 + 8])(v1)") >= 0);
        CHECK(py.text.find("__int8") == std::string::npos);
        CHECK(py.text.find("__int16") == std::string::npos);
        CHECK(py.text.find("(*") == std::string::npos);
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
        int c0 = lineWith(L, "case 0:");
        CHECK(c0 >= 0 && (size_t)(c0 + 1) < L.size() && trimmed(L[(size_t)c0 + 1]) == "pass");
        if (c0 >= 0) CHECK(py.lineVA[(size_t)c0 + 1] == 0x3010); // synthetic pass maps to case/header VA
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

    // The deep emitter really produces the Microsoft-width casts above for
    // movzx/movsx. Exercise the full CFG -> data flow -> Python path so the two
    // sides cannot silently drift apart.
    {
        std::vector<Instruction> ins;
        ins.push_back(mk(0x4000, 3, "movzx", "eax, byte ptr [rcx]"));
        ins.push_back(mk(0x4003, 1, "ret", "", true, true, 0));
        ControlFlowGraph g = buildG(ins);
        DecompileOptions opt;
        DecompResult c = DecompileWithMap(g, opt);
        CHECK(c.text.find("(unsigned __int8)") != std::string::npos);
        DecompResult py = DecompileToPython(c);
        std::vector<std::string> L = splitLines(py.text);
        CHECK(py.lineVA.size() == L.size());
        CHECK(py.text.find("__int8") == std::string::npos);
        CHECK(lineWith(L, "mem[a1]") >= 0);
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
        CHECK(lineWith(L, "first = 1; second = helper(1, 2)") >= 0);
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
        CHECK(lineWith(L, "r6 = left and not right or other") >= 0);
        CHECK(lineWith(L, "r7 = obj.ready(local)") >= 0);
        CHECK(lineWith(L, "r8 = read_file(local)") >= 0);
        CHECK(lineWith(L, "r9 = left and predicate(local)") >= 0);
        CHECK(lineWith(L, "literal = 'x&&y->z'") >= 0);       // operator text in a char literal is opaque
        int local = lineWith(L, "local = 7");
        if (local >= 0) CHECK(py.lineVA[(size_t)local] == 0x5002);
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

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("decompiler_python_test: all checks passed\n");
    return 0;
}
