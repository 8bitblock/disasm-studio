//
// xref_report_test.cpp
// Off-target unit tests for the two new pure-logic Core modules:
//   - XrefIndex (src/Core/XrefIndex.*): the whole-program cross-reference index.
//   - Report    (src/Core/Report.*):    Markdown / HTML analysis-report rendering.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\xref_report_test.cpp src\Core\XrefIndex.cpp src\Core\Report.cpp
//   .\xref_report_test.exe
// (or g++ -std=c++20 -I src tests/xref_report_test.cpp src/Core/XrefIndex.cpp src/Core/Report.cpp)
//
#include "Core/XrefIndex.h"
#include "Core/Report.h"
#include "Disasm/IDisassembler.h"

#include <cstdio>
#include <cstring>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// A tiny stub decoder over a toy encoding, enough to exercise the xref sweep:
//   0xE8 rel32      -> call,  branchTarget = va + 5 + rel32
//   0xE9 rel32      -> jmp,   branchTarget = va + 5 + rel32
//   0xA1 .. .. .. ..-> mov eax, [0x2000]   (absolute data ref, length 5)
//   anything else   -> nop                 (length 1, no refs)
struct StubDis : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "stub"; }
    std::vector<Instruction> disassemble(const uint8_t*, size_t, uint64_t, size_t) override { return {}; }
    bool decodeOne(const uint8_t* d, size_t n, uint64_t va, Instruction& out) override {
        if (n == 0) return false;
        out = Instruction{};
        out.address = va;
        uint8_t op = d[0];
        if ((op == 0xE8 || op == 0xE9) && n >= 5) {
            int32_t rel = 0; std::memcpy(&rel, d + 1, 4);
            out.length = 5; out.isBranch = true; out.isCall = (op == 0xE8);
            out.mnemonic = out.isCall ? "call" : "jmp";
            out.branchTarget = va + 5 + (int64_t)rel;
            return true;
        }
        if (op == 0xA1 && n >= 5) {
            out.length = 5; out.mnemonic = "mov"; out.operands = "eax, [0x2000]";
            return true;
        }
        out.length = 1; out.mnemonic = "nop";
        return true;
    }
};

static bool contains(const std::string& h, const char* needle) {
    return h.find(needle) != std::string::npos;
}

static void testXref() {
    // base 0x1000. Lay out: call->0x1015 ; mov eax,[0x2000] ; call->0x1015 ; nop
    StubDis dis;
    uint8_t code[16] = {0};
    // off 0: E8 rel32 -> target 0x1015 => rel = 0x1015 - (0x1000+5) = 0x10
    code[0] = 0xE8; code[1] = 0x10; code[2] = 0; code[3] = 0; code[4] = 0;
    // off 5: A1 (mov eax,[0x2000]); 4 trailing bytes ignored by the stub
    code[5] = 0xA1; code[6] = 0; code[7] = 0; code[8] = 0; code[9] = 0;
    // off 10: E8 rel32 -> target 0x1015 => rel = 0x1015 - (0x100A+5) = 6
    code[10] = 0xE8; code[11] = 0x06; code[12] = 0; code[13] = 0; code[14] = 0;
    // off 15: nop
    code[15] = 0x90;

    XrefIndex idx;
    BuildXrefInto(idx, code, sizeof(code), 0x1000, dis);
    FinalizeXrefIndex(idx);

    const auto* callers = idx.sources(0x1015);
    CHECK(callers != nullptr);
    CHECK(callers && callers->size() == 2);
    CHECK(callers && (*callers)[0] == 0x1000);   // sorted
    CHECK(callers && (*callers)[1] == 0x100A);

    const auto* dataRefs = idx.sources(0x2000);
    CHECK(dataRefs != nullptr);
    CHECK(dataRefs && dataRefs->size() == 1);
    CHECK(dataRefs && (*dataRefs)[0] == 0x1005);

    CHECK(idx.sources(0xDEAD) == nullptr);       // unreferenced target
    CHECK(idx.edgeCount() == 3);

    // Idempotent finalize (sort/unique must not duplicate or drop).
    FinalizeXrefIndex(idx);
    CHECK(idx.sources(0x1015)->size() == 2);
}

static void testReport() {
    ReportInput in;
    in.title = "demo.exe";
    in.hashHex = "ABCD1234";
    in.arch = "x64"; in.engine = "Zydis";
    in.functionCount = 12; in.stringCount = 34;
    in.renames   = { { 0x1000, "main" }, { 0x1100, "helper" } };
    in.comments  = { { 0x1004, "entry check < 0" } };   // '<' must be HTML-escaped
    in.bookmarks = { { 0x1100, "interesting" } };
    in.notes     = "first pass notes";
    ReportFunction f; f.address = 0x1000; f.name = "main";
    f.signature = "int main(int, char**)"; f.pseudocode = "return 0;";
    in.functions.push_back(f);

    std::string md = RenderReportMarkdown(in);
    CHECK(contains(md, "# Analysis report: demo.exe"));
    CHECK(contains(md, "`ABCD1234`"));
    CHECK(contains(md, "0x1000"));
    CHECK(contains(md, "main"));
    CHECK(contains(md, "entry check < 0"));    // raw in markdown
    CHECK(contains(md, "```c"));
    CHECK(contains(md, "return 0;"));

    std::string html = RenderReportHtml(in);
    CHECK(contains(html, "<h1>Analysis report: demo.exe</h1>"));
    CHECK(contains(html, "entry check &lt; 0"));   // '<' escaped
    CHECK(!contains(html, "entry check < 0"));      // ...and not present raw
    CHECK(contains(html, "<pre>return 0;</pre>"));
    CHECK(contains(html, "ABCD1234"));
}

int main() {
    testXref();
    testReport();
    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("xref_report_test: all checks passed\n");
    return 0;
}
