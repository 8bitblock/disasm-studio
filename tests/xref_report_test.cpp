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
//   0xA1 .. .. .. ..-> mov eax, [0x2000]   (absolute data READ, length 5)
//   0xA3 .. .. .. ..-> mov [0x2000], eax   (absolute data WRITE, length 5)
//   0x8D .. .. .. ..-> lea rax, [0x2000]   (address taken, length 5)
//   0xA0            -> mov eax, [0x0]       (VA-zero data READ, length 1)
//   0xB8 imm32      -> mov eax, imm32       (immediate pointer candidate)
//   0x68 imm32      -> push imm32           (immediate pointer candidate)
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
        if (op == 0xA0) {
            out.length = 1; out.mnemonic = "mov"; out.operands = "eax, [0x0]";
            return true;
        }
        if (op == 0xA3 && n >= 5) {
            out.length = 5; out.mnemonic = "mov"; out.operands = "[0x2000], eax";
            return true;
        }
        if (op == 0x8D && n >= 5) {
            out.length = 5; out.mnemonic = "lea"; out.operands = "rax, [0x2000]";
            return true;
        }
        if ((op == 0xB8 || op == 0x68) && n >= 5) {
            uint32_t immediate = 0;
            std::memcpy(&immediate, d + 1, sizeof(immediate));
            out.length = 5;
            out.mnemonic = op == 0xB8 ? "mov" : "push";
            TypedOperand operand;
            operand.kind = OperandKind::Immediate;
            operand.access = OperandAccess::Read;
            operand.widthBits = 32;
            operand.immediate = immediate;
            out.typedOperands.push_back(std::move(operand));
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

    // Branch/call sources carry NO data-access kind; the data read defaults Read.
    CHECK(idx.accessOf.count(0x1000) == 0);
    CHECK(idx.access(0x1005) == 0);              // mov eax,[0x2000] -> Read

    // Numeric zero is a real address, not the absence of a parsed data ref.
    const uint8_t zeroRef[] = {0xA0};
    XrefIndex zero;
    CHECK(BuildXrefInto(zero, zeroRef, sizeof(zeroRef), 0x5000, dis));
    FinalizeXrefIndex(zero);
    const auto* atZero = zero.sources(0);
    CHECK(atZero && atZero->size() == 1 && (*atZero)[0] == 0x5000);
}

// Access-kind classification: read vs write vs address-taken on the same target.
static void testXrefAccessKinds() {
    StubDis dis;
    uint8_t code[15] = {0};
    code[0]  = 0xA1;     // 0x1000: mov eax, [0x2000]   -> Read
    code[5]  = 0xA3;     // 0x1005: mov [0x2000], eax   -> Write
    code[10] = 0x8D;     // 0x100A: lea rax, [0x2000]   -> Ref

    XrefIndex idx;
    BuildXrefInto(idx, code, sizeof(code), 0x1000, dis);
    FinalizeXrefIndex(idx);

    const auto* refs = idx.sources(0x2000);
    CHECK(refs && refs->size() == 3);
    CHECK(idx.access(0x1000) == 0);              // Read
    CHECK(idx.access(0x1005) == 1);              // Write
    CHECK(idx.access(0x100A) == 2);              // Ref (lea)
    CHECK(idx.access(0xDEAD) == 0);              // unknown source defaults to Read
    idx.clear();
    CHECK(idx.accessOf.empty() && idx.toTarget.empty());
}

// Whole-image sweeps should retain common crackme pointer materialization while
// leaving mapped-address ownership to the image-aware caller. Even a predicate
// that maps VA zero must not turn a bare scalar/null immediate into an xref;
// the explicit [0] memory-reference case above retains real VA-zero support.
static void testImmediatePointerXrefs() {
    StubDis dis;
    const uint8_t code[] = {
        0xB8, 0x00, 0x20, 0x00, 0x00, // mov eax, 0x2000 (mapped)
        0x68, 0x00, 0x20, 0x00, 0x00, // push 0x2000     (mapped)
        0xB8, 0x00, 0x30, 0x00, 0x00, // mov eax, 0x3000 (unmapped)
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5      (small scalar)
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0      (scalar/null)
    };
    XrefBuildLimits limits;
    limits.immediateTargetMapped = [](uint64_t target) {
        return target == 0x2000 || target == 0;
    };
    XrefIndex idx;
    CHECK(BuildXrefInto(idx, code, sizeof(code), 0x6000, dis,
                        nullptr, {}, limits));
    FinalizeXrefIndex(idx);

    const auto* mapped = idx.sources(0x2000);
    CHECK(mapped && mapped->size() == 2);
    CHECK(mapped && (*mapped)[0] == 0x6000 && (*mapped)[1] == 0x6005);
    CHECK(idx.access(0x6000) == 2 && idx.access(0x6005) == 2);
    CHECK(idx.sources(0x3000) == nullptr);
    CHECK(idx.sources(5) == nullptr);

    CHECK(idx.sources(0) == nullptr);
    CHECK(idx.accessOf.count(0x6014) == 0);
    CHECK(idx.edgeCount() == 2);
}

static void testXrefBudgetsAndCancellation() {
    StubDis dis;
    uint8_t nops[32]; std::memset(nops, 0x90, sizeof(nops));

    XrefBuildLimits byteLimits;
    byteLimits.maxBytes = 5;
    XrefIndex bytes;
    CHECK(!BuildXrefInto(bytes, nops, sizeof(nops), 0x3000, dis,
                         nullptr, {}, byteLimits));
    CHECK(!bytes.complete && bytes.stopReason == XrefStopReason::ByteBudget);
    CHECK(bytes.bytesSwept == 5 && bytes.decodeAttempts == 5);
    CHECK(std::strcmp(bytes.incompleteReason(), "byte-scan budget reached") == 0);

    XrefBuildLimits decodeLimits;
    decodeLimits.maxDecodeAttempts = 2;
    XrefIndex decodes;
    CHECK(!BuildXrefInto(decodes, nops, sizeof(nops), 0x3000, dis,
                         nullptr, {}, decodeLimits));
    CHECK(!decodes.complete && decodes.stopReason == XrefStopReason::DecodeBudget);
    CHECK(decodes.bytesSwept == 2 && decodes.decodeAttempts == 2);

    size_t cancellationChecks = 0;
    XrefBuildLimits cancelLimits;
    cancelLimits.cancellationCheckBytes = 4;
    cancelLimits.cancelled = [&] { return ++cancellationChecks >= 2; };
    XrefIndex cancelled;
    CHECK(!BuildXrefInto(cancelled, nops, sizeof(nops), 0x3000, dis,
                         nullptr, {}, cancelLimits));
    CHECK(!cancelled.complete && cancelled.stopReason == XrefStopReason::Cancelled);
    CHECK(cancelled.bytesSwept == 4 && cancellationChecks == 2);

    // Three distinct direct-call targets exercise both retained-edge and
    // target-node bounds without allocating an adversarial index.
    uint8_t calls[15] = {0};
    calls[0] = calls[5] = calls[10] = 0xE8;
    XrefBuildLimits edgeLimits;
    edgeLimits.maxEdges = 1;
    XrefIndex edges;
    CHECK(!BuildXrefInto(edges, calls, sizeof(calls), 0x4000, dis,
                         nullptr, {}, edgeLimits));
    CHECK(edges.stopReason == XrefStopReason::EdgeBudget &&
          edges.acceptedEdges == 1 && edges.edgeCount() == 1);

    XrefBuildLimits targetLimits;
    targetLimits.maxTargets = 1;
    XrefIndex targets;
    CHECK(!BuildXrefInto(targets, calls, sizeof(calls), 0x4000, dis,
                         nullptr, {}, targetLimits));
    CHECK(targets.stopReason == XrefStopReason::TargetBudget &&
          targets.toTarget.size() == 1 && targets.edgeCount() == 1);

    targets.clear();
    CHECK(targets.complete && targets.stopReason == XrefStopReason::None &&
          targets.bytesSwept == 0 && targets.decodeAttempts == 0 &&
          targets.acceptedEdges == 0);
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
    testXrefAccessKinds();
    testImmediatePointerXrefs();
    testXrefBudgetsAndCancellation();
    testReport();
    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("xref_report_test: all checks passed\n");
    return 0;
}
