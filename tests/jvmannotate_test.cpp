//
// jvmannotate_test.cpp
// Unit test for the Java bytecode annotation engine (src/Core/JvmAnnotate.cpp):
// descriptor slot math, per-opcode stack effects + deltas, branch meaning,
// operand-stack depth interpretation (over the real synthetic class), call /
// field / string extraction, API-category findings, and check-method scoring.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\jvmannotate_test.cpp ^
//      src\Core\JvmAnnotate.cpp src\Core\JvmClass.cpp src\Disasm\JvmDisassembler.cpp
//   .\jvmannotate_test.exe
//
#include "Core/JvmAnnotate.h"
#include "Core/JvmClass.h"
#include "Disasm/JvmDisassembler.h"
#include "jvm_testclass.h"

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

// ---- a tiny hand-built constant pool so we can drive the engine directly ------
// Slot layout produced by addMethodref / addFieldref below.
struct CpBuilder {
    JvmClassFile cf;
    CpBuilder() { cf.ok = true; cf.cp.resize(1); cf.thisClass = "Crackme"; }   // cp[0] unused

    uint16_t utf8(const std::string& s) { JvmCpEntry e; e.tag = CP_Utf8; e.utf8 = s; cf.cp.push_back(e); return (uint16_t)(cf.cp.size() - 1); }
    uint16_t klass(const std::string& name) { JvmCpEntry e; e.tag = CP_Class; e.a = utf8(name); cf.cp.push_back(e); return (uint16_t)(cf.cp.size() - 1); }
    uint16_t nameType(const std::string& n, const std::string& d) { JvmCpEntry e; e.tag = CP_NameAndType; e.a = utf8(n); e.b = utf8(d); cf.cp.push_back(e); return (uint16_t)(cf.cp.size() - 1); }
    uint16_t methodref(const std::string& owner, const std::string& n, const std::string& d) {
        JvmCpEntry e; e.tag = CP_Methodref; e.a = klass(owner); e.b = nameType(n, d); cf.cp.push_back(e); return (uint16_t)(cf.cp.size() - 1);
    }
    uint16_t fieldref(const std::string& owner, const std::string& n, const std::string& d) {
        JvmCpEntry e; e.tag = CP_Fieldref; e.a = klass(owner); e.b = nameType(n, d); cf.cp.push_back(e); return (uint16_t)(cf.cp.size() - 1);
    }
    uint16_t strconst(const std::string& s) { JvmCpEntry e; e.tag = CP_String; e.a = utf8(s); cf.cp.push_back(e); return (uint16_t)(cf.cp.size() - 1); }
};

static Instruction mk(uint64_t addr, const char* mnem, const std::string& ops,
                      bool call = false, bool ret = false, uint64_t target = 0) {
    Instruction in; in.address = addr; in.mnemonic = mnem; in.operands = ops;
    in.isCall = call; in.isRet = ret; in.isBranch = call || ret || target != 0; in.branchTarget = target;
    in.length = 1;
    return in;
}
static std::string cpOp(uint16_t idx) { return "#" + std::to_string(idx); }

int main() {
    // ---- 1) descriptor slot math --------------------------------------------
    {
        int a = -1, r = -1;
        CHECK(JvmDescriptorSlots("(Ljava/lang/String;I)Z", a, r) && a == 2 && r == 1);
        CHECK(JvmDescriptorSlots("(JD)V", a, r) && a == 4 && r == 0);          // long+double = 4 slots, void
        CHECK(JvmDescriptorSlots("()J", a, r) && a == 0 && r == 2);            // long return = 2
        CHECK(JvmDescriptorSlots("([Ljava/lang/String;)V", a, r) && a == 1 && r == 0);
        CHECK(!JvmDescriptorSlots("garbage", a, r));
    }

    // ---- 2) stack effects + deltas for representative opcodes ----------------
    {
        JvmClassFile empty; empty.ok = true; empty.cp.resize(1);
        auto eff = [&](const char* mn, const std::string& ops = "") {
            return JvmInstrStackEffect(empty, mk(0, mn, ops));
        };
        CHECK(eff("iconst_0").delta == 1);
        CHECK(eff("ldc2_w").delta == 2);
        CHECK(eff("pop2").delta == -2);
        CHECK(eff("dup").delta == 1);
        CHECK(eff("iadd").delta == -1);
        CHECK(eff("ladd").delta == -2);
        CHECK(eff("ifeq", "0x10").delta == -1);
        CHECK(eff("if_icmpne", "0x10").delta == -2);
        CHECK(eff("goto", "0x10").delta == 0);
        { auto r = eff("ireturn"); CHECK(r.delta == -1 && r.terminator); }
        { auto r = eff("return");  CHECK(r.delta == 0  && r.terminator); }
        { auto r = eff("athrow");  CHECK(r.terminator); }
        // The spec's canonical examples must read in plain language.
        CHECK(has(eff("ifeq", "0x10").effect, "zero"));
    }

    // ---- 3) descriptor-dependent effects via a real CP -----------------------
    {
        CpBuilder b;
        uint16_t mref  = b.methodref("java/io/PrintStream", "println", "(Ljava/lang/String;)V");
        uint16_t sref  = b.methodref("Crackme", "sum", "(JJ)J");
        uint16_t fref  = b.fieldref("Crackme", "count", "I");
        uint16_t lfref = b.fieldref("Crackme", "total", "J");
        uint16_t scon  = b.strconst("Hello");

        // invokevirtual println: objref + 1 arg slot, void -> delta -2.
        { auto e = JvmInstrStackEffect(b.cf, mk(0, "invokevirtual", cpOp(mref), true)); CHECK(e.delta == -2); CHECK(has(e.effect, "objectref")); }
        // invokestatic sum(JJ)J: 4 arg slots, 2 ret -> delta -2.
        { auto e = JvmInstrStackEffect(b.cf, mk(0, "invokestatic", cpOp(sref), true)); CHECK(e.delta == -2); CHECK(has(e.effect, "static")); }
        // getstatic count:I -> +1 ; getstatic total:J -> +2.
        CHECK(JvmInstrStackEffect(b.cf, mk(0, "getstatic", cpOp(fref))).delta == 1);
        CHECK(JvmInstrStackEffect(b.cf, mk(0, "getstatic", cpOp(lfref))).delta == 2);
        // putfield count:I -> pops value + objref -> -2.
        CHECK(JvmInstrStackEffect(b.cf, mk(0, "putfield", cpOp(fref))).delta == -2);
        // ldc of a String names it.
        { auto e = JvmInstrStackEffect(b.cf, mk(0, "ldc", cpOp(scon))); CHECK(e.delta == 1); CHECK(has(e.effect, "String")); }
    }

    // ---- 4) branch meaning ----------------------------------------------------
    {
        CHECK(has(JvmBranchMeaning(mk(0, "ifeq", "0x20", false, false, 0x20)), "zero"));
        CHECK(has(JvmBranchMeaning(mk(0, "if_icmpeq", "0x20", false, false, 0x20)), "equal"));
        CHECK(has(JvmBranchMeaning(mk(0, "ifnull", "0x20", false, false, 0x20)), "null"));
        CHECK(JvmBranchMeaning(mk(0, "goto", "0x20", false, false, 0x20)) == "jumps to 0x20");
        CHECK(JvmBranchMeaning(mk(0, "ifne", "0x20", false, false, 0x20)) ==
              "jumps to 0x20 if the top int is non-zero; otherwise falls through");
        Instruction zeroTarget = mk(4, "ifeq", "0x0");
        zeroTarget.flow.kind = FlowKind::ConditionalBranch;
        zeroTarget.flow.directTargetValid = true;
        zeroTarget.flow.directTarget = 0;
        CHECK(JvmBranchMeaning(zeroTarget) ==
              "jumps to 0x0 if the top int is zero; otherwise falls through");
        zeroTarget.flow.directTargetValid = false;
        CHECK(JvmBranchMeaning(zeroTarget) ==
              "jumps if the top int is zero; otherwise falls through");
        CHECK(JvmBranchMeaning(mk(0, "tableswitch", "")).find("falls through") == std::string::npos);
        CHECK(JvmBranchMeaning(mk(0, "iadd", "")).empty());
    }

    // ---- 5) operand-stack depth interpretation over the real synthetic class --
    {
        ClassBytes tc = jvmtest::buildTestClass();
        auto cf = std::make_shared<JvmClassFile>(ParseJavaClass(tc.bytes.data(), tc.bytes.size()));
        CHECK(cf->ok);
        JvmDisassembler dis; dis.attachClass(cf);

        // helper(): bipush 42 ; ireturn  -> depth 0->1, then return.
        const JvmMethod* helper = nullptr;
        for (const auto& m : cf->methods) if (m.name == "helper") helper = &m;
        CHECK(helper != nullptr);
        if (helper) {
            auto hi = dis.disassemble(tc.bytes.data() + helper->codeOffset, helper->codeLength, helper->codeOffset, 0);
            JvmMethodAnalysis ha = AnalyzeJvmMethod(*cf, *helper, hi);
            CHECK(ha.notes.size() == hi.size());
            CHECK(ha.notes.front().stackBefore == 0);
            CHECK(ha.notes.front().stackAfter == 1);          // bipush pushed one
            CHECK(ha.computedMaxStack == 1);
            CHECK(has(ha.notes.back().effect, "returns"));    // ireturn explained
        }

        // main(): traces 0..4; ldc "Hello"; one LOCAL call to helper.
        const JvmMethod* mainM = nullptr;
        for (const auto& m : cf->methods) if (m.name == "main") mainM = &m;
        CHECK(mainM != nullptr);
        if (mainM) {
            auto mi = dis.disassemble(tc.bytes.data() + mainM->codeOffset, mainM->codeLength, mainM->codeOffset, 0);
            JvmMethodAnalysis ma = AnalyzeJvmMethod(*cf, *mainM, mi);
            CHECK(ma.notes.front().stackBefore == 0);
            CHECK(ma.computedMaxStack == 4);                  // peak before tableswitch pops
            CHECK(ma.strings.size() == 1 && ma.strings[0].text == "Hello");
            CHECK(ma.calls.size() == 1 && ma.calls[0].local && ma.calls[0].name == "helper");
            // ldc note explains the push.
            CHECK(has(ma.notes[0].effect, "String"));
        }
    }

    // ---- 6) API-category findings + check-method scoring ---------------------
    // A synthetic isValid(String) that compares with String.equals, reads input,
    // and calls System.exit on failure — the classic crackme shape.
    {
        CpBuilder b;
        b.cf.thisClass = "Crackme";
        JvmMethod m;
        m.name = "isValid"; m.descriptor = "(Ljava/lang/String;)Z";
        m.accessFlags = JVM_ACC_PUBLIC | JVM_ACC_STATIC;
        m.codeOffset = 0; m.codeLength = 16; m.maxStack = 3; m.maxLocals = 2;

        uint16_t eqRef   = b.methodref("java/lang/String", "equals", "(Ljava/lang/Object;)Z");
        uint16_t scanRef = b.methodref("java/util/Scanner", "nextLine", "()Ljava/lang/String;");
        uint16_t urlRef  = b.methodref("java/net/URL", "openConnection", "()Ljava/net/URLConnection;");
        uint16_t exitRef = b.methodref("java/lang/System", "exit", "(I)V");
        uint16_t secret  = b.strconst("hunter2");
        uint16_t local   = b.strconst("http://127.0.0.1:8080/check?key=");
        uint16_t keep    = b.strconst("Keep-Alive");

        std::vector<Instruction> ins = {
            mk(0, "ldc", cpOp(secret)),
            mk(1, "aload_0", ""),
            mk(2, "invokevirtual", cpOp(eqRef), true),
            mk(3, "ifeq", "0xE", false, false, 0xE),
            mk(4, "invokevirtual", cpOp(scanRef), true),
            mk(5, "pop", ""),
            mk(6, "ldc", cpOp(local)),
            mk(7, "invokevirtual", cpOp(urlRef), true),
            mk(8, "pop", ""),
            mk(9, "ldc", cpOp(keep)),
            mk(10, "pop", ""),
            mk(11, "iconst_1", ""),
            mk(12, "ireturn", "", false, true),
            mk(14, "iconst_0", ""),
            mk(15, "invokestatic", cpOp(exitRef), true),
            mk(16, "iconst_0", ""),
            mk(17, "ireturn", "", false, true),
        };
        JvmMethodAnalysis a = AnalyzeJvmMethod(b.cf, m, ins);

        // String constant captured.
        CHECK(a.strings.size() == 3 && a.strings[0].text == "hunter2");
        // Calls collected with descriptors resolved.
        CHECK(a.calls.size() == 4);
        // Category findings: input + exit + localhost handoff present.
        bool input = false, exit = false, localNet = false;
        for (const JvmFinding& f : a.findings) {
            if (f.cat == JvmCat::Input) input = true;
            if (f.cat == JvmCat::Exit)  exit = true;
            if (f.cat == JvmCat::Network && has(f.text, "localhost auth")) localNet = true;
        }
        CHECK(input); CHECK(exit);
        CHECK(localNet);
        // Check-method verdict fires (name + bool return + String.equals + System.exit).
        CHECK(a.likelyCheck);
        CHECK(a.checkConfidence >= 0.5f && a.checkConfidence <= 1.0f);
        CHECK(has(a.checkEvidence, "String.equals") || has(a.checkEvidence, "validation"));
        CHECK(has(a.checkEvidence, "localhost"));
        // Branch annotation on ifeq.
        CHECK(has(a.notes[3].branch, "zero"));
        // Summary names a category and the CHECK flag.
        CHECK(has(a.summary, "CHECK"));
    }

    // ---- 7) field access extraction ------------------------------------------
    {
        CpBuilder b;
        JvmMethod m; m.name = "bump"; m.descriptor = "()V"; m.codeOffset = 0; m.codeLength = 8;
        uint16_t fref = b.fieldref("Crackme", "tries", "I");
        std::vector<Instruction> ins = {
            mk(0, "getstatic", cpOp(fref)),
            mk(1, "iconst_1", ""),
            mk(2, "iadd", ""),
            mk(3, "putstatic", cpOp(fref)),
            mk(4, "return", "", false, true),
        };
        JvmMethodAnalysis a = AnalyzeJvmMethod(b.cf, m, ins);
        CHECK(a.fields.size() == 2);
        bool sawGet = false, sawPut = false;
        for (const JvmFieldAccess& f : a.fields) {
            CHECK(f.name == "tries"); CHECK(f.isStatic);
            if (!f.put) sawGet = true; else sawPut = true;
        }
        CHECK(sawGet && sawPut);
    }

    // ---- 8) JvmCatName covers every category ---------------------------------
    for (int c = 0; c <= (int)JvmCat::Ui; ++c)
        CHECK(std::string(JvmCatName((JvmCat)c)) != "?");

    if (g_fail == 0) std::printf("jvmannotate_test: ALL PASS\n");
    else             std::printf("jvmannotate_test: %d FAIL\n", g_fail);
    return g_fail ? 1 : 0;
}
