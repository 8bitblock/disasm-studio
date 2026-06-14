//
// jvmclass_test.cpp
// Off-target tests for src/Core/JvmClass.cpp: constant-pool parsing (incl.
// double-slot Long/Double), method/Code-attribute extraction with exact file
// offsets, exception tables + LineNumberTable, describeCp text, descriptor
// pretty-printing, and hostile-input rejection.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\jvmclass_test.cpp src\Core\JvmClass.cpp
//   .\jvmclass_test.exe
//
#include "Core/JvmClass.h"
#include "jvm_testclass.h"

#include <cstdio>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    ClassBytes tc = jvmtest::buildTestClass();
    const uint8_t* p = tc.bytes.data();
    const size_t   n = tc.bytes.size();

    CHECK(IsJavaClassImage(p, n));
    CHECK(!IsJavaClassImage(p, 6));                       // too short
    {
        auto bad = tc.bytes; bad[7] = 200;                // major version 200: implausible
        CHECK(!IsJavaClassImage(bad.data(), bad.size()));
    }

    JvmClassFile cf = ParseJavaClass(p, n);
    CHECK(cf.ok);
    CHECK(cf.majorVersion == 52);
    CHECK(cf.thisClass == "Main");
    CHECK(cf.superClass == "java/lang/Object");
    CHECK(cf.sourceFile == "Main.java");
    CHECK(cf.accessFlags == 0x0021);
    CHECK(cf.interfaces.empty() && cf.fields.empty());

    // ---- methods + Code attributes -----------------------------------------
    CHECK(cf.methods.size() == 2);
    if (cf.methods.size() == 2) {
        const JvmMethod& m0 = cf.methods[0];
        CHECK(m0.name == "main");
        CHECK(m0.descriptor == "([Ljava/lang/String;)V");
        CHECK((m0.accessFlags & JVM_ACC_STATIC) != 0);
        CHECK(m0.codeOffset == tc.mainCodeOff);
        CHECK(m0.codeLength == 41);
        CHECK(m0.maxStack == 2 && m0.maxLocals == 2);
        CHECK(m0.handlers.empty());

        const JvmMethod& m1 = cf.methods[1];
        CHECK(m1.name == "helper");
        CHECK(m1.descriptor == "()I");
        CHECK(m1.codeOffset == tc.helperCodeOff);
        CHECK(m1.codeLength == 3);
        CHECK(m1.handlers.size() == 1);
        if (!m1.handlers.empty()) {
            CHECK(m1.handlers[0].startPC == 0 && m1.handlers[0].endPC == 2);
            CHECK(m1.handlers[0].handlerPC == 2 && m1.handlers[0].catchTypeIndex == 0);
        }
        CHECK(m1.lineNumbers.size() == 2);
        CHECK(JvmClassFile::lineForBci(m1, 0) == 10);
        CHECK(JvmClassFile::lineForBci(m1, 1) == 10);     // between entries: previous wins
        CHECK(JvmClassFile::lineForBci(m1, 2) == 11);
    }

    // ---- constant-pool resolution -------------------------------------------
    CHECK(cf.describeCp(2)  == "\"Hello\"");              // String
    CHECK(cf.describeCp(12) == "Main.helper:()I");        // local Methodref
    CHECK(cf.describeCp(18) == "java/io/PrintStream.println:(Ljava/lang/String;)V");
    CHECK(cf.describeCp(19) == "42");                     // Integer
    CHECK(cf.describeCp(20) == "123456789L");             // Long (double slot)
    CHECK(cf.describeCp(26) == "2.5f");                   // Float
    CHECK(cf.describeCp(27) == "3.5");                    // Double
    CHECK(cf.describeCp(21).empty());                     // Long's pad slot
    CHECK(cf.describeCp(0).empty() && cf.describeCp(999).empty());
    CHECK(cf.classNameAt(4) == "Main");
    CHECK(cf.utf8At(7) == "main");

    // ---- methodAtOffset ------------------------------------------------------
    CHECK(cf.methodAtOffset(tc.mainCodeOff) == &cf.methods[0]);
    CHECK(cf.methodAtOffset(tc.mainCodeOff + 40) == &cf.methods[0]);
    CHECK(cf.methodAtOffset(tc.mainCodeOff + 41) == nullptr);   // exception table, not code
    CHECK(cf.methodAtOffset(tc.mainCodeOff - 1) == nullptr);    // Code attr header
    CHECK(cf.methodAtOffset(tc.helperCodeOff + 2) == &cf.methods[1]);
    CHECK(cf.methodAtOffset(0) == nullptr);

    // ---- descriptor pretty-printing ------------------------------------------
    CHECK(JvmPrettyMethod("main", "([Ljava/lang/String;)V") == "void main(String[])");
    CHECK(JvmPrettyMethod("f", "(I[JLjava/lang/String;)D") == "double f(int, long[], String)");
    CHECK(JvmPrettyMethod("g", "()V") == "void g()");
    CHECK(JvmPrettyMethod("weird", "not-a-descriptor") == "weirdnot-a-descriptor");
    CHECK(JvmShortClassName("com/example/Main") == "Main");
    CHECK(JvmShortClassName("Main") == "Main");

    // ---- hostile inputs -------------------------------------------------------
    {
        auto bad = tc.bytes;
        bad[10] = 99;                                     // first cp entry: unknown tag
        CHECK(!ParseJavaClass(bad.data(), bad.size()).ok);
    }
    {
        // Truncations at every prefix must fail cleanly, never crash/UB.
        for (size_t cut : {12u, 40u, 100u, 200u})
            if (cut < n) { JvmClassFile c2 = ParseJavaClass(p, cut); CHECK(!c2.ok); }
    }
    CHECK(!ParseJavaClass(nullptr, 0).ok);

    if (g_fail == 0) std::printf("ALL JVMCLASS TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
