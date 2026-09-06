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
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void putU2(std::vector<uint8_t>& bytes, size_t off, uint16_t value) {
    bytes[off] = (uint8_t)(value >> 8);
    bytes[off + 1] = (uint8_t)value;
}

static void putU4(std::vector<uint8_t>& bytes, size_t off, uint32_t value) {
    bytes[off] = (uint8_t)(value >> 24);
    bytes[off + 1] = (uint8_t)(value >> 16);
    bytes[off + 2] = (uint8_t)(value >> 8);
    bytes[off + 3] = (uint8_t)value;
}

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

    // Modified UTF-8 is validated and normalized for UI-facing strings:
    // C0 80 -> UTF-8 NUL, and a UTF-16 surrogate pair -> one four-byte rune.
    {
        const uint8_t pool[] = {
            CP_Utf8, 0, 11,
            'A', 0xC0, 0x80, 0xC2, 0xA2,
            0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80,
        };
        JvmClassFile decoded;
        CHECK(ParseConstantPoolOnly(pool, sizeof(pool), 2, decoded));
        const std::string expected("A\0\xC2\xA2\xF0\x9F\x98\x80", 8);
        CHECK(decoded.utf8At(1) == expected);
        CHECK(decoded.utf8StatusAt(1) == JvmUtf8Status::Valid);
        CHECK(!decoded.hasUtf8Issues());
    }
    {
        const uint8_t rawNul[] = { CP_Utf8, 0, 1, 0 };
        const uint8_t fourByte[] = { CP_Utf8, 0, 4, 0xF0, 0x9F, 0x98, 0x80 };
        const uint8_t unpaired[] = { CP_Utf8, 0, 3, 0xED, 0xA0, 0xBD };
        const uint8_t truncatedTwo[] = { CP_Utf8, 0, 1, 0xC2 };
        const uint8_t truncatedThree[] = { CP_Utf8, 0, 2, 0xE2, 0x82 };
        const uint8_t longWithoutPad[] = { CP_Long, 0, 0, 0, 0, 0, 0, 0, 1 };
        JvmClassFile decoded;
        CHECK(ParseConstantPoolOnly(rawNul, sizeof(rawNul), 2, decoded));
        CHECK(decoded.utf8At(1) == std::string("\xEF\xBF\xBD", 3));
        CHECK(HasJvmUtf8Status(decoded.utf8StatusAt(1), JvmUtf8Status::InvalidEncoding));
        CHECK(decoded.hasUtf8Issues());

        CHECK(ParseConstantPoolOnly(fourByte, sizeof(fourByte), 2, decoded));
        CHECK(decoded.utf8At(1) == std::string("\xEF\xBF\xBD", 3));
        CHECK(HasJvmUtf8Status(decoded.utf8StatusAt(1), JvmUtf8Status::InvalidEncoding));

        CHECK(ParseConstantPoolOnly(unpaired, sizeof(unpaired), 2, decoded));
        CHECK(decoded.utf8At(1) == std::string("\xEF\xBF\xBD", 3));
        CHECK(HasJvmUtf8Status(decoded.utf8StatusAt(1), JvmUtf8Status::UnpairedSurrogate));

        CHECK(ParseConstantPoolOnly(truncatedTwo, sizeof(truncatedTwo), 2, decoded));
        CHECK(decoded.utf8At(1) == std::string("\xEF\xBF\xBD", 3));
        CHECK(HasJvmUtf8Status(decoded.utf8StatusAt(1), JvmUtf8Status::TruncatedEncoding));
        CHECK(decoded.at(1) && !decoded.at(1)->utf8EncodingValid());
        CHECK(decoded.at(1) && decoded.at(1)->utf8TextTruncated());

        CHECK(ParseConstantPoolOnly(truncatedThree, sizeof(truncatedThree), 2, decoded));
        CHECK(HasJvmUtf8Status(decoded.utf8StatusAt(1), JvmUtf8Status::TruncatedEncoding));
        CHECK(!ParseConstantPoolOnly(longWithoutPad, sizeof(longWithoutPad), 2, decoded));
    }
    {
        std::vector<uint8_t> capped = { CP_Utf8, 0x10, 0x02 }; // 4098 input bytes
        capped.insert(capped.end(), 4094, (uint8_t)'x');
        capped.insert(capped.end(), { 0xE2, 0x82, 0xAC, (uint8_t)'Z' });
        JvmClassFile decoded;
        CHECK(ParseConstantPoolOnly(capped.data(), capped.size(), 2, decoded));
        CHECK(decoded.utf8At(1) == std::string(4094, 'x')); // no split rune or later suffix
        CHECK(HasJvmUtf8Status(decoded.utf8StatusAt(1), JvmUtf8Status::OutputTruncated));
        CHECK(decoded.at(1) && decoded.at(1)->utf8EncodingValid());
        CHECK(decoded.at(1) && decoded.at(1)->utf8TextTruncated());
    }

    // ---- methodAtOffset ------------------------------------------------------
    CHECK(cf.methodAtOffset(tc.mainCodeOff) == &cf.methods[0]);
    CHECK(cf.methodAtOffset(tc.mainCodeOff + 40) == &cf.methods[0]);
    CHECK(cf.methodAtOffset(tc.mainCodeOff + 41) == nullptr);   // exception table, not code
    CHECK(cf.methodAtOffset(tc.mainCodeOff - 1) == nullptr);    // Code attr header
    CHECK(cf.methodAtOffset(tc.helperCodeOff + 2) == &cf.methods[1]);
    CHECK(cf.methodAtOffset(0) == nullptr);
    {
        // Bodyless methods keep a zero codeOffset and can appear after a later
        // concrete method; they must not break ordered code-method lookup.
        JvmClassFile mixed;
        JvmMethod first; first.codeOffset = 100; first.codeLength = 10;
        JvmMethod later; later.codeOffset = 200; later.codeLength = 10;
        JvmMethod bodyless;
        JvmMethod last; last.codeOffset = 300; last.codeLength = 10;
        mixed.methods = { first, later, bodyless, last }; // predicate was T,F,T,F at off=105
        CHECK(mixed.methodAtOffset(105) == &mixed.methods[0]);
        CHECK(mixed.methodAtOffset(205) == &mixed.methods[1]);
        CHECK(mixed.methodAtOffset(305) == &mixed.methods[3]);
        CHECK(mixed.methodAtOffset(110) == nullptr);
    }

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
    {
        // The helper Code payload may not read its exception table or nested
        // attributes from bytes following the declared parent boundary.
        auto bad = tc.bytes;
        putU4(bad, tc.helperCodeOff - 12, 11);            // ends immediately after code[]
        CHECK(!ParseJavaClass(bad.data(), bad.size()).ok);
    }
    {
        // A nested attribute must itself fit wholly inside its Code payload.
        auto bad = tc.bytes;
        putU4(bad, tc.helperCodeOff + 17, 20);            // only 10 payload bytes remain
        CHECK(!ParseJavaClass(bad.data(), bad.size()).ok);
    }
    {
        // LineNumberTable's declared payload cannot be shorter than its table.
        auto bad = tc.bytes;
        putU4(bad, tc.helperCodeOff + 17, 2);             // count present, entries spill out
        CHECK(!ParseJavaClass(bad.data(), bad.size()).ok);
    }
    {
        // Conversely, every declared Code byte must belong to its structure.
        auto bad = tc.bytes;
        putU4(bad, tc.helperCodeOff - 12, 41);            // valid payload is exactly 39 bytes
        CHECK(!ParseJavaClass(bad.data(), bad.size()).ok);
    }
    {
        // JVMS permits 1..65535 byte code arrays, never 65536. Keep enough
        // backing bytes in both cases so this tests the semantic ceiling.
        auto maxCode = tc.bytes;
        maxCode.insert(maxCode.begin() + tc.helperCodeOff + 3, 65532, 0);
        putU4(maxCode, tc.helperCodeOff - 12, 39 + 65532);
        putU4(maxCode, tc.helperCodeOff - 4, 65535);
        JvmClassFile maxParsed = ParseJavaClass(maxCode.data(), maxCode.size());
        CHECK(maxParsed.ok);
        CHECK(maxParsed.methods.size() == 2 && maxParsed.methods[1].codeLength == 65535);

        auto tooLarge = tc.bytes;
        tooLarge.insert(tooLarge.begin() + tc.helperCodeOff + 3, 65533, 0);
        putU4(tooLarge, tc.helperCodeOff - 12, 39 + 65533);
        putU4(tooLarge, tc.helperCodeOff - 4, 65536);
        CHECK(!ParseJavaClass(tooLarge.data(), tooLarge.size()).ok);
    }
    {
        // Handler and source-line PCs are bounded by code_length.
        auto badHandler = tc.bytes;
        putU2(badHandler, tc.helperCodeOff + 7, 4);       // end_pc > code_length (3)
        CHECK(!ParseJavaClass(badHandler.data(), badHandler.size()).ok);

        auto badLine = tc.bytes;
        putU2(badLine, tc.helperCodeOff + 27, 3);         // start_pc == code_length
        CHECK(!ParseJavaClass(badLine.data(), badLine.size()).ok);
    }
    {
        // The final class-attribute table is not an optional best-effort tail.
        auto truncatedPayload = tc.bytes;
        truncatedPayload.pop_back();
        CHECK(!ParseJavaClass(truncatedPayload.data(), truncatedPayload.size()).ok);

        auto missingAttribute = tc.bytes;
        putU2(missingAttribute, missingAttribute.size() - 10, 2); // declares 2, contains 1
        CHECK(!ParseJavaClass(missingAttribute.data(), missingAttribute.size()).ok);

        auto trailingByte = tc.bytes;
        trailingByte.push_back(0);
        CHECK(!ParseJavaClass(trailingByte.data(), trailingByte.size()).ok);
    }
    CHECK(!ParseJavaClass(nullptr, 0).ok);

    if (g_fail == 0) std::printf("ALL JVMCLASS TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
