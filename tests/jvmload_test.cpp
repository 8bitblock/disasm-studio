//
// jvmload_test.cpp
// Off-target tests for the BinaryFile JavaClass loader + FunctionAnalyzer's
// JVM method seeding: 0xCAFEBABE detection, identity VA<->offset mapping,
// per-method executable sections, entry-point selection (static main), the
// whole-file backing section, raw fallback for a corrupt pool, and the
// method-table-driven function list (exact names/sizes, no x86 heuristics).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\jvmload_test.cpp src\Core\JvmClass.cpp ^
//      src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp src\Disasm\JvmDisassembler.cpp
//   .\jvmload_test.exe
//
#include "Core/BinaryFile.h"
#include "Core/FunctionAnalyzer.h"
#include "Core/JvmClass.h"
#include "Disasm/JvmDisassembler.h"
#include "jvm_testclass.h"

#include <cstdio>
#include <fstream>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static bool writeTemp(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write((const char*)bytes.data(), (std::streamsize)bytes.size());
    return (bool)f;
}

int main() {
    ClassBytes tc = jvmtest::buildTestClass();
    const std::string tmp = "jvmload_test_Main.class";
    CHECK(writeTemp(tmp, tc.bytes));

    BinaryFile bf;
    CHECK(bf.load(tmp));
    std::remove(tmp.c_str());

    CHECK(bf.format() == BinFormat::JavaClass);
    CHECK(std::string(bf.formatName()) == "Java class");
    CHECK(bf.machine() == MachineArch::JVM);
    CHECK(!bf.is64Bit());
    CHECK(bf.imageBase() == 0);
    CHECK(bf.entryPoint() == tc.mainCodeOff);              // static main wins
    CHECK(bf.javaClass() && bf.javaClass()->thisClass == "Main");

    // ---- sections: one executable per method body + the whole-file backing ----
    {
        const auto& secs = bf.sections();
        CHECK(secs.size() == 3);
        if (secs.size() == 3) {
            CHECK(secs[0].name == "Main.main" && secs[0].executable);
            CHECK(secs[0].virtualAddress == tc.mainCodeOff && secs[0].virtualSize == 41);
            CHECK(secs[1].name == "Main.helper" && secs[1].executable);
            CHECK(secs[1].virtualAddress == tc.helperCodeOff && secs[1].virtualSize == 3);
            CHECK(secs[2].name == "classfile" && !secs[2].executable);
            CHECK(secs[2].virtualSize == tc.bytes.size());
        }
        const Section* first = bf.firstCodeSection();
        CHECK(first && first->name == "Main.main");
    }

    // ---- identity VA <-> offset mapping ----------------------------------------
    {
        size_t avail = 0;
        const uint8_t* p = bf.ptrFromVA(tc.mainCodeOff, avail);
        CHECK(p && avail == 41);                           // method section caps the span
        CHECK(p == bf.bytes().data() + tc.mainCodeOff);
        p = bf.ptrFromVA(0, avail);                        // header: whole-file section
        CHECK(p == bf.bytes().data() && avail == bf.bytes().size());

        uint64_t off = 0, va = 0;
        CHECK(bf.vaToOffset(tc.mainCodeOff + 5, off) && off == tc.mainCodeOff + 5);
        CHECK(bf.offsetToVA(7, va) && va == 7);
        CHECK(!bf.vaToOffset(tc.bytes.size() + 100, off)); // past EOF: unmapped
    }

    // ---- patches reach the image (the patch system path) ------------------------
    {
        const uint8_t nop = 0x00;
        const uint64_t rev = bf.imageRevision();
        CHECK(bf.writeImage(tc.mainCodeOff, &nop, 1) == 1);
        CHECK(bf.bytes()[tc.mainCodeOff] == 0x00);
        CHECK(bf.imageRevision() > rev);
    }

    // ---- FunctionAnalyzer: method table is authoritative -------------------------
    {
        JvmDisassembler dis;
        dis.attachClass(bf.javaClass());
        FunctionAnalyzer fa;
        auto fns = fa.analyze(bf, dis);
        CHECK(fns.size() == 2);
        if (fns.size() == 2) {
            CHECK(fns[0].address == tc.mainCodeOff);
            CHECK(fns[0].size == 41);
            CHECK(fns[0].name == "Main.main" && fns[0].isExport);
            CHECK(fns[1].address == tc.helperCodeOff);
            CHECK(fns[1].size == 3);
            CHECK(fns[1].name == "Main.helper" && fns[1].isExport);
        }
        CHECK(fa.lastSummary().find("class file") != std::string::npos);
    }

    // ---- corrupt pool: clean Raw fallback, not a crash ---------------------------
    {
        auto bad = tc.bytes;
        bad[10] = 99;                                      // unknown cp tag
        const std::string tmp2 = "jvmload_test_bad.class";
        CHECK(writeTemp(tmp2, bad));
        BinaryFile b2;
        CHECK(b2.load(tmp2));                              // still loads...
        std::remove(tmp2.c_str());
        CHECK(b2.format() == BinFormat::Raw);              // ...as a raw blob
        CHECK(!b2.javaClass());
    }

    if (g_fail == 0) std::printf("ALL JVMLOAD TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
