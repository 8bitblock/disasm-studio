//
// jvmaware_test.cpp
// Tests for src/Core/JvmAware.h: JVM module-name recognition, the remote
// export-directory walk (FindExportRVA over a synthetic in-memory PE via a
// fake reader), and the JVM-internal exception classifier's boundary cases.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\jvmaware_test.cpp
//   .\jvmaware_test.exe
//
#include "Core/JvmAware.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }

// Synthetic 64-bit PE *image* (RVA == buffer offset) with an export directory at
// RVA 0x400 exporting `names` in order (function RVAs 0x1000 + 0x10*i).
static std::vector<uint8_t> buildExportPE(const std::vector<std::string>& names) {
    std::vector<uint8_t> b(0x2000, 0);
    b[0] = 'M'; b[1] = 'Z';
    const uint32_t e_lfanew = 0x80;
    put32(b, 0x3C, e_lfanew);
    put32(b, e_lfanew, 0x00004550);            // "PE\0\0"
    const size_t coff = e_lfanew + 4;
    put16(b, coff + 0, 0x8664);
    put16(b, coff + 2, 0);                     // no sections needed (flat image reader)
    put16(b, coff + 16, 0xF0);
    const size_t opt = coff + 20;
    put16(b, opt + 0, 0x20B);                  // PE32+
    const size_t dataDir = opt + 112;
    put32(b, dataDir - 4, 16);                 // NumberOfRvaAndSizes
    put32(b, dataDir + 0, 0x400);              // export dir RVA
    put32(b, dataDir + 4, 0x400);              // export dir size

    // IMAGE_EXPORT_DIRECTORY at 0x400.
    const size_t ed = 0x400;
    const uint32_t n = (uint32_t)names.size();
    const uint32_t funcsRVA = 0x500, namesRVA = 0x600, ordsRVA = 0x700, strRVA = 0x800;
    put32(b, ed + 20, n);                      // NumberOfFunctions
    put32(b, ed + 24, n);                      // NumberOfNames
    put32(b, ed + 28, funcsRVA);
    put32(b, ed + 32, namesRVA);
    put32(b, ed + 36, ordsRVA);
    uint32_t strOff = strRVA;
    for (uint32_t i = 0; i < n; ++i) {
        put32(b, funcsRVA + 4 * i, 0x1000 + 0x10 * i);
        put32(b, namesRVA + 4 * i, strOff);
        put16(b, ordsRVA + 2 * i, (uint16_t)i);
        std::memcpy(b.data() + strOff, names[i].c_str(), names[i].size() + 1);
        strOff += (uint32_t)names[i].size() + 1;
    }
    return b;
}

int main() {
    // ---- module-name table -------------------------------------------------
    CHECK(IsJvmModuleName("jvm.dll"));
    CHECK(IsJvmModuleName("JVM.DLL"));                                  // case-insensitive
    CHECK(IsJvmModuleName("C:\\Program Files\\Java\\jre\\bin\\server\\jvm.dll"));
    CHECK(IsJvmModuleName("j9vm.dll"));                                 // OpenJ9
    CHECK(IsJvmModuleName("jli.dll"));                                  // launcher lib
    CHECK(!IsJvmModuleName("kernel32.dll"));
    CHECK(!IsJvmModuleName("myjvm.dll"));                               // no substring match
    CHECK(!IsJvmModuleName("jvm.dll.bak"));
    CHECK(!IsJvmModuleName(""));
    // VM-proper subset: jli.dll must NOT bound JVM-internal exceptions.
    CHECK(IsJvmVmModuleName("jvm.dll"));
    CHECK(IsJvmVmModuleName("D:/jdk/bin/server/JVM.dll"));
    CHECK(IsJvmVmModuleName("j9vm.dll"));
    CHECK(!IsJvmVmModuleName("jli.dll"));
    CHECK(!IsJvmVmModuleName("java.dll"));

    // ---- FindExportRVA over a synthetic image ------------------------------
    {
        const uint64_t base = 0x7FF800000000ull;
        auto img = buildExportPE({ "JLI_Launch", "JNI_CreateJavaVM", "JNI_GetCreatedJavaVMs" });
        RemoteReader rr = [&](uint64_t va, void* out, size_t n) -> bool {
            if (va < base) return false;
            uint64_t off = va - base;
            if (off > img.size() || n > img.size() - off) return false;
            std::memcpy(out, img.data() + off, n);
            return true;
        };
        CHECK(FindExportRVA(rr, base, "JNI_CreateJavaVM") == 0x1010);   // second export
        CHECK(FindExportRVA(rr, base, "JLI_Launch")       == 0x1000);
        CHECK(FindExportRVA(rr, base, "JNI_GetCreatedJavaVMs") == 0x1020);
        CHECK(FindExportRVA(rr, base, "NotThere")         == 0);
        CHECK(FindExportRVA(rr, base, "JNI_CreateJavaV")  == 0);        // prefix must not match
        CHECK(FindExportRVA(rr, base, "")                 == 0);
        CHECK(FindExportRVA(rr, 0,    "JNI_CreateJavaVM") == 0);
        CHECK(FindExportRVA(nullptr, base, "JNI_CreateJavaVM") == 0);

        // Reader that always fails (unmapped module) -> 0, no crash.
        RemoteReader bad = [](uint64_t, void*, size_t) { return false; };
        CHECK(FindExportRVA(bad, base, "JNI_CreateJavaVM") == 0);

        // No export directory -> 0.
        auto noexp = buildExportPE({});
        put32(noexp, 0x84 + 20 + 112, 0);                               // zero the export dir RVA
        RemoteReader rr2 = [&](uint64_t va, void* out, size_t n) -> bool {
            if (va < base) return false;
            uint64_t off = va - base;
            if (off > noexp.size() || n > noexp.size() - off) return false;
            std::memcpy(out, noexp.data() + off, n);
            return true;
        };
        CHECK(FindExportRVA(rr2, base, "JNI_CreateJavaVM") == 0);

        // Hostile name count -> rejected, no spin.
        auto hostile = buildExportPE({ "JNI_CreateJavaVM" });
        put32(hostile, 0x400 + 24, 0x7FFFFFFF);                         // NumberOfNames bomb
        RemoteReader rr3 = [&](uint64_t va, void* out, size_t n) -> bool {
            if (va < base) return false;
            uint64_t off = va - base;
            if (off > hostile.size() || n > hostile.size() - off) return false;
            std::memcpy(out, hostile.data() + off, n);
            return true;
        };
        CHECK(FindExportRVA(rr3, base, "JNI_CreateJavaVM") == 0);
    }

    // ---- JVM-internal exception classifier ---------------------------------
    {
        const uint64_t jb = 0x7FFA10000000ull, js = 0x800000;
        const uint32_t AV = 0xC0000005u, ILL = 0xC000001Du;
        CHECK(IsJvmInternalException(AV,  jb,            jb, js));      // first byte
        CHECK(IsJvmInternalException(AV,  jb + js - 1,   jb, js));      // last byte
        CHECK(IsJvmInternalException(ILL, jb + 0x1234,   jb, js));
        CHECK(!IsJvmInternalException(AV,  jb + js,      jb, js));      // one past the end
        CHECK(!IsJvmInternalException(AV,  jb - 1,       jb, js));      // just below
        CHECK(!IsJvmInternalException(AV,  0x401000,     jb, js));      // user code
        CHECK(!IsJvmInternalException(0xC00000FDu, jb,   jb, js));      // stack overflow: NOT internal
        CHECK(!IsJvmInternalException(0x80000003u, jb,   jb, js));      // breakpoint: NOT internal
        CHECK(!IsJvmInternalException(AV, jb, 0, js));                  // no jvm module yet
        CHECK(!IsJvmInternalException(AV, jb, jb, 0));
    }

    if (g_fail == 0) std::printf("ALL JVMAWARE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
