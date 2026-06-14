//
// runtimescan_test.cpp
// Tests for src/Core/RuntimeScan.cpp (+ the BinaryFile CLR data-directory [14]
// accessors): the .NET / Electron / Unity / Python detection ladders, the
// mirrored JavaScan finding, embedded-.class scanning, the entropy heuristics,
// the wrapper verdict, and the never-fabricate negatives. JavaScanResult
// inputs are hand-filled — ScanJava is never called and JavaScan.cpp is NOT
// linked (RuntimeScan takes its result as pure data).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\runtimescan_test.cpp src\Core\RuntimeScan.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
//   .\runtimescan_test.exe
//
#include "Core/RuntimeScan.h"
#include "Core/BinaryFile.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
static void putstr(std::vector<uint8_t>& b, size_t off, const char* s, size_t cap) {
    std::memset(b.data() + off, 0, cap);
    std::memcpy(b.data() + off, s, std::min(std::strlen(s), cap));
}

// ---- synthetic PE32 (same shape as javascan_test) ---------------------------
// One ".text" section, RVA 0x1000, raw [0x400, 0x400+textRawSize). Data
// directory array sits at file offset 0xF8; NumberOfRvaAndSizes at 0xF4.
static const size_t kDataDir = 0x84 + 20 + 96;   // coff 0x84, opt 0x98 -> 0xF8
static const size_t kNumDirs = 0x84 + 20 + 92;   // NumberOfRvaAndSizes at 0xF4

static std::vector<uint8_t> buildPE32(size_t textRawSize = 0x200) {
    std::vector<uint8_t> b(0x400 + textRawSize, 0);
    b[0] = 'M'; b[1] = 'Z';
    const uint32_t e_lfanew = 0x80;
    put32(b, 0x3C, e_lfanew);
    put32(b, e_lfanew, 0x00004550);
    const size_t coff = e_lfanew + 4;
    put16(b, coff + 0,  0x014C);
    put16(b, coff + 2,  1);
    put16(b, coff + 16, 0xE0);
    put16(b, coff + 18, 0x102);
    const size_t opt = coff + 20;
    put16(b, opt + 0,  0x10B);
    put32(b, opt + 16, 0x1000);
    put32(b, opt + 28, 0x400000);
    put32(b, opt + 32, 0x1000);
    put32(b, opt + 36, 0x200);
    put32(b, opt + 56, 0x2000);
    put32(b, opt + 60, 0x400);
    put32(b, opt + 92, 16);                       // NumberOfRvaAndSizes
    const size_t sec = opt + 0xE0;
    putstr(b, sec + 0,  ".text", 8);
    put32(b, sec + 8,  (uint32_t)std::max<size_t>(textRawSize, 0x1000)); // VirtualSize
    put32(b, sec + 12, 0x1000);
    put32(b, sec + 16, (uint32_t)textRawSize);
    put32(b, sec + 20, 0x400);
    put32(b, sec + 36, 0x60000020u);
    return b;
}

static void setDir(std::vector<uint8_t>& b, int idx, uint32_t rva, uint32_t size) {
    put32(b, kDataDir + (size_t)idx * 8,     rva);
    put32(b, kDataDir + (size_t)idx * 8 + 4, size);
}
static void plant(std::vector<uint8_t>& b, size_t fileOff, const char* s) {
    std::memcpy(b.data() + fileOff, s, std::strlen(s));
}

// Imports "mscoree.dll!_CorExeMain" (PE32 layout, file offset = RVA - 0xC00):
// descriptor at RVA 0x1100, OFT 0x1140, IAT 0x1160, name 0x1180, hint/name 0x1190.
static void addMscoreeImport(std::vector<uint8_t>& b) {
    setDir(b, 1, 0x1100, 40);
    put32(b, 0x500 + 0,  0x1140);
    put32(b, 0x500 + 12, 0x1180);
    put32(b, 0x500 + 16, 0x1160);
    put32(b, 0x540, 0x1190);
    put32(b, 0x560, 0x1190);
    plant(b, 0x580, "mscoree.dll");
    plant(b, 0x590 + 2, "_CorExeMain");
}

static bool loadBytes(BinaryFile& bf, const std::vector<uint8_t>& bytes, const char* tmp) {
    { std::ofstream f(tmp, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
    bool ok = bf.load(tmp);
    std::remove(tmp);
    return ok;
}

static uint32_t g_xs = 0x12345678u;
static uint8_t xsByte() { g_xs ^= g_xs << 13; g_xs ^= g_xs >> 17; g_xs ^= g_xs << 5; return (uint8_t)g_xs; }

static const Finding* byTitle(const RuntimeScanResult& r, const char* needle) {
    for (const auto& f : r.findings)
        if (f.title.find(needle) != std::string::npos) return &f;
    return nullptr;
}
static bool hasCategory(const RuntimeScanResult& r, const char* cat) {
    for (const auto& f : r.findings) if (f.category == cat) return true;
    return false;
}

// (11) every emitted finding is honest: analyzer + detail + evidence present,
// confidence in (0,1]; the list is sorted by confidence descending.
static void checkInvariants(const RuntimeScanResult& r) {
    for (const auto& f : r.findings) {
        CHECK(!f.analyzer.empty());
        CHECK(!f.title.empty());
        CHECK(!f.category.empty());
        CHECK(!f.detail.empty());
        CHECK(!f.evidence.empty());
        CHECK(f.confidence > 0.0f && f.confidence <= 1.0f);
        for (const auto& e : f.evidence) CHECK(!e.what.empty());
    }
    for (size_t i = 1; i < r.findings.size(); ++i)
        CHECK(r.findings[i - 1].confidence >= r.findings[i].confidence);
}

int main() {
    const JavaScanResult kNoJava;   // default: kind None

    // ---- 1. CLR data directory [14] + BSJB metadata -> 0.97, definitional ----
    {
        auto pe = buildPE32();
        setDir(pe, 14, 0x1010, 0x48);            // COM descriptor dir
        put32(pe, 0x410 + 0, 0x48);              // COR20 cb
        put16(pe, 0x410 + 4, 2); put16(pe, 0x410 + 6, 5);
        put32(pe, 0x410 + 8, 0x1100);            // MetaData RVA -> file 0x500
        put32(pe, 0x410 + 12, 0x10);
        plant(pe, 0x500, "BSJB");
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_clr.bin"));
        CHECK(bf.clrDirRVA() == 0x1010);
        CHECK(bf.clrDirSize() == 0x48);
        auto r = ScanRuntimes(bf, kNoJava);
        checkInvariants(r);
        CHECK(r.findings.size() == 1);
        const Finding& f = r.findings[0];
        CHECK(f.analyzer == "RuntimeScan");
        CHECK(f.title == ".NET / CLR runtime");
        CHECK(f.category == "runtime");
        CHECK(f.confidence == 0.97f);
        CHECK(f.evidence.size() == 2);
        CHECK(f.evidence[0].what.find("data directory [14]") != std::string::npos);
        CHECK(f.evidence[0].va == 0x401010);
        CHECK(f.evidence[0].fileOffset == 0x410);
        CHECK(f.evidence[1].what.find("BSJB") != std::string::npos);
        CHECK(f.evidence[1].fileOffset == 0x500);
        CHECK(r.wrapperLikely);
        CHECK(r.wrapperRuntime == ".NET / CLR runtime");
        CHECK(r.wrapperConfidence == 0.97f);
        CHECK(!r.wrapperDetail.empty());
        CHECK(!r.isStandaloneArchive);

        // NumberOfRvaAndSizes must guard index 14 like every other directory.
        auto pe2 = buildPE32();
        put32(pe2, kNumDirs, 8);                 // header declares only 8 dirs
        setDir(pe2, 14, 0x1010, 0x48);           // bytes present but out of range
        BinaryFile bf2; CHECK(loadBytes(bf2, pe2, "rs_clr2.bin"));
        CHECK(bf2.clrDirRVA() == 0 && bf2.clrDirSize() == 0);
        auto r2 = ScanRuntimes(bf2, kNoJava);
        CHECK(r2.findings.empty());
    }

    // ---- 2. mscoree.dll!_CorExeMain import, no directory -> 0.9 ----
    {
        auto pe = buildPE32();
        addMscoreeImport(pe);
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_mscoree.bin"));
        CHECK(bf.clrDirRVA() == 0);
        auto r = ScanRuntimes(bf, kNoJava);
        checkInvariants(r);
        CHECK(r.findings.size() == 1);
        CHECK(r.findings[0].title == ".NET / CLR runtime");
        CHECK(r.findings[0].confidence == 0.9f);
        CHECK(r.findings[0].evidence[0].what == "import: mscoree.dll!_CorExeMain");
        CHECK(r.findings[0].evidence[0].va == 0x401160);   // IAT slot VA
        CHECK(r.wrapperLikely && r.wrapperConfidence == 0.9f);

        // "BSJB" string alone -> weak 0.5, not a wrapper verdict.
        auto pe2 = buildPE32();
        plant(pe2, 0x480, "BSJB");
        BinaryFile bf2; CHECK(loadBytes(bf2, pe2, "rs_bsjb.bin"));
        auto r2 = ScanRuntimes(bf2, kNoJava);
        checkInvariants(r2);
        CHECK(r2.findings.size() == 1);
        CHECK(r2.findings[0].confidence == 0.5f);
        CHECK(!r2.wrapperLikely);
    }

    // ---- 3. Electron: two signals 0.85, one signal 0.55 ----
    {
        auto pe = buildPE32();
        plant(pe, 0x480, "electron.asar");
        plant(pe, 0x4A0, "ELECTRON_RUN_AS_NODE");
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_el2.bin"));
        auto r = ScanRuntimes(bf, kNoJava);
        checkInvariants(r);
        const Finding* f = byTitle(r, "Electron/Node runtime");
        CHECK(f && f->confidence == 0.85f);
        CHECK(f && f->evidence.size() == 2);
        CHECK(f && f->evidence[0].fileOffset == 0x480);
        CHECK(f && f->evidence[0].va == 0x401080);
        CHECK(r.wrapperLikely && r.wrapperRuntime == "Electron/Node runtime");

        auto pe1 = buildPE32();
        plant(pe1, 0x480, "app.asar");
        BinaryFile bf1; CHECK(loadBytes(bf1, pe1, "rs_el1.bin"));
        auto r1 = ScanRuntimes(bf1, kNoJava);
        checkInvariants(r1);
        const Finding* f1 = byTitle(r1, "Electron/Node runtime");
        CHECK(f1 && f1->confidence == 0.55f);
        CHECK(f1 && f1->evidence.size() == 1);
        CHECK(!r1.wrapperLikely);                // 0.55 < 0.6: not asserted as a wrapper
    }

    // ---- 4. Unity / IL2CPP / Mono are independent findings ----
    {
        auto pe = buildPE32();
        plant(pe, 0x480, "UnityPlayer.dll");
        plant(pe, 0x4A0, "GameAssembly.dll");
        plant(pe, 0x4C0, "mono-2.0-bdwgc.dll");
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_unity.bin"));
        auto r = ScanRuntimes(bf, kNoJava);
        checkInvariants(r);
        const Finding* u = byTitle(r, "Unity engine");
        const Finding* i = byTitle(r, "Unity IL2CPP");
        const Finding* m = byTitle(r, "Mono runtime");
        CHECK(u && u->confidence == 0.85f);
        CHECK(i && i->confidence == 0.85f);
        CHECK(m && m->confidence == 0.75f);
        CHECK(r.wrapperLikely && r.wrapperConfidence == 0.85f);
        CHECK(r.wrapperDetail.find(";") != std::string::npos);   // joined runtime details
    }

    // ---- 5. Python ladder ----
    {
        // PyInstaller cookie -> 0.9.
        auto pe = buildPE32();
        static const uint8_t cookie[8] = { 0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E };
        std::memcpy(pe.data() + 0x4C0, cookie, sizeof(cookie));
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_pyi.bin"));
        auto r = ScanRuntimes(bf, kNoJava);
        checkInvariants(r);
        const Finding* f = byTitle(r, "Python (PyInstaller)");
        CHECK(f && f->confidence == 0.9f);
        CHECK(f && f->evidence[0].fileOffset == 0x4C0);
        CHECK(r.wrapperLikely);

        // _MEIPASS + pythonXX.dll string -> 0.85.
        auto pe2 = buildPE32();
        plant(pe2, 0x480, "python38.dll");
        plant(pe2, 0x4A0, "_MEIPASS");
        BinaryFile bf2; CHECK(loadBytes(bf2, pe2, "rs_mei.bin"));
        auto r2 = ScanRuntimes(bf2, kNoJava);
        checkInvariants(r2);
        const Finding* f2 = byTitle(r2, "Python (PyInstaller)");
        CHECK(f2 && f2->confidence == 0.85f);
        CHECK(f2 && f2->evidence.size() == 2);

        // PYTHONSCRIPT -> py2exe 0.8.
        auto pe3 = buildPE32();
        plant(pe3, 0x480, "PYTHONSCRIPT");
        BinaryFile bf3; CHECK(loadBytes(bf3, pe3, "rs_py2.bin"));
        auto r3 = ScanRuntimes(bf3, kNoJava);
        checkInvariants(r3);
        const Finding* f3 = byTitle(r3, "Python (py2exe)");
        CHECK(f3 && f3->confidence == 0.8f);

        // python DLL alone -> weak 0.55, detail says it may not be a wrapper.
        auto pe4 = buildPE32();
        plant(pe4, 0x480, "python311.dll");
        BinaryFile bf4; CHECK(loadBytes(bf4, pe4, "rs_pydll.bin"));
        auto r4 = ScanRuntimes(bf4, kNoJava);
        checkInvariants(r4);
        const Finding* f4 = byTitle(r4, "Python runtime");
        CHECK(f4 && f4->confidence == 0.55f);
        CHECK(f4 && f4->detail.find("may not be a wrapper") != std::string::npos);
        CHECK(f4 && f4->evidence[0].what.find("python311.dll") != std::string::npos);
        CHECK(!r4.wrapperLikely);
    }

    // ---- 6. hand-filled JavaScanResult is mirrored, analyzer "JavaScan" ----
    {
        auto pe = buildPE32();
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_java.bin"));
        JavaScanResult j;
        j.kind       = JavaWrapKind::Launch4j;
        j.confidence = 0.95f;
        j.detail     = "launch4j (launch4j strings) + appended JAR (2 entries, Main-Class com.example.Main)";
        j.jarOffset  = 0x600;
        j.jarSize    = 100;
        j.isJar      = true;
        j.mainClass  = "com.example.Main";
        auto r = ScanRuntimes(bf, j);
        checkInvariants(r);
        CHECK(r.findings.size() == 1);
        const Finding& f = r.findings[0];
        CHECK(f.analyzer == "JavaScan");
        CHECK(f.title == "Java runtime (launch4j)");
        CHECK(f.confidence == 0.95f);
        CHECK(f.detail == j.detail);
        CHECK(f.evidence.size() == 2);
        CHECK(f.evidence[0].fileOffset == 0x600);
        CHECK(f.evidence[1].what == "Main-Class: com.example.Main");
        CHECK(r.wrapperLikely);
        CHECK(r.wrapperRuntime == "Java (launch4j)");
        CHECK(r.wrapperConfidence == 0.95f);
    }

    // ---- 7. clean PE -> zero findings, nothing fabricated ----
    {
        auto pe = buildPE32();
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_clean.bin"));
        auto r = ScanRuntimes(bf, kNoJava);
        CHECK(r.findings.empty());
        CHECK(!r.wrapperLikely);
        CHECK(r.wrapperConfidence == 0.0f);
        CHECK(r.wrapperRuntime.empty() && r.wrapperDetail.empty());
        CHECK(!r.isStandaloneArchive);
    }

    // ---- 8. embedded CAFEBABE: reported outside a jar span, gated inside it ----
    {
        auto pe = buildPE32();
        static const uint8_t cls[8] = { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34 }; // minor 0, major 52
        std::memcpy(pe.data() + 0x4A0, cls, sizeof(cls));
        static const uint8_t bad[8] = { 0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF }; // implausible version
        std::memcpy(pe.data() + 0x4D0, bad, sizeof(bad));
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_cafe.bin"));
        auto r = ScanRuntimes(bf, kNoJava);
        checkInvariants(r);
        CHECK(r.findings.size() == 1);
        const Finding& f = r.findings[0];
        CHECK(f.category == "container");
        CHECK(f.confidence == 0.6f);
        CHECK(f.evidence.size() == 1);             // the implausible one filtered out
        CHECK(f.evidence[0].fileOffset == 0x4A0);
        CHECK(f.detail.find("outside any archive") != std::string::npos);
        CHECK(!r.wrapperLikely);                   // container, not a runtime handoff

        // Same bytes inside the declared archive span -> NOT reported.
        JavaScanResult j;
        j.kind       = JavaWrapKind::JarOverlay;
        j.confidence = 0.8f;
        j.detail     = "appended JAR (2 entries)";
        j.jarOffset  = 0x480;
        j.jarSize    = 0x100;                      // covers [0x480, 0x580)
        auto r2 = ScanRuntimes(bf, j);
        checkInvariants(r2);
        CHECK(!hasCategory(r2, "container"));
        CHECK(byTitle(r2, "Java runtime") != nullptr);
    }

    // ---- 9. entropy heuristics: overlay + section ----
    {
        // 8KB xorshift overlay -> packed 0.7.
        auto pe = buildPE32();
        for (int i = 0; i < 8192; ++i) pe.push_back(xsByte());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "rs_pack.bin"));
        auto r = ScanRuntimes(bf, kNoJava);
        checkInvariants(r);
        CHECK(r.findings.size() == 1);
        CHECK(r.findings[0].category == "packed");
        CHECK(r.findings[0].confidence == 0.7f);
        CHECK(r.findings[0].title.find("High-entropy overlay") != std::string::npos);
        CHECK(r.findings[0].evidence[0].fileOffset == 0x600);
        CHECK(!r.wrapperLikely);                   // packed != runtime handoff

        // The detected archive explains the overlay -> entropy finding suppressed.
        JavaScanResult j;
        j.kind = JavaWrapKind::JarOverlay; j.confidence = 0.8f; j.detail = "appended JAR";
        j.jarOffset = 0x600; j.jarSize = 8192;
        auto rj = ScanRuntimes(bf, j);
        CHECK(!hasCategory(rj, "packed"));

        // 8KB of zeros -> entropy 0, no finding.
        auto pe2 = buildPE32();
        pe2.resize(pe2.size() + 8192, 0);
        BinaryFile bf2; CHECK(loadBytes(bf2, pe2, "rs_zero.bin"));
        auto r2 = ScanRuntimes(bf2, kNoJava);
        CHECK(r2.findings.empty());

        // High-entropy 8KB .text section -> packed 0.5, labelled heuristic.
        auto pe3 = buildPE32(0x2000);
        for (size_t i = 0x400; i < pe3.size(); ++i) pe3[i] = xsByte();
        BinaryFile bf3; CHECK(loadBytes(bf3, pe3, "rs_sec.bin"));
        auto r3 = ScanRuntimes(bf3, kNoJava);
        checkInvariants(r3);
        const Finding* fs = byTitle(r3, "High-entropy section .text");
        CHECK(fs != nullptr);
        CHECK(fs && fs->confidence == 0.5f);
        CHECK(fs && fs->detail.find("compressed resources also look like this") != std::string::npos);
        CHECK(fs && fs->evidence[0].fileOffset == 0x400);
    }

    // ---- 10. ShannonEntropy directly ----
    {
        CHECK(ShannonEntropy(nullptr, 0) == 0.0);
        std::vector<uint8_t> flat(4096, 0x41);
        CHECK(ShannonEntropy(flat.data(), flat.size()) == 0.0);
        std::vector<uint8_t> rnd(65536);
        for (auto& b : rnd) b = xsByte();
        const double h = ShannonEntropy(rnd.data(), rnd.size());
        CHECK(h > 7.9 && h <= 8.0);
    }

    // ---- 12. PK at offset 0: a standalone archive, never a wrapper ----
    {
        std::vector<uint8_t> zip(64, 0);
        zip[0] = 'P'; zip[1] = 'K'; zip[2] = 3; zip[3] = 4;
        BinaryFile bf; CHECK(loadBytes(bf, zip, "rs_zip.bin"));
        auto r = ScanRuntimes(bf, kNoJava);
        CHECK(r.isStandaloneArchive);
        CHECK(!r.wrapperLikely);

        std::vector<uint8_t> eocd(22, 0);
        eocd[0] = 'P'; eocd[1] = 'K'; eocd[2] = 5; eocd[3] = 6;   // empty zip: bare EOCD
        BinaryFile bf2; CHECK(loadBytes(bf2, eocd, "rs_eocd.bin"));
        auto r2 = ScanRuntimes(bf2, kNoJava);
        CHECK(r2.isStandaloneArchive);
        CHECK(!r2.wrapperLikely);
    }

    if (g_fail == 0) std::printf("ALL RUNTIMESCAN TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
