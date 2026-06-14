//
// javascan_test.cpp
// Tests for src/Core/JavaScan.cpp: appended-ZIP/JAR location (EOCD + central
// directory + zipBase math), wrapper-signature detection, Main-Class
// extraction from a STORED manifest, the Authenticode-cert carve, and the
// negatives (no fabricated detections).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\javascan_test.cpp src\Core\JavaScan.cpp src\Core\BinaryFile.cpp src\Core\SigMatch.cpp
//   .\javascan_test.exe
//
#include "Core/JavaScan.h"
#include "Core/BinaryFile.h"
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
static void app16(std::vector<uint8_t>& b, uint16_t v) { size_t o = b.size(); b.resize(o + 2); put16(b, o, v); }
static void app32(std::vector<uint8_t>& b, uint32_t v) { size_t o = b.size(); b.resize(o + 4); put32(b, o, v); }
static void appS(std::vector<uint8_t>& b, const std::string& s) { b.insert(b.end(), s.begin(), s.end()); }

// ---- synthetic PE32 (same shape as binaryfile_pe_va_test) -------------------
// One ".text" section, raw [0x400,0x600). `marker` (e.g. "launch4j") is planted
// inside the section so wrapper-signature detection has something to find.
static std::vector<uint8_t> buildPE32(const char* marker = nullptr) {
    std::vector<uint8_t> b(0x600, 0);
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
    put32(b, opt + 92, 16);
    const size_t sec = opt + 0xE0;
    putstr(b, sec + 0,  ".text", 8);
    put32(b, sec + 8,  0x1000);
    put32(b, sec + 12, 0x1000);
    put32(b, sec + 16, 0x200);
    put32(b, sec + 20, 0x400);
    put32(b, sec + 36, 0x60000020u);
    if (marker) std::memcpy(b.data() + 0x480, marker, std::strlen(marker));
    return b;
}

// ---- hand-built ZIP (stored or fake-deflate entries) -------------------------
struct ZEntry { std::string name; std::string data; uint16_t method = 0; };

static std::vector<uint8_t> buildZip(const std::vector<ZEntry>& es, const std::string& comment = "") {
    std::vector<uint8_t> z;
    std::vector<uint32_t> lho;
    for (const auto& e : es) {                       // local headers + data
        lho.push_back((uint32_t)z.size());
        app32(z, 0x04034b50); app16(z, 20); app16(z, 0); app16(z, e.method);
        app16(z, 0); app16(z, 0); app32(z, 0);                       // time/date/crc
        app32(z, (uint32_t)e.data.size()); app32(z, (uint32_t)e.data.size());
        app16(z, (uint16_t)e.name.size()); app16(z, 0);
        appS(z, e.name); appS(z, e.data);
    }
    const uint32_t cdOff = (uint32_t)z.size();       // central directory
    for (size_t i = 0; i < es.size(); ++i) {
        const auto& e = es[i];
        app32(z, 0x02014b50); app16(z, 20); app16(z, 20); app16(z, 0); app16(z, e.method);
        app16(z, 0); app16(z, 0); app32(z, 0);
        app32(z, (uint32_t)e.data.size()); app32(z, (uint32_t)e.data.size());
        app16(z, (uint16_t)e.name.size()); app16(z, 0); app16(z, 0);
        app16(z, 0); app16(z, 0); app32(z, 0);
        app32(z, lho[i]);
        appS(z, e.name);
    }
    const uint32_t cdSize = (uint32_t)z.size() - cdOff;
    app32(z, 0x06054b50); app16(z, 0); app16(z, 0);  // EOCD
    app16(z, (uint16_t)es.size()); app16(z, (uint16_t)es.size());
    app32(z, cdSize); app32(z, cdOff);
    app16(z, (uint16_t)comment.size()); appS(z, comment);
    return z;
}

static bool loadBytes(BinaryFile& bf, const std::vector<uint8_t>& bytes, const char* tmp) {
    { std::ofstream f(tmp, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
    bool ok = bf.load(tmp);
    std::remove(tmp);
    return ok;
}

static const ZEntry kManifest = { "META-INF/MANIFEST.MF",
    "Manifest-Version: 1.0\r\nMain-Class: com.example.Main\r\nBuild-Jdk: 17\r\n\r\n", 0 };
static const ZEntry kClass = { "com/example/Main.class", std::string("\xCA\xFE\xBA\xBE", 4) + " fake class body", 0 };

int main() {
    // ---- helper-level: EOCD + central directory on a bare zip (zipBase 0) ----
    {
        auto z = buildZip({ kManifest, kClass });
        ZipEOCD e;
        CHECK(FindZipEOCD(z.data(), z.size(), e));
        CHECK(e.entryCount == 2);
        CHECK(e.eocdPos == z.size() - 22);
        CHECK((uint64_t)e.cdOffset + e.cdSize == e.eocdPos);   // bare zip: base 0
        std::vector<JavaZipEntry> es;
        CHECK(ParseZipCentralDir(z.data(), z.size(), e.cdOffset, e.cdSize, es));
        CHECK(es.size() == 2);
        CHECK(es[0].name == "META-INF/MANIFEST.MF" && es[0].method == 0);
        CHECK(es[1].name == "com/example/Main.class");
        CHECK(es[0].uncompSize == kManifest.data.size());
        CHECK(es[1].localHdrOff > 0);
        // EOCD with a zip comment is still found.
        auto zc = buildZip({ kManifest }, "trailing zip comment here");
        CHECK(FindZipEOCD(zc.data(), zc.size(), e));
        CHECK(e.entryCount == 1);
        // No EOCD in random data.
        std::vector<uint8_t> junk(4096, 0xAB);
        CHECK(!FindZipEOCD(junk.data(), junk.size(), e));
        // Bad CD position is rejected.
        CHECK(!ParseZipCentralDir(z.data(), z.size(), z.size() - 4, 46, es));
    }

    // ---- 1. launch4j signature + appended JAR -> 0.95, full info ----
    {
        auto pe = buildPE32("launch4j");
        auto z  = buildZip({ kManifest, kClass });
        pe.insert(pe.end(), z.begin(), z.end());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_l4j.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::Launch4j);
        CHECK(r.confidence >= 0.9f);
        CHECK(r.jarOffset == 0x600);
        CHECK(r.jarSize == z.size());
        CHECK(r.isJar);
        CHECK(r.mainClass == "com.example.Main");
        CHECK(r.entries.size() == 2);
        CHECK(!r.detail.empty());
    }

    // ---- 2. JAR overlay, no wrapper signature -> JarOverlay 0.8 ----
    {
        auto pe = buildPE32();
        auto z  = buildZip({ kManifest, kClass });
        pe.insert(pe.end(), z.begin(), z.end());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_jar.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::JarOverlay);
        CHECK(r.confidence > 0.7f && r.confidence < 0.9f);
        CHECK(r.isJar && r.jarOffset == 0x600);
    }

    // ---- 3. padded zipBase: junk between PE end and the zip ----
    {
        auto pe = buildPE32();
        pe.resize(pe.size() + 0x100, 0xEE);                    // 0x100 bytes of padding
        auto z = buildZip({ kManifest, kClass });
        pe.insert(pe.end(), z.begin(), z.end());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_pad.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::JarOverlay);
        CHECK(r.jarOffset == 0x700);                           // zipBase math, not overlay start
        CHECK(r.jarSize == z.size());
        CHECK(r.mainClass == "com.example.Main");
    }

    // ---- 4. EOCD zip comment after an appended jar ----
    {
        auto pe = buildPE32();
        auto z  = buildZip({ kManifest }, "comment after EOCD");
        pe.insert(pe.end(), z.begin(), z.end());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_cmt.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::JarOverlay);
        CHECK(r.jarOffset == 0x600 && r.jarSize == z.size());
    }

    // ---- 5. trailing Authenticode cert excluded from search + jarSize ----
    {
        auto pe = buildPE32();
        auto z  = buildZip({ kManifest, kClass });
        pe.insert(pe.end(), z.begin(), z.end());
        const uint32_t certOff = (uint32_t)pe.size(), certSize = 0x90;
        pe.resize(pe.size() + certSize, 0xCC);                 // fake cert blob at EOF
        const size_t opt = 0x84 + 20, dataDir = opt + 96;
        put32(pe, dataDir + 4 * 8,     certOff);               // dir[4] = file offset
        put32(pe, dataDir + 4 * 8 + 4, certSize);
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_cert.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::JarOverlay);
        CHECK(r.jarOffset == 0x600);
        CHECK(r.jarSize == z.size());                          // cert NOT in the carve
        CHECK(r.mainClass == "com.example.Main");
    }

    // ---- 6. ZIP without a manifest -> ZipOverlay ~0.5, isJar false ----
    {
        auto pe = buildPE32();
        auto z  = buildZip({ { "readme.txt", "hello", 0 }, { "data.bin", "world", 0 } });
        pe.insert(pe.end(), z.begin(), z.end());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_zip.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::ZipOverlay);
        CHECK(!r.isJar);
        CHECK(r.confidence > 0.3f && r.confidence < 0.7f);
        CHECK(r.mainClass.empty());
    }

    // ---- 7. deflated manifest: isJar yes, Main-Class unavailable (no inflate) ----
    {
        ZEntry deflMf = kManifest; deflMf.method = 8;          // pretend-deflate
        auto pe = buildPE32();
        auto z  = buildZip({ deflMf, kClass });
        pe.insert(pe.end(), z.begin(), z.end());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_defl.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::JarOverlay);
        CHECK(r.isJar);
        CHECK(r.mainClass.empty());
    }

    // ---- 8. manifest continuation line (72-byte wrap) is joined ----
    {
        ZEntry wrapMf = { "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\r\nMain-Class: com.example.\r\n Main\r\n\r\n", 0 };
        auto pe = buildPE32();
        auto z  = buildZip({ wrapMf, kClass });
        pe.insert(pe.end(), z.begin(), z.end());
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_wrap.bin"));
        auto r = ScanJava(bf);
        CHECK(r.isJar);
        CHECK(r.mainClass == "com.example.Main");
    }

    // ---- 9. signature alone (no archive) -> 0.6, no jar fields ----
    {
        auto pe = buildPE32("launch4j");
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_sigonly.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::Launch4j);
        CHECK(r.confidence > 0.5f && r.confidence < 0.7f);
        CHECK(r.jarSize == 0 && !r.isJar);
    }

    // ---- 10. negatives: clean PE / random overlay -> None ----
    {
        auto pe = buildPE32();
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_clean.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::None);
        CHECK(r.confidence == 0.0f && r.jarSize == 0);

        auto pe2 = buildPE32();
        for (int i = 0; i < 0x300; ++i) pe2.push_back((uint8_t)(i * 7 + 3));   // junk overlay
        BinaryFile bf2; CHECK(loadBytes(bf2, pe2, "js_junk.bin"));
        auto r2 = ScanJava(bf2);
        CHECK(r2.kind == JavaWrapKind::None);
    }

    // ---- 11. generic JVM host: JNI_CreateJavaVM string, no archive ----
    {
        auto pe = buildPE32("JNI_CreateJavaVM");
        BinaryFile bf; CHECK(loadBytes(bf, pe, "js_jni.bin"));
        auto r = ScanJava(bf);
        CHECK(r.kind == JavaWrapKind::JvmHost);
        CHECK(r.confidence > 0.5f && r.confidence < 0.7f);
    }

    if (g_fail == 0) std::printf("ALL JAVASCAN TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
