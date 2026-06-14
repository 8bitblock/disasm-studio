//
// zipextract_test.cpp
// Tests for ExtractZipEntry (src/Core/JavaScan.cpp + src/Core/Inflate.cpp):
// STORED and DEFLATE entry extraction, local-header math (name/extra lengths
// from the LOCAL header, sizes from the central directory), zips embedded at a
// nonzero file offset, and the failure paths (bad local sig, truncated data,
// unsupported method, size mismatch).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\zipextract_test.cpp src\Core\JavaScan.cpp
//      src\Core\Inflate.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\SigMatch.cpp
//   .\zipextract_test.exe
//
#include "Core/JavaScan.h"
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
static void app16(std::vector<uint8_t>& b, uint16_t v) { size_t o = b.size(); b.resize(o + 2); put16(b, o, v); }
static void app32(std::vector<uint8_t>& b, uint32_t v) { size_t o = b.size(); b.resize(o + 4); std::memcpy(b.data() + o, &v, 4); }
static void appS(std::vector<uint8_t>& b, const std::string& s) { b.insert(b.end(), s.begin(), s.end()); }

// ---- hand-built ZIP (same shape as javascan_test's buildZip, plus a
// local-header-only extra field so the LOCAL-vs-CD length split is exercised).
struct ZEntry {
    std::string name;
    std::string data;          // bytes as stored in the file (compressed for method 8)
    uint16_t    method = 0;
    uint32_t    uncompSize = 0; // 0 -> data.size() (stored)
    std::string localExtra;     // written ONLY in the local header (CD extraLen stays 0)
};

static std::vector<uint8_t> buildZip(const std::vector<ZEntry>& es) {
    std::vector<uint8_t> z;
    std::vector<uint32_t> lho;
    for (const auto& e : es) {                       // local headers + data
        const uint32_t un = e.uncompSize ? e.uncompSize : (uint32_t)e.data.size();
        lho.push_back((uint32_t)z.size());
        app32(z, 0x04034b50); app16(z, 20); app16(z, 0); app16(z, e.method);
        app16(z, 0); app16(z, 0); app32(z, 0);                       // time/date/crc
        app32(z, (uint32_t)e.data.size()); app32(z, un);
        app16(z, (uint16_t)e.name.size()); app16(z, (uint16_t)e.localExtra.size());
        appS(z, e.name); appS(z, e.localExtra); appS(z, e.data);
    }
    const uint32_t cdOff = (uint32_t)z.size();       // central directory
    for (size_t i = 0; i < es.size(); ++i) {
        const auto& e = es[i];
        const uint32_t un = e.uncompSize ? e.uncompSize : (uint32_t)e.data.size();
        app32(z, 0x02014b50); app16(z, 20); app16(z, 20); app16(z, 0); app16(z, e.method);
        app16(z, 0); app16(z, 0); app32(z, 0);
        app32(z, (uint32_t)e.data.size()); app32(z, un);
        app16(z, (uint16_t)e.name.size()); app16(z, 0); app16(z, 0);
        app16(z, 0); app16(z, 0); app32(z, 0);
        app32(z, lho[i]);
        appS(z, e.name);
    }
    const uint32_t cdSize = (uint32_t)z.size() - cdOff;
    app32(z, 0x06054b50); app16(z, 0); app16(z, 0);  // EOCD
    app16(z, (uint16_t)es.size()); app16(z, (uint16_t)es.size());
    app32(z, cdSize); app32(z, cdOff);
    app16(z, 0);
    return z;
}

// EOCD + CD walk + zipBase recovery (the ScanJava math) over an arbitrary buffer.
static bool listEntries(const std::vector<uint8_t>& buf, uint64_t& zipBase,
                        std::vector<JavaZipEntry>& es) {
    ZipEOCD e;
    if (!FindZipEOCD(buf.data(), buf.size(), e)) return false;
    const uint64_t cdEnd = (uint64_t)e.cdOffset + e.cdSize;
    if (cdEnd > e.eocdPos) return false;
    zipBase = e.eocdPos - cdEnd;
    return ParseZipCentralDir(buf.data(), buf.size(), zipBase + e.cdOffset, e.cdSize, es);
}

// ---- python3 zipfile-generated zip: one ZIP_DEFLATED entry ------------------
//   zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED).writestr('Hello.class',
//       b'The quick brown fox jumps over the lazy dog. ' * 24)   # 1080 bytes
// entry: method 8, compSize 58, uncompSize 1080, localHdrOff 0.
static const unsigned char kDeflZip[178] = {
0x50,0x4b,0x03,0x04,0x14,0x00,0x00,0x00,0x08,0x00,0x6a,0x40,0xcc,0x5c,0x81,0x11,0x61,0x1a,0x3a,0x00,
0x00,0x00,0x38,0x04,0x00,0x00,0x0b,0x00,0x00,0x00,0x48,0x65,0x6c,0x6c,0x6f,0x2e,0x63,0x6c,0x61,0x73,
0x73,0x0b,0xc9,0x48,0x55,0x28,0x2c,0xcd,0x4c,0xce,0x56,0x48,0x2a,0xca,0x2f,0xcf,0x53,0x48,0xcb,0xaf,
0x50,0xc8,0x2a,0xcd,0x2d,0x28,0x56,0xc8,0x2f,0x4b,0x2d,0x52,0x28,0xc9,0x48,0x55,0xc8,0x49,0xac,0xaa,
0x54,0x48,0xc9,0x4f,0xd7,0x53,0x08,0x19,0x55,0x3c,0xaa,0x78,0x54,0x71,0xd2,0xa8,0x62,0x05,0x00,0x50,
0x4b,0x01,0x02,0x14,0x00,0x14,0x00,0x00,0x00,0x08,0x00,0x6a,0x40,0xcc,0x5c,0x81,0x11,0x61,0x1a,0x3a,
0x00,0x00,0x00,0x38,0x04,0x00,0x00,0x0b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,
0x01,0x00,0x00,0x00,0x00,0x48,0x65,0x6c,0x6c,0x6f,0x2e,0x63,0x6c,0x61,0x73,0x73,0x50,0x4b,0x05,0x06,
0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x39,0x00,0x00,0x00,0x63,0x00,0x00,0x00,0x00,0x00
};

static std::vector<uint8_t> dogPayload() {
    static const char kDog[] = "The quick brown fox jumps over the lazy dog. ";
    std::vector<uint8_t> v;
    for (int i = 0; i < 24; ++i) v.insert(v.end(), kDog, kDog + sizeof(kDog) - 1);
    return v;
}

int main() {
    // ---- 1. stored entry extracts byte-exact (incl. local-only extra field) ----
    {
        ZEntry plain = { "readme.txt", "hello stored world", 0 };
        ZEntry extra = { "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n", 0 };
        extra.localExtra = "\x01\x02\x03\x04\x05\x06";   // LOCAL header only, CD says 0
        auto z = buildZip({ plain, extra });
        uint64_t base = 99; std::vector<JavaZipEntry> es;
        CHECK(listEntries(z, base, es));
        CHECK(base == 0 && es.size() == 2);
        std::vector<uint8_t> out;
        CHECK(ExtractZipEntry(z.data(), z.size(), base, es[0], out));
        CHECK(out.size() == plain.data.size() &&
              std::memcmp(out.data(), plain.data.data(), out.size()) == 0);
        // extra field skipped because the LOCAL lengths are used, not the CD's
        CHECK(ExtractZipEntry(z.data(), z.size(), base, es[1], out));
        CHECK(out.size() == extra.data.size() &&
              std::memcmp(out.data(), extra.data.data(), out.size()) == 0);
        // stored comp/uncomp disagreement fails
        JavaZipEntry bad = es[0]; bad.uncompSize += 1;
        std::string err;
        CHECK(!ExtractZipEntry(z.data(), z.size(), base, bad, out, &err));
        CHECK(!err.empty());
    }

    // ---- 2. deflate entry, end-to-end over the python zipfile bytes ----
    {
        std::vector<uint8_t> z(kDeflZip, kDeflZip + sizeof(kDeflZip));
        uint64_t base = 99; std::vector<JavaZipEntry> es;
        CHECK(listEntries(z, base, es));
        CHECK(base == 0 && es.size() == 1);
        CHECK(es[0].name == "Hello.class" && es[0].method == 8);
        CHECK(es[0].compSize == 58 && es[0].uncompSize == 1080);
        std::vector<uint8_t> out;
        CHECK(ExtractZipEntry(z.data(), z.size(), base, es[0], out));
        CHECK(out == dogPayload());
    }

    // ---- 3. same zip embedded at a nonzero offset (zipBase > 0) ----
    {
        std::vector<uint8_t> buf(0x123, 0xEE);           // fake PE-ish prefix junk
        buf.insert(buf.end(), kDeflZip, kDeflZip + sizeof(kDeflZip));
        uint64_t base = 0; std::vector<JavaZipEntry> es;
        CHECK(listEntries(buf, base, es));
        CHECK(base == 0x123 && es.size() == 1);
        std::vector<uint8_t> out;
        CHECK(ExtractZipEntry(buf.data(), buf.size(), base, es[0], out));
        CHECK(out == dogPayload());
        // wrong zipBase lands off the local header -> clean failure
        CHECK(!ExtractZipEntry(buf.data(), buf.size(), 0, es[0], out));
    }

    // ---- 4. bad local-header signature ----
    {
        std::vector<uint8_t> z(kDeflZip, kDeflZip + sizeof(kDeflZip));
        uint64_t base = 0; std::vector<JavaZipEntry> es;
        CHECK(listEntries(z, base, es));
        z[es[0].localHdrOff] = 0x51;                     // 'P' -> 'Q'
        std::vector<uint8_t> out; std::string err;
        CHECK(!ExtractZipEntry(z.data(), z.size(), base, es[0], out, &err));
        CHECK(err.find("local header") != std::string::npos);
    }

    // ---- 5. truncated data: n cut inside the entry payload ----
    {
        std::vector<uint8_t> z(kDeflZip, kDeflZip + sizeof(kDeflZip));
        uint64_t base = 0; std::vector<JavaZipEntry> es;
        CHECK(listEntries(z, base, es));
        const size_t cut = (size_t)(30 + 11 + es[0].compSize - 10); // mid-payload
        std::vector<uint8_t> out;
        CHECK(!ExtractZipEntry(z.data(), cut, base, es[0], out));
        CHECK(!ExtractZipEntry(z.data(), 20, base, es[0], out));    // mid-header
    }

    // ---- 6. unsupported compression method ----
    {
        ZEntry weird = { "lzma.bin", "not really lzma", 99 };
        auto z = buildZip({ weird });
        uint64_t base = 0; std::vector<JavaZipEntry> es;
        CHECK(listEntries(z, base, es));
        CHECK(es[0].method == 99);
        std::vector<uint8_t> out; std::string err;
        CHECK(!ExtractZipEntry(z.data(), z.size(), base, es[0], out, &err));
        CHECK(err == "unsupported compression method 99");
    }

    // ---- 7. deflate size mismatch / corrupt stream ----
    {
        std::vector<uint8_t> z(kDeflZip, kDeflZip + sizeof(kDeflZip));
        uint64_t base = 0; std::vector<JavaZipEntry> es;
        CHECK(listEntries(z, base, es));
        std::vector<uint8_t> out; std::string err;
        JavaZipEntry lied = es[0]; lied.uncompSize += 1; // CD lies about the size
        CHECK(!ExtractZipEntry(z.data(), z.size(), base, lied, out, &err));
        CHECK(err.find("size mismatch") != std::string::npos);
        auto corrupt = z;                                // reserved BTYPE 11 in byte 0
        corrupt[30 + 11] = 0x07;
        CHECK(!ExtractZipEntry(corrupt.data(), corrupt.size(), base, es[0], out, &err));
        CHECK(err.find("corrupt") != std::string::npos);
        JavaZipEntry shortc = es[0]; shortc.compSize -= 4; // truncated deflate stream
        CHECK(!ExtractZipEntry(z.data(), z.size(), base, shortc, out));
    }

    if (g_fail == 0) std::printf("ALL ZIPEXTRACT TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
