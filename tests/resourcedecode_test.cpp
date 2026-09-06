// Tests for the pure PE resource payload decoders (ResourceDecode.*): type
// names, UTF-16 decode, version info, string tables, and .bmp/.ico
// reconstruction. No BinaryFile / Win32 dependency.
//
// Build (VS dev shell, from project root):
//   cl /std:c++20 /EHsc /I src tests\resourcedecode_test.cpp src\Core\ResourceDecode.cpp

#include "Core/ResourceDecode.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
}
static void u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
    v.push_back((x >> 16) & 0xFF); v.push_back((x >> 24) & 0xFF);
}
static void keyw(std::vector<uint8_t>& v, const char* s) {   // UTF-16 + NUL
    for (; *s; ++s) u16(v, (uint8_t)*s);
    u16(v, 0);
}
static void pad4(std::vector<uint8_t>& v) { while (v.size() % 4) v.push_back(0); }
static void patch16(std::vector<uint8_t>& v, size_t off, uint16_t x) {
    v[off] = x & 0xFF; v[off + 1] = (x >> 8) & 0xFF;
}
static void patch32(std::vector<uint8_t>& v, size_t off, uint32_t x) {
    for (size_t i = 0; i < 4; ++i) v[off + i] = (uint8_t)(x >> (i * 8));
}
static uint32_t read32(const std::vector<uint8_t>& v, size_t off) {
    if (off > v.size() || v.size() - off < 4) return UINT32_MAX;
    return v[off] | (v[off + 1] << 8) | (v[off + 2] << 16) |
           ((uint32_t)v[off + 3] << 24);
}
static std::vector<uint8_t> versionString(const char* key, const char* value) {
    std::vector<uint8_t> s;
    u16(s, 0); u16(s, (uint16_t)(std::strlen(value) + 1)); u16(s, 1);
    keyw(s, key);
    pad4(s);
    keyw(s, value);
    patch16(s, 0, (uint16_t)s.size());
    return s;
}
static size_t versionNodeOffset(const std::vector<uint8_t>& v, const char* key) {
    std::vector<uint8_t> encoded;
    keyw(encoded, key);
    const auto it = std::search(v.begin(), v.end(), encoded.begin(), encoded.end());
    return (size_t)(it - v.begin()) - 6;
}

// A minimal but real VS_VERSIONINFO: fixed info 1.2.3.4 / 1.0.0.0 plus one
// StringFileInfo -> StringTable -> String("CompanyName" = "Acme").
static std::vector<uint8_t> buildVersionInfo(bool secondString = false) {
    std::vector<uint8_t> s = versionString("CompanyName", "Acme");

    std::vector<uint8_t> st; // StringTable node
    u16(st, 0); u16(st, 0); u16(st, 1);
    keyw(st, "040904b0");
    pad4(st);
    st.insert(st.end(), s.begin(), s.end());
    if (secondString) {
        pad4(st);
        const auto second = versionString("FileDescription", "Workbench");
        st.insert(st.end(), second.begin(), second.end());
    }
    patch16(st, 0, (uint16_t)st.size());

    std::vector<uint8_t> sfi; // StringFileInfo node
    u16(sfi, 0); u16(sfi, 0); u16(sfi, 1);
    keyw(sfi, "StringFileInfo");
    pad4(sfi);
    sfi.insert(sfi.end(), st.begin(), st.end());
    patch16(sfi, 0, (uint16_t)sfi.size());

    std::vector<uint8_t> root;
    u16(root, 0); u16(root, 52); u16(root, 0); // wLength(patch), value=52, binary
    keyw(root, "VS_VERSION_INFO");
    pad4(root);
    u32(root, 0xFEEF04BD);                  // dwSignature
    u32(root, 0x00010000);                  // dwStrucVersion
    u32(root, 0x00010002);                  // FileVersionMS = 1.2
    u32(root, 0x00030004);                  // FileVersionLS = 3.4
    u32(root, 0x00010000);                  // ProductVersionMS = 1.0
    u32(root, 0x00000000);                  // ProductVersionLS = 0.0
    for (int i = 0; i < 7; ++i) u32(root, 0); // remaining fixed-info dwords (52 total)
    root.insert(root.end(), sfi.begin(), sfi.end());
    patch16(root, 0, (uint16_t)root.size());
    return root;
}

int main() {
    // Type names
    CHECK(std::strcmp(ResourceTypeName(24), "RT_MANIFEST") == 0);
    CHECK(std::strcmp(ResourceTypeName(3), "RT_ICON") == 0);
    CHECK(std::strcmp(ResourceTypeName(16), "RT_VERSION") == 0);
    CHECK(ResourceTypeName(9999) == nullptr);

    // UTF-16LE -> UTF-8, including a non-ASCII BMP char (U+00E9 'é').
    {
        std::vector<uint8_t> w;
        u16(w, 'H'); u16(w, 0x00E9); u16(w, 'i'); u16(w, 0);
        std::string s = Utf16LeToUtf8(w.data(), w.size());
        CHECK(s == "H\xC3\xA9i");
    }

    // Text vs binary detection
    {
        const char* xml = "<assembly xmlns=\"urn:schemas\"/>";
        CHECK(LooksLikeText((const uint8_t*)xml, std::strlen(xml)));
        uint8_t bin[64];
        for (int i = 0; i < 64; ++i) bin[i] = (uint8_t)(i * 7 + 1);
        // Force many low control bytes.
        for (int i = 0; i < 40; ++i) bin[i] = (uint8_t)(i % 8);
        CHECK(!LooksLikeText(bin, sizeof(bin)));
    }

    // Version info
    {
        auto vi = buildVersionInfo();
        std::string out = DecodeVersionInfo(vi.data(), vi.size());
        CHECK(out.find("1.2.3.4") != std::string::npos);
        CHECK(out.find("1.0.0.0") != std::string::npos);
        CHECK(out.find("CompanyName: Acme") != std::string::npos);
        for (size_t prefix = 0; prefix < vi.size(); ++prefix)
            CHECK(DecodeVersionInfo(vi.data(), prefix).empty());
    }

    // A resource span may include trailing data, but wLength bounds the root.
    {
        auto vi = buildVersionInfo();
        pad4(vi);
        const auto trailing = versionString("Unexpected", "unrelated bytes");
        vi.insert(vi.end(), trailing.begin(), trailing.end());
        const auto out = DecodeVersionInfo(vi.data(), vi.size());
        CHECK(out.find("CompanyName: Acme") != std::string::npos);
        CHECK(out.find("Unexpected") == std::string::npos);
    }

    // Keys, values, and descendants must stay within their declared node and
    // parent bounds. A truncated/malformed blob must not produce trusted text.
    {
        const auto original = buildVersionInfo();
        const size_t company = versionNodeOffset(original, "CompanyName");
        auto vi = original;
        patch16(vi, company, 6); // key lies outside the String node
        CHECK(DecodeVersionInfo(vi.data(), vi.size()).empty());
        vi = original;
        patch16(vi, company + 2, 2); // no terminator within the declared value
        CHECK(DecodeVersionInfo(vi.data(), vi.size()).empty());
        vi = original;
        patch16(vi, company + 2, UINT16_MAX); // value spills outside the node
        CHECK(DecodeVersionInfo(vi.data(), vi.size()).empty());
        vi = original;
        const size_t table = versionNodeOffset(vi, "040904b0");
        patch16(vi, table, (uint16_t)(vi.size() - table - 2)); // child exceeds parent
        CHECK(DecodeVersionInfo(vi.data(), vi.size()).empty());
        vi = original;
        patch16(vi, 0, (uint16_t)(vi.size() + 2)); // truncated declared root
        CHECK(DecodeVersionInfo(vi.data(), vi.size()).empty());
    }

    // Advance using the declared value size, even when an early NUL shortens
    // the displayed string; the next sibling still has to be decoded.
    {
        auto vi = buildVersionInfo(true);
        const size_t company = versionNodeOffset(vi, "CompanyName");
        const size_t value = (company + 6 + 12 * 2 + 3) & ~(size_t)3;
        patch16(vi, value + 4, 0);
        const auto out = DecodeVersionInfo(vi.data(), vi.size());
        CHECK(out.find("CompanyName: Ac\n") != std::string::npos);
        CHECK(out.find("FileDescription: Workbench") != std::string::npos);
    }

    // String table: strings at slot 2 ("Hello") and slot 5 ("Wo"), block 1.
    {
        std::vector<uint8_t> b;
        for (int i = 0; i < 16; ++i) {
            if (i == 2) { u16(b, 5); for (const char* p = "Hello"; *p; ++p) u16(b, (uint8_t)*p); }
            else if (i == 5) { u16(b, 2); u16(b, 'W'); u16(b, 'o'); }
            else u16(b, 0);
        }
        auto rows = DecodeStringTable(b.data(), b.size(), 1);
        CHECK(rows.size() == 2);
        if (rows.size() == 2) {
            CHECK(rows[0].first == 2 && rows[0].second == "Hello");
            CHECK(rows[1].first == 5 && rows[1].second == "Wo");
        }
    }

    // DIB describe + BMP reconstruction (2x2, 32bpp, no palette).
    {
        std::vector<uint8_t> dib;
        u32(dib, 40);            // biSize
        u32(dib, 2);             // biWidth
        u32(dib, 2);             // biHeight
        u16(dib, 1);             // biPlanes
        u16(dib, 32);            // biBitCount
        u32(dib, 0);             // biCompression BI_RGB
        u32(dib, 16);            // biSizeImage (2*2*4)
        u32(dib, 0); u32(dib, 0);// x/y ppm
        u32(dib, 0);             // biClrUsed
        u32(dib, 0);             // biClrImportant
        for (int i = 0; i < 16; ++i) dib.push_back((uint8_t)(i + 1)); // pixels

        DibInfo di = DescribeDib(dib.data(), dib.size());
        CHECK(di.valid && !di.png && di.width == 2 && di.height == 2 && di.bitCount == 32);
        CHECK(di.paletteBytes == 0);

        auto bmp = ReconstructBmp(dib.data(), dib.size());
        CHECK(bmp.size() == dib.size() + 14);
        CHECK(bmp[0] == 'B' && bmp[1] == 'M');
        uint32_t bfSize = bmp[2] | (bmp[3] << 8) | (bmp[4] << 16) | ((uint32_t)bmp[5] << 24);
        uint32_t offBits = bmp[10] | (bmp[11] << 8) | (bmp[12] << 16) | ((uint32_t)bmp[13] << 24);
        CHECK(bfSize == dib.size() + 14);
        CHECK(offBits == 14 + 40);  // no palette for 32bpp
        // DIB copied verbatim after the file header.
        CHECK(std::memcmp(bmp.data() + 14, dib.data(), dib.size()) == 0);
    }

    // 8bpp DIB with an implicit 256-entry palette => bfOffBits accounts for it.
    {
        std::vector<uint8_t> dib(40, 0);
        dib[0] = 40;                 // biSize
        dib[4] = 4; dib[8] = 4;      // 4x4
        dib[14] = 8;                 // 8bpp
        // biClrUsed = 0 -> 256 palette entries
        DibInfo di = DescribeDib(dib.data(), dib.size());
        CHECK(di.valid && di.bitCount == 8 && di.paletteBytes == 256 * 4);
        CHECK(ReconstructBmp(dib.data(), dib.size()).empty()); // missing palette/pixels
        dib.resize(40 + 256 * 4 + 16, 0);
        auto bmp = ReconstructBmp(dib.data(), dib.size());
        uint32_t offBits = read32(bmp, 10);
        CHECK(offBits == 14 + 40 + 256 * 4);
    }

    // V4/V5 channel masks live inside the header. Legacy INFOHEADER masks
    // follow the header, before any optional optimization palette.
    for (uint32_t headerSize : {40u, 108u, 124u}) {
        const uint32_t extraMasks = headerSize == 40 ? 12 : 0;
        std::vector<uint8_t> dib(headerSize + extraMasks + 8 + 4, 0);
        patch32(dib, 0, headerSize);
        patch32(dib, 4, 1); patch32(dib, 8, 1);
        patch16(dib, 12, 1); patch16(dib, 14, 32);
        patch32(dib, 16, 3); // BI_BITFIELDS
        patch32(dib, 32, 2); // two optimization palette entries
        const auto di = DescribeDib(dib.data(), dib.size());
        CHECK(di.valid && di.paletteBytes == extraMasks + 8);
        const auto bmp = ReconstructBmp(dib.data(), dib.size());
        CHECK(read32(bmp, 10) == 14 + headerSize + extraMasks + 8);
    }

    // Hostile palette counts must not wrap to a plausible pixel offset, and
    // BMP's 32-bit file-size fields must be checked before any payload copy.
    {
        std::vector<uint8_t> dib(44, 0);
        patch32(dib, 0, 40);
        patch16(dib, 14, 32);
        patch32(dib, 32, 0x40000000u);
        CHECK(!DescribeDib(dib.data(), dib.size()).valid);
        CHECK(ReconstructBmp(dib.data(), dib.size()).empty());
        patch32(dib, 32, 0);
        if (SIZE_MAX > UINT32_MAX)
            CHECK(ReconstructBmp(dib.data(), (size_t)UINT32_MAX).empty());
    }

    // Group icon parse + .ico reconstruction with a fake RT_ICON resolver.
    {
        std::vector<uint8_t> grp;
        u16(grp, 0);         // idReserved
        u16(grp, 1);         // idType = icon
        u16(grp, 2);         // idCount
        // entry 0 -> id 5
        grp.push_back(48); grp.push_back(48); grp.push_back(0); grp.push_back(0);
        u16(grp, 1); u16(grp, 32); u32(grp, 4); u16(grp, 5);
        // entry 1 -> id 9
        grp.push_back(16); grp.push_back(16); grp.push_back(0); grp.push_back(0);
        u16(grp, 1); u16(grp, 8); u32(grp, 3); u16(grp, 9);

        GroupIconDir dir = ParseGroupIcon(grp.data(), grp.size());
        CHECK(dir.valid && !dir.isCursor && dir.entries.size() == 2);
        CHECK(dir.entries[0].id == 5 && dir.entries[0].bytesInRes == 4);
        CHECK(dir.entries[1].id == 9 && dir.entries[1].width == 16);

        static const uint8_t img5[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        static const uint8_t img9[3] = {0x11, 0x22, 0x33};
        auto resolve = [&](uint16_t id, const uint8_t*& p, size_t& n) -> bool {
            if (id == 5) { p = img5; n = 4; return true; }
            if (id == 9) { p = img9; n = 3; return true; }
            return false;
        };
        auto ico = ReconstructIcon(dir, resolve);
        // 6 (ICONDIR) + 2*16 (ICONDIRENTRY) + 4 + 3 image bytes
        CHECK(ico.size() == 6 + 32 + 4 + 3);
        CHECK(ico[2] == 1 && ico[4] == 2);  // idType icon, idCount 2
        // entry 0 image offset = 6 + 32 = 38
        uint32_t off0 = ico[6 + 12] | (ico[6 + 13] << 8) | (ico[6 + 14] << 16) | ((uint32_t)ico[6 + 15] << 24);
        CHECK(off0 == 38);
        uint32_t off1 = ico[22 + 12] | (ico[22 + 13] << 8) | (ico[22 + 14] << 16) | ((uint32_t)ico[22 + 15] << 24);
        CHECK(off1 == 42);
        CHECK(std::memcmp(ico.data() + 38, img5, 4) == 0);
        CHECK(std::memcmp(ico.data() + 42, img9, 3) == 0);
    }

    if (!g_fail) std::printf("ALL RESOURCE DECODE TESTS PASSED\n");
    return g_fail ? 1 : 0;
}
