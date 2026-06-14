//
// inflate_test.cpp
// Tests for src/Core/Inflate.cpp: the hand-rolled RFC 1951 raw-DEFLATE decoder.
// Test vectors are REAL zlib output (python3 zlib.compressobj(9, DEFLATED, -15))
// plus one hand-crafted fixed-Huffman stream with a guaranteed 32100-byte match
// distance, itself validated against zlib at generation time. Failure cases
// (truncated / corrupt LEN / BTYPE 11 / maxOut / garbage) must all return false
// instantly -- no crash, no spin.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\inflate_test.cpp src\Core\Inflate.cpp
//   .\inflate_test.exe
//
#include "Core/Inflate.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// ---- vector 1: fixed-Huffman block (first byte & 7 == 3: BFINAL + BTYPE 01) --
// python3: zlib.compressobj(9, zlib.DEFLATED, -15) over kFixedPlain
static const char kFixedPlain[] = "Hello, inflate! Hello, inflate!";
static const unsigned char kFixedDeflate[21] = {
0xf3,0x48,0xcd,0xc9,0xc9,0xd7,0x51,0xc8,0xcc,0x4b,0xcb,0x49,0x2c,0x49,0x55,0x54,0xf0,0x40,0xe5,0x03,
0x00
};

// ---- vector 2: dynamic-Huffman block (first byte & 7 == 5: BFINAL + BTYPE 10)
// plaintext = "The quick brown fox jumps over the lazy dog. " * 64 (2880 bytes);
// exercises back-references and the 16/17/18 code-length repeat codes.
static const unsigned char kDynDeflate[66] = {
0xed,0xca,0x59,0x01,0x80,0x20,0x14,0x45,0xc1,0x2a,0x37,0x81,0x69,0x28,0xe0,0x02,0xee,0x3e,0x44,0x71,
0x4b,0xaf,0x3d,0x3c,0xdf,0x33,0xae,0xf3,0x5a,0x73,0x5f,0x8f,0xaa,0x92,0x9d,0x8b,0x82,0x5d,0x1a,0xf2,
0x1c,0x37,0xd9,0xe1,0x93,0xf6,0x8f,0xa7,0xf2,0xb9,0xd5,0x58,0x5b,0xc8,0x91,0xc9,0x64,0x32,0x99,0x4c,
0x26,0x93,0xc9,0xff,0xce,0x2f
};

// ---- vector 3: hand-crafted fixed-Huffman stream, far match ------------------
// 100-byte marker, 32000 'x' (distance-1 runs), then the marker again as a
// single len-100 match at distance 32100 (near the 32K window edge), EOB.
// Validated byte-for-byte against zlib.decompress at generation time.
static const unsigned char kFarDeflate[315] = {
0xe3,0x36,0x08,0xad,0x9a,0x7f,0xe4,0x25,0x9f,0x71,0x44,0xed,0xa2,0xe3,0x6f,0x04,0xcd,0xa2,0x1b,0x96,
0x9e,0x7a,0x2f,0x62,0x19,0xd7,0xbc,0xe2,0xec,0x27,0x71,0x9b,0xc4,0xb6,0xd5,0x17,0xbe,0x4a,0xd9,0xa7,
0x74,0xae,0xbb,0xfc,0x43,0xd6,0x29,0xbd,0x67,0xe3,0xb5,0xdf,0x0a,0xae,0x59,0xfd,0x5b,0x6e,0xfe,0x53,
0xf6,0xc8,0x9d,0xb4,0xfd,0x0e,0xa3,0x9a,0x77,0xc1,0xd4,0x5d,0xf7,0x59,0x34,0xfd,0x8a,0x67,0xec,0x7d,
0xc4,0xae,0x13,0x58,0x36,0xfb,0xc0,0x53,0x2e,0xfd,0x90,0xca,0x79,0x87,0x5f,0xf0,0x1a,0x85,0xd7,0x2c,
0x3c,0xf6,0x5a,0xc0,0x34,0xaa,0x62,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,
0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,
0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,
0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,
0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,
0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,
0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,
0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,
0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,
0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0x46,0xc1,0x28,0x18,0x05,
0xa3,0x60,0x14,0x8c,0x82,0x51,0x30,0x0a,0xa0,0x80,0x1e,0x77,0xac,0x03,0x00
};

static std::vector<uint8_t> dynPlain() {
    static const char kDog[] = "The quick brown fox jumps over the lazy dog. ";
    std::vector<uint8_t> v;
    for (int i = 0; i < 64; ++i) v.insert(v.end(), kDog, kDog + sizeof(kDog) - 1);
    return v;
}

static std::vector<uint8_t> farPlain() {
    std::vector<uint8_t> v;
    for (int i = 0; i < 100; ++i) v.push_back((uint8_t)((i * 37 + 11) & 0xFF));
    v.insert(v.end(), 32000, (uint8_t)'x');
    for (int i = 0; i < 100; ++i) v.push_back((uint8_t)((i * 37 + 11) & 0xFF));
    return v;
}

int main() {
    // ---- 1. stored block (hand-crafted: 0x01, LEN, ~LEN, payload) ----
    {
        const char* payload = "stored block payload";
        const uint16_t len = (uint16_t)std::strlen(payload);
        std::vector<uint8_t> s;
        s.push_back(0x01);                              // BFINAL=1 BTYPE=00
        s.push_back((uint8_t)(len & 0xFF)); s.push_back((uint8_t)(len >> 8));
        s.push_back((uint8_t)(~len & 0xFF)); s.push_back((uint8_t)(~len >> 8));
        s.insert(s.end(), payload, payload + len);
        std::vector<uint8_t> out;
        CHECK(InflateRaw(s.data(), s.size(), out));
        CHECK(out.size() == len && std::memcmp(out.data(), payload, len) == 0);

        // empty stored block is fine too
        const uint8_t empty[] = { 0x01, 0x00, 0x00, 0xFF, 0xFF };
        CHECK(InflateRaw(empty, sizeof(empty), out));
        CHECK(out.empty());
    }

    // ---- 2. fixed-Huffman stream: exact bytes back ----
    {
        CHECK((kFixedDeflate[0] & 7) == 3);             // BFINAL + BTYPE 01
        std::vector<uint8_t> out;
        CHECK(InflateRaw(kFixedDeflate, sizeof(kFixedDeflate), out));
        CHECK(out.size() == std::strlen(kFixedPlain));
        CHECK(std::memcmp(out.data(), kFixedPlain, out.size()) == 0);
    }

    // ---- 3. dynamic-Huffman stream of ~3KB repetitive text ----
    {
        CHECK((kDynDeflate[0] & 7) == 5);               // BFINAL + BTYPE 10
        const auto want = dynPlain();
        std::vector<uint8_t> out;
        CHECK(InflateRaw(kDynDeflate, sizeof(kDynDeflate), out));
        CHECK(out == want);
    }

    // ---- 4. long match distance (32100) near the window edge ----
    {
        const auto want = farPlain();
        std::vector<uint8_t> out;
        CHECK(InflateRaw(kFarDeflate, sizeof(kFarDeflate), out));
        CHECK(out.size() == 32200);
        CHECK(out == want);
    }

    // ---- 5. multi-block: non-final stored + final fixed (EOB only) ----
    {
        const uint8_t s[] = { 0x00, 0x03, 0x00, 0xFC, 0xFF, 'a', 'b', 'c',
                              0x03, 0x00 };             // BFINAL=1 BTYPE=01, EOB
        std::vector<uint8_t> out;
        CHECK(InflateRaw(s, sizeof(s), out));
        CHECK(out.size() == 3 && std::memcmp(out.data(), "abc", 3) == 0);
    }

    // ---- 6. truncated streams => false (no hang, no crash) ----
    {
        std::vector<uint8_t> out;
        for (size_t cut : { (size_t)1, sizeof(kDynDeflate) / 2, sizeof(kDynDeflate) - 1 })
            CHECK(!InflateRaw(kDynDeflate, cut, out));
        CHECK(!InflateRaw(kFixedDeflate, sizeof(kFixedDeflate) - 2, out));
        CHECK(!InflateRaw(kFixedDeflate, 0, out));      // empty input
        CHECK(!InflateRaw(nullptr, 0, out));            // null input
        const uint8_t hdrOnly[] = { 0x01, 0x05, 0x00 }; // stored, LEN cut short
        CHECK(!InflateRaw(hdrOnly, sizeof(hdrOnly), out));
        const uint8_t dataCut[] = { 0x01, 0x05, 0x00, 0xFA, 0xFF, 'a', 'b' };
        CHECK(!InflateRaw(dataCut, sizeof(dataCut), out));
    }

    // ---- 7. corrupt LEN/~NLEN => false ----
    {
        const uint8_t s[] = { 0x01, 0x03, 0x00, 0xFD, 0xFF, 'a', 'b', 'c' };
        std::vector<uint8_t> out;
        CHECK(!InflateRaw(s, sizeof(s), out));
    }

    // ---- 8. BTYPE 11 => false ----
    {
        const uint8_t s[] = { 0x07, 0x00, 0x00, 0x00 }; // BFINAL=1 BTYPE=11
        std::vector<uint8_t> out;
        CHECK(!InflateRaw(s, sizeof(s), out));
    }

    // ---- 9. maxOut smaller than the output => false ----
    {
        std::vector<uint8_t> out;
        CHECK(!InflateRaw(kDynDeflate, sizeof(kDynDeflate), out, 100));   // 2880 needed
        CHECK(!InflateRaw(kFarDeflate, sizeof(kFarDeflate), out, 32199)); // off by one
        CHECK(InflateRaw(kFarDeflate, sizeof(kFarDeflate), out, 32200)); // exact cap OK
    }

    // ---- 10. garbage bytes => false, instantly ----
    {
        std::vector<uint8_t> out;
        std::vector<uint8_t> junk(4096);
        for (size_t i = 0; i < junk.size(); ++i) junk[i] = (uint8_t)(i * 151 + 29);
        CHECK(!InflateRaw(junk.data(), junk.size(), out));
        std::vector<uint8_t> ff(4096, 0xFF);            // oversubscribed dynamic header
        CHECK(!InflateRaw(ff.data(), ff.size(), out));
        std::vector<uint8_t> zeros(4096, 0x00);         // endless empty stored blocks, then EOF
        CHECK(!InflateRaw(zeros.data(), zeros.size(), out));
    }

    if (g_fail == 0) std::printf("ALL INFLATE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
