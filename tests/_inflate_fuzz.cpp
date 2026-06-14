// Adversarial probe for src/Core/Inflate.cpp (audit harness, not checked-in test).
//   cl /std:c++20 /O2 /EHsc /I src tests\_inflate_fuzz.cpp src\Core\Inflate.cpp
#include "Core/Inflate.h"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static std::vector<uint8_t> fromHex(const char* h) {
    std::vector<uint8_t> v;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            return (c | 0x20) - 'a' + 10;
        };
        v.push_back((uint8_t)((nib(h[i]) << 4) | nib(h[i + 1])));
    }
    return v;
}

int main() {
    using clock = std::chrono::steady_clock;

    // 1. legal incomplete single-code distance table (zlib-validated) -> must succeed
    {
        auto s = fromHex("05c08100000000009036ff5308");
        std::vector<uint8_t> out;
        CHECK(InflateRaw(s.data(), s.size(), out));
        CHECK(out.size() == 1 && out[0] == 'A');
    }
    // 2. repeat-16 with no previous length (zlib rejects) -> must fail
    {
        auto s = fromHex("05e00300000000001004");
        std::vector<uint8_t> out;
        CHECK(!InflateRaw(s.data(), s.size(), out));
    }
    // 3. HLIT=30 (nlen 287 > 286, zlib rejects) -> must fail
    {
        auto s = fromHex("f5e001000000000000000000000000000000");
        std::vector<uint8_t> out;
        CHECK(!InflateRaw(s.data(), s.size(), out));
    }
    // 4. cross-block back-reference via Z_SYNC_FLUSH (zlib-validated) -> exact bytes
    {
        auto s = fromHex("8a8a1a1ea0342fb3b034553737b1283bb548b724b5a204000000ffff8b1ab63e0300");
        std::string want = std::string(200, 'Z') + "unique-marker-text";
        want += want;
        std::vector<uint8_t> out;
        CHECK(InflateRaw(s.data(), s.size(), out));
        CHECK(out.size() == want.size() && std::memcmp(out.data(), want.data(), want.size()) == 0);
    }
    // 5. fixed block whose first symbol is a match (distance with empty output) -> must fail
    {
        // bits: BFINAL=1 BTYPE=01, litlen 257 (7-bit code 0000001), dist sym 0 (00000), pad
        // 1,1,0 | 0,0,0,0,0,0,1 | 0,0,0,0,0 -> bytes LSB-first
        uint8_t s[3] = { 0x03, 0x02, 0x00 };
        std::vector<uint8_t> out;
        CHECK(!InflateRaw(s, sizeof(s), out));
    }

    // 6. random fuzz: arbitrary buffers must terminate fast, no crash
    {
        uint64_t rng = 0x9E3779B97F4A7C15ull;
        auto next = [&]() { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; };
        std::vector<uint8_t> buf;
        std::vector<uint8_t> out;
        const auto t0 = clock::now();
        size_t accepted = 0;
        for (int it = 0; it < 300000; ++it) {
            buf.resize(1 + (next() % 256));
            for (auto& b : buf) b = (uint8_t)next();
            if (InflateRaw(buf.data(), buf.size(), out, 1 << 20)) ++accepted;
        }
        const double ms = std::chrono::duration<double, std::milli>(clock::now() - t0).count();
        std::printf("random fuzz: 300000 iters, %zu accepted, %.0f ms\n", accepted, ms);
        CHECK(ms < 60000.0);
    }
    // 7. mutational fuzz over the real zlib vectors (bit flips + truncations)
    {
        static const char* vecs[] = {
            "f348cdc9c9d751c8cc4bcb492c495554f040e50300",
            "edca5901802014c5c12a3781692ae002ee3e44714baf3d3cdf33aef35a735f8faa929d8b825d1af21c37d9e193f68fa7f2b9d5585bc891c9643299" /* truncated dyn ok for fuzz */,
            "8a8a1a1ea0342fb3b034553737b1283bb548b724b5a204000000ffff8b1ab63e0300",
        };
        uint64_t rng = 0xDEADBEEFCAFEF00Dull;
        auto next = [&]() { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; };
        std::vector<uint8_t> out;
        const auto t0 = clock::now();
        for (int it = 0; it < 300000; ++it) {
            auto m = fromHex(vecs[it % 3]);
            const int flips = 1 + (int)(next() % 4);
            for (int f = 0; f < flips; ++f) m[next() % m.size()] ^= (uint8_t)(1u << (next() % 8));
            const size_t len = 1 + (next() % m.size());
            InflateRaw(m.data(), len, out, 1 << 20);
        }
        const double ms = std::chrono::duration<double, std::milli>(clock::now() - t0).count();
        std::printf("mutation fuzz: 300000 iters, %.0f ms\n", ms);
        CHECK(ms < 60000.0);
    }

    if (g_fail == 0) std::printf("ALL FUZZ/EDGE CHECKS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
