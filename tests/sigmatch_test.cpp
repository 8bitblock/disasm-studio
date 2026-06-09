//
// sigmatch_test.cpp
// Off-target unit test for the PURE masked Boyer-Moore-Horspool matcher
// (src/Core/SigMatch.cpp). Every BMH result is asserted EXACTLY equal to a
// naive O(n*m) masked matcher over a battery of buffers: overlapping matches,
// wildcards, end-of-buffer matches, all-wildcard, empty, single-byte, and
// random fuzz with randomly-masked patterns.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\sigmatch_test.cpp src\Core\SigMatch.cpp
//   .\sigmatch_test.exe
//
#include "Core/SigMatch.h"

#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Reference: naive masked scan returning every (overlapping) start offset.
static std::vector<size_t> naiveAll(const uint8_t* d, size_t n, const SigPattern& p, size_t maxHits = 0) {
    std::vector<size_t> out;
    const size_t m = p.bytes.size();
    if (m == 0 || n < m) return out;
    for (size_t i = 0; i + m <= n; ++i) {
        bool hit = true;
        for (size_t j = 0; j < m; ++j)
            if (p.mask[j] && d[i + j] != p.bytes[j]) { hit = false; break; }
        if (hit) {
            out.push_back(i);
            if (maxHits && out.size() >= maxHits) break;
        }
    }
    return out;
}

static size_t naiveFirst(const uint8_t* d, size_t n, const SigPattern& p, size_t from) {
    const size_t m = p.bytes.size();
    if (m == 0 || n < m) return SIZE_MAX;
    for (size_t i = from; i + m <= n; ++i) {
        bool hit = true;
        for (size_t j = 0; j < m; ++j)
            if (p.mask[j] && d[i + j] != p.bytes[j]) { hit = false; break; }
        if (hit) return i;
    }
    return SIZE_MAX;
}

static bool eqVec(const std::vector<size_t>& a, const std::vector<size_t>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) if (a[i] != b[i]) return false;
    return true;
}

// Build a SigPattern from explicit bytes + a mask string ('.' = wildcard).
static SigPattern mk(std::vector<uint8_t> bytes, const std::string& maskStr) {
    SigPattern p;
    p.bytes = std::move(bytes);
    for (char c : maskStr) p.mask.push_back(c != '.' && c != '?');
    return p;
}

// Assert BMH FindAll/FindFirst agree with the naive matcher on this buffer.
static void crossCheck(const char* tag, const std::vector<uint8_t>& buf, const SigPattern& p) {
    const uint8_t* d = buf.data();
    size_t n = buf.size();
    auto ref = naiveAll(d, n, p);
    auto got = FindAllMasked(d, n, p);
    if (!eqVec(ref, got)) {
        std::printf("FAIL [%s] FindAllMasked mismatch: ref=%zu got=%zu\n", tag, ref.size(), got.size());
        ++g_fail;
    }
    // FindFirstMasked from a sweep of starting points must match the naive first.
    for (size_t from = 0; from <= n + 1; ++from) {
        size_t rf = naiveFirst(d, n, p, from);
        size_t gf = FindFirstMasked(d, n, p, from);
        if (rf != gf) {
            std::printf("FAIL [%s] FindFirstMasked(from=%zu): ref=%zd got=%zd\n",
                        tag, from, (ptrdiff_t)rf, (ptrdiff_t)gf);
            ++g_fail;
        }
    }
}

int main() {
    // ---- ParseSignature semantics -----------------------------------------
    {
        SigPattern p;
        CHECK(ParseSignature("48 89 ?? 24", p));
        CHECK(p.bytes.size() == 4);
        CHECK(p.mask[0] && p.mask[1] && !p.mask[2] && p.mask[3]);
        CHECK(p.bytes[0] == 0x48 && p.bytes[1] == 0x89 && p.bytes[3] == 0x24);
    }
    { SigPattern p; CHECK(ParseSignature("4889??24", p)); CHECK(p.bytes.size() == 4); CHECK(!p.mask[2]); }
    { SigPattern p; CHECK(ParseSignature("E8 ? ? ? ?", p)); CHECK(p.bytes.size() == 5);
      CHECK(p.mask[0] && !p.mask[1] && !p.mask[4]); }            // single '?' wildcard form
    { SigPattern p; CHECK(!ParseSignature("", p)); }              // empty -> false
    { SigPattern p; CHECK(!ParseSignature("ZZ", p)); }            // bad hex -> false
    { SigPattern p; CHECK(!ParseSignature("   ", p)); }           // whitespace only -> false

    // ---- Hand-built buffers ------------------------------------------------
    // Overlapping matches: "AA AA AA" matched by "AA AA".
    crossCheck("overlap", { 0xAA,0xAA,0xAA,0xAA }, mk({0xAA,0xAA}, "xx"));
    // Wildcard in the middle.
    crossCheck("wild-mid", { 0x48,0x89,0x5C,0x24,0x48,0x89,0x77,0x24 }, mk({0x48,0x89,0x00,0x24}, "xx.x"));
    // Match exactly at end of buffer.
    crossCheck("end-match", { 0x00,0x11,0x22,0x33,0xDE,0xAD }, mk({0xDE,0xAD}, "xx"));
    // No match anywhere.
    crossCheck("no-match", { 1,2,3,4,5,6,7,8 }, mk({0xFF,0xEE}, "xx"));
    // Pattern longer than buffer.
    crossCheck("too-long", { 1,2 }, mk({1,2,3,4}, "xxxx"));
    // All-wildcard pattern: matches at every start where it fits.
    crossCheck("all-wild", { 9,8,7,6,5 }, mk({0,0,0}, "..."));
    // Single concrete byte pattern.
    crossCheck("single", { 5,5,7,5,9,5 }, mk({5}, "x"));
    // Wildcard at the tail (anchor must skip back to a concrete byte).
    crossCheck("tail-wild", { 0x90,0x90,0xCC,0x90,0x90,0xCC,0xCC }, mk({0x90,0x90,0x00}, "xx."));
    // Leading wildcard, concrete tail (anchor at the end).
    crossCheck("lead-wild", { 0x01,0xCC,0x02,0xCC,0x03,0xCC }, mk({0x00,0xCC}, ".x"));
    // Empty buffer.
    crossCheck("empty-buf", {}, mk({0xAA}, "x"));

    // maxHits truncation matches the naive matcher's first-K.
    {
        std::vector<uint8_t> buf(64, 0xAB);
        SigPattern p = mk({0xAB,0xAB}, "xx");
        auto ref = naiveAll(buf.data(), buf.size(), p, 5);
        auto got = FindAllMasked(buf.data(), buf.size(), p, 5);
        CHECK(got.size() == 5);
        CHECK(eqVec(ref, got));
    }

    // ---- Random fuzz: many buffers x many masked patterns ------------------
    {
        std::mt19937 rng(0xC0FFEE);
        // Small alphabet so matches actually occur with reasonable frequency.
        std::uniform_int_distribution<int> alpha(0, 4);
        std::uniform_int_distribution<int> mbit(0, 1);
        for (int trial = 0; trial < 400; ++trial) {
            size_t n = (size_t)(rng() % 200);
            std::vector<uint8_t> buf(n);
            for (auto& b : buf) b = (uint8_t)alpha(rng);
            size_t m = (size_t)(1 + rng() % 6);
            SigPattern p;
            for (size_t j = 0; j < m; ++j) {
                bool concrete = mbit(rng) != 0;
                p.bytes.push_back((uint8_t)alpha(rng));
                p.mask.push_back(concrete);
                if (!concrete) p.bytes.back() = 0;
            }
            char tag[32]; std::snprintf(tag, sizeof(tag), "fuzz-%d", trial);
            crossCheck(tag, buf, p);
        }
    }

    if (g_fail == 0) std::printf("ALL SIGMATCH TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
