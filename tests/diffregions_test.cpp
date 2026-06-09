//
// diffregions_test.cpp
// Off-target unit test for the PURE diff-region coalescing helper
// (src/Core/DiffRegions.h) that backs the Binary Diff view's Prev/Next
// navigation and the side-by-side ASM panel.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\diffregions_test.cpp
//   .\diffregions_test.exe
//
#include "Core/DiffRegions.h"

#include <cstdint>
#include <cstdio>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static std::vector<ByteDiffRegion> run(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b,
                                       uint64_t gap = 16, size_t maxR = 50000) {
    std::vector<ByteDiffRegion> out;
    CoalesceDiffRegions(a.data(), a.size(), b.data(), b.size(), gap, maxR, out);
    return out;
}

int main() {
    // ---- identical -> no regions ------------------------------------------
    {
        std::vector<uint8_t> a(64, 0xAA), b(64, 0xAA);
        CHECK(run(a, b).empty());
    }

    // ---- single differing byte -> one 1-byte region -----------------------
    {
        std::vector<uint8_t> a(64, 0), b(64, 0);
        b[10] = 1;
        auto r = run(a, b);
        CHECK(r.size() == 1);
        CHECK(r[0].start == 10 && r[0].end == 11);
    }

    // ---- adjacent differing bytes merge -----------------------------------
    {
        std::vector<uint8_t> a(64, 0), b(64, 0);
        b[10] = b[11] = b[12] = 1;
        auto r = run(a, b);
        CHECK(r.size() == 1);
        CHECK(r[0].start == 10 && r[0].end == 13);
    }

    // ---- two diffs within the gap coalesce into one -----------------------
    {
        std::vector<uint8_t> a(64, 0), b(64, 0);
        b[10] = 1; b[20] = 1;            // 9 equal bytes between (<= gap 16)
        auto r = run(a, b, /*gap=*/16);
        CHECK(r.size() == 1);
        CHECK(r[0].start == 10 && r[0].end == 21);
    }

    // ---- two diffs beyond the gap stay separate ---------------------------
    {
        std::vector<uint8_t> a(64, 0), b(64, 0);
        b[10] = 1; b[40] = 1;            // 29 equal bytes between (> gap 16)
        auto r = run(a, b, /*gap=*/16);
        CHECK(r.size() == 2);
        CHECK(r[0].start == 10 && r[0].end == 11);
        CHECK(r[1].start == 40 && r[1].end == 41);
    }

    // ---- a tighter gap splits what a wider gap would merge ----------------
    {
        std::vector<uint8_t> a(64, 0), b(64, 0);
        b[10] = 1; b[20] = 1;
        CHECK(run(a, b, /*gap=*/4).size() == 2);   // 9-byte gap > 4 -> split
        CHECK(run(a, b, /*gap=*/16).size() == 1);  // 9-byte gap <= 16 -> merge
    }

    // ---- trailing length mismatch becomes a final region ------------------
    {
        std::vector<uint8_t> a(20, 0), b(64, 0);   // b is longer; [20,64) all "different"
        auto r = run(a, b);
        CHECK(r.size() == 1);
        CHECK(r[0].start == 20 && r[0].end == 64);
    }

    // ---- a diff in the overlap plus a trailing-size region ----------------
    {
        std::vector<uint8_t> a(20, 0), b(64, 0);
        b[2] = 1;                         // far from the tail (gap 16)
        auto r = run(a, b);
        CHECK(r.size() == 2);
        CHECK(r[0].start == 2  && r[0].end == 3);
        CHECK(r[1].start == 20 && r[1].end == 64);
    }

    // ---- a near-tail diff merges into the trailing region -----------------
    {
        std::vector<uint8_t> a(20, 0), b(64, 0);
        b[18] = 1;                        // within gap 16 of offset 20
        auto r = run(a, b);
        CHECK(r.size() == 1);
        CHECK(r[0].start == 18 && r[0].end == 64);
    }

    // ---- maxRegions cap -----------------------------------------------------
    {
        std::vector<uint8_t> a(64, 0), b(64, 0);
        for (int i = 0; i < 64; i += 2) b[i] = 1;   // many isolated diffs (gap 1 splits them)
        auto r = run(a, b, /*gap=*/0, /*maxR=*/3);
        CHECK(r.size() == 3);
    }

    if (g_fail == 0) std::printf("ALL DIFFREGIONS TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
