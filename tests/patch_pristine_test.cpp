//
// patch_pristine_test.cpp
// Off-target unit test for SubstitutePristine (src/Core/Project.h): capturing a
// new patch's "orig" bytes from the already-patched image must substitute the
// saved origs of every overlapping recorded patch, so overlapping patches revert
// exactly (never recording another patch's bytes as "original").
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\patch_pristine_test.cpp
//   .\patch_pristine_test.exe
//
#include "Core/Project.h"

#include <cstdint>
#include <cstdio>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Simulate the image: pristine bytes at base 0x1000.
struct Image {
    uint64_t base = 0x1000;
    std::vector<uint8_t> bytes;
    void write(uint64_t va, const std::vector<uint8_t>& b) {
        for (size_t i = 0; i < b.size(); ++i) bytes[(size_t)(va - base + i)] = b[i];
    }
    std::vector<uint8_t> read(uint64_t va, size_t n) const {
        return { bytes.begin() + (size_t)(va - base), bytes.begin() + (size_t)(va - base) + n };
    }
};

// Mirror applyPatchBytes' capture: read current (patched) bytes, substitute
// pristine, record, apply.
static void apply(Image& img, std::vector<PjPatch>& V, uint64_t va, std::vector<uint8_t> b) {
    std::vector<uint8_t> cur = img.read(va, b.size());
    SubstitutePristine(va, cur, V);
    V.push_back({ va, cur, b });
    img.write(va, b);
}

// Mirror revertPatchAt: restore orig, erase, re-apply surviving overlappers in order.
static void revert(Image& img, std::vector<PjPatch>& V, uint64_t va) {
    for (size_t k = 0; k < V.size(); ++k) {
        if (V[k].address != va) continue;
        const uint64_t lo = va, hi = va + V[k].orig.size();
        img.write(va, V[k].orig);
        V.erase(V.begin() + k);
        for (const auto& p : V) {
            if (p.address >= hi || p.address + p.bytes.size() <= lo) continue;
            img.write(p.address, p.bytes);
        }
        return;
    }
}

int main() {
    const std::vector<uint8_t> pristine = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

    // ---- overlap on the right: P1 @0x1000 [3], P2 @0x1001 [3] ---------------
    {
        Image img{ 0x1000, pristine };
        std::vector<PjPatch> V;
        apply(img, V, 0x1000, { 0xAA, 0xBB, 0xCC });
        apply(img, V, 0x1001, { 0xD1, 0xD2, 0xD3 });
        // P2's orig must be pristine [22 33 44], NOT patched [BB CC 44].
        CHECK(V[1].orig == (std::vector<uint8_t>{ 0x22, 0x33, 0x44 }));
        // Revert in reverse order: P2 then P1 -> pristine.
        revert(img, V, 0x1001);
        revert(img, V, 0x1000);
        CHECK(img.bytes == pristine);
    }
    // ---- same patches, revert in APPLICATION order: P1 then P2 -------------
    {
        Image img{ 0x1000, pristine };
        std::vector<PjPatch> V;
        apply(img, V, 0x1000, { 0xAA, 0xBB, 0xCC });
        apply(img, V, 0x1001, { 0xD1, 0xD2, 0xD3 });
        revert(img, V, 0x1000);
        // P1 reverted but P2 survives: image must be pristine + P2 only.
        CHECK(img.read(0x1001, 3) == (std::vector<uint8_t>{ 0xD1, 0xD2, 0xD3 }));
        CHECK(img.bytes[0] == 0x11);   // P1's non-overlapped byte restored
        revert(img, V, 0x1001);
        CHECK(img.bytes == pristine);
    }
    // ---- patch fully inside another: P1 @0x1000 [6], P2 @0x1002 [2] --------
    {
        Image img{ 0x1000, pristine };
        std::vector<PjPatch> V;
        apply(img, V, 0x1000, { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 });
        apply(img, V, 0x1002, { 0xB0, 0xB1 });
        CHECK(V[1].orig == (std::vector<uint8_t>{ 0x33, 0x44 }));   // pristine, not A2 A3
        revert(img, V, 0x1000);   // outer first: inner survivor re-applied
        CHECK(img.read(0x1002, 2) == (std::vector<uint8_t>{ 0xB0, 0xB1 }));
        revert(img, V, 0x1002);
        CHECK(img.bytes == pristine);
    }
    // ---- overlap on the left: P1 @0x1003 [3], P2 @0x1001 [3] ---------------
    {
        Image img{ 0x1000, pristine };
        std::vector<PjPatch> V;
        apply(img, V, 0x1003, { 0xC0, 0xC1, 0xC2 });
        apply(img, V, 0x1001, { 0xE0, 0xE1, 0xE2 });
        CHECK(V[1].orig == (std::vector<uint8_t>{ 0x22, 0x33, 0x44 }));   // 0x1003 pristine = 0x44
        revert(img, V, 0x1001);
        revert(img, V, 0x1003);
        CHECK(img.bytes == pristine);
    }
    // ---- three-deep layering, mixed revert order ----------------------------
    {
        Image img{ 0x1000, pristine };
        std::vector<PjPatch> V;
        apply(img, V, 0x1000, { 0xA0, 0xA1, 0xA2, 0xA3 });
        apply(img, V, 0x1002, { 0xB0, 0xB1, 0xB2 });
        apply(img, V, 0x1001, { 0xC0, 0xC1 });
        CHECK(V[2].orig == (std::vector<uint8_t>{ 0x22, 0x33 }));   // pristine through 2 layers
        revert(img, V, 0x1002);   // middle first
        revert(img, V, 0x1000);
        revert(img, V, 0x1001);
        CHECK(img.bytes == pristine);
    }
    // ---- non-overlapping patches are untouched by substitution -------------
    {
        Image img{ 0x1000, pristine };
        std::vector<PjPatch> V;
        apply(img, V, 0x1000, { 0xAA });
        apply(img, V, 0x1004, { 0xBB, 0xCC });
        CHECK(V[1].orig == (std::vector<uint8_t>{ 0x55, 0x66 }));
        revert(img, V, 0x1004);
        revert(img, V, 0x1000);
        CHECK(img.bytes == pristine);
    }

    if (g_fail == 0) std::printf("ALL PATCH PRISTINE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
