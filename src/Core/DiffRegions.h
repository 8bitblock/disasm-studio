#pragma once
//
// DiffRegions.h
// Pure, UI-free coalescing of differing byte offsets into navigable regions for
// the Binary Diff view. Kept header-only and dependency-light so it can be unit
// tested directly (see tests/diffregions_test.cpp).
//
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ds {

struct ByteDiffRegion { uint64_t start = 0, end = 0; };   // [start, end) file offsets

// Compare a[0..na) with b[0..nb) and coalesce differing offsets into regions,
// merging two runs whenever the gap of equal bytes between them is <= `gap`
// (so the few bytes of one changed instruction collapse to a single region).
// Any trailing length mismatch past the overlap becomes one final region.
// Output is capped at `maxRegions` entries.
inline void CoalesceDiffRegions(const uint8_t* a, size_t na, const uint8_t* b, size_t nb,
                                uint64_t gap, size_t maxRegions, std::vector<ByteDiffRegion>& out) {
    out.clear();
    const size_t n   = na < nb ? na : nb;   // compared overlap
    const size_t big = na > nb ? na : nb;   // full length

    bool open = false;
    uint64_t st = 0, en = 0;
    auto flush = [&]() { if (open) { if (out.size() < maxRegions) out.push_back({ st, en }); open = false; } };

    for (size_t i = 0; i < n && out.size() < maxRegions; ++i) {
        if (a[i] == b[i]) continue;
        if (open && (uint64_t)i <= en + gap) en = (uint64_t)i + 1;   // extend across a small gap
        else { flush(); st = (uint64_t)i; en = (uint64_t)i + 1; open = true; }
    }
    // The length difference past the overlap is one trailing region.
    if (n < big && out.size() < maxRegions) {
        if (open && (uint64_t)n <= en + gap) en = big;
        else { flush(); st = (uint64_t)n; en = big; open = true; }
    }
    flush();
}

} // namespace ds
