#pragma once
//
// DiffRegions.h
// Pure, UI-free coalescing of differing byte offsets into navigable regions for
// the Binary Diff view. Kept header-only and dependency-light so it can be unit
// tested directly (see tests/diffregions_test.cpp).
//
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace ds {

struct ByteDiffRegion { uint64_t start = 0, end = 0; };   // [start, end) file offsets

// A bounded sample retained for the compact differences list. The total count
// and region list are independent of this cap.
struct ByteDifference {
    uint64_t offset = 0;
    uint8_t  a = 0;
    uint8_t  b = 0;
};

struct ByteDiffScanResult {
    std::vector<ByteDifference> samples;
    std::vector<ByteDiffRegion> regions;
    uint64_t totalDiff = 0;
    bool cancelled = false;
};

using DiffCancelFn = std::function<bool()>;
using DiffProgressFn = std::function<void(uint64_t current, uint64_t total)>;

// One-pass flat comparison used by the Binary Diff background worker. It
// counts every difference, retains bounded UI samples, and coalesces regions
// without requiring a second whole-input pass. Cancellation and progress are
// checked/published at bounded 64 KiB intervals.
inline bool ScanByteDifferences(const uint8_t* a, size_t na, const uint8_t* b, size_t nb,
                                uint64_t gap, size_t maxSamples, size_t maxRegions,
                                ByteDiffScanResult& out,
                                const DiffCancelFn& shouldCancel = {},
                                const DiffProgressFn& onProgress = {}) {
    out = {};
    const size_t n = na < nb ? na : nb;
    const size_t big = na > nb ? na : nb;
    out.samples.reserve(maxSamples < n ? maxSamples : n);

    bool open = false;
    uint64_t start = 0, end = 0;
    auto flush = [&]() {
        if (!open) return;
        if (out.regions.size() < maxRegions) out.regions.push_back({ start, end });
        open = false;
    };

    constexpr size_t kPublishStride = 64u * 1024u;
    for (size_t i = 0; i < n; ++i) {
        if ((i % kPublishStride) == 0) {
            if (shouldCancel && shouldCancel()) {
                out.cancelled = true;
                return false;
            }
            if (onProgress) onProgress(i, n);
        }
        if (a[i] == b[i]) continue;

        ++out.totalDiff;
        if (out.samples.size() < maxSamples)
            out.samples.push_back({ static_cast<uint64_t>(i), a[i], b[i] });

        const uint64_t at = static_cast<uint64_t>(i);
        if (open && (at <= end || at - end <= gap)) end = at + 1;
        else { flush(); start = at; end = at + 1; open = true; }
    }

    if (shouldCancel && shouldCancel()) {
        out.cancelled = true;
        return false;
    }

    // Bytes present on only one side are all different and form one trailing
    // region. Samples deliberately cover only the overlap because there is no
    // byte value for the absent side, matching the historical UI contract.
    if (n < big) {
        out.totalDiff += static_cast<uint64_t>(big - n);
        const uint64_t at = static_cast<uint64_t>(n);
        if (open && (at <= end || at - end <= gap)) end = static_cast<uint64_t>(big);
        else { flush(); start = at; end = static_cast<uint64_t>(big); open = true; }
    }
    flush();
    if (onProgress) onProgress(n, n);
    return true;
}

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
