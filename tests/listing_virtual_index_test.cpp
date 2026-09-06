// Pure stress/adversarial coverage for the 64-bit Fenwick virtual listing index.
#include "Core/ListingVirtualIndex.h"

#include <cstdio>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(x, msg) do { if (!(x)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

int main() {
    std::vector<VirtualListingItem> items;
    items.reserve(20000);
    for (size_t i = 0; i < 20000; ++i)
        items.push_back({ 1000, 0x100000ull + i * 0x1000ull, 0x1000 });
    items[7].rows = 0;
    items[8].rows = 3;
    items[15].rows = 1;
    items[16].rows = 2049;

    ListingVirtualIndex index;
    index.reset(items);
    CHECK(index.totalRows() > 19000000ull, "millions of virtual rows remain 64-bit/indexed");

    ListingVirtualIndex::Location loc;
    CHECK(index.locate(index.rowOfItem(8), loc) && loc.item == 8 && loc.localRow == 0,
          "locate skips a zero-row item across a Fenwick power-of-two boundary");
    CHECK(index.locate(index.rowOfItem(16) + 2048, loc) && loc.item == 16 && loc.localRow == 2048,
          "locate handles exact tail around 16-item Fenwick transition");
    CHECK(!index.locate(index.totalRows(), loc), "global row end is exclusive");

    const uint64_t before17 = index.rowOfItem(17);
    CHECK(index.updateRows(8, 8193), "estimated page weight can become a larger exact weight");
    CHECK(index.rowOfItem(17) == before17 + 8190,
          "increasing one page shifts later prefixes by the exact delta");
    CHECK(index.locate(index.rowOfItem(8) + 8192, loc) && loc.item == 8 && loc.localRow == 8192,
          "updated page tail maps exactly");
    CHECK(index.updateRows(8, 2), "exact page weight can shrink after rematerialization");
    CHECK(index.locate(index.rowOfItem(8) + 1, loc) && loc.item == 8 && loc.localRow == 1,
          "shrunk page maps without stale Fenwick sums");

    // Capture the top row while an earlier page still has an estimated weight,
    // then shrink that page as lazy upward scrolling materializes it.  Reusing
    // the stale global row would land in the following page; descriptor-relative
    // reconciliation must keep the viewport in the page the user entered.
    ListingVirtualIndex reverse;
    reverse.reset({ { 12, 0x1000, 0x1000 }, { 12, 0x2000, 0x1000 },
                    { 12, 0x3000, 0x1000 } });
    ListingVirtualIndex::Location beforeShrink;
    CHECK(reverse.locate(reverse.rowOfItem(1) + 10, beforeShrink) &&
          beforeShrink.item == 1 && beforeShrink.localRow == 10,
          "reverse-scroll anchor is captured relative to its estimated page");
    const uint64_t staleGlobalRow = reverse.rowOfItem(1) + beforeShrink.localRow;
    CHECK(reverse.updateRows(1, 6), "preceding lazy page accepts its smaller exact weight");
    CHECK(reverse.locate(staleGlobalRow, loc) && loc.item == 2,
          "stale global clipper row demonstrates the forward-page bounce");
    uint64_t reconciledRow = UINT64_MAX;
    CHECK(reverse.reconcile(beforeShrink, reconciledRow) &&
          reverse.locate(reconciledRow, loc) && loc.item == 1 && loc.localRow == 5,
          "reverse-scroll anchor clamps inside the newly materialized page");

    // The common viewport case is a page *after* the descriptor whose estimate
    // changes. Preserve both the owning descriptor and its exact local row while
    // one or more preceding pages settle, in either direction.
    ListingVirtualIndex preceding;
    preceding.reset({ { 12, 0x1000, 0x1000 }, { 12, 0x2000, 0x1000 },
                       { 12, 0x3000, 0x1000 } });
    ListingVirtualIndex::Location stableViewport;
    CHECK(preceding.locate(preceding.rowOfItem(2) + 7, stableViewport) &&
          stableViewport.item == 2 && stableViewport.localRow == 7,
          "viewport anchor is captured after an estimated predecessor");
    const uint64_t staleAfterPredecessor = preceding.rowOfItem(2) + 7;
    CHECK(preceding.updateRows(1, 3),
          "preceding page can shrink when upward scrolling materializes it");
    const bool staleStillMapped = preceding.locate(staleAfterPredecessor, loc);
    CHECK(!staleStillMapped || loc.item != 2 || loc.localRow != 7,
          "stale global row drifts or leaves the index when a predecessor shrinks");
    CHECK(preceding.reconcile(stableViewport, reconciledRow) &&
          preceding.locate(reconciledRow, loc) && loc.item == 2 && loc.localRow == 7,
          "reconciliation preserves descriptor/local row after predecessor shrink");
    CHECK(preceding.updateRows(1, 30) &&
          preceding.reconcile(stableViewport, reconciledRow) &&
          preceding.locate(reconciledRow, loc) && loc.item == 2 && loc.localRow == 7,
          "reconciliation also preserves the viewport after predecessor growth");

    ListingVirtualIndex emptied;
    emptied.reset({ { 4, 0x4000, 0x1000 }, { 3, 0x5000, 0x1000 },
                    { 2, 0x6000, 0x1000 } });
    ListingVirtualIndex::Location emptyAnchor;
    CHECK(emptied.locate(5, emptyAnchor) && emptyAnchor.item == 1,
          "empty-page reconciliation fixture captures the middle descriptor");
    CHECK(emptied.updateRows(1, 0) && emptied.reconcile(emptyAnchor, reconciledRow) &&
          emptied.locate(reconciledRow, loc) && loc.item == 0 && loc.localRow == 3,
          "a page that becomes empty anchors to the closest preceding row");

    size_t owner = 0;
    CHECK(index.itemForAddress(0x100000, owner) && owner == 0,
          "address span includes its first byte");
    CHECK(index.itemForAddress(0x100fff, owner) && owner == 0,
          "address span includes its final byte");
    CHECK(index.itemForAddress(0x101000, owner) && owner == 1,
          "address span end is exclusive and selects the following page");

    ListingVirtualIndex overlaps;
    overlaps.reset({ { 1, 0x4000, 0x1000 }, { 1, 0x4000, 0x80 },
                     { 0, 0x5000, 0x100 }, { 2, 0, 0 } });
    CHECK(overlaps.itemForAddress(0x4040, owner) && owner == 1,
          "same-address overlaps prefer the smallest containing span");
    CHECK(overlaps.itemForAddress(0x4080, owner) && owner == 0,
          "small overlap end is exclusive and falls back to the larger span");
    CHECK(overlaps.itemForAddress(0x5000, owner) && owner == 2,
          "zero-row item can still own an address span");
    overlaps.reset({ { 1, 0x4000, 0x1000 }, { 1, 0x4800, 0x10 } });
    CHECK(overlaps.itemForAddress(0x4900, owner) && owner == 0,
          "failed greatest-start group falls back to an earlier enclosing span");

    overlaps.reset({ { 1, UINT64_MAX - 2, 3 }, { 1, UINT64_MAX - 1, 1 } });
    CHECK(overlaps.itemForAddress(UINT64_MAX, owner) && owner == 0,
          "terminal address remains contained when a later non-containing span is skipped");
    overlaps.reset({ { 1, UINT64_MAX, 1 } });
    CHECK(overlaps.itemForAddress(UINT64_MAX, owner) && owner == 0,
          "single-byte span at UINT64_MAX is addressable");

    if (g_fail) { std::printf("listing_virtual_index_test: %d failure(s)\n", g_fail); return 1; }
    std::printf("listing_virtual_index_test: all checks passed\n");
    return 0;
}
