#pragma once
#include "AddressSpan.h"
//
// ListingVirtualIndex.h
// A small, pure Fenwick-tree index for virtualized linear listings.  The backing
// listing has one item per static row or executable code page; each item contributes
// a mutable number of rendered rows.  Code pages start with an estimate and replace
// it with their exact decoded row count only when the page is requested.
//
// No ImGui, decoder, loader, or Win32 dependency.  All row arithmetic is 64-bit so
// multi-million-instruction images do not require a materialized address vector.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace ds {

struct VirtualListingItem {
    uint64_t rows = 1;       // estimated or exact rendered rows; zero hides the item
    uint64_t address = 0;    // optional address span used by itemForAddress()
    uint64_t byteSize = 0;   // zero means this item has no address span
};

class ListingVirtualIndex {
public:
    struct Location {
        size_t   item = 0;
        uint64_t localRow = 0;
    };

    void clear() {
        items_.clear();
        bit_.clear();
        addressOrder_.clear();
        addressPrefixMaxEnd_.clear();
    }

    void reset(const std::vector<VirtualListingItem>& items) {
        items_ = items;
        bit_.assign(items_.size() + 1, 0);
        addressOrder_.clear();
        addressOrder_.reserve(items_.size());
        for (size_t i = 0; i < items_.size(); ++i) {
            add(i, items_[i].rows);
            if (items_[i].byteSize) addressOrder_.push_back(i);
        }
        std::stable_sort(addressOrder_.begin(), addressOrder_.end(), [&](size_t a, size_t b) {
            if (items_[a].address != items_[b].address)
                return items_[a].address < items_[b].address;
            // Reverse search below sees the smallest same-start span first.
            return items_[a].byteSize > items_[b].byteSize;
        });
        addressPrefixMaxEnd_.resize(addressOrder_.size());
        uint64_t maxLast = 0;
        for (size_t i = 0; i < addressOrder_.size(); ++i) {
            const VirtualListingItem& span = items_[addressOrder_[i]];
            const uint64_t last = SaturatingAddressAdd(span.address, span.byteSize - 1);
            maxLast = std::max(maxLast, last);
            addressPrefixMaxEnd_[i] = maxLast;
        }
    }

    bool empty() const { return items_.empty() || totalRows() == 0; }
    size_t itemCount() const { return items_.size(); }
    uint64_t totalRows() const { return prefixRows(items_.size()); }
    uint64_t rows(size_t item) const { return item < items_.size() ? items_[item].rows : 0; }
    uint64_t rowOfItem(size_t item) const { return prefixRows(std::min(item, items_.size())); }

    // Replace an estimated page weight after bounded on-demand decoding.
    bool updateRows(size_t item, uint64_t rows) {
        if (item >= items_.size()) return false;
        const uint64_t old = items_[item].rows;
        if (old == rows) return true;
        items_[item].rows = rows;
        if (rows > old) add(item, rows - old);
        else sub(item, old - rows);
        return true;
    }

    // Map a global virtual row to its descriptor and row within that descriptor.
    bool locate(uint64_t row, Location& out) const {
        if (row >= totalRows() || items_.empty()) return false;
        size_t idx = 0;
        uint64_t consumed = 0;
        size_t step = 1;
        while (step < bit_.size()) step <<= 1;
        for (step >>= 1; step; step >>= 1) {
            const size_t next = idx + step;
            if (next < bit_.size() && bit_[next] <= row - consumed) {
                idx = next;
                consumed += bit_[next];
            }
        }
        if (idx >= items_.size()) return false;
        out.item = idx;
        out.localRow = row - consumed;
        return out.localRow < items_[idx].rows;
    }

    // Re-map a location captured before one or more item weights changed.  A
    // clipper range is expressed in global rows, so using its old row number
    // after a lazy page replaces an estimate with an exact count can silently
    // move the viewport into the following page.  Retain the descriptor and
    // clamp within its new extent instead.  An item that became empty (for
    // example a page wholly consumed by a crossing JVM instruction) resolves to
    // the closest preceding row, then to the following row when there is none.
    bool reconcile(const Location& before, uint64_t& row) const {
        if (before.item >= items_.size() || !totalRows()) return false;
        const uint64_t itemRows = items_[before.item].rows;
        if (itemRows) {
            row = rowOfItem(before.item) + std::min(before.localRow, itemRows - 1);
            return true;
        }

        const uint64_t itemStart = rowOfItem(before.item);
        if (itemStart) {
            row = itemStart - 1;
            return true;
        }
        if (itemStart < totalRows()) {
            row = itemStart;
            return true;
        }
        return false;
    }

    // Find the containing span with the greatest start; equal starts prefer the
    // smallest span. Executable code-page descriptors are disjoint in production,
    // while the tie rule keeps overlapping/synthetic test layouts deterministic.
    bool itemForAddress(uint64_t address, size_t& item) const {
        if (addressOrder_.empty()) return false;
        auto it = std::upper_bound(addressOrder_.begin(), addressOrder_.end(), address,
            [&](uint64_t value, size_t idx) { return value < items_[idx].address; });
        if (it == addressOrder_.begin()) return false;
        size_t pos = (size_t)(it - addressOrder_.begin());
        while (pos) {
            const uint64_t greatestStart = items_[addressOrder_[pos - 1]].address;
            do {
                const size_t candidateIndex = addressOrder_[--pos];
                const VirtualListingItem& candidate = items_[candidateIndex];
                if (AddressInSpan(candidate.address, (size_t)candidate.byteSize, address)) {
                    item = candidateIndex;
                    return true;
                }
            } while (pos && items_[addressOrder_[pos - 1]].address == greatestStart);
            // No earlier interval can reach this address: stop without a linear
            // walk across millions of disjoint code pages. Otherwise continue to
            // an enclosing earlier span (e.g. a section/header overlap).
            if (!pos || addressPrefixMaxEnd_[pos - 1] < address) return false;
        }
        return false;
    }

private:
    uint64_t prefixRows(size_t count) const {
        uint64_t sum = 0;
        for (size_t i = std::min(count, items_.size()); i; i -= i & (~i + 1))
            sum += bit_[i];
        return sum;
    }

    void add(size_t item, uint64_t delta) {
        for (size_t i = item + 1; i < bit_.size(); i += i & (~i + 1))
            bit_[i] += delta;
    }
    void sub(size_t item, uint64_t delta) {
        for (size_t i = item + 1; i < bit_.size(); i += i & (~i + 1))
            bit_[i] -= delta;
    }

    std::vector<VirtualListingItem> items_;
    std::vector<uint64_t>           bit_;          // one-based Fenwick tree
    std::vector<size_t>             addressOrder_; // items with byteSize != 0
    std::vector<uint64_t>           addressPrefixMaxEnd_;
};

} // namespace ds
