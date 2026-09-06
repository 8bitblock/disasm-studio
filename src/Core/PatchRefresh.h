#pragma once
//
// PatchRefresh.h
// Dependency-light accumulation and debounce policy for in-place image edits.
// Callers retain their current view while edits are collected, then consume one
// sorted, merged refresh request after the quiet-period deadline.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ds {

// A non-empty half-open address interval. `end` is the ordinary exclusive end
// unless endAtAddressLimit is true. In that case the mathematical exclusive end
// is UINT64_MAX+1, which uint64_t cannot represent, and `end` is saturated to
// UINT64_MAX. The flag therefore keeps a one-byte span beginning at UINT64_MAX
// distinct from an empty interval.
struct PatchRefreshSpan {
    uint64_t begin = 0;
    uint64_t end = 0;
    bool endAtAddressLimit = false;

    friend bool operator==(const PatchRefreshSpan&,
                           const PatchRefreshSpan&) = default;

    bool contains(uint64_t address) const noexcept {
        if (address < begin) return false;
        return endAtAddressLimit ? true : address < end;
    }
};

struct PatchRefreshRequest {
    // Set for an explicitly unknown mutation or when the precise span budget was
    // exceeded. Consumers must conservatively refresh the complete image and
    // ignore `spans` (which is kept empty in this state).
    bool fullRefresh = false;
    std::vector<PatchRefreshSpan> spans;

    bool empty() const noexcept { return !fullRefresh && spans.empty(); }
    explicit operator bool() const noexcept { return !empty(); }
};

class PatchRefreshDebouncer {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = Clock::duration;

    static constexpr size_t kDefaultMaxSpans = 32;

    explicit PatchRefreshDebouncer(
        size_t maxSpans = kDefaultMaxSpans) noexcept
        : maxSpans_(maxSpans) {}

    // Record [begin, begin+byteCount). A range which would pass UINT64_MAX is
    // saturated at the address-space limit. Zero-byte observations are no-ops:
    // they neither create work nor extend an existing debounce deadline.
    void noteSpan(uint64_t begin, uint64_t byteCount,
                  TimePoint now, Duration debounceDelay) {
        if (!byteCount) return;
        arm(now, debounceDelay);
        if (fullRefresh_) return;

        const PatchRefreshSpan candidate = normalize(begin, byteCount);
        try {
            merge(candidate);
        } catch (const std::bad_alloc&) {
            promoteToFullRefresh();
        } catch (const std::length_error&) {
            promoteToFullRefresh();
        }
    }

    // Use when the changed bytes cannot be described precisely. Once promoted,
    // subsequent precise observations remain conservatively full but still
    // extend the same quiet-period deadline.
    void noteUnknown(TimePoint now, Duration debounceDelay) noexcept {
        arm(now, debounceDelay);
        promoteToFullRefresh();
    }

    bool pending() const noexcept { return pending_; }
    bool due(TimePoint now) const noexcept {
        return pending_ && now >= deadline_;
    }
    TimePoint deadline() const noexcept { return deadline_; }
    bool fullRefreshRequired() const noexcept { return fullRefresh_; }
    const std::vector<PatchRefreshSpan>& spans() const noexcept { return spans_; }
    size_t spanCount() const noexcept { return spans_.size(); }
    size_t maxSpans() const noexcept { return maxSpans_; }

    // Consumption is deliberately separate from due(): a caller may force an
    // early refresh during shutdown or a document transition.
    PatchRefreshRequest take() noexcept {
        PatchRefreshRequest request;
        request.fullRefresh = fullRefresh_;
        request.spans = std::move(spans_);
        pending_ = false;
        fullRefresh_ = false;
        deadline_ = {};
        spans_.clear();
        return request;
    }

    void reset() noexcept {
        pending_ = false;
        fullRefresh_ = false;
        deadline_ = {};
        spans_.clear();
    }

private:
    static constexpr uint64_t addressMax() noexcept {
        return (std::numeric_limits<uint64_t>::max)();
    }

    static PatchRefreshSpan normalize(uint64_t begin,
                                      uint64_t byteCount) noexcept {
        // `addressMax()-begin` is the largest ordinary exclusive-end delta.
        // Any greater count reaches the terminal address and needs the explicit
        // 2^64-end marker instead of a wrapping addition.
        const uint64_t ordinaryRoom = addressMax() - begin;
        if (byteCount > ordinaryRoom)
            return {begin, addressMax(), true};
        return {begin, begin + byteCount, false};
    }

    static bool strictlyBefore(const PatchRefreshSpan& left,
                               const PatchRefreshSpan& right) noexcept {
        if (left.endAtAddressLimit) return false;
        // Equal means adjacent and is intentionally merged.
        return left.end < right.begin;
    }

    static PatchRefreshSpan unite(const PatchRefreshSpan& left,
                                  const PatchRefreshSpan& right) noexcept {
        PatchRefreshSpan result;
        result.begin = (std::min)(left.begin, right.begin);
        result.endAtAddressLimit = left.endAtAddressLimit ||
                                   right.endAtAddressLimit;
        result.end = result.endAtAddressLimit
                   ? addressMax()
                   : (std::max)(left.end, right.end);
        return result;
    }

    static TimePoint saturatingDeadline(TimePoint now,
                                        Duration delay) noexcept {
        if (delay <= Duration::zero()) return now;
        const Duration maxTicks = TimePoint::max().time_since_epoch();
        const Duration nowTicks = now.time_since_epoch();
        if (nowTicks > maxTicks - delay) return TimePoint::max();
        return now + delay;
    }

    void arm(TimePoint now, Duration debounceDelay) noexcept {
        const TimePoint candidate = saturatingDeadline(now, debounceDelay);
        if (!pending_ || candidate > deadline_) deadline_ = candidate;
        pending_ = true;
    }

    void promoteToFullRefresh() noexcept {
        fullRefresh_ = true;
        spans_.clear();
    }

    void merge(PatchRefreshSpan candidate) {
        std::vector<PatchRefreshSpan> merged;
        if (spans_.size() == (std::numeric_limits<size_t>::max)()) {
            promoteToFullRefresh();
            return;
        }
        merged.reserve(spans_.size() + 1);

        bool inserted = false;
        for (const PatchRefreshSpan& span : spans_) {
            if (strictlyBefore(span, candidate)) {
                merged.push_back(span);
            } else if (strictlyBefore(candidate, span)) {
                if (!inserted) {
                    merged.push_back(candidate);
                    inserted = true;
                }
                merged.push_back(span);
            } else {
                candidate = unite(candidate, span);
            }
        }
        if (!inserted) merged.push_back(candidate);

        if (merged.size() > maxSpans_) {
            promoteToFullRefresh();
            return;
        }
        spans_.swap(merged);
    }

    const size_t maxSpans_;
    bool pending_ = false;
    bool fullRefresh_ = false;
    TimePoint deadline_{};
    std::vector<PatchRefreshSpan> spans_;
};

} // namespace ds
