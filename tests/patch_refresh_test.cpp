// Dependency-light coverage for in-place patch span accumulation and debounce.
#include "Core/PatchRefresh.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <limits>

using namespace ds;
using namespace std::chrono_literals;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    using Debouncer = PatchRefreshDebouncer;
    using Clock = Debouncer::Clock;
    constexpr uint64_t kMax = (std::numeric_limits<uint64_t>::max)();
    const Clock::time_point t0{};

    // VA zero is ordinary, the deadline is inclusive, and take atomically
    // returns the work while resetting the accumulator for the next burst.
    {
        Debouncer refresh;
        CHECK(!refresh.pending() && !refresh.due(t0));
        refresh.noteSpan(0, 0, t0, 100ms);
        CHECK(!refresh.pending() && refresh.spans().empty());
        refresh.noteSpan(0, 4, t0, 100ms);
        CHECK(refresh.pending() && !refresh.fullRefreshRequired());
        CHECK(refresh.spans().size() == 1);
        CHECK(refresh.spans()[0] == (PatchRefreshSpan{0, 4, false}));
        CHECK(refresh.spans()[0].contains(0) && refresh.spans()[0].contains(3));
        CHECK(!refresh.spans()[0].contains(4));
        CHECK(!refresh.due(t0 + 99ms) && refresh.due(t0 + 100ms));

        PatchRefreshRequest request = refresh.take();
        CHECK(request && !request.fullRefresh && request.spans.size() == 1);
        CHECK(!refresh.pending() && refresh.spans().empty() &&
              !refresh.fullRefreshRequired());
        CHECK(refresh.take().empty());
    }

    // Overlap, adjacency, and a later bridge all canonicalize into sorted,
    // disjoint spans; a real one-byte gap remains separate.
    {
        Debouncer refresh;
        refresh.noteSpan(100, 10, t0, 1ms); // [100,110)
        refresh.noteSpan(105, 10, t0, 1ms); // overlap -> [100,115)
        refresh.noteSpan(115, 5, t0, 1ms);  // adjacent -> [100,120)
        refresh.noteSpan(50, 10, t0, 1ms);  // sorted disjoint prefix
        refresh.noteSpan(121, 2, t0, 1ms);  // address 120 is a gap
        CHECK(refresh.spans().size() == 3);
        CHECK(refresh.spans()[0] == (PatchRefreshSpan{50, 60, false}));
        CHECK(refresh.spans()[1] == (PatchRefreshSpan{100, 120, false}));
        CHECK(refresh.spans()[2] == (PatchRefreshSpan{121, 123, false}));
        refresh.noteSpan(60, 61, t0, 1ms); // bridges all three ranges
        CHECK(refresh.spans().size() == 1);
        CHECK(refresh.spans()[0] == (PatchRefreshSpan{50, 123, false}));
    }

    // Every real edit in a burst can extend the quiet-period deadline. A zero
    // span and a later observation with a shorter candidate deadline do not
    // accidentally postpone or shorten existing work.
    {
        Debouncer refresh;
        refresh.noteSpan(1, 1, t0, 100ms);
        CHECK(refresh.deadline() == t0 + 100ms);
        refresh.noteSpan(2, 1, t0 + 50ms, 100ms);
        CHECK(refresh.deadline() == t0 + 150ms);
        refresh.noteSpan(3, 0, t0 + 1000ms, 100ms);
        CHECK(refresh.deadline() == t0 + 150ms);
        refresh.noteSpan(3, 1, t0 + 60ms, 10ms);
        CHECK(refresh.deadline() == t0 + 150ms);
        CHECK(!refresh.due(t0 + 149ms) && refresh.due(t0 + 150ms));
    }

    // Terminal spans never wrap to VA zero. The saturated-end flag represents
    // the mathematical exclusive end 2^64, including a one-byte edit at MAX.
    {
        Debouncer refresh;
        refresh.noteSpan(kMax - 1, 8, t0, 0ms);
        CHECK(refresh.spans().size() == 1);
        CHECK(refresh.spans()[0] == (PatchRefreshSpan{kMax - 1, kMax, true}));
        CHECK(refresh.spans()[0].contains(kMax - 1));
        CHECK(refresh.spans()[0].contains(kMax));
        CHECK(!refresh.spans()[0].contains(0));

        refresh.reset();
        refresh.noteSpan(0, kMax, t0, 0ms); // [0, MAX), excludes MAX
        CHECK(refresh.spans()[0] == (PatchRefreshSpan{0, kMax, false}));
        refresh.noteSpan(kMax, 1, t0, 0ms); // adjacent terminal byte
        CHECK(refresh.spans().size() == 1);
        CHECK(refresh.spans()[0] == (PatchRefreshSpan{0, kMax, true}));
        CHECK(refresh.spans()[0].contains(0) &&
              refresh.spans()[0].contains(kMax));
    }

    // Compare the bound only after merging: a bridge which collapses two
    // existing spans is precise, while a third truly disjoint span promotes the
    // request to the safe full-image fallback.
    {
        Debouncer refresh(2);
        refresh.noteSpan(0, 2, t0, 5ms);
        refresh.noteSpan(4, 2, t0, 5ms);
        refresh.noteSpan(2, 2, t0, 5ms);
        CHECK(!refresh.fullRefreshRequired() && refresh.spanCount() == 1);
        CHECK(refresh.spans()[0] == (PatchRefreshSpan{0, 6, false}));

        refresh.noteSpan(20, 1, t0, 5ms);
        CHECK(!refresh.fullRefreshRequired() && refresh.spanCount() == 2);
        refresh.noteSpan(40, 1, t0, 5ms);
        CHECK(refresh.pending() && refresh.fullRefreshRequired());
        CHECK(refresh.spans().empty());
        refresh.noteSpan(60, 1, t0 + 10ms, 5ms);
        CHECK(refresh.fullRefreshRequired() && refresh.spans().empty());
        CHECK(refresh.deadline() == t0 + 15ms);
        PatchRefreshRequest request = refresh.take();
        CHECK(request.fullRefresh && request.spans.empty());
    }

    // An unknown mutation and a zero-sized precision budget both fail safely to
    // a full refresh. reset() discards either kind of pending work.
    {
        Debouncer unknown;
        unknown.noteSpan(0x1000, 4, t0, 10ms);
        unknown.noteUnknown(t0, 25ms);
        CHECK(unknown.pending() && unknown.fullRefreshRequired() &&
              unknown.spans().empty());
        CHECK(!unknown.due(t0 + 24ms) && unknown.due(t0 + 25ms));
        unknown.reset();
        CHECK(!unknown.pending() && !unknown.fullRefreshRequired());

        Debouncer noPreciseCapacity(0);
        noPreciseCapacity.noteSpan(0, 1, t0, 0ms);
        CHECK(noPreciseCapacity.fullRefreshRequired() &&
              noPreciseCapacity.spans().empty());
    }

    // Deadline arithmetic itself saturates instead of overflowing and making a
    // queued refresh spuriously due near the clock's maximum time point.
    {
        Debouncer refresh;
        const auto nearMax = Clock::time_point::max() - Clock::duration{5};
        refresh.noteSpan(1, 1, nearMax, Clock::duration{10});
        CHECK(refresh.deadline() == Clock::time_point::max());
        CHECK(!refresh.due(nearMax) && refresh.due(Clock::time_point::max()));
    }

    if (!g_fail) std::printf("patch_refresh_test: all checks passed\n");
    return g_fail ? 1 : 0;
}
