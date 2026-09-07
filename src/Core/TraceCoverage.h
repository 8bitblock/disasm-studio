#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace ds {

// A stable, UI-facing counter. Vectors in TraceCoverageSnapshot are sorted by VA
// so callers can binary-search them and snapshots are deterministic in tests.
struct TraceHitCount {
    uint64_t va = 0;
    uint64_t hits = 0;
};

struct TraceCoverageSnapshot {
    bool active = false;
    uint64_t generation = 0;
    uint64_t revision = 0; // changes whenever snapshot-visible state changes

    size_t requestedSites = 0; // before de-duplication / the safety cap
    size_t plannedSites = 0;   // unique, bounded basic-block starts
    bool planTruncated = false; // additional unique sites exceeded the limit
    size_t armedSites = 0;     // internal int3 sites currently owned by Debugger
    size_t hitSites = 0;       // one-shot sites already consumed
    size_t skippedSites = 0;   // unreadable, conflicting, or naturally int3 sites
    size_t retiredSites = 0;   // consumed coverage hidden by Clear Trace

    uint64_t instructionHitTotal = 0;
    uint64_t blockHitTotal = 0;
    std::vector<TraceHitCount> instructions;
    std::vector<TraceHitCount> blocks;
    std::vector<uint64_t> armed;
};

// Dependency-light trace/coverage state. It deliberately knows nothing about
// Win32 or process memory: Debugger owns byte planting/restoration and calls the
// generation-checked hooks below from its debug-event thread.
class TraceCoverage {
public:
    static constexpr size_t kMaxSites = 65536;

    // Starts a fresh session and returns its generation. Input is sorted,
    // de-duplicated, and capped at min(maxSites, kMaxSites); VA 0 is valid.
    // Admission retains the lowest unique VAs with bounded temporary storage.
    uint64_t begin(const std::vector<uint64_t>& basicBlockStarts,
                   size_t maxSites = kMaxSites);
    void stop();
    void clearHits();
    void reset(); // detach/new target: discard plan and counters

    bool active() const;
    uint64_t generation() const;
    std::vector<uint64_t> pendingSites(uint64_t generation) const;

    void markArmed(uint64_t generation, uint64_t va);
    void markSkipped(uint64_t generation, uint64_t va);
    void markDisarmed(uint64_t generation, uint64_t va);

    // A one-shot block hit is also an executed-instruction hit at the block VA.
    void recordBlockHit(uint64_t generation, uint64_t va);
    void recordInstructionHit(uint64_t generation, uint64_t va);

    TraceCoverageSnapshot snapshot() const;
    // Refresh caller-owned retained state only when its generation/revision
    // differs. Unchanged polling does not allocate, sort, or touch its vectors.
    bool snapshotIfChanged(TraceCoverageSnapshot& retained) const;

private:
    enum class SiteState : uint8_t { Pending, Armed, Hit, Skipped, Retired };
    TraceCoverageSnapshot snapshotLocked() const; // mtx_ must be held

    mutable std::mutex mtx_;
    bool active_ = false;
    uint64_t generation_ = 0;
    uint64_t revision_ = 0;
    size_t requestedSites_ = 0;
    bool planTruncated_ = false;
    std::unordered_map<uint64_t, SiteState> sites_;
    std::unordered_map<uint64_t, uint64_t> instructionHits_;
    std::unordered_map<uint64_t, uint64_t> blockHits_;
};

} // namespace ds
