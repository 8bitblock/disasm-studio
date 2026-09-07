#include "TraceCoverage.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <set>
#include <utility>

namespace ds {

namespace {

void bump(std::unordered_map<uint64_t, uint64_t>& counts, uint64_t va) {
    uint64_t& n = counts[va];
    if (n != std::numeric_limits<uint64_t>::max()) ++n;
}

void copyCounts(const std::unordered_map<uint64_t, uint64_t>& counts,
                std::vector<TraceHitCount>& out, uint64_t& total) {
    out.reserve(counts.size());
    for (const auto& [va, hits] : counts) {
        out.push_back({ va, hits });
        if (std::numeric_limits<uint64_t>::max() - total < hits)
            total = std::numeric_limits<uint64_t>::max();
        else
            total += hits;
    }
}

void sortSnapshot(TraceCoverageSnapshot& snapshot) {
    const auto byAddress = [](const auto& a, const auto& b) {
        return a.va < b.va;
    };
    std::sort(snapshot.instructions.begin(), snapshot.instructions.end(), byAddress);
    std::sort(snapshot.blocks.begin(), snapshot.blocks.end(), byAddress);
    std::sort(snapshot.armed.begin(), snapshot.armed.end());
}

} // namespace

uint64_t TraceCoverage::begin(const std::vector<uint64_t>& basicBlockStarts,
                              size_t maxSites) {
    const size_t limit = std::min(maxSites, kMaxSites);
    std::vector<uint64_t> starts;
    bool truncated = false;
    if (basicBlockStarts.size() <= limit) {
        starts = basicBlockStarts;
        std::sort(starts.begin(), starts.end());
        starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    } else if (limit == 0) {
        truncated = !basicBlockStarts.empty();
    } else {
        // A caller can supply arbitrarily many seeds. Never copy the whole
        // request only to discard most of it after sorting. The bounded set
        // preserves the existing lowest-address admission policy and tells us
        // whether unique sites, rather than merely duplicates, were omitted.
        std::set<uint64_t> selected;
        for (const uint64_t va : basicBlockStarts) {
            if (selected.size() == limit && va > *selected.rbegin()) {
                truncated = true;
                continue;
            }
            selected.insert(va);
            if (selected.size() > limit) {
                selected.erase(std::prev(selected.end()));
                truncated = true;
            }
        }
        starts.assign(selected.begin(), selected.end());
    }

    std::lock_guard<std::mutex> lock(mtx_);
    ++generation_;
    if (generation_ == 0) ++generation_; // reserve zero as "no session"
    active_ = true;
    ++revision_;
    requestedSites_ = basicBlockStarts.size();
    planTruncated_ = truncated;
    sites_.clear();
    instructionHits_.clear();
    blockHits_.clear();
    sites_.reserve(starts.size());
    for (uint64_t va : starts) sites_.emplace(va, SiteState::Pending);
    return generation_;
}

void TraceCoverage::stop() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (active_) { active_ = false; ++revision_; }
}

void TraceCoverage::clearHits() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (instructionHits_.empty() && blockHits_.empty()) return;
    instructionHits_.clear();
    blockHits_.clear();
    for (auto& [_, state] : sites_)
        if (state == SiteState::Hit) state = SiteState::Retired;
    ++revision_;
}

void TraceCoverage::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    ++generation_;
    if (generation_ == 0) ++generation_;
    ++revision_;
    active_ = false;
    requestedSites_ = 0;
    planTruncated_ = false;
    sites_.clear();
    instructionHits_.clear();
    blockHits_.clear();
}

bool TraceCoverage::active() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return active_;
}

uint64_t TraceCoverage::generation() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return generation_;
}

std::vector<uint64_t> TraceCoverage::pendingSites(uint64_t generation) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<uint64_t> out;
    if (!active_ || generation != generation_) return out;
    for (const auto& [va, state] : sites_)
        if (state == SiteState::Pending) out.push_back(va);
    std::sort(out.begin(), out.end());
    return out;
}

void TraceCoverage::markArmed(uint64_t generation, uint64_t va) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_) return;
    auto it = sites_.find(va);
    if (it != sites_.end() && it->second == SiteState::Pending)
        { it->second = SiteState::Armed; ++revision_; }
}

void TraceCoverage::markSkipped(uint64_t generation, uint64_t va) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (generation != generation_) return;
    auto it = sites_.find(va);
    if (it != sites_.end() && it->second != SiteState::Hit &&
        it->second != SiteState::Retired && it->second != SiteState::Skipped)
        { it->second = SiteState::Skipped; ++revision_; }
}

void TraceCoverage::markDisarmed(uint64_t generation, uint64_t va) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (generation != generation_) return;
    auto it = sites_.find(va);
    if (it != sites_.end() && it->second == SiteState::Armed)
        { it->second = SiteState::Pending; ++revision_; }
}

void TraceCoverage::recordBlockHit(uint64_t generation, uint64_t va) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_) return;
    auto it = sites_.find(va);
    if (it == sites_.end()) return;
    bump(instructionHits_, va);
    bump(blockHits_, va);
    it->second = SiteState::Hit;
    ++revision_;
}

void TraceCoverage::recordInstructionHit(uint64_t generation, uint64_t va) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (active_ && generation == generation_) { bump(instructionHits_, va); ++revision_; }
}

TraceCoverageSnapshot TraceCoverage::snapshotLocked() const {
    TraceCoverageSnapshot out;
    out.active = active_;
    out.generation = generation_;
    out.revision = revision_;
    out.requestedSites = requestedSites_;
    out.plannedSites = sites_.size();
    out.planTruncated = planTruncated_;
    copyCounts(instructionHits_, out.instructions, out.instructionHitTotal);
    copyCounts(blockHits_, out.blocks, out.blockHitTotal);
    for (const auto& [va, state] : sites_) {
        switch (state) {
            case SiteState::Armed: ++out.armedSites; out.armed.push_back(va); break;
            case SiteState::Hit: ++out.hitSites; break;
            case SiteState::Skipped: ++out.skippedSites; break;
            case SiteState::Retired: ++out.retiredSites; break;
            case SiteState::Pending: break;
        }
    }
    return out;
}

TraceCoverageSnapshot TraceCoverage::snapshot() const {
    TraceCoverageSnapshot out;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        out = snapshotLocked();
    }
    // Sorting a large report must not hold up the debug-event owner recording
    // hits. All vectors and totals above already belong to one coherent revision.
    sortSnapshot(out);
    return out;
}

bool TraceCoverage::snapshotIfChanged(TraceCoverageSnapshot& retained) const {
    TraceCoverageSnapshot out;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (retained.generation == generation_ && retained.revision == revision_)
            return false;
        out = snapshotLocked();
    }
    sortSnapshot(out);
    retained = std::move(out);
    return true;
}

} // namespace ds
