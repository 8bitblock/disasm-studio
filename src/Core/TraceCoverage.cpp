#include "TraceCoverage.h"

#include <algorithm>
#include <limits>

namespace ds {

namespace {

void bump(std::unordered_map<uint64_t, uint64_t>& counts, uint64_t va) {
    uint64_t& n = counts[va];
    if (n != std::numeric_limits<uint64_t>::max()) ++n;
}

std::vector<TraceHitCount> sortedCounts(
    const std::unordered_map<uint64_t, uint64_t>& counts) {
    std::vector<TraceHitCount> out;
    out.reserve(counts.size());
    for (const auto& [va, hits] : counts) out.push_back({ va, hits });
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        return a.va < b.va;
    });
    return out;
}

uint64_t totalOf(const std::unordered_map<uint64_t, uint64_t>& counts) {
    uint64_t total = 0;
    for (const auto& [_, hits] : counts) {
        if (std::numeric_limits<uint64_t>::max() - total < hits)
            return std::numeric_limits<uint64_t>::max();
        total += hits;
    }
    return total;
}

} // namespace

uint64_t TraceCoverage::begin(const std::vector<uint64_t>& basicBlockStarts,
                              size_t maxSites) {
    std::vector<uint64_t> starts = basicBlockStarts;
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    if (starts.size() > maxSites) starts.resize(maxSites);

    std::lock_guard<std::mutex> lock(mtx_);
    ++generation_;
    if (generation_ == 0) ++generation_; // reserve zero as "no session"
    active_ = true;
    ++revision_;
    requestedSites_ = basicBlockStarts.size();
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
        it->second != SiteState::Retired)
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

TraceCoverageSnapshot TraceCoverage::snapshot() const {
    std::lock_guard<std::mutex> lock(mtx_);
    TraceCoverageSnapshot out;
    out.active = active_;
    out.generation = generation_;
    out.revision = revision_;
    out.requestedSites = requestedSites_;
    out.plannedSites = sites_.size();
    out.instructions = sortedCounts(instructionHits_);
    out.blocks = sortedCounts(blockHits_);
    out.instructionHitTotal = totalOf(instructionHits_);
    out.blockHitTotal = totalOf(blockHits_);
    for (const auto& [va, state] : sites_) {
        switch (state) {
            case SiteState::Armed: ++out.armedSites; out.armed.push_back(va); break;
            case SiteState::Hit: ++out.hitSites; break;
            case SiteState::Skipped: ++out.skippedSites; break;
            case SiteState::Retired: ++out.retiredSites; break;
            case SiteState::Pending: break;
        }
    }
    std::sort(out.armed.begin(), out.armed.end());
    return out;
}

} // namespace ds
