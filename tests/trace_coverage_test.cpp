#include "Core/TraceCoverage.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include <vector>

using namespace ds;

static void testBoundedAdmission() {
    TraceCoverage trace;

    // A caller cannot raise the process-memory planting safety cap. Include
    // duplicates and descending input so admission cannot merely keep a prefix.
    std::vector<uint64_t> excessive;
    for (uint64_t va = TraceCoverage::kMaxSites + 2000; va != 0; --va) {
        excessive.push_back(va);
        excessive.push_back(va);
    }
    excessive.push_back(0);
    auto generation = trace.begin(excessive, std::numeric_limits<size_t>::max());
    auto retained = trace.snapshot();
    assert(retained.requestedSites == excessive.size());
    assert(retained.plannedSites == TraceCoverage::kMaxSites);
    assert(retained.planTruncated);
    const auto pending = trace.pendingSites(generation);
    for (size_t i = 0; i < pending.size(); ++i) assert(pending[i] == i);

    generation = trace.begin({ 7, 7, 7, 2, 2 }, 2);
    assert((trace.pendingSites(generation) == std::vector<uint64_t>{ 2, 7 }));
    assert(!trace.snapshot().planTruncated); // duplicates do not imply lost coverage
    generation = trace.begin({ 7, 7, 7 }, 0);
    assert(trace.pendingSites(generation).empty());
    assert(trace.snapshot().planTruncated);
    trace.begin({}, 0);
    assert(!trace.snapshot().planTruncated);

    // Compare bounded admission with the original full-sort definition across
    // varied limits, duplicates, large addresses, and adversarial input order.
    std::mt19937_64 random(0x5349544553);
    for (size_t trial = 0; trial < 200; ++trial) {
        const size_t limit = random() % 65;
        std::vector<uint64_t> input(random() % 500);
        for (auto& va : input) {
            va = random() % 100;
            if ((trial & 1) != 0) va += std::numeric_limits<uint64_t>::max() - 100;
        }
        auto expected = input;
        std::sort(expected.begin(), expected.end());
        expected.erase(std::unique(expected.begin(), expected.end()), expected.end());
        const bool truncated = expected.size() > limit;
        if (truncated) expected.resize(limit);
        generation = trace.begin(input, limit);
        assert(trace.pendingSites(generation) == expected);
        retained = trace.snapshot();
        assert(retained.planTruncated == truncated);
        assert(retained.requestedSites == input.size());
    }
    trace.reset();
    retained = trace.snapshot();
    assert(!retained.planTruncated && retained.requestedSites == 0);
}

static void testRetainedSnapshots() {
    TraceCoverage trace;
    TraceCoverageSnapshot retained;
    assert(!trace.snapshotIfChanged(retained));
    const auto generation = trace.begin({ 30, 10, 20, 0 });
    trace.markArmed(generation, 30);
    trace.markArmed(generation, 20);
    trace.recordBlockHit(generation, 10);
    trace.recordBlockHit(generation, 0);
    assert(trace.snapshotIfChanged(retained));
    assert((retained.armed == std::vector<uint64_t>{ 20, 30 }));
    assert(retained.blocks.size() == 2 && retained.blocks[0].va == 0);
    assert(retained.instructions.size() == 2 && retained.instructions[1].va == 10);
    const auto revision = retained.revision;
    const auto* instructions = retained.instructions.data();
    const auto* blocks = retained.blocks.data();
    const auto* armed = retained.armed.data();
    for (int i = 0; i < 100; ++i) assert(!trace.snapshotIfChanged(retained));
    assert(retained.instructions.data() == instructions);
    assert(retained.blocks.data() == blocks);
    assert(retained.armed.data() == armed);
    assert(retained.revision == revision);

    // Stale completions and idempotent lifecycle updates cannot trigger costly
    // snapshot reconstruction on an otherwise unchanged UI frame.
    trace.markArmed(generation + 1, 20);
    trace.markDisarmed(generation + 1, 20);
    trace.markSkipped(generation + 1, 20);
    trace.recordBlockHit(generation + 1, 20);
    trace.recordInstructionHit(generation + 1, 21);
    trace.markArmed(generation, 30);
    assert(!trace.snapshotIfChanged(retained));
    trace.markSkipped(generation, 20);
    assert(trace.snapshotIfChanged(retained));
    trace.markSkipped(generation, 20);
    assert(!trace.snapshotIfChanged(retained));
    trace.clearHits();
    assert(trace.snapshotIfChanged(retained));
    assert(retained.retiredSites == 2 && retained.instructions.empty());
    trace.clearHits();
    assert(!trace.snapshotIfChanged(retained));

    // A repeatable user breakpoint can prove new execution at a retired or
    // conflicting trace site after Clear; retain that actual new observation.
    trace.recordBlockHit(generation, 0);
    trace.recordBlockHit(generation, 20);
    trace.recordBlockHit(generation, 20);
    assert(trace.snapshotIfChanged(retained));
    assert(retained.hitSites == 2 && retained.retiredSites == 1);
    assert(retained.blockHitTotal == 3 && retained.instructionHitTotal == 3);
    assert(retained.blocks[1].va == 20 && retained.blocks[1].hits == 2);
    trace.stop();
    assert(trace.snapshotIfChanged(retained) && !retained.active);
    trace.stop();
    assert(!trace.snapshotIfChanged(retained));
    trace.markDisarmed(generation, 30);
    assert(trace.snapshotIfChanged(retained) && retained.armed.empty());
    trace.reset();
    assert(trace.snapshotIfChanged(retained));
    assert(retained.plannedSites == 0 && retained.instructions.empty());
}

static void testConcurrentSnapshotCoherence() {
    TraceCoverage trace;
    const auto generation = trace.begin({ 0, 10 });
    std::atomic<bool> done{ false };
    std::thread recorder([&] {
        for (size_t i = 0; i < 10000; ++i)
            trace.recordBlockHit(generation, i % 2 == 0 ? 0 : 10);
        done = true;
    });
    TraceCoverageSnapshot retained;
    do {
        if (!trace.snapshotIfChanged(retained)) continue;
        // Both count vectors and totals must describe the same locked instant,
        // even though sorting occurs after releasing the recording mutex.
        assert(retained.instructions.size() == retained.blocks.size());
        assert(retained.instructionHitTotal == retained.blockHitTotal);
        assert(retained.hitSites == retained.blocks.size());
        for (size_t i = 0; i < retained.blocks.size(); ++i) {
            assert(retained.instructions[i].va == retained.blocks[i].va);
            assert(retained.instructions[i].hits == retained.blocks[i].hits);
        }
    } while (!done);
    recorder.join();
    trace.snapshotIfChanged(retained);
    assert(retained.blockHitTotal == 10000 && retained.blocks.size() == 2);
}

int main() {
    testBoundedAdmission();
    testRetainedSnapshots();
    testConcurrentSnapshotCoherence();
    TraceCoverage trace;

    // VA zero is valid; plans are deterministic, unique, and bounded.
    uint64_t g1 = trace.begin({ 0x30, 0, 0x20, 0x20, 0x10 }, 4);
    auto pending = trace.pendingSites(g1);
    assert((pending == std::vector<uint64_t>{ 0, 0x10, 0x20, 0x30 }));
    auto s = trace.snapshot();
    assert(s.active && s.requestedSites == 5 && s.plannedSites == 4);

    trace.markArmed(g1, 0);
    trace.markArmed(g1, 0x10);
    trace.markSkipped(g1, 0x20);
    trace.recordBlockHit(g1, 0);
    trace.recordInstructionHit(g1, 0x01);
    trace.recordInstructionHit(g1, 0x01);
    s = trace.snapshot();
    assert(s.armedSites == 1 && s.hitSites == 1 && s.skippedSites == 1);
    assert(s.blockHitTotal == 1 && s.instructionHitTotal == 3);
    assert(s.blocks.size() == 1 && s.blocks[0].va == 0 && s.blocks[0].hits == 1);
    assert(s.instructions.size() == 2 && s.instructions[1].hits == 2);

    // Clear does not stop the session or make consumed one-shot sites pending.
    trace.clearHits();
    s = trace.snapshot();
    assert(s.active && s.instructions.empty() && s.blocks.empty());
    assert(s.hitSites == 0 && s.retiredSites == 1);
    assert(trace.pendingSites(g1) == std::vector<uint64_t>{ 0x30 });

    // Stale debug-thread completions cannot mutate a replacement session.
    uint64_t g2 = trace.begin({ 0x100, 0x200 });
    assert(g2 != g1);
    trace.markArmed(g1, 0x100);
    trace.recordBlockHit(g1, 0x100);
    s = trace.snapshot();
    assert(s.armedSites == 0 && s.blocks.empty());

    trace.markArmed(g2, 0x100);
    trace.markDisarmed(g2, 0x100);
    assert(trace.pendingSites(g2) == std::vector<uint64_t>({ 0x100, 0x200 }));

    // Concurrent debug-event recording and UI snapshots are race-free and exact.
    trace.markArmed(g2, 0x100);
    constexpr int kThreads = 4;
    constexpr int kHits = 4000;
    std::vector<std::thread> workers;
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&] {
            for (int i = 0; i < kHits; ++i)
                trace.recordInstructionHit(g2, 0x1234);
        });
    }
    for (int i = 0; i < 200; ++i) (void)trace.snapshot();
    for (auto& worker : workers) worker.join();
    s = trace.snapshot();
    assert(s.instructionHitTotal == uint64_t(kThreads * kHits));
    assert(s.instructions.size() == 1 && s.instructions[0].hits == kThreads * kHits);

    trace.stop();
    trace.recordBlockHit(g2, 0x200);
    s = trace.snapshot();
    assert(!s.active && s.blocks.empty());
    assert(trace.pendingSites(g2).empty());

    std::cout << "trace_coverage_test: all checks passed\n";
    return 0;
}
