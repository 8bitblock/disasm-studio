#include "Core/TraceCoverage.h"

#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

using namespace ds;

int main() {
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
