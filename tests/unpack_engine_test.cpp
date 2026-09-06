#include "Core/UnpackEngine.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>

using namespace ds;

static int g_failures = 0;

#define CHECK(expr) do { if (!(expr)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    ++g_failures; \
} } while (0)

static const OepEvidence* evidence(const OepCandidate& candidate,
                                   OepEvidenceKind kind) {
    for (const auto& item : candidate.evidence)
        if (item.kind == kind) return &item;
    return nullptr;
}

static UnpackObservation observation(uint64_t timestamp, uint64_t rip,
                                     double entropy = 6.0) {
    UnpackObservation value;
    value.timestampMs = timestamp;
    value.rip = rip;
    value.rsp = 0x800000;
    value.imageEntropy = entropy;
    value.executionRegion = { rip & ~uint64_t{0xfff}, 0x1000 };
    value.regionExecutable = true;
    value.regionImageBacked = true;
    return value;
}

int main() {
    // Half-open address ranges never wrap and include a real address zero.
    {
        UnpackRange zero{0, 1};
        uint64_t end = 99;
        CHECK(zero.valid());
        CHECK(zero.contains(0));
        CHECK(!zero.contains(1));
        CHECK(zero.end(end) && end == 1);

        UnpackRange ordinary{0x1000, 0x20};
        CHECK(ordinary.contains(0x1000));
        CHECK(ordinary.contains(0x101f));
        CHECK(!ordinary.contains(0x1020));
        CHECK((!UnpackRange{0x1000, 0}.valid()));
        CHECK((!UnpackRange{(std::numeric_limits<uint64_t>::max)(), 1}.valid()));
        CHECK((!UnpackRange{(std::numeric_limits<uint64_t>::max)() - 1, 2}.valid()));
    }

    // A corroborated write-then-execute transfer produces one high-confidence
    // candidate. Re-observation merges evidence instead of duplicating rows.
    {
        UnpackEngine engine;
        engine.begin(UnpackStrategy::Hybrid, {0x400000, 0x4000}, 0x800000);
        CHECK(engine.state() == UnpackState::Observing);

        auto first = observation(10, 0x401234, 7.1);
        first.rsp = 0x800080; // inferred as near the stack baseline
        first.pageWasWritten = true;
        first.controlTransfer = true;
        first.changedBytes = 0x500;
        first.changedPages = 1;
        CHECK(engine.observe(first));

        auto report = engine.report();
        CHECK(report.status.state == UnpackState::CandidateReady);
        CHECK(report.status.hasBestOep && report.status.bestOep == 0x401234);
        CHECK(report.candidates.size() == 1);
        if (!report.candidates.empty()) {
            const auto& candidate = report.candidates.front();
            CHECK(candidate.confidence == UnpackConfidence::High);
            CHECK(candidate.score >= 75 && candidate.score <= 100);
            CHECK(evidence(candidate, OepEvidenceKind::WriteThenExecute) != nullptr);
            CHECK(evidence(candidate, OepEvidenceKind::InOriginalImage) != nullptr);
            CHECK(evidence(candidate, OepEvidenceKind::ExecutableRegion) != nullptr);
            CHECK(evidence(candidate, OepEvidenceKind::StackNearBaseline) != nullptr);
        }

        auto second = first;
        second.timestampMs = 20;
        second.changedBytes = 0;
        second.changedPages = 0;
        CHECK(engine.observe(second));
        report = engine.report();
        CHECK(report.candidates.size() == 1);
        if (!report.candidates.empty()) {
            const auto& candidate = report.candidates.front();
            CHECK(candidate.observations == 2);
            const auto* write = evidence(candidate, OepEvidenceKind::WriteThenExecute);
            const auto* repeated = evidence(candidate, OepEvidenceKind::RepeatedObservation);
            CHECK(write && write->occurrences == 2);
            CHECK(repeated && repeated->occurrences == 1);
            CHECK(candidate.evidence.size() <= 7);
        }

        // Rejections are atomic: accepted totals and retained samples do not move.
        auto invalidEntropy = second;
        invalidEntropy.timestampMs = 30;
        invalidEntropy.imageEntropy = std::numeric_limits<double>::quiet_NaN();
        CHECK(!engine.observe(invalidEntropy));
        auto backwards = second;
        backwards.timestampMs = 19;
        CHECK(!engine.observe(backwards));
        auto wrongRegion = second;
        wrongRegion.timestampMs = 30;
        wrongRegion.executionRegion = {0x500000, 0x1000};
        CHECK(!engine.observe(wrongRegion));
        report = engine.report();
        CHECK(report.status.totalSamples == 2);
        CHECK(report.status.retainedSamples == 2);
        CHECK(report.status.rejectedSamples == 3);

        engine.complete();
        report = engine.report();
        CHECK(report.status.state == UnpackState::Completed);
        CHECK(report.status.hasBestOep && report.status.bestOep == 0x401234);
        CHECK(!engine.observe(second));
        CHECK(engine.report().status.rejectedSamples == 4);
    }

    // Entropy-settle requires earlier activity, then a complete quiet window.
    {
        UnpackConfig config;
        config.settleWindowMs = 300;
        config.minSettleSamples = 4;
        config.maxEntropySpread = 0.02;
        config.maxChangedBytesInSettleWindow = 16;
        config.maxChangedPagesInSettleWindow = 1;
        UnpackEngine engine(config);
        engine.begin(UnpackStrategy::EntropySettle, {0x400000, 0x1000});

        auto active = observation(0, 0x400010, 7.4);
        active.changedBytes = 0x2000;
        active.changedPages = 3;
        CHECK(engine.observe(active));
        for (uint64_t t : {1000ull, 1100ull, 1200ull, 1300ull})
            CHECK(engine.observe(observation(t, 0x400050, 6.00)));

        const auto report = engine.report();
        CHECK(report.entropy.settled);
        CHECK(report.entropy.windowStartMs == 1000);
        CHECK(report.entropy.windowEndMs == 1300);
        CHECK(report.entropy.sampleCount == 4);
        CHECK(report.entropy.changedBytes == 0);
        CHECK(report.status.hasBestOep && report.status.bestOep == 0x400050);
        CHECK(!report.candidates.empty());
        if (!report.candidates.empty())
            CHECK(evidence(report.candidates.front(), OepEvidenceKind::EntropySettled) != nullptr);
    }

    // Sample retention is bounded while lifetime counters remain exact.
    {
        UnpackConfig config;
        config.maxSamples = 2;
        UnpackEngine engine(config);
        engine.begin(UnpackStrategy::Manual, {0x600000, 0x1000});
        CHECK(engine.observe(observation(1, 0x600010)));
        CHECK(engine.observe(observation(2, 0x600020)));
        CHECK(engine.observe(observation(3, 0x600030)));
        const auto report = engine.report();
        CHECK(report.status.totalSamples == 3);
        CHECK(report.status.retainedSamples == 2);
        CHECK(report.status.droppedSamples == 1);
        CHECK(report.samples.size() == 2);
        CHECK(report.samples[0].timestampMs == 2 && report.samples[1].timestampMs == 3);
    }

    // VA zero is selected through the explicit boolean, never treated as a sentinel.
    {
        UnpackEngine engine;
        engine.begin(UnpackStrategy::Manual, {0, 0x100});
        CHECK(!engine.selectManualOep(0x100, 1, "outside"));
        CHECK(engine.selectManualOep(0, 1, "analyst selected address zero"));
        engine.complete(0, true);
        const auto report = engine.report();
        CHECK(report.status.state == UnpackState::Completed);
        CHECK(report.status.hasBestOep);
        CHECK(report.status.bestOep == 0);
        CHECK(report.status.bestConfidence == UnpackConfidence::High);
        CHECK(!report.candidates.empty() && report.candidates.front().va == 0);
    }

    // An OEP in a recovered private image needs an explicit, valid allocation
    // approval. Approval is for one exact address, not the whole allocation.
    {
        constexpr uint64_t externalOep = 0x710120;
        const UnpackRange privateImage{0x710000, 0x5000};
        UnpackEngine engine;
        engine.begin(UnpackStrategy::Manual, {0x400000, 0x2000});
        CHECK(!engine.selectManualOep(externalOep, 1, "outside original image"));
        CHECK(!engine.selectValidatedExternalOep(externalOep, {}, 1));
        CHECK(!engine.selectValidatedExternalOep(externalOep,
            {(std::numeric_limits<uint64_t>::max)(), 1}, 1));
        CHECK(!engine.selectValidatedExternalOep(externalOep,
            {0x720000, 0x1000}, 1));
        CHECK(!engine.selectValidatedExternalOep(0x400100,
            privateImage, 1));
        CHECK(engine.selectValidatedExternalOep(externalOep, privateImage, 1,
            "validated recovered PE allocation"));
        CHECK(engine.report().status.state == UnpackState::CandidateReady);
        engine.complete(externalOep + 1, true); // same range is not enough
        const auto report = engine.report();
        CHECK(report.status.state == UnpackState::Completed);
        CHECK(report.status.hasBestOep);
        CHECK(report.status.bestOep == externalOep);
    }

    // An observed private-memory candidate is not accepted as a final OEP until
    // the caller validates and explicitly approves its recovered image range.
    {
        constexpr uint64_t externalOep = 0x730088;
        UnpackEngine engine;
        engine.begin(UnpackStrategy::WriteExecute, {0x400000, 0x2000});
        auto sample = observation(10, externalOep);
        sample.regionPrivate = true;
        sample.regionImageBacked = false;
        sample.pageWasWritten = true;
        CHECK(engine.observe(sample));
        CHECK(engine.report().status.hasBestOep);
        engine.complete(externalOep, true);
        const auto report = engine.report();
        CHECK(report.status.state == UnpackState::Completed);
        CHECK(!report.status.hasBestOep);
    }

    // Approval cannot be reused across reset and all terminal states reject it.
    {
        constexpr uint64_t externalOep = 0x740010;
        const UnpackRange privateImage{0x740000, 0x2000};
        UnpackEngine engine;
        engine.begin(UnpackStrategy::Manual, {0x400000, 0x1000});
        CHECK(engine.selectValidatedExternalOep(externalOep, privateImage, 1));
        engine.reset();
        engine.begin(UnpackStrategy::Manual, {0x400000, 0x1000});
        engine.complete(externalOep, true);
        CHECK(!engine.report().status.hasBestOep);
        CHECK(!engine.selectValidatedExternalOep(externalOep, privateImage, 2));

        engine.reset();
        engine.begin(UnpackStrategy::Manual, {0x400000, 0x1000});
        engine.cancel();
        CHECK(!engine.selectValidatedExternalOep(externalOep, privateImage, 2));
    }

    // Repeated exact private-memory back-edges plus a handler produce a bounded,
    // evidence-rich VM report. A hot forward-only trace is not enough by itself.
    {
        UnpackConfig config;
        config.hotRipMinimumHits = 3;
        config.loopMinimumHits = 2;
        config.maxReportedHotRips = 2;
        config.maxReportedHandlers = 2;
        config.maxReportedLoops = 2;
        UnpackEngine engine(config);
        engine.begin(UnpackStrategy::Manual, {0x500000, 0x2000});
        for (uint64_t i = 0; i < 6; ++i) {
            auto sample = observation(i, 0x500000);
            sample.regionPrivate = true;
            sample.regionImageBacked = false;
            sample.hasTransitionSource = true;
            sample.transitionSource = 0x500100;
            sample.exceptionHandlerEntry = i < 2;
            CHECK(engine.observe(sample));
        }
        const auto report = engine.report();
        CHECK(report.vmTrace.vmLike);
        CHECK(report.vmTrace.score >= 50 && report.vmTrace.score <= 100);
        CHECK(report.vmTrace.observedTransitions == 6);
        CHECK(!report.vmTrace.hotRips.empty());
        CHECK(!report.vmTrace.handlers.empty());
        CHECK(!report.vmTrace.loops.empty());
        CHECK(report.vmTrace.hotRips.size() <= 2);
        CHECK(report.vmTrace.handlers.size() <= 2);
        CHECK(report.vmTrace.loops.size() <= 2);
        if (!report.vmTrace.loops.empty()) {
            CHECK(report.vmTrace.loops.front().from == 0x500100);
            CHECK(report.vmTrace.loops.front().to == 0x500000);
            CHECK(report.vmTrace.loops.front().hits == 6);
            CHECK(report.vmTrace.loops.front().backward);
        }

        UnpackEngine forwardOnly(config);
        forwardOnly.begin(UnpackStrategy::Manual, {0x700000, 0x2000});
        for (uint64_t i = 0; i < 6; ++i) {
            auto sample = observation(i, 0x700100);
            sample.hasTransitionSource = true;
            sample.transitionSource = 0x700000;
            CHECK(forwardOnly.observe(sample));
        }
        CHECK(!forwardOnly.report().vmTrace.vmLike);
    }

    // Invalid begin, cancel, fail, and reset have explicit terminal semantics.
    {
        UnpackEngine engine;
        engine.begin(UnpackStrategy::Hybrid, {0x1000, 0});
        CHECK(engine.state() == UnpackState::Failed);
        engine.reset();
        CHECK(engine.state() == UnpackState::Idle);
        engine.begin(UnpackStrategy::RunFree, {0x1000, 0x100});
        engine.cancel();
        CHECK(engine.state() == UnpackState::Cancelled);
        engine.reset();
        engine.begin(UnpackStrategy::Hybrid, {0x1000, 0x100});
        engine.fail(std::string(700, 'x'));
        const auto report = engine.report();
        CHECK(report.status.state == UnpackState::Failed);
        CHECK(report.status.message.size() == 512);
    }

    CHECK(std::string(UnpackStrategyName(UnpackStrategy::WriteExecute)) == "Write then execute");
    CHECK(std::string(UnpackStateName(UnpackState::CandidateReady)) == "Candidate ready");
    CHECK(std::string(UnpackConfidenceName(UnpackConfidence::High)) == "High");
    CHECK(std::string(OepEvidenceName(OepEvidenceKind::WriteThenExecute)) == "Write then execute");

    if (g_failures == 0)
        std::printf("unpack_engine_test: all checks passed\n");
    else
        std::printf("unpack_engine_test: %d check(s) failed\n", g_failures);
    return g_failures ? 1 : 0;
}
