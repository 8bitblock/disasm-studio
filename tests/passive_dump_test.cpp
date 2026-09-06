#include "Core/PassiveDump.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iterator>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#include <chrono>
#include <thread>
#endif

using namespace ds;

template <typename T>
static void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    assert(offset <= bytes.size() && sizeof(T) <= bytes.size() - offset);
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static PassiveSampleMetrics sample(uint64_t ms, double changed, double entropyDelta,
                                   double comparable = 1.0, uint32_t pages = 100) {
    PassiveSampleMetrics s;
    s.timestampMs = ms;
    s.totalPages = pages;
    s.readablePages = pages;
    s.comparablePages = static_cast<uint32_t>(pages * comparable);
    s.changedPageRatio = changed;
    s.comparablePageRatio = comparable;
    s.entropyDelta = entropyDelta;
    return s;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    if (argc == 2 && std::string(argv[1]) == "--passive-dump-child") {
        Sleep(10000);
        return 0;
    }
#else
    (void)argc; (void)argv;
#endif
    {
        auto estimateSmall = EstimatePassiveDumpMemory(64ull * 1024 * 1024, true, true);
        assert(estimateSmall.accepted && estimateSmall.imageMultiplier == 6);
        assert(estimateSmall.estimatedPeakBytes <= estimateSmall.budgetBytes);
        auto hostile = EstimatePassiveDumpMemory(512ull * 1024 * 1024, true, true);
        assert(!hostile.accepted && hostile.estimatedPeakBytes > hostile.budgetBytes);
        auto rawOnly = EstimatePassiveDumpMemory(512ull * 1024 * 1024, false, true);
        assert(rawOnly.accepted && rawOnly.imageMultiplier == 2);
        assert(!EstimatePassiveDumpMemory(UINT64_MAX, true, true).accepted);
    }

    {
        std::vector<uint8_t> pe(0x3000, 0);
        put<uint16_t>(pe, 0, 0x5a4d);
        put<uint32_t>(pe, 0x3c, 0x80);
        put<uint32_t>(pe, 0x80, 0x4550);
        put<uint16_t>(pe, 0x86, 1);       // NumberOfSections
        put<uint16_t>(pe, 0x94, 0xf0);    // SizeOfOptionalHeader
        const size_t opt = 0x98;
        put<uint16_t>(pe, opt, 0x20b);
        put<uint32_t>(pe, opt + 16, 0x1000);
        put<uint32_t>(pe, opt + 56, 0x3000);
        const size_t sec = opt + 0xf0;
        put<uint32_t>(pe, sec + 8, 0x1800);
        put<uint32_t>(pe, sec + 12, 0x1000);
        put<uint32_t>(pe, sec + 16, 0x1800);

        PassiveCapture capture;
        capture.base = 0x140000000ull;
        capture.bytes = pe;
        capture.pageValid = { 1, 1, 1 };
        capture.pageProtection = { 0x04, 0x20, 0x04 }; // RW, RX, RW

        auto header = AssessPassiveOep(capture, false, 0);
        assert(header.trust == PassiveOepTrust::HeaderEntryUnverified);
        assert(header.structurallyValid && header.executablePage);
        assert(header.effectiveVA == capture.base + 0x1000);

        auto manual = AssessPassiveOep(capture, true, capture.base + 0x1100);
        assert(manual.trust == PassiveOepTrust::ManualOepValidated);
        assert(manual.entryRVA == 0x1100);
        auto nonExec = AssessPassiveOep(capture, true, capture.base + 0x2100);
        assert(nonExec.structurallyValid && !nonExec.executablePage);
        assert(nonExec.trust == PassiveOepTrust::ManualOepRejected);
        capture.pageValid[1] = 0;
        auto unreadable = AssessPassiveOep(capture, true, capture.base + 0x1100);
        assert(!unreadable.pageCaptured);
        assert(unreadable.trust == PassiveOepTrust::ManualOepRejected);
        assert(AssessPassiveOep(capture, true, capture.base + 0x4000).trust ==
               PassiveOepTrust::ManualOepRejected);

        assert(AssessPassiveArtifact(false, PassiveOepTrust::ManualOepValidated, false) ==
               PassiveArtifactAssessment::RawCaptureOnly);
        assert(AssessPassiveArtifact(true, PassiveOepTrust::HeaderEntryUnverified, false) ==
               PassiveArtifactAssessment::RebuiltAnalysisOnly);
        assert(AssessPassiveArtifact(true, PassiveOepTrust::ManualOepRejected, false) ==
               PassiveArtifactAssessment::RebuiltAnalysisOnly);
        assert(AssessPassiveArtifact(true, PassiveOepTrust::ManualOepValidated, true) ==
               PassiveArtifactAssessment::RebuiltAnalysisOnly);
        assert(AssessPassiveArtifact(true, PassiveOepTrust::ManualOepValidated, false) ==
               PassiveArtifactAssessment::RebuiltRunnable);
    }

    {
        std::vector<uint8_t> zeros(8192, 0);
        auto fp = FingerprintPassivePages(zeros, { 1, 1 }, 4096);
        assert(fp.hashes.size() == 2 && fp.valid.size() == 2);
        assert(fp.hashes[0] != 0 && fp.hashes[1] != 0);
        assert(fp.sampledBytes == zeros.size());
        assert(std::abs(fp.entropy) < 1e-12);

        std::vector<uint8_t> uniform(256 * 32);
        for (size_t i = 0; i < uniform.size(); ++i) uniform[i] = static_cast<uint8_t>(i);
        auto uf = FingerprintPassivePages(uniform, { 1, 1 }, 4096);
        assert(uf.entropy > 7.99 && uf.entropy <= 8.0);

        auto partial = FingerprintPassivePages(zeros, { 1, 0 }, 4096);
        assert(partial.valid[0] == 1 && partial.valid[1] == 0);
        assert(partial.hashes[0] != 0 && partial.hashes[1] == 0);
        assert(partial.sampledBytes == 4096);
    }

    {
        std::vector<uint8_t> a(3 * 4096, 0x11);
        std::vector<uint8_t> b = a;
        b[4096 + 7] ^= 0xff;
        auto af = FingerprintPassivePages(a, { 1, 1, 1 });
        auto bf = FingerprintPassivePages(b, { 1, 1, 0 });
        auto first = ComparePassiveSamples(nullptr, af, 100);
        assert(first.comparablePages == 0 && first.changedPageRatio == 1.0);
        auto delta = ComparePassiveSamples(&af, bf, 200);
        assert(delta.totalPages == 3);
        assert(delta.readablePages == 2);
        assert(delta.comparablePages == 2);
        assert(delta.changedPages == 1);
        assert(delta.validityChangedPages == 1);
        assert(std::abs(delta.comparablePageRatio - (2.0 / 3.0)) < 1e-9);
        assert(std::abs(delta.changedPageRatio - (2.0 / 3.0)) < 1e-9);
    }

    {
        PassiveSettleConfig cfg;
        cfg.minWatchMs = 1000;
        cfg.maxWatchMs = 5000;
        cfg.stableSamplesRequired = 3;
        cfg.maxChangedPageRatio = 0.01;
        cfg.maxEntropyDelta = 0.02;
        cfg.minComparablePageRatio = 0.8;
        PassiveSettleTracker tracker(cfg);
        tracker.reset(100);
        assert(tracker.observe(sample(100, 1.0, 0.0)) == PassiveSettleDecision::Continue);
        assert(tracker.observe(sample(500, 0.0, 0.0)) == PassiveSettleDecision::Continue);
        assert(tracker.stableSamples() == 1);
        assert(tracker.observe(sample(900, 0.005, 0.01)) == PassiveSettleDecision::Continue);
        assert(tracker.observe(sample(1200, 0.0, 0.0)) == PassiveSettleDecision::Settled);
        assert(tracker.stableSamples() == 3);

        tracker.reset(10);
        tracker.observe(sample(10, 1.0, 0.0));
        tracker.observe(sample(500, 0.0, 0.0, 0.5));
        assert(tracker.stableSamples() == 0); // insufficient comparable coverage
        tracker.observe(sample(700, 0.0, 0.0));
        tracker.observe(sample(600, 0.0, 0.0)); // non-monotonic telemetry is unstable
        assert(tracker.stableSamples() == 0);
        assert(tracker.observe(sample(5010, 0.5, 1.0)) == PassiveSettleDecision::TimedOut);

        tracker.reset(100);
        assert(tracker.observe(sample(101, 1.0, 0.0), true) == PassiveSettleDecision::Manual);
    }

    {
        // Invalid configs are bounded instead of enabling instant/NaN settling.
        PassiveSettleConfig cfg;
        cfg.stableSamplesRequired = 0;
        cfg.maxChangedPageRatio = std::nan("");
        cfg.maxEntropyDelta = std::nan("");
        cfg.minComparablePageRatio = 2.0;
        PassiveSettleTracker tracker(cfg);
        assert(tracker.config().stableSamplesRequired == 1);
        assert(std::isfinite(tracker.config().maxChangedPageRatio));
        assert(std::isfinite(tracker.config().maxEntropyDelta));
        assert(tracker.config().minComparablePageRatio == 1.0);
    }

#ifdef _WIN32
    {
        // End-to-end smoke: passively open and rebuild this test executable.
        // Suspending is deliberately off because the worker lives in the same
        // process being captured. No debugger API or target write is involved.
        auto processes = EnumeratePassiveProcesses();
        bool sawSelf = false;
        for (const auto& p : processes) if (p.pid == GetCurrentProcessId()) sawSelf = true;
        assert(sawSelf);

        PassiveDumpService service;
        PassiveDumpRequest request;
        request.pid = GetCurrentProcessId();
        request.timing = PassiveTiming::Immediate;
        request.suspendDuringFinalCapture = false;
        request.observeExactExportImports = true;
        request.rebuildPe = true;
        std::string error;
        assert(service.start(request, &error));
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (service.busy() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        assert(!service.busy());
        PassiveDumpResult result;
        assert(service.tryTakeResult(result));
        assert(result.success);
        assert(result.pid == GetCurrentProcessId());
        assert(result.capture.completeForDiskRebuild);
        assert(result.capture.readablePages != 0);
        assert(result.rebuilt.success && !result.rebuilt.image.empty());
        assert(result.rebuilt.rawMappedImage.empty());
        assert(result.memory.accepted);
        assert(result.oep.trust == PassiveOepTrust::HeaderEntryUnverified);
        assert(result.artifactAssessment == PassiveArtifactAssessment::RebuiltAnalysisOnly);
        bool sawUnverified = false;
        for (const auto& issue : result.rebuilt.issues)
            if (issue.code == "oep-unverified") sawUnverified = true;
        assert(sawUnverified);
        assert(result.report.find("no DebugActiveProcess") != std::string::npos);
        assert(result.report.find("analysis-only") != std::string::npos);
        assert(result.report.find("Page provenance map") != std::string::npos);
        assert(result.report.find("remote-valid") != std::string::npos);
        assert(result.report.find("PE reconstruction details") != std::string::npos);
    }

    {
        // Re-run with a structurally and protection-validated analyst OEP. The
        // same address is no longer inferred from the unchanged header.
        auto* module = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
        assert(module);
        uint32_t peOffset = 0, entryRva = 0;
        std::memcpy(&peOffset, module + 0x3c, sizeof(peOffset));
        std::memcpy(&entryRva, module + peOffset + 24 + 16, sizeof(entryRva));
        PassiveDumpService service;
        PassiveDumpRequest request;
        request.pid = GetCurrentProcessId();
        request.timing = PassiveTiming::Immediate;
        request.observeExactExportImports = false;
        request.hasManualOep = true;
        request.manualOepVA = reinterpret_cast<uintptr_t>(module) + entryRva;
        std::string error;
        assert(service.start(request, &error));
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (service.busy() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        PassiveDumpResult result;
        assert(!service.busy() && service.tryTakeResult(result));
        assert(result.success && result.rebuilt.success);
        assert(result.oep.trust == PassiveOepTrust::ManualOepValidated);
        assert(result.artifactAssessment == PassiveArtifactAssessment::RebuiltRunnable);
        bool sawValidated = false;
        for (const auto& issue : result.rebuilt.issues)
            if (issue.code == "manual-oep-validated") sawValidated = true;
        assert(sawValidated);
    }

    if (GetEnvironmentVariableW(L"DS_PASSIVE_LAUNCH_SMOKE", nullptr, 0)) {
        wchar_t self[32768]{};
        DWORD n = GetModuleFileNameW(nullptr, self, static_cast<DWORD>(std::size(self)));
        assert(n && n < std::size(self));
        PassiveDumpService service;
        PassiveDumpRequest request;
        request.executable.assign(self, n);
        request.arguments = { L"--passive-dump-child" };
        request.timing = PassiveTiming::Immediate;
        request.rebuildPe = false;
        request.observeExactExportImports = true;
        request.suspendDuringFinalCapture = true;
        std::string error;
        assert(service.start(request, &error));
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (service.busy() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        PassiveDumpResult result;
        assert(!service.busy() && service.tryTakeResult(result));
        if (!result.success) std::cerr << result.report << std::endl;
        assert(result.success && result.launched && result.launchContained);
        assert(result.suspendedDuringCapture && result.importObservationCoherent);
        assert(result.pid != GetCurrentProcessId());
        service.terminateContainedLaunch();
    }
#endif

    std::cout << "passive_dump_test passed\n";
    return 0;
}
