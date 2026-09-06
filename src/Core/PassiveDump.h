#pragma once
//
// PassiveDump.h
// Non-invasive process snapshotting.  This subsystem never calls
// DebugActiveProcess and never writes to, injects into, or patches the target.
// The platform worker opens only query/read access (plus the explicitly
// requested PROCESS_SUSPEND_RESUME right for a short final-capture window).
//
// Page fingerprinting and settle decisions are Win32-free and deterministic so
// policy can be tested without a live process.

#include "PeUnpack.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ds {

constexpr size_t kPassiveDumpPageSize = 0x1000;
constexpr size_t kPassiveDumpMaxImage = 512ull * 1024 * 1024;
// This is an aggregate peak budget, not merely an input-size limit. Rebuild
// admission reserves room for the capture, optional discardable-page working
// copy, PeUnpack's transactional copies/output, and bounded export metadata.
constexpr uint64_t kPassiveDumpAggregateMemoryBudget = 2ull * 1024 * 1024 * 1024;

enum class PassiveTiming {
    Immediate,
    Manual,
    AutoSettle,
};

enum class PassiveDumpPhase {
    Idle,
    Opening,
    Watching,
    Suspending,
    Capturing,
    ResolvingImports,
    Rebuilding,
    Complete,
    Failed,
    Cancelled,
};

enum class PassiveSettleDecision {
    Continue,
    Immediate,
    Settled,
    TimedOut,
    Manual,
};

enum class PassiveOepTrust {
    NotAssessed,
    HeaderEntryUnverified,
    ManualOepRejected,
    ManualOepValidated,
};

enum class PassiveArtifactAssessment {
    RawCaptureOnly,
    RebuiltAnalysisOnly,
    RebuiltRunnable,
};

enum class PassiveWorkerFailure : uint32_t {
    None,
    OutOfMemory,
    Unexpected,
};

struct PassiveMemoryAssessment {
    uint64_t imageBytes = 0;
    uint64_t estimatedPeakBytes = 0;
    uint64_t budgetBytes = kPassiveDumpAggregateMemoryBudget;
    uint32_t imageMultiplier = 0;
    bool accepted = false;
};

PassiveMemoryAssessment EstimatePassiveDumpMemory(uint64_t imageBytes,
                                                   bool rebuildPe,
                                                   bool observeExactExportImports);

struct PassiveSettleConfig {
    uint64_t minWatchMs = 1500;
    uint64_t maxWatchMs = 60000;
    uint32_t stableSamplesRequired = 4;
    double maxChangedPageRatio = 0.0025;
    double maxEntropyDelta = 0.015;
    // A sample with less comparable coverage is not allowed to claim stability.
    double minComparablePageRatio = 0.80;
};

struct PassivePageFingerprint {
    size_t pageSize = kPassiveDumpPageSize;
    size_t byteSize = 0;
    std::vector<uint64_t> hashes; // zero for unreadable pages
    std::vector<uint8_t> valid;   // one byte per page
    double entropy = 0.0;         // Shannon entropy, bits per byte
    uint64_t sampledBytes = 0;
};

struct PassiveSampleMetrics {
    uint64_t timestampMs = 0;
    uint32_t totalPages = 0;
    uint32_t readablePages = 0;
    uint32_t comparablePages = 0;
    uint32_t changedPages = 0;
    uint32_t validityChangedPages = 0;
    double changedPageRatio = 1.0;
    double comparablePageRatio = 0.0;
    double entropy = 0.0;
    double entropyDelta = 0.0;
};

// valid is one byte per page. Entropy work is deterministically sampled and
// capped so a 512 MiB image cannot monopolize a worker.
PassivePageFingerprint FingerprintPassivePages(const std::vector<uint8_t>& bytes,
                                                const std::vector<uint8_t>& valid,
                                                size_t pageSize = kPassiveDumpPageSize,
                                                size_t entropyByteCap = 4ull * 1024 * 1024);

PassiveSampleMetrics ComparePassiveSamples(const PassivePageFingerprint* previous,
                                            const PassivePageFingerprint& current,
                                            uint64_t timestampMs);

class PassiveSettleTracker {
public:
    explicit PassiveSettleTracker(PassiveSettleConfig config = {});

    void reset(uint64_t startTimestampMs = 0);
    PassiveSettleDecision observe(const PassiveSampleMetrics& sample,
                                  bool manualCaptureRequested = false);

    uint32_t stableSamples() const { return stableSamples_; }
    uint64_t startTimestampMs() const { return startTimestampMs_; }
    const PassiveSampleMetrics& latest() const { return latest_; }
    const PassiveSettleConfig& config() const { return config_; }

private:
    PassiveSettleConfig config_;
    uint64_t startTimestampMs_ = 0;
    uint64_t lastTimestampMs_ = 0;
    uint32_t stableSamples_ = 0;
    bool haveSample_ = false;
    PassiveSampleMetrics latest_{};
};

struct PassiveProcessInfo {
    uint32_t pid = 0;
    std::wstring imageName;
    std::wstring imagePath;
};

struct PassiveModuleInfo {
    uint64_t base = 0;
    uint64_t size = 0;
    std::wstring name;
    std::wstring path;
    bool mainModule = false;
};

struct PassiveCapture {
    uint64_t base = 0;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> pageValid;
    // A reconstruction may source an unreadable discardable page (normally
    // .reloc) from the exact on-disk main module after header/layout identity
    // checks. bytes remains the pristine remote snapshot; this mask records
    // that separate provenance.
    std::vector<uint8_t> pageBackfilled;
    std::vector<uint32_t> pageProtection;
    uint32_t readablePages = 0;
    uint32_t unreadablePages = 0;
    bool completeForDiskRebuild = false;
    std::vector<uint32_t> missingRequiredPageRvas;
};

struct PassiveOepAssessment {
    PassiveOepTrust trust = PassiveOepTrust::NotAssessed;
    uint64_t effectiveVA = 0;
    uint32_t entryRVA = 0;
    bool structurallyValid = false;
    bool pageCaptured = false;
    bool executablePage = false;
};

// A manual address is trusted only when it is inside a modeled PE section and
// its exact remote page was both captured and executable. An unchanged header
// entry can be structurally valid but deliberately remains unverified.
PassiveOepAssessment AssessPassiveOep(const PassiveCapture& capture,
                                      bool hasManualOep,
                                      uint64_t manualOepVA);

// A rebuilt artifact is runnable only when reconstruction succeeded, the OEP
// came from a validated analyst address, and every output byte came from the
// remote capture. Best-effort disk backfill deliberately downgrades the whole
// artifact even when the OEP itself remains trusted.
PassiveArtifactAssessment AssessPassiveArtifact(bool rebuildSucceeded,
                                                 PassiveOepTrust oepTrust,
                                                 bool usedDiskBackfill) noexcept;

struct PassiveDumpRequest {
    // Exactly one source is used. A non-zero pid snapshots an existing process;
    // otherwise executable is launched normally without DEBUG_* creation flags.
    uint32_t pid = 0;
    std::wstring executable;
    std::vector<std::wstring> arguments;
    std::wstring workingDirectory;

    PassiveTiming timing = PassiveTiming::AutoSettle;
    PassiveSettleConfig settle{};
    uint32_t sampleIntervalMs = 250;
    size_t captureCap = kPassiveDumpMaxImage;

    // NtSuspendProcess/NtResumeProcess are resolved dynamically. Failure to gain
    // that optional right is reported and capture continues read-only.
    bool suspendDuringFinalCapture = false;
    // Fresh launches are always created suspended, assigned to a one-process
    // kill-on-close Job, then resumed. There are never DEBUG_* creation flags.
    // The service retains the Job after capture so completing a dump does not
    // unexpectedly terminate the watched process.
    bool rebuildPe = true;
    bool observeExactExportImports = true;
    bool normalizeRelocations = true;
    bool terminateLaunchedOnCancel = false;

    bool hasManualOep = false;
    uint64_t manualOepVA = 0;
};

struct PassiveDumpProgress {
    PassiveDumpPhase phase = PassiveDumpPhase::Idle;
    uint32_t pid = 0;
    uint64_t moduleBase = 0;
    uint64_t moduleSize = 0;
    uint64_t elapsedMs = 0;
    uint32_t samples = 0;
    uint32_t stableSamples = 0;
    uint32_t readablePages = 0;
    uint32_t totalPages = 0;
    double changedPageRatio = 1.0;
    double entropy = 0.0;
    std::string status;
};

struct PassiveDumpResult {
    bool success = false;
    bool launched = false;
    bool suspendedDuringCapture = false;
    bool launchContained = false;
    bool importObservationRequested = false;
    bool importObservationTruncated = false;
    bool importObservationCoherent = false;
    PassiveWorkerFailure workerFailure = PassiveWorkerFailure::None;
    PassiveOepAssessment oep{};
    PassiveArtifactAssessment artifactAssessment = PassiveArtifactAssessment::RawCaptureOnly;
    PassiveMemoryAssessment memory{};
    uint32_t pid = 0;
    std::wstring processPath;
    PassiveModuleInfo module;
    PassiveSettleDecision timingDecision = PassiveSettleDecision::Continue;
    PassiveSampleMetrics finalSample{};
    std::vector<PassiveSampleMetrics> sampleHistory; // bounded to 512
    PassiveCapture capture;
    std::vector<PeUnpackImport> observedImports;
    PeUnpackResult rebuilt;
    std::vector<std::string> warnings;
    std::string error;
    std::string report;
};

// Bounded process enumeration. Image paths are queried using a minimal query
// handle; inaccessible/protected processes are still returned with a blank path.
std::vector<PassiveProcessInfo> EnumeratePassiveProcesses(size_t cap = 4096);

// One-job, thread-safe worker. Results are moved out by tryTakeResult().
class PassiveDumpService {
public:
    PassiveDumpService() = default;
    ~PassiveDumpService();

    PassiveDumpService(const PassiveDumpService&) = delete;
    PassiveDumpService& operator=(const PassiveDumpService&) = delete;

    bool start(PassiveDumpRequest request, std::string* error = nullptr);
    void requestCapture();
    void cancel();
    void cancelAndWait();
    // Explicitly ends a contained launched process. The same happens when the
    // service is destroyed or a new contained launch replaces the old one.
    void terminateContainedLaunch();

    bool busy() const { return busy_.load(std::memory_order_acquire); }
    PassiveDumpProgress progress() const;
    bool tryTakeResult(PassiveDumpResult& out);

private:
    void workerMain(PassiveDumpRequest request);
    void publish(PassiveDumpPhase phase, const std::string& status);
    void failWorkerNoexcept(PassiveWorkerFailure failure, bool launched) noexcept;

    mutable std::mutex mutex_;
    // Serializes worker_ join/replacement. The atomic busy flag arbitrates job
    // ownership, while this mutex closes concurrent start/cancelAndWait races on
    // the std::thread object itself.
    mutable std::mutex lifecycleMutex_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> busy_{false};
    std::atomic<bool> cancel_{false};
    std::atomic<bool> manualCapture_{false};
    std::atomic<PassiveWorkerFailure> emergencyFailure_{PassiveWorkerFailure::None};
    PassiveDumpProgress progress_{};
    std::vector<PassiveDumpResult> results_; // bounded to the newest result
    uintptr_t ownedLaunchJob_ = 0;
};

} // namespace ds
