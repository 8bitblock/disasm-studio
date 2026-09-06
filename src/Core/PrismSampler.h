#pragma once
//
// PrismSampler.h
// The Win32 collection service behind Prism. A dedicated worker first attempts a
// bounded real-time ETW kernel session (sampled profile + image/thread/scheduling/
// I/O evidence). If policy or privilege prevents that, PreferEtw falls back to the
// explicitly labelled suspend-and-walk collector. A second worker owns report
// aggregation, so the render thread never copies and reprocesses the sample window.
//
#include "Prism.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ds {

enum class PrismStartMode : uint8_t {
    PreferEtw,
    EtwOnly,
    SuspendWalkOnly
};

const char* PrismStartModeName(PrismStartMode mode);

class PrismSampler {
public:
    // Rolling history bound: profiling continues after this many observations;
    // the oldest sample is discarded so refresh/memory cost stays predictable.
    static constexpr size_t kMaxSamples = 10000;

    PrismSampler();
    ~PrismSampler();

    // Begin collecting process `pid`. Setup that may require elevation (ETW) is
    // performed by the worker; PreferEtw automatically records the reason and
    // enters the compatibility fallback when ETW is unavailable.
    bool start(uint32_t pid, PrismStartMode mode, std::string& err);
    bool start(uint32_t pid, std::string& err) {
        return start(pid, PrismStartMode::PreferEtw, err);
    }

    // Non-blocking cancellation for UI actions. stop() additionally joins and is
    // used for destruction/restart.
    void requestStop();
    void stop();

    bool     running() const { return running_.load(); }
    uint32_t pid() const { return pid_; }
    uint64_t creationTime100ns() const {
        return creationTime100ns_.load(std::memory_order_acquire);
    }
    PrismCollectorKind collectorKind() const {
        return collector_.load(std::memory_order_acquire);
    }
    bool wow64Target() const { return wow64_.load(std::memory_order_acquire); }

    // Copy the samples collected so far (thread-safe).
    std::vector<PrismSample> snapshot() const;
    size_t sampleCount() const;
    uint64_t sampleGeneration() const { return generation_.load(std::memory_order_acquire); }
    void   clearSamples();
    PrismCollectionQuality quality() const;

    // Immutable report produced by the aggregation worker. Copying this shared
    // pointer is the only report work performed by PrismTab::render().
    std::shared_ptr<const PrismReport> report() const;
    uint64_t reportGeneration() const { return reportGeneration_.load(std::memory_order_acquire); }
    // Asynchronous initialization failure (for example SymInitialize). Empty when
    // the worker is healthy or stopped normally.
    std::string lastError() const;

private:
    void collectorThreadEntry() noexcept;
    void reportThreadEntry() noexcept;
    void publishFatalError(const char* message) noexcept;
    void cleanupFailedCollector(const char* message) noexcept;
    void run();
    bool runEtw(void* hProc, std::string& reason);
    void runSuspendWalk(void* hProc);
    bool sampleThread(void* hProc, uint32_t tid);
    void appendSample(PrismSample&& sample, uint32_t resolvedFrames);
    void reportLoop();
    void publishError(std::string error);
    void setQuality(const PrismCollectionQuality& quality);

    // EVENT_RECORD/TRACE_LOGFILE callbacks are kept void*-typed here so the public
    // header remains independent of windows.h/evntrace.h.
    static void __stdcall etwEventThunk(void* record);
    static unsigned long __stdcall etwBufferThunk(void* logfile);
    void onEtwEvent(void* record);
    unsigned long onEtwBuffer(void* logfile);

    std::thread              thread_;
    std::thread              reportThread_;
    std::atomic<bool>        running_{ false };
    std::atomic<bool>        stop_{ false };
    std::atomic<bool>        reportStop_{ false };
    std::atomic<uint64_t>    generation_{ 0 };
    std::atomic<uint64_t>    reportGeneration_{ 0 };
    std::atomic<PrismCollectorKind> collector_{ PrismCollectorKind::SuspendWalk };
    std::atomic<bool>        wow64_{ false };
    PrismStartMode           startMode_ = PrismStartMode::PreferEtw;
    uint32_t                 pid_   = 0;
    std::atomic<uint64_t>    creationTime100ns_{ 0 };
    void*                    hProc_ = nullptr;     // HANDLE (owned while running)
    std::atomic<uint64_t>    etwSession_{ 0 };     // TRACEHANDLE, owner worker stops it
    mutable std::mutex       mtx_;
    std::condition_variable  reportCv_;
    std::deque<PrismSample>  samples_;
    PrismCollectionQuality   quality_;
    std::shared_ptr<const PrismReport> report_;
    std::string              error_;
    std::unordered_map<uint32_t, uint64_t> lastCycles_; // worker-thread only
    std::unordered_set<uint32_t> targetThreads_;        // ETW worker-thread only
};

} // namespace ds
