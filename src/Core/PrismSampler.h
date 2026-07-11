#pragma once
//
// PrismSampler.h
// The thin Win32 sampling layer behind the Prism profiler (Core/Prism). It runs a
// background thread that periodically suspends every thread of a target process,
// StackWalk64s it, symbolizes the frames ("module!function"), and appends a
// PrismSample. The UI thread snapshots the samples and hands them to BuildPrismReport
// for the aggregation + plain-English verdict.
//
// Uses DbgHelp (StackWalk64 / SymFromAddr) and so takes the process-global
// DbgHelpMutex around every DbgHelp call, exactly like Debugger::unwindStack. x64
// targets only for now (WOW64 / 32-bit targets are rejected at start()).
//
#include "Prism.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ds {

class PrismSampler {
public:
    // Rolling history bound: profiling continues after this many observations;
    // the oldest sample is discarded so refresh/memory cost stays predictable.
    static constexpr size_t kMaxSamples = 10000;

    ~PrismSampler();

    // Begin sampling process `pid`. Returns false with `err` set on failure
    // (OpenProcess denied, 32-bit target, already running).
    bool start(uint32_t pid, std::string& err);
    // Signal the sampler thread and join it. Collected samples are retained.
    void stop();

    bool     running() const { return running_.load(); }
    uint32_t pid() const { return pid_; }

    // Copy the samples collected so far (thread-safe).
    std::vector<PrismSample> snapshot() const;
    size_t sampleCount() const;
    uint64_t sampleGeneration() const { return generation_.load(std::memory_order_acquire); }
    void   clearSamples();
    // Asynchronous initialization failure (for example SymInitialize). Empty when
    // the worker is healthy or stopped normally.
    std::string lastError() const;

private:
    void run();                                   // sampler thread body
    void sampleThread(void* hProc, uint32_t tid); // one thread, one instant

    std::thread              thread_;
    std::atomic<bool>        running_{ false };
    std::atomic<bool>        stop_{ false };
    std::atomic<uint64_t>    generation_{ 0 };
    uint32_t                 pid_   = 0;
    void*                    hProc_ = nullptr;     // HANDLE (owned while running)
    mutable std::mutex       mtx_;
    std::deque<PrismSample>  samples_;
    std::string              error_;
    std::unordered_map<uint32_t, uint64_t> lastCycles_; // worker-thread only
};

} // namespace ds
