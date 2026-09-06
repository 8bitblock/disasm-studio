#pragma once
//
// LiveScanService.h
// A background WORKER POOL for scans that read LIVE DEBUGGEE MEMORY, so they no longer
// block the ImGui render thread:
//   * Strings   — extract printable strings from a set of memory ranges.
//   * Xref      — decode-sweep executable ranges for instructions referencing a target.
//   * ReadImage — copy one module's mapped image out of the process (backs the parallel
//                 "analyze all modules": the UI then loadFromMemory's it + hands the
//                 BinaryFile to AnalysisService).
//
// This is the sibling of AnalysisService. The crucial difference: AnalysisService must
// NEVER touch the Debugger, so it can't do these. A LiveScanService job instead carries
// a `reader` closure bound to Debugger::readMemoryMasked (which is thread-safe), and the
// worker only ever calls that closure + its own private decoder — never ImGui, never the
// Debugger directly, never a shared decoder. Results are delivered through a polled queue
// the render thread drains each frame; an epoch drops results a detach/reload superseded,
// and a per-request token matches "the latest request of this kind".
//
// Lifetime: declare a LiveScanService AFTER the Debugger it reads, so its dtor (which
// joins the workers) runs BEFORE the Debugger is destroyed — no worker can call a freed
// reader. The ranges to scan are captured on the UI thread (so the worker never calls
// Debugger::regions()/ProcessManager); the reader is the only debuggee touch-point.
//
// ImGui-free / Win32-free, so the mechanics are unit-testable with a stub reader +
// stub disassembler (see tests/livescan_service_test.cpp).
//
#include "AnalysisJobs.h"                // StrResult, ScanStringsBuffer
#include "../Disasm/IDisassembler.h"     // Engine, Arch, IDisassembler

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ds {

enum class LiveKind : uint32_t { Strings, Xref, ReadImage };

// One [base, base+size) span of debuggee memory to scan/read.
struct LiveRange { uint64_t base = 0; uint64_t size = 0; };

using MemReader = std::function<size_t(uint64_t va, void* out, size_t n)>;

struct LiveScanResult {
    LiveKind kind  = LiveKind::Strings;
    uint64_t epoch = 0;
    uint64_t token = 0;          // matches the request that produced it
    uint64_t target = 0;         // Xref: the searched address (echoed back)
    uint64_t moduleBase = 0;     // ReadImage: which module (echoed back)
    std::vector<StrResult> strings;   // Strings
    std::vector<uint64_t>  hits;      // Xref (instruction addresses)
    std::vector<uint8_t>   image;     // ReadImage (the module's mapped bytes)
    bool truncated = false;           // hit a cap (strings/hits/bytes)
    bool complete = false;            // false means error describes a failed job
    std::string error;
};

// Lightweight progress for the status-bar bar (lock-free atomic reads).
struct LiveProgress {
    LiveKind kind    = LiveKind::Strings;
    bool     active  = false;
    uint32_t current = 0;   // ranges processed so far
    uint32_t total   = 0;   // ranges total
};

class LiveScanService {
public:
    using DecoderFactory =
        std::function<std::unique_ptr<IDisassembler>(const DecoderConfig&)>;
    using LegacyDecoderFactory =
        std::function<std::unique_ptr<IDisassembler>(Engine, Arch)>;

    explicit LiveScanService(DecoderFactory factory);
    explicit LiveScanService(LegacyDecoderFactory factory);
    ~LiveScanService();

    LiveScanService(const LiveScanService&)            = delete;
    LiveScanService& operator=(const LiveScanService&) = delete;

    uint64_t epoch() const { return epoch_.load(std::memory_order_acquire); }
    uint64_t bumpEpoch()   { return epoch_.fetch_add(1, std::memory_order_acq_rel) + 1; }

    // Queue a job; returns a token to match its result with. `reader` must stay valid
    // until the job runs (it captures the Debugger, which outlives this service).
    uint64_t requestStrings(std::vector<LiveRange> ranges, MemReader reader, uint64_t epoch,
                            size_t strCap = kDefaultStringScanCap,
                            size_t byteCap = 256ull * 1024 * 1024);
    uint64_t requestXref(std::vector<LiveRange> ranges, uint64_t target, Engine engine, Arch arch,
                         MemReader reader, uint64_t epoch,
                         size_t hitCap = 3000, size_t byteCap = 64ull * 1024 * 1024);
    uint64_t requestXref(std::vector<LiveRange> ranges, uint64_t target,
                         const DecoderConfig& decoder, MemReader reader, uint64_t epoch,
                         size_t hitCap = 3000, size_t byteCap = 64ull * 1024 * 1024);
    uint64_t requestReadImage(uint64_t base, uint64_t size, uint64_t moduleBase,
                              MemReader reader, uint64_t epoch);

    // Non-blocking: move the next finished result out, if any (drain in a loop; still
    // check out.epoch == epoch() before applying).
    bool tryTake(LiveScanResult& out);

    bool         busy() const { return pending_.load(std::memory_order_acquire); }
    LiveProgress progress() const;

    // Announce a batch of `total` ReadImage jobs ("analyze all modules") for the count.
    void beginBatch(uint32_t total) { batchTotal_.store(total, std::memory_order_relaxed);
                                      batchDone_.store(0, std::memory_order_relaxed); }
    uint32_t batchTotal() const { return batchTotal_.load(std::memory_order_relaxed); }
    uint32_t batchDone()  const { return batchDone_.load(std::memory_order_relaxed); }

    void cancelAndWaitIdle();   // blocking: drain + wait for workers idle (before teardown)
    void cancelPending();       // non-blocking: drop queued/unpicked + supersede running

private:
    struct Job {
        LiveKind  kind  = LiveKind::Strings;
        std::vector<LiveRange> ranges;
        uint64_t  target = 0;
        uint64_t  moduleBase = 0;
        DecoderConfig decoder;
        size_t    strCap = kDefaultStringScanCap;
        size_t    hitCap = 3000;
        size_t    byteCap = 256ull * 1024 * 1024;
        uint64_t  epoch = 0;
        uint64_t  token = 0;
        MemReader reader;
    };

    uint64_t enqueue(Job&& j);
    void     threadMain();
    void     runJob(const Job& j);

    DecoderFactory             factory_;
    std::vector<std::thread>   threads_;
    mutable std::mutex         mtx_;
    std::condition_variable    cv_;
    std::condition_variable    cvIdle_;
    std::deque<Job>            queue_;
    std::deque<LiveScanResult> results_;
    int                        inFlight_ = 0;
    uint64_t                   nextToken_ = 1;
    std::atomic<bool>          quit_{false};
    std::atomic<bool>          pending_{false};
    std::atomic<uint64_t>      epoch_{1};
    // Progress (published by whichever worker is running).
    std::atomic<uint32_t>      progKind_{0};
    std::atomic<uint32_t>      progActive_{0};
    std::atomic<uint32_t>      progCur_{0};
    std::atomic<uint32_t>      progTotal_{0};
    std::atomic<uint32_t>      batchTotal_{0};
    std::atomic<uint32_t>      batchDone_{0};
};

} // namespace ds
