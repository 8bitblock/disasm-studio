#pragma once
//
// AnalysisService.h
// A background WORKER POOL that runs the heavy, image-reading analysis passes
// (string scan + function discovery/naming + listing index + xref sweep) off the
// ImGui render thread, so loading a large binary never freezes the UI and many
// modules can be analyzed in parallel. Results are handed back through a
// mutex-guarded queue the render thread drains each frame; an epoch counter drops
// results that a newer binary load or patch has superseded.
//
// Two responsiveness properties matter:
//   * PARALLELISM — N worker threads (≈ cores-2) so a "analyze every module"
//     batch fans out across cores while the single render thread stays free.
//   * INCREMENTAL DELIVERY — each pass (strings, then functions, then listing,
//     then xref) is pushed as a separate result the moment it finishes, so the
//     cheap functions/strings appear immediately and the heavier listing/xref
//     sweeps never delay them.
//
// Mirrors the existing Debugger idiom (own threads + lock-guarded snapshot consumed
// by the UI thread). ImGui-free and Win32-free, so the mechanics are unit-testable
// with a stub disassembler (see tests/analysis_service_test.cpp).
//
// Threading contract:
//   * A worker NEVER touches ImGui, the Debugger, or a shared decoder — it builds
//     its own IDisassembler via the injected factory.
//   * The BinaryFile passed to requestBulk() must outlive every in-flight job that
//     reads it. Because loading/closing a binary reallocates its bytes, the owner
//     MUST call cancelAndWaitIdle() before BinaryFile::load/loadRaw/clear (and
//     before destroying a module the pool may be reading) so no worker read is in
//     flight against memory about to be freed.
//   * writeImage() patches overwrite bytes in place (no reallocation), so a patch
//     concurrent with a sweep cannot dangle; the result is merely superseded by the
//     post-patch bumpEpoch()+requestBulk() and dropped on pickup.
//
#include "AnalysisJobs.h"
#include "XrefIndex.h"
#include "AlgoScan.h"                   // AlgoMatch (K_Intent results)
#include "Synthesis.h"                  // SynthResult (K_Synthesis results)
#include "PathExplore.h"                // PathTree (K_PathExplore results)
#include "../Disasm/IDisassembler.h"   // Engine, Arch, IDisassembler

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace ds {

class BinaryFile;

// Which passes a bulk request should run (OR together). K_Synthesis (F1) and
// K_PathExplore (F3, static/structural) target a single region [regionLo,regionHi)
// passed to requestBulk; the live-debugger-seeded F3 explore runs on its own thread.
enum BulkKind : uint32_t {
    K_Funcs = 1, K_Strings = 2, K_Listing = 4, K_Xref = 8, K_Intent = 16, K_CallGraph = 32,
    K_Synthesis = 64, K_PathExplore = 128
};

// Coarse "what is the pool doing right now" indicator for the progress bar.
enum class AnalysisPhase : uint32_t { Idle = 0, Strings, Functions, Listing, Xref };

// Lock-free snapshot of pool progress (plain atomic loads; never blocks the UI).
struct ProgressSnapshot {
    AnalysisPhase phase        = AnalysisPhase::Idle;
    uint32_t      current      = 0;   // units depend on phase (bytes / instructions)
    uint32_t      total        = 0;   // 0 => indeterminate
    uint32_t      modulesDone  = 0;   // for a multi-module "analyze all" batch
    uint32_t      modulesTotal = 0;   // 0 => not a batch
    uint64_t      moduleBase   = 0;   // module currently being worked (0 = single binary)
};

struct AnalysisResult {
    uint64_t epoch      = 0;     // the epoch this result was computed for
    uint32_t kinds      = 0;     // which passes the originating job requested
    uint64_t moduleBase = 0;     // which module this result is for (0 = single binary)

    std::vector<StrResult>  strings;       bool stringsValid = false;
    std::vector<FuncResult> functions;     bool funcsValid   = false;
    std::string             summary;
    std::vector<ListRowR>   listRows;      bool listingValid = false;
    int                     listInsnCount = 0;
    std::shared_ptr<XrefIndex> xref;       // non-null only when K_Xref ran
    std::vector<AlgoMatch>  algos;         bool algosValid   = false;  // K_Intent results
    std::vector<CallEdgeR>  callEdges;     bool callGraphValid = false; // K_CallGraph results
    SynthResult             synth;         bool synthValid   = false;  // K_Synthesis (F1) result
    PathTree                pathTree;      bool pathValid    = false;  // K_PathExplore (F3) result
    uint64_t                regionLo = 0, regionHi = 0;                // the region these targeted
};

class AnalysisService {
public:
    using DecoderFactory = std::function<std::unique_ptr<IDisassembler>(Engine, Arch)>;

    explicit AnalysisService(DecoderFactory factory);
    ~AnalysisService();

    AnalysisService(const AnalysisService&)            = delete;
    AnalysisService& operator=(const AnalysisService&) = delete;

    // Monotone cancellation token. A result is accepted by the consumer only when
    // result.epoch == epoch(); bumpEpoch() invalidates everything older.
    uint64_t epoch() const { return epoch_.load(std::memory_order_acquire); }
    uint64_t bumpEpoch()   { return epoch_.fetch_add(1, std::memory_order_acq_rel) + 1; }

    // Queue (and coalesce) a bulk job for `moduleBase` (0 = the single loaded
    // binary). A pending-but-unstarted request for the same module is merged: the
    // kinds are OR'd and the newest binary/engine/arch/guess/epoch win. Different
    // modules queue independently and fan out across the worker pool.
    void requestBulk(const BinaryFile* bin, Engine engine, Arch arch,
                     uint32_t kinds, bool guessNames, uint64_t epoch,
                     uint64_t moduleBase = 0, uint64_t regionLo = 0, uint64_t regionHi = 0);

    // Non-blocking: move the next finished result out, if any. The pool delivers one
    // result PER PASS, so the caller should drain in a loop each frame and still
    // check out.epoch == epoch() before applying each one.
    bool tryTakeBulk(AnalysisResult& out);

    // True while any request is queued or running (drives the UI's "analyzing…" hint).
    bool     bulkPending()  const { return pending_.load(std::memory_order_acquire); }
    uint32_t pendingKinds() const { return pendingKinds_.load(std::memory_order_acquire); }

    // Lock-free progress snapshot for a progress bar.
    ProgressSnapshot progress() const;

    // Announce that `total` module jobs are about to be enqueued, so progress() can
    // report "N / total modules". Each completed module job increments the count;
    // the batch auto-resets when done reaches total (or on cancelAndWaitIdle).
    void beginModuleBatch(uint32_t total) {
        progModDone_.store(0, std::memory_order_relaxed);
        progModTotal_.store(total, std::memory_order_relaxed);
    }

    // Supersede all queued/running jobs and block until every worker is idle, so the
    // caller can safely reallocate/free a BinaryFile the pool was reading.
    void cancelAndWaitIdle();

    // Non-blocking cancel for a UI "Cancel" button: drop queued jobs + unpicked
    // results and supersede running ones (they bail at the next checkpoint). Safe to
    // call from the render thread — unlike cancelAndWaitIdle it never blocks.
    void cancelPending();

private:
    struct BulkJob {
        const BinaryFile* bin    = nullptr;
        Engine            engine = Engine::Zydis;
        Arch              arch   = Arch::X64;
        uint32_t          kinds  = 0;
        bool              guess  = false;
        uint64_t          epoch  = 0;
        uint64_t          modBase = 0;
        uint64_t          regionLo = 0, regionHi = 0;   // K_Synthesis / K_PathExplore target
    };

    void threadMain();
    void runJob(const BulkJob& job);
    void setPhase(AnalysisPhase p, uint32_t total, uint64_t modBase);

    DecoderFactory               factory_;
    std::vector<std::thread>     threads_;
    mutable std::mutex           mtx_;
    std::condition_variable      cv_;       // wakes a worker (new job / quit)
    std::condition_variable      cvIdle_;   // wakes cancelAndWaitIdle when fully idle
    std::deque<BulkJob>          queue_;     // pending (unstarted) jobs
    std::deque<AnalysisResult>   results_;   // finished results awaiting pickup
    int                          inFlight_ = 0;  // jobs currently executing
    std::atomic<bool>            quit_{false};
    std::atomic<bool>            pending_{false};
    std::atomic<uint32_t>        pendingKinds_{0};
    std::atomic<uint64_t>        epoch_{1};

    // Progress channel (published by whichever worker is running; during a batch the
    // module counters are the meaningful aggregate, the per-pass counters cosmetic).
    std::atomic<uint32_t>        progPhase_{0};
    std::atomic<uint32_t>        progCur_{0};
    std::atomic<uint32_t>        progTotal_{0};
    std::atomic<uint32_t>        progModDone_{0};
    std::atomic<uint32_t>        progModTotal_{0};
    std::atomic<uint64_t>        progModBase_{0};
};

} // namespace ds
