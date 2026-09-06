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
//   * BinaryFile::writeImage() is also a mutation of storage workers read. The
//     owner MUST call cancelAndWaitIdle() before every patch/revert write; an epoch
//     guard rejects stale results but does not make a concurrent byte read/write
//     data-race-free. A fresh request may be queued after the mutation.
//
#include "AnalysisJobs.h"
#include "AnalysisCache.h"
#include "XrefIndex.h"
#include "AlgoScan.h"                   // AlgoMatch (K_Intent results)
#include "Synthesis.h"                  // SynthResult (K_Synthesis results)
#include "PathExplore.h"                // PathTree (K_PathExplore results)
#include "CrackmeTriage.h"              // CrackmeTriageReport (offline network trail)
#include "../Disasm/IDisassembler.h"   // Engine, Arch, IDisassembler

#include <atomic>
#include <cstddef>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace ds {

struct ProjectAnalysisOverrides;

class BinaryFile;

// Which passes a bulk request should run (OR together). K_Synthesis (F1) and
// K_PathExplore (F3, static/structural) target a single region [regionLo,regionHi)
// passed to requestBulk with regionValid=true; the explicit flag keeps VA 0 usable.
// The live-debugger-seeded F3 explore runs on its own thread.
enum BulkKind : uint32_t {
    K_Funcs = 1, K_Strings = 2, K_Listing = 4, K_Xref = 8, K_Intent = 16, K_CallGraph = 32,
    K_Synthesis = 64, K_PathExplore = 128, K_Decompile = 256, K_ListingPrefix = 512,
    K_CrackmeTriage = 1024
};

// Coarse "what is the pool doing right now" indicator for the progress bar.
enum class AnalysisPhase : uint32_t {
    Idle = 0, Strings, Functions, Listing, ListingPrefix, Xref, CrackmeTriage
};

// Lock-free snapshot of pool progress (plain atomic loads; never blocks the UI).
struct ProgressSnapshot {
    AnalysisPhase phase        = AnalysisPhase::Idle;
    uint32_t      current      = 0;   // units depend on phase (bytes / instructions)
    uint32_t      total        = 0;   // 0 => indeterminate
    uint32_t      modulesDone  = 0;   // for a multi-module "analyze all" batch
    uint32_t      modulesTotal = 0;   // 0 => not a batch
    uint64_t      moduleBase   = 0;   // module currently being worked (0 = single binary)
    uint64_t      jobsFailed   = 0;   // worker exceptions converted into failure results
    uint64_t      resultsDropped = 0; // completed results evicted by the bounded queue
    uint64_t      requestsCoalesced = 0; // pending requests merged before execution
    uint64_t      cacheHits = 0;      // worker-side immutable derived-result reuse
    uint64_t      cacheMisses = 0;    // cacheable passes which required recomputation
};

struct AnalysisResult {
    uint64_t epoch      = 0;     // the epoch this result was computed for
    uint32_t kinds      = 0;     // which passes the originating job requested
    uint64_t moduleBase = 0;     // which module this result is for (0 = single binary)
    std::string failure;         // structured worker failure; normal pass fields remain invalid
    bool failureValid = false;

    std::vector<StrResult>  strings;       bool stringsValid = false;
    bool                    stringsTruncated = false; // hit kDefaultStringScanCap
    std::vector<FuncResult> functions;     bool funcsValid   = false;
    std::string             summary;
    std::shared_ptr<const CodeDataMap> codeData; // accompanies K_Funcs; reusable by layout-only rebuilds
    std::vector<ListRowR>   listRows;      bool listingValid = false;
    uint64_t                listingCodeBytes = 0; // described executable bytes (not eagerly decoded)
    uint64_t                listingCodePages = 0; // fixed-size lazy CodePage descriptors
    uint64_t                listingRevision = 0; // immutable layout snapshot generation
    uint64_t                listingTopologyGeneration = 0; // exact CodePage/root topology request
    std::vector<ListingPrefixCheckpoint> listingPrefixCheckpoints;
    bool                    listingPrefixDone = false;
    bool                    listingPrefixValid = false;
    uint64_t                listingPrefixTarget = 0;
    std::shared_ptr<XrefIndex> xref;       // non-null only when K_Xref ran
    uint64_t xrefImageRevision = 0;
    uint64_t xrefDecoderSignature = 0;
    uint64_t xrefOverrideDigest = 0;
    std::vector<AlgoMatch>  algos;         bool algosValid   = false;  // K_Intent results
    CrackmeTriageReport     crackmeTriage; bool crackmeTriageValid = false;
    std::vector<CallEdgeR>  callEdges;     bool callGraphValid = false; // K_CallGraph results
    SynthResult             synth;         bool synthValid   = false;  // K_Synthesis (F1) result
    PathTree                pathTree;      bool pathValid    = false;  // K_PathExplore (F3) result
    std::string             decompText;    bool decompValid  = false;  // K_Decompile (pseudocode) result
    std::vector<uint64_t>   decompLineVA;  // per-line source VAs (DecompResult::lineVA)
    std::vector<SourceOrigin> decompLineOrigins;
    bool                    decompComplete = true;
    std::string             decompIncompleteReason;
    std::vector<DecompileDiagnostic> decompDiagnostics;
    uint64_t                decompVA      = 0;                          // function start the pseudocode is for
    uint64_t                decompContext = 0; // caller name generation; rejects stale renamed output
    uint64_t                regionLo = 0, regionHi = 0;                // the region these targeted
    bool                    regionValid = false; // a targeted region may begin at VA 0
};

// Conservative accounting for the immutable derived-result cache.  This is
// public so the bounded cache policy can be regression-tested without exposing
// or mutating AnalysisService's private LRU.  Nested vector/string allocations
// are included; the estimate may intentionally over-count SSO storage.
size_t EstimateAnalysisResultBytes(const AnalysisResult& result);

class AnalysisService {
public:
    using DecoderFactory = std::function<std::unique_ptr<IDisassembler>(const DecoderConfig&)>;
    using LegacyDecoderFactory = std::function<std::unique_ptr<IDisassembler>(Engine, Arch)>;
    static constexpr unsigned kAutomaticWorkerCount = 0;
    static constexpr unsigned kMaxWorkerCount = 8;

    // `workerCount == 0` preserves the historical automatic policy
    // (approximately hardware_concurrency()-2, clamped to [1, 8]).  Owners
    // which create several independent services may request a smaller explicit
    // pool so aggregate concurrency remains bounded.
    explicit AnalysisService(DecoderFactory factory,
                             unsigned workerCount = kAutomaticWorkerCount);
    explicit AnalysisService(LegacyDecoderFactory factory,
                             unsigned workerCount = kAutomaticWorkerCount);
    ~AnalysisService();

    AnalysisService(const AnalysisService&)            = delete;
    AnalysisService& operator=(const AnalysisService&) = delete;

    unsigned workerCount() const {
        return static_cast<unsigned>(threads_.size());
    }

    // Monotone cancellation token. A result is accepted by the consumer only when
    // result.epoch == epoch(); bumpEpoch() invalidates everything older.
    uint64_t epoch() const { return epoch_.load(std::memory_order_acquire); }
    uint64_t bumpEpoch()   { return epoch_.fetch_add(1, std::memory_order_acq_rel) + 1; }

    // Queue (and coalesce) a bulk job for `moduleBase` (0 = the single loaded
    // binary). A compatible pending request for the same module is merged: kinds
    // are OR'd and newest settings win. Different targeted kinds (Synthesis, Path
    // Explore, Decompile) stay separate because each owns a distinct address range.
    // Different modules queue independently and fan out across the worker pool.
    // Targeted callers must set regionValid=true; regionLo==0 is a real address.
    void requestBulk(const BinaryFile* bin, const DecoderConfig& decoder,
                     uint32_t kinds, bool guessNames, uint64_t epoch,
                     uint64_t moduleBase = 0, uint64_t regionLo = 0, uint64_t regionHi = 0,
                     bool regionValid = false,
                     std::shared_ptr<const DecompileNameMap> decompNames = {},
                     std::string decompSignature = {}, uint64_t decompContext = 0,
                     std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides = {},
                     uint64_t orderedPatchDigest = 0,
                     std::shared_ptr<const std::vector<FunctionChunk>> decompChunks = {},
                     bool decompOwnershipTruncated = false,
                     std::shared_ptr<const std::vector<uint64_t>> noreturnTargets = {});
    void requestBulk(const BinaryFile* bin, Engine engine, Arch arch,
                     uint32_t kinds, bool guessNames, uint64_t epoch,
                     uint64_t moduleBase = 0, uint64_t regionLo = 0, uint64_t regionHi = 0,
                     bool regionValid = false,
                     std::shared_ptr<const DecompileNameMap> decompNames = {},
                     std::string decompSignature = {}, uint64_t decompContext = 0,
                     std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides = {},
                     uint64_t orderedPatchDigest = 0,
                     std::shared_ptr<const std::vector<FunctionChunk>> decompChunks = {},
                     bool decompOwnershipTruncated = false,
                     std::shared_ptr<const std::vector<uint64_t>> noreturnTargets = {});

    // Untargeted bulk request carrying the exact listing visibility/fold snapshot
    // that K_Listing must plan against. A separate listingRevision lets the UI
    // reject an older layout result without bumping the global analysis epoch and
    // accidentally cancelling function/string/xref work already in flight.
    void requestBulkWithListing(const BinaryFile* bin, const DecoderConfig& decoder,
                                uint32_t kinds, bool guessNames, uint64_t epoch,
                                 std::shared_ptr<const ListingLayout> listingLayout,
                                 uint64_t listingRevision,
                                 std::shared_ptr<const std::vector<StrResult>> listingStrings = {},
                                 uint64_t moduleBase = 0,
                                 std::shared_ptr<const CodeDataMap> listingCodeData = {},
                                 std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides = {},
                                 uint64_t orderedPatchDigest = 0);
    void requestBulkWithListing(const BinaryFile* bin, Engine engine, Arch arch,
                                uint32_t kinds, bool guessNames, uint64_t epoch,
                                std::shared_ptr<const ListingLayout> listingLayout,
                                uint64_t listingRevision,
                                std::shared_ptr<const std::vector<StrResult>> listingStrings = {},
                                uint64_t moduleBase = 0,
                                std::shared_ptr<const CodeDataMap> listingCodeData = {},
                                std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides = {},
                                uint64_t orderedPatchDigest = 0);

    // On-demand exact variable-width checkpoint preparation. `startVA` is a
    // trustworthy section/function boundary; `pageBase` is the section's first
    // CodePage and `targetPage` is the page the UI needs. Long scans stay on the
    // analysis pool and inherit its cancellation/lifetime guarantees.
    void requestListingPrefix(const BinaryFile* bin, const DecoderConfig& decoder,
                              uint64_t epoch, uint64_t startVA, uint64_t pageBase,
                              uint64_t targetPage, uint64_t listingRevision,
                              uint64_t orderedPatchDigest = 0,
                              uint64_t listingTopologyGeneration = 0);
    void requestListingPrefix(const BinaryFile* bin, Engine engine, Arch arch,
                              uint64_t epoch, uint64_t startVA, uint64_t pageBase,
                              uint64_t targetPage, uint64_t listingRevision,
                              uint64_t orderedPatchDigest = 0,
                              uint64_t listingTopologyGeneration = 0);

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
        DecoderConfig     decoder;
        uint32_t          kinds  = 0;
        bool              guess  = false;
        uint64_t          epoch  = 0;
        uint64_t          modBase = 0;
        uint64_t          regionLo = 0, regionHi = 0;   // K_Synthesis / K_PathExplore target
        bool              regionValid = false;          // explicit because regionLo may be VA 0
        std::shared_ptr<const DecompileNameMap> decompNames; // immutable UI name snapshot
        std::string       decompSignature;
        uint64_t          decompContext = 0;
        std::shared_ptr<const std::vector<FunctionChunk>> decompChunks;
        bool              decompOwnershipTruncated = false;
        std::shared_ptr<const std::vector<uint64_t>> noreturnTargets;
        std::shared_ptr<const ListingLayout> listingLayout;
        std::shared_ptr<const std::vector<StrResult>> listingStrings;
        std::shared_ptr<const CodeDataMap> listingCodeData;
        std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides;
        uint64_t          orderedPatchDigest = 0;
        uint64_t          listingRevision = 0;
        uint64_t          listingPrefixPageBase = 0;
        uint64_t          listingTopologyGeneration = 0;
    };

    void requestBulkImpl(const BinaryFile* bin, const DecoderConfig& decoder,
                         uint32_t kinds, bool guessNames, uint64_t epoch,
                         uint64_t moduleBase, uint64_t regionLo, uint64_t regionHi,
                         bool regionValid,
                         std::shared_ptr<const DecompileNameMap> decompNames,
                         std::string decompSignature, uint64_t decompContext,
                          std::shared_ptr<const ListingLayout> listingLayout,
                          uint64_t listingRevision,
                          std::shared_ptr<const std::vector<StrResult>> listingStrings = {},
                          uint64_t listingPrefixPageBase = 0,
                          uint64_t listingTopologyGeneration = 0,
                          std::shared_ptr<const CodeDataMap> listingCodeData = {},
                          std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides = {},
                         uint64_t orderedPatchDigest = 0,
                         std::shared_ptr<const std::vector<FunctionChunk>> decompChunks = {},
                         bool decompOwnershipTruncated = false,
                         std::shared_ptr<const std::vector<uint64_t>> noreturnTargets = {});
    void threadMain();
    void runJob(const BulkJob& job);
    void publishResult(AnalysisResult&& result);
    void publishFailure(const BulkJob& job, const char* message) noexcept;
    void setPhase(AnalysisPhase p, uint32_t total, uint64_t modBase);

    DecoderFactory               factory_;
    AnalysisCache                cache_;
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
    std::atomic<uint64_t>        failedJobs_{0};
    std::atomic<uint64_t>        droppedResults_{0};
    std::atomic<uint64_t>        coalescedRequests_{0};
    std::atomic<uint64_t>        cacheHits_{0};
    std::atomic<uint64_t>        cacheMisses_{0};

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
