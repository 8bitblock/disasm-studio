//
// AnalysisService.cpp — see AnalysisService.h.
//
#include "AnalysisService.h"
#include "BinaryFile.h"
#include "SynthesisJob.h"     // K_Synthesis (F1)
#include "PathExploreJob.h"   // K_PathExplore (F3, static)
#include "../Disasm/JvmDisassembler.h"   // AttachJvmClass (JavaClass symbolication)

#include <algorithm>
#include <limits>

namespace ds {

AnalysisService::AnalysisService(DecoderFactory factory) : factory_(std::move(factory)) {
    // ≈ cores-2 workers (leave one core for the render thread and one for the OS),
    // clamped to [1, 8]. The pool lets an "analyze every module" batch fan out.
    unsigned hc = std::thread::hardware_concurrency();
    unsigned n  = hc > 3 ? hc - 2 : 1;
    if (n > 8) n = 8;
    threads_.reserve(n);
    for (unsigned i = 0; i < n; ++i) threads_.emplace_back([this] { threadMain(); });
}

AnalysisService::~AnalysisService() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        quit_.store(true);
    }
    cv_.notify_all();
    for (auto& t : threads_) if (t.joinable()) t.join();
}

void AnalysisService::requestBulk(const BinaryFile* bin, Engine engine, Arch arch,
                                  uint32_t kinds, bool guessNames, uint64_t epoch,
                                  uint64_t moduleBase, uint64_t regionLo, uint64_t regionHi,
                                  std::shared_ptr<const DecompileNameMap> decompNames,
                                  std::string decompSignature, uint64_t decompContext) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        constexpr uint32_t kTargeted = K_Synthesis | K_PathExplore | K_Decompile;
        const uint32_t incomingTargeted = kinds & kTargeted;
        BulkJob* mergeInto = nullptr;
        for (auto& j : queue_) {                 // coalesce with an unstarted request
            if (j.modBase != moduleBase) continue;
            const uint32_t queuedTargeted = j.kinds & kTargeted;
            // Targeted passes share regionLo/regionHi storage. Different target
            // kinds must remain separate jobs or the newer request silently moves
            // the older pass to its own region. Untargeted bulk work may still
            // merge into either job; the same target kind takes the newest region.
            if (queuedTargeted && incomingTargeted
                && queuedTargeted != incomingTargeted) continue;
            if (!mergeInto) mergeInto = &j; // untargeted fallback
            // Prefer an already-pending request for this exact targeted pass over
            // an earlier untargeted job, avoiding duplicate decompiles.
            if (!incomingTargeted || queuedTargeted == incomingTargeted) {
                mergeInto = &j;
                break;
            }
        }
        if (mergeInto) {
            BulkJob& j = *mergeInto;
            j.kinds |= kinds;
            j.bin    = bin;
            j.engine = engine;
            j.arch   = arch;
            j.guess  = guessNames;
            j.epoch  = epoch;
            if (incomingTargeted) { j.regionLo = regionLo; j.regionHi = regionHi; }
            if (kinds & K_Decompile) {
                j.decompNames = std::move(decompNames);
                j.decompSignature = std::move(decompSignature);
                j.decompContext = decompContext;
            }
        } else {
            BulkJob job;
            job.bin = bin; job.engine = engine; job.arch = arch; job.kinds = kinds;
            job.guess = guessNames; job.epoch = epoch; job.modBase = moduleBase;
            job.regionLo = regionLo; job.regionHi = regionHi;
            job.decompNames = std::move(decompNames);
            job.decompSignature = std::move(decompSignature);
            job.decompContext = decompContext;
            queue_.push_back(std::move(job));
        }
        pending_.store(true);
        pendingKinds_.store(pendingKinds_.load(std::memory_order_relaxed) | kinds);
    }
    cv_.notify_one();
}

bool AnalysisService::tryTakeBulk(AnalysisResult& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (results_.empty()) return false;
    out = std::move(results_.front());
    results_.pop_front();
    return true;
}

ProgressSnapshot AnalysisService::progress() const {
    ProgressSnapshot s;
    s.phase        = (AnalysisPhase)progPhase_.load(std::memory_order_acquire);
    s.current      = progCur_.load(std::memory_order_relaxed);
    s.total        = progTotal_.load(std::memory_order_relaxed);
    s.modulesDone  = progModDone_.load(std::memory_order_relaxed);
    s.modulesTotal = progModTotal_.load(std::memory_order_relaxed);
    s.moduleBase   = progModBase_.load(std::memory_order_relaxed);
    return s;
}

void AnalysisService::cancelAndWaitIdle() {
    std::unique_lock<std::mutex> lk(mtx_);
    queue_.clear();                                  // drop all queued requests
    results_.clear();                                // and any finished-but-unpicked results
    epoch_.fetch_add(1, std::memory_order_acq_rel);  // supersede everything running
    pending_.store(false);
    pendingKinds_.store(0);
    progModTotal_.store(0, std::memory_order_relaxed);
    progModDone_.store(0, std::memory_order_relaxed);
    progPhase_.store((uint32_t)AnalysisPhase::Idle, std::memory_order_relaxed);
    cvIdle_.wait(lk, [this] { return inFlight_ == 0; });  // block until workers yield
}

void AnalysisService::cancelPending() {
    std::lock_guard<std::mutex> lk(mtx_);
    queue_.clear();                                  // drop all queued requests
    results_.clear();                                // and any finished-but-unpicked results
    epoch_.fetch_add(1, std::memory_order_acq_rel);  // supersede everything running (bails at a checkpoint)
    pending_.store(inFlight_ > 0);                   // still "pending" while running jobs wind down
    pendingKinds_.store(0);
    progModTotal_.store(0, std::memory_order_relaxed);
    progModDone_.store(0, std::memory_order_relaxed);
}

void AnalysisService::setPhase(AnalysisPhase p, uint32_t total, uint64_t modBase) {
    progPhase_.store((uint32_t)p, std::memory_order_release);
    progTotal_.store(total, std::memory_order_relaxed);
    progCur_.store(0, std::memory_order_relaxed);
    progModBase_.store(modBase, std::memory_order_relaxed);
}

void AnalysisService::threadMain() {
    for (;;) {
        BulkJob job;
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [this] { return quit_.load() || !queue_.empty(); });
            if (quit_.load()) return;
            job = queue_.front();
            queue_.pop_front();
            ++inFlight_;
            pending_.store(true);
            pendingKinds_.store(job.kinds);
        }

        runJob(job);

        {
            std::lock_guard<std::mutex> lk(mtx_);
            --inFlight_;
            // Count a completed module-batch job (even when superseded, so a cancelled
            // batch still converges and resets its counters).
            if (job.modBase != 0 && progModTotal_.load(std::memory_order_relaxed) > 0) {
                uint32_t done = progModDone_.fetch_add(1, std::memory_order_relaxed) + 1;
                if (done >= progModTotal_.load(std::memory_order_relaxed)) {
                    progModTotal_.store(0, std::memory_order_relaxed);
                    progModDone_.store(0, std::memory_order_relaxed);
                }
            }
            bool idle = queue_.empty() && inFlight_ == 0;
            pending_.store(!idle);
            if (idle) {
                pendingKinds_.store(0);
                progPhase_.store((uint32_t)AnalysisPhase::Idle, std::memory_order_relaxed);
            }
        }
        cvIdle_.notify_all();
    }
}

void AnalysisService::runJob(const BulkJob& job) {
    auto superseded = [this, e = job.epoch] {
        return epoch_.load(std::memory_order_acquire) != e;
    };
    // Drop a job already superseded by a newer epoch before touching the (possibly
    // freed) binary.
    if (superseded() || !job.bin) return;
    std::unique_ptr<IDisassembler> dis = factory_ ? factory_(job.engine, job.arch) : nullptr;
    if (!dis) return;
    // Java class: hand the worker's own decoder the parsed class so listing
    // operands symbolicate (constant pool) and switch padding is exact. The
    // shared_ptr keeps the class alive for the job even across a concurrent
    // unload (the epoch check still drops the stale result).
    if (job.arch == Arch::JVM && job.bin->javaClass())
        AttachJvmClass(*dis, job.bin->javaClass());

    // Emit one result per pass, the moment it finishes, so the consumer can apply the
    // cheap functions/strings immediately and the heavier listing/xref later.
    auto emit = [&](AnalysisResult&& r) {
        r.epoch   = job.epoch;
        r.kinds   = job.kinds;
        r.moduleBase = job.modBase;
        std::lock_guard<std::mutex> lk(mtx_);
        results_.push_back(std::move(r));
        if (results_.size() > 512) results_.pop_front();   // backstop if the UI isn't draining
    };

    std::vector<StrResult>  strings;  bool haveStrings = false;
    std::vector<FuncResult> funcs;
    std::shared_ptr<XrefIndex> xrefIdx;   // built by K_Xref; reused by K_Intent for extent mapping

    if ((job.kinds & K_Strings) && !superseded()) {
        const size_t imageBytes = job.bin->bytes().size();
        setPhase(AnalysisPhase::Strings,
                 (uint32_t)std::min(imageBytes, (size_t)std::numeric_limits<uint32_t>::max()),
                 job.modBase);
        bool stringsTruncated = false;
        strings = ScanStringsImage(*job.bin, kDefaultStringScanCap, &progCur_, &stringsTruncated);
        haveStrings = true;
        AnalysisResult r; r.strings = strings; r.stringsValid = true;
        r.stringsTruncated = stringsTruncated;
        emit(std::move(r));
    }

    if ((job.kinds & K_Funcs) && !superseded()) {
        setPhase(AnalysisPhase::Functions, 0, job.modBase);   // FunctionAnalyzer has no granular count
        if (!haveStrings) { strings = ScanStringsImage(*job.bin); haveStrings = true; }
        AnalyzeOut a = AnalyzeFunctionsNamed(*job.bin, *dis, strings, job.guess);
        funcs = a.functions;
        AnalysisResult r; r.functions = funcs; r.summary = std::move(a.summary); r.funcsValid = true;
        emit(std::move(r));
    }

    if ((job.kinds & K_Listing) && !superseded()) {
        setPhase(AnalysisPhase::Listing, 800000, job.modBase);
        // A strings-only rescan also asks the worker to refresh data-string rows.
        // Discover divider starts locally when K_Funcs was not part of that job;
        // do not emit/churn the UI's existing function list.
        if (funcs.empty()) {
            if (!haveStrings) { strings = ScanStringsImage(*job.bin); haveStrings = true; }
            funcs = AnalyzeFunctionsNamed(*job.bin, *dis, strings, job.guess).functions;
        }
        std::vector<uint64_t> starts;
        starts.reserve(funcs.size());
        for (const auto& f : funcs) starts.push_back(f.address);   // dividers from this job's funcs
        std::vector<ListRowR> rows = BuildListingRows(*job.bin, *dis, starts, strings, 800000, superseded, &progCur_);
        if (!superseded()) {
            int cnt = 0;
            for (const auto& r : rows) if (!r.divider && !r.strData) ++cnt;
            AnalysisResult r; r.listRows = std::move(rows); r.listInsnCount = cnt; r.listingValid = true;
            emit(std::move(r));
        }
    }

    if ((job.kinds & K_CallGraph) && !superseded()) {
        // Reuse this job's discovered functions when K_Funcs ran; otherwise (a lazy
        // call-graph-only request from the tab) discover them locally without emitting
        // a funcs result, so opening the Call Graph view doesn't churn the UI's
        // function list / listing.
        std::vector<FuncResult> localFuncs;
        const std::vector<FuncResult>* fp = &funcs;
        if (funcs.empty()) {
            if (!haveStrings) { strings = ScanStringsImage(*job.bin); haveStrings = true; }
            localFuncs = AnalyzeFunctionsNamed(*job.bin, *dis, strings, job.guess).functions;
            fp = &localFuncs;
        }
        std::vector<CallEdgeR> edges = BuildCallEdges(*job.bin, *dis, *fp);
        if (!superseded()) {
            AnalysisResult r; r.callEdges = std::move(edges); r.callGraphValid = true;
            emit(std::move(r));
        }
    }

    if ((job.kinds & K_Xref) && !superseded()) {
        uint32_t total = 0;
        for (const auto& s : job.bin->sections()) {
            if (!s.executable) continue;
            size_t av = 0;
            uint64_t va = job.bin->imageBase() + s.virtualAddress;
            if (job.bin->ptrFromVA(va, av)) total += (uint32_t)av;
        }
        setPhase(AnalysisPhase::Xref, total, job.modBase);
        xrefIdx = std::make_shared<XrefIndex>();
        for (const auto& s : job.bin->sections()) {
            if (superseded()) break;
            if (!s.executable) continue;
            size_t avail = 0;
            uint64_t va = job.bin->imageBase() + s.virtualAddress;
            const uint8_t* p = job.bin->ptrFromVA(va, avail);
            if (p && avail) BuildXrefInto(*xrefIdx, p, avail, va, *dis, &progCur_);
        }
        FinalizeXrefIndex(*xrefIdx);
        if (!superseded()) {
            AnalysisResult r; r.xref = xrefIdx;   // share with K_Intent; UI adopts a copy
            emit(std::move(r));
        }
    }

    // Algorithm/crypto recognition (AlgoScan). Runs LAST so it can reuse this job's
    // function list (K_Funcs) and xref index (K_Xref) for extent mapping; either being
    // absent only drops the "referenced by" links, not the matches themselves.
    if ((job.kinds & K_Intent) && !superseded()) {
        std::vector<AlgoMatch> algos = ScanAlgorithmsJob(*job.bin, xrefIdx.get(), funcs);
        if (!superseded()) {
            AnalysisResult r; r.algos = std::move(algos); r.algosValid = true;
            emit(std::move(r));
        }
    }

    // F1 clean-room synthesis of the requested region (off the render thread). With the
    // stub engine the result is "engine unavailable"; with DS_HAVE_SYMENGINE it is real.
    if ((job.kinds & K_Synthesis) && !superseded() && job.regionHi > job.regionLo) {
        SynthesisOptions opt; opt.samples = 256;
        SynthResult sr = SynthesizeJob(*job.bin, *dis, job.arch, job.regionLo, job.regionHi, opt);
        if (!superseded()) {
            AnalysisResult r; r.synth = std::move(sr); r.synthValid = true;
            r.regionLo = job.regionLo; r.regionHi = job.regionHi;
            emit(std::move(r));
        }
    }

    // F3 STATIC path exploration from the region start (structural CFG look-ahead; the
    // live-debugger concolic explore is the own-thread follow-up).
    if ((job.kinds & K_PathExplore) && !superseded() && job.regionLo) {
        PathTree pt = PathExploreJob(*job.bin, *dis, job.arch, job.regionLo);
        if (!superseded()) {
            AnalysisResult r; r.pathTree = std::move(pt); r.pathValid = true;
            r.regionLo = job.regionLo; r.regionHi = job.regionHi;
            emit(std::move(r));
        }
    }

    // Structured pseudo-C for [regionLo, regionHi), off the render thread. The job
    // owns an immutable name/signature snapshot, including analyst renames and the
    // current discovered/guessed function names.
    if ((job.kinds & K_Decompile) && !superseded() && job.regionHi > job.regionLo) {
        DecompResult t = DecompileRegion(*job.bin, *dis, ArchIsX86(job.arch),
                                         job.regionLo, job.regionHi,
                                         job.decompNames.get(), job.decompSignature);
        if (!superseded()) {
            AnalysisResult r; r.decompText = std::move(t.text); r.decompLineVA = std::move(t.lineVA);
            r.decompValid = true;
            r.decompVA = job.regionLo;
            r.decompContext = job.decompContext;
            r.regionLo = job.regionLo; r.regionHi = job.regionHi;
            emit(std::move(r));
        }
    }
}

} // namespace ds
