//
// LiveScanService.cpp — see LiveScanService.h.
//
#include "LiveScanService.h"
#include "XrefIndex.h"     // FindRefsInBuffer

#include <algorithm>

namespace ds {

LiveScanService::LiveScanService(DecoderFactory factory) : factory_(std::move(factory)) {
    unsigned hc = std::thread::hardware_concurrency();
    unsigned n  = hc > 3 ? hc - 2 : 1;
    if (n > 8) n = 8;
    threads_.reserve(n);
    for (unsigned i = 0; i < n; ++i) threads_.emplace_back([this] { threadMain(); });
}

LiveScanService::~LiveScanService() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        quit_.store(true);
    }
    cv_.notify_all();
    for (auto& t : threads_) if (t.joinable()) t.join();
}

uint64_t LiveScanService::enqueue(Job&& j) {
    uint64_t token;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        token = j.token = nextToken_++;
        queue_.push_back(std::move(j));
        pending_.store(true);
    }
    cv_.notify_one();
    return token;
}

uint64_t LiveScanService::requestStrings(std::vector<LiveRange> ranges, MemReader reader,
                                         uint64_t epoch, size_t strCap, size_t byteCap) {
    Job j; j.kind = LiveKind::Strings; j.ranges = std::move(ranges); j.reader = std::move(reader);
    j.epoch = epoch; j.strCap = strCap; j.byteCap = byteCap;
    return enqueue(std::move(j));
}

uint64_t LiveScanService::requestXref(std::vector<LiveRange> ranges, uint64_t target,
                                      Engine engine, Arch arch, MemReader reader, uint64_t epoch,
                                      size_t hitCap, size_t byteCap) {
    Job j; j.kind = LiveKind::Xref; j.ranges = std::move(ranges); j.target = target;
    j.engine = engine; j.arch = arch; j.reader = std::move(reader);
    j.epoch = epoch; j.hitCap = hitCap; j.byteCap = byteCap;
    return enqueue(std::move(j));
}

uint64_t LiveScanService::requestReadImage(uint64_t base, uint64_t size, uint64_t moduleBase,
                                           MemReader reader, uint64_t epoch) {
    Job j; j.kind = LiveKind::ReadImage; j.ranges = { { base, size } }; j.moduleBase = moduleBase;
    j.reader = std::move(reader); j.epoch = epoch;
    return enqueue(std::move(j));
}

bool LiveScanService::tryTake(LiveScanResult& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (results_.empty()) return false;
    out = std::move(results_.front());
    results_.pop_front();
    return true;
}

LiveProgress LiveScanService::progress() const {
    LiveProgress p;
    p.kind    = (LiveKind)progKind_.load(std::memory_order_relaxed);
    p.active  = progActive_.load(std::memory_order_acquire) != 0;
    p.current = progCur_.load(std::memory_order_relaxed);
    p.total   = progTotal_.load(std::memory_order_relaxed);
    return p;
}

void LiveScanService::cancelAndWaitIdle() {
    std::unique_lock<std::mutex> lk(mtx_);
    queue_.clear();
    results_.clear();
    epoch_.fetch_add(1, std::memory_order_acq_rel);
    pending_.store(false);
    progActive_.store(0, std::memory_order_relaxed);
    batchTotal_.store(0, std::memory_order_relaxed);
    batchDone_.store(0, std::memory_order_relaxed);
    cvIdle_.wait(lk, [this] { return inFlight_ == 0; });
}

void LiveScanService::cancelPending() {
    std::lock_guard<std::mutex> lk(mtx_);
    queue_.clear();
    results_.clear();
    epoch_.fetch_add(1, std::memory_order_acq_rel);
    pending_.store(inFlight_ > 0);
    batchTotal_.store(0, std::memory_order_relaxed);
    batchDone_.store(0, std::memory_order_relaxed);
}

void LiveScanService::threadMain() {
    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [this] { return quit_.load() || !queue_.empty(); });
            if (quit_.load()) return;
            job = std::move(queue_.front());
            queue_.pop_front();
            ++inFlight_;
            pending_.store(true);
        }

        runJob(job);

        {
            std::lock_guard<std::mutex> lk(mtx_);
            --inFlight_;
            if (job.kind == LiveKind::ReadImage && batchTotal_.load(std::memory_order_relaxed) > 0) {
                uint32_t done = batchDone_.fetch_add(1, std::memory_order_relaxed) + 1;
                if (done >= batchTotal_.load(std::memory_order_relaxed)) {
                    batchTotal_.store(0, std::memory_order_relaxed);
                    batchDone_.store(0, std::memory_order_relaxed);
                }
            }
            bool idle = queue_.empty() && inFlight_ == 0;
            pending_.store(!idle);
            if (idle) progActive_.store(0, std::memory_order_relaxed);
        }
        cvIdle_.notify_all();
    }
}

void LiveScanService::runJob(const Job& job) {
    auto superseded = [this, e = job.epoch] {
        return epoch_.load(std::memory_order_acquire) != e;
    };
    if (superseded() || !job.reader) return;

    progKind_.store((uint32_t)job.kind, std::memory_order_relaxed);
    progTotal_.store((uint32_t)job.ranges.size(), std::memory_order_relaxed);
    progCur_.store(0, std::memory_order_relaxed);
    progActive_.store(1, std::memory_order_release);

    LiveScanResult res;
    res.kind = job.kind; res.epoch = job.epoch; res.token = job.token;
    res.target = job.target; res.moduleBase = job.moduleBase;

    std::vector<uint8_t> buf;
    size_t scanned = 0;

    std::unique_ptr<IDisassembler> dis;
    if (job.kind == LiveKind::Xref) dis = factory_ ? factory_(job.engine, job.arch) : nullptr;

    for (size_t r = 0; r < job.ranges.size(); ++r) {
        if (superseded()) return;                       // dropped by a newer epoch
        const LiveRange& rg = job.ranges[r];
        if (rg.size == 0) { progCur_.store((uint32_t)(r + 1), std::memory_order_relaxed); continue; }

        size_t sz = (size_t)rg.size;
        if (job.kind != LiveKind::ReadImage) {          // honour the overall byte cap
            if (scanned >= job.byteCap) { res.truncated = true; break; }
            if (scanned + sz > job.byteCap) sz = job.byteCap - scanned;
        }
        buf.resize(sz);
        size_t got = job.reader(rg.base, buf.data(), sz);
        scanned += sz;

        if (got) {
            switch (job.kind) {
                case LiveKind::Strings:
                    ScanStringsBuffer(buf.data(), got, rg.base, res.strings, job.strCap);
                    if (res.strings.size() >= job.strCap) res.truncated = true;
                    break;
                case LiveKind::Xref:
                    if (dis && !FindRefsInBuffer(buf.data(), got, rg.base, job.target, *dis, res.hits, job.hitCap)) {
                        res.truncated = true;
                        progCur_.store((uint32_t)(r + 1), std::memory_order_relaxed);
                        r = job.ranges.size();          // hit the cap: stop scanning
                    }
                    break;
                case LiveKind::ReadImage:
                    buf.resize(got);
                    res.image = std::move(buf);
                    buf = std::vector<uint8_t>();       // moved-from: re-init scratch
                    break;
            }
        }
        progCur_.store((uint32_t)(r + 1), std::memory_order_relaxed);
        if (job.kind == LiveKind::Strings && res.strings.size() >= job.strCap) break;
    }

    if (job.kind == LiveKind::Strings) {
        std::sort(res.strings.begin(), res.strings.end(),
                  [](const StrResult& a, const StrResult& b) { return a.address < b.address; });
        res.strings.erase(std::unique(res.strings.begin(), res.strings.end(),
                          [](const StrResult& a, const StrResult& b) { return a.address == b.address; }),
                          res.strings.end());
    }

    if (superseded()) return;   // don't deliver a result a detach/reload superseded
    std::lock_guard<std::mutex> lk(mtx_);
    results_.push_back(std::move(res));
    if (results_.size() > 256) results_.pop_front();
}

} // namespace ds
