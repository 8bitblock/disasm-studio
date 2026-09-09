//
// LiveScanService.cpp — see LiveScanService.h.
//
#include "LiveScanService.h"
#include "XrefIndex.h"     // FindRefsInBuffer

#include <algorithm>
#include <exception>
#include <limits>

namespace ds {

std::string FormatLiveXrefStatus(const LiveScanResult& result) {
    if (!result.complete)
        return result.error.empty() ? "Live reference search failed. Refresh to retry."
                                    : "Live reference search failed: " + result.error;
    std::string status = std::to_string(result.hits.size()) + " reference(s); " +
        std::to_string(result.scannedBytes) + " of " +
        std::to_string(result.attemptedBytes) + " requested byte(s) read";
    if (result.truncated) status += "; partial coverage: scan limit reached";
    if (result.partialChunks || result.unreadableChunks)
        status += "; partial coverage: " + std::to_string(result.partialChunks) +
            " short read(s), " + std::to_string(result.unreadableChunks) + " unreadable range(s)";
    if (!result.scopeWarning.empty()) status += "; memory map partial: " + result.scopeWarning;
    if (!result.coverageComplete()) status += ". Missing references remain unknown.";
    return status;
}

LiveScanService::LiveScanService(DecoderFactory factory) : factory_(std::move(factory)) {
    unsigned hc = std::thread::hardware_concurrency();
    unsigned n  = hc > 3 ? hc - 2 : 1;
    if (n > 8) n = 8;
    threads_.reserve(n);
    try {
        for (unsigned i = 0; i < n; ++i) threads_.emplace_back([this] { threadMain(); });
    } catch (...) {
        // A partially-constructed vector of joinable std::threads would call
        // std::terminate while unwinding the constructor. Stop and join every
        // worker that was created before propagating the startup failure.
        quit_.store(true, std::memory_order_release);
        cv_.notify_all();
        for (auto& thread : threads_) if (thread.joinable()) thread.join();
        throw;
    }
}

LiveScanService::LiveScanService(LegacyDecoderFactory factory)
    : LiveScanService(factory
        ? DecoderFactory([factory = std::move(factory)](const DecoderConfig& config) {
              return LegacyDecoderFactoryCanRepresent(config)
                   ? factory(config.engine, config.arch) : nullptr;
          })
        : DecoderFactory{}) {}

LiveScanService::~LiveScanService() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        // Destruction is cancellation, not a request to finish potentially
        // uncapped target-memory work. Supersede in-flight jobs and release
        // queued readers before joining the workers.
        quit_.store(true, std::memory_order_release);
        queue_.clear();
        results_.clear();
        nonPatternResultCount_ = 0;
        epoch_.fetch_add(1, std::memory_order_acq_rel);
        pending_.store(false, std::memory_order_release);
        progActive_.store(0, std::memory_order_relaxed);
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

void LiveScanService::publishResultLocked(LiveScanResult&& result) {
    const bool nonPattern = result.kind != LiveKind::Pattern;
    results_.push_back(std::move(result));
    if (!nonPattern) return;

    ++nonPatternResultCount_;
    constexpr size_t kMaxSharedResults = 256;
    if (nonPatternResultCount_ <= kMaxSharedResults) return;

    // A Pattern completion belongs to one exact UI token and must not vanish
    // merely because unrelated shared work completed later. Evict only the
    // oldest ordinary result, keeping its historical bound independent of
    // retained Pattern completions.
    const auto oldestShared = std::find_if(
        results_.begin(), results_.end(), [](const LiveScanResult& candidate) {
            return candidate.kind != LiveKind::Pattern;
        });
    if (oldestShared != results_.end()) {
        results_.erase(oldestShared);
        --nonPatternResultCount_;
    }
}

uint64_t LiveScanService::requestStrings(std::vector<LiveRange> ranges, MemReader reader,
                                         uint64_t epoch, size_t strCap, size_t byteCap) {
    Job j; j.kind = LiveKind::Strings; j.ranges = std::move(ranges); j.reader = std::move(reader);
    j.epoch = epoch; j.strCap = strCap; j.byteCap = byteCap;
    return enqueue(std::move(j));
}

uint64_t LiveScanService::requestXref(std::vector<LiveRange> ranges, uint64_t target,
                                      Engine engine, Arch arch, MemReader reader, uint64_t epoch,
                                      size_t hitCap, size_t byteCap, std::string scopeWarning) {
    DecoderConfig decoder;
    decoder.engine = engine;
    decoder.arch = arch;
    return requestXref(std::move(ranges), target, decoder, std::move(reader), epoch,
                       hitCap, byteCap, std::move(scopeWarning));
}

uint64_t LiveScanService::requestXref(std::vector<LiveRange> ranges, uint64_t target,
                                      const DecoderConfig& decoder, MemReader reader,
                                      uint64_t epoch, size_t hitCap, size_t byteCap,
                                      std::string scopeWarning) {
    Job j; j.kind = LiveKind::Xref; j.ranges = std::move(ranges); j.target = target;
    j.decoder = decoder; j.reader = std::move(reader);
    j.epoch = epoch; j.hitCap = hitCap; j.byteCap = byteCap;
    j.scopeWarning = std::move(scopeWarning);
    return enqueue(std::move(j));
}

uint64_t LiveScanService::requestReadImage(uint64_t base, uint64_t size, uint64_t moduleBase,
                                           MemReader reader, uint64_t epoch) {
    Job j; j.kind = LiveKind::ReadImage; j.ranges = { { base, size } }; j.moduleBase = moduleBase;
    j.reader = std::move(reader); j.epoch = epoch;
    return enqueue(std::move(j));
}

uint64_t LiveScanService::requestPattern(std::vector<LiveRange> ranges,
                                         SigPattern pattern, MemReader reader,
                                         uint64_t epoch, size_t hitCap,
                                         uint64_t byteCap, size_t chunkBytes) {
    Job j;
    j.kind = LiveKind::Pattern;
    j.ranges = std::move(ranges);
    j.pattern = std::move(pattern);
    j.reader = std::move(reader);
    j.epoch = epoch;
    j.hitCap = hitCap;
    j.byteCap = byteCap > (std::numeric_limits<size_t>::max)()
        ? (std::numeric_limits<size_t>::max)()
        : static_cast<size_t>(byteCap);
    constexpr size_t kMaxPatternChunk = 64u << 20;
    j.chunkBytes = (std::clamp)(chunkBytes, size_t{1}, kMaxPatternChunk);
    return enqueue(std::move(j));
}

bool LiveScanService::tryTake(LiveScanResult& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (results_.empty()) return false;
    if (results_.front().kind != LiveKind::Pattern)
        --nonPatternResultCount_;
    out = std::move(results_.front());
    results_.pop_front();
    return true;
}

bool LiveScanService::tryTakePattern(uint64_t token, LiveScanResult& out) {
    if (!token) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    const auto found = std::find_if(results_.begin(), results_.end(),
        [token](const LiveScanResult& result) {
            return result.kind == LiveKind::Pattern && result.token == token;
        });
    if (found == results_.end()) return false;
    out = std::move(*found);
    results_.erase(found);
    return true;
}

bool LiveScanService::tryTakeNonPattern(LiveScanResult& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    const auto found = std::find_if(results_.begin(), results_.end(),
        [](const LiveScanResult& result) {
            return result.kind != LiveKind::Pattern;
        });
    if (found == results_.end()) return false;
    --nonPatternResultCount_;
    out = std::move(*found);
    results_.erase(found);
    return true;
}

void LiveScanService::cancelPattern(uint64_t token) {
    if (!token) return;
    std::lock_guard<std::mutex> lk(mtx_);
    std::erase_if(queue_, [token](const Job& job) {
        return job.kind == LiveKind::Pattern && job.token == token;
    });
    std::erase_if(results_, [token](const LiveScanResult& result) {
        return result.kind == LiveKind::Pattern && result.token == token;
    });
    if (inFlightPatternTokens_.contains(token))
        canceledTokens_.insert(token);
    const bool idle = queue_.empty() && inFlight_ == 0;
    pending_.store(!idle, std::memory_order_release);
    if (idle) progActive_.store(0, std::memory_order_relaxed);
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
    nonPatternResultCount_ = 0;
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
    nonPatternResultCount_ = 0;
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
            if (job.kind == LiveKind::Pattern)
                inFlightPatternTokens_.insert(job.token);
            pending_.store(true);
        }

        try {
            runJob(job);
        } catch (const std::exception& exception) {
            try {
                LiveScanResult failure;
                failure.kind = job.kind;
                failure.epoch = job.epoch;
                failure.token = job.token;
                failure.target = job.target;
                failure.moduleBase = job.moduleBase;
                failure.error = std::string("live scan worker failed: ") + exception.what();
                std::lock_guard<std::mutex> lk(mtx_);
                if (epoch_.load(std::memory_order_acquire) == job.epoch &&
                    !(job.kind == LiveKind::Pattern &&
                      canceledTokens_.contains(job.token))) {
                    publishResultLocked(std::move(failure));
                }
            } catch (...) {
                // Even reporting an allocation failure must not escape a
                // std::thread entry point and terminate the application.
            }
        } catch (...) {
            try {
                LiveScanResult failure;
                failure.kind = job.kind;
                failure.epoch = job.epoch;
                failure.token = job.token;
                failure.target = job.target;
                failure.moduleBase = job.moduleBase;
                failure.error = "live scan worker failed: unknown exception";
                std::lock_guard<std::mutex> lk(mtx_);
                if (epoch_.load(std::memory_order_acquire) == job.epoch &&
                    !(job.kind == LiveKind::Pattern &&
                      canceledTokens_.contains(job.token))) {
                    publishResultLocked(std::move(failure));
                }
            } catch (...) {
            }
        }

        {
            std::lock_guard<std::mutex> lk(mtx_);
            --inFlight_;
            if (job.kind == LiveKind::Pattern) {
                inFlightPatternTokens_.erase(job.token);
                canceledTokens_.erase(job.token);
            }
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
    auto superseded = [this, e = job.epoch, token = job.token,
                       kind = job.kind] {
        if (quit_.load(std::memory_order_acquire)) return true;
        if (epoch_.load(std::memory_order_acquire) != e) return true;
        if (kind != LiveKind::Pattern) return false;
        std::lock_guard<std::mutex> lk(mtx_);
        return canceledTokens_.contains(token);
    };
    if (superseded() || !job.reader) return;

    progKind_.store((uint32_t)job.kind, std::memory_order_relaxed);
    progTotal_.store((uint32_t)job.ranges.size(), std::memory_order_relaxed);
    progCur_.store(0, std::memory_order_relaxed);
    progActive_.store(1, std::memory_order_release);

    LiveScanResult res;
    res.kind = job.kind; res.epoch = job.epoch; res.token = job.token;
    res.target = job.target; res.moduleBase = job.moduleBase;
    res.scopeWarning = job.scopeWarning;

    auto publish = [&](LiveScanResult&& value) {
        if (epoch_.load(std::memory_order_acquire) != job.epoch) return;
        std::lock_guard<std::mutex> lk(mtx_);
        if (epoch_.load(std::memory_order_acquire) != job.epoch ||
            (job.kind == LiveKind::Pattern &&
             canceledTokens_.contains(job.token)))
            return;
        publishResultLocked(std::move(value));
    };

    std::vector<uint8_t> buf;
    size_t scanned = 0;

    if (job.kind == LiveKind::Pattern) {
        if (job.pattern.empty() || job.pattern.mask.size() != job.pattern.size()) {
            res.error = "live pattern scan received an invalid or empty pattern";
            publish(std::move(res));
            return;
        }

        const uint64_t byteCap = static_cast<uint64_t>(job.byteCap);
        const bool capped = byteCap != 0;
        const size_t lookaheadMax = job.pattern.size() - 1;
        uint64_t plannedChunks = 0;
        uint64_t plannedBudget = capped ? byteCap : UINT64_MAX;
        for (const LiveRange& range : job.ranges) {
            if (!plannedBudget) break;
            if (!range.size || range.base > UINT64_MAX - range.size) continue;
            const uint64_t bytes = capped
                ? (std::min)(range.size, plannedBudget) : range.size;
            const uint64_t chunks = bytes / job.chunkBytes +
                                    (bytes % job.chunkBytes != 0);
            plannedChunks = plannedChunks > UINT64_MAX - chunks
                ? UINT64_MAX : plannedChunks + chunks;
            if (capped) plannedBudget -= bytes;
        }
        progTotal_.store(static_cast<uint32_t>((std::min<uint64_t>)(
                             plannedChunks, UINT32_MAX)),
                         std::memory_order_relaxed);
        uint64_t completedChunks = 0;
        for (size_t r = 0; r < job.ranges.size(); ++r) {
            if (superseded()) return;
            const LiveRange& range = job.ranges[r];
            if (!range.size || range.base > UINT64_MAX - range.size) {
                if (range.size) {
                    res.error = "live pattern scan range overflows the address space";
                    publish(std::move(res));
                    return;
                }
                continue;
            }

            for (uint64_t offset = 0; offset < range.size;) {
                if (superseded()) return;
                if (capped && res.attemptedBytes >= byteCap) {
                    res.truncated = true;
                    break;
                }

                const uint64_t remaining = range.size - offset;
                uint64_t owned64 = (std::min<uint64_t>)(remaining, job.chunkBytes);
                if (capped)
                    owned64 = (std::min)(owned64, byteCap - res.attemptedBytes);
                if (!owned64) {
                    res.truncated = remaining != 0;
                    break;
                }
                const uint64_t lookahead64 = (std::min<uint64_t>)(
                    lookaheadMax, remaining - owned64);
                const size_t owned = static_cast<size_t>(owned64);
                if (lookahead64 > (std::numeric_limits<size_t>::max)() - owned) {
                    res.error = "live pattern scan buffer size overflows the host";
                    publish(std::move(res));
                    return;
                }
                const size_t wanted = owned + static_cast<size_t>(lookahead64);
                buf.assign(wanted, 0);

                const uint64_t address = range.base + offset;
                size_t got = job.reader(address, buf.data(), wanted);
                if (got > wanted) got = wanted;
                res.attemptedBytes += owned64;
                res.scannedBytes += (std::min<size_t>)(got, owned);
                if (!got) ++res.unreadableChunks;
                else if (got < wanted) ++res.partialChunks;

                if (got >= job.pattern.size()) {
                    size_t room = 0;
                    if (job.hitCap) {
                        room = res.hits.size() >= job.hitCap
                            ? 1 : job.hitCap - res.hits.size() + 1;
                    }
                    const auto localHits = FindAllMaskedAccepted(
                        buf.data(), got, job.pattern, room,
                        [owned](size_t local) { return local < owned; });
                    for (size_t local : localHits) {
                        res.hits.push_back(address + local);
                        if (job.hitCap && res.hits.size() > job.hitCap) {
                            res.hits.resize(job.hitCap);
                            res.truncated = true;
                            break;
                        }
                    }
                }
                offset += owned64;
                ++completedChunks;
                progCur_.store(static_cast<uint32_t>((std::min<uint64_t>)(
                                   completedChunks, UINT32_MAX)),
                               std::memory_order_relaxed);
                if (job.hitCap && res.truncated && res.hits.size() >= job.hitCap)
                    break;
            }
            if (res.truncated &&
                ((job.hitCap && res.hits.size() >= job.hitCap) ||
                 (capped && res.attemptedBytes >= byteCap)))
                break;
        }
        res.complete = true;
        publish(std::move(res));
        return;
    }

    std::unique_ptr<IDisassembler> dis;
    if (job.kind == LiveKind::Xref) {
        try {
            dis = factory_ ? factory_(job.decoder) : nullptr;
        } catch (const std::exception& exception) {
            res.error = std::string("live xref decoder initialization failed: ") + exception.what();
        } catch (...) {
            res.error = "live xref decoder initialization failed: unknown exception";
        }
        if (res.error.empty() && !dis)
            res.error = "live xref decoder factory returned null";
        if (res.error.empty() && !dis->ready()) {
            res.error = "live xref decoder initialization failed";
            if (!dis->errorMessage().empty()) {
                res.error += ": ";
                res.error.append(dis->errorMessage());
            }
        }
        if (!res.error.empty()) {
            publish(std::move(res));
            return;
        }
    }

    for (size_t r = 0; r < job.ranges.size(); ++r) {
        if (superseded()) return;                       // dropped by a newer epoch
        const LiveRange& rg = job.ranges[r];
        if (rg.size == 0) { progCur_.store((uint32_t)(r + 1), std::memory_order_relaxed); continue; }

        size_t sz = static_cast<size_t>((std::min)(rg.size,
            static_cast<uint64_t>((std::numeric_limits<size_t>::max)())));
        if (job.kind != LiveKind::ReadImage) {          // honour the overall byte cap
            if (scanned >= job.byteCap) { res.truncated = true; break; }
            if (rg.size > job.byteCap - scanned) {
                sz = job.byteCap - scanned;
                res.truncated = true; // the tail of this range will not be scanned
            }
        }
        buf.resize(sz);
        const size_t got = (std::min)(job.reader(rg.base, buf.data(), sz), sz);
        scanned += sz;
        if (job.kind == LiveKind::Xref) {
            res.attemptedBytes += sz;
            res.scannedBytes += got;
            if (!got) ++res.unreadableChunks;
            else if (got < sz) ++res.partialChunks;
        }

        if (got) {
            switch (job.kind) {
                case LiveKind::Strings:
                {
                    bool bufferTruncated = false;
                    ScanStringsBuffer(buf.data(), got, rg.base, res.strings,
                                      job.strCap, &bufferTruncated);
                    if (bufferTruncated) res.truncated = true;
                    break;
                }
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
                case LiveKind::Pattern:
                    break; // handled by the bounded chunk path above
            }
        }
        progCur_.store((uint32_t)(r + 1), std::memory_order_relaxed);
        // Exactly hitting the cap is not proof that data was omitted. Continue to
        // the next range with zero room; its first candidate will set truncated.
        if (job.kind == LiveKind::Strings && res.truncated
            && res.strings.size() >= job.strCap) break;
    }

    if (job.kind == LiveKind::Strings) {
        std::sort(res.strings.begin(), res.strings.end(),
                  [](const StrResult& a, const StrResult& b) { return a.address < b.address; });
        res.strings.erase(std::unique(res.strings.begin(), res.strings.end(),
                          [](const StrResult& a, const StrResult& b) { return a.address == b.address; }),
                          res.strings.end());
    }

    res.complete = true;
    publish(std::move(res)); // don't deliver a result a detach/reload superseded
}

} // namespace ds
