#include "SigScannerTab.h"
#include "../Core/BinaryFile.h"
#include "../Core/FunctionAnalyzer.h"
#include "../Core/PatchSet.h"
#include "../Core/ProcessManager.h"
#include "../Core/Project.h"
#include "../Core/SigMatch.h"
#include "../Disasm/DisassemblerFactory.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <exception>
#include <limits>
#include <memory>
#include <utility>

namespace ds {

// Parse "48 89 ?? 24" into a SigPattern (bytes + wildcard mask) via the shared
// masked matcher's parser, which keeps identical semantics (single/double '?'
// wildcards, hex pairs, spaces ignored). Returns false if malformed.
static bool parsePattern(const std::string& in, SigPattern& pat) {
    return ParseSignature(in, pat);
}

static std::string healthFromCount(int count) {
    return count < 0 ? "malformed" : count == 0 ? "none" : count == 1 ? "unique" : "multiple";
}

namespace {

constexpr size_t kResultCap = 4096;
constexpr size_t kHealthCountCap = 100000;
constexpr size_t kScanChunk = 4u << 20;

struct WorkerImageSpec {
    DocumentResultIdentity owner;
    std::string path;
    std::string label;
    bool raw = false;
    bool mapped = false;
    uint64_t base = 0;
    uint64_t mappedSize = 0;
    bool rawEntryExplicit = false;
    uint64_t rawEntry = 0;
    std::vector<AnalysisLandmark> landmarks;
    std::vector<PjPatch> patches;
    DecoderConfig decoder;
    Debugger* debugger = nullptr;
    uint32_t livePid = 0;
    uint64_t liveGeneration = 0;
};

static bool captureWorkerImage(AppContext& ctx,
                               const DocumentResultIdentity& owner,
                               WorkerImageSpec& spec,
                               std::string& error) {
    const BinaryFile& binary = ctx.staticBinary();
    spec = {};
    spec.owner = owner;
    spec.path = binary.path();
    spec.label = binary.path();
    spec.raw = binary.format() == BinFormat::Raw && !binary.isMappedImage();
    spec.mapped = binary.isMappedImage();
    spec.base = binary.imageBase();
    spec.mappedSize = binary.bytes().size();
    spec.rawEntryExplicit = binary.rawEntryExplicit();
    spec.rawEntry = binary.entryPointVA();
    spec.landmarks = binary.analysisLandmarks();
    const PjPatchSetPlan patchPlan = SnapshotActivePatchRecords(
        ctx.staticProject().patches, ctx.staticProject().patchSets,
        spec.patches);
    if (!patchPlan.success) {
        error = std::string("invalid active patch selection (") +
                PjPatchSetPlanErrorText(patchPlan.error) + ")";
        spec = {};
        return false;
    }
    spec.decoder = ctx.staticDecoderConfig();
    if (spec.mapped) {
        const DbgSnapshot snapshot = ctx.debug.snapshot();
        spec.debugger = &ctx.debug;
        spec.livePid = snapshot.pid;
        spec.liveGeneration = snapshot.sessionGeneration;
    }
    return true;
}

static bool sameLiveSession(Debugger* debugger, uint32_t pid, uint64_t generation) {
    if (!debugger || !pid || !generation) return false;
    const DbgSnapshot snapshot = debugger->snapshot();
    return snapshot.attached() && snapshot.pid == pid &&
           snapshot.sessionGeneration == generation;
}

static bool loadWorkerImage(const WorkerImageSpec& spec, BinaryFile& binary,
                            const std::stop_token& stop,
                            const std::function<void(uint64_t, uint64_t)>& progress,
                            std::string& error) {
    if (stop.stop_requested()) return false;
    bool loaded = false;
    if (spec.mapped) {
        if (!sameLiveSession(spec.debugger, spec.livePid, spec.liveGeneration)) {
            error = "the live image no longer belongs to the captured debugger session";
            return false;
        }
        if (!spec.mappedSize || spec.mappedSize > (uint64_t)std::numeric_limits<size_t>::max()) {
            error = "the mapped image size is invalid";
            return false;
        }
        std::vector<uint8_t> bytes((size_t)spec.mappedSize);
        size_t copied = 0;
        constexpr size_t kReadChunk = 1u << 20;
        while (copied < bytes.size() && !stop.stop_requested()) {
            if (!sameLiveSession(spec.debugger, spec.livePid, spec.liveGeneration)) {
                error = "the debugger target changed while the image was being read";
                return false;
            }
            const size_t want = std::min(kReadChunk, bytes.size() - copied);
            const size_t got = spec.debugger->readMemoryMasked(
                spec.base + copied, bytes.data() + copied, want);
            if (!sameLiveSession(spec.debugger, spec.livePid, spec.liveGeneration)) {
                error = "the debugger target changed while the image was being read";
                return false;
            }
            if (!got) break;
            copied += got;
            progress(copied, bytes.size());
            if (got < want) break;
        }
        if (stop.stop_requested()) return false;
        if (!copied) {
            error = "could not read the captured live image";
            return false;
        }
        bytes.resize(copied);
        loaded = binary.loadFromMemory(std::move(bytes), spec.base, spec.label);
    } else {
        BinaryLoadOptions options;
        options.cancelled = [&stop] { return stop.stop_requested(); };
        loaded = spec.raw ? binary.loadRaw(spec.path, spec.base, options)
                          : binary.load(spec.path, options);
    }
    if (!loaded) {
        error = binary.loadErrorText().empty()
              ? "could not reload the source image"
              : binary.loadErrorText();
        return false;
    }
    if (binary.contentHash() != spec.owner.contentHash) {
        error = spec.mapped ? "the live image changed; reload it before scanning"
                            : "the source file changed while the scan was queued";
        return false;
    }
    if (spec.raw) {
        if (spec.rawEntryExplicit && !binary.setRawEntryPointVA(spec.rawEntry)) {
            error = "could not restore the Raw entry point";
            return false;
        }
        if (!binary.setAnalysisLandmarks(spec.landmarks)) {
            error = "could not restore the Raw analysis landmarks";
            return false;
        }
    }
    for (const PjPatch& patch : spec.patches) {
        if (stop.stop_requested()) return false;
        if (!patch.bytes.empty() &&
            binary.writeImage(patch.address, patch.bytes.data(), patch.bytes.size()) !=
                patch.bytes.size()) {
            error = "a saved patch no longer maps to the source image";
            return false;
        }
    }
    return !stop.stop_requested();
}

// Scan in bounded windows so cancellation is checked at least once per 4 MiB.
// The extra pattern tail lets matches cross a window boundary; only starts in
// the primary window are accepted, preventing duplicates in the next window.
template <typename Hit>
static bool scanMaskedChunks(const std::vector<uint8_t>& bytes,
                             const SigPattern& pattern, size_t hitLimit,
                             const std::stop_token& stop,
                             const std::function<void(uint64_t, uint64_t)>& progress,
                             Hit&& onHit, bool& hitLimitReached,
                             const std::function<bool(size_t)>& admit = {}) {
    hitLimitReached = false;
    if (pattern.empty() || bytes.size() < pattern.size()) {
        progress(bytes.size(), bytes.size());
        return !stop.stop_requested();
    }
    size_t accepted = 0;
    for (size_t base = 0; base < bytes.size();) {
        if (stop.stop_requested()) return false;
        const size_t primary = std::min(kScanChunk, bytes.size() - base);
        const size_t tail = std::min(pattern.size() - 1, bytes.size() - base - primary);
        const size_t window = primary + tail;
        const size_t room = hitLimit ? hitLimit - std::min(hitLimit, accepted) : 0;
        const size_t localLimit = hitLimit ? room : 0;
        const auto hits = FindAllMaskedAccepted(
            bytes.data() + base, window, pattern, localLimit,
            [&](size_t local) {
                return local < primary && (!admit || admit(base + local));
            });
        for (const size_t local : hits) {
            if (local >= primary) break;
            if (!onHit(base + local)) return false;
            ++accepted;
            if (hitLimit && accepted >= hitLimit) {
                hitLimitReached = true;
                return true;
            }
        }
        base += primary;
        progress(base, bytes.size());
    }
    return !stop.stop_requested();
}

static uint64_t saturatingMultiply(uint64_t left, uint64_t right) {
    if (!left || !right) return 0;
    if (left > std::numeric_limits<uint64_t>::max() / right)
        return std::numeric_limits<uint64_t>::max();
    return left * right;
}

} // namespace

static DocumentResultIdentity currentStaticIdentity(const AppContext& ctx) {
    const BinaryFile& binary = ctx.staticBinary();
    return MakeDocumentResultIdentity(
        ctx.staticDocumentId(), ctx.staticImageGeneration(), binary.loaded(),
        binary.loaded() ? binary.contentHash() : 0,
        binary.loaded() ? binary.imageRevision() : 0);
}

void SigScannerTab::cancelWorker(const char* status) {
    requestSerial_.fetch_add(1, std::memory_order_acq_rel);
    if (worker_.joinable()) worker_.request_stop();
    workerPending_ = false;
    activeWorkerKind_ = WorkerKind::None;
    activeWorkerOwner_ = {};
    activeLivePid_ = 0;
    activeLiveGeneration_ = 0;
    activeFunctionsDecoder_ = {};
    workerStatus_ = status ? status : "Scan cancelled.";
}

void SigScannerTab::scan(AppContext& ctx) {
    SigPattern pattern;
    const std::string patternText(patternInput_);
    if (!parsePattern(patternText, pattern)) {
        workerStatus_ = "Malformed signature pattern.";
        ui::Toast(ui::ToastKind::Error, workerStatus_);
        return;
    }

    requestedSub_ = 0; // A new scan or Binary View handoff must reveal Results.
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    {
        std::lock_guard lock(readyMutex_);
        ready_.reset();
    }
    results_.clear();
    staticResultsOwner_ = {};
    resultsLive_ = live_;
    truncated_ = false;
    progress_ = 0.0f;
    workerDone_.store(0, std::memory_order_release);
    workerTotal_.store(1, std::memory_order_release);
    workerStatus_.clear();
    const uint64_t request = requestSerial_.fetch_add(1, std::memory_order_acq_rel) + 1;

    if (live_) {
        const DbgSnapshot snapshot = ctx.debug.snapshot();
        if (!snapshot.attached()) {
            workerStatus_ = "No live debugger target is attached.";
            return;
        }
        Debugger* debugger = &ctx.debug;
        const uint32_t pid = snapshot.pid;
        const uint64_t generation = snapshot.sessionGeneration;
        workerPending_ = true;
        activeWorkerKind_ = WorkerKind::LiveScan;
        activeWorkerOwner_ = {};
        activeLivePid_ = pid;
        activeLiveGeneration_ = generation;
        activeFunctionsDecoder_ = {};
        resultsLivePid_ = pid;
        resultsLiveGeneration_ = generation;
        workerTotal_.store(1, std::memory_order_release);
        try {
            worker_ = std::jthread(
                [this, request, pattern = std::move(pattern), patternText,
                 debugger, pid, generation](std::stop_token stop) mutable {
                    WorkerResult result;
                    result.request = request;
                    result.kind = WorkerKind::LiveScan;
                    result.livePid = pid;
                    result.liveGeneration = generation;
                    try {
                        if (!sameLiveSession(debugger, pid, generation)) {
                            result.error = "the debugger target changed before the live scan started";
                        } else {
                            std::vector<MemRegion> regions = debugger->regions();
                            if (!sameLiveSession(debugger, pid, generation)) {
                                result.error = "the debugger target changed while memory regions were collected";
                            }
                            ProcessManager manager;
                            const std::vector<ModuleInfo> modules = manager.modules(pid);
                            auto moduleAt = [&](uint64_t address) {
                                for (const ModuleInfo& module : modules) {
                                    if (address >= module.base && address - module.base < module.size)
                                        return module.name.empty() ? module.path : module.name;
                                }
                                return std::string("live");
                            };
                            auto protection = [](const MemRegion& region) {
                                std::string text = " [";
                                text += region.read ? 'r' : '-';
                                text += region.write ? 'w' : '-';
                                text += region.exec ? 'x' : '-';
                                text += ']';
                                return text;
                            };

                            constexpr size_t kChunk = 1u << 20;
                            constexpr uint64_t kByteBudget = 512ull << 20;
                            uint64_t total = 0;
                            for (const MemRegion& region : regions) {
                                if (!region.read || region.state != 0x1000 ||
                                    region.size < pattern.size()) continue;
                                const uint64_t room = kByteBudget - total;
                                total += std::min(region.size, room);
                                if (total == kByteBudget) break;
                            }
                            workerTotal_.store(std::max<uint64_t>(1, total),
                                               std::memory_order_release);
                            const size_t overlap = pattern.size() - 1;
                            uint64_t scanned = 0;
                            std::vector<uint8_t> buffer;
                            for (const MemRegion& region : regions) {
                                if (stop.stop_requested()) return;
                                if (!region.read || region.state != 0x1000 ||
                                    region.size < pattern.size()) continue;
                                if (scanned >= kByteBudget) {
                                    result.truncated = true;
                                    break;
                                }
                                for (uint64_t offset = 0; offset < region.size;) {
                                    if (stop.stop_requested()) return;
                                    if (!sameLiveSession(debugger, pid, generation)) {
                                        result.error = "the debugger target changed during the live scan";
                                        break;
                                    }
                                    if (scanned >= kByteBudget) {
                                        result.truncated = true;
                                        break;
                                    }
                                    size_t want = (size_t)std::min<uint64_t>(
                                        kChunk, std::min<uint64_t>(region.size - offset,
                                                                  kByteBudget - scanned));
                                    buffer.resize(want);
                                    const size_t got = debugger->readMemoryMasked(
                                        region.base + offset, buffer.data(), want);
                                    if (!sameLiveSession(debugger, pid, generation)) {
                                        result.error = "the debugger target changed during the live scan";
                                        break;
                                    }
                                    scanned += got;
                                    workerDone_.store(scanned, std::memory_order_release);
                                    if (got >= pattern.size()) {
                                        const size_t room = kResultCap + 1 - result.results.size();
                                        for (size_t local : FindAllMasked(
                                                 buffer.data(), got, pattern, room)) {
                                            const uint64_t address = region.base + offset + local;
                                            result.results.push_back({
                                                address, patternText,
                                                moduleAt(address) + protection(region), true });
                                            if (result.results.size() > kResultCap) {
                                                result.truncated = true;
                                                break;
                                            }
                                        }
                                    }
                                    if (!result.error.empty() ||
                                        result.results.size() > kResultCap) break;
                                    if (got < want) break;
                                    offset += want > overlap ? want - overlap : want;
                                }
                                if (!result.error.empty() ||
                                    result.results.size() > kResultCap) break;
                            }
                            result.scannedBytes = scanned;
                            if (result.results.size() > kResultCap)
                                result.results.resize(kResultCap);
                        }
                    } catch (const std::exception& exception) {
                        result.error = std::string("live signature scan failed: ") + exception.what();
                    } catch (...) {
                        result.error = "live signature scan failed: unknown exception";
                    }
                    if (stop.stop_requested() ||
                        requestSerial_.load(std::memory_order_acquire) != request) return;
                    try {
                        std::lock_guard lock(readyMutex_);
                        ready_ = std::move(result);
                    } catch (...) {
                        // A worker entry point must never let result publication
                        // escape into std::terminate during low-memory teardown.
                    }
                });
        } catch (const std::exception& exception) {
            workerPending_ = false;
            activeWorkerKind_ = WorkerKind::None;
            workerStatus_ = std::string("could not start the signature worker: ") + exception.what();
        }
        return;
    }

    if (!ctx.staticBinary().loaded()) {
        workerStatus_ = "No static image is loaded.";
        return;
    }
    const DocumentResultIdentity owner = currentStaticIdentity(ctx);
    WorkerImageSpec spec;
    std::string captureError;
    if (!captureWorkerImage(ctx, owner, spec, captureError)) {
        workerPending_ = false;
        activeWorkerKind_ = WorkerKind::None;
        workerStatus_ = "Static signature scan refused: " + captureError + ".";
        return;
    }
    workerPending_ = true;
    activeWorkerKind_ = WorkerKind::StaticScan;
    activeWorkerOwner_ = owner;
    activeLivePid_ = 0;
    activeLiveGeneration_ = 0;
    activeFunctionsDecoder_ = {};
    resultsLivePid_ = 0;
    resultsLiveGeneration_ = 0;
    workerTotal_.store(std::max<uint64_t>(1, spec.mappedSize), std::memory_order_release);
    try {
        worker_ = std::jthread(
            [this, request, pattern = std::move(pattern), patternText,
             spec = std::move(spec)](std::stop_token stop) mutable {
                WorkerResult result;
                result.request = request;
                result.kind = WorkerKind::StaticScan;
                result.owner = spec.owner;
                try {
                    BinaryFile binary;
                    auto progress = [this](uint64_t done, uint64_t total) {
                        workerTotal_.store(std::max<uint64_t>(1, total), std::memory_order_release);
                        workerDone_.store(done, std::memory_order_release);
                    };
                    if (loadWorkerImage(spec, binary, stop, progress, result.error)) {
                        workerDone_.store(0, std::memory_order_release);
                        workerTotal_.store(std::max<uint64_t>(1, binary.bytes().size()),
                                           std::memory_order_release);
                        bool limitReached = false;
                        scanMaskedChunks(binary.bytes(), pattern, kResultCap + 1, stop,
                            progress,
                            [&](size_t offset) {
                                uint64_t address = 0;
                                if (binary.offsetToVA(offset, address)) {
                                    result.results.push_back({ address, patternText,
                                                               binary.path(), false });
                                }
                                return !stop.stop_requested() &&
                                       result.results.size() <= kResultCap;
                            }, limitReached,
                            [&](size_t offset) {
                                uint64_t address = 0;
                                return binary.offsetToVA(offset, address);
                            });
                        if (stop.stop_requested()) return;
                        result.truncated = result.results.size() > kResultCap || limitReached;
                        if (result.results.size() > kResultCap)
                            result.results.resize(kResultCap);
                        result.scannedBytes = workerDone_.load(std::memory_order_acquire);
                    }
                } catch (const std::exception& exception) {
                    result.error = std::string("signature scan failed: ") + exception.what();
                } catch (...) {
                    result.error = "signature scan failed: unknown exception";
                }
                if (stop.stop_requested() ||
                    requestSerial_.load(std::memory_order_acquire) != request) return;
                try {
                    std::lock_guard lock(readyMutex_);
                    ready_ = std::move(result);
                } catch (...) {
                }
            });
    } catch (const std::exception& exception) {
        workerPending_ = false;
        activeWorkerKind_ = WorkerKind::None;
        workerStatus_ = std::string("could not start the signature worker: ") + exception.what();
    }
}

void SigScannerTab::refreshHealth(AppContext& ctx) {
    if (!ctx.staticBinary().loaded()) return;
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    {
        std::lock_guard lock(readyMutex_);
        ready_.reset();
    }
    const DocumentResultIdentity owner = currentStaticIdentity(ctx);
    WorkerImageSpec spec;
    std::string captureError;
    if (!captureWorkerImage(ctx, owner, spec, captureError)) {
        workerPending_ = false;
        activeWorkerKind_ = WorkerKind::None;
        workerStatus_ = "Signature health scan refused: " + captureError + ".";
        return;
    }
    std::vector<std::string> patterns;
    patterns.reserve(sigs_.size());
    for (const Sig& signature : sigs_) patterns.push_back(signature.pattern);
    healthOwner_ = {};
    for (Sig& signature : sigs_) {
        signature.count = -1;
        signature.countCapped = false;
        signature.health = "pending";
    }
    workerDone_.store(0, std::memory_order_release);
    workerTotal_.store(std::max<uint64_t>(1,
        saturatingMultiply(spec.mappedSize, patterns.size())), std::memory_order_release);
    workerStatus_.clear();
    workerPending_ = true;
    activeWorkerKind_ = WorkerKind::Health;
    activeWorkerOwner_ = owner;
    activeLivePid_ = 0;
    activeLiveGeneration_ = 0;
    activeFunctionsDecoder_ = {};
    const uint64_t request = requestSerial_.fetch_add(1, std::memory_order_acq_rel) + 1;
    try {
        worker_ = std::jthread(
            [this, request, spec = std::move(spec),
             patterns = std::move(patterns)](std::stop_token stop) mutable {
                WorkerResult result;
                result.request = request;
                result.kind = WorkerKind::Health;
                result.owner = spec.owner;
                try {
                    BinaryFile binary;
                    auto loadProgress = [this](uint64_t done, uint64_t total) {
                        workerTotal_.store(std::max<uint64_t>(1, total), std::memory_order_release);
                        workerDone_.store(done, std::memory_order_release);
                    };
                    if (loadWorkerImage(spec, binary, stop, loadProgress, result.error)) {
                        const uint64_t bytesPerPattern = binary.bytes().size();
                        workerDone_.store(0, std::memory_order_release);
                        workerTotal_.store(std::max<uint64_t>(1,
                            saturatingMultiply(bytesPerPattern, patterns.size())),
                            std::memory_order_release);
                        result.health.reserve(patterns.size());
                        uint64_t completedBase = 0;
                        for (const std::string& text : patterns) {
                            if (stop.stop_requested()) return;
                            SigPattern pattern;
                            HealthResult health;
                            if (!parsePattern(text, pattern)) {
                                health.count = -1;
                                health.health = "malformed";
                            } else {
                                size_t count = 0;
                                bool limitReached = false;
                                scanMaskedChunks(binary.bytes(), pattern,
                                    kHealthCountCap + 1, stop,
                                    [this, completedBase](uint64_t done, uint64_t) {
                                        workerDone_.store(completedBase + done,
                                                          std::memory_order_release);
                                    },
                                    [&](size_t) {
                                        ++count;
                                        return !stop.stop_requested();
                                    }, limitReached);
                                if (stop.stop_requested()) return;
                                health.capped = count > kHealthCountCap || limitReached;
                                health.count = (int)std::min(count, kHealthCountCap);
                                health.health = healthFromCount(health.count);
                            }
                            result.health.push_back(std::move(health));
                            completedBase = std::min<uint64_t>(
                                std::numeric_limits<uint64_t>::max(),
                                completedBase + bytesPerPattern);
                            workerDone_.store(completedBase, std::memory_order_release);
                        }
                    }
                } catch (const std::exception& exception) {
                    result.error = std::string("signature health scan failed: ") + exception.what();
                } catch (...) {
                    result.error = "signature health scan failed: unknown exception";
                }
                if (stop.stop_requested() ||
                    requestSerial_.load(std::memory_order_acquire) != request) return;
                try {
                    std::lock_guard lock(readyMutex_);
                    ready_ = std::move(result);
                } catch (...) {
                }
            });
    } catch (const std::exception& exception) {
        workerPending_ = false;
        activeWorkerKind_ = WorkerKind::None;
        workerStatus_ = std::string("could not start the health worker: ") + exception.what();
    }
}

void SigScannerTab::analyzeFunctions(AppContext& ctx) {
    if (!ctx.staticBinary().loaded() || !ctx.staticDisassembler()) return;
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    {
        std::lock_guard lock(readyMutex_);
        ready_.reset();
    }
    const DocumentResultIdentity owner = currentStaticIdentity(ctx);
    WorkerImageSpec spec;
    std::string captureError;
    if (!captureWorkerImage(ctx, owner, spec, captureError)) {
        workerPending_ = false;
        activeWorkerKind_ = WorkerKind::None;
        workerStatus_ = "Function analysis refused: " + captureError + ".";
        return;
    }
    functions_.clear();
    functionsOwner_ = {};
    analyzeSummary_.clear();
    workerDone_.store(0, std::memory_order_release);
    workerTotal_.store(3, std::memory_order_release);
    workerStatus_.clear();
    workerPending_ = true;
    activeWorkerKind_ = WorkerKind::Functions;
    activeWorkerOwner_ = owner;
    activeLivePid_ = 0;
    activeLiveGeneration_ = 0;
    activeFunctionsDecoder_ = spec.decoder;
    const uint64_t request = requestSerial_.fetch_add(1, std::memory_order_acq_rel) + 1;
    try {
        worker_ = std::jthread(
            [this, request, spec = std::move(spec)](std::stop_token stop) mutable {
                WorkerResult result;
                result.request = request;
                result.kind = WorkerKind::Functions;
                result.owner = spec.owner;
                result.decoder = spec.decoder;
                try {
                    BinaryFile binary;
                    auto loadProgress = [](uint64_t, uint64_t) {};
                    if (loadWorkerImage(spec, binary, stop, loadProgress, result.error)) {
                        workerDone_.store(1, std::memory_order_release);
                        std::unique_ptr<IDisassembler> disassembler = MakeDisassembler(spec.decoder);
                        if (!disassembler) {
                            result.error = "the function-analysis decoder could not be created";
                        } else if (!disassembler->ready()) {
                            result.error = "the function-analysis decoder is unavailable";
                            if (!disassembler->errorMessage().empty())
                                result.error += ": " + std::string(disassembler->errorMessage());
                        } else {
                            workerDone_.store(2, std::memory_order_release);
                            FunctionAnalyzer analyzer;
                            const auto cancelled = [&] { return stop.stop_requested(); };
                            auto discovered = analyzer.analyze(
                                binary, *disassembler, spec.decoder.arch,
                                50000, 4000, cancelled);
                            if (stop.stop_requested()) return;
                            result.functions.reserve(discovered.size());
                            for (const DiscoveredFunction& function : discovered) {
                                result.functions.push_back(
                                    { function.address, function.name, function.size });
                            }
                            result.summary = analyzer.lastSummary();
                            result.truncated = result.summary.find("truncated") != std::string::npos;
                            workerDone_.store(3, std::memory_order_release);
                        }
                    }
                } catch (const std::exception& exception) {
                    result.error = std::string("function analysis failed: ") + exception.what();
                } catch (...) {
                    result.error = "function analysis failed: unknown exception";
                }
                if (stop.stop_requested() ||
                    requestSerial_.load(std::memory_order_acquire) != request) return;
                try {
                    std::lock_guard lock(readyMutex_);
                    ready_ = std::move(result);
                } catch (...) {
                }
            });
    } catch (const std::exception& exception) {
        workerPending_ = false;
        activeWorkerKind_ = WorkerKind::None;
        workerStatus_ = std::string("could not start the function worker: ") + exception.what();
    }
}

void SigScannerTab::pollWorker(AppContext& ctx,
                               const DocumentResultIdentity& currentIdentity,
                               const DbgSnapshot& snapshot) {
    if (workerPending_) {
        const bool staleStatic = activeWorkerOwner_ &&
            !SameDocumentResultImage(activeWorkerOwner_, currentIdentity);
        const bool staleLive = activeWorkerKind_ == WorkerKind::LiveScan &&
            (!snapshot.attached() || snapshot.pid != activeLivePid_ ||
             snapshot.sessionGeneration != activeLiveGeneration_);
        const bool staleDecoder = activeWorkerKind_ == WorkerKind::Functions &&
            activeFunctionsDecoder_ != ctx.staticDecoderConfig();
        if (staleStatic || staleLive || staleDecoder) {
            cancelWorker(staleLive ? "Live target changed; scan cancelled."
                                   : staleDecoder ? "Decoder changed; function analysis cancelled."
                                                  : "Document changed; scan cancelled.");
        }
    }

    std::optional<WorkerResult> ready;
    {
        std::lock_guard lock(readyMutex_);
        if (ready_) ready.swap(ready_);
    }
    if (!ready) return;
    if (ready->request != requestSerial_.load(std::memory_order_acquire)) return;
    if (ready->kind == WorkerKind::LiveScan) {
        if (!snapshot.attached() || snapshot.pid != ready->livePid ||
            snapshot.sessionGeneration != ready->liveGeneration) return;
    } else if (!SameDocumentResultImage(ready->owner, currentIdentity)) {
        return;
    } else if (ready->kind == WorkerKind::Functions &&
               ready->decoder != ctx.staticDecoderConfig()) {
        return;
    }

    workerPending_ = false;
    activeWorkerKind_ = WorkerKind::None;
    activeWorkerOwner_ = {};
    activeLivePid_ = 0;
    activeLiveGeneration_ = 0;
    activeFunctionsDecoder_ = {};
    progress_ = 1.0f;
    if (!ready->error.empty()) {
        workerStatus_ = std::move(ready->error);
        ui::Toast(ui::ToastKind::Error, workerStatus_);
        return;
    }
    workerStatus_.clear();
    switch (ready->kind) {
        case WorkerKind::StaticScan:
        case WorkerKind::LiveScan: {
            results_ = std::move(ready->results);
            resultsLive_ = ready->kind == WorkerKind::LiveScan;
            resultsLivePid_ = resultsLive_ ? ready->livePid : 0;
            resultsLiveGeneration_ = resultsLive_ ? ready->liveGeneration : 0;
            staticResultsOwner_ = resultsLive_ ? DocumentResultIdentity{} : ready->owner;
            truncated_ = ready->truncated;
            char message[96];
            std::snprintf(message, sizeof(message), "%s scan: %d match(es)%s.",
                          resultsLive_ ? "Live" : "File", (int)results_.size(),
                          truncated_ ? " (capped or byte-budget limited)" : "");
            ui::Toast(truncated_ ? ui::ToastKind::Warn : ui::ToastKind::Info, message);
            break;
        }
        case WorkerKind::Health:
            if (ready->health.size() != sigs_.size()) {
                workerStatus_ = "Signature list changed while health results were pending.";
                break;
            }
            for (size_t i = 0; i < sigs_.size(); ++i) {
                sigs_[i].count = ready->health[i].count;
                sigs_[i].health = std::move(ready->health[i].health);
                sigs_[i].countCapped = ready->health[i].capped;
            }
            healthOwner_ = ready->owner;
            ui::Toast(ui::ToastKind::Info, "Signature health recomputed.");
            break;
        case WorkerKind::Functions:
            functions_ = std::move(ready->functions);
            analyzeSummary_ = std::move(ready->summary);
            functionsOwner_ = ready->owner;
            functionsEngine_ = ctx.staticEngine();
            functionsArch_ = ctx.staticArch();
            if (ready->truncated && analyzeSummary_.find("truncated") == std::string::npos)
                analyzeSummary_ += "; bounded result truncated";
            ui::Toast(ready->truncated ? ui::ToastKind::Warn : ui::ToastKind::Info,
                      "Function analysis completed.");
            break;
        case WorkerKind::None:
            break;
    }
}

void SigScannerTab::render(AppContext& ctx) {
    const DocumentResultIdentity currentIdentity = currentStaticIdentity(ctx);
    const DbgSnapshot snap = ctx.debug.snapshot();
    pollWorker(ctx, currentIdentity, snap);
    if (workerPending_) {
        ctx.wantContinuousRedraw = true;
        const uint64_t total = workerTotal_.load(std::memory_order_acquire);
        const uint64_t done = workerDone_.load(std::memory_order_acquire);
        progress_ = total ? (float)std::min<double>(1.0, (double)done / (double)total) : 0.0f;
    }
    if (staticResultsOwner_ &&
        !SameDocumentResultImage(staticResultsOwner_, currentIdentity)) {
        results_.clear();
        staticResultsOwner_ = {};
        resultsLive_ = false;
        resultsLivePid_ = 0;
        resultsLiveGeneration_ = 0;
        truncated_ = false;
        progress_ = 0.0f;
    }
    if (resultsLive_ &&
        (!snap.attached() || snap.pid != resultsLivePid_ ||
         snap.sessionGeneration != resultsLiveGeneration_)) {
        results_.clear();
        resultsLive_ = false;
        resultsLivePid_ = 0;
        resultsLiveGeneration_ = 0;
        truncated_ = false;
        progress_ = 0.0f;
    }
    if (functionsOwner_ &&
        (!SameDocumentResultImage(functionsOwner_, currentIdentity) ||
         functionsEngine_ != ctx.staticEngine() ||
         functionsArch_ != ctx.staticArch())) {
        functions_.clear();
        functionsOwner_ = {};
        analyzeSummary_.clear();
    }
    if (healthOwner_ && !SameDocumentResultImage(healthOwner_, currentIdentity)) {
        for (auto& signature : sigs_) {
            signature.count = -1;
            signature.health = "n/a";
            signature.countCapped = false;
        }
        healthOwner_ = {};
    }

    // A signature created from the Binary View's right-click menu arrives here:
    // load it into the pattern box, jump to Results, and scan immediately.
    if (!ctx.pendingSignature.empty()) {
        // Scan in the mode the signature was built in: a signature captured from the live
        // listing carries runtime bytes that won't match the on-disk image, so it must be
        // scanned against process memory, not the file.
        const bool pendingLive = ctx.pendingSignatureLive;
        if (pendingLive && (!snap.attached() || !DebugTargetIdentityMatches(
                {snap.pid, snap.sessionGeneration}, ctx.pendingSignatureTarget))) {
            ctx.clearPendingSignature();
            ui::Toast(ui::ToastKind::Warn,
                      "Discarded a signature from an older debugger session.");
        } else if (!pendingLive &&
            !SameDocumentResultImage(ctx.pendingSignatureOwner,
                                     currentIdentity)) {
            ctx.clearPendingSignature();
            ui::Toast(ui::ToastKind::Warn,
                      "Discarded a signature from an older static document image.");
        } else {
            std::string signature = std::move(ctx.pendingSignature);
            ctx.clearPendingSignature();
            live_ = pendingLive;
            patternClipped_ = signature.size() >= sizeof(patternInput_);   // defensive: buffer holds the worst case
            std::snprintf(patternInput_, sizeof(patternInput_), "%s", signature.c_str());
            scan(ctx);   // populate Results (the default sub-tab) right away
        }
    }
    ImGui::TextUnformatted("Signature Scanner");
    ui::SameLineIfFits(300.0f * theme::UiScale());
    ImGui::TextDisabled("Byte patterns, match health and functions");

    if (!ctx.staticBinary().loaded() && !snap.attached()) {
        if (ui::EmptyState(DS_ICON_SEARCH, "Nothing to scan",
                           "Open a binary to scan for byte patterns, or attach a process for live scans.",
                           "Open Binary..."))
            ctx.openBinaryDialog();
        return;
    }

    // ---- Toolbar: pattern + scan + live | name + save | progress / warnings ----
    const float s = theme::UiScale();
    const bool canScan = live_ ? snap.attached() : ctx.staticBinary().loaded();
    ImGui::SetNextItemWidth(std::max(1.0f, ImGui::GetContentRegionAvail().x - 190.0f * s));
    const bool enterScan = ImGui::InputTextWithHint("##pattern", "AA BB ?? DD pattern...", patternInput_,
        sizeof(patternInput_), ImGuiInputTextFlags_EnterReturnsTrue);
    if (ImGui::IsItemEdited()) patternClipped_ = false;
    if (enterScan && canScan && !workerPending_) scan(ctx);
    ui::SameLineIfFits(90.0f * s);
    ImGui::BeginDisabled(!canScan || workerPending_);
    if (ui::ToolbarIconButton(DS_ICON_SEARCH, "Scan",
                              live_ ? "Scan the attached process's memory" : "Scan the loaded file"))
        scan(ctx);
    ImGui::EndDisabled();
    ui::SameLineIfFits(70.0f * s);
    if (ImGui::Checkbox("Live", &live_)) {
        if (workerPending_) cancelWorker("Scan mode changed; scan cancelled.");
        results_.clear();
        staticResultsOwner_ = {};
        resultsLive_ = live_;
        resultsLivePid_ = 0;
        resultsLiveGeneration_ = 0;
        truncated_ = false;
        progress_ = 0.0f;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Scan the attached process's committed memory (works paused or running) instead of the file on disk.");
    if (!canScan) ImGui::TextDisabled(live_ ? "Attach a process in Communications to scan live memory."
                                                        : "Open a binary to scan file bytes.");
    ImGui::SetNextItemWidth(std::min(190.0f * s, ImGui::GetContentRegionAvail().x));
    ImGui::InputTextWithHint("##signame", "signature name", sigName_, sizeof(sigName_));
    ui::SameLineIfFits(105.0f * s);
    SigPattern savePattern;
    const bool validPattern = !patternClipped_ && parsePattern(patternInput_, savePattern);
    ImGui::BeginDisabled(workerPending_ || !validPattern);
    if (ui::ToolbarIconButton(DS_ICON_SAVE, "Save Sig", validPattern
        ? "Keep this pattern in Sig Health for this session"
        : "Enter a valid byte pattern before saving")) {
        if (healthOwner_ &&
            !SameDocumentResultImage(healthOwner_, currentIdentity)) {
            for (auto& signature : sigs_) {
                signature.count = -1;
                signature.health = "n/a";
                signature.countCapped = false;
            }
            healthOwner_ = {};
        }
        Sig s2{ sigName_, patternInput_, ctx.staticBinary().loaded() ? "pending" : "n/a", -1 };
        sigs_.push_back(std::move(s2));
        if (ctx.staticBinary().loaded()) refreshHealth(ctx);
        requestedSub_ = 2;
        ui::Toast(ui::ToastKind::Success, "Signature added to Sig Health for this session.");
    }
    ImGui::EndDisabled();
    if (workerPending_) {
        ui::SameLineIfFits(140.0f * s);
        ImGui::ProgressBar(progress_, ImVec2(140.0f * s, 0));
        ui::SameLineIfFits(80.0f * s);
        if (ImGui::SmallButton("Cancel##sigworker")) cancelWorker();
    }
    if (patternClipped_) {
        ui::SameLineIfFits(170.0f * s);
        ui::Badge("signature truncated", theme::col::warn());
    }
    if (!workerStatus_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::col::warn());
        ImGui::TextWrapped("%s", workerStatus_.c_str());
        ImGui::PopStyleColor();
    } else if (workerPending_) {
        ui::SameLineIfFits(240.0f * s);
        const char* activity = activeWorkerKind_ == WorkerKind::Health ? "scoring signatures..."
                             : activeWorkerKind_ == WorkerKind::Functions ? "analyzing functions..."
                             : activeWorkerKind_ == WorkerKind::LiveScan ? "scanning live memory..."
                             : "scanning file...";
        ImGui::TextDisabled("%s", activity);
    }

    if (ImGui::BeginTabBar("sigsub")) {
        const int selectSub = std::exchange(requestedSub_, -1);
        if (ImGui::BeginTabItem("Results", nullptr, selectSub == 0 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::Text("%d match(es)", (int)results_.size());
            ui::SameLineIfFits(180.0f * s);
            ImGui::TextDisabled(resultsLive_ ? "(live process memory)" : "(file on disk)");
            if (truncated_) {
                ui::SameLineIfFits(280.0f * s);
                ImGui::TextColored(theme::col::warn(), "(capped at %d \xE2\x80\x94 refine the pattern)",
                                   (int)results_.size());
            }
            if (ImGui::BeginTable("res", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_Resizable,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f * s);
                ImGui::TableSetupColumn("Signature");
                ImGui::TableSetupColumn("Module");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                ImGuiListClipper clip;   // up to 4096 rows -> only build widgets for the visible ones
                clip.Begin((int)results_.size());
                while (clip.Step())
                    for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        auto& r = results_[(size_t)i];
                        ImGui::TableNextRow();
                        ImGui::PushID((void*)(uintptr_t)r.address);
                        ImGui::TableSetColumnIndex(0);
                        char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)r.address);
                        // Live hits are runtime VAs -> open the live view; file hits are file VAs.
                        if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) {
                            if (r.live)
                                ctx.gotoAddressLive(
                                    r.address,
                                    { resultsLivePid_, resultsLiveGeneration_ });
                            else
                                ctx.gotoAddress(r.address);
                        }
                        ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(r.sig.c_str());
                        ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", r.module.c_str());
                        ImGui::PopID();
                    }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Current Scan", nullptr, selectSub == 1 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextWrapped("Pattern: %s", patternInput_);
            if (live_) ImGui::Text("Live process: %lu", static_cast<unsigned long>(snap.pid));
            else ImGui::Text("Bytes loaded: %zu", ctx.staticBinary().bytes().size());
            ImGui::ProgressBar(progress_, ImVec2(-1, 0));
            if (workerPending_) {
                const uint64_t done = workerDone_.load(std::memory_order_acquire);
                const uint64_t total = workerTotal_.load(std::memory_order_acquire);
                ImGui::TextDisabled("Background worker: %llu / %llu work units",
                                    (unsigned long long)done,
                                    (unsigned long long)total);
                if (ImGui::Button("Cancel current work")) cancelWorker();
            } else if (!workerStatus_.empty()) {
                ImGui::TextColored(theme::col::bad(), "%s", workerStatus_.c_str());
            } else {
                ImGui::TextDisabled("No signature work is currently queued.");
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Sig Health", nullptr, selectSub == 2 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::BeginDisabled(!ctx.staticBinary().loaded() || workerPending_);
            if (ImGui::Button("Recompute health")) refreshHealth(ctx);
            ImGui::EndDisabled();
            ui::SameLineIfFits(300.0f * s);
            ImGui::TextDisabled(ctx.staticBinary().loaded() ? "FILE match counts: none / unique / multiple"
                                                     : "Load a binary to score signatures.");
            ImGui::PushTextWrapPos();
            ImGui::TextDisabled("Session signatures: select to edit, double-click to scan in the selected FILE / Live mode.");
            ImGui::PopTextWrapPos();
            if (ImGui::BeginTable("health", 4,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_Resizable,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 140.0f * s);
                ImGui::TableSetupColumn("Pattern");
                ImGui::TableSetupColumn("Matches", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
                ImGui::TableSetupColumn("Health", ImGuiTableColumnFlags_WidthFixed, 90.0f * s);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                ImGuiListClipper clip;
                clip.Begin(static_cast<int>(sigs_.size()));
                while (clip.Step()) for (int index = clip.DisplayStart; index < clip.DisplayEnd; ++index) {
                    auto& s = sigs_[index];
                    ImGui::PushID(index);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(s.name.empty() ? "(unnamed)" : s.name.c_str(), false,
                            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        std::snprintf(patternInput_, sizeof(patternInput_), "%s", s.pattern.c_str());
                        std::snprintf(sigName_, sizeof(sigName_), "%s", s.name.c_str());
                        patternClipped_ = s.pattern.size() >= sizeof(patternInput_);
                        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && canScan && !workerPending_)
                            scan(ctx);
                    }
                    ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", s.pattern.c_str());
                    ImGui::TableSetColumnIndex(2);
                    if (s.count < 0) ImGui::TextDisabled("-");
                    else if (s.countCapped) ImGui::Text("%d+", s.count);
                    else                     ImGui::Text("%d", s.count);
                    ImGui::TableSetColumnIndex(3);
                    ImVec4 col = s.health == "unique"   ? theme::col::good()
                               : s.health == "multiple" ? theme::col::warn()
                               : s.health == "none" || s.health == "malformed" ? theme::col::bad()
                               : theme::col::muted();
                    ImGui::TextColored(col, "%s", s.health.c_str());
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("All Functions", nullptr, selectSub == 3 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::BeginDisabled(!ctx.staticBinary().loaded() ||
                                 !ctx.staticDisassembler() || workerPending_);
            if (ImGui::Button("Analyze Functions")) {
                analyzeFunctions(ctx);
            }
            ImGui::EndDisabled();
            ui::SameLineIfFits(200.0f * s);
            ImGui::SetNextItemWidth(std::min(200.0f * s, ImGui::GetContentRegionAvail().x));
            ImGui::InputTextWithHint("##fnfilter", "filter name...", fnFilter_, sizeof(fnFilter_));
            ui::SameLineIfFits(330.0f * s);
            ImGui::PushTextWrapPos();
            if (!analyzeSummary_.empty()) ImGui::TextDisabled("%s", analyzeSummary_.c_str());
            else ImGui::TextDisabled("Recursive-descent + prologue + export sweep.");
            ImGui::PopTextWrapPos();

            if (ImGui::BeginTable("fns", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_Resizable,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f * s);
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                // Pre-filter into a dense index list so a uniform-height clipper can
                // skip the off-screen rows (this list can hold thousands of entries).
                std::vector<int> vis;
                vis.reserve(functions_.size());
                for (int i = 0; i < (int)functions_.size(); ++i)
                    if (!fnFilter_[0] || functions_[(size_t)i].name.find(fnFilter_) != std::string::npos)
                        vis.push_back(i);
                ImGuiListClipper clip;
                clip.Begin((int)vis.size());
                while (clip.Step())
                    for (int vi = clip.DisplayStart; vi < clip.DisplayEnd; ++vi) {
                        auto& f = functions_[(size_t)vis[(size_t)vi]];
                        ImGui::TableNextRow();
                        ImGui::PushID((void*)(uintptr_t)f.address);
                        ImGui::TableSetColumnIndex(0);
                        char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)f.address);
                        if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) ctx.gotoAddress(f.address);
                        ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(f.name.c_str());
                        ImGui::TableSetColumnIndex(2); ImGui::Text("%u", f.size);
                        ImGui::PopID();
                    }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

} // namespace ds
