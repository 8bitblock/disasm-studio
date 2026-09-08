#include "SigScannerTab.h"
#include "../Core/BinaryFile.h"
#include "../Core/FunctionAnalyzer.h"
#include "../Core/FunctionFilter.h"
#include "../Core/PatchSet.h"
#include "../Core/ProcessManager.h"
#include "../Core/Project.h"
#include "../Core/SigMatch.h"
#include "../Disasm/DisassemblerFactory.h"
#include "../Ui/Icons.h"
#include "../Ui/Fonts.h"
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
#include <chrono>
#include <windows.h>
#include <commdlg.h>

namespace ds {

namespace {
bool signatureLibraryDialog(bool save, std::filesystem::path& path, std::string& error) {
    std::vector<wchar_t> file(32768, L'\0');
    if (save) wcscpy_s(file.data(), file.size(), L"signatures.dssig.json");
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetActiveWindow();
    dialog.lpstrFilter = L"DisasmStudio signature library\0*.dssig.json;*.json\0All files\0*.*\0";
    dialog.lpstrFile = file.data();
    dialog.nMaxFile = static_cast<DWORD>(file.size());
    dialog.lpstrDefExt = L"json";
    dialog.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    if (!(save ? GetSaveFileNameW(&dialog) : GetOpenFileNameW(&dialog))) {
        if (const DWORD code = CommDlgExtendedError()) error = "Signature file dialog failed (" + std::to_string(code) + ").";
        return false;
    }
    path = std::filesystem::path(file.data());
    return true;
}
} // namespace

SignatureLibrary SigScannerTab::librarySnapshot() const {
    SignatureLibrary library;
    library.lastId = libraryLastId_;
    for (const auto& signature : sigs_) library.entries.push_back(signature);
    return library;
}

void SigScannerTab::adoptLibrary(SignatureLibrary library) {
    if (workerPending_ && activeWorkerKind_ == WorkerKind::Health)
        cancelWorker("Signature library changed; recompute health for the new definitions.");
    libraryLastId_ = library.lastId;
    sigs_.clear();
    sigs_.reserve(library.entries.size());
    for (auto& entry : library.entries) {
        Sig signature;
        static_cast<LibrarySignature&>(signature) = std::move(entry);
        sigs_.push_back(std::move(signature));
    }
    healthOwner_ = {};
    if (std::none_of(sigs_.begin(), sigs_.end(), [&](const auto& entry) { return entry.id == selectedSignatureId_; }))
        selectedSignatureId_ = 0;
}

void SigScannerTab::pollLibrary(AppContext& ctx) {
    if (!libraryStarted_) {
        libraryStarted_ = true;
        libraryStatus_ = "Loading signature library...";
        try {
            libraryIo_ = std::async(std::launch::async, [] {
                LibraryIoResult result;
                const auto path = DefaultSignatureLibraryPath();
                const auto loaded = LoadSignatureLibraryFile(path, result.library);
                if (loaded.source != atomic_file::ReadSource::None) {
                    result.publish = true;
                    result.status = loaded.source == atomic_file::ReadSource::Backup
                        ? "Recovered the signature library from its backup."
                        : "Signature library loaded.";
                } else if (loaded.missing) {
                    result.library = StarterSignatureLibrary();
                    result.publish = true;
                    result.failed = !SaveSignatureLibraryFile(path, result.library, result.status);
                    if (result.failed) result.retry = result.library;
                    else result.status = "Created a persistent library with three example signatures.";
                } else {
                    result.failed = true;
                    result.status = loaded.error + " Import a valid library or save a new signature to recover.";
                }
                return result;
            });
        } catch (const std::exception& error) {
            libraryFailed_ = true; libraryReady_ = true;
            libraryStatus_ = std::string("Could not start library loading: ") + error.what();
        }
    }
    if (!libraryIo_.valid()) return;
    ctx.wantContinuousRedraw = true;
    if (libraryIo_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) return;
    try {
        auto result = libraryIo_.get();
        if (result.publish) adoptLibrary(std::move(result.library));
        libraryFailed_ = result.failed;
        libraryStatus_ = std::move(result.status);
        if (result.publish || result.retry) libraryRetry_ = std::move(result.retry);
    } catch (const std::exception& error) {
        libraryFailed_ = true;
        libraryStatus_ = std::string("Signature library operation failed: ") + error.what();
    }
    libraryReady_ = true;
}

void SigScannerTab::saveLibrary(SignatureLibrary candidate, std::string success) {
    if (libraryIo_.valid()) return;
    libraryRetry_ = candidate;
    libraryStatus_ = "Saving signature library...";
    libraryFailed_ = false;
    try {
        libraryIo_ = std::async(std::launch::async, [candidate = std::move(candidate), success = std::move(success)]() mutable {
            LibraryIoResult result;
            result.failed = !SaveSignatureLibraryFile(DefaultSignatureLibraryPath(), candidate, result.status);
            if (result.failed) result.retry = std::move(candidate);
            else {
                result.publish = true;
                result.library = std::move(candidate);
                result.status = std::move(success);
            }
            return result;
        });
    } catch (const std::exception& error) {
        libraryFailed_ = true;
        libraryStatus_ = std::string("Could not start library saving: ") + error.what();
    }
}

void SigScannerTab::importLibrary() {
    std::filesystem::path path;
    std::string error;
    if (!signatureLibraryDialog(false, path, error)) {
        if (!error.empty()) { libraryStatus_ = error; libraryFailed_ = true; }
        return;
    }
    const auto current = librarySnapshot();
    libraryStatus_ = "Importing and saving signature library...";
    libraryFailed_ = false;
    libraryRetry_.reset();
    try {
        libraryIo_ = std::async(std::launch::async, [path, current] {
            LibraryIoResult result;
            std::string text;
            SignatureLibrary imported;
            result.failed = true;
            if (!atomic_file::Read(path, text, kMaxSignatureLibraryBytes)) {
                result.status = "Cannot read the import file, or it exceeds 4 MiB.";
                return result;
            }
            if (!ParseSignatureLibrary(text, imported, result.status) ||
                !MergeSignatureLibrary(current, imported, result.library, result.status)) return result;
            if (!SaveSignatureLibraryFile(DefaultSignatureLibraryPath(), result.library, result.status)) {
                result.retry = result.library;
                return result;
            }
            result.failed = false; result.publish = true;
            result.status = "Imported " + std::to_string(result.library.entries.size() - current.entries.size()) +
                " new signatures. Existing definitions were preserved; duplicates were skipped.";
            return result;
        });
    } catch (const std::exception& exception) {
        libraryFailed_ = true;
        libraryStatus_ = std::string("Could not start library import: ") + exception.what();
    }
}

void SigScannerTab::exportLibrary() {
    std::filesystem::path path;
    std::string error;
    if (!signatureLibraryDialog(true, path, error)) {
        if (!error.empty()) { libraryStatus_ = error; libraryFailed_ = true; }
        return;
    }
    const auto current = librarySnapshot();
    libraryStatus_ = "Exporting signature library...";
    libraryFailed_ = false;
    try {
        libraryIo_ = std::async(std::launch::async, [path, current] {
            LibraryIoResult result;
            result.failed = !SaveSignatureLibraryFile(path, current, result.status);
            if (!result.failed) result.status = "Signature library exported. Match counts and live addresses are excluded.";
            return result;
        });
    } catch (const std::exception& exception) {
        libraryFailed_ = true;
        libraryStatus_ = std::string("Could not start library export: ") + exception.what();
    }
}

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

static std::string formatScanBytes(uint64_t bytes) {
    constexpr const char* units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    if (bytes < 1024) return std::to_string(bytes) + " B";
    double value = static_cast<double>(bytes);
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(units)) {
        value /= 1024.0;
        ++unit;
    }
    char text[48]{};
    std::snprintf(text, sizeof(text), "%.1f %s", value, units[unit]);
    return text;
}

} // namespace

bool SigScannerTab::scanLivePatternRanges(
    const std::vector<LivePatternRange>& ranges,
    const SigPattern& pattern, std::string_view patternText,
    const LivePatternReader& reader,
    const LivePatternSourceCurrent& sourceCurrent,
    const LivePatternProgress& progress, const std::stop_token& stop,
    WorkerResult& result, size_t hitCap, size_t chunkBytes) {
    result.results.clear();
    result.truncated = false;
    result.scopeBytes = 0;
    result.attemptedBytes = 0;
    result.scannedBytes = 0;
    result.partialChunks = 0;
    result.unreadableChunks = 0;
    result.error.clear();

    if (pattern.empty() || pattern.mask.size() != pattern.size()) {
        result.error = "live signature scan received an invalid or empty pattern";
        return true;
    }
    if (!reader) {
        result.error = "live signature scan has no target-memory reader";
        return true;
    }
    if (sourceCurrent && !sourceCurrent()) {
        result.error = "the debugger target changed before the live scan started";
        return true;
    }

    for (const LivePatternRange& range : ranges) {
        if (range.size && range.base > UINT64_MAX - range.size) {
            result.error = "live signature scan range overflows the address space";
            return true;
        }
        result.scopeBytes = result.scopeBytes > UINT64_MAX - range.size
            ? UINT64_MAX : result.scopeBytes + range.size;
    }
    if (progress) progress(0, result.scopeBytes);

    chunkBytes = (std::max<size_t>)(1, chunkBytes);
    const size_t lookaheadMax = pattern.size() - 1;
    if (chunkBytes > (std::numeric_limits<size_t>::max)() - lookaheadMax)
        chunkBytes = (std::numeric_limits<size_t>::max)() - lookaheadMax;
    if (!chunkBytes) chunkBytes = 1;

    std::vector<uint8_t> buffer;
    for (const LivePatternRange& range : ranges) {
        for (uint64_t offset = 0; offset < range.size;) {
            if (stop.stop_requested()) return false;
            if (sourceCurrent && !sourceCurrent()) {
                result.error = "the debugger target changed during the live scan";
                return true;
            }

            const uint64_t remaining = range.size - offset;
            const size_t owned = static_cast<size_t>((std::min<uint64_t>)(
                remaining, static_cast<uint64_t>(chunkBytes)));
            const size_t lookahead = static_cast<size_t>((std::min<uint64_t>)(
                lookaheadMax, remaining - owned));
            const size_t wanted = owned + lookahead;
            buffer.resize(wanted);

            size_t got = reader(range.base + offset, buffer.data(), wanted);
            if (got > wanted) got = wanted;
            if (stop.stop_requested()) return false;
            if (sourceCurrent && !sourceCurrent()) {
                result.error = "the debugger target changed during the live scan";
                return true;
            }

            result.attemptedBytes = result.attemptedBytes > UINT64_MAX - owned
                ? UINT64_MAX : result.attemptedBytes + owned;
            const size_t ownedRead = (std::min)(got, owned);
            result.scannedBytes = result.scannedBytes > UINT64_MAX - ownedRead
                ? UINT64_MAX : result.scannedBytes + ownedRead;
            if (!got) ++result.unreadableChunks;
            else if (got < wanted) ++result.partialChunks;

            if (got >= pattern.size()) {
                size_t localLimit = 0;
                if (hitCap) {
                    localLimit = result.results.size() >= hitCap
                        ? 1 : hitCap - result.results.size() + 1;
                }
                const auto hits = FindAllMaskedAccepted(
                    buffer.data(), got, pattern, localLimit,
                    [owned](size_t local) { return local < owned; });
                for (const size_t local : hits) {
                    result.results.push_back({
                        range.base + offset + local,
                        std::string(patternText), range.source, true });
                    if (hitCap && result.results.size() > hitCap) {
                        result.results.resize(hitCap);
                        result.truncated = true;
                        if (progress)
                            progress(result.attemptedBytes, result.scopeBytes);
                        return true;
                    }
                }
            }

            offset += owned;
            if (progress) progress(result.attemptedBytes, result.scopeBytes);
        }
    }
    return true;
}

std::string SigScannerTab::formatLiveCoverage(const WorkerResult& result,
                                              bool& partial) {
    const bool missingReadBytes = result.scannedBytes < result.attemptedBytes;
    const bool unattemptedBytes = result.attemptedBytes < result.scopeBytes;
    partial = result.truncated || !result.memoryMapComplete ||
              result.partialChunks != 0 || result.unreadableChunks != 0 ||
              missingReadBytes || unattemptedBytes;

    std::string status = "LIVE coverage: " + formatScanBytes(result.scannedBytes) +
        " read from " + formatScanBytes(result.scopeBytes) +
        " enumerated readable committed memory";
    if (!partial) return status + "; complete.";

    status += "; partial";
    if (result.truncated)
        status += " (4,096-match cap reached; remaining memory may contain more matches)";
    if (unattemptedBytes && !result.truncated)
        status += "; not all enumerated memory was attempted";
    if (result.partialChunks) {
        status += "; " + std::to_string(result.partialChunks) + " short read";
        if (result.partialChunks != 1) status += 's';
    }
    if (result.unreadableChunks) {
        status += "; " + std::to_string(result.unreadableChunks) +
            " unreadable chunk";
        if (result.unreadableChunks != 1) status += 's';
    }
    if (missingReadBytes) {
        status += "; " + formatScanBytes(result.attemptedBytes - result.scannedBytes) +
            " of attempted memory was not returned";
    }
    if (!result.memoryMapComplete) {
        status += "; memory map incomplete";
        if (!result.memoryMapWarning.empty())
            status += ": " + result.memoryMapWarning;
    }
    status += '.';
    return status;
}

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
    if (patternClipped_ || !parsePattern(patternText, pattern)) {
        workerStatus_ = patternClipped_ ? "The signature was truncated. Edit or replace it before scanning."
                                       : "Use hex byte pairs and ? or ?? wildcard bytes, for example: 48 89 ?? 24.";
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
    resultsFilterDirty_ = true;
    selectedResult_ = -1;
    scanPattern_ = patternText;
    scanTarget_ = live_ ? "LIVE process memory" : ctx.staticBinary().path();
    scanCompleted_ = false;
    staticResultsOwner_ = {};
    resultsLive_ = live_;
    truncated_ = false;
    scanPartial_ = false;
    scanCoverageStatus_.clear();
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
        scanTarget_ = "LIVE process " + std::to_string(pid);
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
                            DbgRegionResult mapped = debugger->queryRegionsForSession(
                                pid, generation);
                            if (!sameLiveSession(debugger, pid, generation)) {
                                result.error = "the debugger target changed while memory regions were collected";
                            } else {
                                result.memoryMapComplete = mapped.complete;
                                if (!mapped.complete) {
                                    result.memoryMapWarning = mapped.error.empty()
                                        ? "enumeration ended before the full address space"
                                        : mapped.error;
                                }

                                ProcessManager manager;
                                const std::vector<ModuleInfo> modules =
                                    manager.modules(pid);
                                auto moduleAt = [&](uint64_t address) {
                                    for (const ModuleInfo& module : modules) {
                                        if (address >= module.base &&
                                            address - module.base < module.size)
                                            return module.name.empty()
                                                ? module.path : module.name;
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
                                auto appendMapWarning = [&](std::string_view warning) {
                                    result.memoryMapComplete = false;
                                    if (!result.memoryMapWarning.empty())
                                        result.memoryMapWarning += "; ";
                                    result.memoryMapWarning.append(warning);
                                };

                                std::vector<LivePatternRange> ranges;
                                ranges.reserve(mapped.regions.size());
                                for (const MemRegion& region : mapped.regions) {
                                    if (!region.size || !region.read ||
                                        region.state != MEM_COMMIT ||
                                        (region.protect &
                                            (PAGE_GUARD | PAGE_NOACCESS)) != 0)
                                        continue;
                                    if (region.base > UINT64_MAX - region.size) {
                                        appendMapWarning(
                                            "an invalid overflowing region was skipped");
                                        continue;
                                    }
                                    ranges.push_back({
                                        region.base, region.size,
                                        moduleAt(region.base) + protection(region) });
                                }

                                if (!sameLiveSession(debugger, pid, generation)) {
                                    result.error =
                                        "the debugger target changed while memory regions were prepared";
                                } else {
                                    LivePatternReader reader =
                                        [debugger, pid, generation](
                                            uint64_t address, void* output,
                                            size_t size) {
                                            return debugger->readMemoryMaskedForSession(
                                                pid, generation, address,
                                                output, size);
                                        };
                                    LivePatternSourceCurrent sourceCurrent =
                                        [debugger, pid, generation] {
                                            return sameLiveSession(
                                                debugger, pid, generation);
                                        };
                                    LivePatternProgress reportProgress =
                                        [this](uint64_t completed,
                                               uint64_t total) {
                                            workerTotal_.store(
                                                (std::max<uint64_t>)(1, total),
                                                std::memory_order_release);
                                            workerDone_.store(
                                                completed,
                                                std::memory_order_release);
                                        };
                                    if (!scanLivePatternRanges(
                                            ranges, pattern, patternText,
                                            reader, sourceCurrent,
                                            reportProgress, stop, result,
                                            kResultCap, 1u << 20))
                                        return;
                                }
                            }
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
    functionsFilterDirty_ = true;
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
            resultsFilterDirty_ = true;
            selectedResult_ = -1;
            scanCompleted_ = true;
            resultsLive_ = ready->kind == WorkerKind::LiveScan;
            resultsLivePid_ = resultsLive_ ? ready->livePid : 0;
            resultsLiveGeneration_ = resultsLive_ ? ready->liveGeneration : 0;
            staticResultsOwner_ = resultsLive_ ? DocumentResultIdentity{} : ready->owner;
            truncated_ = ready->truncated;
            if (resultsLive_) {
                scanCoverageStatus_ = formatLiveCoverage(*ready, scanPartial_);
            } else {
                scanPartial_ = truncated_;
                scanCoverageStatus_ = truncated_
                    ? "Partial results: the 4,096-match cap was reached. Refine the pattern; additional FILE matches may exist."
                    : std::string{};
            }
            const std::string message = std::string(resultsLive_ ? "Live" : "File") +
                " scan: " + std::to_string(results_.size()) + " match(es)" +
                (scanPartial_ ? " (partial)." : ".");
            ui::Toast(scanPartial_ ? ui::ToastKind::Warn : ui::ToastKind::Info,
                      message);
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
            functionsFilterDirty_ = true;
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
    pollLibrary(ctx);
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
        resultsFilterDirty_ = true;
        selectedResult_ = -1;
        scanPattern_.clear();
        scanTarget_.clear();
        scanCompleted_ = false;
        staticResultsOwner_ = {};
        resultsLive_ = false;
        resultsLivePid_ = 0;
        resultsLiveGeneration_ = 0;
        truncated_ = false;
        scanPartial_ = false;
        scanCoverageStatus_.clear();
        progress_ = 0.0f;
    }
    if (resultsLive_ &&
        (!snap.attached() || snap.pid != resultsLivePid_ ||
         snap.sessionGeneration != resultsLiveGeneration_)) {
        results_.clear();
        resultsFilterDirty_ = true;
        selectedResult_ = -1;
        scanPattern_.clear();
        scanTarget_.clear();
        scanCompleted_ = false;
        resultsLive_ = false;
        resultsLivePid_ = 0;
        resultsLiveGeneration_ = 0;
        truncated_ = false;
        scanPartial_ = false;
        scanCoverageStatus_.clear();
        progress_ = 0.0f;
    }
    if (functionsOwner_ &&
        (!SameDocumentResultImage(functionsOwner_, currentIdentity) ||
         functionsEngine_ != ctx.staticEngine() ||
         functionsArch_ != ctx.staticArch())) {
        functions_.clear();
        functionsFilterDirty_ = true;
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
            selectedSignatureId_ = 0;
            std::string signature = std::move(ctx.pendingSignature);
            ctx.clearPendingSignature();
            live_ = pendingLive;
            patternClipped_ = signature.size() >= sizeof(patternInput_);   // defensive: buffer holds the worst case
            std::snprintf(patternInput_, sizeof(patternInput_), "%s", signature.c_str());
            scan(ctx);   // populate Results (the default sub-tab) right away
        }
    }
    ui::PanelHeader("Signature Scanner", "Byte patterns, uniqueness and functions");

    if (!ctx.staticBinary().loaded() && !snap.attached()) {
        if (ui::AccentButton("Open Binary...", theme::col::accent())) ctx.openBinaryDialog();
        ui::SameLineIfFits(ImGui::CalcTextSize("Your saved signature library is available below.").x);
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled("Your saved signature library is available below.");
        ImGui::PopTextWrapPos();
    }

    // Source is chosen before computing availability, so mode changes cannot
    // leave the Scan button enabled against the previous source for one frame.
    const float s = theme::UiScale();
    const auto buttonWidth = [](const char* label) {
        return ImGui::CalcTextSize(label).x + ImGui::GetStyle().FramePadding.x * 2.0f;
    };
    const bool previousLive = live_;
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Scan target");
    ui::SameLineIfFits(buttonWidth("FILE") + ImGui::GetFrameHeight());
    if (ImGui::RadioButton("FILE", !live_)) live_ = false;
    ui::SameLineIfFits(buttonWidth("LIVE") + ImGui::GetFrameHeight());
    if (ImGui::RadioButton("LIVE", live_)) live_ = true;
    ui::ItemTooltip("Scan readable committed memory in the attached debugger session, paused or running.");
    if (previousLive != live_) {
        if (workerPending_) cancelWorker("Scan mode changed; scan cancelled.");
        results_.clear();
        resultsFilterDirty_ = true;
        selectedResult_ = -1;
        scanPattern_.clear();
        scanTarget_.clear();
        scanCompleted_ = false;
        staticResultsOwner_ = {};
        resultsLive_ = live_;
        resultsLivePid_ = 0;
        resultsLiveGeneration_ = 0;
        truncated_ = false;
        scanPartial_ = false;
        scanCoverageStatus_.clear();
        progress_ = 0.0f;
    }
    const bool canScan = live_ ? snap.attached() : ctx.staticBinary().loaded();
    ui::SameLineIfFits(270.0f * s);
    ImGui::PushTextWrapPos();
    if (canScan && live_) ImGui::TextDisabled("Attached process %lu", static_cast<unsigned long>(snap.pid));
    else if (canScan) ImGui::TextDisabled("Current image, including active patches");
    else ImGui::TextDisabled(live_ ? "Attach a process in Communications."
                                  : "Open a binary to scan file bytes.");
    ImGui::PopTextWrapPos();
    ui::SameLineIfFits(100.0f * s);
    ui::StatePill(workerPending_ ? "RUNNING" : scanCompleted_ ? (scanPartial_ ? "PARTIAL" : "COMPLETE") : "IDLE",
        workerPending_ ? theme::col::accent() : scanCompleted_ ? (scanPartial_ ? theme::col::warn() : theme::col::good())
                                                              : theme::col::muted());

    const float scanWidth = buttonWidth("Scan");
    const float inputWidth = ImGui::GetContentRegionAvail().x;
    const bool scanFits = inputWidth >= 360.0f * s + scanWidth;
    ImGui::SetNextItemWidth(std::max(1.0f, inputWidth -
        (scanFits ? scanWidth + ImGui::GetStyle().ItemSpacing.x : 0.0f)));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, theme::col::code());
    ui::PushMono();
    const bool enterScan = ImGui::InputTextWithHint("##pattern", "Byte pattern: 48 89 ?? 24", patternInput_,
        sizeof(patternInput_), ImGuiInputTextFlags_EnterReturnsTrue);
    ui::PopMono();
    ImGui::PopStyleColor();
    if (ImGui::IsItemEdited()) patternClipped_ = false;
    ui::ItemTooltip("Hex byte pairs, with ? or ?? for any byte. Spaces are optional. Press Enter to scan.");
    SigPattern savePattern;
    const bool validPattern = !patternClipped_ && parsePattern(patternInput_, savePattern);
    if (enterScan && canScan && validPattern && !workerPending_) scan(ctx);
    if (scanFits) ImGui::SameLine();
    ImGui::BeginDisabled(!canScan || !validPattern || workerPending_);
    if (ui::AccentButton("Scan###tbib_Scan", theme::col::accent(), !canScan ? "Choose an available FILE or LIVE target."
            : !validPattern ? "Enter valid hex byte pairs and optional ? or ?? wildcards."
            : workerPending_ ? "Wait for the current work or cancel it first."
            : live_ ? "Scan every readable committed region in the captured debugger session."
                    : "Scan the current file image, including enabled patches.")) scan(ctx);
    ImGui::EndDisabled();
    ImGui::PushTextWrapPos();
    if (patternClipped_) ImGui::TextColored(theme::col::warn(), "Pattern was truncated. Edit or replace it before scanning.");
    else if (patternInput_[0] && !validPattern)
        ImGui::TextColored(theme::col::warn(), "Use complete hex byte pairs and ? or ?? wildcard bytes.");
    else if (validPattern) {
        const size_t fixed = static_cast<size_t>(std::count(savePattern.mask.begin(), savePattern.mask.end(), true));
        ImGui::TextDisabled("%zu bytes  /  %zu fixed  /  %zu wildcards", savePattern.size(), fixed, savePattern.size() - fixed);
        if (!fixed) {
            ui::SameLineIfFits(250.0f * s);
            ImGui::TextColored(theme::col::warn(), "All wildcards: every offset can match.");
        }
    }
    ImGui::PopTextWrapPos();

    ImGui::Separator();
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Library");
    ui::SameLineIfFits(190.0f * s);
    ImGui::SetNextItemWidth(std::min(190.0f * s, ImGui::GetContentRegionAvail().x));
    ImGui::InputTextWithHint("##signame", "signature name", sigName_, sizeof(sigName_));
    ui::SameLineIfFits(buttonWidth(selectedSignatureId_ ? "Update Sig" : "Save Sig") + ImGui::GetFrameHeight());
    ImGui::BeginDisabled(workerPending_ || libraryIo_.valid() || !libraryReady_ || !validPattern || !sigName_[0]);
    if (ui::ToolbarIconButton(DS_ICON_SAVE, selectedSignatureId_ ? "Update Sig" : "Save Sig",
        "Save this named pattern in your persistent signature library")) {
        auto candidate = librarySnapshot();
        auto existing = std::find_if(candidate.entries.begin(), candidate.entries.end(),
            [&](const auto& entry) { return entry.id == selectedSignatureId_; });
        const bool creating = existing == candidate.entries.end();
        if (creating && (candidate.lastId == UINT64_MAX || candidate.entries.size() >= kMaxLibrarySignatures)) {
            libraryFailed_ = true;
            libraryStatus_ = "The signature library is full or its identities are exhausted.";
        } else {
            LibrarySignature signature;
            if (!creating) signature = *existing;
            else signature.id = ++candidate.lastId;
            signature.name = sigName_; signature.pattern = patternInput_;
            // A changed pattern has new provenance. Retaining just its name
            // preserves the original source instead of relabeling it on reuse.
            if (creating || existing->pattern != signature.pattern) {
                signature.architecture.clear(); signature.sourceHash.clear();
                if (!live_ && ctx.staticBinary().loaded()) {
                    signature.architecture = ArchName(ctx.staticArch());
                    char hash[17]{};
                    std::snprintf(hash, sizeof(hash), "%016llX", static_cast<unsigned long long>(ctx.staticBinary().contentHash()));
                    signature.sourceHash = hash;
                }
            }
            if (creating) candidate.entries.push_back(std::move(signature));
            else *existing = std::move(signature);
            saveLibrary(std::move(candidate), "Signature saved to the library. Recompute health for the current FILE image.");
            requestedSub_ = 2;
        }
    }
    ImGui::EndDisabled();
    if (selectedSignatureId_) {
        ui::SameLineIfFits(buttonWidth("New / save copy"));
        if (ImGui::Button("New / save copy")) selectedSignatureId_ = 0;
    }
    ui::SameLineIfFits(buttonWidth("Import library"));
    ImGui::BeginDisabled(!libraryReady_ || libraryIo_.valid() || workerPending_);
    if (ImGui::Button("Import library")) importLibrary();
    ImGui::EndDisabled();
    ui::SameLineIfFits(buttonWidth("Export library"));
    ImGui::BeginDisabled(!libraryReady_ || libraryIo_.valid());
    if (ImGui::Button("Export library")) exportLibrary();
    ImGui::EndDisabled();
    if (!libraryStatus_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, libraryFailed_ ? theme::col::bad() : theme::col::muted());
        ImGui::TextWrapped("%s", libraryStatus_.c_str());
        ImGui::PopStyleColor();
    }
    if (libraryRetry_ && !libraryIo_.valid()) {
        if (ImGui::Button("Retry library save")) saveLibrary(*libraryRetry_, "Signature library saved.");
        ui::SameLineIfFits(200.0f * s);
        if (ImGui::Button("Discard pending library change")) {
            libraryRetry_.reset(); libraryFailed_ = false;
            libraryStatus_ = "Pending library change discarded; displayed definitions were kept.";
        }
    }
    if (workerPending_) {
        ui::SameLineIfFits(140.0f * s);
        ImGui::ProgressBar(progress_, ImVec2(140.0f * s, 0));
        ui::SameLineIfFits(80.0f * s);
        if (ImGui::SmallButton("Cancel##sigworker")) cancelWorker();
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
        if (ui::BeginCountTabItem("Results", results_.size(), selectSub == 0 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ui::SearchBox("##resultfilter", "Filter address, module or pattern...", resultFilter_,
                          sizeof(resultFilter_), std::min(310.0f * s, ImGui::GetContentRegionAvail().x));
            if (resultsFilterDirty_ || cachedResultFilter_ != resultFilter_) {
                const FunctionFilter filter(resultFilter_);
                visibleResults_.clear();
                visibleResults_.reserve(results_.size());
                for (size_t i = 0; i < results_.size(); ++i) {
                    const auto& result = results_[i];
                    if (filter.matches(result.module, result.sig, result.address))
                        visibleResults_.push_back(static_cast<int>(i));
                }
                cachedResultFilter_ = resultFilter_;
                resultsFilterDirty_ = false;
            }
            ui::SameLineIfFits(225.0f * s);
            ImGui::TextDisabled("%zu of %zu matches  /  %s", visibleResults_.size(), results_.size(),
                                resultsLive_ ? "LIVE memory" : "FILE image");
            if (!scanCoverageStatus_.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text,
                    scanPartial_ ? theme::col::warn() : theme::col::muted());
                ImGui::TextWrapped("%s", scanCoverageStatus_.c_str());
                ImGui::PopStyleColor();
            }
            if (!visibleResults_.empty()) {
                ImGui::PushTextWrapPos();
                ImGui::TextDisabled("Select a match to open its address. Right-click for copy actions.");
                ImGui::PopTextWrapPos();
            } else if (!results_.empty()) {
                if (ui::EmptyState(DS_ICON_SEARCH, "No matches in this filter",
                        "Try an address, module name or a shorter search. Escape clears the search field.", "Clear filter"))
                    resultFilter_[0] = '\0';
            } else if (workerPending_ && (activeWorkerKind_ == WorkerKind::StaticScan || activeWorkerKind_ == WorkerKind::LiveScan)) {
                ui::EmptyState(DS_ICON_SEARCH, "Scanning for matches",
                    "Results appear when the scan finishes. You can cancel above.");
            } else if (scanCompleted_) {
                ui::EmptyState(DS_ICON_SEARCH, "No byte-pattern matches",
                    scanPartial_ ? "This scan was partial. Review its coverage status before treating zero matches as absence."
                                 : "Check the selected target, shorten the pattern or use ?? for bytes that can change.");
            } else {
                ui::EmptyState(DS_ICON_SEARCH, "Find a byte pattern",
                    "Enter hex bytes above and choose Scan, or select a saved pattern in Sig Health.");
            }
            if (!visibleResults_.empty() && ui::BeginDataTable("res", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollX,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f * s);
                ImGui::TableSetupColumn("Module / source", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                ImGuiListClipper clip;   // up to 4096 rows -> only build widgets for the visible ones
                clip.Begin((int)visibleResults_.size());
                while (clip.Step())
                    for (int vi = clip.DisplayStart; vi < clip.DisplayEnd; ++vi) {
                        const int i = visibleResults_[static_cast<size_t>(vi)];
                        auto& r = results_[(size_t)i];
                        ImGui::TableNextRow();
                        ImGui::PushID(i);
                        ImGui::TableSetColumnIndex(0);
                        char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)r.address);
                        // Live hits are runtime VAs -> open the live view; file hits are file VAs.
                        const auto navigate = [&] {
                            selectedResult_ = i;
                            if (r.live)
                                ctx.gotoAddressLive(
                                    r.address,
                                    { resultsLivePid_, resultsLiveGeneration_ });
                            else
                                ctx.gotoAddress(r.address);
                        };
                        if (ImGui::Selectable(al, selectedResult_ == i, ImGuiSelectableFlags_SpanAllColumns)) navigate();
                        if (ImGui::BeginPopupContextItem("##result_actions")) {
                            if (ImGui::MenuItem(r.live ? "Open in Live Assembly" : "Open in Binary View")) navigate();
                            ImGui::Separator();
                            if (ImGui::MenuItem("Copy address")) ImGui::SetClipboardText(al);
                            if (ImGui::MenuItem("Copy pattern")) ImGui::SetClipboardText(r.sig.c_str());
                            if (ImGui::MenuItem("Copy module / source")) ImGui::SetClipboardText(r.module.c_str());
                            ImGui::EndPopup();
                        }
                        ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(r.module.c_str());
                        ui::ItemTooltip(r.module.c_str());
                        ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", r.sig.c_str());
                        // Signatures can be large; the table keeps one clipped row,
                        // and copy preserves the complete pattern without a huge tooltip.
                        ImGui::PopID();
                    }
                ui::EndDataTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Current Scan", nullptr, selectSub == 1 ? ImGuiTabItemFlags_SetSelected : 0)) {
            // The editor stays available while work runs. Display the captured
            // request here, never its subsequently edited name/pattern/target.
            if (workerPending_) {
                const char* activity = activeWorkerKind_ == WorkerKind::Health ? "Checking signature health"
                                     : activeWorkerKind_ == WorkerKind::Functions ? "Analyzing functions"
                                     : activeWorkerKind_ == WorkerKind::LiveScan ? "Scanning LIVE memory"
                                     : "Scanning FILE image";
                ImGui::TextUnformatted(activity);
                ImGui::ProgressBar(progress_, ImVec2(-1, 0));
                const uint64_t done = workerDone_.load(std::memory_order_acquire);
                const uint64_t total = workerTotal_.load(std::memory_order_acquire);
                ImGui::TextDisabled("Progress: %llu / %llu work units",
                                    (unsigned long long)done,
                                    (unsigned long long)total);
                if (ImGui::Button("Cancel current work")) cancelWorker();
            } else if (!workerStatus_.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, theme::col::warn());
                ImGui::TextWrapped("%s", workerStatus_.c_str());
                ImGui::PopStyleColor();
            } else if (scanCompleted_) {
                ui::StatePill(scanPartial_ ? "PARTIAL" : "COMPLETE",
                              scanPartial_ ? theme::col::warn() : theme::col::good());
                ImGui::Text("%zu matches", results_.size());
                if (!scanCoverageStatus_.empty()) {
                    ImGui::PushStyleColor(ImGuiCol_Text,
                        scanPartial_ ? theme::col::warn() : theme::col::muted());
                    ImGui::TextWrapped("%s", scanCoverageStatus_.c_str());
                    ImGui::PopStyleColor();
                }
            } else {
                ui::EmptyState(DS_ICON_SEARCH, "No scan in progress",
                    "Choose FILE or LIVE, enter a byte pattern and select Scan. Completed work keeps its captured target and pattern here.");
            }
            if (!scanPattern_.empty() && (!workerPending_ || activeWorkerKind_ == WorkerKind::StaticScan || activeWorkerKind_ == WorkerKind::LiveScan)) {
                ImGui::Separator();
                ImGui::TextDisabled("Captured scan target");
                ImGui::TextWrapped("%s", scanTarget_.c_str());
                ImGui::TextDisabled("Captured byte pattern");
                if (ImGui::SmallButton("Copy scanned pattern")) ImGui::SetClipboardText(scanPattern_.c_str());
                ImGui::BeginChild("##captured_pattern", ImVec2(0, std::max(ImGui::GetFrameHeight(),
                                  std::min(130.0f * s, ImGui::GetContentRegionAvail().y))),
                                  ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
                ImGui::TextUnformatted(scanPattern_.c_str());
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }
        if (ui::BeginCountTabItem("Sig Health", sigs_.size(), selectSub == 2 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::BeginDisabled(!ctx.staticBinary().loaded() || workerPending_ || !libraryReady_ || libraryIo_.valid());
            if (ui::AccentButton("Recompute health", theme::col::accent())) refreshHealth(ctx);
            ImGui::EndDisabled();
            ui::ItemTooltip("Count each saved pattern against the current FILE image, including active patches. A unique match is a useful signature candidate.");
            ui::SameLineIfFits(300.0f * s);
            ImGui::TextDisabled("%zu saved signatures  /  %s", sigs_.size(), ctx.staticBinary().loaded()
                ? "FILE match counts" : "Open a binary to check uniqueness");
            ImGui::PushTextWrapPos();
            ImGui::TextDisabled("Saved library: select to edit, double-click to scan, right-click to remove. Counts belong to the current FILE image.");
            ImGui::PopTextWrapPos();
            uint64_t removeSignature = 0;
            if (sigs_.empty()) {
                ui::EmptyState(DS_ICON_SEARCH, libraryReady_ ? "Your signature library is empty" : "Loading signature library",
                    libraryReady_ ? "Name and save a pattern above, or import an existing signature library."
                                  : "Saved definitions will appear here when loading finishes.");
            }
            if (!sigs_.empty() && ui::BeginDataTable("health", 4,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollX,
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
                    if (ImGui::Selectable(s.name.empty() ? "(unnamed)" : s.name.c_str(), s.id == selectedSignatureId_,
                            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        selectedSignatureId_ = s.id;
                        std::snprintf(patternInput_, sizeof(patternInput_), "%s", s.pattern.c_str());
                        std::snprintf(sigName_, sizeof(sigName_), "%s", s.name.c_str());
                        patternClipped_ = s.pattern.size() >= sizeof(patternInput_);
                        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && canScan && !workerPending_)
                            scan(ctx);
                    }
                    if (ImGui::IsItemHovered() && (!s.architecture.empty() || !s.sourceHash.empty())) {
                        ImGui::SetTooltip("Source architecture: %s\nSource FILE hash: %s\nProvenance is descriptive; scanning uses the selected FILE / Live target.",
                            s.architecture.empty() ? "unspecified" : s.architecture.c_str(),
                            s.sourceHash.empty() ? "unspecified" : s.sourceHash.c_str());
                    }
                    if (ImGui::BeginPopupContextItem("##signature_actions")) {
                        if (ImGui::MenuItem("Scan this pattern", nullptr, false, canScan && !workerPending_)) {
                            selectedSignatureId_ = s.id;
                            std::snprintf(patternInput_, sizeof(patternInput_), "%s", s.pattern.c_str());
                            std::snprintf(sigName_, sizeof(sigName_), "%s", s.name.c_str());
                            patternClipped_ = s.pattern.size() >= sizeof(patternInput_);
                            scan(ctx);
                        }
                        if (ImGui::MenuItem("Copy pattern")) ImGui::SetClipboardText(s.pattern.c_str());
                        ImGui::Separator();
                        if (ImGui::MenuItem("Remove from library", nullptr, false, !libraryIo_.valid() && !workerPending_))
                            removeSignature = s.id;
                        ImGui::EndPopup();
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
                ui::EndDataTable();
            }
            if (removeSignature) {
                auto candidate = librarySnapshot();
                std::erase_if(candidate.entries, [&](const auto& entry) { return entry.id == removeSignature; });
                saveLibrary(std::move(candidate), "Signature removed from the saved library.");
            }
            ImGui::EndTabItem();
        }
        if (ui::BeginCountTabItem("All Functions", functions_.size(), selectSub == 3 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::BeginDisabled(!ctx.staticBinary().loaded() ||
                                 !ctx.staticDisassembler() || workerPending_);
            if (ui::AccentButton("Analyze Functions", theme::col::accent())) {
                analyzeFunctions(ctx);
            }
            ImGui::EndDisabled();
            ui::SameLineIfFits(290.0f * s);
            ui::SearchBox("##fnfilter", "Filter function name or address...", fnFilter_, sizeof(fnFilter_),
                          std::min(290.0f * s, ImGui::GetContentRegionAvail().x));
            ui::ItemTooltip("Search names and hex addresses, ignoring case. Space-separated terms are combined; use -term to exclude and quotes for phrases. Escape clears the search.");
            if (functionsFilterDirty_ || cachedFnFilter_ != fnFilter_) {
                const FunctionFilter filter(fnFilter_);
                visibleFunctions_.clear();
                visibleFunctions_.reserve(functions_.size());
                for (size_t i = 0; i < functions_.size(); ++i) {
                    const auto& function = functions_[i];
                    if (filter.matches(function.name, {}, function.address))
                        visibleFunctions_.push_back(static_cast<int>(i));
                }
                cachedFnFilter_ = fnFilter_;
                functionsFilterDirty_ = false;
            }
            ui::SameLineIfFits(190.0f * s);
            ImGui::TextDisabled("%zu of %zu functions", visibleFunctions_.size(), functions_.size());
            ImGui::PushTextWrapPos();
            if (!analyzeSummary_.empty()) ImGui::TextDisabled("%s", analyzeSummary_.c_str());
            else ImGui::TextDisabled("Discover function candidates in the current FILE image, then select an address to inspect it.");
            ImGui::PopTextWrapPos();

            if (visibleFunctions_.empty()) {
                if (!functions_.empty()) {
                    if (ui::EmptyState(DS_ICON_SEARCH, "No functions match this filter",
                            "Try a shorter name or a hex address. Escape clears the search field.", "Clear filter"))
                        fnFilter_[0] = '\0';
                } else if (workerPending_ && activeWorkerKind_ == WorkerKind::Functions) {
                    ui::EmptyState(DS_ICON_SEARCH, "Discovering functions", "The analysis runs in the background. You can cancel above.");
                } else {
                    ui::EmptyState(DS_ICON_SEARCH, functionsOwner_ ? "No function candidates found" : "Explore the file's functions",
                        !ctx.staticBinary().loaded() ? "Open a binary, then choose Analyze Functions."
                        : functionsOwner_ ? "Check the selected architecture and the file's executable mappings."
                                          : "Choose Analyze Functions to build the list for this FILE image.");
                }
            }
            if (!visibleFunctions_.empty() && ui::BeginDataTable("fns", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollX,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f * s);
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                ImGuiListClipper clip;
                clip.Begin((int)visibleFunctions_.size());
                while (clip.Step())
                    for (int vi = clip.DisplayStart; vi < clip.DisplayEnd; ++vi) {
                        auto& f = functions_[(size_t)visibleFunctions_[(size_t)vi]];
                        ImGui::TableNextRow();
                        ImGui::PushID((void*)(uintptr_t)f.address);
                        ImGui::TableSetColumnIndex(0);
                        char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)f.address);
                        if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) ctx.gotoAddress(f.address);
                        if (ImGui::BeginPopupContextItem("##function_actions")) {
                            if (ImGui::MenuItem("Open in Binary View")) ctx.gotoAddress(f.address);
                            ImGui::Separator();
                            if (ImGui::MenuItem("Copy address")) ImGui::SetClipboardText(al);
                            if (ImGui::MenuItem("Copy function name")) ImGui::SetClipboardText(f.name.c_str());
                            ImGui::EndPopup();
                        }
                        ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(f.name.c_str());
                        ui::ItemTooltip(f.name.c_str());
                        ImGui::TableSetColumnIndex(2); ImGui::Text("%u", f.size);
                        ImGui::PopID();
                    }
                ui::EndDataTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

} // namespace ds
