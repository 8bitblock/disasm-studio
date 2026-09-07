#pragma once
#include "ITab.h"
#include "../Core/DocumentResultIdentity.h"
#include "../Core/SigMatch.h"
#include "../Core/SignatureLibrary.h"
#include <atomic>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ds {

// Signature scanner: define byte-pattern signatures, scan the loaded image,
// and review results, current-scan progress, signature health, and the
// all-functions list.
class SigScannerTab final : public ITab {
public:
    const char* name() const override { return "Sig Scanner"; }
    void render(AppContext& ctx) override;

private:
    enum class WorkerKind : uint8_t { None, StaticScan, LiveScan, Health, Functions };

    void scan(AppContext& ctx);
    void refreshHealth(AppContext& ctx);   // queue a rescore against a private image
    void analyzeFunctions(AppContext& ctx);
    void pollWorker(AppContext& ctx, const DocumentResultIdentity& currentIdentity,
                    const DbgSnapshot& snapshot);
    void cancelWorker(const char* status = "Scan cancelled.");
    SignatureLibrary librarySnapshot() const;
    void adoptLibrary(SignatureLibrary library);
    void pollLibrary(AppContext& ctx);
    void saveLibrary(SignatureLibrary candidate, std::string success);
    void importLibrary();
    void exportLibrary();

    struct Result   {
        uint64_t address;
        std::string sig;
        std::string module;
        bool live = false; // result ownership is immutable; the toolbar may change later
    };
    struct Sig : LibrarySignature {
        std::string health = "n/a";
        int count = -1;
        bool countCapped = false;
    };
    struct Function { uint64_t address; std::string name; uint32_t size; };

    struct HealthResult {
        int count = -1;
        std::string health;
        bool capped = false;
    };

    struct WorkerResult {
        uint64_t request = 0;
        WorkerKind kind = WorkerKind::None;
        DocumentResultIdentity owner;
        DecoderConfig decoder;
        uint32_t livePid = 0;
        uint64_t liveGeneration = 0;
        std::vector<Result> results;
        std::vector<HealthResult> health;
        std::vector<Function> functions;
        std::string summary;
        std::string error;
        bool truncated = false;
        bool memoryMapComplete = true;
        std::string memoryMapWarning;
        uint64_t scopeBytes = 0;
        uint64_t attemptedBytes = 0;
        uint64_t scannedBytes = 0;
        size_t partialChunks = 0;
        size_t unreadableChunks = 0;
    };

    struct LivePatternRange {
        uint64_t base = 0;
        uint64_t size = 0;
        std::string source;
    };
    using LivePatternReader =
        std::function<size_t(uint64_t address, void* output, size_t size)>;
    using LivePatternSourceCurrent = std::function<bool()>;
    using LivePatternProgress =
        std::function<void(uint64_t completed, uint64_t total)>;

    // Win32-free scan core used by the LIVE jthread. Each bounded read owns a
    // non-overlap prefix and includes only enough lookahead for boundary starts.
    // False means cooperative cancellation; target/session failures are returned
    // as a publishable WorkerResult error.
    static bool scanLivePatternRanges(
        const std::vector<LivePatternRange>& ranges,
        const SigPattern& pattern, std::string_view patternText,
        const LivePatternReader& reader,
        const LivePatternSourceCurrent& sourceCurrent,
        const LivePatternProgress& progress, const std::stop_token& stop,
        WorkerResult& result, size_t hitCap, size_t chunkBytes);
    static std::string formatLiveCoverage(const WorkerResult& result,
                                          bool& partial);

    // Big enough to hold the largest signature buildSignature can hand off
    // (its 512-instruction x 16-byte cap -> ~24.5k chars of "XX " tokens), so a
    // multi-instruction "Create signature from selection" is never silently clipped.
    char patternInput_[32768] = "48 89 5C 24 ?? 57 48 83 EC 20";
    char sigName_[kMaxLibraryNameBytes + 1] = "fn_init";
    bool live_              = false;   // scan the attached process's memory instead of the file
    bool patternClipped_   = false;   // a handed-off signature was longer than patternInput_ (defensive; shows a warning)
    // Definitions survive restart; health and result ownership remain ephemeral.
    std::vector<Sig> sigs_;
    uint64_t libraryLastId_ = 0;
    uint64_t selectedSignatureId_ = 0;
    bool libraryStarted_ = false;
    bool libraryReady_ = false;
    bool libraryFailed_ = false;
    std::string libraryStatus_;
    std::optional<SignatureLibrary> libraryRetry_;
    struct LibraryIoResult {
        bool publish = false;
        bool failed = false;
        SignatureLibrary library;
        std::optional<SignatureLibrary> retry;
        std::string status;
    };
    // One bounded I/O operation at a time; it owns its complete input and never
    // accesses the UI or BinaryFile. Destruction joins before member storage dies.
    std::future<LibraryIoResult> libraryIo_;
    std::vector<Result>   results_;
    bool                  resultsLive_ = false;
    uint32_t              resultsLivePid_ = 0;
    uint64_t              resultsLiveGeneration_ = 0;
    DocumentResultIdentity staticResultsOwner_;
    bool                  truncated_ = false;   // results hit the display cap (4096)
    bool                  scanPartial_ = false; // LIVE map/read gaps or the result cap
    std::string           scanCoverageStatus_; // retained, truthful LIVE coverage summary
    std::vector<Function> functions_;
    DocumentResultIdentity functionsOwner_;
    Engine                functionsEngine_ = Engine::Zydis;
    Arch                  functionsArch_ = Arch::X64;
    DocumentResultIdentity healthOwner_;
    std::string           analyzeSummary_;
    std::string           workerStatus_;
    // Search indexes rebuild only when their publication or query changes.
    char                  resultFilter_[128] = "";
    char                  fnFilter_[128] = "";
    std::string           cachedResultFilter_;
    std::string           cachedFnFilter_;
    std::vector<int>      visibleResults_;
    std::vector<int>      visibleFunctions_;
    bool                  resultsFilterDirty_ = true;
    bool                  functionsFilterDirty_ = true;
    int                   selectedResult_ = -1;
    std::string           scanPattern_;
    std::string           scanTarget_;
    bool                  scanCompleted_ = false;
    int  requestedSub_ = -1;
    float progress_ = 0.0f;

    bool                  workerPending_ = false;
    WorkerKind            activeWorkerKind_ = WorkerKind::None;
    DocumentResultIdentity activeWorkerOwner_;
    uint32_t              activeLivePid_ = 0;
    uint64_t              activeLiveGeneration_ = 0;
    DecoderConfig         activeFunctionsDecoder_{};

    // Declared last: std::jthread requests stop and joins before the result
    // mutex/storage and UI-owned state above are destroyed.
    std::atomic<uint64_t> requestSerial_{0};
    std::atomic<uint64_t> workerDone_{0};
    std::atomic<uint64_t> workerTotal_{0};
    std::mutex            readyMutex_;
    std::optional<WorkerResult> ready_;
    std::jthread          worker_;
};

} // namespace ds
