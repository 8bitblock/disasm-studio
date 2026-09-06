#pragma once
#include "ITab.h"
#include "../Core/DocumentResultIdentity.h"
#include <atomic>
#include <mutex>
#include <optional>
#include <string>
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

    struct Result   {
        uint64_t address;
        std::string sig;
        std::string module;
        bool live = false; // result ownership is immutable; the toolbar may change later
    };
    struct Sig      {
        std::string name;
        std::string pattern;
        std::string health;
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
        uint64_t scannedBytes = 0;
    };

    // Big enough to hold the largest signature buildSignature can hand off
    // (its 512-instruction x 16-byte cap -> ~24.5k chars of "XX " tokens), so a
    // multi-instruction "Create signature from selection" is never silently clipped.
    char patternInput_[32768] = "48 89 5C 24 ?? 57 48 83 EC 20";
    char sigName_[64]       = "fn_init";
    bool live_              = false;   // scan the attached process's memory instead of the file
    bool patternClipped_   = false;   // a handed-off signature was longer than patternInput_ (defensive; shows a warning)
    // Starter example patterns; health/count are computed against the loaded binary.
    std::vector<Sig>      sigs_{
        { "fn_init",     "48 89 5C 24 ?? 57 48 83 EC 20", "?", -1 },
        { "g_world_ptr", "48 8B 05 ?? ?? ?? ?? 48 85 C0", "?", -1 },
        { "tick_hook",   "E8 ?? ?? ?? ?? 84 C0 74",       "?", -1 },
    };
    std::vector<Result>   results_;
    bool                  resultsLive_ = false;
    uint32_t              resultsLivePid_ = 0;
    uint64_t              resultsLiveGeneration_ = 0;
    DocumentResultIdentity staticResultsOwner_;
    bool                  truncated_ = false;   // results hit the display cap (4096)
    std::vector<Function> functions_;
    DocumentResultIdentity functionsOwner_;
    Engine                functionsEngine_ = Engine::Zydis;
    Arch                  functionsArch_ = Arch::X64;
    DocumentResultIdentity healthOwner_;
    std::string           analyzeSummary_;
    std::string           workerStatus_;
    char  fnFilter_[64] = "";
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
