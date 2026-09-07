#pragma once

#include "ITab.h"
#include "../Core/MemoryPointer.h"
#include "../Core/MemoryScan.h"
#include "../Core/MemoryTable.h"
#include "../Core/ProcessManager.h"
#include "../Core/ProcessMemorySession.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ds {

// A live-memory workbench with a non-invasive process connection as its normal
// path and an identity-checked Debugger bridge when a debug session is active.
// Expensive scans and pointer searches own immutable inputs on worker threads;
// the render path only consumes completed snapshots and small visible pages.
class MemoryToolsTab final : public ITab {
public:
    MemoryToolsTab();
    ~MemoryToolsTab() override;

    const char* name() const override { return "Memory Tools"; }
    void render(AppContext& ctx) override;

private:
    enum class TargetSource : uint8_t { None, Debugger, Passive };
    struct TargetToken {
        TargetSource source = TargetSource::None;
        uint32_t pid = 0;
        uint64_t generation = 0;
        uint64_t creationTime = 0;
        bool is32 = false;
        bool canWrite = false;
        bool paused = false;
        std::string name;
        std::string path;

        bool valid() const noexcept;
        bool sameSession(const TargetToken& other) const noexcept;
    };

public:
    // Public projections keep the pure filter/format helpers outside the class
    // without exposing any process handle or mutation authority.
    struct TargetRegion {
        uint64_t base = 0;
        uint64_t size = 0;
        uint64_t allocationBase = 0;
        uint32_t protect = 0;
        uint32_t state = 0;
        uint32_t type = 0;
        bool readable = false;
        bool writable = false;
        bool executable = false;
        bool copyOnWrite = false;
        bool guarded = false;
        bool noAccess = false;
    };

    struct ScanScope {
        bool includePrivate = true;
        bool includeImage = true;
        bool includeMapped = true;
        bool writableOnly = false;
        bool excludeExecutable = false;
        bool hasStart = false;
        bool hasEnd = false; // inclusive in the UI
        uint64_t start = 0;
        uint64_t end = UINT64_MAX;
        uint64_t maxBytes = 512ull << 20;
        uint64_t requestedMaxBytes = 512ull << 20;
        bool memoryAdmissionLimited = false;
    };

private:
    struct ScanCompletion {
        std::shared_ptr<MemoryScanSnapshot> snapshot;
        MemoryScanConfig config;
        TargetToken owner;
        uint64_t epoch = 0;
        uint64_t bytesRead = 0;
        uint64_t bytesAttempted = 0;
        size_t unreadableChunks = 0;
        size_t partialChunks = 0;
        bool coverageTruncated = false;
        bool adopt = false;
        std::string status;
        std::string mapWarning;
    };

    struct PointerRow {
        MemoryPointerChain chain;
        MemoryTableAddress address;
        bool moduleRoot = false;
        std::string rootLabel;
    };

    struct PointerCompletion {
        std::vector<PointerRow> rows;
        TargetToken owner;
        uint64_t epoch = 0;
        uint64_t bytesRead = 0;
        bool coverageTruncated = false;
        std::string status;
    };

    struct TableRow {
        uint64_t id = 0;
        MemoryTableRecord record;
        TargetToken absoluteOwner;
        std::string currentText;
        std::string status;
        uint64_t resolvedAddress = 0;
        bool resolved = false;
        bool writeOk = false;
        double lastReadAt = 0.0;
    };

    struct FreezeRowPlan {
        uint64_t id = 0;
        MemoryTableRecord record;
        TargetToken absoluteOwner;
    };
    struct FreezePlan {
        uint64_t revision = 0;
        Debugger* debugger = nullptr;
        ProcessMemorySession* passive = nullptr;
        ProcessManager* processManager = nullptr;
        TargetToken target;
        std::vector<FreezeRowPlan> rows;
        uint32_t intervalMs = 200;
    };
    struct FreezeRowResult {
        uint64_t id = 0;
        bool ok = false;
        bool wrote = false;
        bool resolved = false;
        uint64_t address = 0;
        std::string status;
    };
    struct FreezeCompletion {
        uint64_t revision = 0;
        TargetToken owner;
        std::vector<FreezeRowResult> rows;
    };

    // Target/session --------------------------------------------------------
    TargetToken currentTarget(AppContext& ctx);
    void handleTargetTransition(const TargetToken& target);
    void renderTargetBar(AppContext& ctx, const TargetToken& target);
    void renderProcessPicker(AppContext& ctx);
    void refreshProcessList();
    void refreshRegionCache(AppContext& ctx, const TargetToken& target);
    bool refreshPassiveModules(const TargetToken& target, double refreshedAt);
    std::vector<MemoryTableModuleView> modulesFor(
        AppContext& ctx, const TargetToken& target) const;
    static size_t readTarget(Debugger* debugger, ProcessMemorySession* passive,
                             const TargetToken& target, uint64_t address,
                             void* output, size_t size, std::string* error = nullptr);
    static bool writeTarget(Debugger* debugger, ProcessMemorySession* passive,
                            const TargetToken& target, uint64_t address,
                            const std::vector<uint8_t>& bytes,
                            bool allowProtectionChange, std::string& error);
    static std::vector<TargetRegion> collectRegions(
        Debugger* debugger, ProcessMemorySession* passive,
        const TargetToken& target, std::string& error);

    // Scanner ---------------------------------------------------------------
    void renderScanner(AppContext& ctx, const TargetToken& target);
    bool buildScanConfig(bool first, MemoryScanConfig& config,
                         std::string& error) const;
    bool buildScanScope(ScanScope& scope, std::string& error) const;
    void firstScan(AppContext& ctx, const TargetToken& target);
    void nextScan(AppContext& ctx, const TargetToken& target);
    void cancelScan();
    void pumpScanCompletion();
    void clearScan(const char* status = nullptr);
    void rebuildScanPage();
    bool applyScanPreset(const MemoryScanValue& value);

    // Viewer / region browser / pointer scanner ----------------------------
    void renderInspector(AppContext& ctx, const TargetToken& target);
    void renderHexViewer(AppContext& ctx, const TargetToken& target);
    void renderRegionBrowser(AppContext& ctx, const TargetToken& target);
    void renderPointerScanner(AppContext& ctx, const TargetToken& target);
    void refreshViewer(AppContext& ctx, const TargetToken& target, bool force);
    void navigateViewer(uint64_t address, bool recordHistory = true,
                        uint32_t selectionBytes = 1);
    void consumeMemoryRequest(AppContext& ctx, const TargetToken& target);
    void startPointerScan(AppContext& ctx, const TargetToken& target);
    void cancelPointerScan();
    void pumpPointerCompletion();

    // Address table / continuous freeze ------------------------------------
    void renderAddressTable(AppContext& ctx, const TargetToken& target);
    void addAddressRow(AppContext& ctx, const TargetToken& target,
                       uint64_t address, MemoryValueType type,
                       const std::vector<uint8_t>* captured = nullptr,
                       const char* description = "address");
    void addPointerRow(AppContext& ctx, const TargetToken& target,
                       const PointerRow& pointer);
    bool resolveRow(AppContext& ctx, const TargetToken& target,
                    TableRow& row, uint64_t& address, std::string& error);
    void publishFreezePlan(AppContext& ctx, const TargetToken& target);
    void freezeWorkerLoop();
    void pumpFreezeCompletion();
    bool saveTableDialog(const TargetToken& target);
    bool loadTableDialog();

    // Passive target state.
    ProcessMemorySession passive_;
    ProcessManager processManager_;
    TargetSource targetSource_ = TargetSource::None;
    TargetToken lastTarget_;
    std::vector<ProcessInfo> processes_;
    std::vector<ModuleInfo> passiveModules_;
    double passiveModulesLastRefresh_ = 0.0;
    char processFilter_[128]{};
    int selectedProcess_ = -1;
    bool processPickerOpen_ = false;
    std::string targetStatus_;

    // Region snapshot shared by browser/filter UI (scan jobs capture their own).
    std::vector<TargetRegion> regionCache_;
    TargetToken regionOwner_;
    std::string regionStatus_;
    char regionFilter_[128]{};
    bool regionReadableOnly_ = false;
    bool regionWritableOnly_ = false;
    bool regionExecutableOnly_ = false;

    // Scan controls and immutable result snapshot.
    int valueKind_ = 2; // 1/2/4/8 byte, float, double, AOB, UTF-8, UTF-16
    bool signedIntegers_ = true;
    bool scanHex_ = false;
    bool nullTerminateText_ = false;
    int scanMode_ = static_cast<int>(MemoryScanMode::Exact);
    char scanValue_[512] = "100";
    char scanValue2_[512]{};
    bool floatTolerance_ = false;
    float absoluteTolerance_ = 0.0001f;
    int alignment_ = 1;
    bool scanPrivate_ = true;
    bool scanImage_ = true;
    bool scanMapped_ = true;
    bool scanWritableOnly_ = false;
    bool scanExcludeExecutable_ = false;
    char scanStart_[32]{};
    char scanEnd_[32]{};
    int scanMaxMiB_ = 512;
    std::shared_ptr<MemoryScanSnapshot> scanSnapshot_;
    MemoryScanConfig scanShape_{};
    bool firstScanDone_ = false;
    uint64_t scanPageStart_ = 0;
    size_t scanPageSize_ = 250;
    MemoryScanPage scanPage_;
    struct ScanLiveRow {
        uint64_t tick = UINT64_MAX;
        std::vector<uint8_t> bytes;
        bool complete = false;
    };
    std::vector<ScanLiveRow> scanLiveRows_;
    TargetToken scanLiveOwner_;
    uint64_t scanLiveRevision_ = UINT64_MAX;
    uint64_t scanLivePageStart_ = UINT64_MAX;
    uint64_t scanRevision_ = 0;
    uint64_t scanPageRevision_ = UINT64_MAX;
    uint64_t scanPageCachedStart_ = UINT64_MAX;
    std::string scanStatus_;
    std::string scanMapWarning_; // retained across refinements of the same scope
    std::thread scanThread_;
    std::atomic<bool> scanRunning_{false};
    std::atomic<bool> scanCancel_{false};
    std::atomic<uint64_t> scanProgress_{0};
    std::atomic<uint64_t> scanTotal_{0};
    std::atomic<uint64_t> scanMatches_{0};
    std::mutex scanMutex_;
    ScanCompletion scanCompletion_;
    bool scanCompletionReady_ = false;
    uint64_t scanEpoch_ = 1;

    // Inspector state.
    int inspectorTab_ = 0;
    int inspectorSelectRequest_ = -1;
    char viewAddress_[32] = "0";
    uint64_t viewBase_ = 0;
    bool viewBaseValid_ = false;
    TargetToken viewOwner_;
    std::array<uint8_t, 256> viewBytes_{};
    std::array<uint8_t, 256> viewPrevious_{};
    size_t viewBytesRead_ = 0;
    bool viewHavePrevious_ = false;
    bool viewAutoRefresh_ = true;
    bool viewNeedsRefresh_ = true;
    double viewLastRefresh_ = 0.0;
    int viewSelectionBegin_ = -1;
    int viewSelectionEnd_ = -1;
    char viewEdit_[1024]{};
    std::vector<uint64_t> viewHistory_;
    size_t viewHistoryIndex_ = 0;

    // Pointer scan state.
    char pointerTarget_[32]{};
    int pointerDepth_ = 4;
    int pointerMaxOffset_ = 4096;
    int pointerMaxMiB_ = 256;
    bool pointerStaticRootsOnly_ = true;
    bool pointerWritableOnly_ = false;
    std::vector<PointerRow> pointerRows_;
    std::string pointerStatus_;
    std::thread pointerThread_;
    std::atomic<bool> pointerRunning_{false};
    std::atomic<bool> pointerCancel_{false};
    std::atomic<uint64_t> pointerProgress_{0};
    std::atomic<uint64_t> pointerTotal_{0};
    std::mutex pointerMutex_;
    PointerCompletion pointerCompletion_;
    bool pointerCompletionReady_ = false;
    uint64_t pointerEpoch_ = 1;

    // Address table and always-on freeze scheduler.
    std::vector<TableRow> table_;
    uint64_t nextTableId_ = 1;
    char newAddress_[32]{};
    uint32_t freezeIntervalMs_ = 200;
    std::thread freezeThread_;
    std::atomic<bool> freezeStop_{false};
    std::mutex freezeMutex_;
    std::condition_variable freezeCv_;
    FreezePlan freezePlan_;
    uint64_t freezePlanRevision_ = 0;
    uint64_t freezePlanFingerprint_ = 0;
    FreezeCompletion freezeCompletion_;
    bool freezeCompletionReady_ = false;

    float scannerWidth_ = 0.0f;
    float upperHeight_ = 0.0f;
    int compactUpperView_ = 0;
    bool compactUpperLayout_ = false;
};

} // namespace ds
