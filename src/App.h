#pragma once
//
// App.h
// Top-level application shell: owns shared state (loaded binary, debug
// controller, active disassembler engine) and the collection of tabs. Renders
// the menu bar, the debug-control toolbar, and the docked tab windows.
//
#include <memory>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "Core/AnalysisService.h"
#include "Core/BinaryFile.h"
#include "Core/CodeExport.h"
#include "Core/Debugger.h"
#include "Core/DocumentContext.h"
#include "Core/DocumentResultIdentity.h"
#include "Core/DllDebugPlan.h"
#include "Core/FirmwareSniffer.h"
#include "Core/JavaScan.h"
#include "Core/JdwpClient.h"
#include "Core/InvestigationService.h"
#include "Core/LiveScanService.h"
#include "Core/MemoryScan.h"
#include "Core/ModuleRegistry.h"
#include "Core/PassiveDump.h"
#include "Core/PeUnpack.h"
#include "Core/Preferences.h"
#include "Core/Project.h"
#include "Core/RuntimeScan.h"
#include "Core/StaticUnpack.h"
#include "Core/SymbolResolver.h"
#include "Core/UnpackEngine.h"
#include "Disasm/DisassemblerFactory.h"
#include "Disasm/JvmDisassembler.h"   // AttachJvmClass (JavaClass symbolication)
#include "Ui/CommandPalette.h"
#include "Ui/Theme.h"

namespace ds {

class ITab;
class BinaryViewTab;
class BinaryViewHostTab;

// Programmatic destinations inside Binary View's crackme-triage workspace.
// Keeping this small routing enum in the shell avoids coupling the command
// palette, Binary Tech, Cortex, and Communications to BinaryViewTab internals.
enum class TriageWorkspaceView : uint8_t {
    StartHere = 0,
    NetworkTrail,
    Authorization,
    Strings,
    Functions,
    Runtime,
};

// Why a mapped module document was queued. Manual module browsing has no shell
// reconciliation state; the two automatic paths publish completion only after
// the frame-boundary document transaction succeeds.
enum class LiveDocumentOpenOrigin : uint8_t {
    Manual = 0,
    AttachMain,
    HostedDll,
};

// One-shot, identity-bound navigation into the live-memory workbench. Ordinary
// callers only select bytes in the viewer. An explicit scan-preparation action
// may additionally supply a typed value; Memory Tools applies it only after the
// same debugger PID/session has been revalidated and never starts a scan itself.
struct MemoryToolsRequest {
    bool                pending = false;
    uint64_t            address = 0;
    DebugTargetIdentity target{};
    uint32_t            selectionBytes = 1;
    bool                prepareScan = false;
    MemoryScanValue     scanValue;
};

// Convert a captured canonical GML numeric payload into the exact value type
// understood by Memory Tools. The flags/type tag beside the payload remain
// inspection evidence and are intentionally not part of the typed scan needle.
bool BuildGmlMemoryScanPreset(const GmlHelperNumericSlot& slot,
                              MemoryScanValue& value,
                              uint32_t& selectionBytes);

// Shared, app-wide state passed by reference to every tab.
struct AppContext {
    AppContext();
    ~AppContext();

    AppContext(const AppContext&) = delete;
    AppContext& operator=(const AppContext&) = delete;

    Debugger                       debug;
    bool                           gmlExecutionMode = false;
    bool                           gmlAutoFollow = true;
    GmlPauseIdentity               gmlFollowedStop{};
    bool                           requestedGameMakerConnection = false;
    // Borrowed for the duration of App::render(): lets the active tab reuse the
    // toolbar/status snapshot instead of deep-copying debugger vectors again.
    // Null outside rendering (and in standalone tab tests).
    const DbgSnapshot*             frameDebugSnapshot = nullptr;
    // Borrowed alongside frameDebugSnapshot for one App::render() call. Trace
    // snapshots can contain tens of thousands of hit records, so the toolbar,
    // status bar, and Binary View share this one copy instead of each locking and
    // copying the debugger's coverage store independently.
    const TraceCoverageSnapshot*   frameTraceCoverageSnapshot = nullptr;
    // Live-memory scan worker pool (process string scan / xref sweep / module-image
    // reads, off the render thread). Declared AFTER `debug` so its dtor joins the
    // workers before the Debugger — whose readMemoryMasked the workers call — is gone.
    LiveScanService                livescan{ [](const DecoderConfig& config) {
        return MakeDisassembler(config);
    } };
    std::string                    requestedTab;
    int                            requestedWorkflow = -1; // Analyze / Debug / Memory / Compare
    uint32_t                       navigatorOptionalMask = 0;
    bool                           analysisQueueCollapsed = false;
    bool                           workbenchPrefsDirty = false;
    bool                           requestedTypeWorkbench = false;
    bool                           requestedLiveAssembly = false;
    bool                           requestedCrackmeTriage = false;
    TriageWorkspaceView            requestedTriageView = TriageWorkspaceView::StartHere;
    // Opaque producer-stable identity used to focus one complete authorization
    // chain after a Ctrl+K handoff. Empty opens the view without selection.
    std::string                    requestedTriageAuthorizationFlow;
    bool                           requestedTriageStartupEntitlementLead = false;
    uint64_t                       requestedTriageFileOffset = 0;
    bool                           requestedTriageFileOffsetValid = false;
    bool                           requestedLiveObservation = false;
    // Identity captured when Triage/Ctrl+K hands the analyst to Server Watch.
    // Communications must not silently observe an unrelated attached process.
    DocumentId                     requestedLiveObservationDocument{};
    uint64_t                       requestedLiveObservationImageGeneration = 0;
    bool                           requestResetDockLayout = false; // View > Reset Layout, consumed by Binary View's dockspace
    bool                           requestedExportAnalysis = false; // File > Export Analysis, consumed by Binary View
    bool                           requestedCodeExport    = false; // File > Save ASM/C, consumed by Binary View
    CodeExportFormat               requestedCodeExportFormat = CodeExportFormat::Assembly;
    bool                           requestedTraceToggle   = false; // toolbar/menu/palette -> Binary View seed planner
    DebugTargetIdentity            requestedTraceTarget{};         // debugger owner captured with trace request
    bool                           requestedTraceClear    = false;
    DebugTargetIdentity            requestedTraceClearTarget{};
    bool                           requestedTraceCancel   = false;
    DebugTargetIdentity            requestedTraceCancelTarget{};
    // A DLL cannot be passed directly to CreateProcess. The same request flag is
    // raised by the menu, toolbar, command palette, and Binary View's Run button;
    // App consumes it by opening the hosted-DLL launch modal.
    bool                           requestedDebugDll      = false;
    // Communications can ask the app-owned passive-dump modal to target a
    // selected PID without coupling that tab to file dialogs or worker lifetime.
    bool                           requestedPassiveDump   = false;
    uint32_t                       requestedPassiveDumpPid = 0;
    // The Binary View builds trace breakpoint sites in small bounded slices from
    // its already-indexed listing. These mirrors let the global status bar expose
    // that pre-planting phase without reaching into tab-private state.
    bool                           traceSeedPlanning      = false;
    size_t                         traceSeedCurrent       = 0;
    size_t                         traceSeedTotal         = 0;
    size_t                         traceSeedFound         = 0;
    bool                           binaryJustLoaded      = false; // set on load, consumed by Binary View
    uint64_t                       requestedGotoVA       = 0;     // cross-tab "view this address" request
    bool                           hasGotoRequest        = false; // distinguishes "go to VA 0" from "no request"
    bool                           requestedGotoLive     = false; // goto target is a runtime VA -> open the live view (no file-VA translation)
    DebugTargetIdentity            requestedGotoTarget{};         // owner of a LIVE goto; empty for FILE requests
    MemoryToolsRequest             requestedMemory;              // one-shot live viewer / explicit scan-preparation handoff
    std::string                    pendingSignature;             // Binary View -> Sig Scanner pattern handoff
    bool                           pendingSignatureLive  = false; // pendingSignature was built from live process memory -> scan live, not the file
    DocumentResultIdentity         pendingSignatureOwner;        // exact source for static handoffs; empty for live handoffs
    DebugTargetIdentity            pendingSignatureTarget{};     // exact debugger session for live handoffs

    void clearPendingSignature() {
        pendingSignature.clear();
        pendingSignatureLive = false;
        pendingSignatureOwner = {};
        pendingSignatureTarget = {};
    }

    // Live JVM debugger (JDWP over a socket): attach via the Communications
    // tab's "Java debug (JDWP)" console. Independent of `debug` (the Win32
    // debugger) — a JVM target can have both attached at once (native frames
    // via debug, bytecode-level control via jdwp).
    JdwpClient                     jdwp;
    // PID of the JVM the JDWP session is attached to (0 = none). JDWP itself is a
    // socket and carries no PID, so the inject path records it here so other views
    // (e.g. the Connections tab's "attached process only") can scope to it.
    uint32_t                       jdwpTargetPid = 0;

    bool                           requestedExtractJava  = false; // banner button -> App::extractEmbeddedJar (same pattern as requestedExportAnalysis)
    bool                           requestedBrowseArchive = false; // banner/menu -> App opens the archive-entries popup

    // PDB/symbol-server policy is app-wide and persisted in prefs.ini. Network
    // is deliberately false by default; Binary View applies revisions to its
    // asynchronous symbol worker without ever resolving on the render thread.
    SymbolResolverOptions          symbolOptions;
    uint64_t                       symbolOptionsRevision = 1;
    bool                           requestedSymbolSettings = false;

    // A tab sets this true during render() when it needs the UI to keep redrawing
    // even while idle (e.g. the live connection monitor's auto-refresh). Reset to
    // false at the top of every App::render(), so only a tab rendered this frame
    // can keep it on. Read by App::wantsContinuousRedraw().
    bool                           wantContinuousRedraw = false;

    // Binary View cursor, mirrored here each frame so the status bar can show it
    // (the tab's cursorVA_ is private). cursorFuncName is the enclosing function.
    uint64_t                       cursorVA       = 0;
    bool                           hasCursor      = false;
    bool                           cursorLive     = false; // cursorVA is a debugger-session VA, not a FILE VA
    DebugTargetIdentity            cursorTarget{}; // owner of cursorVA when cursorLive
    std::string                    cursorFuncName;
    // Runtime (ASLR-translated) cursor address for the debug toolbar's Run to Cursor.
    // Equals cursorVA in the static view; the live view sets it to the runtime VA.
    uint64_t                       runtimeCursorVA = 0;
    DebugTargetIdentity            runtimeCursorTarget{};

    // Ask the Binary View to focus an address (from another tab). Also switches
    // to the Binary View tab.
    void gotoAddress(uint64_t va) {
        requestedGotoVA = va;
        hasGotoRequest = true;
        requestedGotoLive = false;
        requestedGotoTarget = {};
        requestedTab = "Binary View";
    }

    // Like gotoAddress, but `va` is a live (ASLR-relocated) runtime address — e.g. a
    // live-mode Sig Scanner hit. The Binary View opens the live view at it instead of
    // feeding the runtime VA into the file-VA static listing (which would land on the
    // wrong bytes for a relocated process).
    void gotoAddressLive(uint64_t va, DebugTargetIdentity target) {
        requestedGotoVA = va;
        hasGotoRequest = true;
        requestedGotoLive = true;
        requestedGotoTarget = target;
        requestedTab = "Binary View";
    }
    void gotoAddressLive(uint64_t va) {
        const DbgSnapshot* snap = frameDebugSnapshot;
        gotoAddressLive(va, snap && snap->attached()
                              ? DebugTargetIdentity{snap->pid, snap->sessionGeneration}
                              : DebugTargetIdentity{});
    }

    // Send a runtime address to Memory Tools. Supplying the debugger identity
    // prevents a delayed UI request from being applied after detach/reattach.
    void openMemoryToolsAt(uint64_t va, uint32_t pid = 0,
                           uint64_t sessionGeneration = 0,
                           uint32_t selectionBytes = 1) {
        requestedMemory = {};
        requestedMemory.pending = true;
        requestedMemory.address = va;
        requestedMemory.target = { pid, sessionGeneration };
        requestedMemory.selectionBytes = selectionBytes ? selectionBytes : 1;
        requestedTab = "Memory Tools";
    }

    // Unlike openMemoryToolsAt, this explicitly replaces the scanner inputs.
    // Requiring a complete debugger identity prevents a delayed GML value from
    // being prepared against a different attachment.
    void prepareMemoryToolsScanAt(uint64_t va, DebugTargetIdentity target,
                                  MemoryScanValue value,
                                  uint32_t selectionBytes = 1) {
        if (!target.valid() || !value.valid()) return;
        requestedMemory = {};
        requestedMemory.pending = true;
        requestedMemory.address = va;
        requestedMemory.target = target;
        requestedMemory.selectionBytes = selectionBytes ? selectionBytes : 1;
        requestedMemory.prepareScan = true;
        requestedMemory.scanValue = std::move(value);
        requestedTab = "Memory Tools";
    }

    // A non-Binary-View workflow (currently explicit semantic-diff metadata
    // transfer) edited annotation maps directly in ProjectState. Binary View
    // consumes this edge before its next mirror-back so stale tab-local maps
    // cannot overwrite the accepted transfer.
    bool                           projectAnnotationsExternallyChanged = false;

    enum class ProjectSaveState : uint8_t { Clean, Dirty, Saving, Failed };
    ProjectSaveState               projectSaveState = ProjectSaveState::Clean;
    std::string                    projectSaveError;
    std::string                    projectSaveWarning;
    uint64_t                       projectRevision = 0;
    uint64_t                       projectSavedRevision = 0;
    std::chrono::steady_clock::time_point projectDirtySince{};
    std::future<ProjectSaveResult> projectSaveFuture;
    uint64_t                       projectSaveInFlightRevision = 0;
    DocumentSaveTicket             projectSaveInFlightTicket;
    uint64_t                       projectSaveInFlightSequence = 0;
    uint64_t                       projectSaveNextSequence = 1;
    uint64_t                       projectSaveCompletedSequence = 0;

    // Mutation sites call this after mirroring their state into `project`.
    // App::render debounces the actual flushed/atomic write so rapid edits do
    // not turn into one filesystem transaction per frame.
    void markProjectDirty();
    bool projectDirty() const;

    // All modules of the attached process (the whole app: EXE + DLLs), each loadable
    // from live memory into the disassembler.  Declaration order is load-bearing:
    // documents_ is destroyed first, moduleAnalysis_ joins second, and only then may
    // this registry release the mapped module images borrowed by that global pool.
    ModuleRegistry                 modules;

private:
    // Live-module analysis must never borrow the currently active document's
    // AnalysisService: changing/closing one static tab may cancel only that tab's
    // work.  This app-global pool instead borrows ModuleRegistry::LoadedModule::bin.
    AnalysisService                moduleAnalysis_;

    // Kept after moduleAnalysis_ and ModuleRegistry so static-document workers join
    // first. DocumentContext itself declares its workers after BinaryFile, so they
    // also join before their own static image storage is destroyed.
    DocumentManager                documents_;
    uint64_t                       moduleAnalysisDroppedSeen_ = 0;
    uint32_t                       moduleRegistryPid_ = 0;
    uint64_t                       moduleRegistrySessionGeneration_ = 0;
    bool                           moduleRegistrySessionValid_ = false;
    uint64_t                       documentRetryRevision_ = 1;

    DocumentContext& activeStaticDocument();
    const DocumentContext& activeStaticDocument() const;

public:
    // Active-document compatibility boundary used by existing tabs. The fixed
    // single-window shell switches this facade only at a frame boundary; each
    // owner and its workers remain in DocumentManager. Live services stay global.
    const BinaryFile& staticBinary() const { return activeStaticDocument().binary(); }
    const BinaryFile& staticBinary() { return activeStaticDocument().binary(); }
    ProjectState& staticProject() { return activeStaticDocument().projectForMirroring(); }
    const ProjectState& staticProject() const { return activeStaticDocument().project(); }
    AnalysisService& staticAnalysis() { return activeStaticDocument().analysis(); }
    const AnalysisService& staticAnalysis() const { return activeStaticDocument().analysis(); }
    DocumentAnalysisCache& staticAnalysisCache() { return activeStaticDocument().cache(); }
    DocumentNavigation& staticNavigation() { return activeStaticDocument().navigation(); }
    const DocumentAnalysisCache& staticAnalysisCache() const { return activeStaticDocument().cache(); }
    CodeExportService& staticCodeExport() { return activeStaticDocument().codeExport(); }
    IDisassembler* staticDisassembler() { return activeStaticDocument().decoder(); }
    const IDisassembler* staticDisassembler() const { return activeStaticDocument().decoder(); }
    Engine staticEngine() const { return activeStaticDocument().engine(); }
    Arch staticArch() const { return activeStaticDocument().arch(); }
    DecoderConfig staticDecoderConfig() const { return activeStaticDocument().decoderConfig(); }
    const JavaScanResult& staticJavaInfo() const { return activeStaticDocument().javaInfo(); }
    const RuntimeScanResult& staticRuntimeInfo() const { return activeStaticDocument().runtimeInfo(); }
    const FirmwareDetection& staticFirmwareInfo() const { return activeStaticDocument().firmwareInfo(); }
    const DocumentRuntimeMetadata& staticRuntimeMetadata() const {
        return activeStaticDocument().runtimeMetadata();
    }
    void setStaticDebugImageIdentity(
        DocumentRuntimeMetadata::LiveImageIdentity identity) {
        activeStaticDocument().setDebugImageIdentity(std::move(identity));
    }
    void invalidateStaticDebugImageIdentity() noexcept {
        activeStaticDocument().invalidateDebugImageIdentity();
    }
    DocumentId staticDocumentId() const { return activeStaticDocument().id(); }
    uint64_t staticImageGeneration() const { return activeStaticDocument().imageGeneration(); }
    uint64_t documentRetryRevision() const { return documentRetryRevision_; }

    struct StaticDocumentSummary {
        DocumentId  id;
        std::string title;
        std::string path;
        std::string format;
        bool        loaded = false;
        bool        mapped = false;
        bool        dirty = false;
        bool        active = false;
    };

    struct DocumentCommandOutcome {
        bool        hadCommand = false;
        bool        success = false;
        bool        activeChanged = false;
        bool        opened = false;
        bool        closed = false;
        bool        browseArchive = false;
        DocumentId  previous;
        DocumentId  current;
        DocumentId  retired;
        bool        liveModule = false;
        LiveDocumentOpenOrigin liveOrigin = LiveDocumentOpenOrigin::Manual;
        uint32_t    livePid = 0;
        uint64_t    liveSessionGeneration = 0;
        uint64_t    liveBase = 0;
        std::string error;
        std::string warning;
    };

    struct BinaryLoadPoll {
        bool completed = false;
        bool success = false; // candidate was staged as a document command
        bool cancelled = false;
        bool offerRaw = false;
        std::string path;
        std::string error;
    };

    using PrepareDocumentUi =
        std::function<bool(DocumentId, bool closing, std::string& error)>;

    // Topology mutations are queued while ImGui is rendering and applied once
    // the frame has released every tab-local reference. This is the narrow UI
    // facade over DocumentManager; callers never retain DocumentContext pointers.
    std::vector<StaticDocumentSummary> staticDocuments() const;
    size_t staticDocumentCount() const { return documents_.size(); }
    void setTypeDraftPending(DocumentId id, bool pending);
    bool commitTypeDefinition(DocumentId id, uint64_t imageGeneration,
        const TypeDefinition& definition, bool persist, std::string& error);
    bool queueActivateStaticDocument(DocumentId id);
    bool queueCloseStaticDocument(DocumentId id);
    bool documentCommandPending() const;
    const std::string& documentCommandError() const { return documentCommandError_; }
    DocumentCommandOutcome applyPendingDocumentCommand(
        const PrepareDocumentUi& prepareUi = {});
    bool beginBinaryLoadPath(const std::string& path);
    bool beginRawLoadPath(const std::string& path, uint64_t base, Arch arch,
                          uint64_t entryVA,
                          std::vector<AnalysisLandmark> landmarks,
                          FirmwareDetection firmware,
                          bool entryExplicit = true,
                          ByteOrder byteOrder = ByteOrder::Little,
                          bool riscvCompressed = true);
    void cancelBinaryLoad();
    BinaryLoadPoll pollBinaryLoad();
    bool binaryLoadPending() const { return binaryLoadFuture_.valid(); }

    bool setStaticDecoderConfiguration(Engine engine, Arch arch);
    bool setStaticDecoderConfiguration(const DecoderConfig& decoder);
    size_t writeStaticImage(uint64_t va, const uint8_t* bytes, size_t size) {
        return activeStaticDocument().writeImage(va, bytes, size);
    }
    bool commitStaticPatchedImage(
        std::vector<uint8_t>&& replacement,
        DocumentLiveImageCommit liveImageCommit) {
        return activeStaticDocument().commitPatchedImage(
            std::move(replacement), liveImageCommit);
    }
    bool clearStaticImage(std::string* error = nullptr);
    void rebuildDisassembler() {
        (void)setStaticDecoderConfiguration(staticEngine(), staticArch());
    }

    void openLiveAssemblyView() {
        requestedTab = "Binary View";
        requestedLiveAssembly = true;
    }

    void openCrackmeTriage(
        TriageWorkspaceView view = TriageWorkspaceView::StartHere) {
        requestedTriageView = view;
        requestedTriageAuthorizationFlow.clear();
        requestedTriageStartupEntitlementLead = false;
        requestedCrackmeTriage = true;
        requestedTriageFileOffsetValid = false;
        requestedTab = "Binary View";
    }

    void openCrackmeAuthorization(std::string flowId = {}) {
        openCrackmeTriage(TriageWorkspaceView::Authorization);
        requestedTriageAuthorizationFlow = std::move(flowId);
    }

    void openCrackmeStartupEntitlementLead() {
        openCrackmeAuthorization();
        requestedTriageStartupEntitlementLead = true;
    }

    void openCrackmeAuthorizationAtFileOffset(uint64_t fileOffset,
                                              std::string flowId = {}) {
        openCrackmeAuthorization(std::move(flowId));
        requestedTriageFileOffset = fileOffset;
        requestedTriageFileOffsetValid = true;
    }

    void openCrackmeTriageAtFileOffset(uint64_t fileOffset) {
        openCrackmeTriage(TriageWorkspaceView::NetworkTrail);
        requestedTriageFileOffset = fileOffset;
        requestedTriageFileOffsetValid = true;
    }

    void openLiveObservation() {
        if (staticBinary().loaded()) {
            requestedLiveObservationDocument = staticDocumentId();
            requestedLiveObservationImageGeneration = staticImageGeneration();
        } else {
            requestedLiveObservationDocument = {};
            requestedLiveObservationImageGeneration = 0;
        }
        requestedLiveObservation = true;
        requestedTab = "Communications";
    }

    bool binaryDebugArchitectureMatches() const {
        return (staticBinary().machine() == MachineArch::X86 && staticArch() == Arch::X86) ||
               (staticBinary().machine() == MachineArch::X64 && staticArch() == Arch::X64);
    }

    // Static breakpoint actions may also be prepared for a raw image, whose
    // architecture is explicitly chosen in Open as Raw and therefore has no
    // MachineArch header value.  Structured images must agree with their
    // recorded machine so changing only the decoder menu cannot expose x86
    // debugger operations for an ARM (or other non-x86) binary.
    bool debuggerActionsMatchImage() const {
        if (!ArchSupportsDebugger(staticArch())) return false;
        return staticBinary().format() == BinFormat::Raw || binaryDebugArchitectureMatches();
    }

    // Resolve the exact loaded module that corresponds to the active static
    // image. Both on-disk and mapped documents require a fresh validated
    // PID/session/base/path stamp; the on-disk stamp is granted only after
    // backing-file identity + byte equality checks. Both enforce target bitness.
    bool debuggerRuntimeImage(const DbgSnapshot& snap, uint64_t& baseOut,
                              uint64_t& sizeOut) const;
    // Checked file-VA -> runtime-VA translation through debuggerRuntimeImage.
    // Returns false instead of guessing when identity/range evidence is absent.
    bool debuggerStaticRuntimeVA(const DbgSnapshot& snap, uint64_t fileVA,
                                 uint64_t& runtimeVA) const;

    // True when Launch & Debug can hand the loaded binary to CreateProcess: a PE
    // image opened from disk. Live memory mappings have no launchable file behind
    // them, and Windows can't start ELF/Mach-O/.class/raw images directly.
    bool binaryLaunchable() const {
        return staticBinary().loaded() && !staticBinary().isMappedImage() &&
               (staticBinary().format() == BinFormat::PE32 || staticBinary().format() == BinFormat::PE32Plus) &&
               !staticBinary().isDll() && binaryDebugArchitectureMatches();
    }
    // Capture one coherent pre-launch proof for Authorization Watch: full
    // immutable analyzed bytes plus the exact identity of the handle whose
    // contents were compared. CREATE_PROCESS must validate both again.
    bool captureStaticAuthorizationWatchSourceEvidence(
        AuthorizationWatchPlan& plan) const;

    // True when the active file is a supported on-disk PE DLL. Detailed export,
    // entry-point, and bitness validation is presented by the launch modal.
    bool binaryDllDebuggable() const {
        return staticBinary().loaded() && !staticBinary().isMappedImage() && staticBinary().isDll() &&
               (staticBinary().format() == BinFormat::PE32 || staticBinary().format() == BinFormat::PE32Plus) &&
               binaryDebugArchitectureMatches();
    }

    // Launch the loaded binary under the debugger (break at entry) and open the
    // live view after exact-owner completion. The UI only enqueues startup.
    uint64_t debugLaunchRequest = 0;
    DocumentId debugLaunchDocument{};
    uint64_t debugLaunchImageGeneration = 0;

    uint64_t requestDebugLaunch(DbgLaunchRequest request, std::string& err) {
        const uint64_t id = debug.requestLaunch(std::move(request), &err);
        if (id) {
            debugLaunchRequest = id;
            debugLaunchDocument = staticDocumentId();
            debugLaunchImageGeneration = staticImageGeneration();
        }
        return id;
    }
    uint64_t requestDebugDllLaunch(DllDebugLaunchPlan plan, std::string& err) {
        const uint64_t id = debug.requestLaunchDll(std::move(plan), &err);
        if (id) {
            debugLaunchRequest = id;
            debugLaunchDocument = staticDocumentId();
            debugLaunchImageGeneration = staticImageGeneration();
        }
        return id;
    }
    bool debugLaunchSourceCurrent(uint64_t requestId) const {
        return requestId && requestId == debugLaunchRequest &&
            debugLaunchDocument == staticDocumentId() &&
            debugLaunchImageGeneration == staticImageGeneration();
    }

    // Shared toolbar / command palette / Binary View Run path. True means queued.
    bool launchAndDebug(std::string& err) {
        if (!binaryLaunchable()) {
            err = staticBinary().loaded() && !binaryDebugArchitectureMatches()
                ? std::string("the Win32 debugger requires a matching x86/x64 PE machine and decoder mode; active architecture is ") + ArchName(staticArch())
                : "the active image is not a launchable on-disk PE executable";
            return false;
        }
        DbgLaunchRequest request;
        request.executable = staticBinary().path();
        return requestDebugLaunch(std::move(request), err) != 0;
    }

    // Opens a Win32 file dialog and loads the chosen binary. Returns true on
    // success. Defined in App.cpp (uses commdlg). Callable from any tab.
    bool openBinaryDialog();

    // Load a binary by path (saving the current project first, picking the arch
    // from the file header, and loading any saved analysis). Shared by the file
    // dialog and the Projects tab. Returns false if the file can't be loaded.
    bool loadBinaryPath(const std::string& path);
    // Load a flat code blob with an explicit architecture and entry point. The
    // entry and named firmware landmarks are validated against the staged image
    // before the current target is replaced, including a legitimate VA 0 entry.
    bool loadRawPath(const std::string& path, uint64_t base, Arch a,
                     uint64_t entryVA,
                     std::vector<AnalysisLandmark> landmarks = {},
                     FirmwareDetection firmware = {},
                     bool entryExplicit = true,
                     ByteOrder byteOrder = ByteOrder::Little,
                     bool riscvCompressed = true);
    // Load one module of the attached process into the disassembler by reading its
    // mapped image straight from live memory (BinaryFile::loadFromMemory). Picks the
    // arch from the PE machine field, makes the module the active registry entry, and
    // triggers the normal load-time analysis. Not sidecar-persisted (live image).
    // Returns false if not attached or the image can't be read.
    bool loadLiveModule(uint64_t base, uint64_t size, const std::string& name,
                        const std::string& path = {},
                        LiveDocumentOpenOrigin origin =
                            LiveDocumentOpenOrigin::Manual);
    // Kick off background analysis of a registry module whose image is already loaded
    // (its `bin` populated, e.g. by an "analyze all modules" ReadImage). Tags the job
    // with the module base so its results route to the registry's per-module cache.
    void analyzeModule(LoadedModule& m, bool guess);
    // Adopt global module results every App frame, independent of which document
    // or workbench tab is visible. Failures remain on the registry entry and are
    // also surfaced as a toast.
    void drainModuleAnalysisResults();
    bool moduleAnalysisPending() const { return moduleAnalysis_.bulkPending(); }
    ProgressSnapshot moduleAnalysisProgress() const { return moduleAnalysis_.progress(); }
    size_t moduleAnalysesInFlight() const;
    void cancelModuleAnalysisPending();
    void cancelModuleAnalysisAndWait();
    void clearModules();
    void removeModuleByBase(uint64_t base);
    void synchronizeModuleSession(const DbgSnapshot& snapshot);

    // Persist the current project to its sidecar (no-op if nothing is loaded).
    // The debounced path starts and polls an immutable worker-owned snapshot;
    // close/switch/shutdown joins it so state is never discarded on failure.
    bool beginProjectSave();
    void pollProjectSave();
    bool saveProject();

    // Open a Save dialog (Markdown / HTML) and write the chosen analysis report.
    // The format is picked from the chosen file's extension. Returns true on
    // success; `msg` receives a human-readable result. Defined in App.cpp (commdlg).
    bool exportAnalysisFile(const std::string& defaultBaseName,
                             const std::string& markdown, const std::string& html,
                             std::string& msg);

    // Pick the destination for a background ASM/C export. This only runs the native
    // save dialog; CodeExportService performs generation and file I/O afterward.
    bool selectCodeExportPath(const std::string& defaultName, CodeExportFormat format,
                              std::string& pathOut, std::string& err);

    // Open a Save dialog and write raw bytes to the chosen file. Used by the
    // Resources tab to dump a resource verbatim or save a reconstructed
    // .bmp/.ico. `filterSpec`/`defExt` are Win32 GetSaveFileName strings (a null
    // filter falls back to All Files). Returns true on success; `msg` gets a
    // human-readable result. Defined in App.cpp (commdlg).
    bool saveBytesFile(const std::string& defaultName, const std::vector<uint8_t>& bytes,
                       std::string& msg,
                       const wchar_t* filterSpec = nullptr, const wchar_t* defExt = nullptr,
                       std::string* savedPath = nullptr);

private:
    enum class PendingDocumentKind : uint8_t { Open, Activate, Close };
    struct PendingDocumentCommand {
        PendingDocumentKind kind = PendingDocumentKind::Activate;
        DocumentId id;
        std::string title;
        BinaryFile image;
        ProjectState project;
        DecoderConfig decoder;
        DocumentInstallPersistence persistence =
            DocumentInstallPersistence::DurableSnapshot;
        DocumentRuntimeMetadata metadata;
        bool browseArchive = false;
        bool ignoredInvalidRawProject = false;
        std::string projectLoadWarning;
        bool liveModule = false;
        uint32_t livePid = 0;
        uint64_t liveSessionGeneration = 0;
        uint64_t liveBase = 0;
        uint64_t liveSize = 0;          // captured byte span (bounded)
        uint64_t liveReportedSize = 0;  // SizeOfImage from debugger module record
        uint64_t liveLoadGeneration = 0;
        std::string liveName;
        std::string livePath;
        LiveDocumentOpenOrigin liveOrigin = LiveDocumentOpenOrigin::Manual;
    };

    struct RawLoadSelection {
        Arch arch = Arch::X64;
        uint64_t entryVA = 0;
        bool entryExplicit = true;
        ByteOrder byteOrder = ByteOrder::Little;
        bool riscvCompressed = true;
        std::vector<AnalysisLandmark> landmarks;
        FirmwareDetection firmware;
    };

    struct BinaryLoadCandidate {
        bool success = false;
        bool cancelled = false;
        bool offerRaw = false;
        std::string path;
        std::string error;
        BinaryFile image;
        DocumentRuntimeMetadata metadata;
        bool browseArchive = false;
        bool ignoredInvalidRawProject = false;
        std::string projectLoadWarning;
        std::optional<RawLoadSelection> rawSelection;
    };

    bool queueDocumentOpen(PendingDocumentCommand command);
    static BinaryLoadCandidate buildBinaryLoadCandidate(
        const std::string& path,
        const std::shared_ptr<std::atomic_bool>& cancelled = {});
    static BinaryLoadCandidate buildRawLoadCandidate(
        const std::string& path, uint64_t base, RawLoadSelection selection,
        const std::shared_ptr<std::atomic_bool>& cancelled = {});
    bool stageBinaryLoadCandidate(BinaryLoadCandidate candidate);
    void prepareProjectSaveSnapshot();
    bool finishProjectSave(bool wait);
    bool prepareStaticDocumentTransition(std::string* error = nullptr);
    void resetProjectSaveMirrorFromActive();
    // After binary is loaded: hash it, pull any saved sidecar into `project`,
    // and stamp fresh metadata. Resets `project` when there is no sidecar. When
    // `applySavedArchEngine` is true, a saved engine/arch choice is reapplied to
    // the live context (so a binary reopens as last analyzed); the raw-load path
    // passes false so the arch the user just picked in the dialog wins.
    ProjectState projectForBinary(const BinaryFile& binary, Engine& engine,
                                  Arch& arch, bool applySavedArchEngine = true,
                                  bool loadSavedState = true,
                                  std::string* loadWarning = nullptr) const;

    std::optional<PendingDocumentCommand> pendingDocumentCommand_;
    std::string documentCommandError_;
    std::future<BinaryLoadCandidate> binaryLoadFuture_;
    std::shared_ptr<std::atomic_bool> binaryLoadCancelled_;
    std::string binaryLoadPath_;
};

class App {
public:
    // `startupPath` is the optional file supplied as the first command-line
    // argument (`DisasmStudio <path>`). It is loaded through the same path as
    // File > Open so architecture selection, sidecars, and background analysis
    // stay identical regardless of how the file was opened.
    explicit App(std::string startupPath = {});
    ~App();

    void render();              // called once per frame
    bool wantsExit() const { return exit_; }
    // File > Exit and the native close button share the same loss-preventing
    // project flush. A failed save leaves the window open.
    void requestExit();

    // True when the UI should keep redrawing every frame rather than sleeping until
    // the next input event: background analysis / live-scan in progress (progress
    // spinners + incoming results), or an active debug session (async state changes
    // + the pulsing RIP/selection highlight). Drives the main loop's idle throttle.
    // Non-const: Debugger::snapshot() takes a lock.
    bool wantsContinuousRedraw();

    // Main-window WM_NCHITTEST consults the empty gap in the integrated
    // brand/menu/caption row. Coordinates are Win32 screen pixels; menus and
    // caption buttons are deliberately excluded by renderMenuBar().
    bool mainTitleBarDragHit(int screenX, int screenY) const {
        return titleDragRegionValid_ &&
               screenX >= titleDragMinX_ && screenX < titleDragMaxX_ &&
               screenY >= titleDragMinY_ && screenY < titleDragMaxY_;
    }

private:
    void renderDocumentStrip();
    void applyPendingDocumentCommand();
    void retireActiveDocumentRequests();
    void renderMenuBar();
    void renderDebugToolbar(const DbgSnapshot& snap);
    void resolveWorkbenchNavigation();                 // apply requests/shortcuts before drawing the strip
    void renderMainWindow(const DbgSnapshot& snap);
    void renderTabCardStrip(const DbgSnapshot& snap);  // contiguous primary workbench navigation
    void renderStatusBar(const DbgSnapshot& snap);
    void openCommandPalette(const DbgSnapshot& snap);  // build the Ctrl+K action list + symbol snapshot
    void maintainInvestigationWorkspace();             // sliced snapshot -> background omnibox index
    void rememberInvestigationQuery(std::string query,
                                    InvestigationIdentity identity);
    void renderHelpWindow();                            // grouped F1 shortcut / interaction reference
    void openFileDialog();
    void openRawFileDialog();   // pick a file, then prompt for base + arch
    bool prepareRawLoadPath(const std::string& path);
    void renderRawLoadPopup();
    void renderDllDebugPopup();
    void renderUnpackPopup();
    void beginUnpackObservation();
    void sampleUnpackObservation();
    void rebuildUnpackImage(uint64_t oep, bool hasOep);
    bool saveUnpackArtifacts(bool loadAfterSave);
    void renderStaticUnpackPopup();
    bool saveStaticUnpackArtifact(int artifactKind, bool loadAfterSave);
    void renderPassiveDumpPopup();
    void browsePassiveExecutable();
    bool savePassiveDumpArtifacts(bool loadAfterSave);
    void renderAntiDebugPopup();
    void renderSymbolSettingsPopup();
    void browseDllCustomHost();
    void saveBinaryAs();        // splice accumulated patches into a copy on disk (result -> toast)
    void extractEmbeddedJar();  // carve ctx_.javaInfo's jar/zip span to a file (result -> toast)
    void openArchiveBrowser();  // snapshot ctx_.javaInfo's archive into archiveBrowser_ + open the popup
    void renderArchiveBrowser(); // "Archive Entries" modal: list / open-as-binary / extract one entry
    void extractArchiveEntryToFile(const JavaZipEntry& e);  // Save dialog writing the DECOMPRESSED entry bytes
    void loadPrefs();           // validated primary / .bak recovery from %APPDATA%
    bool savePrefs();           // flushed atomic replace; false stays visible in status
    void setUiZoomPercent(int percent);
    void closeBinary();         // flush + unload the current binary (menu / file tab / palette)

    AppContext                          ctx_;
    TraceCoverageSnapshot               traceSnapshot_; // retained across unchanged frames
    std::vector<std::unique_ptr<ITab>>  tabs_;
    BinaryViewHostTab*                  binaryView_ = nullptr;  // per-document Binary View owner + investigation source
    InvestigationService                investigation_;         // sole worker for unified index build/query
    ui::CommandPalette                  palette_;               // Ctrl+K command palette
    std::vector<InvestigationRecentQuery> investigationRecentQueries_;
    uint64_t                            investigationRecentRevision_ = 1;
    uint64_t                            investigationSubmittedGeneration_ = 0;
    DebugTargetIdentity                 investigationSubmittedLiveTarget_{};
    int                                 activeTab_ = 0;   // index into tabs_ (primary strip selection)
    uint64_t                            lastDebugLifecycleCompletion_ = 0;
    DebugTargetIdentity                 suppressedLaunchNavigation_{};
    bool                                exit_      = false;
    bool                                showDemo_  = false;
    bool                                showHelp_  = false;
    bool                                showAbout_ = false;
    theme::ThemeId                      theme_     = theme::ThemeId::Midnight;
    theme::Density                      density_   = theme::Density::Compact;
    bool                                prefsSaveFailed_ = false;
    std::string                         prefsSaveError_;

    float                               titleDragMinX_ = 0.0f;
    float                               titleDragMinY_ = 0.0f;
    float                               titleDragMaxX_ = 0.0f;
    float                               titleDragMaxY_ = 0.0f;
    bool                                titleDragRegionValid_ = false;

    // Browser-style command-bar address control. It follows the Binary View
    // cursor while idle, but stops mirroring while the analyst is typing.
    char                                toolbarAddress_[32] = {};
    uint64_t                            toolbarAddressMirror_ = 0;
    bool                                toolbarAddressMirrorValid_ = false;
    bool                                toolbarAddressMirrorLive_ = false;
    DebugTargetIdentity                 toolbarAddressMirrorTarget_{};
    bool                                toolbarAddressEditing_ = false;

    // Raw-load prompt state.
    bool                                openRawPopup_ = false;
    std::string                         rawPendingPath_;
    uint64_t                            rawPendingSize_ = 0;
    char                                rawBaseBuf_[32] = "0x140000000";
    char                                rawEntryBuf_[32] = "0x140000000";
    int                                 rawArchSel_   = 2;   // see rawArchFromSelection
    bool                                rawBigEndian_ = false;
    bool                                rawRiscvCompressed_ = true;
    bool                                rawSeedFirmwareLandmarks_ = true;
    FirmwareDetection                   rawFirmware_;
    std::string                         rawFirmwareNote_;

    // Debug-a-DLL prompt. Export choices come from the bounded pure inspection
    // model; launch planning is rebuilt from these fields when the user presses
    // Debug so command-line quoting and breakpoint RVAs have one source of truth.
    struct DllDebugPopupState {
        bool          open = false;
        DllInspection inspection;
        int           selectedExport = -1;
        int           hostMode = 0;       // 0 = system rundll32, 1 = custom executable
        int           customBitness = 0;  // 0 = unknown, 1 = x86, 2 = x64
        bool          breakOnDllMain = true;
        bool          breakOnExport = true;
        char          customHost[4096] = {};
        char          userArguments[4096] = {};
        std::string   error;
    };
    DllDebugPopupState                  dllDebugPopup_;
    struct LiveDocumentAttempt {
        bool     valid = false;
        uint32_t pid = 0;
        uint64_t sessionGeneration = 0;
        uint64_t base = 0;
        uint64_t retryRevision = 0;

        bool matches(uint32_t wantedPid, uint64_t wantedGeneration,
                     uint64_t wantedBase = 0) const {
            return valid && pid == wantedPid &&
                   sessionGeneration == wantedGeneration &&
                   (!wantedBase || base == wantedBase);
        }
        void clear() { *this = {}; }
    };
    uint32_t                            dllRetargetPid_ = 0;
    uint64_t                            dllRetargetGeneration_ = 0;
    uint64_t                            dllRetargetBase_ = 0;
    LiveDocumentAttempt                 dllRetargetPending_;
    LiveDocumentAttempt                 dllRetargetFailure_;
    // The main-image/document reconciliation is app-global. Binary View children
    // are retained per document, so their local attach edges cannot own this
    // exact-session decision without re-firing on an ordinary document switch.
    bool                                attachMainDocumentSessionValid_ = false;
    uint32_t                            attachMainDocumentPid_ = 0;
    uint64_t                            attachMainDocumentGeneration_ = 0;
    LiveDocumentAttempt                 attachMainDocumentPending_;
    LiveDocumentAttempt                 attachMainDocumentFailure_;

    // Adaptive generic-unpack workflow. Telemetry/scoring lives in the pure
    // UnpackEngine; this state only owns the live sampler and modal choices.
    struct UnpackPopupState {
        bool open = false;
        bool closeAfterDocumentLoad = false;
        bool observing = false;
        bool waitingForInitialBreak = false;
        uint64_t launchRequestId = 0;
        DocumentId sourceDocument{};
        uint64_t sourceImageGeneration = 0;
        DebugTargetIdentity target{};
        bool pauseRequested = false;
        bool containedLaunch = true;
        bool autoRun = true;
        bool autoPause = true;
        bool loadAfterSave = true;
        int strategy = 0; // UnpackStrategy enum order
        int intervalMs = 300;
        int timeoutMs = 30000;
        uint64_t moduleBase = 0;
        uint64_t moduleSize = 0;
        uint64_t startedTick = 0;
        uint64_t lastProbeTick = 0;
        uint64_t runStartedTick = 0;
        uint64_t accumulatedRunMs = 0;
        uint64_t previousRip = 0;
        uint64_t baselineRsp = 0;
        bool hasPreviousRip = false;
        uint64_t lastExceptionSequence = 0;
        std::vector<uint8_t> previousImage;
        // One bit per 4-KiB probe page. Unreadable pages are never treated as
        // zero-filled writes and a partial final capture is never called runnable.
        std::vector<uint8_t> previousValidPages;
        std::vector<uint8_t> writtenPages;
        std::vector<uint8_t> executablePages;
        PeUnpackResult result;
        char manualOep[32] = {};
        std::string error;
    };
    UnpackPopupState                   unpackPopup_;
    UnpackEngine                       unpackEngine_;

    // Dependency-free static packed-PE recovery runs on its own worker. The
    // UI keeps both reconstructed and mapped artifacts available so a partial
    // recovery is inspectable instead of being reduced to a success/fail toast.
    struct StaticUnpackPopupState {
        bool open = false;
        bool closeAfterDocumentLoad = false;
        bool rebuildDiskPe = true;
        bool loadAfterSave = true;
        int strategy = static_cast<int>(StaticUnpackStrategy::Auto);
        int maxOutputMiB = 512;
        int maxDictionaryMiB = 64;
        char oep[32] = {};
        std::string sourcePath;
        uint64_t sourceHash = 0;
        uint64_t sourceRevision = 0;
        bool sourceWasDll = false;
        StaticUnpackResult result;
        std::string error;
    };
    StaticUnpackPopupState             staticUnpackPopup_;
    StaticUnpackService                staticUnpackService_;

    struct PassiveDumpPopupState {
        bool open = false;
        bool closeAfterDocumentLoad = false;
        bool launchMode = false;
        bool suspendFinal = true;
        bool rebuildImports = true;
        bool normalizeRelocations = true;
        bool loadAfterSave = true;
        int timing = static_cast<int>(PassiveTiming::AutoSettle);
        int sampleIntervalMs = 250;
        int maxWatchMs = 60000;
        int stableSamples = 4;
        uint32_t selectedPid = 0;
        char processFilter[96] = {};
        char launchPath[4096] = {};
        char launchArguments[8192] = {};
        char workingDirectory[4096] = {};
        char manualOep[32] = {};
        std::vector<PassiveProcessInfo> processes;
        PassiveDumpResult result;
        std::string error;
    };
    PassiveDumpPopupState              passiveDumpPopup_;
    PassiveDumpService                 passiveDumpService_;

    enum class PendingDocumentLoadOwner : uint8_t {
        None = 0,
        AdaptiveUnpack,
        StaticUnpack,
        PassiveDump,
    };
    PendingDocumentLoadOwner           pendingDocumentLoadOwner_ =
        PendingDocumentLoadOwner::None;

    bool                               antiDebugPopupOpen_ = false;
    AntiDebugPolicy                    antiDebugDraft_{};
    std::string                        antiDebugError_;

    bool                               symbolSettingsOpen_ = false;
    bool                               symbolNetworkDraft_ = false;
    bool                               symbolSourceDraft_ = true;
    bool                               symbolTypesDraft_ = true;
    bool                               symbolLocalsDraft_ = true;
    char                               symbolCacheDraft_[4096] = {};
    char                               symbolServerDraft_[2048] = {};
    std::string                        symbolSettingsError_;

    // Archive-entries browser state, snapshotted at open time: "Open as binary"
    // replaces the loaded binary while the popup is up, so entry extraction always
    // re-reads sourcePath from disk instead of touching ctx_.binary.
    struct ArchiveBrowserState {
        bool        open = false;          // open-request flag, consumed by renderArchiveBrowser
        std::string sourcePath;            // file containing the archive (UTF-8, as BinaryFile::path)
        std::string sourceName;            // display base name of sourcePath
        uint64_t    zipBase = 0;           // file offset of the zip start (javaInfo.jarOffset)
        std::vector<JavaZipEntry> entries; // central-directory snapshot (capped upstream)
        char        filter[128] = {};
        int         selected = -1;
    };
    ArchiveBrowserState                 archiveBrowser_;

};

} // namespace ds
