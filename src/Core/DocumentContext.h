#pragma once
//
// DocumentContext.h
// Core ownership boundary for one static-analysis document and a deterministic,
// bounded collection of those documents.  Debugger, JDWP, and Prism targets are
// deliberately absent: they remain app-global while each document owns every
// worker which may borrow its BinaryFile storage.
//
// This is a Core foundation only.  The fixed-window document tab strip and the
// migration of AppContext/BinaryView state onto this owner are separate UI work.

#include "AnalysisService.h"
#include "BinaryFile.h"
#include "CodeExport.h"
#include "DebugTargetIdentity.h"
#include "FirmwareSniffer.h"
#include "JavaScan.h"
#include "Project.h"
#include "RuntimeScan.h"
#include "XrefIndex.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ds {

struct DocumentId {
    uint64_t value = 0;

    friend bool operator==(DocumentId, DocumentId) = default;
    explicit operator bool() const { return value != 0; }
};

enum class DocumentView : uint8_t {
    Assembly = 0,
    Pseudocode,
    Hex,
    Graph,
    CallGraph,
    LiveAssembly,
    Overview,
};

enum class DocumentAddressSpace : uint8_t {
    File = 0,
    Live,
    FileOffset,
};

// `valid` is authoritative: zero is a normal location, not an empty marker.
// `va` contains a file offset when addressSpace == FileOffset.
struct DocumentLocation {
    uint64_t             va = 0;
    bool                 valid = false;
    DocumentView         view = DocumentView::Assembly;
    DocumentAddressSpace addressSpace = DocumentAddressSpace::File;
    DebugTargetIdentity target{}; // LIVE locations belong to one debugger session

    friend bool operator==(const DocumentLocation& a, const DocumentLocation& b) {
        return a.va == b.va && a.valid == b.valid && a.view == b.view &&
               a.addressSpace == b.addressSpace && a.target.pid == b.target.pid &&
               a.target.sessionGeneration == b.target.sessionGeneration;
    }
};

class DocumentNavigation {
public:
    static constexpr size_t kHistoryLimit = 512;

    const DocumentLocation& current() const { return current_; }
    const std::vector<DocumentLocation>& backStack() const { return back_; }
    const std::vector<DocumentLocation>& forwardStack() const { return forward_; }

    void navigateTo(uint64_t va, DocumentView view = DocumentView::Assembly,
                    DocumentAddressSpace addressSpace = DocumentAddressSpace::File,
                    DebugTargetIdentity target = {});
    void navigateTo(DocumentLocation location);
    // Selection and representation changes replace the current anchor without
    // adding a jump or discarding a still-useful forward branch.
    void replaceCurrent(DocumentLocation location);
    // Preserve FILE positions and retire only LIVE entries from other sessions.
    void retireLiveLocations(DebugTargetIdentity keep = {});
    bool goBack();
    bool goForward();
    void clear();

private:
    static void pushBounded(std::vector<DocumentLocation>& stack,
                            const DocumentLocation& location);

    DocumentLocation              current_;
    std::vector<DocumentLocation> back_;
    std::vector<DocumentLocation> forward_;
};

// Immutable-result holders which otherwise tend to leak back into one app-wide
// cache.  AnalysisService additionally owns its bounded derived-pass LRU; both
// layers therefore follow the document's image lifetime.
struct DocumentAnalysisCache {
    uint64_t imageRevision = 0;
    uint64_t analysisEpoch = 0;
    std::shared_ptr<const std::vector<StrResult>> strings;
    bool stringsTruncated = false; // FILE result coverage, independent of the live Strings view
    std::shared_ptr<const std::vector<FuncResult>> functions;
    std::shared_ptr<const CodeDataMap> codeData;
    std::shared_ptr<const XrefIndex> xrefs;
    std::shared_ptr<const CrackmeTriageReport> crackmeTriage;

    bool matches(const BinaryFile& binary, uint64_t epoch) const {
        return binary.loaded() && imageRevision == binary.imageRevision() &&
               analysisEpoch == epoch;
    }
    void clear();
};

enum class DocumentLifecycle : uint8_t { Open = 0, Closing, Closed };

struct DocumentRuntimeMetadata {
    struct LiveImageIdentity {
        bool        valid = false;
        uint32_t    pid = 0;
        uint64_t    sessionGeneration = 0;
        uint64_t    moduleBase = 0;
        uint64_t    moduleSize = 0;
        std::string moduleName;
        std::string modulePath;
        uint64_t    moduleLoadGeneration = 0;
    } liveImage;
    JavaScanResult    java;
    RuntimeScanResult runtime;
    FirmwareDetection firmware;
};

enum class DocumentSaveState : uint8_t { Clean = 0, Dirty, Saving, Failed };

// Every installed image states its durable relationship explicitly.  A restored
// sidecar is already durable, a newly synthesized file/raw project must receive
// an initial save even before the analyst edits it, and a live mapped image is
// deliberately session-only.
enum class DocumentInstallPersistence : uint8_t {
    DurableSnapshot = 0,
    RequiresInitialSave,
    Ephemeral,
};

// Ordinary file opens canonicalize by content hash. A debugger memory capture
// instead represents one exact live session and must receive a fresh image
// generation even when an older ephemeral capture has identical bytes.
enum class DocumentOpenReuse : uint8_t {
    ReuseContentHash = 0,
    AlwaysCreate,
};

// A full-image patch commit must state what happened to an already-verified
// mapped debugger image.  File-backed documents retain their existing
// conservative invalidation behavior regardless of this value.  Preserving a
// mapped identity is only valid for an exact live mirror (or a same-turn mirror
// attempt whose caller will invalidate immediately if it does not complete).
enum class DocumentLiveImageCommit : uint8_t {
    PreserveVerifiedIdentity = 0,
    InvalidateMappedIdentity,
};

// Identity carried by an external asynchronous writer.  `imageGeneration`
// prevents a completion for an older image in the same DocumentContext from
// acknowledging (or failing) its replacement; `revision` permits a completed
// older snapshot to coexist with newer in-memory edits.
struct DocumentSaveTicket {
    DocumentId document;
    uint64_t imageGeneration = 0;
    uint64_t revision = 0;

    explicit operator bool() const {
        return static_cast<bool>(document) && imageGeneration != 0;
    }
};

// The UI injects its chosen durable store (normally the atomic Project sidecar
// writer).  The callback receives an immutable, fully stamped snapshot and may
// report a user-facing error.  Keeping the abstraction here avoids coupling the
// Core lifetime owner to Win32 UI or a particular storage location.
using DocumentSaveCallback =
    std::function<bool(const BinaryFile&, const ProjectState&, std::string&)>;

class DocumentContext {
public:
    using DecoderFactory = AnalysisService::DecoderFactory;
    using LegacyDecoderFactory = AnalysisService::LegacyDecoderFactory;

    DocumentContext(DocumentId id, std::string title, DecoderFactory factory,
                    Engine engine = Engine::Zydis, Arch arch = Arch::X64,
                    DocumentSaveCallback saveCallback = {});
    DocumentContext(DocumentId id, std::string title, LegacyDecoderFactory factory,
                    Engine engine = Engine::Zydis, Arch arch = Arch::X64,
                    DocumentSaveCallback saveCallback = {});
    ~DocumentContext();

    DocumentContext(const DocumentContext&) = delete;
    DocumentContext& operator=(const DocumentContext&) = delete;
    DocumentContext(DocumentContext&&) = delete;
    DocumentContext& operator=(DocumentContext&&) = delete;

    DocumentId id() const { return id_; }
    const std::string& title() const { return title_; }
    void setTitle(std::string title) { title_ = std::move(title); }
    DocumentLifecycle lifecycle() const { return lifecycle_; }
    bool open() const { return lifecycle_ == DocumentLifecycle::Open; }

    const BinaryFile& binary() const { return binary_; }
    const ProjectState& project() const { return project_; }
    // Mutable access is an explicit edit operation so no caller can change
    // analyst state and accidentally bypass the close/replacement save barrier.
    ProjectState& editProject() {
        markDirty();
        return project_;
    }
    // AppContext's legacy UI mirror writes ProjectState first and calls its
    // markProjectDirty() edge afterward. Keep that two-step compatibility path
    // explicit while ownership lives here; new Core callers should prefer
    // editProject().
    ProjectState& projectForMirroring() { return project_; }
    Engine engine() const { return engine_; }
    Arch arch() const { return arch_; }
    DecoderConfig decoderConfig() const {
        DecoderConfig config;
        config.engine = engine_;
        config.arch = arch_;
        config.byteOrder = byteOrder_;
        config.features = decoderFeatures_;
        return config;
    }
    IDisassembler* decoder() { return decoder_.get(); }
    const IDisassembler* decoder() const { return decoder_.get(); }
    AnalysisService& analysis() { return analysis_; }
    const AnalysisService& analysis() const { return analysis_; }
    CodeExportService& codeExport() { return codeExport_; }
    DocumentAnalysisCache& cache() { return cache_; }
    const DocumentAnalysisCache& cache() const { return cache_; }
    DocumentNavigation& navigation() { return navigation_; }
    const DocumentNavigation& navigation() const { return navigation_; }
    const JavaScanResult& javaInfo() const { return metadata_.java; }
    const RuntimeScanResult& runtimeInfo() const { return metadata_.runtime; }
    const FirmwareDetection& firmwareInfo() const { return metadata_.firmware; }
    const DocumentRuntimeMetadata& runtimeMetadata() const { return metadata_; }
    void setDebugImageIdentity(
        DocumentRuntimeMetadata::LiveImageIdentity identity) {
        // Debug-session provenance is ephemeral navigation safety state, not an
        // analyst edit and never belongs in a project sidecar.
        metadata_.liveImage = std::move(identity);
    }
    void invalidateDebugImageIdentity() noexcept {
        // `valid` is the authority bit for the complete PID/session/module
        // stamp.  Retaining the descriptive fields is useful for diagnostics,
        // but no static-to-runtime consumer may use them once this bit is clear.
        metadata_.liveImage.valid = false;
    }

    DocumentSaveState saveState() const { return saveState_; }
    DocumentInstallPersistence persistence() const { return persistence_; }
    const std::string& saveError() const { return saveError_; }
    uint64_t revision() const { return revision_; }
    uint64_t savedRevision() const { return savedRevision_; }
    uint64_t imageGeneration() const { return imageGeneration_; }
    bool dirty() const { return revision_ != savedRevision_; }
    void setSaveCallback(DocumentSaveCallback callback) {
        saveCallback_ = std::move(callback);
    }
    void markDirty();
    bool flush(std::string* error = nullptr);
    // Transient editor state is never serialized as a completed type. Image
    // replacement and close must resolve it before releasing its owner.
    void setTypeDraftPending(bool pending) { typeDraftPending_ = pending; }
    bool typeDraftPending() const { return typeDraftPending_; }

    // AppContext retains its existing debounced asynchronous sidecar writer.
    // These two edges let that writer acknowledge exactly the document revision
    // represented by its immutable snapshot without performing a second save.
    DocumentSaveTicket externalSaveTicket() const;
    bool acknowledgeExternalSave(const DocumentSaveTicket& ticket);
    bool rejectExternalSave(const DocumentSaveTicket& ticket,
                            std::string error);

    // Stage the new file and decoder before disturbing the current document.  A
    // failed load therefore preserves the previous image and analyst state.
    bool loadFile(const std::string& path, Engine engine, Arch arch);
    bool loadRaw(const std::string& path, uint64_t base, Engine engine, Arch arch,
                 uint64_t entryVA, bool entryExplicit = true,
                 std::vector<AnalysisLandmark> landmarks = {});
    bool loadRaw(const std::string& path, uint64_t base,
                 const DecoderConfig& decoder, uint64_t entryVA,
                 bool entryExplicit = true,
                 std::vector<AnalysisLandmark> landmarks = {});

    // Install a caller-staged image together with the exact persisted analyst
    // state and cheap per-document runtime metadata. Decoder construction and
    // outgoing-save validation both happen before the current image is changed.
    bool replaceImage(BinaryFile&& image, ProjectState project,
                      Engine engine, Arch arch,
                      DocumentInstallPersistence persistence,
                      DocumentRuntimeMetadata metadata = {});
    bool replaceImage(BinaryFile&& image, ProjectState project,
                      const DecoderConfig& decoder,
                      DocumentInstallPersistence persistence,
                      DocumentRuntimeMetadata metadata = {});

    // Configuration changes supersede and join old-config work before swapping
    // the UI decoder.  Returns false without changing state if construction fails.
    bool setDecoderConfiguration(Engine engine, Arch arch);
    bool setDecoderConfiguration(const DecoderConfig& decoder);

    // Safe mutation gateways.  They enforce the two worker lifetime contracts
    // before BinaryFile storage is cleared or written.
    size_t writeImage(uint64_t va, const uint8_t* bytes, size_t size);
    bool commitPatchedImage(std::vector<uint8_t>&& replacement,
                            DocumentLiveImageCommit liveImageCommit);
    bool clearImage(std::string* error = nullptr);

    // Terminal, idempotent close. A dirty document is flushed first. Failure
    // leaves lifecycle, image, decoder, caches, project, and metadata intact.
    bool close(std::string* error = nullptr);

private:
    friend class DocumentManager;

    std::unique_ptr<IDisassembler> makeDecoder(const DecoderConfig& decoder,
                                                const BinaryFile& image) const;
    bool installStaged(BinaryFile&& image, ProjectState&& project,
                       const DecoderConfig& decoderConfig,
                       std::unique_ptr<IDisassembler> decoder,
                       DocumentInstallPersistence persistence,
                       DocumentRuntimeMetadata&& metadata);
    void quiesceWorkers();
    void invalidateDerivedState();
    ProjectState saveSnapshot() const;
    void forceClose() noexcept;

    DecoderFactory                   factory_;
    BinaryFile                       binary_;
    ProjectState                     project_;
    DocumentId                       id_;
    std::string                      title_;
    Engine                           engine_ = Engine::Zydis;
    Arch                             arch_ = Arch::X64;
    ByteOrder                        byteOrder_ = ByteOrder::Little;
    DecoderFeatures                  decoderFeatures_;
    std::unique_ptr<IDisassembler>   decoder_;
    DocumentAnalysisCache            cache_;
    DocumentNavigation               navigation_;
    DocumentRuntimeMetadata          metadata_;
    DocumentLifecycle                lifecycle_ = DocumentLifecycle::Open;
    DocumentSaveCallback             saveCallback_;
    DocumentSaveState                saveState_ = DocumentSaveState::Clean;
    DocumentInstallPersistence       persistence_ =
        DocumentInstallPersistence::DurableSnapshot;
    std::string                      saveError_;
    uint64_t                         revision_ = 0;
    uint64_t                         savedRevision_ = 0;
    uint64_t                         imageGeneration_ = 1;
    bool                             typeDraftPending_ = false;

    // Declared after BinaryFile so reverse destruction joins both workers before
    // the storage they may be reading is destroyed, even if a caller forgets to
    // invoke close explicitly.
    AnalysisService                  analysis_;
    CodeExportService                codeExport_;
};

class DocumentManager {
public:
    using DecoderFactory = DocumentContext::DecoderFactory;
    using LegacyDecoderFactory = DocumentContext::LegacyDecoderFactory;
    using PrepareTransition =
        std::function<bool(DocumentContext&, std::string&)>;
    static constexpr size_t kMaxDocuments = 8;

    explicit DocumentManager(DecoderFactory factory,
                             DocumentSaveCallback saveCallback = {});
    explicit DocumentManager(LegacyDecoderFactory factory,
                             DocumentSaveCallback saveCallback = {});
    ~DocumentManager();

    DocumentManager(const DocumentManager&) = delete;
    DocumentManager& operator=(const DocumentManager&) = delete;

    // New documents receive monotone IDs which are never reused and become the
    // active document.  nullopt reports the fixed eight-document limit.
    std::optional<DocumentId> create(std::string title = {},
                                     PrepareTransition prepare = {});
    bool activate(DocumentId id, PrepareTransition prepare = {},
                  std::string* error = nullptr);
    bool close(DocumentId id, PrepareTransition prepare = {},
               std::string* error = nullptr);
    bool clear(PrepareTransition prepare = {}, std::string* error = nullptr);

    enum class OpenStatus : uint8_t {
        Created = 0,
        ActivatedExisting,
        InvalidImage,
        LimitReached,
        DecoderRejected,
        TransitionBlocked,
    };
    struct OpenResult {
        OpenStatus status = OpenStatus::InvalidImage;
        DocumentId id;
        std::string error;
        explicit operator bool() const {
            return status == OpenStatus::Created ||
                   status == OpenStatus::ActivatedExisting;
        }
    };

    // Production opening path: ordinary file content identity is checked before
    // allocating a ninth context or installing duplicate state. Exact-session
    // live captures opt into AlwaysCreate so stale same-byte mappings cannot be
    // reactivated without a new image-generation/analysis edge.
    OpenResult openStaged(std::string title, BinaryFile&& image,
                          ProjectState project, Engine engine, Arch arch,
                          DocumentInstallPersistence persistence,
                          DocumentRuntimeMetadata metadata = {},
                          PrepareTransition prepare = {},
                          DocumentOpenReuse reuse =
                              DocumentOpenReuse::ReuseContentHash);
    OpenResult openStaged(std::string title, BinaryFile&& image,
                          ProjectState project, const DecoderConfig& decoder,
                          DocumentInstallPersistence persistence,
                          DocumentRuntimeMetadata metadata = {},
                          PrepareTransition prepare = {},
                          DocumentOpenReuse reuse =
                              DocumentOpenReuse::ReuseContentHash);

    const std::string& lastError() const { return lastError_; }
    void setSaveCallback(DocumentSaveCallback callback);

    size_t size() const { return documents_.size(); }
    bool empty() const { return documents_.empty(); }
    std::optional<DocumentId> activeId() const { return activeId_; }
    DocumentContext* active();
    const DocumentContext* active() const;
    DocumentContext* find(DocumentId id);
    const DocumentContext* find(DocumentId id) const;
    DocumentContext* at(size_t index);
    const DocumentContext* at(size_t index) const;

private:
    DocumentContext* canonicalForHash(uint64_t hash,
                                      DocumentId except = {});
    bool prepareAndFlush(DocumentContext& document,
                         const PrepareTransition& prepare,
                         std::string* error);
    void forceClear() noexcept;
    void refreshAnalysisPriorities();

    DecoderFactory                                factory_;
    DocumentSaveCallback                         saveCallback_;
    std::vector<std::unique_ptr<DocumentContext>> documents_;
    std::optional<DocumentId>                     activeId_;
    uint64_t                                      nextId_ = 1;
    std::string                                   lastError_;
};

} // namespace ds
