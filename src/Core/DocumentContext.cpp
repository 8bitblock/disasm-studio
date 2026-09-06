#include "DocumentContext.h"

#include "../Disasm/JvmDisassembler.h"
#include "../Disasm/GmlDisassembler.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace ds {

static void storeRawDecoderFeatures(ProjectState& project,
                                    const DecoderFeatures& features) {
    project.rawDecoderFeatureBits = DecoderFeatureBits(features);
    project.rawRiscvCompressed = features.riscvCompressed;
}

void DocumentNavigation::pushBounded(std::vector<DocumentLocation>& stack,
                                     const DocumentLocation& location) {
    if (!location.valid) return;
    if (stack.size() >= kHistoryLimit) stack.erase(stack.begin());
    stack.push_back(location);
}

void DocumentNavigation::navigateTo(uint64_t va, DocumentView view,
                                    DocumentAddressSpace addressSpace,
                                    DebugTargetIdentity target) {
    navigateTo({ va, true, view, addressSpace, target });
}

void DocumentNavigation::navigateTo(DocumentLocation next) {
    if (!next.valid) return;
    if (next.addressSpace != DocumentAddressSpace::Live) next.target = {};
    if (current_ == next) return;
    pushBounded(back_, current_);
    current_ = next;
    forward_.clear();
}

void DocumentNavigation::replaceCurrent(DocumentLocation location) {
    if (location.addressSpace != DocumentAddressSpace::Live) location.target = {};
    current_ = location;
}

void DocumentNavigation::retireLiveLocations(DebugTargetIdentity keep) {
    auto retired = [&](const DocumentLocation& location) {
        return location.addressSpace == DocumentAddressSpace::Live &&
               (!keep.valid() || !DebugTargetIdentityMatches(location.target, keep));
    };
    std::erase_if(back_, retired);
    std::erase_if(forward_, retired);
    if (retired(current_)) {
        current_ = {};
        if (!back_.empty()) {
            current_ = back_.back();
            back_.pop_back();
        }
    }
}

bool DocumentNavigation::goBack() {
    if (back_.empty()) return false;
    pushBounded(forward_, current_);
    current_ = back_.back();
    back_.pop_back();
    return true;
}

bool DocumentNavigation::goForward() {
    if (forward_.empty()) return false;
    pushBounded(back_, current_);
    current_ = forward_.back();
    forward_.pop_back();
    return true;
}

void DocumentNavigation::clear() {
    current_ = {};
    back_.clear();
    forward_.clear();
}

void DocumentAnalysisCache::clear() {
    imageRevision = 0;
    analysisEpoch = 0;
    strings.reset();
    stringsTruncated = false;
    functions.reset();
    codeData.reset();
    xrefs.reset();
    crackmeTriage.reset();
}

DocumentContext::DocumentContext(DocumentId id, std::string title,
                                 DecoderFactory factory, Engine engine, Arch arch,
                                 DocumentSaveCallback saveCallback)
    : factory_(std::move(factory)),
      id_(id),
      title_(std::move(title)),
      engine_(engine),
      arch_(arch),
      saveCallback_(std::move(saveCallback)),
      analysis_(factory_, 1),
      codeExport_(factory_) {
    if (!id_) throw std::invalid_argument("DocumentContext requires a valid ID");
    if (!factory_) throw std::invalid_argument("DocumentContext requires a decoder factory");
    decoder_ = makeDecoder(decoderConfig(), binary_);
    if (!decoder_ || !decoder_->ready())
        throw std::runtime_error(decoder_ && !decoder_->errorMessage().empty()
            ? std::string(decoder_->errorMessage())
            : "decoder factory rejected the initial configuration");
}

DocumentContext::DocumentContext(DocumentId id, std::string title,
                                 LegacyDecoderFactory factory, Engine engine, Arch arch,
                                 DocumentSaveCallback saveCallback)
    : DocumentContext(id, std::move(title), DecoderFactory(
          [legacy = std::move(factory)](const DecoderConfig& config) {
              return legacy && LegacyDecoderFactoryCanRepresent(config)
                   ? legacy(config.engine, config.arch) : nullptr;
          }), engine, arch, std::move(saveCallback)) {}

DocumentContext::~DocumentContext() {
    std::string ignored;
    if (!close(&ignored)) forceClose();
}

std::unique_ptr<IDisassembler> DocumentContext::makeDecoder(
    const DecoderConfig& requested, const BinaryFile& image) const {
    const DecoderConfig config = DecoderConfigForImage(image, requested);
    std::unique_ptr<IDisassembler> decoder = factory_ ? factory_(config) : nullptr;
    if (decoder && config.arch == Arch::JVM && image.javaClass())
        AttachJvmClass(*decoder, image.javaClass());
    if (decoder && config.arch == Arch::GML && image.gameMakerArchive())
        AttachGameMakerArchive(*decoder, image.gameMakerArchive());
    return decoder;
}

void DocumentContext::quiesceWorkers() {
    // Export first matches AppContext's existing mutation barrier.  Both calls
    // are idempotent and discard unpublished results from the superseded image.
    codeExport_.cancelAndWaitIdle();
    analysis_.cancelAndWaitIdle();
}

void DocumentContext::invalidateDerivedState() {
    cache_.clear();
    navigation_.clear();
}

ProjectState DocumentContext::saveSnapshot() const {
    ProjectState snapshot = project_;
    if (binary_.loaded()) {
        snapshot.hash = binary_.contentHash();
        snapshot.binaryPath = binary_.path();
    }
    snapshot.arch = ArchName(arch_);
    snapshot.engine = EngineNameOf(engine_);
    snapshot.rawMappingSaved = binary_.format() == BinFormat::Raw;
    snapshot.rawLandmarks.clear();
    if (snapshot.rawMappingSaved) {
        snapshot.rawImageBase = binary_.imageBase();
        snapshot.rawEntryExplicit = binary_.rawEntryExplicit();
        snapshot.rawEntry = snapshot.rawEntryExplicit ? binary_.entryPointVA() : 0;
        snapshot.rawBigEndian = byteOrder_ == ByteOrder::Big;
        storeRawDecoderFeatures(snapshot, decoderFeatures_);
        snapshot.rawLandmarks.reserve(binary_.analysisLandmarks().size());
        for (const AnalysisLandmark& landmark : binary_.analysisLandmarks())
            snapshot.rawLandmarks.push_back(
                {landmark.address, landmark.name, landmark.evidence});
    } else {
        snapshot.rawImageBase = 0;
        snapshot.rawEntry = 0;
        snapshot.rawEntryExplicit = false;
        snapshot.rawBigEndian = false;
        storeRawDecoderFeatures(snapshot, DecoderFeatures{});
    }
    return snapshot;
}

void DocumentContext::markDirty() {
    if (!open()) return;
    ++revision_;
    if (!revision_) ++revision_;
    saveState_ = DocumentSaveState::Dirty;
    saveError_.clear();
}

DocumentSaveTicket DocumentContext::externalSaveTicket() const {
    return {id_, imageGeneration_, revision_};
}

bool DocumentContext::acknowledgeExternalSave(
    const DocumentSaveTicket& ticket) {
    if (!open() || ticket.document != id_ ||
        ticket.imageGeneration != imageGeneration_ ||
        ticket.revision > revision_)
        return false;
    // Never move the durable watermark backward if an older completion is
    // observed after a newer one. Newer UI edits remain dirty.
    savedRevision_ = std::max(savedRevision_, ticket.revision);
    saveState_ = dirty() ? DocumentSaveState::Dirty : DocumentSaveState::Clean;
    saveError_.clear();
    return true;
}

bool DocumentContext::rejectExternalSave(const DocumentSaveTicket& ticket,
                                         std::string error) {
    if (!open() || ticket.document != id_ ||
        ticket.imageGeneration != imageGeneration_ ||
        ticket.revision > revision_ || ticket.revision <= savedRevision_)
        return false;
    saveState_ = DocumentSaveState::Failed;
    saveError_ = error.empty()
               ? "Project save failed; changes remain in memory."
               : std::move(error);
    return true;
}

bool DocumentContext::flush(std::string* error) {
    if (error) error->clear();
    if (!open()) {
        const bool closed = lifecycle_ == DocumentLifecycle::Closed;
        if (!closed && error) *error = "document is already closing";
        return closed;
    }
    if (persistence_ == DocumentInstallPersistence::Ephemeral) {
        // Live mapped images intentionally have no durable sidecar. Treat a
        // transition as acknowledging session-only edits without invoking a
        // store which could create a misleading one-off project.
        savedRevision_ = revision_;
        saveState_ = DocumentSaveState::Clean;
        saveError_.clear();
        return true;
    }
    if (!dirty()) {
        saveState_ = DocumentSaveState::Clean;
        saveError_.clear();
        return true;
    }
    if (!saveCallback_) {
        saveState_ = DocumentSaveState::Failed;
        saveError_ = "No project save store is configured; changes remain in memory.";
        if (error) *error = saveError_;
        return false;
    }

    ProjectState snapshot = saveSnapshot();
    std::string callbackError;
    bool saved = false;
    saveState_ = DocumentSaveState::Saving;
    try {
        saved = saveCallback_(binary_, snapshot, callbackError);
    } catch (const std::exception& e) {
        callbackError = e.what();
        saved = false;
    } catch (...) {
        callbackError = "unknown project-store exception";
        saved = false;
    }
    if (!saved) {
        saveState_ = DocumentSaveState::Failed;
        saveError_ = callbackError.empty()
                   ? "Project save failed; changes remain in memory."
                   : std::move(callbackError);
        if (error) *error = saveError_;
        return false;
    }

    project_ = std::move(snapshot);
    savedRevision_ = revision_;
    saveState_ = DocumentSaveState::Clean;
    saveError_.clear();
    return true;
}

bool DocumentContext::installStaged(BinaryFile&& image, ProjectState&& project,
                                    const DecoderConfig& requestedConfig,
                                    std::unique_ptr<IDisassembler> decoder,
                                    DocumentInstallPersistence persistence,
                                    DocumentRuntimeMetadata&& metadata) {
    if (!open() || !image.loaded() || !decoder || !decoder->ready()) return false;
    const DecoderConfig config = DecoderConfigForImage(image, requestedConfig);
    if (!flush()) return false;
    quiesceWorkers();
    binary_ = std::move(image);
    project_ = std::move(project);
    engine_ = config.engine;
    arch_ = config.arch;
    byteOrder_ = config.byteOrder;
    decoderFeatures_ = config.features;
    decoder_ = std::move(decoder);
    metadata_ = std::move(metadata);
    persistence_ = persistence;
    ++imageGeneration_;
    if (!imageGeneration_) ++imageGeneration_;
    revision_ = savedRevision_ = 0;
    saveState_ = DocumentSaveState::Clean;
    saveError_.clear();
    invalidateDerivedState();
    if (persistence_ == DocumentInstallPersistence::RequiresInitialSave)
        markDirty();
    return true;
}

bool DocumentContext::loadFile(const std::string& path, Engine engine, Arch arch) {
    if (!open()) return false;
    BinaryFile staged;
    if (!staged.load(path)) return false;
    DecoderConfig config;
    config.engine = engine;
    config.arch = arch;
    config = DecoderConfigForImage(staged, config);
    std::unique_ptr<IDisassembler> decoder;
    try {
        decoder = makeDecoder(config, staged);
    } catch (...) {
        return false;
    }
    ProjectState project;
    project.hash = staged.contentHash();
    project.binaryPath = staged.path();
    project.arch = ArchName(config.arch);
    project.engine = EngineNameOf(engine);
    const size_t slash = project.binaryPath.find_last_of("/\\");
    project.name = slash == std::string::npos
                 ? project.binaryPath : project.binaryPath.substr(slash + 1);
    return installStaged(std::move(staged), std::move(project), config,
                         std::move(decoder),
                         DocumentInstallPersistence::RequiresInitialSave, {});
}

bool DocumentContext::loadRaw(const std::string& path, uint64_t base,
                              Engine engine, Arch arch, uint64_t entryVA,
                              bool entryExplicit,
                              std::vector<AnalysisLandmark> landmarks) {
    DecoderConfig config;
    config.engine = engine;
    config.arch = arch;
    return loadRaw(path, base, config, entryVA, entryExplicit,
                   std::move(landmarks));
}

bool DocumentContext::loadRaw(const std::string& path, uint64_t base,
                              const DecoderConfig& config, uint64_t entryVA,
                              bool entryExplicit,
                              std::vector<AnalysisLandmark> landmarks) {
    if (!open()) return false;
    BinaryFile staged;
    if (!staged.loadRaw(path, base) ||
        !ArchMappingRangeFits(config.arch, base, staged.bytes().size()))
        return false;
    if (entryExplicit && !staged.setRawEntryPointVA(entryVA)) return false;
    if (!staged.setAnalysisLandmarks(std::move(landmarks))) return false;
    std::unique_ptr<IDisassembler> decoder;
    try {
        decoder = makeDecoder(config, staged);
    } catch (...) {
        return false;
    }
    ProjectState project;
    project.hash = staged.contentHash();
    project.binaryPath = staged.path();
    project.arch = ArchName(config.arch);
    project.engine = EngineNameOf(config.engine);
    project.rawBigEndian = config.byteOrder == ByteOrder::Big;
    storeRawDecoderFeatures(project, config.features);
    const size_t slash = project.binaryPath.find_last_of("/\\");
    project.name = slash == std::string::npos
                 ? project.binaryPath : project.binaryPath.substr(slash + 1);
    return installStaged(std::move(staged), std::move(project), config,
                         std::move(decoder),
                         DocumentInstallPersistence::RequiresInitialSave, {});
}

bool DocumentContext::replaceImage(BinaryFile&& image, ProjectState project,
                                   Engine engine, Arch arch,
                                   DocumentInstallPersistence persistence,
                                   DocumentRuntimeMetadata metadata) {
    DecoderConfig config;
    config.engine = engine;
    config.arch = arch;
    return replaceImage(std::move(image), std::move(project), config,
                        persistence, std::move(metadata));
}

bool DocumentContext::replaceImage(BinaryFile&& image, ProjectState project,
                                   const DecoderConfig& requestedConfig,
                                   DocumentInstallPersistence persistence,
                                   DocumentRuntimeMetadata metadata) {
    if (!open() || !image.loaded()) return false;
    const DecoderConfig config = DecoderConfigForImage(image, requestedConfig);
    const uint64_t imageHash = image.contentHash();
    if (project.hash && project.hash != imageHash) return false;
    project.hash = imageHash;
    project.binaryPath = image.path();
    project.arch = ArchName(config.arch);
    project.engine = EngineNameOf(config.engine);
    if (image.format() == BinFormat::Raw) {
        project.rawBigEndian = config.byteOrder == ByteOrder::Big;
        storeRawDecoderFeatures(project, config.features);
    }
    if (project.name.empty()) {
        const size_t slash = project.binaryPath.find_last_of("/\\");
        project.name = slash == std::string::npos
                     ? project.binaryPath : project.binaryPath.substr(slash + 1);
    }
    std::unique_ptr<IDisassembler> decoder;
    try {
        decoder = makeDecoder(config, image);
    } catch (...) {
        return false;
    }
    if (!decoder || !decoder->ready()) return false;
    return installStaged(std::move(image), std::move(project), config,
                         std::move(decoder), persistence, std::move(metadata));
}

bool DocumentContext::setDecoderConfiguration(Engine engine, Arch arch) {
    DecoderConfig config = decoderConfig();
    config.engine = engine;
    config.arch = arch;
    return setDecoderConfiguration(config);
}

bool DocumentContext::setDecoderConfiguration(const DecoderConfig& requestedConfig) {
    if (!open()) return false;
    const DecoderConfig config = DecoderConfigForImage(binary_, requestedConfig);
    const bool configurationChanged = config != decoderConfig();
    std::unique_ptr<IDisassembler> decoder;
    try {
        decoder = makeDecoder(config, binary_);
    } catch (...) {
        return false;
    }
    if (!decoder || !decoder->ready()) return false;
    quiesceWorkers();
    engine_ = config.engine;
    arch_ = config.arch;
    byteOrder_ = config.byteOrder;
    decoderFeatures_ = config.features;
    decoder_ = std::move(decoder);
    cache_.clear();
    if (binary_.loaded() && (configurationChanged ||
        project_.arch != ArchName(arch_) || project_.engine != EngineNameOf(engine_))) {
        project_.arch = ArchName(arch_);
        project_.engine = EngineNameOf(engine_);
        if (binary_.format() == BinFormat::Raw) {
            project_.rawBigEndian = byteOrder_ == ByteOrder::Big;
            storeRawDecoderFeatures(project_, decoderFeatures_);
        }
        markDirty();
    }
    return true;
}

size_t DocumentContext::writeImage(uint64_t va, const uint8_t* bytes, size_t size) {
    if (!open() || !bytes || !size || !binary_.loaded()) return 0;
    quiesceWorkers();
    const size_t written = binary_.writeImage(va, bytes, size);
    if (written) {
        cache_.clear();
        if (!binary_.isMappedImage()) invalidateDebugImageIdentity();
    }
    return written;
}

bool DocumentContext::commitPatchedImage(
    std::vector<uint8_t>&& replacement,
    DocumentLiveImageCommit liveImageCommit) {
    if (!open() || !binary_.loaded()) return false;
    quiesceWorkers();
    if (!binary_.commitPatchedImage(std::move(replacement))) return false;
    cache_.clear();
    if (!binary_.isMappedImage() ||
        liveImageCommit == DocumentLiveImageCommit::InvalidateMappedIdentity)
        invalidateDebugImageIdentity();
    return true;
}

bool DocumentContext::clearImage(std::string* error) {
    if (!open()) return false;
    BinaryFile emptyImage;
    std::unique_ptr<IDisassembler> emptyDecoder;
    try {
        emptyDecoder = makeDecoder(decoderConfig(), emptyImage);
    } catch (...) {
        if (error) *error = "decoder factory rejected the empty document";
        return false;
    }
    if (!emptyDecoder || !emptyDecoder->ready() || !flush(error)) return false;
    quiesceWorkers();
    binary_ = std::move(emptyImage);
    decoder_ = std::move(emptyDecoder);
    ++imageGeneration_;
    if (!imageGeneration_) ++imageGeneration_;
    invalidateDerivedState();
    project_.reset();
    metadata_ = {};
    persistence_ = DocumentInstallPersistence::DurableSnapshot;
    revision_ = savedRevision_ = 0;
    saveState_ = DocumentSaveState::Clean;
    saveError_.clear();
    return true;
}

bool DocumentContext::close(std::string* error) {
    if (lifecycle_ == DocumentLifecycle::Closed) return true;
    if (lifecycle_ == DocumentLifecycle::Closing) {
        if (error) *error = "document is already closing";
        return false;
    }
    if (!flush(error)) return false;
    lifecycle_ = DocumentLifecycle::Closing;
    quiesceWorkers();
    decoder_.reset();
    invalidateDerivedState();
    project_.reset();
    binary_.clear();
    metadata_ = {};
    lifecycle_ = DocumentLifecycle::Closed;
    return true;
}

void DocumentContext::forceClose() noexcept {
    if (lifecycle_ == DocumentLifecycle::Closed) return;
    lifecycle_ = DocumentLifecycle::Closing;
    quiesceWorkers();
    decoder_.reset();
    invalidateDerivedState();
    project_.reset();
    binary_.clear();
    metadata_ = {};
    lifecycle_ = DocumentLifecycle::Closed;
}

DocumentManager::DocumentManager(DecoderFactory factory,
                                 DocumentSaveCallback saveCallback)
    : factory_(std::move(factory)), saveCallback_(std::move(saveCallback)) {
    if (!factory_) throw std::invalid_argument("DocumentManager requires a decoder factory");
}

DocumentManager::DocumentManager(LegacyDecoderFactory factory,
                                 DocumentSaveCallback saveCallback)
    : DocumentManager(DecoderFactory(
          [legacy = std::move(factory)](const DecoderConfig& config) {
              return legacy && LegacyDecoderFactoryCanRepresent(config)
                   ? legacy(config.engine, config.arch) : nullptr;
          }), std::move(saveCallback)) {}

DocumentManager::~DocumentManager() {
    std::string ignored;
    if (!clear({}, &ignored)) forceClear();
}

bool DocumentManager::prepareAndFlush(DocumentContext& document,
                                      const PrepareTransition& prepare,
                                      std::string* error) {
    lastError_.clear();
    if (prepare) {
        try {
            if (!prepare(document, lastError_)) {
                if (lastError_.empty()) lastError_ = "Document transition was rejected.";
                if (error) *error = lastError_;
                return false;
            }
        } catch (const std::exception& e) {
            lastError_ = e.what();
            if (error) *error = lastError_;
            return false;
        } catch (...) {
            lastError_ = "Document transition callback failed.";
            if (error) *error = lastError_;
            return false;
        }
    }
    if (!document.flush(&lastError_)) {
        if (error) *error = lastError_;
        return false;
    }
    return true;
}

std::optional<DocumentId> DocumentManager::create(std::string title,
                                                  PrepareTransition prepare) {
    lastError_.clear();
    if (documents_.size() >= kMaxDocuments || nextId_ == 0) {
        lastError_ = "The eight-document limit has been reached.";
        return std::nullopt;
    }
    const DocumentId id{ nextId_ };
    std::unique_ptr<DocumentContext> candidate;
    try {
        candidate = std::make_unique<DocumentContext>(
            id, std::move(title), factory_, Engine::Zydis, Arch::X64,
            saveCallback_);
    } catch (const std::exception& e) {
        lastError_ = e.what();
        return std::nullopt;
    } catch (...) {
        lastError_ = "Document creation failed.";
        return std::nullopt;
    }
    if (DocumentContext* outgoing = active();
        outgoing && !prepareAndFlush(*outgoing, prepare, nullptr))
        return std::nullopt;

    try {
        documents_.push_back(std::move(candidate));
    } catch (const std::exception& error) {
        lastError_ = std::string("Document publication failed: ") + error.what();
        return std::nullopt;
    } catch (...) {
        lastError_ = "Document publication failed.";
        return std::nullopt;
    }
    if (nextId_ == (std::numeric_limits<uint64_t>::max)()) nextId_ = 0;
    else ++nextId_;
    activeId_ = id;
    return id;
}

DocumentContext* DocumentManager::canonicalForHash(uint64_t hash,
                                                   DocumentId except) {
    for (auto& document : documents_) {
        if (document->id() == except || !document->binary().loaded()) continue;
        if (document->binary().contentHash() == hash) return document.get();
    }
    return nullptr;
}

bool DocumentManager::activate(DocumentId id, PrepareTransition prepare,
                               std::string* error) {
    lastError_.clear();
    if (error) error->clear();
    DocumentContext* target = find(id);
    if (!target) {
        lastError_ = "Document no longer exists.";
        if (error) *error = lastError_;
        return false;
    }
    if (activeId_ && *activeId_ == target->id()) return true;
    if (DocumentContext* outgoing = active();
        outgoing && !prepareAndFlush(*outgoing, prepare, error))
        return false;
    id = target->id();
    activeId_ = id;
    return true;
}

bool DocumentManager::close(DocumentId id, PrepareTransition prepare,
                            std::string* error) {
    lastError_.clear();
    if (error) error->clear();
    auto it = std::find_if(documents_.begin(), documents_.end(),
                           [id](const auto& document) { return document->id() == id; });
    if (it == documents_.end()) {
        lastError_ = "Document no longer exists.";
        if (error) *error = lastError_;
        return false;
    }
    const size_t index = static_cast<size_t>(it - documents_.begin());
    const bool wasActive = activeId_ && *activeId_ == id;
    if (wasActive) {
        if (!prepareAndFlush(**it, prepare, error)) return false;
    } else if (!(*it)->flush(&lastError_)) {
        if (error) *error = lastError_;
        return false;
    }
    if (!(*it)->close(&lastError_)) {
        if (error) *error = lastError_;
        return false;
    }
    documents_.erase(it);

    if (documents_.empty()) {
        activeId_.reset();
    } else if (wasActive) {
        // Prefer the successor which slid into the removed slot; for the old
        // final slot this naturally selects its predecessor.
        activeId_ = documents_[std::min(index, documents_.size() - 1)]->id();
    }
    return true;
}

bool DocumentManager::clear(PrepareTransition prepare, std::string* error) {
    lastError_.clear();
    if (error) error->clear();
    // First phase performs every UI mirror and durable flush while all contexts
    // remain alive. A failure cannot leave a half-erased collection.
    for (auto& document : documents_) {
        const bool isActive = activeId_ && *activeId_ == document->id();
        if (isActive) {
            if (!prepareAndFlush(*document, prepare, error)) return false;
        } else if (!document->flush(&lastError_)) {
            if (error) *error = lastError_;
            return false;
        }
    }
    for (auto& document : documents_) {
        if (!document->close(&lastError_)) {
            if (error) *error = lastError_;
            return false;
        }
    }
    documents_.clear();
    activeId_.reset();
    return true;
}

void DocumentManager::forceClear() noexcept {
    for (auto& document : documents_) document->forceClose();
    documents_.clear();
    activeId_.reset();
}

void DocumentManager::setSaveCallback(DocumentSaveCallback callback) {
    saveCallback_ = std::move(callback);
    for (auto& document : documents_) document->setSaveCallback(saveCallback_);
}

DocumentManager::OpenResult DocumentManager::openStaged(
    std::string title, BinaryFile&& image, ProjectState project,
    Engine engine, Arch arch, DocumentInstallPersistence persistence,
    DocumentRuntimeMetadata metadata,
    PrepareTransition prepare, DocumentOpenReuse reuse) {
    DecoderConfig config;
    config.engine = engine;
    config.arch = arch;
    return openStaged(std::move(title), std::move(image), std::move(project),
                      config, persistence, std::move(metadata),
                      std::move(prepare), reuse);
}

DocumentManager::OpenResult DocumentManager::openStaged(
    std::string title, BinaryFile&& image, ProjectState project,
    const DecoderConfig& decoderConfig,
    DocumentInstallPersistence persistence,
    DocumentRuntimeMetadata metadata,
    PrepareTransition prepare, DocumentOpenReuse reuse) {
    OpenResult result;
    lastError_.clear();
    if (!image.loaded()) {
        result.status = OpenStatus::InvalidImage;
        result.error = "The staged image is not loaded.";
        return result;
    }

    const uint64_t hash = image.contentHash();
    if (reuse == DocumentOpenReuse::ReuseContentHash) {
        if (DocumentContext* existing = canonicalForHash(hash)) {
            std::string transitionError;
            if (!activate(existing->id(), std::move(prepare), &transitionError)) {
                result.status = OpenStatus::TransitionBlocked;
                result.error = std::move(transitionError);
                return result;
            }
            result.status = OpenStatus::ActivatedExisting;
            result.id = existing->id();
            return result;
        }
    }
    if (documents_.size() >= kMaxDocuments || nextId_ == 0) {
        result.status = OpenStatus::LimitReached;
        result.error = "The eight-document limit has been reached.";
        return result;
    }

    const DocumentId id{nextId_};
    std::unique_ptr<DocumentContext> candidate;
    try {
        candidate = std::make_unique<DocumentContext>(
            id, std::move(title), factory_, decoderConfig.engine, decoderConfig.arch,
            DocumentSaveCallback{});
    } catch (const std::exception& e) {
        result.status = OpenStatus::DecoderRejected;
        result.error = e.what();
        return result;
    } catch (...) {
        result.status = OpenStatus::DecoderRejected;
        result.error = "Decoder construction failed.";
        return result;
    }
    if (!candidate->replaceImage(std::move(image), std::move(project),
                                 decoderConfig, persistence,
                                 std::move(metadata))) {
        result.status = OpenStatus::DecoderRejected;
        result.error = candidate->saveError().empty()
                     ? "The staged document could not be installed."
                     : candidate->saveError();
        return result;
    }
    std::string transitionError;
    if (DocumentContext* outgoing = active();
        outgoing && !prepareAndFlush(*outgoing, prepare, &transitionError)) {
        result.status = OpenStatus::TransitionBlocked;
        result.error = std::move(transitionError);
        return result;
    }

    // Publish the owner before enabling its durable store. If vector growth or
    // callback copying throws, the still-unpublished dirty candidate has no save
    // callback, so unwinding cannot create a sidecar for a document the user
    // never actually opened.
    try {
        documents_.push_back(std::move(candidate));
    } catch (const std::exception& e) {
        result.status = OpenStatus::DecoderRejected;
        result.error = std::string("Document publication failed: ") + e.what();
        return result;
    } catch (...) {
        result.status = OpenStatus::DecoderRejected;
        result.error = "Document publication failed.";
        return result;
    }
    try {
        documents_.back()->setSaveCallback(saveCallback_);
    } catch (const std::exception& e) {
        // The callback is still empty if its by-value copy failed. Destroying
        // this unpublished owner therefore remains side-effect free.
        documents_.pop_back();
        result.status = OpenStatus::DecoderRejected;
        result.error = std::string("Document save-store setup failed: ") + e.what();
        return result;
    } catch (...) {
        documents_.pop_back();
        result.status = OpenStatus::DecoderRejected;
        result.error = "Document save-store setup failed.";
        return result;
    }

    if (nextId_ == (std::numeric_limits<uint64_t>::max)()) nextId_ = 0;
    else ++nextId_;
    activeId_ = id;
    result.status = OpenStatus::Created;
    result.id = id;
    return result;
}

DocumentContext* DocumentManager::find(DocumentId id) {
    auto it = std::find_if(documents_.begin(), documents_.end(),
                           [id](const auto& document) { return document->id() == id; });
    return it == documents_.end() ? nullptr : it->get();
}

const DocumentContext* DocumentManager::find(DocumentId id) const {
    auto it = std::find_if(documents_.begin(), documents_.end(),
                           [id](const auto& document) { return document->id() == id; });
    return it == documents_.end() ? nullptr : it->get();
}

DocumentContext* DocumentManager::active() {
    return activeId_ ? find(*activeId_) : nullptr;
}

const DocumentContext* DocumentManager::active() const {
    return activeId_ ? find(*activeId_) : nullptr;
}

DocumentContext* DocumentManager::at(size_t index) {
    return index < documents_.size() ? documents_[index].get() : nullptr;
}

const DocumentContext* DocumentManager::at(size_t index) const {
    return index < documents_.size() ? documents_[index].get() : nullptr;
}

} // namespace ds
