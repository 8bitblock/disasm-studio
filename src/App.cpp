#include "App.h"
#include "Core/GameMakerArchive.h"
#include "Tabs/ITab.h"

#include "Tabs/ProjectsTab.h"
#include "Tabs/CommunicationsTab.h"
#include "Tabs/SigScannerTab.h"
#include "Tabs/BinaryViewHostTab.h"
#include "Tabs/MemoryToolsTab.h"
#include "Tabs/BinaryDiffTab.h"
#include "Tabs/BinaryTechTab.h"
#include "Tabs/CortexTab.h"
#include "Tabs/PrismTab.h"

#include "Core/Demangle.h"
#include "Core/PatchedImage.h"
#include "Core/AttachImagePolicy.h"
#include "Core/AddressInspector.h"

#include "Ui/Theme.h"
#include "Ui/Fonts.h"
#include "Ui/Icons.h"
#include "Ui/Widgets.h"
#include "resource.h"
#include "imgui.h"

#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cmath>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <cwchar>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <stdexcept>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ds {

bool BuildGmlMemoryScanPreset(const GmlHelperNumericSlot& slot,
                              MemoryScanValue& value,
                              uint32_t& selectionBytes) {
    MemoryScanValue next;
    uint32_t width = 0;
    switch (slot.kind) {
    case GmlNumericKind::Real:
        next.type = MemoryValueType::Float64;
        width = 8;
        break;
    case GmlNumericKind::Int32:
        next.type = MemoryValueType::Int32;
        width = 4;
        break;
    case GmlNumericKind::Int64:
        next.type = MemoryValueType::Int64;
        width = 8;
        break;
    // The only verified runner adapter represents Boolean payloads as Float64.
    case GmlNumericKind::Boolean:
        next.type = MemoryValueType::Float64;
        width = 8;
        break;
    default:
        value = {};
        selectionBytes = 1;
        return false;
    }
    next.bytes.resize(width);
    std::memcpy(next.bytes.data(), &slot.value.payload, width);
    if (!next.valid()) {
        value = {};
        selectionBytes = 1;
        return false;
    }
    value = std::move(next);
    selectionBytes = width;
    return true;
}

// Keep full dialogs usable on small displays and at high DPI. The window's
// normal scroll path retains every field when its preferred size cannot fit.
static void prepareWorkbenchDialog(float width, float height,
                                   ImGuiCond condition = ImGuiCond_Appearing) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const float scale = theme::UiScale();
    const ImVec2 available(std::max(1.0f, viewport->WorkSize.x - 24.0f * scale),
                           std::max(1.0f, viewport->WorkSize.y - 24.0f * scale));
    const ImVec2 minimum(std::min(320.0f * scale, available.x),
                         std::min(160.0f * scale, available.y));
    ImGui::SetNextWindowSizeConstraints(minimum, available);
    ImGui::SetNextWindowPos(viewport->GetWorkCenter(), ImGuiCond_Appearing,
                           ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(width * scale, available.x),
        height > 0.0f ? std::min(height * scale, available.y) : 0.0f), condition);
}

static bool liveDocumentSessionState(const DbgSnapshot& snapshot) {
    return snapshot.state == DbgState::Running ||
           snapshot.state == DbgState::Paused;
}

static bool hasEnabledProjectPatches(const ProjectState& project) {
    if (project.patchRecoveryPending) return false;
    for (const PjPatch& patch : project.patches) {
        if (patch.patchSetId == kUngroupedPatchSetId) return true;
        const PjPatchSet* set = FindPatchSet(project.patchSets,
                                             patch.patchSetId);
        if (set && set->enabled) return true;
    }
    return false;
}

static AttachedModuleIdentity attachedModuleIdentity(const DbgModule& module) {
    return { module.base, module.size, module.name, module.path,
             module.loadGeneration };
}

static const DbgModule* matchingAttachedModule(
    const DbgSnapshot& snapshot,
    const AttachedModuleIdentity& expected) {
    for (const DbgModule& module : snapshot.modules)
        if (module.base == expected.base &&
            AttachedModuleIdentityMatches(expected,
                                          attachedModuleIdentity(module)))
            return &module;
    return nullptr;
}

static DocumentRuntimeMetadata::LiveImageIdentity debugImageIdentity(
    const DbgSnapshot& snapshot, const DbgModule& module) {
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = liveDocumentSessionState(snapshot) &&
                     snapshot.pid != 0 &&
                     snapshot.sessionGeneration != 0 && module.base != 0 &&
                     module.loadGeneration != 0;
    identity.pid = snapshot.pid;
    identity.sessionGeneration = snapshot.sessionGeneration;
    identity.moduleBase = module.base;
    identity.moduleSize = module.size;
    identity.moduleName = module.name;
    identity.modulePath = module.path;
    identity.moduleLoadGeneration = module.loadGeneration;
    return identity;
}

static void storeRawDecoderFeatures(ProjectState& project,
                                    const DecoderFeatures& features) {
    project.rawDecoderFeatureBits = DecoderFeatureBits(features);
    project.rawRiscvCompressed = features.riscvCompressed;
}

AppContext::AppContext()
    : moduleAnalysis_([](const DecoderConfig& config) {
          return MakeDisassembler(config);
      }),
      documents_(
          [](const DecoderConfig& config) { return MakeDisassembler(config); },
          [](const BinaryFile& binary, const ProjectState& snapshot,
             std::string& error) {
              // Live mapped images intentionally have no durable sidecar.
              if (!binary.loaded() || binary.isMappedImage() || !snapshot.hash)
                  return true;
              if (SaveProject(snapshot)) return true;
              error = "Project save failed; changes remain in memory.";
              return false;
          }) {
    moduleAnalysis_.setActiveDocument(false);
    if (!documents_.create("Untitled"))
        throw std::runtime_error("Unable to create the initial static document: " +
                                 documents_.lastError());
}

AppContext::~AppContext() {
    if (binaryLoadFuture_.valid()) {
        cancelBinaryLoad();
        try { binaryLoadFuture_.wait(); }
        catch (...) {}
    }
    // std::future's async destructor also waits, but joining explicitly while
    // DocumentManager is still alive lets the completion reach the exact
    // originating document and preserves its dirty/failure state for the
    // manager's final synchronous flush retry.
    if (projectSaveFuture.valid()) (void)finishProjectSave(true);
}

DocumentContext& AppContext::activeStaticDocument() {
    DocumentContext* document = documents_.active();
    if (!document) throw std::logic_error("AppContext has no active static document");
    return *document;
}

const DocumentContext& AppContext::activeStaticDocument() const {
    const DocumentContext* document = documents_.active();
    if (!document) throw std::logic_error("AppContext has no active static document");
    return *document;
}

std::vector<AppContext::StaticDocumentSummary> AppContext::staticDocuments() const {
    std::vector<StaticDocumentSummary> result;
    result.reserve(documents_.size());
    const std::optional<DocumentId> active = documents_.activeId();
    for (size_t i = 0; i < documents_.size(); ++i) {
        const DocumentContext* document = documents_.at(i);
        if (!document) continue;
        const BinaryFile& binary = document->binary();
        result.push_back({
            document->id(), document->title(), binary.path(),
            binary.loaded() ? binary.formatName() : std::string(),
            binary.loaded(), binary.loaded() && binary.isMappedImage(),
            document->dirty(), active && *active == document->id()
        });
    }
    return result;
}

bool AppContext::documentCommandPending() const {
    return pendingDocumentCommand_.has_value() || binaryLoadFuture_.valid();
}

bool AppContext::queueDocumentOpen(PendingDocumentCommand command) {
    documentCommandError_.clear();
    if (pendingDocumentCommand_) {
        documentCommandError_ =
            "Another document operation is already queued for this frame.";
        return false;
    }
    try {
        pendingDocumentCommand_.emplace(std::move(command));
    } catch (const std::exception& error) {
        documentCommandError_ = std::string("Could not stage the document: ") + error.what();
        return false;
    } catch (...) {
        documentCommandError_ = "Could not stage the document.";
        return false;
    }
    return true;
}

bool AppContext::queueActivateStaticDocument(DocumentId id) {
    documentCommandError_.clear();
    if (!id || !documents_.find(id)) {
        documentCommandError_ = "The selected document is no longer open.";
        return false;
    }
    if (documents_.activeId() && *documents_.activeId() == id) return true;
    PendingDocumentCommand command;
    command.kind = PendingDocumentKind::Activate;
    command.id = id;
    return queueDocumentOpen(std::move(command));
}

void AppContext::setTypeDraftPending(DocumentId id, bool pending) {
    if (auto* document = documents_.find(id)) document->setTypeDraftPending(pending);
}

bool AppContext::commitTypeDefinition(DocumentId id, uint64_t imageGeneration,
    const TypeDefinition& definition, bool persist, std::string& error) {
    error.clear();
    auto* document = documents_.find(id);
    if (!document || !document->open() || !document->binary().loaded() ||
        document->imageGeneration() != imageGeneration) {
        error = "The Types draft belongs to a different document image; its contents have been retained.";
        return false;
    }
    if (persist && (document->persistence() == DocumentInstallPersistence::Ephemeral ||
                    document->binary().isMappedImage())) {
        error = "This live-image document has no persistent project sidecar. The Types draft cannot be saved for closing; cancel to keep it open, or explicitly discard it.";
        return false;
    }
    TypeRegistry proposed = document->project().typeRegistry;
    if (auto* old = FindType(proposed, definition.id)) *old = definition;
    else proposed.types.push_back(definition);
    if (!RecomputeTypeArraySizes(proposed, &error) || !ValidateTypeRegistry(proposed, &error)) return false;
    for (const auto& application : proposed.applications) {
        const auto* type = FindType(proposed, application.typeId);
        size_t available = 0;
        if (!type || !document->binary().ptrFromVA(application.address, available) || type->sizeBytes > available) {
            error = "Definition would extend an applied global beyond backed FILE memory.";
            return false;
        }
    }
    // Join any older asynchronous save before committing a closing draft. This
    // applies equally to inactive documents, whose state cannot use active aliases.
    if (persist && projectSaveFuture.valid() && !finishProjectSave(true)) {
        error = projectSaveError;
        return false;
    }
    TypeRegistry previous = document->project().typeRegistry;
    document->editProject().typeRegistry = std::move(proposed);
    if (persist && !document->flush(&error)) {
        document->editProject().typeRegistry = std::move(previous);
        if (id == staticDocumentId()) resetProjectSaveMirrorFromActive();
        return false;
    }
    document->setTypeDraftPending(false);
    if (id == staticDocumentId()) resetProjectSaveMirrorFromActive();
    return true;
}

bool AppContext::queueCloseStaticDocument(DocumentId id) {
    documentCommandError_.clear();
    if (!id || !documents_.find(id)) {
        documentCommandError_ = "The selected document is no longer open.";
        return false;
    }
    PendingDocumentCommand command;
    command.kind = PendingDocumentKind::Close;
    command.id = id;
    return queueDocumentOpen(std::move(command));
}

AppContext::DocumentCommandOutcome AppContext::applyPendingDocumentCommand(
    const PrepareDocumentUi& prepareUi) {
    DocumentCommandOutcome outcome;
    if (!pendingDocumentCommand_) return outcome;

    outcome.hadCommand = true;
    PendingDocumentCommand command = std::move(*pendingDocumentCommand_);
    pendingDocumentCommand_.reset();
    documentCommandError_.clear();
    if (const auto active = documents_.activeId()) outcome.previous = *active;
    if (command.liveModule) {
        outcome.liveModule = true;
        outcome.liveOrigin = command.liveOrigin;
        outcome.livePid = command.livePid;
        outcome.liveSessionGeneration = command.liveSessionGeneration;
        outcome.liveBase = command.liveBase;
    }

    auto callPrepareUi = [&](DocumentId id, bool closing,
                             std::string& error) -> bool {
        if (!prepareUi) return true;
        try {
            if (prepareUi(id, closing, error)) return true;
            if (error.empty()) error = "The document view rejected the transition.";
        } catch (const std::exception& exception) {
            error = exception.what();
        } catch (...) {
            error = "The document view could not prepare for the transition.";
        }
        return false;
    };

    // Manager callbacks run while the outgoing document is still the active
    // compatibility target. Mirror its Binary View first, then serialize with
    // the exact asynchronous sidecar ticket before changing activeId().
    DocumentManager::PrepareTransition prepareOutgoing =
        [&](DocumentContext& document, std::string& error) {
            if (!callPrepareUi(document.id(), false, error)) return false;
            return prepareStaticDocumentTransition(&error);
        };
    DocumentManager::PrepareTransition persistOutgoing =
        [&](DocumentContext&, std::string& error) {
            return prepareStaticDocumentTransition(&error);
        };

    auto fail = [&](std::string error) {
        outcome.error = error.empty() ? "The document operation failed." : std::move(error);
        documentCommandError_ = outcome.error;
        if (const auto active = documents_.activeId()) outcome.current = *active;
        outcome.activeChanged = outcome.previous != outcome.current;
        if (outcome.activeChanged && outcome.current) resetProjectSaveMirrorFromActive();
        return outcome;
    };

    if (command.kind == PendingDocumentKind::Open) {
        if (command.liveModule) {
            const DbgSnapshot snapshot = debug.snapshot();
            const AttachedModuleIdentity expected{
                command.liveBase, command.liveReportedSize,
                command.liveName, command.livePath,
                command.liveLoadGeneration
            };
            if (!liveDocumentSessionState(snapshot) ||
                snapshot.pid != command.livePid ||
                snapshot.sessionGeneration != command.liveSessionGeneration) {
                return fail("The debug session changed before the live module could be opened.");
            }
            const DbgModule* current = matchingAttachedModule(snapshot, expected);
            if (!current) {
                return fail(
                    "The exact live module unloaded or changed before its document could be opened.");
            }
            if (command.liveOrigin == LiveDocumentOpenOrigin::AttachMain &&
                (snapshot.modules.empty() ||
                 snapshot.modules.front().base != command.liveBase)) {
                return fail("The process main image changed before its document could be opened.");
            }
            if (command.liveOrigin == LiveDocumentOpenOrigin::HostedDll &&
                (!snapshot.dllHostedLaunch || !snapshot.dllTargetMatched ||
                 snapshot.dllTargetBase != command.liveBase)) {
                return fail("The hosted DLL target changed before its document could be opened.");
            }
        }

        const bool retireInitialScratch = documents_.size() == 1 &&
            documents_.active() && !documents_.active()->binary().loaded();
        const DocumentId scratchId = retireInitialScratch
                                   ? documents_.active()->id() : DocumentId{};
        DocumentManager::OpenResult opened = documents_.openStaged(
            std::move(command.title), std::move(command.image),
            std::move(command.project), command.decoder,
            command.persistence, std::move(command.metadata),
            std::move(prepareOutgoing),
            command.liveModule ? DocumentOpenReuse::AlwaysCreate
                               : DocumentOpenReuse::ReuseContentHash);
        if (!opened) return fail(std::move(opened.error));

        outcome.success = true;
        outcome.opened = true;
        if (retireInitialScratch && scratchId != opened.id) {
            std::string scratchError;
            if (documents_.close(scratchId, {}, &scratchError)) {
                outcome.retired = scratchId;
            } else {
                outcome.warning = scratchError.empty()
                    ? "The initial empty document could not be retired."
                    : "The initial empty document could not be retired: " + scratchError;
            }
        }

        if (command.liveModule) {
            modules.addOrUpdate(command.liveName, command.liveBase,
                                command.liveReportedSize
                                    ? command.liveReportedSize
                                    : command.liveSize,
                                command.livePath);
            if (LoadedModule* module = modules.byBase(command.liveBase))
                module->arch = staticBinary().machine();
            modules.setActiveByBase(command.liveBase);
        }
        outcome.browseArchive = command.browseArchive;
        if (command.ignoredInvalidRawProject) {
            if (!outcome.warning.empty()) outcome.warning += " ";
            outcome.warning +=
                "Ignored an invalid saved raw mapping and used a safe fallback mapping.";
        }
        if (!command.projectLoadWarning.empty()) {
            if (!outcome.warning.empty()) outcome.warning += " ";
            outcome.warning += command.projectLoadWarning;
        }
        binaryJustLoaded = opened.status == DocumentManager::OpenStatus::Created;
    } else if (command.kind == PendingDocumentKind::Activate) {
        std::string error;
        if (!documents_.activate(command.id, std::move(prepareOutgoing), &error))
            return fail(std::move(error));
        outcome.success = true;
    } else {
        DocumentContext* target = documents_.find(command.id);
        if (!target) return fail("The selected document is no longer open.");

        std::string error;
        // Inactive views are already mirrored from their last deactivation, but
        // they may still own a symbol worker. Give every close target this edge
        // before DocumentContext releases its BinaryFile storage.
        if (!callPrepareUi(command.id, true, error)) return fail(std::move(error));

        if (documents_.size() == 1) {
            // Construct the replacement scratch while the old owner is intact.
            // If allocation/decoder construction fails, close is rejected with
            // the original document still active.
            const std::optional<DocumentId> scratch =
                documents_.create("Untitled", std::move(persistOutgoing));
            if (!scratch) return fail(documents_.lastError());

            if (!documents_.close(command.id, {}, &error)) {
                std::string ignored;
                (void)documents_.activate(command.id, {}, &ignored);
                (void)documents_.close(*scratch, {}, &ignored);
                return fail(std::move(error));
            }
        } else if (!documents_.close(command.id, std::move(persistOutgoing), &error)) {
            return fail(std::move(error));
        }
        outcome.success = true;
        outcome.closed = true;
        outcome.retired = command.id;
        binaryJustLoaded = false;
    }

    if (const auto active = documents_.activeId()) outcome.current = *active;
    outcome.activeChanged = outcome.previous != outcome.current;
    ++documentRetryRevision_;
    if (!documentRetryRevision_) ++documentRetryRevision_;
    resetProjectSaveMirrorFromActive();
    if (staticBinary().loaded() && staticBinary().isMappedImage())
        modules.setActiveByBase(staticBinary().imageBase());
    return outcome;
}

void AppContext::markProjectDirty() {
    if (!staticBinary().loaded() || staticBinary().isMappedImage() ||
        !staticProject().hash)
        return;
    activeStaticDocument().markDirty();
    ++projectRevision;
    if (!projectRevision) ++projectRevision;
    projectSaveState = projectSaveFuture.valid()
                     ? ProjectSaveState::Saving : ProjectSaveState::Dirty;
    projectSaveError.clear();
    projectDirtySince = std::chrono::steady_clock::now();
}

bool AppContext::projectDirty() const {
    return activeStaticDocument().dirty();
}

bool AppContext::setStaticDecoderConfiguration(Engine engine, Arch arch) {
    DecoderConfig decoder = staticDecoderConfig();
    decoder.engine = engine;
    decoder.arch = arch;
    return setStaticDecoderConfiguration(decoder);
}

bool AppContext::setStaticDecoderConfiguration(const DecoderConfig& decoder) {
    DocumentContext& document = activeStaticDocument();
    const DecoderConfig previous = document.decoderConfig();
    if (!document.setDecoderConfiguration(decoder)) return false;
    const bool changed = document.decoderConfig() != previous;
    if (changed && staticBinary().loaded() && staticBinary().isMappedImage()) {
        // Decoder choices for ephemeral live mappings are session-only.
        (void)document.acknowledgeExternalSave(document.externalSaveTicket());
    } else if (changed && staticBinary().loaded() && staticProject().hash) {
        // DocumentContext already marked its own revision while updating the
        // persisted engine/architecture fields. Mirror only the legacy async
        // writer's generation here so one UI action is one document edit.
        ++projectRevision;
        if (!projectRevision) ++projectRevision;
        projectSaveState = projectSaveFuture.valid()
                         ? ProjectSaveState::Saving : ProjectSaveState::Dirty;
        projectSaveError.clear();
        projectDirtySince = std::chrono::steady_clock::now();
    }
    return true;
}

App::App(std::string startupPath) {
    loadPrefs();                 // restore the last-used theme, density and zoom
    theme::SetDensity(density_);
    theme::ApplyTheme(theme_);
    tabs_.emplace_back(std::make_unique<ProjectsTab>());
    tabs_.emplace_back(std::make_unique<CommunicationsTab>());
    tabs_.emplace_back(std::make_unique<SigScannerTab>());
    {   // retained children keep one complete Binary View workspace per document
        auto bv = std::make_unique<BinaryViewHostTab>();
        binaryView_ = bv.get();
        tabs_.emplace_back(std::move(bv));
    }
    tabs_.emplace_back(std::make_unique<MemoryToolsTab>());
    tabs_.emplace_back(std::make_unique<BinaryDiffTab>());
    tabs_.emplace_back(std::make_unique<BinaryTechTab>());
    tabs_.emplace_back(std::make_unique<CortexTab>());   // RE brain (additions.md #3)
    tabs_.emplace_back(std::make_unique<PrismTab>());    // explanatory profiler (additions.md #5)

    if (!startupPath.empty()) {
        if (ctx_.beginBinaryLoadPath(startupPath)) {
            ctx_.requestedTab = "Binary View";
            ui::Toast(ui::ToastKind::Info, "Opening command-line target: " + startupPath);
        } else {
            ui::Toast(ui::ToastKind::Error, "Could not open command-line target: " + startupPath);
        }
    }
}

App::~App() {
    std::string ignored;
    if (binaryView_)
        (void)binaryView_->prepareDocumentTransition(
            ctx_, ctx_.staticDocumentId(), false, ignored);
    ctx_.saveProject();   // flush analysis on shutdown (window close / Alt+F4)
}

void App::requestExit() {
    if (exit_ || exitPending_) return;
    exitFailure_.clear();
    if (binaryView_ && !binaryView_->prepareTypeDraftsForExit(ctx_)) {
        exitFailure_ = "Pending type edits need a save or discard decision before closing.";
        return;
    }
    exitPending_ = true;
    exitArtifactRevision_ = ctx_.artifactWriteCompletionRevision;
    exitDebugRequestId_ = 0;
    pollExit();
}

void App::pollExitWithoutRendering() {
    ctx_.pollArtifactWrites();
    pollExit();
}

std::string App::exitFailureReason() {
    if (!exitFailure_.empty()) return exitFailure_;
    const auto target = ctx_.debug.snapshot();
    if (target.cleanupOnly) return target.lastEvent;
    const auto lifecycle = ctx_.debug.lifecycleSnapshot();
    if (!lifecycle.error.empty()) return lifecycle.error;
    if (!ctx_.projectSaveError.empty()) return ctx_.projectSaveError;
    if (ctx_.artifactWriteFailed && !ctx_.artifactWriteFailure.empty())
        return ctx_.artifactWriteFailure;
    return "The active document still needs attention before it can close.";
}

void App::pollExit() {
    if (!exitPending_) return;
    // Consume accepted file jobs before leaving, including their UI callback.
    // A failed/partial output cancels this close attempt so its error stays visible.
    if (ctx_.artifactWriteCompletionRevision != exitArtifactRevision_ &&
        ctx_.artifactWriteFailed) {
        exitFailure_ = ctx_.artifactWriteFailure;
        exitPending_ = false;
        return;
    }
    if (ctx_.artifactWrites.pending()) return;

    const auto lifecycle = ctx_.debug.lifecycleSnapshot();
    if (exitDebugRequestId_) {
        // A different lifecycle request belongs to a newer user action.
        if (lifecycle.requestId != exitDebugRequestId_) {
            exitFailure_ = "A newer debugger operation replaced this close request.";
            exitPending_ = false;
            return;
        }
        if (lifecycle.busy) return;
        if (!lifecycle.completed ||
            (!lifecycle.succeeded && (lifecycle.command == DbgLifecycleCommand::Detach ||
                                     ctx_.debug.snapshot().cleanupOnly))) {
            exitFailure_ = lifecycle.error.empty() ? "Debugger cleanup did not complete." : lifecycle.error;
            exitPending_ = false;
            return;
        }
        exitDebugRequestId_ = 0;
    } else if (lifecycle.busy) {
        exitDebugRequestId_ = lifecycle.requestId;
        if (lifecycle.command != DbgLifecycleCommand::Detach)
            ctx_.debug.cancelLifecycle(lifecycle.requestId);
        return;
    }

    const auto target = ctx_.debug.snapshot();
    if (target.state != DbgState::Detached) {
        exitDebugRequestId_ = ctx_.debug.requestDetach({target.pid, target.sessionGeneration});
        if (!exitDebugRequestId_) {
            exitPending_ = false;
            exitFailure_ = "Could not request debugger cleanup; the application remains open.";
            ui::Toast(ui::ToastKind::Error, exitFailure_);
        }
        return;
    }

    // The document can change while cleanup runs, so validate and save it at the
    // final close boundary. Failed debugger cleanup never reaches destruction.
    exitPending_ = false;
    if (binaryView_ && !binaryView_->prepareTypeDraftsForExit(ctx_)) {
        exitFailure_ = "Pending type edits need a save or discard decision before closing.";
        return;
    }
    std::string error;
    if (binaryView_ && !binaryView_->prepareDocumentTransition(
            ctx_, ctx_.staticDocumentId(), false, error)) {
        exitFailure_ = error.empty() ? "Could not prepare the active document for exit." : error;
        ui::Toast(ui::ToastKind::Error, exitFailure_);
        return;
    }
    if (ctx_.saveProject()) exit_ = true;
    else {
        exitFailure_ = ctx_.projectSaveError;
        ui::Toast(ui::ToastKind::Error, exitFailure_);
    }
}

namespace {
constexpr DWORD kDialogPathChars = 32768;

// Win32's common dialogs return UTF-16 paths. Convert with a sizing pass so
// non-ASCII paths are never truncated into a fixed narrow buffer. Explicit
// source lengths also avoid writing a terminator past std::string's storage.
bool utf8FromWide(const wchar_t* value, std::string& out) {
    out.clear();
    if (!value) return false;
    const size_t len = std::wcslen(value);
    if (len > static_cast<size_t>((std::numeric_limits<int>::max)())) return false;
    if (!len) return true;
    const int inputLen = static_cast<int>(len);
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                            value, inputLen, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return false;
    out.resize(static_cast<size_t>(needed));
    const int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                             value, inputLen, out.data(), needed,
                                             nullptr, nullptr);
    if (written != needed) { out.clear(); return false; }
    return true;
}

bool wideFromUtf8(const std::string& value, std::wstring& out) {
    out.clear();
    if (value.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) return false;
    if (value.empty()) return true;
    const int inputLen = static_cast<int>(value.size());
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           value.data(), inputLen, nullptr, 0);
    if (needed <= 0) return false;
    out.resize(static_cast<size_t>(needed));
    const int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                            value.data(), inputLen, out.data(), needed);
    if (written != needed) { out.clear(); return false; }
    return true;
}

std::filesystem::path pathFromUtf8(const std::string& value) {
    std::u8string utf8(value.size(), u8'\0');
    if (!value.empty()) std::memcpy(utf8.data(), value.data(), value.size());
    return std::filesystem::path(utf8);
}

AttachedFileIdentity attachedFileIdentityForHandle(HANDLE file) {
    AttachedFileIdentity identity;
    if (!file || file == INVALID_HANDLE_VALUE) return identity;
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileInformationByHandle(file, &info)) {
        identity.valid = true;
        identity.volumeSerial = info.dwVolumeSerialNumber;
        identity.fileIndex =
            (static_cast<uint64_t>(info.nFileIndexHigh) << 32) |
            info.nFileIndexLow;
        identity.fileSize =
            (static_cast<uint64_t>(info.nFileSizeHigh) << 32) |
            info.nFileSizeLow;
        identity.lastWriteTime =
            (static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
            info.ftLastWriteTime.dwLowDateTime;
    }
    return identity;
}

bool loadedBytesStillMatchDisk(const BinaryFile& binary,
                               AttachedFileIdentity* identityOut = nullptr) {
    if (identityOut) *identityOut = {};
    if (!binary.loaded() || binary.isMappedImage() || binary.path().empty())
        return false;
    const std::vector<uint8_t>& expected = binary.bytes();
    if (expected.empty() ||
        expected.size() > kAuthorizationWatchSourceByteCap)
        return false;

    std::vector<uint8_t> chunk;
    try {
        chunk.resize((std::min<size_t>)(1024u * 1024u, expected.size()));
    } catch (...) {
        return false;
    }

    std::wstring wide;
    if (!wideFromUtf8(binary.path(), wide) || wide.empty()) return false;
    HANDLE file = CreateFileW(
        wide.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const AttachedFileIdentity identity = attachedFileIdentityForHandle(file);
    if (!identity.valid || identity.fileSize != expected.size()) {
        CloseHandle(file);
        return false;
    }

    size_t offset = 0;
    while (offset < expected.size()) {
        const size_t count = (std::min)(chunk.size(), expected.size() - offset);
        DWORD got = 0;
        if (!ReadFile(file, chunk.data(), static_cast<DWORD>(count), &got,
                      nullptr) || got != static_cast<DWORD>(count) ||
            std::memcmp(chunk.data(), expected.data() + offset, count) != 0) {
            CloseHandle(file);
            return false;
        }
        offset += count;
    }
    const AttachedFileIdentity identityAfterRead =
        attachedFileIdentityForHandle(file);
    CloseHandle(file);
    if (!SameAttachedFileIdentity(identity, identityAfterRead)) return false;
    if (identityOut) *identityOut = identityAfterRead;
    return true;
}

const char* dllBitnessName(DllBitness value) {
    switch (value) {
        case DllBitness::X86: return "x86";
        case DllBitness::X64: return "x64";
        default: return "unknown";
    }
}

DllBitness nativeWindowsDllBitness() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        return DllBitness::X64;
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        return DllBitness::X86;
    // An ARM64 System32 host cannot load an x64 DLL even when Windows provides
    // x64 emulation, so do not claim a safely compatible system host here.
    return DllBitness::Unknown;
}

std::optional<std::string> systemRundll32Path(DllSystemHostPath policy) {
    std::vector<wchar_t> dir(kDialogPathChars, L'\0');
    UINT n = 0;
    if (policy == DllSystemHostPath::NativeSystem32) {
        n = GetSystemDirectoryW(dir.data(), static_cast<UINT>(dir.size()));
    } else {
        n = GetWindowsDirectoryW(dir.data(), static_cast<UINT>(dir.size()));
        if (n && n < dir.size()) {
            std::wstring value(dir.data(), n);
            if (!value.empty() && value.back() != L'\\') value.push_back(L'\\');
            value += L"SysWOW64";
            if (value.size() >= dir.size()) return std::nullopt;
            std::copy(value.begin(), value.end(), dir.begin());
            dir[value.size()] = L'\0';
            n = static_cast<UINT>(value.size());
        }
    }
    if (!n || n >= dir.size()) return std::nullopt;
    std::wstring path(dir.data(), n);
    if (!path.empty() && path.back() != L'\\') path.push_back(L'\\');
    path += L"rundll32.exe";
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY))
        return std::nullopt;
    std::string utf8;
    if (!utf8FromWide(path.c_str(), utf8) || utf8.empty()) return std::nullopt;
    return utf8;
}

bool splitWindowsUserArguments(const char* text, std::vector<std::string>& out,
                               std::string& error) {
    out.clear();
    error.clear();
    if (!text || !*text) return true;
    std::wstring args;
    if (!wideFromUtf8(text, args)) {
        error = "The argument text is not valid UTF-8.";
        return false;
    }
    // CommandLineToArgvW applies special parsing to argv[0]. Prefix a harmless
    // executable token so every user-supplied token follows the normal Windows
    // backslash/quote rules, then discard that first result.
    std::wstring command = L"dllhost ";
    command += args;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(command.c_str(), &argc);
    if (!argv) {
        error = "Windows could not parse the argument text.";
        return false;
    }
    bool ok = true;
    for (int i = 1; i < argc; ++i) {
        std::string value;
        if (!utf8FromWide(argv[i], value)) {
            error = "A parsed argument could not be encoded as UTF-8.";
            ok = false;
            break;
        }
        out.push_back(std::move(value));
    }
    LocalFree(argv);
    if (!ok) out.clear();
    return ok;
}

std::string dllExportLabel(const DllCallableExport& value) {
    if (!value.name.empty()) return DemangleForDisplay(value.name);
    return "#" + std::to_string(value.ordinal);
}

bool parseHexU64(const char* text, uint64_t& out) {
    if (!text) return false;
    while (*text && std::isspace((unsigned char)*text)) ++text;
    if (!*text || *text == '-') return false;
    const char* begin = text;
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 16);
    while (end && *end && std::isspace((unsigned char)*end)) ++end;
    if (errno == ERANGE || !end || end == begin || *end != '\0') return false;
    out = static_cast<uint64_t>(value);
    return true;
}

void formatHexU64(char* dst, size_t capacity, uint64_t value) {
    if (dst && capacity)
        std::snprintf(dst, capacity, "0x%llX", (unsigned long long)value);
}

int rawArchForFirmwareMode(FirmwareCpuMode mode) {
    switch (mode) {
        case FirmwareCpuMode::X86Real16: return 0;
        case FirmwareCpuMode::X86_32:    return 1;
        case FirmwareCpuMode::X86_64:    return 2;
        case FirmwareCpuMode::ARM_A32:   return 3;
        case FirmwareCpuMode::ARM_Thumb: return 4;
        case FirmwareCpuMode::ARM_AArch64: return 5;
        default:                         return 2;
    }
}

Arch rawArchFromSelection(int selection) {
    switch (selection) {
        case 0: return Arch::X86_16;
        case 1: return Arch::X86;
        case 2: return Arch::X64;
        case 3: return Arch::ARM;
        case 4: return Arch::THUMB;
        case 5: return Arch::ARM64;
        case 6: return Arch::MIPS;
        case 7: return Arch::MIPS64;
        case 8: return Arch::PPC;
        case 9: return Arch::PPC64;
        case 10: return Arch::RISCV32;
        case 11: return Arch::RISCV64;
        default: return Arch::X64;
    }
}

static bool archFitsActiveRawMapping(const AppContext& ctx, Arch arch) {
    return !ctx.staticBinary().loaded() ||
           ctx.staticBinary().format() != BinFormat::Raw ||
           ArchMappingRangeFits(arch, ctx.staticBinary().imageBase(),
                                ctx.staticBinary().bytes().size());
}

// Firmware probing happens after the native file picker but before the modal is
// shown. Raw PC firmware is normally a few MiB; cap the synchronous probe so an
// arbitrarily large blob never turns opening the options dialog into a huge
// allocation. The normal raw loader remains available when probing is skipped.
bool readFirmwareProbe(const std::string& path, uint64_t& sizeOut,
                       FirmwareDetection& detection, std::string& note) {
    sizeOut = 0;
    detection = FirmwareDetection{};
    note.clear();
    std::ifstream f(pathFromUtf8(path), std::ios::binary | std::ios::ate);
    if (!f) return false;
    const std::streamsize n = f.tellg();
    if (n <= 0) return false;
    sizeOut = static_cast<uint64_t>(n);
    constexpr uint64_t kProbeFileCap = 64ull * 1024ull * 1024ull;
    if (sizeOut > kProbeFileCap) {
        note = "Firmware sniff skipped because the file exceeds the 64 MiB interactive probe limit.";
        return true;
    }
    if (sizeOut > static_cast<uint64_t>((std::numeric_limits<size_t>::max)())) return false;
    std::vector<uint8_t> bytes(static_cast<size_t>(sizeOut));
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(bytes.data()), n)) return false;
    detection = SniffFirmware(bytes);
    if (detection.scanTruncated)
        note = "Signature scanning used bounded head/tail windows; fixed reset-vector checks still ran.";
    else if (!detection.detected())
        note = "No corroborated PC-firmware structure was detected; raw settings remain manual.";
    return true;
}

std::string pathLeafLower(const std::string& value) {
    size_t slash = value.find_last_of("/\\");
    std::string leaf = slash == std::string::npos ? value : value.substr(slash + 1);
    for (char& c : leaf) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return leaf;
}

std::wstring normalizedWindowsPath(const std::string& value) {
    std::wstring wide;
    if (!wideFromUtf8(value, wide) || wide.empty()) return {};
    if (wide.rfind(L"\\\\?\\", 0) == 0) wide.erase(0, 4);
    std::vector<wchar_t> full(kDialogPathChars, L'\0');
    DWORD n = GetFullPathNameW(wide.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
    if (n && n < full.size()) wide.assign(full.data(), n);
    for (wchar_t& c : wide) {
        if (c == L'/') c = L'\\';
        c = static_cast<wchar_t>(std::towlower(c));
    }
    return wide;
}

const DbgModule* unpackMainModule(const DbgSnapshot& snap, const std::string& sourcePath) {
    const std::wstring wantedPath = normalizedWindowsPath(sourcePath);
    const std::string wantedLeaf = pathLeafLower(sourcePath);
    for (const auto& m : snap.modules) {
        if (!m.path.empty() && !wantedPath.empty() && normalizedWindowsPath(m.path) == wantedPath)
            return &m;
        if (m.path.empty() && !m.name.empty() && pathLeafLower(m.name) == wantedLeaf)
            return &m;
    }
    // The debugger explicitly publishes CREATE_PROCESS as the first module. Use
    // that fallback only when Windows supplied no path at all; a resolved path
    // mismatch means the analyst attached a different process and must not dump it
    // under the loaded file's identity.
    if (!snap.modules.empty() && snap.modules.front().path.empty() &&
        snap.modules.front().name.rfind("<main@", 0) == 0) return &snap.modules.front();
    return nullptr;
}

bool readMappedImage(Debugger& dbg, uint64_t base, uint64_t size,
                     std::vector<uint8_t>& out, uint64_t cap,
                     std::vector<uint8_t>* validPages = nullptr) {
    if (!base || !size || base > UINT64_MAX - size || size > cap ||
        size > static_cast<uint64_t>((std::numeric_limits<size_t>::max)()))
        return false;
    out.assign(static_cast<size_t>(size), 0);
    const size_t pageCount = (out.size() + 0xfff) / 0x1000;
    std::vector<uint32_t> covered;
    if (validPages) {
        validPages->assign(pageCount, 0);
        covered.assign(pageCount, 0);
    }
    bool any = false;
    const auto regions = dbg.regions();
    constexpr size_t kChunk = 1u << 20;
    for (const auto& region : regions) {
        if (!region.read || !region.size || region.base > UINT64_MAX - region.size) continue;
        const uint64_t lo = std::max(base, region.base);
        const uint64_t hi = std::min(base + size, region.base + region.size);
        if (lo >= hi) continue;
        uint64_t at = lo;
        while (at < hi) {
            const size_t want = static_cast<size_t>(std::min<uint64_t>(hi - at, kChunk));
            const size_t got = dbg.readMemoryMasked(at, out.data() + static_cast<size_t>(at - base), want);
            if (!got) break;
            any = true;
            if (validPages) {
                const uint64_t readLo = at - base;
                const uint64_t readHi = readLo + got;
                const size_t firstPage = static_cast<size_t>(readLo / 0x1000);
                const size_t lastPage = static_cast<size_t>((readHi - 1) / 0x1000);
                for (size_t page = firstPage; page <= lastPage; ++page) {
                    const uint64_t pageLo = static_cast<uint64_t>(page) * 0x1000;
                    const uint64_t pageHi = std::min<uint64_t>(size, pageLo + 0x1000);
                    const uint64_t overlapLo = std::max(readLo, pageLo);
                    const uint64_t overlapHi = std::min(readHi, pageHi);
                    if (overlapLo < overlapHi)
                        covered[page] += static_cast<uint32_t>(overlapHi - overlapLo);
                }
            }
            at += got;
            if (got < want) break;
        }
    }
    if (validPages) {
        for (size_t page = 0; page < pageCount; ++page) {
            const size_t pageLo = page * 0x1000;
            const size_t required = std::min<size_t>(0x1000, out.size() - pageLo);
            (*validPages)[page] = covered[page] >= required ? 1 : 0;
        }
    }
    return any;
}

double sampledEntropy(const std::vector<uint8_t>& bytes,
                      const std::vector<uint8_t>* validPages = nullptr) {
    if (bytes.empty()) return 0.0;
    constexpr size_t kMaxSamples = 4u * 1024u * 1024u;
    const size_t stride = std::max<size_t>(1, bytes.size() / kMaxSamples);
    uint64_t hist[256]{};
    uint64_t n = 0;
    for (size_t i = 0; i < bytes.size(); i += stride) {
        if (validPages && (i / 0x1000 >= validPages->size() || !(*validPages)[i / 0x1000])) continue;
        ++hist[bytes[i]]; ++n;
    }
    if (!n) return 0.0;
    double h = 0.0;
    for (uint64_t count : hist) if (count) {
        const double p = static_cast<double>(count) / static_cast<double>(n);
        h -= p * std::log2(p);
    }
    return h;
}

bool mappedPeCoverageComplete(const std::vector<uint8_t>& mapped,
                              const std::vector<uint8_t>& validPages,
                              std::string& reason) {
    auto read16 = [&](size_t off, uint16_t& v) {
        if (off > mapped.size() || mapped.size() - off < sizeof(v)) return false;
        std::memcpy(&v, mapped.data() + off, sizeof(v)); return true;
    };
    auto read32 = [&](size_t off, uint32_t& v) {
        if (off > mapped.size() || mapped.size() - off < sizeof(v)) return false;
        std::memcpy(&v, mapped.data() + off, sizeof(v)); return true;
    };
    auto covered = [&](uint64_t off, uint64_t len) {
        if (!len) return true;
        if (off > mapped.size() || len > mapped.size() - off) return false;
        const size_t first = static_cast<size_t>(off / 0x1000);
        const size_t last = static_cast<size_t>((off + len - 1) / 0x1000);
        if (last >= validPages.size()) return false;
        for (size_t page = first; page <= last; ++page) if (!validPages[page]) return false;
        return true;
    };
    if (!covered(0, std::min<size_t>(mapped.size(), 0x1000))) {
        reason = "PE headers were not fully readable"; return false;
    }
    uint32_t pe = 0, sig = 0, sizeHeaders = 0;
    uint16_t sections = 0, optionalSize = 0;
    if (mapped.size() < 0x40 || mapped[0] != 'M' || mapped[1] != 'Z' ||
        !read32(0x3c, pe) || !read32(static_cast<size_t>(pe), sig) || sig != 0x00004550 ||
        !read16(static_cast<size_t>(pe) + 6, sections) ||
        !read16(static_cast<size_t>(pe) + 20, optionalSize) ||
        !read32(static_cast<size_t>(pe) + 24 + 60, sizeHeaders)) {
        reason = "captured PE headers are incomplete"; return false;
    }
    if (!covered(0, sizeHeaders)) {
        reason = "one or more header pages were unreadable"; return false;
    }
    const uint64_t table = static_cast<uint64_t>(pe) + 24 + optionalSize;
    if (sections > 96 || table > mapped.size() ||
        static_cast<uint64_t>(sections) * 40 > mapped.size() - table) {
        reason = "captured section table is incomplete"; return false;
    }
    for (uint16_t i = 0; i < sections; ++i) {
        const size_t sh = static_cast<size_t>(table + static_cast<uint64_t>(i) * 40);
        uint32_t virtualSize = 0, rawSize = 0, rva = 0;
        if (!read32(sh + 8, virtualSize) || !read32(sh + 16, rawSize) ||
            !read32(sh + 12, rva) || !covered(rva, std::max(virtualSize, rawSize))) {
            reason = "one or more reconstructed section pages were unreadable"; return false;
        }
    }
    return true;
}

struct LiveExportName {
    std::string dll;
    std::string name;
    uint16_t ordinal = 0;
    bool byOrdinal = false;
};

void collectLiveExports(Debugger& dbg, const DbgModule& module,
                        std::unordered_map<uint64_t, LiveExportName>& out) {
    if (!module.base || !module.size || module.size > 512ull * 1024ull * 1024ull) return;
    uint8_t dos[0x40]{};
    if (dbg.readMemory(module.base, dos, sizeof(dos)) != sizeof(dos) || dos[0] != 'M' || dos[1] != 'Z') return;
    uint32_t pe = 0; std::memcpy(&pe, dos + 0x3c, 4);
    if (pe > 0x100000 || pe + 24 > module.size) return;
    uint8_t nt[0x1a]{};
    if (dbg.readMemory(module.base + pe, nt, sizeof(nt)) != sizeof(nt) || nt[0] != 'P' || nt[1] != 'E') return;
    uint16_t magic = 0; std::memcpy(&magic, nt + 24, 2);
    if (magic != 0x10b && magic != 0x20b) return;
    const uint32_t ddOff = pe + 24 + (magic == 0x20b ? 112u : 96u);
    uint32_t expRva = 0, expSize = 0;
    if (dbg.readMemory(module.base + ddOff, &expRva, 4) != 4 ||
        dbg.readMemory(module.base + ddOff + 4, &expSize, 4) != 4 || !expRva ||
        expRva > module.size || expSize > module.size - expRva) return;
    uint8_t ed[40]{};
    if (dbg.readMemory(module.base + expRva, ed, sizeof(ed)) != sizeof(ed)) return;
    uint32_t ordinalBase = 0, funcs = 0, names = 0, eatRva = 0, namesRva = 0, ordsRva = 0;
    std::memcpy(&ordinalBase, ed + 16, 4); std::memcpy(&funcs, ed + 20, 4);
    std::memcpy(&names, ed + 24, 4); std::memcpy(&eatRva, ed + 28, 4);
    std::memcpy(&namesRva, ed + 32, 4); std::memcpy(&ordsRva, ed + 36, 4);
    if (!funcs || funcs > 200000 || names > 100000 ||
        eatRva > module.size || funcs * 4ull > module.size - eatRva) return;
    std::vector<uint32_t> eat(funcs);
    if (dbg.readMemory(module.base + eatRva, eat.data(), eat.size() * 4) != eat.size() * 4) return;
    std::vector<std::string> byIndex(funcs);
    if (names && namesRva <= module.size && names * 4ull <= module.size - namesRva &&
        ordsRva <= module.size && names * 2ull <= module.size - ordsRva) {
        std::vector<uint32_t> nameRvas(names);
        std::vector<uint16_t> ords(names);
        if (dbg.readMemory(module.base + namesRva, nameRvas.data(), names * 4) == names * 4 &&
            dbg.readMemory(module.base + ordsRva, ords.data(), names * 2) == names * 2) {
            for (uint32_t i = 0; i < names; ++i) if (ords[i] < funcs && nameRvas[i] < module.size) {
                char name[512]{};
                const size_t got = dbg.readMemory(module.base + nameRvas[i], name, sizeof(name) - 1);
                if (got) { name[sizeof(name) - 1] = 0; byIndex[ords[i]] = name; }
            }
        }
    }
    const std::string dll = !module.name.empty() ? module.name : pathLeafLower(module.path);
    for (uint32_t i = 0; i < funcs && out.size() < 1000000; ++i) {
        const uint32_t rva = eat[i];
        if (!rva || rva >= module.size || (rva >= expRva && rva < expRva + expSize)) continue;
        LiveExportName item;
        item.dll = dll;
        item.ordinal = static_cast<uint16_t>(std::min<uint64_t>(ordinalBase + i, UINT16_MAX));
        item.name = byIndex[i];
        item.byOrdinal = item.name.empty();
        out.emplace(module.base + rva, std::move(item));
    }
}

std::vector<PeUnpackImport> recoverLiveImports(AppContext& ctx, uint64_t moduleBase,
                                                const std::vector<uint8_t>& mapped,
                                                const DbgSnapshot& snap,
                                                bool originalSectionLayout) {
    std::unordered_map<uint64_t, LiveExportName> exports;
    for (const auto& module : snap.modules) collectLiveExports(ctx.debug, module, exports);
    std::unordered_set<uint64_t> knownSlots;
    if (originalSectionLayout) {
        for (const auto& im : ctx.staticBinary().imports())
            if (im.addressKnown && im.iatVA >= ctx.staticBinary().imageBase())
                knownSlots.insert(moduleBase +
                                  (im.iatVA - ctx.staticBinary().imageBase()));
    }

    const size_t ptr = snap.is32 ? 4 : 8;
    std::vector<PeUnpackImport> result;
    uint64_t scannedBytes = 0;
    constexpr uint64_t kMaxImportScanBytes = 32ull * 1024ull * 1024ull;
    auto scanSpan = [&](uint64_t begin, uint64_t end) {
        begin = (begin + ptr - 1) & ~(static_cast<uint64_t>(ptr) - 1);
        std::vector<PeUnpackImport> run;
        auto flush = [&] {
            if (run.size() >= 2 || (run.size() == 1 && knownSlots.count(run[0].slotVA)))
                result.insert(result.end(), run.begin(), run.end());
            run.clear();
        };
        for (uint64_t rva = begin; rva + ptr <= end &&
             result.size() + run.size() < 16384 && scannedBytes < kMaxImportScanBytes;
             rva += ptr, scannedBytes += ptr) {
            uint64_t value = 0;
            if (ptr == 8) std::memcpy(&value, mapped.data() + rva, 8);
            else { uint32_t v = 0; std::memcpy(&v, mapped.data() + rva, 4); value = v; }
            auto it = exports.find(value);
            if (it == exports.end()) { flush(); continue; }
            PeUnpackImport im;
            im.slotVA = moduleBase + rva;
            im.dll = it->second.dll;
            im.name = it->second.name;
            im.ordinal = it->second.ordinal;
            im.byOrdinal = it->second.byOrdinal;
            im.resolvedVA = value;
            if (!run.empty() && pathLeafLower(run.back().dll) != pathLeafLower(im.dll)) flush();
            run.push_back(std::move(im));
        }
        flush();
    };
    if (originalSectionLayout) {
        for (const auto& s : ctx.staticBinary().sections()) {
            if (s.virtualAddress >= mapped.size()) continue;
            const uint64_t span = std::max(s.virtualSize, s.rawSize);
            const uint64_t end = span > UINT64_MAX - s.virtualAddress ? mapped.size() :
                std::min<uint64_t>(mapped.size(), s.virtualAddress + span);
            scanSpan(s.virtualAddress, end);
        }
    } else {
        scanSpan(0, mapped.size());
    }
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a.slotVA < b.slotVA; });
    result.erase(std::unique(result.begin(), result.end(), [](const auto& a, const auto& b) {
        return a.slotVA == b.slotVA;
    }), result.end());
    return result;
}

// Small persisted-prefs file alongside the project sidecars in %APPDATA%.
std::string prefsPath() {
    char appdata[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) return "";
    std::string dir = std::string(appdata) + "\\DisasmStudio";
    CreateDirectoryA(dir.c_str(), nullptr);   // ensure it exists (no-op if already there)
    return dir + "\\prefs.ini";
}

std::string defaultSymbolCachePath() {
    char base[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("LOCALAPPDATA", base, sizeof(base)) &&
        !GetEnvironmentVariableA("APPDATA", base, sizeof(base)))
        return {};
    return std::string(base) + "\\DisasmStudio\\symbols";
}

bool queryEqualsInsensitive(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        unsigned char a = static_cast<unsigned char>(left[i]);
        unsigned char b = static_cast<unsigned char>(right[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}
} // namespace

bool AppContext::captureStaticAuthorizationWatchSourceEvidence(
    AuthorizationWatchPlan& plan) const {
    plan.launchSource = {};

    AttachedFileIdentity identity;
    if (!loadedBytesStillMatchDisk(staticBinary(), &identity)) return false;

    try {
        // BinaryFile is immutable after load, while project patches live in a
        // separate overlay. Keep an independent const copy alive until the
        // CREATE_PROCESS file handle has been checked byte-for-byte.
        plan.launchSource.bytes =
            std::make_shared<std::vector<uint8_t>>(staticBinary().bytes());
    } catch (...) {
        plan.launchSource = {};
        return false;
    }
    plan.launchSource.fileIdentity = identity;
    if (!CompleteAuthorizationWatchSourceEvidence(plan.launchSource)) {
        plan.launchSource = {};
        return false;
    }
    return true;
}

void App::loadPrefs() {
    PreferencesData defaults;
    defaults.theme = static_cast<int>(theme_);
    defaults.density = static_cast<int>(density_);
    defaults.uiZoomPercent = theme::UiZoomPercent();
    defaults.symbolNetwork = false;
    defaults.symbolCache = defaultSymbolCachePath();
    defaults.symbolServer = "https://msdl.microsoft.com/download/symbols";
    defaults.symbolSource = defaults.symbolTypes = defaults.symbolLocals = true;

    // Defaults are authoritative when no valid copy exists. In particular,
    // malformed prefs can never silently enable network symbol fetching.
    ctx_.symbolOptions.networkEnabled = defaults.symbolNetwork;
    ctx_.symbolOptions.cacheDirectory = defaults.symbolCache;
    ctx_.symbolOptions.serverUrl = defaults.symbolServer;
    ctx_.symbolOptions.collectSourceLines = defaults.symbolSource;
    ctx_.symbolOptions.collectTypes = defaults.symbolTypes;
    ctx_.symbolOptions.collectLocals = defaults.symbolLocals;
    investigationRecentQueries_.clear();

    const std::string path = prefsPath();
    if (path.empty()) return;
    const PreferencesBounds bounds{
        static_cast<int>(theme::ThemeId::Count),
        static_cast<int>(theme::Density::Compact),
        static_cast<int>(theme::Density::Spacious),
    };
    PreferencesData loaded;
    if (LoadPreferencesFile(path, defaults, bounds, loaded) ==
        atomic_file::ReadSource::None)
        return;

    theme_ = static_cast<theme::ThemeId>(loaded.theme);
    density_ = static_cast<theme::Density>(loaded.density);
    theme::SetUiZoomPercent(loaded.uiZoomPercent);
    ctx_.navigatorOptionalMask = static_cast<uint32_t>(loaded.navigatorOptionalMask);
    ctx_.analysisQueueCollapsed = loaded.analysisQueueCollapsed;
    ctx_.symbolOptions.networkEnabled = loaded.symbolNetwork;
    ctx_.symbolOptions.cacheDirectory = std::move(loaded.symbolCache);
    ctx_.symbolOptions.serverUrl = std::move(loaded.symbolServer);
    ctx_.symbolOptions.collectSourceLines = loaded.symbolSource;
    ctx_.symbolOptions.collectTypes = loaded.symbolTypes;
    ctx_.symbolOptions.collectLocals = loaded.symbolLocals;
    investigationRecentQueries_.reserve(loaded.investigationRecent.size());
    for (PreferenceRecentQuery& recent : loaded.investigationRecent) {
        investigationRecentQueries_.push_back({
            recent.identity == PreferenceIdentity::Live
                ? InvestigationIdentity::Live : InvestigationIdentity::File,
            std::move(recent.query),
        });
    }
}

bool App::savePrefs() {
    PreferencesData data;
    data.theme = static_cast<int>(theme_);
    data.density = static_cast<int>(density_);
    data.uiZoomPercent = theme::UiZoomPercent();
    data.navigatorOptionalMask = static_cast<int>(ctx_.navigatorOptionalMask);
    data.analysisQueueCollapsed = ctx_.analysisQueueCollapsed;
    data.symbolNetwork = ctx_.symbolOptions.networkEnabled;
    data.symbolCache = ctx_.symbolOptions.cacheDirectory;
    data.symbolServer = ctx_.symbolOptions.serverUrl;
    data.symbolSource = ctx_.symbolOptions.collectSourceLines;
    data.symbolTypes = ctx_.symbolOptions.collectTypes;
    data.symbolLocals = ctx_.symbolOptions.collectLocals;
    data.investigationRecent.reserve(
        std::min(investigationRecentQueries_.size(), kMaxPreferenceRecentQueries));
    for (size_t i = 0; i < investigationRecentQueries_.size() &&
                       i < kMaxPreferenceRecentQueries; ++i) {
        const InvestigationRecentQuery& recent = investigationRecentQueries_[i];
        data.investigationRecent.push_back({
            recent.identity == InvestigationIdentity::Live
                ? PreferenceIdentity::Live : PreferenceIdentity::File,
            recent.query,
        });
    }

    const PreferencesBounds bounds{
        static_cast<int>(theme::ThemeId::Count),
        static_cast<int>(theme::Density::Compact),
        static_cast<int>(theme::Density::Spacious),
    };
    const std::string path = prefsPath();
    const bool ok = !path.empty() && SavePreferencesFile(path, data, bounds);
    if (ok) {
        prefsSaveFailed_ = false;
        prefsSaveError_.clear();
        return true;
    }

    const bool firstFailure = !prefsSaveFailed_;
    prefsSaveFailed_ = true;
    prefsSaveError_ = "Preferences save failed; the previous prefs.ini/.bak remain available.";
    if (firstFailure) ui::Toast(ui::ToastKind::Error, prefsSaveError_);
    return false;
}

void App::setUiZoomPercent(int percent) {
    const int previous = theme::UiZoomPercent();
    theme::SetUiZoomPercent(percent);
    if (theme::UiZoomPercent() != previous) savePrefs();
}

void App::renderSymbolSettingsPopup() {
    if (ctx_.requestedSymbolSettings) {
        ctx_.requestedSymbolSettings = false;
        symbolSettingsOpen_ = true;
        symbolNetworkDraft_ = ctx_.symbolOptions.networkEnabled;
        symbolSourceDraft_ = ctx_.symbolOptions.collectSourceLines;
        symbolTypesDraft_ = ctx_.symbolOptions.collectTypes;
        symbolLocalsDraft_ = ctx_.symbolOptions.collectLocals;
        std::snprintf(symbolCacheDraft_, sizeof(symbolCacheDraft_), "%s",
                      ctx_.symbolOptions.cacheDirectory.c_str());
        std::snprintf(symbolServerDraft_, sizeof(symbolServerDraft_), "%s",
                      ctx_.symbolOptions.serverUrl.c_str());
        symbolSettingsError_.clear();
        ImGui::OpenPopup("Symbol Settings");
    }
    if (!symbolSettingsOpen_) return;

    prepareWorkbenchDialog(650.0f, 0.0f);
    if (!ImGui::BeginPopupModal("Symbol Settings", nullptr,
                                ImGuiWindowFlags_AlwaysAutoResize)) {
        symbolSettingsOpen_ = false;
        return;
    }

    ImGui::TextWrapped("PDB discovery runs on a dedicated worker. Local PDBs and the configured cache are searched without network access unless you explicitly enable the symbol server below.");
    ImGui::Separator();
    ImGui::Checkbox("Enable network symbol fetching", &symbolNetworkDraft_);
    if (symbolNetworkDraft_)
        ImGui::TextColored(theme::col::warn(),
                           "The worker may contact the configured server and write downloaded PDBs to the cache.");

    ImGui::TextUnformatted("Cache directory");
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("###Cache directory", "absolute local cache path",
                             symbolCacheDraft_, sizeof(symbolCacheDraft_));
    ImGui::TextUnformatted("Symbol server");
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("###Symbol server", "https://... or a trusted symbol store",
                             symbolServerDraft_, sizeof(symbolServerDraft_));
    ImGui::Checkbox("Source lines", &symbolSourceDraft_);
    ui::SameLineIfFits(ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x +
                       ImGui::CalcTextSize("PDB prototypes/types").x);
    ImGui::Checkbox("PDB prototypes/types", &symbolTypesDraft_);
    ui::SameLineIfFits(ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x +
                       ImGui::CalcTextSize("Parameters/locals").x);
    ImGui::Checkbox("Parameters/locals", &symbolLocalsDraft_);

    if (!symbolSettingsError_.empty())
        ImGui::TextColored(theme::col::bad(), "%s", symbolSettingsError_.c_str());

    auto invalidSearchPart = [](const char* value) {
        return !value || std::strchr(value, '\n') || std::strchr(value, '\r') ||
               std::strchr(value, ';') || std::strchr(value, '*');
    };
    auto remoteCachePath = [](const char* value) {
        return value && ((value[0] == '\\' && value[1] == '\\') ||
                         (value[0] == '/' && value[1] == '/') ||
                         std::strstr(value, "://"));
    };
    if (ImGui::Button("Apply", ImVec2(110.0f * theme::UiScale(), 0))) {
        symbolSettingsError_.clear();
        if (invalidSearchPart(symbolCacheDraft_) || invalidSearchPart(symbolServerDraft_)) {
            symbolSettingsError_ = "Cache and server values cannot contain newlines, semicolons, or '*'.";
        } else if (remoteCachePath(symbolCacheDraft_)) {
            symbolSettingsError_ = "The symbol cache must be a local path, not a UNC path or URL.";
        } else if (symbolNetworkDraft_ && (!symbolCacheDraft_[0] || !symbolServerDraft_[0])) {
            symbolSettingsError_ = "Network fetching requires both an explicit cache and a symbol server.";
        } else if (symbolNetworkDraft_ && !pathFromUtf8(symbolCacheDraft_).is_absolute()) {
            symbolSettingsError_ = "The symbol cache must be an absolute local path.";
        } else {
            ctx_.symbolOptions.networkEnabled = symbolNetworkDraft_;
            ctx_.symbolOptions.cacheDirectory = symbolCacheDraft_;
            ctx_.symbolOptions.serverUrl = symbolServerDraft_;
            ctx_.symbolOptions.collectSourceLines = symbolSourceDraft_;
            ctx_.symbolOptions.collectTypes = symbolTypesDraft_;
            ctx_.symbolOptions.collectLocals = symbolLocalsDraft_;
            ++ctx_.symbolOptionsRevision;
            if (!ctx_.symbolOptionsRevision) ++ctx_.symbolOptionsRevision;
            if (savePrefs()) {
                symbolSettingsOpen_ = false;
                ImGui::CloseCurrentPopup();
            } else {
                symbolSettingsError_ = prefsSaveError_;
            }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Defaults", ImVec2(110.0f * theme::UiScale(), 0))) {
        symbolNetworkDraft_ = false;
        symbolSourceDraft_ = symbolTypesDraft_ = symbolLocalsDraft_ = true;
        std::snprintf(symbolCacheDraft_, sizeof(symbolCacheDraft_), "%s",
                      defaultSymbolCachePath().c_str());
        std::snprintf(symbolServerDraft_, sizeof(symbolServerDraft_), "%s",
                      "https://msdl.microsoft.com/download/symbols");
        symbolSettingsError_.clear();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110.0f * theme::UiScale(), 0))) {
        symbolSettingsOpen_ = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

static bool archFromMachine(MachineArch m, Arch& out) {
    switch (m) {
        case MachineArch::X86:     out = Arch::X86; return true;
        case MachineArch::X64:     out = Arch::X64; return true;
        case MachineArch::ARM:     out = Arch::ARM; return true;
        case MachineArch::THUMB:   out = Arch::THUMB; return true;
        case MachineArch::ARM64:   out = Arch::ARM64; return true;
        case MachineArch::MIPS:    out = Arch::MIPS; return true;
        case MachineArch::MIPS64:  out = Arch::MIPS64; return true;
        case MachineArch::PPC:     out = Arch::PPC; return true;
        case MachineArch::PPC64:   out = Arch::PPC64; return true;
        case MachineArch::RISCV:   out = Arch::RISCV32; return true;
        case MachineArch::RISCV64: out = Arch::RISCV64; return true;
        case MachineArch::JVM:     out = Arch::JVM; return true;
        case MachineArch::GML:     out = Arch::GML; return true;
        case MachineArch::Unknown: return false;
    }
    return false;
}

bool AppContext::debuggerRuntimeImage(const DbgSnapshot& snap, uint64_t& baseOut,
                                      uint64_t& sizeOut) const {
    baseOut = sizeOut = 0;
    const BinaryFile& binary = staticBinary();
    const Arch arch = staticArch();
    const bool liveDebuggee = snap.state == DbgState::Running ||
                              snap.state == DbgState::Paused;
    if (!liveDebuggee || !binary.loaded() || !debuggerActionsMatchImage()) return false;
    const bool wants32 = arch == Arch::X86;
    if ((!wants32 && arch != Arch::X64) || snap.is32 != wants32) return false;

    const DocumentRuntimeMetadata::LiveImageIdentity& live =
        staticRuntimeMetadata().liveImage;
    if (!live.valid || live.pid != snap.pid ||
        live.sessionGeneration != snap.sessionGeneration ||
        !live.moduleBase)
        return false;
    if (!binary.isMappedImage()) {
        // A session stamp is granted only by the fresh-attach backing-file
        // validation. Any enabled analyst patch makes the file/process byte
        // relationship uncertain again and disables FILE->LIVE writes; disabled
        // experiment records leave the verified pristine image untouched.
        if (hasEnabledProjectPatches(staticProject()) || live.modulePath.empty() ||
            !AttachedImagePathsMatch(binary.path(), live.modulePath))
            return false;
    }
    const AttachedModuleIdentity expected{
        live.moduleBase, live.moduleSize,
        live.moduleName, live.modulePath,
        live.moduleLoadGeneration
    };
    const DbgModule* module = matchingAttachedModule(snap, expected);
    if (!module || !module->size) return false;
    baseOut = module->base;
    sizeOut = module->size;
    return true;
}

bool AppContext::debuggerStaticRuntimeVA(const DbgSnapshot& snap, uint64_t fileVA,
                                         uint64_t& runtimeVA) const {
    runtimeVA = 0;
    const BinaryFile& binary = staticBinary();
    uint64_t runtimeBase = 0, runtimeSize = 0;
    if (!debuggerRuntimeImage(snap, runtimeBase, runtimeSize) ||
        fileVA < binary.imageBase())
        return false;
    // A static address can be mapped without having file bytes (for example,
    // zero-filled PE section padding).  Runtime translation is an image/RVA
    // relationship, so do not incorrectly require ptrFromVA/file backing.
    const AddressInspection inspected = InspectAddress(binary, fileVA);
    if (!inspected.staticMapped || !inspected.rva.valid) return false;
    const uint64_t rva = inspected.rva.value;
    return rva < runtimeSize && CheckedAddressAdd(runtimeBase, rva, runtimeVA);
}

ProjectState AppContext::projectForBinary(const BinaryFile& binary, Engine& engine,
                                          Arch& arch, bool applySavedArchEngine,
                                          bool loadSavedState,
                                          std::string* loadWarning) const {
    ProjectState project;
    if (!binary.loaded()) return project;
    const uint64_t h = binary.contentHash();
    ProjectState loaded;
    ProjectLoadResult loadResult;
    if (loadSavedState) loadResult = LoadProjectDetailed(h, loaded);
    if (loadWarning && loadSavedState) {
        if (loadResult.recoveredFromBackup() ||
            (!loadResult.loaded &&
             (ProjectLoadAttemptRequiresWarning(loadResult.primary) ||
              ProjectLoadAttemptRequiresWarning(loadResult.backup)))) {
            *loadWarning = loadResult.error.empty()
                ? (loadResult.recoveredFromBackup()
                    ? "Recovered project analysis from the backup sidecar."
                    : "The saved project sidecar is invalid and was not applied.")
                : loadResult.error;
        }
    }
    if (loadResult.loaded) {
        project = std::move(loaded);   // restore saved analysis
        // Reapply the saved engine/arch so the binary reopens exactly as last
        // analyzed - especially valuable for raw blobs and mis-detected images
        // where the header gives the wrong arch. Skipped on the raw-load path,
        // where the dialog's explicit choice must win.
        if (applySavedArchEngine) {
            Arch   savedArch;   if (ArchFromName(project.arch.c_str(), savedArch))   arch   = savedArch;
            Engine savedEngine; if (EngineFromName(project.engine.c_str(), savedEngine)) engine = savedEngine;
        }
    }
    project.hash       = h;
    project.binaryPath = binary.path();
    project.arch       = ArchName(arch);
    project.engine     = EngineNameOf(engine);
    size_t s = binary.path().find_last_of("/\\");
    project.name       = (s == std::string::npos) ? binary.path() : binary.path().substr(s + 1);
    project.lastOpenedUnix = (int64_t)std::time(nullptr);
    return project;
}

void AppContext::prepareProjectSaveSnapshot() {
    ProjectState& project = staticProject();
    const BinaryFile& binary = staticBinary();
    const Engine engine = staticEngine();
    const Arch arch = staticArch();
    project.arch   = ArchName(arch);
    project.engine = EngineNameOf(engine);
    project.rawMappingSaved = binary.format() == BinFormat::Raw;
    project.rawLandmarks.clear();
    if (project.rawMappingSaved) {
        const DecoderConfig decoder = staticDecoderConfig();
        project.rawImageBase = binary.imageBase();
        project.rawEntryExplicit = binary.rawEntryExplicit();
        project.rawEntry = project.rawEntryExplicit ? binary.entryPointVA() : 0;
        project.rawBigEndian = decoder.byteOrder == ByteOrder::Big;
        storeRawDecoderFeatures(project, decoder.features);
        project.rawLandmarks.reserve(binary.analysisLandmarks().size());
        for (const AnalysisLandmark& landmark : binary.analysisLandmarks())
            project.rawLandmarks.push_back({landmark.address, landmark.name, landmark.evidence});
    } else {
        project.rawImageBase = project.rawEntry = 0;
        project.rawEntryExplicit = false;
        project.rawBigEndian = false;
        storeRawDecoderFeatures(project, DecoderFeatures{});
    }
}

bool AppContext::finishProjectSave(bool wait) {
    if (!projectSaveFuture.valid()) return projectSaveState != ProjectSaveState::Failed;
    if (!wait && projectSaveFuture.wait_for(std::chrono::seconds(0)) !=
                 std::future_status::ready)
        return true;

    const DocumentSaveTicket ticket = projectSaveInFlightTicket;
    const uint64_t appRevision = projectSaveInFlightRevision;
    const uint64_t sequence = projectSaveInFlightSequence;
    ProjectSaveResult result;
    try {
        if (wait) projectSaveFuture.wait();
        result = projectSaveFuture.get();
    } catch (...) {
        result.saved = false;
        result.error = "Project save worker failed unexpectedly.";
    }
    projectSaveInFlightTicket = {};
    projectSaveInFlightRevision = 0;
    projectSaveInFlightSequence = 0;
    if (sequence) projectSaveCompletedSequence =
        (std::max)(projectSaveCompletedSequence, sequence);

    DocumentContext* origin = ticket ? documents_.find(ticket.document) : nullptr;
    if (!result.saved) {
        projectSaveState = ProjectSaveState::Failed;
        projectSaveError = result.error.empty()
                         ? "Project save failed; your in-memory changes are still dirty."
                         : result.error;
        projectSaveWarning.clear();
        if (origin) (void)origin->rejectExternalSave(ticket, projectSaveError);
        projectDirtySince = std::chrono::steady_clock::now();
        return false;
    }

    ++documentRetryRevision_;
    if (!documentRetryRevision_) ++documentRetryRevision_;

    // A transition is required to join this writer before replacing/closing its
    // image. Validate anyway so an accidental future caller cannot acknowledge
    // a different image which happens to reuse the same DocumentId/revision.
    const bool acknowledged = origin && origin->acknowledgeExternalSave(ticket);
    if (acknowledged && documents_.activeId() == ticket.document) {
        projectSavedRevision = (std::max)(projectSavedRevision, appRevision);
        projectSaveError.clear();
        projectSaveWarning = std::move(result.warning);
        projectSaveState = origin->dirty() ? ProjectSaveState::Dirty
                                           : ProjectSaveState::Clean;
    } else if (documents_.active()) {
        DocumentContext* active = documents_.active();
        projectSaveState = active->dirty() ? ProjectSaveState::Dirty
                                           : ProjectSaveState::Clean;
        if (active->saveState() != DocumentSaveState::Failed)
            projectSaveError.clear();
        projectSaveWarning = std::move(result.warning);
    }
    return true;
}

void AppContext::pollProjectSave() {
    finishProjectSave(false);
}

bool AppContext::beginProjectSave() {
    DocumentContext& document = activeStaticDocument();
    if (projectSaveFuture.valid()) {
        // The same document's worker is already the latest permitted writer.
        // A different document may never start while it is outstanding: join
        // and publish A's completion before taking B's snapshot.
        if (projectSaveInFlightTicket.document == document.id() &&
            projectSaveInFlightTicket.imageGeneration ==
                document.imageGeneration())
            return true;
        if (!finishProjectSave(true)) return false;
    }

    // Live (memory-mapped) modules are not sidecar-persisted: their content hash is a
    // memory image, not the on-disk file, so a sidecar would never re-match and would
    // litter %APPDATA% with junk keyed to a one-off mapping.
    const BinaryFile& binary = staticBinary();
    const ProjectState& project = staticProject();
    if (!binary.loaded() || !project.hash ||
        document.persistence() == DocumentInstallPersistence::Ephemeral ||
        binary.isMappedImage()) {
        projectSavedRevision = projectRevision;
        (void)document.acknowledgeExternalSave(document.externalSaveTicket());
        projectSaveState = ProjectSaveState::Clean;
        projectSaveError.clear();
        projectSaveWarning.clear();
        return true;
    }
    if (!document.dirty()) {
        projectSavedRevision = projectRevision;
        projectSaveState = ProjectSaveState::Clean;
        projectSaveError.clear();
        projectSaveWarning.clear();
        return true;
    }

    prepareProjectSaveSnapshot();
    ProjectState snapshot = project;
    projectSaveInFlightRevision = projectRevision;
    projectSaveInFlightTicket = document.externalSaveTicket();
    projectSaveInFlightSequence = projectSaveNextSequence++;
    if (!projectSaveNextSequence) ++projectSaveNextSequence;
    projectSaveState = ProjectSaveState::Saving;
    projectSaveError.clear();
    projectSaveWarning.clear();
    try {
        projectSaveFuture = std::async(std::launch::async,
            [snapshot = std::move(snapshot)]() { return SaveProjectDetailed(snapshot); });
    } catch (...) {
        projectSaveState = ProjectSaveState::Failed;
        projectSaveError = "Project save worker could not be started; changes remain in memory.";
        (void)document.rejectExternalSave(projectSaveInFlightTicket,
                                          projectSaveError);
        projectSaveInFlightTicket = {};
        projectSaveInFlightRevision = 0;
        projectSaveInFlightSequence = 0;
        projectDirtySince = std::chrono::steady_clock::now();
        return false;
    }
    return true;
}

bool AppContext::saveProject() {
    if (projectSaveFuture.valid() && !finishProjectSave(true)) return false;
    if (!beginProjectSave()) return false;
    return finishProjectSave(true);
}

bool AppContext::prepareStaticDocumentTransition(std::string* error) {
    if (error) error->clear();
    // This is the serialization point between the render-thread controller and
    // both the async writer and DocumentContext's synchronous transition store.
    // It ensures an older snapshot can never finish after a replacement save.
    if (saveProject()) return true;
    if (error) *error = projectSaveError.empty()
                      ? "Project save failed; the current target was preserved."
                      : projectSaveError;
    return false;
}

void AppContext::resetProjectSaveMirrorFromActive() {
    const DocumentContext& document = activeStaticDocument();
    projectRevision = document.revision();
    projectSavedRevision = document.savedRevision();
    projectSaveError = document.saveError();
    projectSaveWarning.clear();
    switch (document.saveState()) {
    case DocumentSaveState::Dirty:  projectSaveState = ProjectSaveState::Dirty; break;
    case DocumentSaveState::Saving: projectSaveState = ProjectSaveState::Saving; break;
    case DocumentSaveState::Failed: projectSaveState = ProjectSaveState::Failed; break;
    default:                        projectSaveState = ProjectSaveState::Clean; break;
    }
    if (document.dirty()) projectDirtySince = std::chrono::steady_clock::now();
}

bool AppContext::clearStaticImage(std::string* error) {
    if (!prepareStaticDocumentTransition(error)) return false;
    if (!activeStaticDocument().clearImage(error)) return false;
    resetProjectSaveMirrorFromActive();
    return true;
}

AppContext::BinaryLoadCandidate AppContext::buildBinaryLoadCandidate(
    const std::string& path,
    const std::shared_ptr<std::atomic_bool>& cancelled) {
    BinaryLoadCandidate result;
    result.path = path;
    const auto cancellationRequested = [&] {
        return cancelled && cancelled->load(std::memory_order_acquire);
    };
    BinaryFile candidate;
    BinaryLoadOptions loadOptions;
    loadOptions.cancelled = cancellationRequested;
    if (!candidate.load(path, loadOptions)) {
        result.cancelled = candidate.loadError() == BinaryLoadError::Cancelled;
        result.error = candidate.loadErrorText().empty()
                     ? "The binary could not be loaded."
                     : candidate.loadErrorText();
        switch (candidate.loadError()) {
        case BinaryLoadError::UnsupportedMachine:
        case BinaryLoadError::MalformedPE:
        case BinaryLoadError::MalformedELF:
        case BinaryLoadError::MalformedMachO:
        case BinaryLoadError::MalformedJavaClass:
        case BinaryLoadError::MalformedGameMakerArchive:
            result.offerRaw = true;
            result.error +=
                " The format was recognized, so no fallback instruction set was granted. "
                "Use File > Open as Raw only if you intentionally want to choose the mapping and architecture.";
            break;
        default:
            break;
        }
        return result;
    }
    if (cancellationRequested()) {
        result.cancelled = true;
        result.error = "Binary load cancelled.";
        return result;
    }
    bool ignoredInvalidRawProject = false;
    std::string projectLoadWarning;
    std::optional<RawLoadSelection> restoredRawSelection;

    // A raw file has no self-describing base, entry, or code roots. If its
    // content-hash sidecar carries an exact raw mapping, rebuild that mapping
    // before exposing the target; loading once at the fallback base and only
    // restoring annotations would silently shift every saved VA.
    if (candidate.format() == BinFormat::Raw) {
        ProjectState saved;
        const ProjectLoadResult rawLoad = LoadProjectDetailed(candidate.contentHash(), saved);
        if (rawLoad.recoveredFromBackup() && !rawLoad.error.empty())
            projectLoadWarning = rawLoad.error;
        if (rawLoad.loaded && saved.rawMappingSaved) {
            Arch savedArch;
            bool valid = ArchFromName(saved.arch.c_str(), savedArch) &&
                         ArchMappingRangeFits(savedArch, saved.rawImageBase,
                                              candidate.bytes().size());
            RawLoadSelection selection;
            if (valid) {
                selection.arch = savedArch;
                selection.entryVA = saved.rawEntry;
                selection.entryExplicit = saved.rawEntryExplicit;
                selection.byteOrder = saved.rawBigEndian ? ByteOrder::Big : ByteOrder::Little;
                DecoderFeatures features;
                if (DecoderFeaturesFromBits(saved.rawDecoderFeatureBits, features))
                    selection.riscvCompressed = features.riscvCompressed;
                selection.landmarks.reserve(saved.rawLandmarks.size());
                for (const PjRawLandmark& landmark : saved.rawLandmarks)
                    selection.landmarks.push_back(
                        {landmark.address, landmark.name, landmark.evidence});
                // Restore metadata over the bytes already read and hashed. A
                // second load both wastes I/O and can observe a different file.
                valid = candidate.remapRaw(saved.rawImageBase, saved.rawEntry,
                                            saved.rawEntryExplicit, selection.landmarks);
                if (valid) {
                    restoredRawSelection = std::move(selection);
                }
            }
            ignoredInvalidRawProject = !valid;
        }
        if (cancellationRequested()) {
            result.cancelled = true;
            result.error = "Binary load cancelled.";
            return result;
        }
        if (!restoredRawSelection) {
            result.offerRaw = true;
            result.error = ignoredInvalidRawProject
                ? "The saved Raw mapping or decoder metadata was invalid. Review the mapping and architecture explicitly."
                : "The file has no supported structured format. Review the Raw mapping and architecture explicitly; no fallback instruction set was granted.";
            return result;
        }
    }
    // Cheap metadata still runs on the load worker: large archives and firmware
    // probes must not monopolize the Win32/ImGui thread.
    DocumentRuntimeMetadata metadata;
    metadata.java = ScanJava(candidate);
    if (cancellationRequested()) {
        result.cancelled = true;
        result.error = "Binary load cancelled.";
        return result;
    }
    metadata.runtime = ScanRuntimes(candidate, metadata.java);
    if (cancellationRequested()) {
        result.cancelled = true;
        result.error = "Binary load cancelled.";
        return result;
    }
    constexpr size_t kFirmwareUiProbeCap = 512ull * 1024ull * 1024ull;
    metadata.firmware = candidate.format() == BinFormat::Raw &&
                        candidate.bytes().size() <= kFirmwareUiProbeCap
                      ? SniffFirmware(candidate.bytes()) : FirmwareDetection{};
    if (cancellationRequested()) {
        result.cancelled = true;
        result.error = "Binary load cancelled.";
        return result;
    }

    // Prime the pristine identity on this worker; project staging and saves
    // must not perform the first whole-file hash on the render thread.
    (void)candidate.contentHash();
    if (cancellationRequested()) {
        result.cancelled = true;
        result.error = "Binary load cancelled.";
        return result;
    }
    result.browseArchive = metadata.runtime.isStandaloneArchive &&
                           !metadata.java.entries.empty();
    result.image = std::move(candidate);
    result.metadata = std::move(metadata);
    result.ignoredInvalidRawProject = ignoredInvalidRawProject;
    result.projectLoadWarning = std::move(projectLoadWarning);
    if (restoredRawSelection) {
        restoredRawSelection->firmware = metadata.firmware;
        result.rawSelection = std::move(restoredRawSelection);
    }
    result.success = true;
    return result;
}

AppContext::BinaryLoadCandidate AppContext::buildRawLoadCandidate(
    const std::string& path, uint64_t base, RawLoadSelection selection,
    const std::shared_ptr<std::atomic_bool>& cancelled) {
    BinaryLoadCandidate result;
    result.path = path;
    const auto cancellationRequested = [&] {
        return cancelled && cancelled->load(std::memory_order_acquire);
    };
    BinaryLoadOptions loadOptions;
    loadOptions.cancelled = cancellationRequested;
    BinaryFile image;
    if (!image.loadRaw(path, base, loadOptions)) {
        result.cancelled = image.loadError() == BinaryLoadError::Cancelled;
        result.error = image.loadErrorText().empty()
                     ? "The Raw image could not be loaded."
                     : image.loadErrorText();
        return result;
    }
    if (cancellationRequested()) {
        result.cancelled = true;
        result.error = "Raw binary load cancelled.";
        return result;
    }
    if (!ArchMappingRangeFits(selection.arch, base, image.bytes().size())) {
        result.error = "The selected architecture cannot address the complete Raw mapping.";
        return result;
    }
    if ((selection.entryExplicit && !image.setRawEntryPointVA(selection.entryVA)) ||
        !image.setAnalysisLandmarks(std::move(selection.landmarks))) {
        result.error = "The Raw entry point or an analysis landmark is outside the mapped file.";
        return result;
    }
    DocumentRuntimeMetadata metadata;
    metadata.runtime = ScanRuntimes(image, metadata.java);
    metadata.firmware = std::move(selection.firmware);
    if (!cancellationRequested()) (void)image.contentHash();
    if (cancellationRequested()) {
        result.cancelled = true;
        result.error = "Raw binary load cancelled.";
        return result;
    }
    result.image = std::move(image);
    result.metadata = std::move(metadata);
    result.rawSelection = std::move(selection);
    result.success = true;
    return result;
}

bool AppContext::stageBinaryLoadCandidate(BinaryLoadCandidate candidate) {
    if (!candidate.success) {
        documentCommandError_ = candidate.error.empty()
                              ? "The binary could not be loaded." : candidate.error;
        return false;
    }
    if (pendingDocumentCommand_) {
        documentCommandError_ =
            "Another document operation is already queued for this frame.";
        return false;
    }

    BinaryFile& image = candidate.image;
    Engine targetEngine = staticEngine();
    Arch targetArch = candidate.rawSelection ? candidate.rawSelection->arch : Arch::X64;
    if (!candidate.rawSelection && !archFromMachine(image.machine(), targetArch)) {
        documentCommandError_ =
            "The structured image has no supported machine architecture. Open it explicitly as Raw to choose a decoder.";
        return false;
    }
    ProjectState targetProject = projectForBinary(
        image, targetEngine, targetArch,
        /*applySavedArchEngine=*/!candidate.rawSelection.has_value(),
        /*loadSavedState=*/!candidate.ignoredInvalidRawProject,
        &candidate.projectLoadWarning);
    DecoderConfig targetDecoder;
    targetDecoder.engine = targetEngine;
    targetDecoder.arch = targetArch;
    if (candidate.rawSelection) {
        const RawLoadSelection& raw = *candidate.rawSelection;
        targetProject.rawBigEndian = raw.byteOrder == ByteOrder::Big;
        DecoderFeatures rawFeatures;
        if (!DecoderFeaturesFromBits(targetProject.rawDecoderFeatureBits,
                                     rawFeatures)) {
            rawFeatures = DecoderFeatures{};
            candidate.projectLoadWarning =
                "The saved Raw decoder feature mask was invalid; default ISA features were used.";
        }
        rawFeatures.riscvCompressed = raw.riscvCompressed;
        storeRawDecoderFeatures(targetProject, rawFeatures);
        targetDecoder.byteOrder = raw.byteOrder;
        targetDecoder.features = rawFeatures;
    } else if (image.format() == BinFormat::Raw) {
        targetDecoder.byteOrder = targetProject.rawBigEndian
                                ? ByteOrder::Big : ByteOrder::Little;
        DecoderFeatures savedFeatures;
        if (DecoderFeaturesFromBits(targetProject.rawDecoderFeatureBits,
                                    savedFeatures)) {
            targetDecoder.features = savedFeatures;
        } else {
            // Deserialization rejects this already; retain a defensive visible
            // fallback for any future programmatic ProjectState producer.
            targetDecoder.features = DecoderFeatures{};
            candidate.projectLoadWarning =
                "The saved Raw decoder feature mask was invalid; default ISA features were used.";
        }
    }
    const size_t slash = candidate.path.find_last_of("/\\");
    PendingDocumentCommand command;
    command.kind = PendingDocumentKind::Open;
    command.title = slash == std::string::npos
                  ? candidate.path : candidate.path.substr(slash + 1);
    if (command.title.empty()) command.title = "Untitled";
    command.image = std::move(candidate.image);
    command.project = std::move(targetProject);
    command.decoder = targetDecoder;
    command.persistence = DocumentInstallPersistence::RequiresInitialSave;
    command.metadata = std::move(candidate.metadata);
    command.browseArchive = candidate.browseArchive;
    command.ignoredInvalidRawProject = candidate.ignoredInvalidRawProject;
    command.projectLoadWarning = std::move(candidate.projectLoadWarning);
    return queueDocumentOpen(std::move(command));
}

bool AppContext::loadBinaryPath(const std::string& path) {
    return stageBinaryLoadCandidate(buildBinaryLoadCandidate(path));
}

bool AppContext::beginBinaryLoadPath(const std::string& path) {
    documentCommandError_.clear();
    if (path.empty()) {
        documentCommandError_ = "No binary path was supplied.";
        return false;
    }
    if (pendingDocumentCommand_ || binaryLoadFuture_.valid()) {
        documentCommandError_ = "Another document load or operation is already pending.";
        return false;
    }
    try {
        binaryLoadCancelled_ = std::make_shared<std::atomic_bool>(false);
        binaryLoadPath_ = path;
        const auto cancelled = binaryLoadCancelled_;
        binaryLoadFuture_ = std::async(std::launch::async,
            [path, cancelled] { return buildBinaryLoadCandidate(path, cancelled); });
        return true;
    } catch (const std::exception& exception) {
        documentCommandError_ = std::string("Could not start the binary-load worker: ") +
                                exception.what();
    } catch (...) {
        documentCommandError_ = "Could not start the binary-load worker.";
    }
    binaryLoadCancelled_.reset();
    binaryLoadPath_.clear();
    return false;
}

bool AppContext::beginRawLoadPath(const std::string& path, uint64_t base, Arch arch,
                                  uint64_t entryVA,
                                  std::vector<AnalysisLandmark> landmarks,
                                  FirmwareDetection firmware,
                                  bool entryExplicit,
                                  ByteOrder byteOrder,
                                  bool riscvCompressed) {
    documentCommandError_.clear();
    if (path.empty()) {
        documentCommandError_ = "No Raw binary path was supplied.";
        return false;
    }
    if (pendingDocumentCommand_ || binaryLoadFuture_.valid()) {
        documentCommandError_ = "Another document load or operation is already pending.";
        return false;
    }
    RawLoadSelection selection;
    selection.arch = arch;
    selection.entryVA = entryVA;
    selection.entryExplicit = entryExplicit;
    selection.byteOrder = byteOrder;
    selection.riscvCompressed = riscvCompressed;
    selection.landmarks = std::move(landmarks);
    selection.firmware = std::move(firmware);
    try {
        binaryLoadCancelled_ = std::make_shared<std::atomic_bool>(false);
        binaryLoadPath_ = path;
        const auto cancelled = binaryLoadCancelled_;
        binaryLoadFuture_ = std::async(std::launch::async,
            [path, base, selection = std::move(selection), cancelled]() mutable {
                return buildRawLoadCandidate(path, base, std::move(selection), cancelled);
            });
        return true;
    } catch (const std::exception& exception) {
        documentCommandError_ = std::string("Could not start the Raw-load worker: ") +
                                exception.what();
    } catch (...) {
        documentCommandError_ = "Could not start the Raw-load worker.";
    }
    binaryLoadCancelled_.reset();
    binaryLoadPath_.clear();
    return false;
}

void AppContext::cancelBinaryLoad() {
    if (binaryLoadCancelled_)
        binaryLoadCancelled_->store(true, std::memory_order_release);
}

AppContext::BinaryLoadPoll AppContext::pollBinaryLoad() {
    BinaryLoadPoll poll;
    if (!binaryLoadFuture_.valid() ||
        binaryLoadFuture_.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        return poll;

    poll.completed = true;
    poll.path = std::move(binaryLoadPath_);
    try {
        BinaryLoadCandidate candidate = binaryLoadFuture_.get();
        poll.path = candidate.path;
        poll.cancelled = candidate.cancelled;
        poll.offerRaw = candidate.offerRaw;
        poll.success = stageBinaryLoadCandidate(std::move(candidate));
        if (!poll.success)
            poll.error = poll.cancelled ? "Binary load cancelled." : documentCommandError_;
    } catch (const std::exception& exception) {
        poll.error = std::string("Binary-load worker failed: ") + exception.what();
        documentCommandError_ = poll.error;
    } catch (...) {
        poll.error = "Binary-load worker failed with an unknown exception.";
        documentCommandError_ = poll.error;
    }
    binaryLoadCancelled_.reset();
    return poll;
}

bool AppContext::loadRawPath(const std::string& path, uint64_t base, Arch a,
                             uint64_t entryVA,
                             std::vector<AnalysisLandmark> landmarks,
                             FirmwareDetection firmware,
                             bool entryExplicit,
                             ByteOrder byteOrder,
                             bool riscvCompressed) {
    RawLoadSelection selection;
    selection.arch = a;
    selection.entryVA = entryVA;
    selection.entryExplicit = entryExplicit;
    selection.byteOrder = byteOrder;
    selection.riscvCompressed = riscvCompressed;
    selection.landmarks = std::move(landmarks);
    selection.firmware = std::move(firmware);
    return stageBinaryLoadCandidate(
        buildRawLoadCandidate(path, base, std::move(selection)));
}

bool AppContext::loadLiveModule(uint64_t base, uint64_t size,
                                const std::string& name,
                                const std::string& path,
                                LiveDocumentOpenOrigin origin) {
    if (pendingDocumentCommand_) {
        documentCommandError_ =
            "Another document operation is already queued for this frame.";
        return false;
    }
    const DbgSnapshot session = debug.snapshot();
    if (!liveDocumentSessionState(session) || !base) return false;

    const DbgModule* observed = nullptr;
    for (const DbgModule& module : session.modules) {
        if (module.base == base) {
            observed = &module;
            break;
        }
    }
    if (!observed) return false;
    if (size && observed->size && size != observed->size) return false;
    if (!path.empty() && !observed->path.empty() &&
        !AttachedImagePathsMatch(path, observed->path) && path != observed->path)
        return false;
    if (path.empty() && !name.empty() && !observed->name.empty() &&
        !AttachedModuleNamesMatch(name, observed->name))
        return false;

    const AttachedModuleIdentity exactModule = attachedModuleIdentity(*observed);
    const uint64_t reportedSize = exactModule.size;
    uint64_t captureSize = reportedSize ? reportedSize : size;
    if (!captureSize) captureSize = 0x10000;
    if (captureSize > 256ull * 1024 * 1024)
        captureSize = 256ull * 1024 * 1024;   // cap pathological sizes
    // Read the module's mapped image straight from the debuggee (masked so our own
    // 0xCC breakpoints don't corrupt the decode). This is one module (a few MB), so the
    // brief read on the UI thread is acceptable; "analyze all modules" uses the worker.
    std::vector<uint8_t> img(static_cast<size_t>(captureSize));
    size_t got = debug.readMemoryMasked(base, img.data(), img.size());
    if (!got) return false;
    img.resize(got);

    BinaryFile candidate;
    const std::string imageIdentity = exactModule.path.empty()
        ? exactModule.name : exactModule.path;
    if (!candidate.loadFromMemory(std::move(img), base, imageIdentity)) return false;
    Arch targetArch = Arch::X64;
    if (!archFromMachine(candidate.machine(), targetArch)) {
        ui::Toast(ui::ToastKind::Error,
                  "The live module's structured machine architecture is unsupported; no decoder was selected.");
        return false;
    }
    const Engine targetEngine = staticEngine();
    const DbgSnapshot confirmed = debug.snapshot();
    if (!liveDocumentSessionState(confirmed) ||
        confirmed.pid != session.pid ||
        confirmed.sessionGeneration != session.sessionGeneration ||
        !matchingAttachedModule(confirmed, exactModule))
        return false;

    const std::string& displayIdentity = exactModule.name.empty()
        ? imageIdentity : exactModule.name;
    const size_t slash = displayIdentity.find_last_of("/\\");
    std::string leaf = slash == std::string::npos
                     ? displayIdentity : displayIdentity.substr(slash + 1);
    if (leaf.empty()) leaf = "module";
    PendingDocumentCommand command;
    command.kind = PendingDocumentKind::Open;
    command.title = "[LIVE] " + leaf;
    command.image = std::move(candidate);
    command.project = {};
    command.decoder.engine = targetEngine;
    command.decoder.arch = targetArch;
    command.persistence = DocumentInstallPersistence::Ephemeral;
    command.metadata.liveImage = debugImageIdentity(session, *observed);
    command.liveModule = true;
    command.livePid = session.pid;
    command.liveSessionGeneration = session.sessionGeneration;
    command.liveBase = base;
    command.liveSize = captureSize;
    command.liveReportedSize = reportedSize;
    command.liveLoadGeneration = exactModule.loadGeneration;
    command.liveName = exactModule.name;
    command.livePath = exactModule.path;
    command.liveOrigin = origin;
    return queueDocumentOpen(std::move(command));
}

void AppContext::analyzeModule(LoadedModule& m, bool guess) {
    if (!m.imageLoaded || !m.bin.loaded()) return;
    if (m.analyzing && m.analysisEpoch == moduleAnalysis_.epoch()) return;
    Arch a = Arch::X64;
    if (!archFromMachine(m.bin.machine(), a)) {
        m.analysisComplete = false;
        m.analysisError =
            "The live module's structured machine architecture is unsupported; analysis was not started.";
        return;
    }
    // This cache represents one coherent request. Partial data from an earlier
    // failed/cancelled attempt must not combine with the retry's final xrefs.
    m.cache.clear();
    m.analysisComplete = false;
    m.analysisError.clear();
    m.analyzing = true;
    m.analysisEpoch = moduleAnalysis_.epoch();
    // moduleBase routes the immutable per-pass results to ModuleRegistry. The
    // service is app-global, so changing the active static document cannot cancel
    // or accidentally consume this live-module work.
    try {
        moduleAnalysis_.requestBulk(&m.bin, staticEngine(), a,
                                    K_Funcs | K_Strings | K_Listing | K_Xref,
                                    guess, m.analysisEpoch, m.base);
    } catch (const std::exception& error) {
        m.analyzing = false;
        m.analysisComplete = false;
        m.analysisError = std::string("Could not queue module analysis: ") + error.what();
        if (m.analysisError.size() > 1024) m.analysisError.resize(1024);
        ui::Toast(ui::ToastKind::Error, m.analysisError);
    } catch (...) {
        m.analyzing = false;
        m.analysisComplete = false;
        m.analysisError = "Could not queue module analysis: unknown error.";
        ui::Toast(ui::ToastKind::Error, m.analysisError);
    }
}

size_t AppContext::moduleAnalysesInFlight() const {
    size_t count = 0;
    for (const auto& module : modules.all())
        if (module && module->analyzing && module->analysisEpoch) ++count;
    return count;
}

void AppContext::drainModuleAnalysisResults() {
    AnalysisResult result;
    while (moduleAnalysis_.tryTakeBulk(result)) {
        if (result.epoch != moduleAnalysis_.epoch()) continue;
        const uint64_t base = result.moduleBase;
        const ModuleAnalysisRoute route = modules.applyAnalysisResult(std::move(result));
        if (route == ModuleAnalysisRoute::Failed) {
            if (LoadedModule* module = modules.byBase(base)) {
                std::string label = module->name;
                if (label.empty()) {
                    char value[32];
                    std::snprintf(value, sizeof(value), "module at 0x%llX",
                                  (unsigned long long)base);
                    label = value;
                }
                ui::Toast(ui::ToastKind::Error,
                          "Background analysis failed for " + label + ": " +
                          module->analysisError);
            }
        }
    }

    const ProgressSnapshot progress = moduleAnalysis_.progress();
    if (progress.resultsDropped > moduleAnalysisDroppedSeen_) {
        moduleAnalysisDroppedSeen_ = progress.resultsDropped;
        ui::Toast(ui::ToastKind::Warn,
                  "One or more live-module analysis results were dropped; incomplete modules can be retried.");
    }

    // The result queue was drained above. If the service is now idle, any module
    // from this epoch which never received its terminal xref result was cancelled,
    // failed before publication, or lost a bounded-queue result. Make that state
    // retryable and visible instead of leaving a permanent spinner.
    if (!moduleAnalysis_.bulkPending()) {
        const uint64_t epoch = moduleAnalysis_.epoch();
        for (const auto& module : modules.all()) {
            if (!module || !module->analyzing || !module->analysisEpoch ||
                module->analysisEpoch != epoch)
                continue;
            module->analyzing = false;
            module->analysisComplete = false;
            if (module->analysisError.empty())
                module->analysisError = "Module analysis ended without a complete result; retry the module.";
        }
    }
}

void AppContext::cancelModuleAnalysisPending() {
    const uint64_t cancelledEpoch = moduleAnalysis_.epoch();
    moduleAnalysis_.cancelPending();
    for (const auto& module : modules.all()) {
        if (!module || !module->analyzing || module->analysisEpoch != cancelledEpoch)
            continue;
        module->analyzing = false;
        module->analysisComplete = false;
        module->analysisEpoch = 0;
        module->analysisError = "Module analysis was cancelled.";
    }
}

void AppContext::cancelModuleAnalysisAndWait() {
    moduleAnalysis_.cancelAndWaitIdle();
    for (const auto& module : modules.all()) {
        if (!module || !module->analyzing || !module->analysisEpoch) continue;
        module->analyzing = false;
        module->analysisComplete = false;
        module->analysisEpoch = 0;
        if (module->analysisError.empty())
            module->analysisError = "Module analysis was cancelled because the live module set changed.";
    }
}

void AppContext::clearModules() {
    cancelModuleAnalysisAndWait();
    modules.clear();
}

void AppContext::removeModuleByBase(uint64_t base) {
    // One global pool may currently read any registry image. Joining the whole
    // bounded pool is required before erasing even one BinaryFile.
    cancelModuleAnalysisAndWait();
    modules.removeByBase(base);
}

void AppContext::synchronizeModuleSession(const DbgSnapshot& snapshot) {
    if (!snapshot.attached()) {
        if (moduleRegistrySessionValid_) livescan.cancelPending();
        if (moduleRegistrySessionValid_ || !modules.empty()) clearModules();
        moduleRegistrySessionValid_ = false;
        moduleRegistryPid_ = 0;
        moduleRegistrySessionGeneration_ = 0;
        return;
    }

    const bool changed = !moduleRegistrySessionValid_ ||
        moduleRegistryPid_ != snapshot.pid ||
        moduleRegistrySessionGeneration_ != snapshot.sessionGeneration;
    if (!changed) return;

    // This gate is app-global because retained Binary View children can all miss
    // a detach/reattach edge while another workbench section is visible. Never
    // carry module BinaryFiles, memory scans, or results into a new debugger
    // generation. This is deliberately app-global: individual retained Binary
    // View children only retire their own result tokens and projections.
    livescan.cancelPending();
    clearModules();
    moduleRegistrySessionValid_ = true;
    moduleRegistryPid_ = snapshot.pid;
    moduleRegistrySessionGeneration_ = snapshot.sessionGeneration;
}

bool AppContext::openBinaryDialog() {
    if (documentCommandPending()) {
        ui::Toast(ui::ToastKind::Info,
                  "Wait for the current document operation to finish, or cancel its load in the status bar.");
        return false;
    }
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Executables\0*.exe;*.dll;*.sys;*.bin;*.class;*.jar;*.zip\0All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return false;

    std::string path;
    if (!utf8FromWide(file.data(), path)) {
        ui::Toast(ui::ToastKind::Error, "Open failed: the selected path is not valid Unicode.");
        return false;
    }
    if (beginBinaryLoadPath(path)) return true;
    ui::Toast(ui::ToastKind::Error, documentCommandError_.empty()
        ? "The selected binary could not be opened." : documentCommandError_);
    return false;
}

void App::openFileDialog() {
    if (ctx_.openBinaryDialog()) {
        // A palette action runs after its render pass. Retire the old immutable
        // session immediately rather than exposing it until the next frame's
        // snapshot collection notices the replacement target.
        investigation_.cancel();
        investigationSubmittedGeneration_ = 0;
        investigationSubmittedLiveTarget_ = {};
        ctx_.requestedTab = "Binary View";
    }
}

void App::openRawFileDialog() {
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Raw / firmware images\0*.bin;*.rom;*.fd;*.cap;*.shc;*.dat\0All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    std::string path;
    if (!utf8FromWide(file.data(), path)) {
        ui::Toast(ui::ToastKind::Error, "Open Raw failed: the selected path is not valid Unicode.");
        return;
    }
    if (!prepareRawLoadPath(path))
        ui::Toast(ui::ToastKind::Error, "Open Raw failed while reading the selected file.");
}

bool App::prepareRawLoadPath(const std::string& path) {
    if (path.empty()) return false;
    rawPendingPath_ = path;
    rawBaseBuf_[0] = rawEntryBuf_[0] = '\0';
    formatHexU64(rawBaseBuf_, sizeof(rawBaseBuf_), 0x140000000ull);
    formatHexU64(rawEntryBuf_, sizeof(rawEntryBuf_), 0x140000000ull);
    rawArchSel_ = 2; // manual default: x64
    rawBigEndian_ = false;
    rawRiscvCompressed_ = true;
    rawSeedFirmwareLandmarks_ = true;
    if (!readFirmwareProbe(rawPendingPath_, rawPendingSize_, rawFirmware_, rawFirmwareNote_)) {
        rawPendingPath_.clear();
        return false;
    }
    if (rawFirmware_.detected()) {
        const uint64_t base = rawFirmware_.recommendedImageBaseValid
                            ? rawFirmware_.recommendedImageBase : 0x140000000ull;
        uint64_t entry = base;
        if (rawFirmware_.entry.detected && rawFirmware_.entry.location.valid &&
            rawFirmware_.entry.location.fileOffset < rawPendingSize_ &&
            rawFirmware_.entry.location.fileOffset <=
                (std::numeric_limits<uint64_t>::max)() - base)
            entry = base + rawFirmware_.entry.location.fileOffset;
        formatHexU64(rawBaseBuf_, sizeof(rawBaseBuf_), base);
        formatHexU64(rawEntryBuf_, sizeof(rawEntryBuf_), entry);
    }
    // A flat blob may have a strong instruction-motif architecture hint without
    // claiming a BIOS/UEFI container or changing the editable mapping defaults.
    if (rawFirmware_.architecture.mode != FirmwareCpuMode::Unknown)
        rawArchSel_ = rawArchForFirmwareMode(rawFirmware_.architecture.mode);
    // A recovered entry has its own authoritative mode even if embedded images
    // supplied conflicting machine hints.
    if (rawFirmware_.entry.mode != FirmwareCpuMode::Unknown)
        rawArchSel_ = rawArchForFirmwareMode(rawFirmware_.entry.mode);
    // A32/Thumb have a 32-bit architectural PC and Capstone reports their
    // direct branch targets in that address space. An architecture-only motif
    // hint must therefore replace the generic x64 high-base default with a
    // mapping whose entire file fits below 4 GiB.
    {
        uint64_t base = 0, entry = 0;
        const Arch hinted = rawArchFromSelection(rawArchSel_);
        if (parseHexU64(rawBaseBuf_, base) && parseHexU64(rawEntryBuf_, entry) &&
            !ArchMappingRangeFits(hinted, base, rawPendingSize_) &&
            (hinted == Arch::ARM || hinted == Arch::THUMB)) {
            base = 0;
            entry = rawFirmware_.entry.detected && rawFirmware_.entry.location.valid &&
                    rawFirmware_.entry.location.fileOffset < rawPendingSize_
                  ? rawFirmware_.entry.location.fileOffset : 0;
            formatHexU64(rawBaseBuf_, sizeof(rawBaseBuf_), base);
            formatHexU64(rawEntryBuf_, sizeof(rawEntryBuf_), entry);
        }
    }
    openRawPopup_   = true;   // prompt for base + arch
    return true;
}

void App::saveBinaryAs() {
    if (!ctx_.staticBinary().loaded()) return;
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    if (ctx_.staticProject().patchRecoveryPending) {
        ui::Toast(ui::ToastKind::Error, "Save blocked: resolve saved-patch recovery in Patches first.");
        return;
    }
    if (ctx_.artifactWrites.pending()) {
        ui::Toast(ui::ToastKind::Error, "A file save is still pending; wait for its result.");
        return;
    }
    try {
        // Copy mapping/patch metadata and share immutable image storage. Full
        // composition and image allocation happen exclusively on the worker.
        auto image = ctx_.staticBinary();
        auto patches = ctx_.staticProject().patches;
        auto sets = ctx_.staticProject().patchSets;
        const std::filesystem::path destination(file.data());
        std::string message;
        const bool queued = ctx_.queueArtifactWrite(
            [image = std::move(image), patches = std::move(patches),
             sets = std::move(sets), destination] {
                auto built = BuildPatchSetImageForSelection(image, patches, sets, {},
                    PatchSetImageSource::CurrentEnabledSets);
                if (!built.success) {
                    ArtifactWriteResult result; result.path = destination;
                    result.error = "Save blocked: " + std::string(PatchSetImageErrorText(built.error));
                    if (built.failedPatch != std::numeric_limits<size_t>::max())
                        result.error += " at patch #" + std::to_string(built.failedPatch + 1);
                    const auto& plan = !built.currentPlan.success ? built.currentPlan : built.desiredPlan;
                    if (plan.error != PjPatchSetPlanError::None)
                        result.error += ": " + std::string(PjPatchSetPlanErrorText(plan.error));
                    return result;
                }
                return WriteArtifactBytes(destination, built.image);
            }, message);
        ui::Toast(queued ? ui::ToastKind::Info : ui::ToastKind::Error, message);
    } catch (const std::exception& error) {
        ui::Toast(ui::ToastKind::Error, std::string("Could not capture save inputs: ") + error.what());
    }
}

// Carve the detected embedded JAR/ZIP (ctx_.javaInfo's [jarOffset, +jarSize)
// span of the loaded file's bytes) out to a file the user picks. The span was
// validated by ScanJava (EOCD + central-directory math, trailing Authenticode
// cert excluded), so this is a plain byte copy -- no re-parsing here.
void App::extractEmbeddedJar() {
    const JavaScanResult& ji = ctx_.staticJavaInfo();
    if (!ctx_.staticBinary().loaded() || !ji.jarSize) return;
    const auto& bytes = ctx_.staticBinary().bytes();
    if (ji.jarOffset >= bytes.size() || ji.jarSize > bytes.size() - ji.jarOffset) {
        ui::Toast(ui::ToastKind::Error, "Extract failed: archive span is out of bounds (stale scan?).");
        return;
    }

    // Default name: "<binary stem>.jar" (".zip" when there is no JAR manifest).
    std::wstring def;
    {
        std::string base = ctx_.staticBinary().path();
        size_t slash = base.find_last_of("/\\");
        if (slash != std::string::npos) base = base.substr(slash + 1);
        size_t dot = base.find_last_of('.');
        if (dot != std::string::npos && dot > 0) base = base.substr(0, dot);
        base += ji.isJar ? ".jar" : ".zip";
        if (!wideFromUtf8(base, def)) def = ji.isJar ? L"embedded.jar" : L"embedded.zip";
    }
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    wcsncpy_s(file.data(), file.size(), def.c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = ji.isJar ? L"JAR archive (*.jar)\0*.jar\0ZIP archive (*.zip)\0*.zip\0All Files\0*.*\0"
                               : L"ZIP archive (*.zip)\0*.zip\0All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.lpstrDefExt = ji.isJar ? L"jar" : L"zip";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    const auto owned = ctx_.staticBinary().ownedBytes();
    const auto offset = ji.jarOffset, count = ji.jarSize;
    const std::filesystem::path destination(file.data());
    std::string message;
    const bool queued = ctx_.queueArtifactWrite([owned, offset, count, destination] {
        return WriteArtifactBytes(destination,
            std::span<const uint8_t>(*owned).subspan(static_cast<size_t>(offset), static_cast<size_t>(count)));
    }, message);
    ui::Toast(queued ? ui::ToastKind::Info : ui::ToastKind::Error, message);
}

// ---- Archive entry browser ("Archive Entries" popup) ------------------------

namespace {

// "lib/app.jar" -> "app.jar" with Windows-invalid filename chars replaced.
std::string sanitizeEntryBaseName(const std::string& entryName) {
    size_t s = entryName.find_last_of("/\\");
    std::string b = (s == std::string::npos) ? entryName : entryName.substr(s + 1);
    for (char& c : b)
        if ((unsigned char)c < 0x20 || std::strchr("<>:\"/\\|?*", c)) c = '_';
    while (!b.empty() && (b.back() == '.' || b.back() == ' ')) b.pop_back();
    if (b.empty()) b = "entry";
    std::string stem = b.substr(0, b.find('.'));
    for (char& c : stem) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    const bool numberedDevice = stem.size() == 4 && stem[3] >= '1' && stem[3] <= '9' &&
        (stem.starts_with("COM") || stem.starts_with("LPT"));
    if (numberedDevice || stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL")
        b.insert(b.begin(), '_');
    return b;
}

// Reserve a private extraction directory with an atomic create. The final
// filename is installed without replacement, preserving every previous entry.
ArtifactWriteResult writeExtractedTemp(const std::string& name, const std::vector<uint8_t>& bytes) {
    static std::atomic<uint64_t> sequence{0};
    const auto root = std::filesystem::temp_directory_path() / L"DisasmStudio" / L"extracted";
    std::filesystem::create_directories(root);
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto dir = root / (std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(sequence.fetch_add(1)));
        std::error_code error;
        if (!std::filesystem::create_directory(dir, error)) {
            if (!error || error == std::errc::file_exists) continue;
            ArtifactWriteResult result; result.error = error.message(); return result;
        }
        auto result = WriteArtifactBytes(dir / pathFromUtf8(name), bytes, false);
        if (!result.success) std::filesystem::remove(dir, error);
        return result;
    }
    ArtifactWriteResult result; result.error = "Could not reserve a unique extraction directory.";
    return result;
}

} // namespace

void App::openArchiveBrowser() {
    if (!ctx_.staticBinary().loaded() || ctx_.staticJavaInfo().entries.empty()) return;
    archiveBrowser_ = {};
    archiveBrowser_.sourcePath = ctx_.staticBinary().path();
    archiveBrowser_.sourceBytes = ctx_.staticBinary().ownedBytes();
    size_t s = archiveBrowser_.sourcePath.find_last_of("/\\");
    archiveBrowser_.sourceName = (s == std::string::npos) ? archiveBrowser_.sourcePath
                                                          : archiveBrowser_.sourcePath.substr(s + 1);
    archiveBrowser_.zipBase = ctx_.staticJavaInfo().jarOffset;
    archiveBrowser_.entries = ctx_.staticJavaInfo().entries;
    archiveBrowser_.open    = true;
}

// Save-dialog flow for one archive entry: extractEmbeddedJar's shape, but
// writing the DECOMPRESSED entry bytes rather than the raw archive span.
void App::extractArchiveEntryToFile(const JavaZipEntry& e) {
    std::string base = sanitizeEntryBaseName(e.name);
    std::wstring def;
    {
        if (!wideFromUtf8(base, def)) def = L"entry";
    }
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    wcsncpy_s(file.data(), file.size(), def.c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    const auto owned = archiveBrowser_.sourceBytes;
    const auto zipBase = archiveBrowser_.zipBase;
    const std::filesystem::path destination(file.data());
    std::string message;
    const bool queued = ctx_.queueArtifactWrite([owned, zipBase, entry = e, destination] {
        std::vector<uint8_t> bytes;
        ArtifactWriteResult result; result.path = destination;
        if (!owned || !ExtractZipEntry(owned->data(), owned->size(), zipBase, entry, bytes, &result.error)) {
            if (result.error.empty()) result.error = "Archive snapshot is unavailable.";
            return result;
        }
        return WriteArtifactBytes(destination, bytes);
    }, message);
    ui::Toast(queued ? ui::ToastKind::Info : ui::ToastKind::Error, message);
}

void App::renderArchiveBrowser() {
    if (archiveBrowser_.open) { ImGui::OpenPopup("Archive Entries"); archiveBrowser_.open = false; }
    const float s = theme::UiScale();
    prepareWorkbenchDialog(700.0f, 440.0f);
    if (!ImGui::BeginPopupModal("Archive Entries", nullptr, 0)) return;

    ImGui::TextDisabled("%s \xE2\x80\x94 %zu entr%s", archiveBrowser_.sourceName.c_str(),
                        archiveBrowser_.entries.size(),
                        archiveBrowser_.entries.size() == 1 ? "y" : "ies");
    ImGui::SameLine();
    ui::SearchBox("##arcfilter", "filter name...", archiveBrowser_.filter,
                  sizeof(archiveBrowser_.filter), 240.0f * s);

    // Case-insensitive substring filter over entry names.
    auto lc = [](std::string v) { for (char& ch : v) ch = (char)std::tolower((unsigned char)ch); return v; };
    const std::string needle = lc(archiveBrowser_.filter);
    std::vector<int> rows;
    rows.reserve(archiveBrowser_.entries.size());
    for (int i = 0; i < (int)archiveBrowser_.entries.size(); ++i)
        if (needle.empty() || lc(archiveBrowser_.entries[i].name).find(needle) != std::string::npos)
            rows.push_back(i);

    const float footer = ImGui::GetFrameHeightWithSpacing() + 4.0f * s;
    if (ImGui::BeginTable("##arcentries", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY,
                          ImVec2(0, -footer))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 64.0f * s);
        ImGui::TableSetupColumn("Size",   ImGuiTableColumnFlags_WidthFixed, 90.0f * s);
        ImGui::TableSetupColumn("Packed", ImGuiTableColumnFlags_WidthFixed, 90.0f * s);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin((int)rows.size());
        while (clip.Step()) {
            for (int r = clip.DisplayStart; r < clip.DisplayEnd; ++r) {
                const int i = rows[r];
                const JavaZipEntry& e = archiveBrowser_.entries[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(i);   // entry names can repeat across directories
                if (ImGui::Selectable(e.name.c_str(), archiveBrowser_.selected == i,
                                      ImGuiSelectableFlags_SpanAllColumns))
                    archiveBrowser_.selected = i;
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%s", e.method == 0 ? "stored" : e.method == 8 ? "deflate" : "other");
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%u", e.uncompSize);
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%u", e.compSize);
            }
        }
        ImGui::EndTable();
    }

    const bool hasSel = archiveBrowser_.selected >= 0 &&
                        archiveBrowser_.selected < (int)archiveBrowser_.entries.size();
    ImGui::BeginDisabled(!hasSel);
    if (ImGui::Button("Open as binary") && hasSel) {
        const auto owned = archiveBrowser_.sourceBytes;
        const auto zipBase = archiveBrowser_.zipBase;
        const auto entry = archiveBrowser_.entries[archiveBrowser_.selected];
        const auto document = ctx_.staticDocumentId();
        const auto generation = ctx_.staticImageGeneration();
        const auto revision = ctx_.staticBinary().imageRevision();
        std::string message;
        const bool queued = ctx_.queueArtifactWrite([owned, zipBase, entry] {
            std::vector<uint8_t> bytes;
            ArtifactWriteResult result;
            if (!owned || !ExtractZipEntry(owned->data(), owned->size(), zipBase, entry, bytes, &result.error)) {
                if (result.error.empty()) result.error = "Archive snapshot is unavailable.";
                return result;
            }
            return writeExtractedTemp(sanitizeEntryBaseName(entry.name), bytes);
        }, message, [this, document, generation, revision](const ArtifactWriteResult& result) {
            if (!result.success || ctx_.staticDocumentId() != document || ctx_.staticImageGeneration() != generation ||
                ctx_.staticBinary().imageRevision() != revision || ctx_.binaryLoadPending()) return;
            std::string path;
            if (utf8FromWide(result.path.c_str(), path) && ctx_.beginBinaryLoadPath(path))
                ctx_.requestedTab = "Binary View";
            else ui::Toast(ui::ToastKind::Error, "Entry saved, but its background load could not start.");
        });
        ui::Toast(queued ? ui::ToastKind::Info : ui::ToastKind::Error, message);
        if (queued) ImGui::CloseCurrentPopup();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Decompress the selected entry to %%TEMP%% and load it as the active binary.");
    ImGui::SameLine();
    if (ImGui::Button("Extract...") && hasSel)
        extractArchiveEntryToFile(archiveBrowser_.entries[archiveBrowser_.selected]);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Save the selected entry's decompressed bytes to a file you pick.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

bool AppContext::queueArtifactWrite(std::function<ArtifactWriteResult()> ownedJob,
    std::string& message, std::function<void(const ArtifactWriteResult&)> completion) {
    if (!artifactWrites.start(std::move(ownedJob), message)) return false;
    artifactWriteCompletion = std::move(completion);
    message = "File save queued in the background.";
    return true;
}

void AppContext::pollArtifactWrites() {
    ArtifactWriteResult result;
    if (!artifactWrites.take(result)) return;
    ++artifactWriteCompletionRevision;
    artifactWriteFailed = !result.success || !result.warning.empty();
    artifactWriteFailure = !result.success ? result.error : result.warning;
    auto completion = std::move(artifactWriteCompletion);
    artifactWriteCompletion = {};
    if (!result.success) ui::Toast(ui::ToastKind::Error, "Save failed: " + result.error);
    else if (!result.warning.empty()) ui::Toast(ui::ToastKind::Warn, result.warning);
    else {
        std::string path;
        utf8FromWide(result.path.c_str(), path);
        ui::Toast(ui::ToastKind::Success, "Wrote " + std::to_string(result.bytes) + " bytes to " + path);
    }
    if (completion) completion(result);
}

bool AppContext::exportAnalysisFile(const std::string& defaultBaseName,
                                    const std::string& markdown, const std::string& html,
                                    std::string& msg) {
    // Seed the dialog with "<binary>_analysis.md".
    std::wstring def;
    {
        std::string base = defaultBaseName.empty() ? std::string("analysis") : defaultBaseName;
        base += "_analysis.md";
        if (!wideFromUtf8(base, def)) def = L"analysis_analysis.md";
    }
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    wcsncpy_s(file.data(), file.size(), def.c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Markdown (*.md)\0*.md\0HTML (*.html)\0*.html\0All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.lpstrDefExt = L"md";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) { msg.clear(); return false; }   // cancelled

    std::string p;
    if (!utf8FromWide(file.data(), p)) {
        msg = "Failed to encode the selected path as UTF-8.";
        return false;
    }

    // HTML when the chosen name ends in .htm/.html (case-insensitive), else Markdown.
    auto endsWithCI = [&](const char* suf) {
        size_t ls = std::strlen(suf);
        if (p.size() < ls) return false;
        for (size_t i = 0; i < ls; ++i)
            if (std::tolower((unsigned char)p[p.size() - ls + i]) != (unsigned char)suf[i]) return false;
        return true;
    };
    const std::string& body = (endsWithCI(".html") || endsWithCI(".htm")) ? html : markdown;

    const std::filesystem::path destination(file.data());
    return queueArtifactWrite([destination, body = std::string(body)] {
        return WriteArtifactBytes(destination, std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(body.data()), body.size()));
    }, msg);
}

bool AppContext::selectCodeExportPath(const std::string& defaultName,
                                      CodeExportFormat format,
                                      std::string& pathOut, std::string& err) {
    pathOut.clear();
    err.clear();

    std::wstring def;
    const std::string fallback = format == CodeExportFormat::Assembly ? "disassembly.asm" : "decompiled.c";
    if (!wideFromUtf8(defaultName.empty() ? fallback : defaultName, def)) {
        if (!wideFromUtf8(fallback, def)) def = format == CodeExportFormat::Assembly
                                               ? L"disassembly.asm" : L"decompiled.c";
    }
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    wcsncpy_s(file.data(), file.size(), def.c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = format == CodeExportFormat::Assembly
                    ? L"Assembly source (*.asm)\0*.asm\0All Files\0*.*\0"
                    : L"C source (*.c)\0*.c\0All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.lpstrDefExt = format == CodeExportFormat::Assembly ? L"asm" : L"c";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return false; // cancelled is not an error

    if (!utf8FromWide(file.data(), pathOut)) {
        err = "Failed to encode the selected path as UTF-8.";
        pathOut.clear();
        return false;
    }
    return true;
}

bool AppContext::saveBytesFile(const std::string& defaultName,
                               const std::vector<uint8_t>& bytes, std::string& msg,
                               const wchar_t* filterSpec, const wchar_t* defExt,
                               std::function<void(const ArtifactWriteResult&)> completion,
                               std::string reportSuffix, std::string report) {
    if (artifactWrites.pending()) { msg = "A file save is still pending; wait for its result."; return false; }
    std::wstring def;
    if (!wideFromUtf8(defaultName.empty() ? std::string("resource.bin") : defaultName, def))
        def = L"resource.bin";
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    wcsncpy_s(file.data(), file.size(), def.c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = filterSpec ? filterSpec : L"All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.lpstrDefExt = defExt;
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) { msg.clear(); return false; }   // cancelled

    std::string p;
    if (!utf8FromWide(file.data(), p)) {
        msg = "Failed to encode the selected path as UTF-8.";
        return false;
    }
    const std::filesystem::path destination(file.data());
    try {
        return queueArtifactWrite([destination, bytes = std::vector<uint8_t>(bytes),
            suffix = std::move(reportSuffix), report = std::move(report)] {
            auto result = WriteArtifactBytes(destination, bytes);
            if (result.success && !suffix.empty()) {
                auto reportPath = destination;
                reportPath += pathFromUtf8(suffix);
                auto written = WriteArtifactBytes(reportPath, std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(report.data()), report.size()));
                if (!written.success) result.warning = "Artifact saved, but its report failed: " + written.error;
            }
            return result;
        }, msg, std::move(completion));
    } catch (const std::exception& error) { msg = error.what(); return false; }
}

void App::closeBinary() {
    if (!ctx_.queueCloseStaticDocument(ctx_.staticDocumentId())) {
        ui::Toast(ui::ToastKind::Error,
                  ctx_.documentCommandError().empty()
                    ? "Could not queue the document close."
                    : ctx_.documentCommandError());
    }
}

void App::retireActiveDocumentRequests() {
    palette_.close();
    investigation_.cancel();
    investigationSubmittedGeneration_ = 0;
    investigationSubmittedLiveTarget_ = {};

    // Every address-bearing request below was authored against the outgoing
    // document. The debugger/JDWP/Prism targets are intentionally not touched:
    // they are app-global and survive static tab switches.
    ctx_.requestedGotoVA = 0;
    ctx_.hasGotoRequest = false;
    ctx_.requestedGotoLive = false;
    ctx_.requestedGotoTarget = {};
    ctx_.requestedLiveAssembly = false;
    ctx_.requestedCrackmeTriage = false;
    ctx_.requestedTriageView = TriageWorkspaceView::StartHere;
    ctx_.requestedTriageAuthorizationFlow.clear();
    ctx_.requestedTriageStartupEntitlementLead = false;
    ctx_.requestedTriageFileOffset = 0;
    ctx_.requestedTriageFileOffsetValid = false;
    ctx_.hasCursor = false;
    ctx_.cursorVA = 0;
    ctx_.cursorLive = false;
    ctx_.cursorTarget = {};
    ctx_.runtimeCursorVA = 0;
    ctx_.runtimeCursorTarget = {};
    ctx_.cursorFuncName.clear();
    ctx_.clearPendingSignature();
    ctx_.requestedExtractJava = false;
    ctx_.requestedBrowseArchive = false;
    ctx_.requestedExportAnalysis = false;
    ctx_.requestedCodeExport = false;
    ctx_.requestResetDockLayout = false;
    ctx_.projectAnnotationsExternallyChanged = false;
    ctx_.requestedDebugDll = false;
    ctx_.requestedTraceToggle = false;
    ctx_.requestedTraceTarget = {};
    ctx_.requestedTraceClear = false;
    ctx_.requestedTraceClearTarget = {};
    ctx_.requestedTraceCancel = false;
    ctx_.requestedTraceCancelTarget = {};
    ctx_.traceSeedPlanning = false;
    ctx_.traceSeedCurrent = ctx_.traceSeedTotal = ctx_.traceSeedFound = 0;
    toolbarAddressEditing_ = false;
    toolbarAddressMirrorValid_ = false;
    toolbarAddressMirrorLive_ = false;
    toolbarAddressMirrorTarget_ = {};
    toolbarAddress_[0] = 0;
}

void App::applyPendingDocumentCommand() {
    const AppContext::DocumentCommandOutcome outcome =
        ctx_.applyPendingDocumentCommand(
            [this](DocumentId id, bool closing, std::string& error) {
                return !binaryView_ ||
                       binaryView_->prepareDocumentTransition(
                           ctx_, id, closing, error);
            });
    if (!outcome.hadCommand) return;
    if (outcome.liveModule) {
        auto recordFailure = [&](LiveDocumentAttempt& attempt) {
            attempt.valid = true;
            attempt.pid = outcome.livePid;
            attempt.sessionGeneration = outcome.liveSessionGeneration;
            attempt.base = outcome.liveBase;
            attempt.retryRevision = ctx_.documentRetryRevision();
        };
        if (outcome.liveOrigin == LiveDocumentOpenOrigin::AttachMain) {
            if (attachMainDocumentPending_.matches(
                    outcome.livePid, outcome.liveSessionGeneration,
                    outcome.liveBase))
                attachMainDocumentPending_.clear();
            if (outcome.success) {
                attachMainDocumentSessionValid_ = true;
                attachMainDocumentPid_ = outcome.livePid;
                attachMainDocumentGeneration_ = outcome.liveSessionGeneration;
                attachMainDocumentFailure_.clear();
            } else {
                recordFailure(attachMainDocumentFailure_);
            }
        } else if (outcome.liveOrigin == LiveDocumentOpenOrigin::HostedDll) {
            if (dllRetargetPending_.matches(
                    outcome.livePid, outcome.liveSessionGeneration,
                    outcome.liveBase))
                dllRetargetPending_.clear();
            if (outcome.success) {
                dllRetargetPid_ = outcome.livePid;
                dllRetargetGeneration_ = outcome.liveSessionGeneration;
                dllRetargetBase_ = outcome.liveBase;
                dllRetargetFailure_.clear();
                ctx_.requestedTab = "Binary View";
                ui::Toast(ui::ToastKind::Success,
                          "Loaded the target DLL at its runtime ASLR base for live analysis.");
            } else {
                recordFailure(dllRetargetFailure_);
            }
        }
    }
    auto finishOwnedLoad = [&](bool success) {
        const PendingDocumentLoadOwner owner = pendingDocumentLoadOwner_;
        pendingDocumentLoadOwner_ = PendingDocumentLoadOwner::None;
        switch (owner) {
        case PendingDocumentLoadOwner::AdaptiveUnpack:
            if (success) {
                unpackPopup_.result = {};
                unpackPopup_.closeAfterDocumentLoad = true;
            } else {
                unpackPopup_.error = outcome.error;
            }
            break;
        case PendingDocumentLoadOwner::StaticUnpack:
            if (success) {
                staticUnpackPopup_.result = {};
                staticUnpackPopup_.sourcePath.clear();
                staticUnpackPopup_.sourceHash = 0;
                staticUnpackPopup_.sourceRevision = 0;
                staticUnpackPopup_.sourceWasDll = false;
                staticUnpackPopup_.closeAfterDocumentLoad = true;
            } else {
                staticUnpackPopup_.error = outcome.error;
            }
            break;
        case PendingDocumentLoadOwner::PassiveDump:
            if (success) {
                passiveDumpPopup_.result = {};
                passiveDumpPopup_.closeAfterDocumentLoad = true;
            } else {
                passiveDumpPopup_.error = outcome.error;
            }
            break;
        default:
            break;
        }
    };
    if (!outcome.success) {
        finishOwnedLoad(false);
        if (outcome.activeChanged) retireActiveDocumentRequests();
        ui::Toast(ui::ToastKind::Error,
                  outcome.error.empty() ? "The document operation failed."
                                        : outcome.error);
        return;
    }

    finishOwnedLoad(true);

    if (outcome.retired && binaryView_)
        binaryView_->retireDocument(ctx_, outcome.retired);
    if (outcome.activeChanged) retireActiveDocumentRequests();
    if (outcome.browseArchive) ctx_.requestedBrowseArchive = true;
    if (!outcome.warning.empty())
        ui::Toast(ui::ToastKind::Warn, outcome.warning);
}

void App::renderMenuBar() {
    const float k = theme::UiScale();
    titleDragRegionValid_ = false;
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.0f * k,
        ((std::max)(32.0f * k, ImGui::GetTextLineHeight() + 8.0f * k) -
            ImGui::GetTextLineHeight()) * 0.5f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f * k, 4.0f * k));
    ImGui::PushStyleColor(ImGuiCol_MenuBarBg, theme::col::chrome());
    if (ImGui::BeginMainMenuBar()) {
        // Brand, menus, document identity and real debugger state share the
        // reference's single compact title row.
        const ImVec2 brandAt = ImGui::GetCursorScreenPos();
        const float brandSize = 16.0f * k;
        ImGui::Dummy(ImVec2(brandSize, ImGui::GetTextLineHeight()));
        const float brandY = brandAt.y + (ImGui::GetTextLineHeight() - brandSize) * 0.5f;
        ImVec4 brandFill = theme::col::accent(); brandFill.w = 0.22f;
        ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(brandAt.x, brandY),
            ImVec2(brandAt.x + brandSize, brandY + brandSize),
            ImGui::GetColorU32(brandFill), 5.0f * k);
        const float brandFont = ImGui::GetFontSize() * 0.62f;
        const ImVec2 brandText = ImGui::GetFont()->CalcTextSizeA(brandFont, FLT_MAX, 0, "DS");
        ImGui::GetWindowDrawList()->AddText(ImGui::GetFont(), brandFont,
            ImVec2(brandAt.x + (brandSize - brandText.x) * 0.5f,
                brandY + (brandSize - brandText.y) * 0.5f),
            ImGui::GetColorU32(theme::col::accent()), "DS");
        ImGui::SameLine(0.0f, 8.0f * k);
        ImGui::TextUnformatted("DisasmStudio");
        ImGui::SameLine(0.0f, 12.0f * k);
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open Binary...", "Ctrl+O")) openFileDialog();
            if (ImGui::MenuItem("Open as Raw...")) openRawFileDialog();
            ImGui::Separator();
            const bool canDebugDll = ctx_.binaryDllDebuggable() &&
                                     (!ctx_.frameDebugSnapshot || !ctx_.frameDebugSnapshot->attached());
            if (ImGui::MenuItem("Debug DLL...", nullptr, false, canDebugDll))
                ctx_.requestedDebugDll = true;
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(ctx_.binaryDebugArchitectureMatches()
                    ? "Launch this PE DLL in a bitness-compatible host and break at DllMain or an export."
                    : "Hosted DLL debugging requires a matching x86/x64 PE machine and decoder mode (active: %s).",
                    ArchName(ctx_.staticArch()));
            if (ImGui::MenuItem("Save Binary As...", nullptr, false, ctx_.staticBinary().loaded()))
                saveBinaryAs();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Write a copy of the loaded file with the currently enabled patch-set selection applied.");
            const bool canCodeExport = ctx_.staticBinary().loaded() && !ctx_.staticCodeExport().pending();
            if (ImGui::MenuItem("Save ASM...", nullptr, false, canCodeExport)) {
                ctx_.requestedCodeExport = true;
                ctx_.requestedCodeExportFormat = CodeExportFormat::Assembly;
                ctx_.requestedTab = "Binary View";
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Export the whole program or current function as assembly on a background worker.");
            const bool canCExport = canCodeExport && ArchIsX86_32Or64(ctx_.staticArch());
            if (ImGui::MenuItem("Save C...", nullptr, false, canCExport)) {
                ctx_.requestedCodeExport = true;
                ctx_.requestedCodeExportFormat = CodeExportFormat::C;
                ctx_.requestedTab = "Binary View";
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(ArchIsX86_32Or64(ctx_.staticArch())
                    ? "Export readable pseudocode or a self-contained compilable C translation unit."
                    : "C export currently requires an x86 or x64 target; Save ASM supports this architecture.");
            if (ImGui::MenuItem("Export Analysis...", nullptr, false, ctx_.staticBinary().loaded())) {
                ctx_.requestedExportAnalysis = true;
                ctx_.requestedTab = "Binary View";
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Export comments, renames, bookmarks, notes and decompiled named functions to Markdown / HTML.");
            if (ImGui::MenuItem(ctx_.staticJavaInfo().isJar ? "Extract Embedded JAR..." : "Extract Embedded ZIP...",
                                nullptr, false, ctx_.staticJavaInfo().jarSize > 0))
                extractEmbeddedJar();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(ctx_.staticJavaInfo().jarSize > 0
                                      ? "Carve the appended archive a Java launcher embedded in this EXE out to a file."
                                      : "Enabled when an appended JAR/ZIP archive is detected in the loaded binary.");
            if (ImGui::MenuItem("Browse Embedded Archive...", nullptr, false, !ctx_.staticJavaInfo().entries.empty()))
                ctx_.requestedBrowseArchive = true;
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(!ctx_.staticJavaInfo().entries.empty()
                                      ? "List the embedded archive's entries; open one as a binary or extract it decompressed."
                                      : "Enabled when a JAR/ZIP archive with entries is detected in the loaded binary.");
            ImGui::Separator();
            if (ImGui::MenuItem("Close Document", "Ctrl+W", false,
                                ctx_.staticDocumentCount() != 0))
                closeBinary();
            if (ImGui::BeginMenu("Open documents", ctx_.staticDocumentCount() != 0)) {
                const auto documents = ctx_.staticDocuments();
                ImGui::BeginDisabled(ctx_.documentCommandPending() || palette_.isOpen());
                for (const auto& document : documents) {
                    ImGui::PushID(static_cast<int>(document.id.value));
                    const std::string label = (document.mapped ? "[LIVE] " : "") +
                        (document.title.empty() ? std::string("Untitled") : document.title) +
                        (document.dirty ? " *" : "");
                    if (ImGui::MenuItem(label.c_str(), nullptr, document.active) &&
                        !ctx_.queueActivateStaticDocument(document.id))
                        ui::Toast(ui::ToastKind::Error, ctx_.documentCommandError());
                    if (ImGui::BeginPopupContextItem("##file_document_actions")) {
                        if (!document.path.empty() && ImGui::MenuItem("Copy full path"))
                            ImGui::SetClipboardText(document.path.c_str());
                        if (ImGui::MenuItem("Close document") &&
                            !ctx_.queueCloseStaticDocument(document.id))
                            ui::Toast(ui::ToastKind::Error, ctx_.documentCommandError());
                        ImGui::EndPopup();
                    }
                    ImGui::PopID();
                }
                ImGui::EndDisabled();
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                requestExit();
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::BeginMenu("Disassembler")) {
                // A32/Thumb/A64 force Capstone (Zydis is x86-only); reflect the
                // effective engine so the menu never disagrees with reality.
                const bool nonX86 = !ArchIsX86(ctx_.staticArch());
                const Engine effective = ctx_.staticDisassembler()
                    ? ctx_.staticDisassembler()->engine() : ctx_.staticEngine();
                const bool z = effective == Engine::Zydis;
                const bool c = effective == Engine::Capstone;
                ImGui::BeginDisabled(nonX86);
                if (ImGui::MenuItem("Zydis", nullptr, z))
                    ctx_.setStaticDecoderConfiguration(Engine::Zydis, ctx_.staticArch());
                ImGui::EndDisabled();
                if (nonX86 && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                    ImGui::SetTooltip("Zydis decodes x86-16/x86/x64 only - Capstone is used for every other architecture.");
                if (ImGui::MenuItem("Capstone", nullptr, c))
                    ctx_.setStaticDecoderConfiguration(Engine::Capstone, ctx_.staticArch());
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Architecture")) {
                auto archItem = [&](const char* label, Arch a) {
                    const bool mappingFits = archFitsActiveRawMapping(ctx_, a);
                    if (ImGui::MenuItem(label, nullptr,
                                        ctx_.staticArch() == a, mappingFits))
                        ctx_.setStaticDecoderConfiguration(ctx_.staticEngine(), a);
                    if (!mappingFits && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                        ImGui::SetTooltip("This raw mapping does not fit the %s address space. Reopen it with a lower base.",
                                          ArchName(a));
                };
                archItem("x86-16",        Arch::X86_16);
                archItem("x86",           Arch::X86);
                archItem("x64",           Arch::X64);
                archItem("ARM",           Arch::ARM);
                archItem("Thumb/Thumb-2", Arch::THUMB);
                archItem("ARM64",         Arch::ARM64);
                archItem("MIPS",          Arch::MIPS);
                archItem("MIPS64",        Arch::MIPS64);
                archItem("PowerPC",       Arch::PPC);
                archItem("PowerPC64",     Arch::PPC64);
                archItem("RISC-V 32",     Arch::RISCV32);
                archItem("RISC-V 64",     Arch::RISCV64);
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Theme")) {
                for (int i = 0; i < (int)theme::ThemeId::Count; ++i) {
                    theme::ThemeId id = (theme::ThemeId)i;
                    if (ImGui::MenuItem(theme::ThemeName(id), nullptr, theme_ == id)) {
                        theme_ = id;
                        theme::ApplyTheme(id);
                        savePrefs();
                    }
                }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("UI Zoom")) {
                const int zoom = theme::UiZoomPercent();
                if (ImGui::MenuItem("Zoom out", "Ctrl+-", false, zoom > kMinUiZoomPercent))
                    setUiZoomPercent(zoom - 5);
                if (ImGui::MenuItem("Zoom in", "Ctrl++", false, zoom < kMaxUiZoomPercent))
                    setUiZoomPercent(zoom + 5);
                if (ImGui::MenuItem("Actual size (100%)", "Ctrl+0", zoom == 100))
                    setUiZoomPercent(100);
                ImGui::Separator();
                for (int percent : {75, 80, 85, 90, 95, 100, 110, 125, 150}) {
                    char label[40];
                    std::snprintf(label, sizeof(label), percent == kDefaultUiZoomPercent
                        ? "%d%% (default)" : "%d%%", percent);
                    if (ImGui::MenuItem(label, nullptr, zoom == percent))
                        setUiZoomPercent(percent);
                }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Density")) {
                const theme::Density opts[] = { theme::Density::Compact,
                                                theme::Density::Comfortable,
                                                theme::Density::Spacious };
                for (theme::Density density : opts) {
                    if (ImGui::MenuItem(theme::DensityName(density), nullptr,
                                        density_ == density)) {
                        density_ = density;
                        theme::SetDensity(density);
                        theme::ApplyTheme();
                        savePrefs();
                    }
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Reset Binary View Layout"))
                ctx_.requestResetDockLayout = true;
            if (ImGui::MenuItem("Symbol Settings..."))
                ctx_.requestedSymbolSettings = true;
#ifdef _DEBUG
            ImGui::MenuItem("ImGui Demo", nullptr, &showDemo_);
#endif
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")) {
            if (ImGui::MenuItem("Hide Debugger / Anti-Anti-Debug..."))
                antiDebugPopupOpen_ = true;
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Configure an opt-in, reversible concealment policy for the next debug session.");
            ImGui::Separator();
            if (ImGui::MenuItem("Passive Process Dump..."))
                passiveDumpPopup_.open = true;
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Snapshot an existing process or launch-and-watch without DebugActiveProcess, injection, or target writes.");
            ImGui::Separator();
            const bool canUnpack = ctx_.binaryLaunchable();
            const bool canStaticUnpack = ctx_.staticBinary().loaded() && !ctx_.staticBinary().isMappedImage() &&
                (ctx_.staticBinary().format() == BinFormat::PE32 || ctx_.staticBinary().format() == BinFormat::PE32Plus);
            if (ImGui::MenuItem("Static Packed-PE Recovery...", nullptr, false, canStaticUnpack))
                staticUnpackPopup_.open = true;
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Parse VMProtect-style PACKER_INFO blocks or bounded embedded LZMA streams without executing the target.");
            if (ImGui::MenuItem("Adaptive Unpack...", nullptr, false, canUnpack))
                unpackPopup_.open = true;
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(ctx_.binaryDebugArchitectureMatches()
                    ? "Observe a live PE unpacking stub, score OEP candidates, rebuild imports/sections/metadata, and save a clean disk image."
                    : "Adaptive Unpack requires a matching x86/x64 PE machine and decoder mode (active: %s). Use Static Packed-PE Recovery otherwise.",
                    ArchName(ctx_.staticArch()));
            ImGui::Separator();
            const bool canDebugDll = ctx_.binaryDllDebuggable() &&
                                     (!ctx_.frameDebugSnapshot || !ctx_.frameDebugSnapshot->attached());
            if (ImGui::MenuItem("Debug DLL...", nullptr, false, canDebugDll))
                ctx_.requestedDebugDll = true;
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(ctx_.binaryDebugArchitectureMatches()
                    ? "Choose a callable export and a bitness-compatible DLL host."
                    : "Hosted DLL debugging requires a matching x86/x64 PE machine and decoder mode (active: %s).",
                    ArchName(ctx_.staticArch()));
            ImGui::Separator();
            const DbgSnapshot* historyLive = ctx_.frameDebugSnapshot;
            const bool canRecordPath = historyLive && historyLive->state == DbgState::Paused &&
                !historyLive->cleanupOnly && !ctx_.gmlExecutionMode &&
                !ctx_.debug.lifecycleSnapshot().busy;
            if (ImGui::MenuItem("Record Execution Path", nullptr, false, canRecordPath))
                startExecutionHistory(*historyLive);
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Start before the breakpoint. Single-step the selected native thread, retaining up to 10,000 observed instructions and registers. Slower than Continue; replaces the previous recording.");
            if (ImGui::MenuItem("Step Back in Recorded Path", nullptr, false,
                    !executionHistory_.recording && executionHistoryView_.canStepBack(executionHistory_)))
                executionHistoryView_.stepBack(executionHistory_);
            if (ImGui::MenuItem("Execution History...")) executionHistoryView_.open = true;
            if (ImGui::MenuItem("Backtrace / Call Stack")) {
                ctx_.requestedBacktrace = true;
                ctx_.requestedTab = "Binary View";
            }
            ImGui::Separator();
            const TraceCoverageSnapshot* tr = ctx_.frameTraceCoverageSnapshot;
            const bool traceOn = ctx_.traceSeedPlanning || (tr && tr->active) ||
                (ctx_.frameDebugSnapshot && ctx_.frameDebugSnapshot->traceOwnedSites != 0);
            uint64_t traceRuntimeBase = 0, traceRuntimeSize = 0;
            const bool exactTraceImage = ctx_.frameDebugSnapshot &&
                ctx_.debuggerRuntimeImage(*ctx_.frameDebugSnapshot,
                                          traceRuntimeBase, traceRuntimeSize);
            const bool canStartTrace = ctx_.staticBinary().loaded() &&
                                       ctx_.frameDebugSnapshot &&
                                       ctx_.frameDebugSnapshot->state == DbgState::Paused &&
                                       exactTraceImage;
            if (ImGui::MenuItem(traceOn ? "Stop Trace Coverage" : "Start Trace Coverage",
                                nullptr, traceOn, traceOn || canStartTrace)) {
                ctx_.requestedTraceToggle = true;
                ctx_.requestedTraceTarget = ctx_.frameDebugSnapshot
                    ? DebugTargetIdentity{ctx_.frameDebugSnapshot->pid,
                                          ctx_.frameDebugSnapshot->sessionGeneration}
                    : DebugTargetIdentity{};
                ctx_.requestedTab = "Binary View";
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(exactTraceImage || traceOn
                    ? "Plant one-shot basic-block sites in the background and retain green execution coverage."
                    : "Trace requires the exact matching x86/x64 module and target bitness; no sites are planted for an unrelated or ARM image.");
            const bool haveTrace = tr && (!tr->instructions.empty() || !tr->blocks.empty());
            if (ImGui::MenuItem("Clear Trace Coverage", nullptr, false, haveTrace)) {
                ctx_.requestedTraceClear = true;
                ctx_.requestedTraceClearTarget = ctx_.frameDebugSnapshot
                    ? DebugTargetIdentity{ ctx_.frameDebugSnapshot->pid,
                                           ctx_.frameDebugSnapshot->sessionGeneration }
                    : DebugTargetIdentity{};
                ctx_.requestedTab = "Binary View";
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("Keyboard Shortcuts", "F1")) showHelp_ = true;
            if (ImGui::MenuItem("Command Palette", "Ctrl+K") &&
                ctx_.frameDebugSnapshot)
                openCommandPalette(*ctx_.frameDebugSnapshot);
            ImGui::Separator();
            ImGui::MenuItem("About", nullptr, &showAbout_);
            ImGui::EndMenu();
        }

        const ImVec2 menuPos = ImGui::GetWindowPos();
        const ImVec2 menuSize = ImGui::GetWindowSize();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const float menusEndX = ImGui::GetCursorScreenPos().x;
        HWND mainHwnd = reinterpret_cast<HWND>(
            ImGui::GetMainViewport()->PlatformHandleRaw);
        const float captionW = 34.0f * k;
        const float captionStart = menuPos.x + menuSize.x - (mainHwnd ? captionW * 3.0f : 0.0f);
        const float captionH = (std::max)(1.0f, menuSize.y - 1.0f);
        const bool maximized = mainHwnd && ::IsZoomed(mainHwnd);

        const auto lifecycle = ctx_.debug.lifecycleSnapshot();
        const DbgSnapshot* debug = ctx_.frameDebugSnapshot;
        const char* state = lifecycle.busy
            ? (lifecycle.state == DbgLifecycleState::Stopping ? "STOPPING" : "STARTING")
            : debug && debug->cleanupOnly ? "CLEANUP"
            : debug && debug->state == DbgState::Paused ? "PAUSED"
            : debug && debug->state == DbgState::Running ? "RUNNING"
            : debug && debug->state == DbgState::Terminated ? "EXITED" : "DETACHED";
        const ImVec4 stateColor = lifecycle.busy || (debug && (debug->cleanupOnly || debug->state == DbgState::Paused))
            ? theme::col::warn() : debug && debug->state == DbgState::Running
                ? theme::col::good() : theme::col::secondaryText();
        const float capsuleH = captionH - 8.0f * k;
        const float stateW = ImGui::CalcTextSize(state).x + 32.0f * k;
        const float stateX = captionStart - stateW - 8.0f * k;
        const float documentW = (std::min)(300.0f * k,
            (std::max)(0.0f, stateX - menusEndX - 32.0f * k));
        float dragEnd = stateX - 8.0f * k;
        if (documentW >= 80.0f * k) {
            const float documentX = stateX - documentW - 8.0f * k;
            ImGui::SetCursorScreenPos(ImVec2(documentX, menuPos.y + 4.0f * k));
            renderDocumentStrip(documentW, capsuleH);
            dragEnd = documentX - 8.0f * k;
        }
        if (stateX >= menusEndX + 6.0f * k) {
            const ImVec2 at(stateX, menuPos.y + 4.0f * k);
            ImGui::SetCursorScreenPos(at);
            ImGui::InvisibleButton("##header_debug_state", ImVec2(stateW, capsuleH));
            ImVec4 fill = stateColor; fill.w = 0.10f;
            ImVec4 border = stateColor; border.w = 0.30f;
            dl->AddRectFilled(at, ImVec2(at.x + stateW, at.y + capsuleH), ImGui::GetColorU32(fill), capsuleH * 0.5f);
            dl->AddRect(at, ImVec2(at.x + stateW, at.y + capsuleH), ImGui::GetColorU32(border), capsuleH * 0.5f);
            dl->AddCircleFilled(ImVec2(at.x + 11.0f * k, at.y + capsuleH * 0.5f), 3.0f * k,
                ImGui::GetColorU32(stateColor));
            dl->AddText(ImVec2(at.x + 21.0f * k, at.y + (capsuleH - ImGui::GetTextLineHeight()) * 0.5f),
                ImGui::GetColorU32(stateColor), state);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::TextColored(stateColor, "%s", state);
                if (debug && !debug->lastEvent.empty()) ImGui::TextWrapped("%s", debug->lastEvent.c_str());
                if (!lifecycle.error.empty()) ImGui::TextWrapped("%s", lifecycle.error.c_str());
                ImGui::EndTooltip();
            }
        }
        // Search remains a compact, keyboard-addressable command when the title
        // row has room; Help and Ctrl+K always retain the complete investigation.
        if (dragEnd - menusEndX >= 105.0f * k) {
            const ImVec2 at(menusEndX + 8.0f * k, menuPos.y + 4.0f * k);
            ImGui::SetCursorScreenPos(at);
            if (ImGui::InvisibleButton("##global_search", ImVec2(78.0f * k, capsuleH), ImGuiButtonFlags_EnableNav) && debug)
                openCommandPalette(*debug);
            dl->AddText(ImVec2(at.x + 8.0f * k, at.y + (capsuleH - ImGui::GetTextLineHeight()) * 0.5f),
                ImGui::GetColorU32(theme::col::secondaryText()), "Search");
            ui::ItemTooltip("Search commands, addresses, functions and references (Ctrl+K).");
        }

        enum class CaptionGlyph { Minimize, Maximize, Close };
        auto captionButton = [&](const char* id, float x, CaptionGlyph glyph,
                                 const char* tip) {
            const ImVec2 a(x, menuPos.y);
            const ImVec2 b(x + captionW, menuPos.y + captionH);
            ImGui::SetCursorScreenPos(a);
            const bool clicked = ImGui::InvisibleButton(id, ImVec2(captionW, captionH));
            const bool hovered = ImGui::IsItemHovered();
            const bool held = ImGui::IsItemActive();
            if (hovered || held) {
                ImVec4 fill = glyph == CaptionGlyph::Close
                    ? theme::col::bad() : theme::col::accent();
                fill.w = glyph == CaptionGlyph::Close
                    ? (held ? 0.95f : 0.78f) : (held ? 0.25f : 0.14f);
                dl->AddRectFilled(a, b, ImGui::GetColorU32(fill));
            }

            const ImU32 ink = ImGui::GetColorU32(
                hovered && glyph == CaptionGlyph::Close
                    ? ImVec4(1, 1, 1, 1)
                    : ImGui::GetStyleColorVec4(ImGuiCol_Text));
            const float cx = (a.x + b.x) * 0.5f;
            const float cy = (a.y + b.y) * 0.5f;
            const float half = 6.0f * k;
            if (glyph == CaptionGlyph::Minimize) {
                dl->AddLine(ImVec2(cx - half, cy + 3.0f * k),
                            ImVec2(cx + half, cy + 3.0f * k), ink, 1.2f * k);
            } else if (glyph == CaptionGlyph::Close) {
                dl->AddLine(ImVec2(cx - half, cy - half),
                            ImVec2(cx + half, cy + half), ink, 1.2f * k);
                dl->AddLine(ImVec2(cx + half, cy - half),
                            ImVec2(cx - half, cy + half), ink, 1.2f * k);
            } else if (maximized) {
                dl->AddRect(ImVec2(cx - 4.0f * k, cy - 6.0f * k),
                            ImVec2(cx + 6.0f * k, cy + 4.0f * k), ink,
                            0.0f, 0, 1.1f * k);
                dl->AddRect(ImVec2(cx - 7.0f * k, cy - 3.0f * k),
                            ImVec2(cx + 3.0f * k, cy + 7.0f * k), ink,
                            0.0f, 0, 1.1f * k);
            } else {
                dl->AddRect(ImVec2(cx - half, cy - half),
                            ImVec2(cx + half, cy + half), ink,
                            0.0f, 0, 1.1f * k);
            }
            if (hovered && tip) ImGui::SetTooltip("%s", tip);
            return clicked;
        };

        if (mainHwnd) {
            if (captionButton("##caption_minimize", captionStart,
                              CaptionGlyph::Minimize, "Minimize"))
                ::ShowWindow(mainHwnd, SW_MINIMIZE);
            if (captionButton("##caption_maximize", captionStart + captionW,
                              CaptionGlyph::Maximize,
                              maximized ? "Restore" : "Maximize"))
                ::ShowWindow(mainHwnd, maximized ? SW_RESTORE : SW_MAXIMIZE);
            if (captionButton("##caption_close", captionStart + captionW * 2.0f,
                              CaptionGlyph::Close, "Close"))
                ::PostMessageW(mainHwnd, WM_CLOSE, 0, 0);

            titleDragMinX_ = menusEndX + (dragEnd - menusEndX >= 105.0f * k ? 94.0f : 8.0f) * k;
            titleDragMinY_ = menuPos.y;
            titleDragMaxX_ = dragEnd;
            titleDragMaxY_ = menuPos.y + captionH;
            titleDragRegionValid_ = titleDragMaxX_ > titleDragMinX_;
        }

        dl->AddLine(
            ImVec2(menuPos.x, menuPos.y + menuSize.y - 1.0f),
            ImVec2(menuPos.x + menuSize.x, menuPos.y + menuSize.y - 1.0f),
            ImGui::GetColorU32(theme::col::line()));
        ImGui::EndMainMenuBar();
    }
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
}

bool App::saveStaticUnpackArtifact(int artifactKind, bool loadAfterSave) {
    const StaticUnpackResult& result = staticUnpackPopup_.result;
    const std::vector<uint8_t>* bytes = nullptr;
    const wchar_t* filter = nullptr;
    const wchar_t* extension = nullptr;
    std::string suffix;
    bool loadable = false;
    switch (artifactKind) {
        case 0:
            if (result.diskImageReady && !result.image.empty()) bytes = &result.image;
            if (result.oepTrusted) {
                suffix = staticUnpackPopup_.sourceWasDll ? ".static-unpacked.dll" : ".static-unpacked.exe";
            } else {
                suffix = staticUnpackPopup_.sourceWasDll
                    ? ".static-recovered-analysis.dll" : ".static-recovered-analysis.exe";
            }
            filter = staticUnpackPopup_.sourceWasDll
                ? L"PE dynamic library\0*.dll\0All Files\0*.*\0"
                : L"PE executable\0*.exe\0All Files\0*.*\0";
            extension = staticUnpackPopup_.sourceWasDll ? L"dll" : L"exe";
            loadable = true;
            break;
        case 1:
            if (!result.mappedImage.empty()) bytes = &result.mappedImage;
            suffix = ".static-unpacked-mapped.bin";
            filter = L"Mapped PE image\0*.bin\0All Files\0*.*\0";
            extension = L"bin";
            break;
        default:
            if (!result.rawArtifact.empty()) bytes = &result.rawArtifact;
            suffix = ".static-unpack-raw.bin";
            filter = L"Raw recovery artifact\0*.bin\0All Files\0*.*\0";
            extension = L"bin";
            break;
    }
    if (!bytes) {
        staticUnpackPopup_.error = "That recovery artifact is not available.";
        return false;
    }

    std::string base = staticUnpackPopup_.sourcePath;
    const size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base.erase(0, slash + 1);
    const size_t dot = base.find_last_of('.');
    if (dot != std::string::npos) base.resize(dot);
    if (base.empty()) base = "packed-image";

    const auto document = ctx_.staticDocumentId();
    const auto generation = ctx_.staticImageGeneration();
    const auto revision = ctx_.staticBinary().imageRevision();
    const bool trusted = result.oepTrusted;
    std::string message;
    const bool queued = ctx_.saveBytesFile(base + suffix, *bytes, message, filter, extension,
        [this, document, generation, revision, loadable, loadAfterSave, trusted](const ArtifactWriteResult& saved) {
            if (!saved.success || !saved.warning.empty()) return;
            if (loadable && !trusted) ui::Toast(ui::ToastKind::Warn,
                "Saved reconstructed PE for analysis; its original entry point remains unverified.");
            if (!loadable || !loadAfterSave || ctx_.staticDocumentId() != document || ctx_.staticImageGeneration() != generation ||
                ctx_.staticBinary().imageRevision() != revision || ctx_.binaryLoadPending()) return;
            std::string path;
            if (utf8FromWide(saved.path.c_str(), path) && ctx_.beginBinaryLoadPath(path)) {
                ctx_.requestedTab = "Binary View";
                pendingDocumentLoadOwner_ = PendingDocumentLoadOwner::StaticUnpack;
            } else ui::Toast(ui::ToastKind::Error, "Artifact saved, but its background load could not start.");
        }, ".static-unpack-report.txt", result.report);
    if (!queued && !message.empty()) staticUnpackPopup_.error = message;
    if (queued) ui::Toast(ui::ToastKind::Info, message);
    return queued;
}

void App::renderStaticUnpackPopup() {
    StaticUnpackResult completed;
    if (staticUnpackService_.tryTakeResult(completed)) {
        staticUnpackPopup_.result = std::move(completed);
        if (!staticUnpackPopup_.result.success) {
            staticUnpackPopup_.error = "Static recovery did not produce a complete disk-layout PE; inspect the retained artifacts and evidence below.";
        } else if (staticUnpackPopup_.result.diskImageReady &&
                   !staticUnpackPopup_.result.oepTrusted) {
            staticUnpackPopup_.error = "Sections were recovered and a disk-layout PE was reconstructed, but its entry point is not a verified unpacked OEP. Treat this artifact as analysis-only or provide a validated OEP.";
        } else {
            staticUnpackPopup_.error.clear();
        }
    }
    if (staticUnpackPopup_.open) {
        staticUnpackPopup_.open = false;
        const uint64_t currentHash = ctx_.staticBinary().loaded() ? ctx_.staticBinary().contentHash() : 0;
        if (!staticUnpackService_.pending() && staticUnpackPopup_.sourceHash &&
            (currentHash != staticUnpackPopup_.sourceHash ||
             ctx_.staticBinary().imageRevision() != staticUnpackPopup_.sourceRevision)) {
            staticUnpackPopup_.result = {};
            staticUnpackPopup_.error.clear();
            staticUnpackPopup_.sourcePath.clear();
            staticUnpackPopup_.sourceHash = 0;
            staticUnpackPopup_.sourceRevision = 0;
            staticUnpackPopup_.sourceWasDll = false;
        }
        ImGui::OpenPopup("Static Packed-PE Recovery");
    }

    prepareWorkbenchDialog(860.0f, 730.0f, ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Static Packed-PE Recovery", nullptr,
                                ImGuiWindowFlags_NoSavedSettings)) return;
    if (staticUnpackPopup_.closeAfterDocumentLoad) {
        staticUnpackPopup_.closeAfterDocumentLoad = false;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }

    const bool pending = staticUnpackService_.pending();
    const StaticUnpackProgress progress = staticUnpackService_.progress();
    ImGui::TextWrapped("Recover compressed PE sections without executing the sample. Automatic mode validates VMProtect-style PACKER_INFO descriptors first, then falls back to bounded embedded LZMA-alone recovery. All decode, dictionary, block, and output sizes are capped.");

    ImGui::BeginDisabled(pending);
    const char* strategies[] = {
        "Automatic: PACKER_INFO, then LZMA-alone",
        "VMProtect PACKER_INFO only",
        "Embedded LZMA-alone only"
    };
    ImGui::SetNextItemWidth(340.0f * theme::UiScale());
    ImGui::Combo("Recovery strategy", &staticUnpackPopup_.strategy,
                 strategies, IM_ARRAYSIZE(strategies));
    ImGui::Checkbox("Reconstruct an aligned disk-layout PE", &staticUnpackPopup_.rebuildDiskPe);
    ImGui::InputInt("Maximum decompressed output (MiB)", &staticUnpackPopup_.maxOutputMiB, 64, 256);
    staticUnpackPopup_.maxOutputMiB = std::clamp(staticUnpackPopup_.maxOutputMiB, 16, 512);
    ImGui::InputInt("Maximum LZMA dictionary (MiB)", &staticUnpackPopup_.maxDictionaryMiB, 8, 32);
    staticUnpackPopup_.maxDictionaryMiB = std::clamp(staticUnpackPopup_.maxDictionaryMiB, 1, 64);
    ImGui::SetNextItemWidth(220.0f * theme::UiScale());
    ImGui::InputText("Optional OEP VA", staticUnpackPopup_.oep,
                     sizeof(staticUnpackPopup_.oep), ImGuiInputTextFlags_CharsHexadecimal);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("For a complete nested PE payload, use that payload's own preferred-base VA; the outer packer's base is not reused.");

    const bool hasPendingPatches =
        hasEnabledProjectPatches(ctx_.staticProject());
    const bool sourceReady = ctx_.staticBinary().loaded() && !ctx_.staticBinary().isMappedImage() &&
        !hasPendingPatches &&
        ctx_.staticBinary().bytes().size() <= 512ull * 1024ull * 1024ull &&
        (ctx_.staticBinary().format() == BinFormat::PE32 || ctx_.staticBinary().format() == BinFormat::PE32Plus);
    ImGui::BeginDisabled(!sourceReady);
    if (ImGui::Button("Recover statically", ImVec2(170.0f * theme::UiScale(), 0))) {
        staticUnpackPopup_.error.clear();
        bool optionsValid = true;
        StaticUnpackRequest request;
        // The worker opens and owns the disk input; do not copy a potentially
        // 512-MiB BinaryFile vector on the render thread.
        request.inputPath = ctx_.staticBinary().path();
        request.verifySourceIdentity = true;
        request.expectedSourceSize = ctx_.staticBinary().bytes().size();
        request.expectedSourceHash = ctx_.staticBinary().contentHash();
        request.options.strategy = static_cast<StaticUnpackStrategy>(staticUnpackPopup_.strategy);
        request.options.rebuildDiskPe = staticUnpackPopup_.rebuildDiskPe;
        request.options.maxInputBytes = 512ull * 1024ull * 1024ull;
        request.options.maxOutputBytes = static_cast<size_t>(staticUnpackPopup_.maxOutputMiB) * 1024ull * 1024ull;
        request.options.maxDictionaryBytes = static_cast<size_t>(staticUnpackPopup_.maxDictionaryMiB) * 1024ull * 1024ull;
        request.options.runtimeImageBase = ctx_.staticBinary().imageBase();
        uint64_t oep = 0;
        if (staticUnpackPopup_.oep[0]) {
            if (!parseHexU64(staticUnpackPopup_.oep, oep)) {
                staticUnpackPopup_.error = "The optional OEP must be a hexadecimal virtual address.";
                optionsValid = false;
            } else {
                request.options.hasOep = true;
                request.options.oepVA = oep;
            }
        }
        if (optionsValid) {
            staticUnpackPopup_.result = {};
            staticUnpackPopup_.error.clear();
            staticUnpackPopup_.sourcePath = ctx_.staticBinary().path();
            staticUnpackPopup_.sourceHash = ctx_.staticBinary().contentHash();
            staticUnpackPopup_.sourceRevision = ctx_.staticBinary().imageRevision();
            staticUnpackPopup_.sourceWasDll = ctx_.staticBinary().isDll();
            if (!staticUnpackService_.request(std::move(request)))
                staticUnpackPopup_.error = "The static recovery request was rejected (a job is already active or a safety cap was exceeded).";
        }
    }
    ImGui::EndDisabled();
    ImGui::EndDisabled();
    if (!sourceReady && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        if (hasPendingPatches)
            ImGui::SetTooltip("Static recovery reads an identity-checked disk file. Save the patched binary and reopen it first so in-memory patches cannot be silently ignored.");
        else
            ImGui::SetTooltip("Load a disk-layout PE32 or PE32+ image no larger than 512 MiB first.");
    }

    if (pending) {
        ImGui::SameLine();
        if (ImGui::Button("Cancel static recovery")) staticUnpackService_.cancel();
        ImGui::SeparatorText("Worker progress");
        ImGui::Text("%s | block %u/%u | output %llu bytes",
                    StaticUnpackPhaseName(progress.phase), progress.blockIndex,
                    progress.blockCount, static_cast<unsigned long long>(progress.outputBytes));
        const float fraction = progress.total
            ? std::clamp(static_cast<float>(progress.current) / static_cast<float>(progress.total), 0.0f, 1.0f)
            : 0.0f;
        ImGui::ProgressBar(fraction, ImVec2(-1, 0));
    }

    if (!staticUnpackPopup_.error.empty())
        ImGui::TextColored(theme::col::warn(), "%s", staticUnpackPopup_.error.c_str());

    const StaticUnpackResult& result = staticUnpackPopup_.result;
    if (!result.report.empty() || !result.blocks.empty()) {
        ImGui::SeparatorText("Recovery result");
        const ImVec4 resultColor = result.success &&
                                   (!result.diskImageReady || result.oepTrusted)
                                       ? theme::col::good()
                                       : (result.success || result.decoded)
                                           ? theme::col::warn()
                                           : theme::col::bad();
        ImGui::TextColored(resultColor, "%s | confidence %.0f%% | %zu block(s)",
                           StaticUnpackStrategyName(result.strategy), result.confidence * 100.0f,
                           result.blocks.size());
        ImGui::Text("Descriptor file offset 0x%llX | mapped %zu bytes | disk artifact %zu bytes",
                    static_cast<unsigned long long>(result.probe.packerInfoOffset),
                    result.mappedImage.size(), result.image.size());
        if (result.diskImageReady) {
            ImGui::TextColored(result.oepTrusted ? theme::col::good() : theme::col::warn(),
                               "Entry RVA 0x%08X | OEP %s", result.entryRVA,
                               result.oepTrusted ? "validated" : "UNVERIFIED");
            if (!result.oepAssessment.empty())
                ImGui::TextWrapped("%s", result.oepAssessment.c_str());
        }

        if (!result.blocks.empty() && ImGui::BeginTable("##static_blocks", 8,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                ImVec2(0, 150.0f * theme::UiScale()))) {
            ImGui::TableSetupColumn("#");
            ImGui::TableSetupColumn("Source RVA");
            ImGui::TableSetupColumn("Destination RVA");
            ImGui::TableSetupColumn("Packed");
            ImGui::TableSetupColumn("Output");
            ImGui::TableSetupColumn("Codec");
            ImGui::TableSetupColumn("Confidence");
            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (size_t i = 0; i < result.blocks.size(); ++i) {
                const StaticUnpackBlock& block = result.blocks[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%zu", i + 1);
                ImGui::TableSetColumnIndex(1); ImGui::Text("%08X", block.sourceRVA);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%08X", block.destinationRVA);
                ImGui::TableSetColumnIndex(3); ImGui::Text("%llu", static_cast<unsigned long long>(block.compressedSize));
                ImGui::TableSetColumnIndex(4); ImGui::Text("%llu", static_cast<unsigned long long>(block.outputSize));
                ImGui::TableSetColumnIndex(5); ImGui::TextUnformatted(StaticUnpackCodecName(block.codec));
                ImGui::TableSetColumnIndex(6); ImGui::Text("%.0f%%", block.confidence * 100.0f);
                ImGui::TableSetColumnIndex(7); ImGui::TextUnformatted(block.status.c_str());
                if (ImGui::IsItemHovered() && !block.evidence.empty())
                    ImGui::SetTooltip("%s", block.evidence.c_str());
            }
            ImGui::EndTable();
        }

        if (ImGui::BeginChild("##static_evidence", ImVec2(0, 125.0f * theme::UiScale()),
                              ImGuiChildFlags_Borders)) {
            for (const StaticUnpackEvidence& evidence : result.probe.evidence)
                ImGui::BulletText("[%3.0f%%] %s: %s (file +0x%llX)", evidence.confidence * 100.0f,
                                  evidence.code.c_str(), evidence.detail.c_str(),
                                  static_cast<unsigned long long>(evidence.fileOffset));
            for (const StaticUnpackIssue& issue : result.issues) {
                const ImVec4 color = issue.severity == StaticUnpackSeverity::Error ? theme::col::bad() :
                                     issue.severity == StaticUnpackSeverity::Warning ? theme::col::warn() :
                                     theme::col::muted();
                ImGui::TextColored(color, "%s: %s", issue.code.c_str(), issue.message.c_str());
            }
        }
        ImGui::EndChild();

        if (result.diskImageReady && !result.image.empty()) {
            ImGui::Checkbox("Load saved PE into analysis", &staticUnpackPopup_.loadAfterSave);
            const char* saveLabel = result.oepTrusted
                ? "Save runnable reconstructed PE + report"
                : "Save analysis PE (OEP unverified) + report";
            if (ImGui::Button(saveLabel))
                saveStaticUnpackArtifact(0, staticUnpackPopup_.loadAfterSave);
            ImGui::SameLine();
        }
        if (!result.mappedImage.empty()) {
            if (ImGui::Button("Save mapped image + report")) saveStaticUnpackArtifact(1, false);
            ImGui::SameLine();
        }
        if (!result.rawArtifact.empty() && ImGui::Button("Save raw artifact + report"))
            saveStaticUnpackArtifact(2, false);

        if (ImGui::CollapsingHeader("Full static-unpack report")) {
            ImGui::BeginChild("##static_report", ImVec2(0, 150.0f * theme::UiScale()), ImGuiChildFlags_Borders);
            ImGui::TextUnformatted(result.report.c_str());
            ImGui::EndChild();
        }
    }

    ImGui::Separator();
    ImGui::BeginDisabled(pending);
    if (ImGui::Button("Close")) {
        staticUnpackPopup_.result = {};
        staticUnpackPopup_.error.clear();
        staticUnpackPopup_.sourcePath.clear();
        staticUnpackPopup_.sourceHash = 0;
        staticUnpackPopup_.sourceRevision = 0;
        staticUnpackPopup_.sourceWasDll = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndDisabled();
    ImGui::EndPopup();
}

void App::renderAntiDebugPopup() {
    if (antiDebugPopupOpen_) {
        antiDebugPopupOpen_ = false;
        antiDebugDraft_ = ctx_.debug.antiDebugPolicy();
        antiDebugError_.clear();
        ImGui::OpenPopup("Hide Debugger / Anti-Anti-Debug");
    }
    prepareWorkbenchDialog(760.0f, 660.0f, ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Hide Debugger / Anti-Anti-Debug", nullptr,
                                ImGuiWindowFlags_NoSavedSettings)) return;

    const DbgSnapshot snap = ctx_.debug.snapshot();
    const bool attached = snap.attached();
    ImGui::TextWrapped("This session policy conceals common debugger observations while preserving DisasmStudio's own breakpoints. Every option is off by default. Detach attempts a conditional, best-effort restore; target-modified fields or code are not overwritten.");
    if (attached)
        ImGui::TextColored(theme::col::warn(),
                           "Policy is session-atomic. Detach before changing it; live statistics remain visible below.");

    ImGui::BeginDisabled(attached);
    if (ImGui::Button("Recommended coverage")) {
        antiDebugDraft_.normalizePeb = true;
        antiDebugDraft_.normalizeProcessHeap = true;
        antiDebugDraft_.hideProcessDebugQueries = true;
        antiDebugDraft_.hideKernelDebuggerQuery = true;
        antiDebugDraft_.acceptThreadHideRequests = true;
        antiDebugDraft_.neutralizeInvalidHandleClose = true;
        antiDebugDraft_.maskDebugRegisters = true;
        antiDebugDraft_.syntheticClock = true;
        // Software RDTSC traps necessarily patch target code and cannot offer
        // the Hv backend's transparent coverage. Keep them explicit opt-in.
        antiDebugDraft_.rdtsc = RdtscInterception::Off;
    }
    ImGui::SameLine();
    if (ImGui::Button("Disable all")) antiDebugDraft_ = {};

    ImGui::SeparatorText("Environment normalization");
    ImGui::Checkbox("Normalize PEB BeingDebugged and NtGlobalFlag", &antiDebugDraft_.normalizePeb);
    ImGui::Checkbox("Normalize validated process-heap debug flags", &antiDebugDraft_.normalizeProcessHeap);

    ImGui::SeparatorText("Native query mediation");
    ImGui::Checkbox("Hide process debug port/object/flags queries", &antiDebugDraft_.hideProcessDebugQueries);
    ImGui::Checkbox("Hide kernel-debugger system query", &antiDebugDraft_.hideKernelDebuggerQuery);
    ImGui::Checkbox("Accept ThreadHideFromDebugger without losing control", &antiDebugDraft_.acceptThreadHideRequests);
    ImGui::Checkbox("Neutralize invalid-handle close probes", &antiDebugDraft_.neutralizeInvalidHandleClose);
    ImGui::Checkbox("Mask target-visible DR0-DR7 context queries", &antiDebugDraft_.maskDebugRegisters);

    ImGui::SeparatorText("Time virtualization");
    ImGui::Checkbox("Synthetic monotonic QPC and system time", &antiDebugDraft_.syntheticClock);
    int rdtsc = static_cast<int>(antiDebugDraft_.rdtsc);
    const char* rdtscModes[] = { "Off", "Main executable", "All executable images" };
    ImGui::SetNextItemWidth(230.0f * theme::UiScale());
    if (ImGui::Combo("RDTSC / RDTSCP interception", &rdtsc, rdtscModes, IM_ARRAYSIZE(rdtscModes)))
        antiDebugDraft_.rdtsc = static_cast<RdtscInterception>(rdtsc);
    if (antiDebugDraft_.rdtsc != RdtscInterception::Off)
        ImGui::TextColored(theme::col::warn(),
                           "Software timing traps patch only statically proven reachable sites; generated/self-modifying code is not covered.");
    ImGui::EndDisabled();

    const AntiDebugCapabilityReport capabilities = BuildAntiDebugCapabilityReport(antiDebugDraft_);
    if (ImGui::BeginChild("##anti_debug_capabilities", ImVec2(0, 150.0f * theme::UiScale()),
                          ImGuiChildFlags_Borders)) {
        ImGui::TextColored(theme::col::good(), "Win32 debugger coverage");
        for (const std::string& line : capabilities.userModeCoverage)
            ImGui::BulletText("%s", line.c_str());
        if (!capabilities.beyondUserMode.empty()) {
            ImGui::TextColored(theme::col::warn(), "Not achievable from user mode (out of scope)");
            for (const std::string& line : capabilities.beyondUserMode)
                ImGui::BulletText("%s", line.c_str());
        }
    }
    ImGui::EndChild();

    const AntiDebugSessionStats& s = snap.antiDebug;
    if (s.active || s.policy.enabled()) {
        ImGui::Text("%s: %llu field(s) normalized, %llu query call(s), %llu clock call(s), %llu RDTSC/RDTSCP instruction(s)",
                    attached && s.active ? "Live" : "Last session",
                    static_cast<unsigned long long>(s.memoryFieldsNormalized),
                    static_cast<unsigned long long>(s.queryCallsConcealed + s.contextCallsMediated),
                    static_cast<unsigned long long>(s.clockCallsSynthesized),
                    static_cast<unsigned long long>(s.rdtscInstructionsEmulated));
        if (s.memoryFieldsRestored || s.memoryFieldNormalizeFailures ||
            s.memoryFieldRestoreFailures || s.antiTrapRestoreFailures) {
            ImGui::TextDisabled("Environment: %llu field(s) restored; normalize/field-restore/trap-restore failures %llu/%llu/%llu.",
                static_cast<unsigned long long>(s.memoryFieldsRestored),
                static_cast<unsigned long long>(s.memoryFieldNormalizeFailures),
                static_cast<unsigned long long>(s.memoryFieldRestoreFailures),
                static_cast<unsigned long long>(s.antiTrapRestoreFailures));
        }
        if (s.rdtscDiscoveryBudgetTotal) {
            ImGui::TextDisabled("RDTSC discovery: %llu instruction(s), %llu/%llu budget remaining, %llu image(s) capped%s",
                static_cast<unsigned long long>(s.rdtscDiscoveryInstructions),
                static_cast<unsigned long long>(s.rdtscDiscoveryBudgetRemaining),
                static_cast<unsigned long long>(s.rdtscDiscoveryBudgetTotal),
                static_cast<unsigned long long>(s.rdtscDiscoveryImagesCapped),
                s.rdtscDiscoveryBudgetExhausted ? " (session exhausted)" : "");
        }
        if (s.clockRunIntervals) {
            const double resumedSeconds = s.clockQpcFrequency
                ? static_cast<double>(s.clockRunningQpcTicks) /
                    static_cast<double>(s.clockQpcFrequency)
                : 0.0;
            ImGui::TextDisabled("Synthetic time advanced %.3f s across %llu resumed run interval(s); debugger-paused time excluded%s.",
                                resumedSeconds,
                                static_cast<unsigned long long>(s.clockRunIntervals),
                                s.clockRunIntervalsClamped ? " (one or more intervals safety-clamped)" : "");
        }
        for (const std::string& warning : s.warnings)
            ImGui::TextColored(theme::col::warn(), "%s", warning.c_str());
        if (s.warningsDropped || s.warningsDeduplicated)
            ImGui::TextDisabled("Anti-debug warnings bounded: %llu dropped, %llu duplicate occurrence(s) suppressed.",
                                static_cast<unsigned long long>(s.warningsDropped),
                                static_cast<unsigned long long>(s.warningsDeduplicated));
    }
    if (!antiDebugError_.empty())
        ImGui::TextColored(theme::col::bad(), "%s", antiDebugError_.c_str());

    ImGui::BeginDisabled(attached);
    if (ImGui::Button("Apply for next session", ImVec2(180.0f * theme::UiScale(), 0))) {
        std::string error;
        if (ctx_.debug.setAntiDebugPolicy(antiDebugDraft_, &error)) {
            ui::Toast(ui::ToastKind::Success,
                      antiDebugDraft_.enabled() ? "Debugger concealment policy armed for the next session."
                                                : "Debugger concealment disabled.");
            ImGui::CloseCurrentPopup();
        } else antiDebugError_ = error;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void App::browsePassiveExecutable() {
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFilter = L"Windows executables\0*.exe\0All Files\0*.*\0";
    ofn.lpstrFile = file.data();
    ofn.nMaxFile = static_cast<DWORD>(file.size());
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    std::string path;
    if (!utf8FromWide(file.data(), path)) {
        passiveDumpPopup_.error = "Could not encode the selected launch path as UTF-8.";
        return;
    }
    strncpy_s(passiveDumpPopup_.launchPath, path.c_str(), _TRUNCATE);
    const size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        const std::string directory = path.substr(0, slash);
        strncpy_s(passiveDumpPopup_.workingDirectory, directory.c_str(), _TRUNCATE);
    }
}

bool App::savePassiveDumpArtifacts(bool loadAfterSave) {
    const bool rebuilt = passiveDumpPopup_.result.rebuilt.success &&
                         !passiveDumpPopup_.result.rebuilt.image.empty();
    const bool manualOepValidated = rebuilt &&
        passiveDumpPopup_.result.oep.trust == PassiveOepTrust::ManualOepValidated;
    const bool runnable = rebuilt &&
        passiveDumpPopup_.result.artifactAssessment == PassiveArtifactAssessment::RebuiltRunnable;
    const std::vector<uint8_t>& bytes = rebuilt ? passiveDumpPopup_.result.rebuilt.image
                                                : passiveDumpPopup_.result.capture.bytes;
    if (bytes.empty()) {
        passiveDumpPopup_.error = "There is no captured image to save.";
        return false;
    }
    std::string baseName;
    utf8FromWide(passiveDumpPopup_.result.module.name.c_str(), baseName);
    if (baseName.empty()) baseName = "process";
    const size_t dot = baseName.find_last_of('.');
    if (dot != std::string::npos) baseName.resize(dot);
    baseName += rebuilt
        ? (runnable ? ".passive-unpacked.exe" : ".passive-recovered-analysis.exe")
        : ".passive-capture.bin";

    const auto document = ctx_.staticDocumentId();
    const auto generation = ctx_.staticImageGeneration();
    const auto revision = ctx_.staticBinary().imageRevision();
    // Capture whether this request owns a launch; completion must not terminate
    // a later launch that happened to reuse the same popup.
    const auto capturedPid = passiveDumpPopup_.result.pid;
    const auto capturedGeneration = passiveResultGeneration_;
    std::string message;
    const bool queued = ctx_.saveBytesFile(baseName, bytes, message,
        rebuilt ? L"PE executable\0*.exe\0All Files\0*.*\0"
                : L"Mapped process capture\0*.bin\0All Files\0*.*\0",
        rebuilt ? L"exe" : L"bin",
        [this, document, generation, revision, capturedPid, capturedGeneration, rebuilt, runnable, manualOepValidated, loadAfterSave]
        (const ArtifactWriteResult& saved) {
            if (!saved.success || !saved.warning.empty()) return;
            if (rebuilt && !runnable) ui::Toast(ui::ToastKind::Warn, manualOepValidated
                ? "Saved reconstructed PE for analysis; disk-backfilled bytes prevent runnable classification."
                : "Saved reconstructed PE for analysis; its original entry point remains unverified.");
            if (!rebuilt || !loadAfterSave || ctx_.staticDocumentId() != document || ctx_.staticImageGeneration() != generation ||
                ctx_.staticBinary().imageRevision() != revision || ctx_.binaryLoadPending()) return;
            std::string path;
            if (utf8FromWide(saved.path.c_str(), path) && ctx_.beginBinaryLoadPath(path)) {
                if (!passiveDumpService_.busy() && passiveResultGeneration_ == capturedGeneration &&
                    passiveDumpPopup_.result.pid == capturedPid &&
                    passiveDumpPopup_.result.launched && passiveDumpPopup_.result.launchContained) {
                    passiveDumpService_.terminateContainedLaunch();
                    passiveDumpPopup_.result.launchContained = false;
                }
                ctx_.requestedTab = "Binary View";
                pendingDocumentLoadOwner_ = PendingDocumentLoadOwner::PassiveDump;
            } else ui::Toast(ui::ToastKind::Error, "Artifact saved, but its background load could not start.");
        }, ".passive-report.txt", passiveDumpPopup_.result.report);
    if (!queued && !message.empty()) passiveDumpPopup_.error = message;
    if (queued) ui::Toast(ui::ToastKind::Info, message);
    return queued;
}

void App::renderPassiveDumpPopup() {
    if (ctx_.requestedPassiveDump) {
        passiveDumpPopup_.selectedPid = ctx_.requestedPassiveDumpPid;
        passiveDumpPopup_.open = true;
        ctx_.requestedPassiveDump = false;
        ctx_.requestedPassiveDumpPid = 0;
    }
    PassiveDumpResult completed;
    if (passiveDumpService_.tryTakeResult(completed)) {
        passiveDumpPopup_.result = std::move(completed);
        ++passiveResultGeneration_;
        passiveDumpPopup_.error = passiveDumpPopup_.result.error;
    }
    if (passiveDumpPopup_.open) {
        passiveDumpPopup_.open = false;
        if (!passiveDumpService_.busy()) {
            const uint32_t requestedPid = passiveDumpPopup_.selectedPid;
            passiveDumpPopup_.result = {};
            passiveDumpPopup_.error.clear();
            passiveDumpPopup_.processes = EnumeratePassiveProcesses();
            passiveDumpPopup_.selectedPid = requestedPid;
            passiveDumpPopup_.launchMode = false;
            passiveDumpPopup_.suspendFinal = true;
            passiveDumpPopup_.rebuildImports = true;
            passiveDumpPopup_.normalizeRelocations = true;
            passiveDumpPopup_.loadAfterSave = true;
            passiveDumpPopup_.timing = static_cast<int>(PassiveTiming::AutoSettle);
            passiveDumpPopup_.sampleIntervalMs = 250;
            passiveDumpPopup_.maxWatchMs = 60000;
            passiveDumpPopup_.stableSamples = 4;
            passiveDumpPopup_.manualOep[0] = '\0';
            if (passiveDumpPopup_.launchPath[0] == '\0' && ctx_.binaryLaunchable()) {
                strncpy_s(passiveDumpPopup_.launchPath, ctx_.staticBinary().path().c_str(), _TRUNCATE);
                const size_t slash = ctx_.staticBinary().path().find_last_of("/\\");
                if (slash != std::string::npos) {
                    const std::string directory = ctx_.staticBinary().path().substr(0, slash);
                    strncpy_s(passiveDumpPopup_.workingDirectory, directory.c_str(), _TRUNCATE);
                }
            }
        }
        ImGui::OpenPopup("Passive Process Dump");
    }

    prepareWorkbenchDialog(820.0f, 720.0f, ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Passive Process Dump", nullptr,
                                ImGuiWindowFlags_NoSavedSettings)) return;
    if (passiveDumpPopup_.closeAfterDocumentLoad) {
        passiveDumpPopup_.closeAfterDocumentLoad = false;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    const bool busy = passiveDumpService_.busy();
    const PassiveDumpProgress progress = passiveDumpService_.progress();

    ImGui::TextWrapped("Capture an existing process using query/read handles only, or launch normally without DEBUG flags and watch memory until writes and entropy settle. No code is injected and no target bytes are patched.");
    ImGui::BeginDisabled(busy);
    if (ImGui::RadioButton("Existing process", !passiveDumpPopup_.launchMode))
        passiveDumpPopup_.launchMode = false;
    ImGui::SameLine();
    if (ImGui::RadioButton("Launch and watch", passiveDumpPopup_.launchMode))
        passiveDumpPopup_.launchMode = true;

    if (!passiveDumpPopup_.launchMode) {
        if (ImGui::Button("Refresh processes"))
            passiveDumpPopup_.processes = EnumeratePassiveProcesses();
        ImGui::SameLine();
        ui::SearchBox("##passive_filter", "filter process...", passiveDumpPopup_.processFilter,
                      sizeof(passiveDumpPopup_.processFilter), 240.0f * theme::UiScale());
        if (ImGui::BeginChild("##passive_processes", ImVec2(0, 155.0f * theme::UiScale()),
                              ImGuiChildFlags_Borders)) {
            std::string filter = passiveDumpPopup_.processFilter;
            std::transform(filter.begin(), filter.end(), filter.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            for (const PassiveProcessInfo& process : passiveDumpPopup_.processes) {
                std::string name, path;
                utf8FromWide(process.imageName.c_str(), name);
                utf8FromWide(process.imagePath.c_str(), path);
                std::string hay = name + " " + path;
                std::transform(hay.begin(), hay.end(), hay.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (!filter.empty() && hay.find(filter) == std::string::npos) continue;
                char label[512];
                std::snprintf(label, sizeof(label), "%s  (PID %u)##passive%u",
                              name.empty() ? "<unknown>" : name.c_str(), process.pid, process.pid);
                if (ImGui::Selectable(label, passiveDumpPopup_.selectedPid == process.pid))
                    passiveDumpPopup_.selectedPid = process.pid;
                if (ImGui::IsItemHovered() && !path.empty()) ImGui::SetTooltip("%s", path.c_str());
            }
        }
        ImGui::EndChild();
    } else {
        ImGui::SetNextItemWidth(-125.0f * theme::UiScale());
        ImGui::InputText("Executable", passiveDumpPopup_.launchPath,
                         sizeof(passiveDumpPopup_.launchPath));
        ImGui::SameLine();
        if (ImGui::Button("Browse...")) browsePassiveExecutable();
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("Arguments", passiveDumpPopup_.launchArguments,
                         sizeof(passiveDumpPopup_.launchArguments));
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Optional Windows command tail. Quotes and backslashes follow CommandLineToArgvW rules; Core re-quotes every parsed argument safely.");
        ImGui::SetNextItemWidth(-145.0f * theme::UiScale());
        ImGui::InputText("Working directory", passiveDumpPopup_.workingDirectory,
                         sizeof(passiveDumpPopup_.workingDirectory));
        ImGui::SameLine();
        if (ImGui::Button("Use exe folder")) {
            const std::string executable = passiveDumpPopup_.launchPath;
            const size_t slash = executable.find_last_of("/\\");
            if (slash != std::string::npos) {
                const std::string directory = executable.substr(0, slash);
                strncpy_s(passiveDumpPopup_.workingDirectory, directory.c_str(), _TRUNCATE);
            }
        }
        ImGui::TextWrapped("Fresh launches are always assigned to a one-process kill-on-close Job while CREATE_SUSPENDED, then resumed. If containment setup fails, the process is terminated before its first instruction. This does not virtualize filesystem or network access.");
    }

    const char* timingModes[] = { "Immediate snapshot", "Manual capture", "Automatic settle" };
    ImGui::SetNextItemWidth(220.0f * theme::UiScale());
    ImGui::Combo("Capture timing", &passiveDumpPopup_.timing, timingModes, IM_ARRAYSIZE(timingModes));
    ImGui::InputInt("Sample interval (ms)", &passiveDumpPopup_.sampleIntervalMs, 50, 250);
    passiveDumpPopup_.sampleIntervalMs = std::clamp(passiveDumpPopup_.sampleIntervalMs, 100, 5000);
    if (passiveDumpPopup_.timing == static_cast<int>(PassiveTiming::AutoSettle)) {
        ImGui::InputInt("Maximum watch time (ms)", &passiveDumpPopup_.maxWatchMs, 1000, 5000);
        passiveDumpPopup_.maxWatchMs = std::clamp(passiveDumpPopup_.maxWatchMs, 1000, 10 * 60 * 1000);
        ImGui::InputInt("Stable samples required", &passiveDumpPopup_.stableSamples, 1, 2);
        passiveDumpPopup_.stableSamples = std::clamp(passiveDumpPopup_.stableSamples, 2, 32);
    }
    ImGui::Checkbox("Briefly suspend for the final coherent capture", &passiveDumpPopup_.suspendFinal);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Uses dynamically resolved NtSuspendProcess/NtResumeProcess only around final capture; failure falls back to read-only live capture.");
    ImGui::Checkbox("Match exact loaded exports and rebuild imports", &passiveDumpPopup_.rebuildImports);
    ImGui::Checkbox("Normalize relocations when transactionally safe", &passiveDumpPopup_.normalizeRelocations);
    ImGui::SetNextItemWidth(200.0f * theme::UiScale());
    ImGui::InputText("Optional OEP VA", passiveDumpPopup_.manualOep,
                     sizeof(passiveDumpPopup_.manualOep), ImGuiInputTextFlags_CharsHexadecimal);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Only a supplied VA validated against an exactly captured executable page is trusted; runnable output additionally requires zero disk-backfilled pages. The original header entry remains analysis-only.");
    ImGui::EndDisabled();

    if (!busy) {
        const bool selectedAttached = !passiveDumpPopup_.launchMode &&
            ctx_.frameDebugSnapshot && ctx_.frameDebugSnapshot->attached() &&
            ctx_.frameDebugSnapshot->pid == passiveDumpPopup_.selectedPid;
        const bool sourceReady = passiveDumpPopup_.launchMode
            ? passiveDumpPopup_.launchPath[0] != '\0'
            : passiveDumpPopup_.selectedPid != 0 && !selectedAttached;
        if (selectedAttached)
            ImGui::TextColored(theme::col::warn(),
                               "Detach this PID first; a passive read cannot safely remove debugger-owned int3 bytes.");
        ImGui::BeginDisabled(!sourceReady);
        if (ImGui::Button("Start passive capture", ImVec2(180.0f * theme::UiScale(), 0))) {
            PassiveDumpRequest request;
            request.pid = passiveDumpPopup_.launchMode ? 0 : passiveDumpPopup_.selectedPid;
            bool sourceValid = true;
            if (passiveDumpPopup_.launchMode) {
                if (!wideFromUtf8(passiveDumpPopup_.launchPath, request.executable)) {
                    passiveDumpPopup_.error = "The executable path is not valid UTF-8.";
                    sourceValid = false;
                }
                std::vector<std::string> parsedArguments;
                std::string argumentError;
                if (sourceValid && !splitWindowsUserArguments(
                        passiveDumpPopup_.launchArguments, parsedArguments, argumentError)) {
                    passiveDumpPopup_.error = argumentError;
                    sourceValid = false;
                }
                if (sourceValid && parsedArguments.size() > 256) {
                    passiveDumpPopup_.error = "The launch command contains more than 256 arguments.";
                    sourceValid = false;
                }
                if (sourceValid) {
                    request.arguments.reserve(parsedArguments.size());
                    for (const std::string& argument : parsedArguments) {
                        std::wstring wide;
                        if (!wideFromUtf8(argument, wide)) {
                            passiveDumpPopup_.error = "A parsed launch argument is not valid UTF-8.";
                            sourceValid = false;
                            break;
                        }
                        request.arguments.push_back(std::move(wide));
                    }
                }
                if (sourceValid && passiveDumpPopup_.workingDirectory[0]) {
                    if (!wideFromUtf8(passiveDumpPopup_.workingDirectory,
                                      request.workingDirectory)) {
                        passiveDumpPopup_.error = "The working directory is not valid UTF-8.";
                        sourceValid = false;
                    } else {
                        const DWORD attrs = GetFileAttributesW(request.workingDirectory.c_str());
                        if (attrs == INVALID_FILE_ATTRIBUTES ||
                            !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                            passiveDumpPopup_.error = "The working directory does not exist or is not a directory.";
                            sourceValid = false;
                        }
                    }
                }
            }
            if (sourceValid) {
                request.timing = static_cast<PassiveTiming>(passiveDumpPopup_.timing);
                request.sampleIntervalMs = static_cast<uint32_t>(passiveDumpPopup_.sampleIntervalMs);
                request.settle.maxWatchMs = static_cast<uint64_t>(passiveDumpPopup_.maxWatchMs);
                request.settle.stableSamplesRequired = static_cast<uint32_t>(passiveDumpPopup_.stableSamples);
                request.suspendDuringFinalCapture = passiveDumpPopup_.suspendFinal;
                request.observeExactExportImports = passiveDumpPopup_.rebuildImports;
                request.normalizeRelocations = passiveDumpPopup_.normalizeRelocations;
                // A launch created by this modal is our owned, contained analysis
                // target. Cancelling the observation should not strand it running
                // invisibly after the result has no artifact/stop controls.
                request.terminateLaunchedOnCancel = passiveDumpPopup_.launchMode;
                bool optionsValid = true;
                uint64_t oep = 0;
                if (passiveDumpPopup_.manualOep[0]) {
                    if (!parseHexU64(passiveDumpPopup_.manualOep, oep)) {
                        passiveDumpPopup_.error =
                            "The optional OEP must be a complete hexadecimal virtual address.";
                        optionsValid = false;
                    } else {
                        request.hasManualOep = true;
                        request.manualOepVA = oep;
                    }
                }
                if (optionsValid) {
                    std::string error;
                    passiveDumpPopup_.result = {};
                    passiveDumpPopup_.error.clear();
                    if (!passiveDumpService_.start(std::move(request), &error))
                        passiveDumpPopup_.error = error;
                }
            }
        }
        ImGui::EndDisabled();
    } else {
        ImGui::SeparatorText("Capture progress");
        ImGui::Text("%s", progress.status.c_str());
        const float fraction = passiveDumpPopup_.maxWatchMs > 0
            ? std::clamp(static_cast<float>(progress.elapsedMs) /
                         static_cast<float>(passiveDumpPopup_.maxWatchMs), 0.0f, 1.0f) : 0.0f;
        ImGui::ProgressBar(fraction, ImVec2(-1, 0));
        ImGui::Text("PID %u | samples %u | stable %u | readable %u/%u pages | changed %.3f%% | entropy %.3f",
                    progress.pid, progress.samples, progress.stableSamples,
                    progress.readablePages, progress.totalPages,
                    progress.changedPageRatio * 100.0, progress.entropy);
        if (passiveDumpPopup_.timing == static_cast<int>(PassiveTiming::Manual) &&
            progress.phase == PassiveDumpPhase::Watching) {
            if (ImGui::Button("Capture now")) passiveDumpService_.requestCapture();
            ImGui::SameLine();
        }
        if (ImGui::Button("Cancel")) passiveDumpService_.cancel();
    }

    if (!passiveDumpPopup_.error.empty())
        ImGui::TextColored(theme::col::bad(), "%s", passiveDumpPopup_.error.c_str());
    if (!passiveDumpPopup_.result.capture.bytes.empty()) {
        ImGui::SeparatorText("Result");
        const PassiveDumpResult& result = passiveDumpPopup_.result;
        const bool rebuilt = result.rebuilt.success && !result.rebuilt.image.empty();
        const bool manualOepValidated = rebuilt &&
            result.oep.trust == PassiveOepTrust::ManualOepValidated;
        const bool runnable = rebuilt &&
            result.artifactAssessment == PassiveArtifactAssessment::RebuiltRunnable;
        const char* outcome = !rebuilt ? "Raw mapped capture retained"
                            : runnable ? "Runnable reconstructed PE (manual OEP validated)"
                            : manualOepValidated
                                ? "Reconstructed analysis PE (manual OEP validated; disk backfill used)"
                                : "Reconstructed analysis PE (OEP unverified)";
        ImGui::TextColored(runnable ? theme::col::good() : theme::col::warn(), "%s", outcome);
        ImGui::Text("PID %u | image 0x%llX + 0x%llX | readable/unreadable pages %u/%u | imports observed %zu",
                    result.pid, static_cast<unsigned long long>(result.module.base),
                    static_cast<unsigned long long>(result.module.size),
                    result.capture.readablePages, result.capture.unreadablePages,
                    result.observedImports.size());
        if (result.importObservationRequested) {
            ImGui::TextColored(result.importObservationCoherent ? theme::col::good()
                                                                : theme::col::warn(),
                               "Import snapshot: %s",
                               result.importObservationCoherent
                                   ? "remote exports captured in the final suspension window"
                                   : "best-effort live metadata (target was not suspended)");
        }
        if (result.memory.estimatedPeakBytes) {
            ImGui::TextDisabled("Admitted peak estimate %.1f MiB / %.1f MiB budget",
                static_cast<double>(result.memory.estimatedPeakBytes) / (1024.0 * 1024.0),
                static_cast<double>(result.memory.budgetBytes) / (1024.0 * 1024.0));
        }
        if (rebuilt) {
            ImGui::TextColored(manualOepValidated ? theme::col::good() : theme::col::warn(),
                               "Entry RVA 0x%08X | OEP %s", result.oep.entryRVA,
                               manualOepValidated ? "validated" : "UNVERIFIED");
            if (manualOepValidated && !runnable)
                ImGui::TextWrapped("The manual OEP remains validated, but identity-checked disk backfill was used for missing discardable pages, so this artifact is analysis-only.");
            else if (!manualOepValidated)
                ImGui::TextWrapped("The unchanged PE-header entry may still be a loader/protector stub. Supply a validated OEP to produce output labelled runnable.");
        }
        for (const std::string& warning : result.warnings)
            ImGui::TextColored(theme::col::warn(), "%s", warning.c_str());
        for (const PeUnpackIssue& issue : result.rebuilt.issues) {
            const ImVec4 col = issue.severity == PeUnpackSeverity::Error ? theme::col::bad() :
                               issue.severity == PeUnpackSeverity::Warning ? theme::col::warn() :
                               theme::col::muted();
            ImGui::TextColored(col, "%s: %s", issue.code.c_str(), issue.message.c_str());
        }
        if (rebuilt)
            ImGui::Checkbox("Load saved PE into analysis", &passiveDumpPopup_.loadAfterSave);
        const char* saveLabel = !rebuilt ? "Save raw capture + report"
                              : runnable ? "Save runnable reconstructed PE + report"
                              : manualOepValidated
                                  ? "Save analysis PE (disk backfill) + report"
                                  : "Save analysis PE (OEP unverified) + report";
        if (ImGui::Button(saveLabel))
            savePassiveDumpArtifacts(passiveDumpPopup_.loadAfterSave);
        if (result.launched && result.launchContained) {
            ImGui::SameLine();
            if (ImGui::Button("Terminate contained launch")) {
                passiveDumpService_.terminateContainedLaunch();
                passiveDumpPopup_.result.launchContained = false;
                ui::Toast(ui::ToastKind::Info, "Contained launch terminated.");
            }
        }
    }
    ImGui::Separator();
    ImGui::BeginDisabled(busy);
    const bool ownedLaunch = passiveDumpPopup_.result.launched &&
                             passiveDumpPopup_.result.launchContained;
    if (ImGui::Button(ownedLaunch ? "Close and terminate launch" : "Close")) {
        if (ownedLaunch) {
            passiveDumpService_.terminateContainedLaunch();
            passiveDumpPopup_.result.launchContained = false;
        }
        passiveDumpPopup_.result = {};
        passiveDumpPopup_.error.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndDisabled();
    ImGui::EndPopup();
}

// Documents are selected in the title capsule; only one navigation band and
// one execution band consume workspace height.
static float DocumentStripHeight() { return 0.0f; }

static float ToolbarRowHeight() {
    const float k = theme::UiScale();
    return std::max({30.0f * k, ImGui::GetFrameHeight(),
        ImGui::GetTextLineHeight() * 2.0f + 4.0f * k});
}

static float ToolbarHeight() {
    const float k = theme::UiScale();
    const float row = ToolbarRowHeight();
    return row + 10.0f * k;
}

// One flat label row, roughly one third shorter than the former two-line cards.
static float TabStripHeight() {
    const float k = theme::UiScale();
    return (std::max)(30.0f * k, ImGui::GetTextLineHeight() + 12.0f * k);
}

static float StatusStripHeight() {
    const float k = theme::UiScale();
    return (std::max)(24.0f * k, ImGui::GetTextLineHeight() + 8.0f * k);
}

void App::renderDocumentStrip(float width, float height) {
    const float k = theme::UiScale();
    const auto documents = ctx_.staticDocuments();
    const auto active = std::find_if(documents.begin(), documents.end(),
        [](const auto& document) { return document.active; });
    const bool documentMenuOpen = ImGui::IsPopupOpen("##all_documents") ||
        ImGui::IsPopupOpen("##document_context");
    const bool topologyBlocked = ctx_.documentCommandPending() || palette_.isOpen() ||
        (!documentMenuOpen && ImGui::IsPopupOpen(nullptr,
            ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel));
    std::optional<DocumentId> activate, close;
    std::string title = active != documents.end()
        ? (active->title.empty() ? "Untitled" : active->title) : "Open binary";
    if (active != documents.end() && active->mapped && title.rfind("[LIVE]", 0) != 0)
        title = "[LIVE] " + title;
    if (active != documents.end() && active->dirty) title += " *";
    const DbgSnapshot* debug = ctx_.frameDebugSnapshot;
    std::string pid;
    if (debug && debug->attached()) pid = "  /  pid " + std::to_string(debug->pid);
    const float pidWidth = ImGui::CalcTextSize(pid.c_str()).x;
    const bool showPid = width > pidWidth + 100.0f * k;
    const float labelRoom = (std::max)(1.0f, width - 34.0f * k - (showPid ? pidWidth : 0));
    std::string shown = title;
    while (shown.size() > 1 && ImGui::CalcTextSize(shown.c_str()).x > labelRoom) {
        size_t last = shown.size() - 1;
        while (last > 0 && (static_cast<unsigned char>(shown[last]) & 0xC0) == 0x80) --last;
        shown.resize(last);
    }
    if (shown != title) {
        while (shown.size() > 1 && ImGui::CalcTextSize((shown + "...").c_str()).x > labelRoom) {
            size_t last = shown.size() - 1;
            while (last > 0 && (static_cast<unsigned char>(shown[last]) & 0xC0) == 0x80) --last;
            shown.resize(last);
        }
        shown += "...";
    }
    const ImVec2 at = ImGui::GetCursorScreenPos();
    ImGui::BeginDisabled(topologyBlocked);
    if (ImGui::InvisibleButton("##document_list", ImVec2(width, height),
                              ImGuiButtonFlags_EnableNav)) ImGui::OpenPopup("##all_documents");
    const bool hovered = ImGui::IsItemHovered(), focused = ImGui::IsItemFocused();
    if (hovered && active != documents.end() && ImGui::IsMouseClicked(ImGuiMouseButton_Middle))
        close = active->id;
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const float radius = height * 0.5f;
    draw->AddRectFilled(at, ImVec2(at.x + width, at.y + height),
        ImGui::GetColorU32(hovered || focused ? ImGuiCol_FrameBgHovered : ImGuiCol_FrameBg), radius);
    draw->AddRect(at, ImVec2(at.x + width, at.y + height),
        ImGui::GetColorU32(focused ? theme::col::accent() : theme::col::paneLine()), radius);
    const float textY = at.y + (height - ImGui::GetTextLineHeight()) * 0.5f;
    const ImVec4 clip(at.x + 10.0f * k, at.y, at.x + width - 23.0f * k, at.y + height);
    draw->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(at.x + 10.0f * k, textY),
        ImGui::GetColorU32(theme::col::secondaryText()), shown.c_str(), nullptr, 0, &clip);
    if (showPid) draw->AddText(ImVec2(at.x + width - 24.0f * k - pidWidth, textY),
        ImGui::GetColorU32(theme::col::secondaryText()), pid.c_str());
    const float cx = at.x + width - 12.0f * k, cy = at.y + height * 0.5f;
    const ImU32 ink = ImGui::GetColorU32(theme::col::secondaryText());
    draw->AddLine(ImVec2(cx - 3.0f * k, cy - k), ImVec2(cx, cy + 2.0f * k), ink, k);
    draw->AddLine(ImVec2(cx, cy + 2.0f * k), ImVec2(cx + 3.0f * k, cy - k), ink, k);
    if (ImGui::BeginPopupContextItem("##document_context")) {
        if (active != documents.end()) {
            if (!active->path.empty() && ImGui::MenuItem("Copy full path"))
                ImGui::SetClipboardText(active->path.c_str());
            if (ImGui::MenuItem("Close document", "Ctrl+W")) close = active->id;
        }
        if (ImGui::MenuItem("Open another binary...", "Ctrl+O")) openFileDialog();
        ImGui::EndPopup();
    }
    if (hovered) {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted(title.c_str());
        if (active != documents.end() && !active->path.empty())
            ImGui::TextWrapped("%s", active->path.c_str());
        ImGui::TextDisabled("%zu / %u documents | Ctrl+Tab to switch | right-click for actions",
            documents.size(), (unsigned)DocumentManager::kMaxDocuments);
        ImGui::EndTooltip();
    }
    if (ImGui::BeginPopup("##all_documents")) {
        ImGui::TextDisabled("Open documents (%zu / %u)", documents.size(),
                            (unsigned)DocumentManager::kMaxDocuments);
        ImGui::Separator();
        for (size_t i = 0; i < documents.size(); ++i) {
            const auto& document = documents[i];
            ImGui::PushID((int)document.id.value);
            const std::string label = std::to_string(i + 1) + "  " +
                (document.mapped ? "[LIVE] " : "") +
                (document.title.empty() ? "Untitled" : document.title) + (document.dirty ? " *" : "");
            if (ImGui::MenuItem(label.c_str(), nullptr, document.active)) activate = document.id;
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Middle)) close = document.id;
            if (ImGui::BeginPopupContextItem("##document_list_context")) {
                if (!document.path.empty() && ImGui::MenuItem("Copy full path"))
                    ImGui::SetClipboardText(document.path.c_str());
                if (ImGui::MenuItem("Close document")) close = document.id;
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Open another binary...", "Ctrl+O")) openFileDialog();
        if (ImGui::MenuItem("Open as Raw...")) openRawFileDialog();
        if (ImGui::MenuItem("Close active document", "Ctrl+W", false, active != documents.end()))
            close = active->id;
        ImGui::EndPopup();
    }
    ImGui::EndDisabled();
    // Commit only after the frame releases every document borrower, as before.
    if (close) {
        if (!ctx_.queueCloseStaticDocument(*close))
            ui::Toast(ui::ToastKind::Error, ctx_.documentCommandError());
    } else if (activate && !ctx_.queueActivateStaticDocument(*activate)) {
        ui::Toast(ui::ToastKind::Error, ctx_.documentCommandError());
    }
}

bool App::startExecutionHistory(const DbgSnapshot& captured) {
    const DebugTargetIdentity target{captured.pid, captured.sessionGeneration};
    if (ctx_.gmlExecutionMode || captured.state != DbgState::Paused ||
        captured.cleanupOnly ||
        !ctx_.debug.recordExecutionPathForSession(target, captured.activeTid)) {
        ui::Toast(ui::ToastKind::Warn,
            "Recording requires the same paused native thread and an idle execution command. Try again at a native stop.");
        return false;
    }
    executionHistoryView_.open = true;
    executionHistoryPoll_ = {};
    return true;
}

void App::refreshExecutionHistory(const DbgSnapshot& live) {
    const auto now = std::chrono::steady_clock::now();
    const bool sameTarget = DebugTargetIdentityMatches(
        executionHistory_.target, {live.pid, live.sessionGeneration});
    // Polling a running recorder is bounded; at a real pause the final path is
    // adopted immediately so Step Back cannot miss the terminal instruction.
    if (!sameTarget || live.state != DbgState::Running ||
        now - executionHistoryPoll_ >= std::chrono::milliseconds(100)) {
        executionHistoryPoll_ = now;
        if (ctx_.debug.executionHistorySnapshotIfChanged(executionHistory_))
            executionHistoryView_.sync(executionHistory_);
    }
}

void App::renderDebugToolbar(const DbgSnapshot& s) {
    const float k    = theme::UiScale();
    const float commandRadius = ImGui::GetStyle().FrameRounding;
    const float docH = DocumentStripHeight();
    const float barH = ToolbarHeight();
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float toolbarY = vp->WorkPos.y + docH + TabStripHeight();
    const float rowH = ToolbarRowHeight();
    const float toolbarPaddingY = (barH - rowH) * 0.5f;
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, toolbarY));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, barH));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                        ImVec2(8.0f * k, toolbarPaddingY));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, theme::col::tableHeader());
    if (ImGui::Begin("##debugbar", nullptr, flags)) {
        // Bottom border line (wireframe panel chrome).
        ImGui::GetWindowDrawList()->AddLine(
            ImVec2(vp->WorkPos.x, toolbarY + barH - 1.0f),
            ImVec2(vp->WorkPos.x + vp->WorkSize.x,
                   toolbarY + barH - 1.0f),
            ImGui::GetColorU32(theme::col::paneLine()));

        Debugger& d = ctx_.debug;
        const auto lifecycle = d.lifecycleSnapshot();
        const bool attached = s.attached();
        const bool paused   = s.state == DbgState::Paused;
        const bool running  = s.state == DbgState::Running;
        const DebugTargetIdentity frameTarget{ s.pid, s.sessionGeneration };
        const auto gml = d.gameMakerSnapshot();
        const bool gmlTarget = DebugTargetIdentityMatches(gml.target, frameTarget);
        const bool gmlPaused = gmlTarget && paused && gml.state == GameMakerSessionState::Paused &&
            gml.stop && gml.stop->identity.tid == s.activeTid;
        bool executionRequested = false;
        auto executionCommand = [&](GmlControlCommand command) {
            executionRequested = true;
            if (ctx_.gmlExecutionMode) {
                std::string error;
                if (!d.gameMakerCommand(command, gmlPaused ? gml.stop->identity : GmlPauseIdentity{}, error))
                    ui::Toast(ui::ToastKind::Warn, error);
            } else {
                switch (command) {
                case GmlControlCommand::Continue: d.continueForSession(frameTarget); break;
                case GmlControlCommand::Pause: d.pauseForSession(frameTarget); break;
                case GmlControlCommand::StepInto: d.stepIntoForSession(frameTarget); break;
                case GmlControlCommand::StepOver: d.stepOverForSession(frameTarget); break;
                case GmlControlCommand::StepOut: d.stepOutForSession(frameTarget); break;
                default: break;
                }
            }
        };
        if (gmlPaused && ctx_.gmlExecutionMode && ctx_.gmlAutoFollow &&
            ctx_.gmlFollowedStop != gml.stop->identity && gml.archive &&
            ctx_.staticBinary().gameMakerArchive() && ctx_.staticBinary().contentHash() == gml.archiveHash &&
            gml.stop->location.codeIndex < gml.archive->code.size()) {
            const auto& code = gml.archive->code[gml.stop->location.codeIndex];
            const uint64_t offset = code.bytecodeOffset + gml.stop->location.byteOffset;
            if (gml.archive->isInstructionOffset(offset)) {
                ctx_.gotoAddress(offset);
                ctx_.gmlFollowedStop = gml.stop->identity;
            }
        }
        const bool loaded   = ctx_.staticBinary().loaded();
        const float commandH = rowH;
        const bool compactCommands = vp->WorkSize.x < 1000.0f * k;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        auto commandWidth = [&](const char* icon, const char* fallback,
                                const char* label) {
            const char* glyph = compactCommands ? "" : ui::IconsLoaded() && icon ? icon : fallback;
            const float glyphW = (glyph && glyph[0])
                ? ImGui::CalcTextSize(glyph).x : 0.0f;
            const float labelW = ImGui::CalcTextSize(label).x;
            const float gap = glyphW > 0.0f ? 6.0f * k : 0.0f;
            return (std::max)(30.0f * k, 18.0f * k + glyphW + gap + labelW);
        };
        auto commandButton = [&](const char* id, const char* icon,
                                 const char* fallback, const char* label,
                                 const char* tip, bool hot, bool enabled) {
            const char* glyph = compactCommands ? "" : ui::IconsLoaded() && icon ? icon : fallback;
            const ImVec2 glyphSize = ImGui::CalcTextSize(glyph);
            const ImVec2 labelSize = ImGui::CalcTextSize(label);
            const float gap = glyph && glyph[0] ? 6.0f * k : 0.0f;
            const float width = commandWidth(icon, fallback, label);
            const ImVec2 p = ImGui::GetCursorScreenPos();
            if (!enabled) ImGui::BeginDisabled();
            const bool clicked = ImGui::InvisibleButton(id, ImVec2(width, commandH),
                ImGuiButtonFlags_EnableNav);
            const bool hovered = ImGui::IsItemHovered(
                ImGuiHoveredFlags_AllowWhenDisabled);
            const bool focused = ImGui::IsItemFocused();
            const bool held = ImGui::IsItemActive();
            if (!enabled) ImGui::EndDisabled();

            if (enabled) {
                dl->AddRectFilled(p, ImVec2(p.x + width, p.y + commandH),
                    ImGui::GetColorU32(held ? ImGuiCol_FrameBgActive
                        : hovered || focused ? ImGuiCol_FrameBgHovered : ImGuiCol_FrameBg),
                    commandRadius);
                dl->AddRect(p, ImVec2(p.x + width, p.y + commandH),
                    ImGui::GetColorU32(focused ? theme::col::accent() : theme::col::lineSoft()),
                    commandRadius, 0, focused ? 1.5f * k : k);
            } else if (hot) {
                ImVec4 fill = theme::col::accent();
                fill.w = hot ? (held ? 0.30f : 0.18f)
                             : held ? 0.20f : focused ? 0.14f : 0.10f;
                dl->AddRectFilled(p, ImVec2(p.x + width, p.y + commandH),
                                  ImGui::GetColorU32(fill), commandRadius);
            }
            const ImVec4 glyphCol = !enabled ? theme::col::muted()
                                  : hot ? theme::col::accent()
                                        : ImGui::GetStyleColorVec4(ImGuiCol_Text);
            const ImVec4 labelCol = enabled
                ? ImGui::GetStyleColorVec4(ImGuiCol_Text) : theme::col::muted();
            const float glyphY = p.y + (commandH - glyphSize.y) * 0.5f;
            const float labelY = p.y + (commandH - labelSize.y) * 0.5f;
            dl->AddText(ImVec2(p.x + 9.0f * k, glyphY),
                        ImGui::GetColorU32(glyphCol), glyph);
            dl->AddText(ImVec2(p.x + 9.0f * k + glyphSize.x + gap, labelY),
                        ImGui::GetColorU32(labelCol), label);
            if (hovered) ui::ItemTooltip(tip);
            return clicked && enabled;
        };
        auto commandDivider = [&] {
            const ImVec2 p = ImGui::GetCursorScreenPos();
            dl->AddLine(ImVec2(p.x, p.y + 3.0f * k),
                        ImVec2(p.x, p.y + commandH - 3.0f * k),
                        ImGui::GetColorU32(theme::col::lineSoft()), 1.0f * k);
            ImGui::Dummy(ImVec2(1.0f * k, commandH));
        };
        auto nextGroup = [&] {
            ImGui::SameLine(0.0f, 9.0f * k);
            commandDivider();
            ImGui::SameLine(0.0f, 9.0f * k);
        };
        auto nextCommand = [&] { ImGui::SameLine(0.0f, 3.0f * k); };

        const bool modePaused = !s.cleanupOnly && !lifecycle.busy && (ctx_.gmlExecutionMode ? gmlPaused : paused && !gmlPaused);
        const bool modeRunning = !s.cleanupOnly && !lifecycle.busy && running && (!ctx_.gmlExecutionMode || (gmlTarget && gml.ready()));

        const bool lifecycleIdle = !lifecycle.busy;
        const bool canLaunch = lifecycleIdle && ctx_.binaryLaunchable();
        const bool canDebugDll = lifecycleIdle && ctx_.binaryDllDebuggable();
        const bool canRun = canLaunch || canDebugDll;
        const char* launchTip = canDebugDll
            ? "Debug DLL - choose a compatible host, export, and DLL breakpoint"
            : (loaded && !ctx_.binaryDebugArchitectureMatches())
            ? "Launch & Debug requires a matching x86/x64 PE machine and decoder mode"
            : (canLaunch || !loaded)
            ? "Launch & Debug - launch the loaded binary and break at its entry point"
            : "This image cannot be started directly; attach a process in Communications.";
        if (lifecycle.busy) {
            const bool cancellable = lifecycle.command != DbgLifecycleCommand::Detach &&
                lifecycle.state == DbgLifecycleState::Starting;
            if (commandButton("##cmd_primary", DS_ICON_STOP, "[]",
                    cancellable ? "Cancel startup" : "Stopping...",
                    "Debugger startup and cleanup run in the background",
                    true, cancellable)) d.cancelLifecycle(lifecycle.requestId);
        } else if (s.cleanupOnly) {
            if (commandButton("##cmd_primary", DS_ICON_STOP, "[]", "Retry Detach",
                    "Cleanup is incomplete. Retry restoring the target before ending this session.",
                    true, true)) d.requestDetach(frameTarget);
        } else if (attached) {
            if (running) {
                if (commandButton("##cmd_primary", DS_ICON_PAUSE, "||", "Pause",
                                  "Pause - break into the running process (F5)",
                                  true, modeRunning)) executionCommand(GmlControlCommand::Pause);
            } else if (commandButton("##cmd_primary", DS_ICON_PLAY, ">", "Continue",
                                     "Continue - resume until the next breakpoint (F5)",
                                     true, modePaused)) {
                executionCommand(GmlControlCommand::Continue);
            }
        } else {
            const char* primaryLabel = canDebugDll ? "Debug DLL"
                                     : compactCommands ? "Launch" : "Launch & Debug";
            if (commandButton("##cmd_primary", DS_ICON_PLAY, ">", primaryLabel,
                              launchTip, canRun, canRun)) {
                if (canDebugDll) ctx_.requestedDebugDll = true;
                else {
                    std::string error;
                    if (!ctx_.launchAndDebug(error))
                        ui::Toast(ui::ToastKind::Error, "Launch failed: " + error);
                }
            }
        }

        nextGroup();
        if (commandButton("##cmd_step_into", DS_ICON_DOWN, "v",
                          compactCommands ? "Into" : "Step Into",
                          "Step Into (F11) - one instruction, following calls",
                           false, modePaused)) executionCommand(GmlControlCommand::StepInto);
        nextCommand();
        if (commandButton("##cmd_step_over", DS_ICON_REDO, ">>",
                          compactCommands ? "Over" : "Step Over",
                          "Step Over (F10) - one instruction, stepping over calls",
                           false, modePaused)) executionCommand(GmlControlCommand::StepOver);
        nextCommand();
        if (commandButton("##cmd_step_out", DS_ICON_UP, "^",
                          compactCommands ? "Out" : "Step Out",
                          "Step Out (Shift+F11) - run until the current function returns",
                           false, modePaused)) executionCommand(GmlControlCommand::StepOut);

        const bool historyCurrent = DebugTargetIdentityMatches(executionHistory_.target, frameTarget);
        const bool canBrowseBack = !ctx_.gmlExecutionMode && historyCurrent &&
            !executionHistory_.recording && executionHistoryView_.canStepBack(executionHistory_);
        const bool runtimeCursorCurrent = ctx_.runtimeCursorTarget.valid() &&
            DebugTargetIdentityMatches(frameTarget, ctx_.runtimeCursorTarget);
        const bool canRunToCursor = modePaused && !ctx_.gmlExecutionMode &&
            ctx_.runtimeCursorVA && runtimeCursorCurrent;
        const TraceCoverageSnapshot* tr = ctx_.frameTraceCoverageSnapshot;
        const bool traceOn = ctx_.traceSeedPlanning || (tr && tr->active) || s.traceOwnedSites != 0;
        uint64_t traceRuntimeBase = 0, traceRuntimeSize = 0;
        const bool exactTraceImage = ctx_.frameDebugSnapshot &&
            ctx_.debuggerRuntimeImage(*ctx_.frameDebugSnapshot,
                                      traceRuntimeBase, traceRuntimeSize);
        const bool traceStartEnabled = !s.cleanupOnly && (traceOn ||
            (modePaused && !ctx_.gmlExecutionMode && loaded && exactTraceImage));
        const bool showTrace = vp->WorkPos.x + vp->WorkSize.x - 8.0f * k - ImGui::GetItemRectMax().x >=
            commandWidth(DS_ICON_LIGHTNING, "tr", "Trace") + 110.0f * k;
        if (showTrace) {
            nextGroup();
            if (commandButton("##cmd_trace", DS_ICON_LIGHTNING, "tr", "Trace",
                          traceOn
                              ? "Stop Trace Coverage; collected coverage remains"
                              : exactTraceImage
                                  ? "Start one-shot basic-block Trace Coverage"
                                  : "Trace requires a paused matching x86/x64 module",
                          traceOn, traceStartEnabled)) {
            ctx_.requestedTraceToggle = true;
            ctx_.requestedTraceTarget = frameTarget;
            ctx_.requestedTab = "Binary View";
            }
        }

        // Secondary execution commands are available in More, leaving the
        // primary command row at one fixed height on every window width.
        const float trailingStart = ImGui::GetItemRectMax().x;
        const float toolbarRight = vp->WorkPos.x + vp->WorkSize.x - 8.0f * k;
        const float available = toolbarRight - trailingStart;
        const bool showAddress = available >= 490.0f * k;
        const bool showThread = available >= 270.0f * k;
        const bool showDetach = attached && available >= 350.0f * k;
        const bool showArmed = available >= 590.0f * k;
        const size_t armedBreakpoints = attached ? static_cast<size_t>(std::count_if(
            s.breakpoints.begin(), s.breakpoints.end(),
            [](const auto& breakpoint) { return breakpoint.enabled && breakpoint.armed; })) : 0;
        auto openBreakpoints = [&] {
            ctx_.requestedBreakpoints = true;
            ctx_.requestedTab = "Binary View";
        };
        if (showArmed) {
            nextGroup();
            char count[32];
            std::snprintf(count, sizeof(count), "%zu", armedBreakpoints);
            const float countW = (std::max)(20.0f * k, ImGui::CalcTextSize(count).x + 12.0f * k);
            const float labelW = ImGui::CalcTextSize("Armed").x;
            const float width = labelW + countW + 28.0f * k;
            const ImVec2 at = ImGui::GetCursorScreenPos();
            if (ImGui::InvisibleButton("##toolbar_armed", ImVec2(width, rowH),
                                      ImGuiButtonFlags_EnableNav)) openBreakpoints();
            ImVec4 tint = theme::col::bad(); tint.w = ImGui::IsItemHovered() ? 0.18f : 0.10f;
            ImVec4 edge = theme::col::bad(); edge.w = ImGui::IsItemFocused() ? 1.0f : 0.28f;
            dl->AddRectFilled(at, ImVec2(at.x + width, at.y + rowH), ImGui::GetColorU32(tint), rowH * 0.5f);
            dl->AddRect(at, ImVec2(at.x + width, at.y + rowH), ImGui::GetColorU32(edge), rowH * 0.5f);
            const float textY = at.y + (rowH - ImGui::GetTextLineHeight()) * 0.5f;
            dl->AddText(ImVec2(at.x + 12.0f * k, textY), ImGui::GetColorU32(theme::col::bad()), "Armed");
            const ImVec2 bubble(at.x + width - countW - 6.0f * k, at.y + (rowH - 20.0f * k) * 0.5f);
            dl->AddRectFilled(bubble, ImVec2(bubble.x + countW, bubble.y + 20.0f * k),
                ImGui::GetColorU32(theme::col::bad()), 10.0f * k);
            dl->AddText(ImVec2(bubble.x + (countW - ImGui::CalcTextSize(count).x) * 0.5f, textY),
                IM_COL32(255, 255, 255, 255), count);
            ui::ItemTooltip("Physically armed, enabled software breakpoints in this native session. Open Breakpoints.");
        }
        auto renderAddressControl = [&](float addressWidth) {
            bool mirrorValid = false;
            bool mirrorLive = false;
            uint64_t mirrorAddress = 0;
            DebugTargetIdentity mirrorTarget{};
            const bool cursorOwnerCurrent = !ctx_.cursorLive ||
                (attached && ctx_.cursorTarget.valid() &&
                 DebugTargetIdentityMatches(frameTarget, ctx_.cursorTarget));
            if (ctx_.hasCursor && cursorOwnerCurrent) {
                mirrorAddress = ctx_.cursorVA;
                mirrorValid = true;
                mirrorLive = ctx_.cursorLive;
                if (mirrorLive) mirrorTarget = frameTarget;
            } else if (loaded && ctx_.staticBinary().hasEntryPoint()) {
                mirrorAddress = ctx_.staticBinary().entryPointVA();
                mirrorValid = true;
            } else if (loaded) {
                mirrorAddress = ctx_.staticBinary().imageBase();
                mirrorValid = true;
            }
            if (!toolbarAddressEditing_ &&
                (mirrorValid != toolbarAddressMirrorValid_ ||
                 (mirrorValid && (mirrorAddress != toolbarAddressMirror_ ||
                                  mirrorLive != toolbarAddressMirrorLive_ ||
                                  mirrorTarget.pid != toolbarAddressMirrorTarget_.pid ||
                                  mirrorTarget.sessionGeneration !=
                                      toolbarAddressMirrorTarget_.sessionGeneration)))) {
                if (mirrorValid)
                    std::snprintf(toolbarAddress_, sizeof(toolbarAddress_), "0x%llX",
                                  (unsigned long long)mirrorAddress);
                else
                    toolbarAddress_[0] = 0;
                toolbarAddressMirror_ = mirrorAddress;
                toolbarAddressMirrorValid_ = mirrorValid;
                toolbarAddressMirrorLive_ = mirrorValid && mirrorLive;
                toolbarAddressMirrorTarget_ = toolbarAddressMirrorLive_
                    ? mirrorTarget : DebugTargetIdentity{};
            }

            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, commandRadius);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                                ImVec2(10.0f * k, (rowH - ImGui::GetTextLineHeight()) * 0.5f));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, theme::col::panelHeader());
            ImGui::PushStyleColor(ImGuiCol_Border, theme::col::lineSoft());
            ImGui::SetNextItemWidth(addressWidth);
            const bool gotoSubmitted = ImGui::InputTextWithHint(
                "##toolbar_address", "goto address", toolbarAddress_,
                sizeof(toolbarAddress_),
                ImGuiInputTextFlags_EnterReturnsTrue |
                ImGuiInputTextFlags_AutoSelectAll);
            toolbarAddressEditing_ = ImGui::IsItemActive();
            ui::ItemTooltip(toolbarAddressMirrorLive_
                                ? "Go to this live runtime address (Enter); editing it creates a static FILE-address request"
                                : "Go to a static virtual address (Enter)",
                            false);
            if (gotoSubmitted) {
                uint64_t address = 0;
                if (parseHexU64(toolbarAddress_, address)) {
                    const bool submitLive = toolbarAddressMirrorValid_ &&
                        toolbarAddressMirrorLive_ && address == toolbarAddressMirror_ &&
                        attached && toolbarAddressMirrorTarget_.valid() &&
                        DebugTargetIdentityMatches(frameTarget,
                                                   toolbarAddressMirrorTarget_);
                    toolbarAddressMirror_ = address;
                    toolbarAddressMirrorValid_ = true;
                    toolbarAddressMirrorLive_ = submitLive;
                    toolbarAddressMirrorTarget_ = submitLive
                        ? frameTarget : DebugTargetIdentity{};
                    if (submitLive) ctx_.gotoAddressLive(address, frameTarget);
                    else            ctx_.gotoAddress(address);
                } else {
                    ui::Toast(ui::ToastKind::Error,
                              "The command-bar address must be hexadecimal.");
                }
            }
            ImGui::SameLine(0.0f, 0.0f);
            if (ImGui::ArrowButton("##toolbar_address_presets", ImGuiDir_Down))
                ImGui::OpenPopup("##toolbar_address_popup");
            ImGui::PopStyleColor(2);
            ImGui::PopStyleVar(3);

            auto chooseAddress = [&](const char* label, uint64_t address, bool live) {
                if (!ImGui::MenuItem(label)) return;
                std::snprintf(toolbarAddress_, sizeof(toolbarAddress_), "0x%llX",
                              (unsigned long long)address);
                toolbarAddressMirror_ = address;
                toolbarAddressMirrorValid_ = true;
                toolbarAddressMirrorLive_ = live;
                toolbarAddressMirrorTarget_ = live
                    ? frameTarget : DebugTargetIdentity{};
                if (live) ctx_.gotoAddressLive(address, frameTarget);
                else ctx_.gotoAddress(address);
            };
            if (ImGui::BeginPopup("##toolbar_address_popup")) {
                char label[96];
                if (ctx_.hasCursor && cursorOwnerCurrent) {
                    std::snprintf(label, sizeof(label), "Cursor   0x%llX",
                                  (unsigned long long)ctx_.cursorVA);
                    chooseAddress(label, ctx_.cursorVA, ctx_.cursorLive);
                }
                if (loaded && ctx_.staticBinary().hasEntryPoint()) {
                    std::snprintf(label, sizeof(label), "Entry point   0x%llX",
                                  (unsigned long long)ctx_.staticBinary().entryPointVA());
                    chooseAddress(label, ctx_.staticBinary().entryPointVA(), false);
                }
                if (loaded) {
                    std::snprintf(label, sizeof(label), "Image base   0x%llX",
                                  (unsigned long long)ctx_.staticBinary().imageBase());
                    chooseAddress(label, ctx_.staticBinary().imageBase(), false);
                }
                if (attached) {
                    std::snprintf(label, sizeof(label), "Live RIP   0x%llX",
                                  (unsigned long long)s.regs.rip);
                    chooseAddress(label, s.regs.rip, true);
                    std::snprintf(label, sizeof(label), "Inspect RIP in Memory Tools   0x%llX",
                                  (unsigned long long)s.regs.rip);
                    if (ImGui::MenuItem(label))
                        ctx_.openMemoryToolsAt(s.regs.rip, s.pid,
                                               s.sessionGeneration);
                }
                ImGui::EndPopup();
            }
        };
        if (showAddress) {
            nextGroup();
            renderAddressControl(132.0f * k);
        }

        // Keep the thread and Detach group against the right edge, as in the
        // reference. Their popup retains the debugger's checked stop identity.
        char threadLabel[48];
        std::snprintf(threadLabel, sizeof(threadLabel), s.activeTid ? "Thread %u" : "Threads", s.activeTid);
        const float threadW = ImGui::CalcTextSize(threadLabel).x + 46.0f * k;
        const float detachW = showDetach ? commandWidth(DS_ICON_STOP, "X", "Detach") : 0.0f;
        const float moreW = ImGui::CalcTextSize("More").x + 28.0f * k;
        const float rightGroupW = moreW + (showThread ? threadW + 8.0f * k : 0.0f) +
            (showDetach ? detachW + 8.0f * k : 0.0f);
        ImGui::SameLine(0.0f, 8.0f * k);
        ImGui::SetCursorScreenPos(ImVec2((std::max)(ImGui::GetCursorScreenPos().x,
            toolbarRight - rightGroupW), toolbarY + toolbarPaddingY));
        if (showThread) {
            renderDebugSessionControls(s, threadW, rowH, executionRequested, true);
            ImGui::SameLine(0.0f, 8.0f * k);
        }
        if (showDetach) {
            if (commandButton("##cmd_detach", DS_ICON_STOP, "X", "Detach",
                "Stop debugging and detach from the process", false, true)) d.requestDetach(frameTarget);
            ImGui::SameLine(0.0f, 8.0f * k);
        }
        // The address editor establishes the row's taller text baseline. Match
        // that baseline for this native button so ItemSize cannot add an extra
        // invisible line-height offset below the otherwise fixed command band.
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
            ImVec2(ImGui::GetStyle().FramePadding.x,
                (rowH - ImGui::GetTextLineHeight()) * 0.5f));
        const bool openMore = ImGui::Button("More##toolbar_more", ImVec2(moreW, rowH));
        ImGui::PopStyleVar();
        if (openMore)
            ImGui::OpenPopup("##toolbar_more_popup");
        std::optional<bool> requestedExecutionMode;
        if (ImGui::BeginPopup("##toolbar_more_popup")) {
            if (!showTrace && ImGui::MenuItem(traceOn ? "Stop Trace Coverage" : "Trace Coverage",
                                              nullptr, traceOn, traceStartEnabled)) {
                ctx_.requestedTraceToggle = true;
                ctx_.requestedTraceTarget = frameTarget;
                ctx_.requestedTab = "Binary View";
            }
            if (ImGui::MenuItem("Step Back", nullptr, false, canBrowseBack))
                executionHistoryView_.stepBack(executionHistory_);
            if (ImGui::MenuItem("Run to cursor", "Ctrl+F9", false, canRunToCursor)) {
                executionRequested = true;
                d.runToCursorForSession(frameTarget, ctx_.runtimeCursorVA);
            }
            if (ImGui::MenuItem("Record execution path", nullptr,
                historyCurrent && executionHistory_.recording,
                modePaused && !ctx_.gmlExecutionMode && !executionRequested))
                executionRequested = startExecutionHistory(s);
            ImGui::Separator();
            if (ImGui::MenuItem("Breakpoints")) openBreakpoints();
            if (ImGui::MenuItem("Backtrace / Call Stack")) {
                ctx_.requestedBacktrace = true;
                ctx_.requestedTab = "Binary View";
            }
            if (!showAddress) {
                ImGui::TextDisabled("Go to address");
                renderAddressControl(180.0f * k);
            }
            if (!showThread) renderDebugSessionControls(s, 280.0f * k, rowH, executionRequested);
            if (attached && !showDetach && ImGui::MenuItem("Detach")) d.requestDetach(frameTarget);
            ImGui::Separator();
            if (ImGui::BeginMenu("Execution mode")) {
                if (ImGui::MenuItem("Native CPU instructions", nullptr, !ctx_.gmlExecutionMode))
                    requestedExecutionMode = false;
                if (ImGui::MenuItem("GameMaker VM instructions", nullptr, ctx_.gmlExecutionMode))
                    requestedExecutionMode = true;
                ImGui::EndMenu();
            }
            if (!attached && loaded && ctx_.staticJavaInfo().kind != JavaWrapKind::None) {
                bool jvmInit = ctx_.debug.breakOnJvmInit();
                if (ImGui::MenuItem("Break on JVM init", nullptr, jvmInit))
                    ctx_.debug.setBreakOnJvmInit(!jvmInit);
            }
            if (ImGui::MenuItem("Search commands...", "Ctrl+K")) openCommandPalette(s);
            ImGui::EndPopup();
        }

        const bool shortcutOverlayOpen = palette_.isOpen() ||
            ImGui::IsPopupOpen(nullptr,
                ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel);
        if (!ImGui::GetIO().WantTextInput && !shortcutOverlayOpen &&
            !requestedExecutionMode.has_value() && attached) {
            if (ImGui::IsKeyPressed(ImGuiKey_F5)) {
                if (modeRunning) executionCommand(GmlControlCommand::Pause);
                else if (modePaused) executionCommand(GmlControlCommand::Continue);
            }
            if (modePaused && ImGui::IsKeyPressed(ImGuiKey_F11) &&
                ImGui::GetIO().KeyShift) executionCommand(GmlControlCommand::StepOut);
            else if (modePaused && ImGui::IsKeyPressed(ImGuiKey_F11)) executionCommand(GmlControlCommand::StepInto);
            if (modePaused && ImGui::IsKeyPressed(ImGuiKey_F10)) executionCommand(GmlControlCommand::StepOver);
            if (canRunToCursor && ImGui::GetIO().KeyCtrl &&
                ImGui::IsKeyPressed(ImGuiKey_F9)) {
                executionRequested = true;
                d.runToCursorForSession(frameTarget, ctx_.runtimeCursorVA);
            }
        }
        if (requestedExecutionMode.has_value()) ctx_.gmlExecutionMode = *requestedExecutionMode;
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
}

bool App::selectDebugToolbarThread(const DbgSnapshot& captured, uint32_t tid) {
    const DebugTargetIdentity target{captured.pid, captured.sessionGeneration};
    if (!toolbarThreadPopupPaused_ || captured.state != DbgState::Paused ||
        captured.cleanupOnly || !target.valid() || !tid ||
        !DebugTargetIdentityMatches(target, toolbarThreadPopupTarget_) ||
        captured.activeTid != toolbarThreadPopupTid_ ||
        captured.regs.rip != toolbarThreadPopupRip_ || ctx_.debug.lifecycleSnapshot().busy ||
        std::none_of(captured.threads.begin(), captured.threads.end(),
            [tid](const ThreadInfo& thread) { return thread.tid == tid; })) return false;

    // Revalidate after the popup click, since its rows may have been painted
    // before execution, a different stop, or a debugger lifecycle transition.
    const DbgSnapshot current = ctx_.debug.snapshot();
    if (current.state != DbgState::Paused || current.cleanupOnly ||
        !DebugTargetIdentityMatches({current.pid, current.sessionGeneration}, target) ||
        current.activeTid != captured.activeTid || current.regs.rip != captured.regs.rip)
        return false;
    return ctx_.debug.setActiveThreadForSession(target, tid);
}

void App::renderDebugSessionControls(const DbgSnapshot& snap, float availableWidth,
                                     float height, bool executionRequested, bool threadOnly) {
    const float k = theme::UiScale();
    const float width = (std::max)(1.0f, availableWidth);
    const auto lifecycle = ctx_.debug.lifecycleSnapshot();
    const DebugTargetIdentity target{snap.pid, snap.sessionGeneration};
    const bool paused = snap.state == DbgState::Paused && !snap.cleanupOnly && !lifecycle.busy;
    const char* state = lifecycle.busy
        ? (lifecycle.state == DbgLifecycleState::Stopping ? "STOPPING" : "STARTING")
        : snap.cleanupOnly ? "CLEANUP" : snap.state == DbgState::Paused ? "PAUSED"
        : snap.state == DbgState::Running ? "RUNNING"
        : snap.state == DbgState::Terminated ? "EXITED" : "DETACHED";
    const ImVec4 stateColor = lifecycle.busy || snap.cleanupOnly || paused ? theme::col::warn()
        : snap.state == DbgState::Running ? theme::col::good() : theme::col::muted();
    const bool canSelect = paused && target.valid() && !executionRequested;
    char threadLabel[48];
    if (snap.activeTid) std::snprintf(threadLabel, sizeof(threadLabel), "Thread %u", snap.activeTid);
    else std::snprintf(threadLabel, sizeof(threadLabel), "Threads");
    const float threadWidth = ImGui::CalcTextSize(threadLabel).x + 46.0f * k;
    const float minimumStatusWidth = ImGui::CalcTextSize(state).x + 33.0f * k;
    const bool showThread = threadOnly || width >= threadWidth + minimumStatusWidth + 8.0f * k;
    const float statusWidth = (std::min)(200.0f * k,
        showThread ? width - threadWidth - 8.0f * k : width);
    const float radius = height * 0.5f;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    auto openSessionPopup = [&] {
        toolbarThreadPopupTarget_ = target;
        toolbarThreadPopupTid_ = snap.activeTid;
        toolbarThreadPopupRip_ = snap.regs.rip;
        toolbarThreadPopupPaused_ = canSelect;
        ImGui::OpenPopup("##toolbar_session_popup");
    };
    if (!threadOnly) {
        if (ImGui::InvisibleButton("##toolbar_debug_status", ImVec2(statusWidth, height),
                                  ImGuiButtonFlags_EnableNav)) openSessionPopup();
        const bool focused = ImGui::IsItemFocused();
        draw->AddRectFilled(origin, ImVec2(origin.x + statusWidth, origin.y + height),
            ImGui::GetColorU32(paused ? theme::col::pauseSurface() : theme::col::panelHeader()), radius);
        ImVec4 outline = stateColor;
        outline.w = focused ? 1.0f : 0.45f;
        draw->AddRect(origin, ImVec2(origin.x + statusWidth, origin.y + height),
            ImGui::GetColorU32(outline), radius, 0, (std::max)(1.0f, std::round(k)));
        draw->AddCircleFilled(ImVec2(origin.x + 11.0f * k, origin.y + height * 0.5f),
            3.5f * k, ImGui::GetColorU32(stateColor));

        const float stateFontSize = ImGui::GetFontSize();
        const float reasonFontSize = ImGui::GetFontSize();
        const float textX = origin.x + 23.0f * k;
        const float textRight = origin.x + statusWidth - (showThread ? 8.0f : 18.0f) * k;
        const ImVec4 textClip(textX, origin.y, (std::max)(textX, textRight), origin.y + height);
        auto abbreviated = [&](const std::string& value, float fontSize) {
            const float room = (std::max)(0.0f, textRight - textX);
            std::string shown = value;
            if (ImGui::GetFont()->CalcTextSizeA(fontSize, FLT_MAX, 0, shown.c_str()).x <= room)
                return shown;
            while (!shown.empty() && ImGui::GetFont()->CalcTextSizeA(fontSize, FLT_MAX, 0,
                    (shown + "...").c_str()).x > room) {
                size_t last = shown.size() - 1;
                while (last > 0 && (static_cast<unsigned char>(shown[last]) & 0xC0) == 0x80) --last;
                shown.resize(last);
            }
            return shown + "...";
        };
        // lastEvent is observation text from the debugger; never synthesize a stop
        // explanation from the selected command or the reference image.
        const std::string reason = abbreviated(snap.lastEvent, reasonFontSize);
        const bool hasReason = !snap.lastEvent.empty();
        const float blockH = stateFontSize + (hasReason ? reasonFontSize : 0.0f);
        const float textY = origin.y + (height - blockH) * 0.5f;
        draw->AddText(ImGui::GetFont(), stateFontSize, ImVec2(textX, textY),
            ImGui::GetColorU32(stateColor), state, nullptr, 0, &textClip);
        if (hasReason)
            draw->AddText(ImGui::GetFont(), reasonFontSize, ImVec2(textX, textY + stateFontSize),
                ImGui::GetColorU32(theme::col::muted()), reason.c_str(), nullptr, 0, &textClip);
        if (!showThread) {
            const float cx = origin.x + statusWidth - 10.0f * k, cy = origin.y + height * 0.5f;
            draw->AddLine(ImVec2(cx - 3.0f * k, cy - k), ImVec2(cx, cy + 2.0f * k),
                ImGui::GetColorU32(theme::col::muted()), k);
            draw->AddLine(ImVec2(cx, cy + 2.0f * k), ImVec2(cx + 3.0f * k, cy - k),
                ImGui::GetColorU32(theme::col::muted()), k);
        }
        ui::ItemTooltip("Debugger status and full event reason. Open to inspect or select a native thread.", false);
    }
    if (showThread) {
        if (!threadOnly) ImGui::SameLine(0.0f, 8.0f * k);
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (ImGui::InvisibleButton("##toolbar_thread", ImVec2(threadWidth, height),
                                  ImGuiButtonFlags_EnableNav)) openSessionPopup();
        const bool hover = ImGui::IsItemHovered(), focus = ImGui::IsItemFocused();
        draw->AddRectFilled(at, ImVec2(at.x + threadWidth, at.y + height),
            ImGui::GetColorU32(hover || focus ? ImGuiCol_FrameBgHovered : ImGuiCol_FrameBg),
            radius);
        draw->AddRect(at, ImVec2(at.x + threadWidth, at.y + height),
            ImGui::GetColorU32(focus ? theme::col::accent() : theme::col::lineSoft()),
            radius);
        const ImU32 ink = ImGui::GetColorU32(theme::col::muted());
        const float cy = at.y + height * 0.5f, ix = at.x + 12.0f * k;
        draw->AddCircle(ImVec2(ix, cy - 3.0f * k), 3.0f * k, ink, 0, k);
        draw->AddLine(ImVec2(ix - 5.0f * k, cy + 5.0f * k), ImVec2(ix - 2.0f * k, cy + 2.0f * k), ink, k);
        draw->AddLine(ImVec2(ix - 2.0f * k, cy + 2.0f * k), ImVec2(ix + 2.0f * k, cy + 2.0f * k), ink, k);
        draw->AddLine(ImVec2(ix + 2.0f * k, cy + 2.0f * k), ImVec2(ix + 5.0f * k, cy + 5.0f * k), ink, k);
        draw->AddText(ImVec2(at.x + 24.0f * k, cy - ImGui::GetTextLineHeight() * 0.5f),
            ImGui::GetColorU32(ImGuiCol_Text), threadLabel);
        const float cx = at.x + threadWidth - 11.0f * k;
        draw->AddLine(ImVec2(cx - 3.0f * k, cy - k), ImVec2(cx, cy + 2.0f * k), ink, k);
        draw->AddLine(ImVec2(cx, cy + 2.0f * k), ImVec2(cx + 3.0f * k, cy - k), ink, k);
        ui::ItemTooltip(canSelect ? "Select the native thread to inspect at this pause."
            : "Native thread selection requires a paused debugger session with no pending execution or cleanup.", false);
    }
    if (ImGui::BeginPopup("##toolbar_session_popup")) {
        const bool sameOwner = target.pid == toolbarThreadPopupTarget_.pid &&
            target.sessionGeneration == toolbarThreadPopupTarget_.sessionGeneration;
        const bool sameStop = toolbarThreadPopupTid_ == snap.activeTid &&
            toolbarThreadPopupRip_ == snap.regs.rip;
        if (!sameOwner || (toolbarThreadPopupPaused_ && (!canSelect || !sameStop))) {
            ImGui::CloseCurrentPopup();
        } else {
            ui::StatePill(state, stateColor);
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + (std::min)(
                440.0f * k, ImGui::GetMainViewport()->WorkSize.x - 32.0f * k));
            ImGui::TextUnformatted(snap.lastEvent.c_str());
            if (snap.pid) ImGui::TextDisabled("PID %u | session %llu | %s controls", snap.pid,
                static_cast<unsigned long long>(snap.sessionGeneration), ctx_.gmlExecutionMode ? "GML" : "Native");
            if (!lifecycle.error.empty()) ImGui::TextWrapped("%s", lifecycle.error.c_str());
            ImGui::PopTextWrapPos();
            ImGui::Separator();
            ImGui::TextDisabled("Native threads (%zu)", snap.threads.size());
            if (snap.threads.empty()) ImGui::TextDisabled("No native threads are available.");
            const bool selectionEnabled = canSelect && toolbarThreadPopupPaused_ && sameStop;
            ImGui::BeginDisabled(!selectionEnabled);
            ImGui::BeginChild("##toolbar_threads", ImVec2((std::min)(300.0f * k,
                ImGui::GetMainViewport()->WorkSize.x - 40.0f * k),
                (std::min)(8.0f, (std::max)(1.0f, static_cast<float>(snap.threads.size()))) *
                    ImGui::GetTextLineHeightWithSpacing()), false);
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(snap.threads.size()));
            while (clipper.Step()) for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& thread = snap.threads[static_cast<size_t>(row)];
                ImGui::PushID(static_cast<int>(thread.tid));
                char label[96];
                std::snprintf(label, sizeof(label), "Thread %u%s", thread.tid,
                    thread.suspended ? " (suspended)" : "");
                if (ImGui::Selectable(label, thread.tid == snap.activeTid)) {
                    if (thread.tid != snap.activeTid && !selectDebugToolbarThread(snap, thread.tid))
                        ui::Toast(ui::ToastKind::Warn, "The debugger pause or thread changed. Reopen the thread selector.");
                    ImGui::CloseCurrentPopup();
                }
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                    ImGui::SetTooltip("Thread %u | RIP 0x%llX%s", thread.tid,
                        static_cast<unsigned long long>(thread.rip), thread.suspended ? " | user-suspended" : "");
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndDisabled();
        }
        ImGui::EndPopup();
    }
}

void App::resolveWorkbenchNavigation() {
    const bool popupOpen = ImGui::IsPopupOpen(
        nullptr, ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel);

    // Resolve routed navigation before the workbench strip is drawn. This keeps
    // the selected cell and the rendered section in lockstep on the first frame
    // of a cross-tab action (including Ctrl+K results).
    if (!ctx_.requestedTab.empty() && !popupOpen) {
        for (int i = 0; i < static_cast<int>(tabs_.size()); ++i) {
            if (ctx_.requestedTab == tabs_[i]->name()) {
                activeTab_ = i;
                break;
            }
        }
        ctx_.requestedTab.clear();
    }

    if (!ImGui::GetIO().WantTextInput && !popupOpen && !palette_.isOpen() &&
        ImGui::GetIO().KeyCtrl) {
        for (int i = 0; i < static_cast<int>(tabs_.size()) && i < 9; ++i) {
            if (ImGui::IsKeyPressed(static_cast<ImGuiKey>(ImGuiKey_1 + i))) {
                activeTab_ = i;
                break;
            }
        }
    }
    if (activeTab_ < 0 || activeTab_ >= static_cast<int>(tabs_.size()))
        activeTab_ = 0;
}

// Compact, flat workbench tabs. The full labels stay on one line and retain their
// existing IDs, shortcuts, status dots, and click targets; transient sublabels
// move into the tooltip instead of consuming a second row of permanent chrome.
void App::renderTabCardStrip(const DbgSnapshot& dbg) {
    const float k = theme::UiScale();
    const float docH    = DocumentStripHeight();
    const float stripH  = TabStripHeight();
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x,
                                   vp->WorkPos.y + docH));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, stripH));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
                             ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(1, 1));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, theme::col::chrome());
    if (ImGui::Begin("##tabstrip", nullptr, flags)) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec2 win = ImGui::GetWindowPos();
        // Workspaces precede their tools; one shared baseline keeps navigation calm.
        dl->AddLine(ImVec2(win.x, win.y + stripH - 1.0f),
                    ImVec2(win.x + vp->WorkSize.x, win.y + stripH - 1.0f),
                    ImGui::GetColorU32(theme::col::paneLine()));

        // Binary View's tooltip carries the loaded basename; live tabs expose
        // their current state there as well.
        std::string binBase;
        {
            const std::string& bp = ctx_.staticBinary().path();
            if (!bp.empty()) {
                size_t slash = bp.find_last_of("/\\");
                binBase = (slash == std::string::npos) ? bp : bp.substr(slash + 1);
            }
        }
        const char* dbgWord = !dbg.attached()              ? "detached"
                            : dbg.state == DbgState::Paused ? "paused"
                            : dbg.state == DbgState::Running ? "running" : "attached";
        auto subFor = [&](const char* nm) -> std::string {
            if (std::strcmp(nm, "Projects") == 0)       return "recent";
            if (std::strcmp(nm, "Communications") == 0) return dbgWord;
            if (std::strcmp(nm, "Connections") == 0)    return dbg.attached() ? "live" : "tcp/udp";
            if (std::strcmp(nm, "Sig Scanner") == 0)    return "scan";
            if (std::strcmp(nm, "Binary View") == 0)    return binBase.empty() ? "no binary" : binBase;
            if (std::strcmp(nm, "Memory Tools") == 0)   return "scan";
            if (std::strcmp(nm, "Binary Diff") == 0)    return "a/b";
            if (std::strcmp(nm, "Binary Tech") == 0)    return "caps";
            if (std::strcmp(nm, "Cortex") == 0)         return "insight";
            if (std::strcmp(nm, "Prism") == 0)          return "profile";
            return "";
        };

        const ImVec4 acc = theme::col::accent();
        const float sidePad = 8.0f * k;
        const float hpad = 10.0f * k;
        const float cardTop = win.y + 1.0f * k;
        const float cardH = (std::max)(1.0f, stripH - 2.0f * k);
        const float usableW = (std::max)(1.0f, vp->WorkSize.x - sidePad * 2.0f);

        // Preserve every full feature name at the supported design widths. On
        // smaller windows use an explicit inventory, retaining the active tab,
        // instead of progressively squeezing labels into ambiguous fragments.
        std::vector<float> naturalWidths;
        naturalWidths.reserve(tabs_.size());
        float naturalTotal = 0.0f;
        for (const auto& tab : tabs_) {
            const char* nm = tab->name();
            const bool reservesBadge = std::strcmp(nm, "Communications") == 0 ||
                                       std::strcmp(nm, "Binary View") == 0;
            const float width = (std::max)(
                62.0f * k, ImGui::CalcTextSize(nm).x + hpad * 2.0f +
                           (reservesBadge ? 14.0f * k : 0.0f));
            naturalWidths.push_back(width);
            naturalTotal += width;
        }
        const bool overflow = naturalTotal > usableW;
        const float overflowWidth = ImGui::CalcTextSize("All features").x + 36.0f * k;
        const float visibleBudget = overflow
            ? (std::max)(0.0f, usableW - overflowWidth - 8.0f * k) : usableW;
        std::vector<int> visibleTabs;
        visibleTabs.reserve(tabs_.size());
        float visibleWidth = 0.0f;
        for (int i = 0; i < (int)tabs_.size(); ++i) {
            if (visibleWidth + naturalWidths[(size_t)i] > visibleBudget) break;
            visibleTabs.push_back(i);
            visibleWidth += naturalWidths[(size_t)i];
        }
        if (overflow && activeTab_ >= 0 && activeTab_ < (int)tabs_.size() &&
            std::find(visibleTabs.begin(), visibleTabs.end(), activeTab_) == visibleTabs.end()) {
            while (!visibleTabs.empty() &&
                   visibleWidth + naturalWidths[(size_t)activeTab_] > visibleBudget) {
                visibleWidth -= naturalWidths[(size_t)visibleTabs.back()];
                visibleTabs.pop_back();
            }
            if (naturalWidths[(size_t)activeTab_] <= visibleBudget)
                visibleTabs.push_back(activeTab_);
        }
        float x = win.x + sidePad;

        for (int i : visibleTabs) {
            const char* nm = tabs_[i]->name();
            const bool active = (i == activeTab_);
            std::string sub = subFor(nm);
            const float cardW = naturalWidths[(size_t)i];
            const ImVec2 a(x, cardTop);
            const ImVec2 b(x + cardW, cardTop + cardH);

            ImGui::PushID(i);
            ImGui::SetCursorScreenPos(a);
            bool clicked = ImGui::InvisibleButton("##tabcard", ImVec2(cardW, cardH),
                ImGuiButtonFlags_EnableNav);
            bool hovered = ImGui::IsItemHovered();
            const bool focused = ImGui::IsItemFocused();
            const bool held = ImGui::IsItemActive();

            // Keep broad shell surfaces neutral; the active workspace uses a
            // small underline rather than a filled colour card.
            const ImVec4 bodyCol = hovered || focused || held
                ? ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered)
                : active ? theme::col::panel() : theme::col::chrome();
            dl->AddRectFilled(a, b, ImGui::GetColorU32(bodyCol));
            if (active)
                dl->AddRectFilled(ImVec2(a.x + 8.0f * k, b.y - 2.0f * k),
                    ImVec2(b.x - 8.0f * k, b.y), ImGui::GetColorU32(acc));
            if (focused)
                dl->AddRect(a, b, ImGui::GetColorU32(acc), 0.0f, 0, k);

            bool badge = false;
            ImVec4 badgeCol(0, 0, 0, 1);
            if (std::strcmp(nm, "Communications") == 0 && dbg.attached()) {
                badge = true;
                badgeCol = dbg.state == DbgState::Paused
                         ? theme::col::warn() : theme::col::good();
            } else if (std::strcmp(nm, "Binary View") == 0 &&
                       (ctx_.staticAnalysis().bulkPending() ||
                        ctx_.moduleAnalysisPending() || ctx_.livescan.busy())) {
                badge = true;
                badgeCol = acc;
                // A steady activity marker keeps the chrome quiet and does not
                // require motion to distinguish active analysis from idle.
            }
            const bool reservesBadge = std::strcmp(nm, "Communications") == 0 ||
                                       std::strcmp(nm, "Binary View") == 0;
            const float badgeSlot = reservesBadge ? 14.0f * k : 0.0f;
            const float textLeft = a.x + 8.0f * k;
            const float textRight = b.x - 8.0f * k - badgeSlot;
            const float textAvail = (std::max)(1.0f, textRight - textLeft);
            const ImVec4 labCol = active || hovered || focused
                ? ImGui::GetStyleColorVec4(ImGuiCol_Text) : theme::col::muted();
            const ImVec2 labelSize = ImGui::CalcTextSize(nm);
            const float labelX = textLeft + (textAvail - labelSize.x) * 0.5f;
            const float labelY = a.y + (cardH - labelSize.y) * 0.5f;
            dl->AddText(ImVec2(labelX, labelY), ImGui::GetColorU32(labCol),
                        nm);
            if (badge)
                dl->AddCircleFilled(ImVec2(b.x - 10.0f * k,
                                           a.y + cardH * 0.5f),
                                    3.0f * k, ImGui::GetColorU32(badgeCol));

            if (clicked) activeTab_ = i;
            if (hovered) {
                char tip[256];
                if (i < 9) std::snprintf(tip, sizeof(tip), "%s\n%s  |  Ctrl+%d",
                                         nm, sub.c_str(), i + 1);
                else       std::snprintf(tip, sizeof(tip), "%s\n%s",
                                         nm, sub.c_str());
                ui::ItemTooltip(tip, false);
            }
            ImGui::PopID();

            x += cardW;
        }

        if (overflow) {
            ImGui::SetCursorScreenPos(ImVec2(
                win.x + sidePad + (std::max)(0.0f, usableW - overflowWidth), cardTop));
            if (ImGui::Button("All features##feature_overflow", ImVec2(
                    (std::min)(overflowWidth, usableW), cardH)))
                ImGui::OpenPopup("##feature_inventory");
            ui::ItemTooltip("All nine workspaces remain available here. Ctrl+1 through Ctrl+9 switch directly; Ctrl+K searches tools.");
        }
        // Keep an already-open inventory alive if a resize restores the full
        // feature strip; otherwise the popup would disappear during selection.
        if (ImGui::BeginPopup("##feature_inventory")) {
            ImGui::TextDisabled("WORKSPACES");
            ImGui::Separator();
            for (int i = 0; i < (int)tabs_.size(); ++i) {
                char shortcut[24]{};
                if (i < 9) std::snprintf(shortcut, sizeof(shortcut), "Ctrl+%d", i + 1);
                if (ImGui::MenuItem(tabs_[i]->name(), shortcut, i == activeTab_))
                    activeTab_ = i;
            }
            ImGui::EndPopup();
        }
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(3);   // WindowRounding + WindowPadding
}

void App::renderMainWindow(const DbgSnapshot& dbg) {
    // One fixed, full-size window: the contiguous workbench strip above selects the
    // section, the content fills the rest. No docking, no floating panels - every
    // section always lives in the same place.
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float docH    = DocumentStripHeight();                     // static-document tabs
    float barH    = ToolbarHeight();                           // debug toolbar below them
    float stripH  = TabStripHeight();                          // primary workbench strip
    float statusH = StatusStripHeight();                       // compact status strip
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x,
                                   vp->WorkPos.y + docH + barH + stripH));
    const float contentHeight = (std::max)(
        1.0f, vp->WorkSize.y - docH - barH - stripH - statusH);
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, contentHeight));
    (void)dbg;   // section switching lives in the primary strip band above

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
                             ImGuiWindowFlags_NoSavedSettings;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    // Zero window padding so the content sits flush against the tab strip/status
    // bar; the content child re-adds the normal padding for the section UIs.
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##main", nullptr, flags);
    ImGui::PopStyleVar();   // WindowPadding (only matters at Begin)

    // PushID is load-bearing: BeginTabItem used to scope each tab's
    // "##tabcontent" ID (scroll position, child state); keep that per-section.
    ImGui::PushID(tabs_[activeTab_]->name());
    ImGui::BeginChild("##tabcontent", ImVec2(0, 0), ImGuiChildFlags_AlwaysUseWindowPadding);
    tabs_[activeTab_]->render(ctx_);
    ImGui::EndChild();
    ImGui::PopID();

    ImGui::End();
    ImGui::PopStyleVar();
}

void App::renderStatusBar(const DbgSnapshot& d) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float statusH = StatusStripHeight();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + vp->WorkSize.y - statusH));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, statusH));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
                             ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(1, 1));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                        ImVec2(ImGui::GetStyle().FramePadding.x, 2.0f * theme::UiScale()));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                        ImVec2(12.0f * theme::UiScale(),
                               (std::max)(0.0f, (statusH - ImGui::GetFrameHeight()) * 0.5f)));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, theme::col::chrome());   // on-palette (incl. Light)
    if (ImGui::Begin("##status", nullptr, flags)) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec2 statusPos = ImGui::GetWindowPos();
        dl->AddLine(statusPos,
                    ImVec2(statusPos.x + ImGui::GetWindowSize().x, statusPos.y),
                    ImGui::GetColorU32(theme::col::line()),
                    (std::max)(1.0f, theme::UiScale()));

        ImGui::AlignTextToFramePadding();
        // Stable left-to-right summary: architecture, format, execution state,
        // then document. Background activity has its own quiet right-edge slot.
        ui::PushMono();
        const float lh = ImGui::GetTextLineHeight();
        const float scale = theme::UiScale();
        const ProgressSnapshot analysisHealth = ctx_.staticAnalysis().progress();
        const ProgressSnapshot moduleHealth = ctx_.moduleAnalysisProgress();
        const bool opening = ctx_.binaryLoadPending();
        const bool analyzing = ctx_.staticAnalysis().bulkPending();
        const bool moduleAnalysis = ctx_.moduleAnalysisPending();
        const size_t modulesInFlight = moduleAnalysis ? ctx_.moduleAnalysesInFlight() : 0;
        const bool liveScanning = ctx_.livescan.busy();
        const LiveProgress liveProgress = liveScanning ? ctx_.livescan.progress() : LiveProgress{};
        const uint32_t liveDone = liveScanning ? ctx_.livescan.batchDone() : 0;
        const uint32_t liveTotal = liveScanning ? ctx_.livescan.batchTotal() : 0;
        const TraceCoverageSnapshot* tr = ctx_.frameTraceCoverageSnapshot;
        const size_t plantedDone = tr ? tr->armedSites + tr->hitSites + tr->skippedSites + tr->retiredSites : 0;
        const bool planting = tr && tr->active && tr->plannedSites > plantedDone;
        const bool exporting = ctx_.staticCodeExport().pending();
        const CodeExportProgress exportProgress = exporting ? ctx_.staticCodeExport().progress() : CodeExportProgress{};
        const bool analysisIssues = analysisHealth.jobsFailed || analysisHealth.resultsDropped ||
                                    moduleHealth.jobsFailed || moduleHealth.resultsDropped;
        const bool saveFailure = prefsSaveFailed_ ||
            ctx_.projectSaveState == AppContext::ProjectSaveState::Failed;
        const bool traceRecovery = d.traceOwnedSites != 0 && tr && !tr->active;
        const bool statusIssues = analysisIssues || saveFailure || traceRecovery || !ctx_.projectSaveWarning.empty();

        // One small activity label owns the right edge. All services keep their
        // separate cancellation routes in its details popup, including when the
        // left summary has to clip on a narrow window. No work runs in this UI.
        enum class StatusActivity { Open, Static, Modules, Live, Trace, Export };
        struct Activity {
            StatusActivity kind;
            const char* label;
            uint64_t current;
            uint64_t total;
        };
        Activity activities[6]{};
        size_t activityCount = 0;
        auto phaseLabel = [](AnalysisPhase phase) {
            switch (phase) {
                case AnalysisPhase::Strings: return "Scanning strings";
                case AnalysisPhase::Functions: return "Finding functions";
                case AnalysisPhase::Listing: return "Building listing";
                case AnalysisPhase::ListingPrefix: return "Code boundaries";
                case AnalysisPhase::Xref: return "Building xrefs";
                case AnalysisPhase::CrackmeTriage: return "Network trail";
                default: return "Analyzing";
            }
        };
        if (opening) activities[activityCount++] = {StatusActivity::Open, "Opening binary", 0, 0};
        if (analyzing) activities[activityCount++] = {
            StatusActivity::Static, phaseLabel(analysisHealth.phase),
            analysisHealth.modulesTotal ? analysisHealth.modulesDone : analysisHealth.current,
            analysisHealth.modulesTotal ? analysisHealth.modulesTotal : analysisHealth.total};
        if (moduleAnalysis) activities[activityCount++] = {
            StatusActivity::Modules, "Analyzing live modules", moduleHealth.current, moduleHealth.total};
        if (liveScanning) activities[activityCount++] = {
            StatusActivity::Live, liveTotal ? "Reading modules"
                : liveProgress.kind == LiveKind::Strings ? "Process strings"
                : liveProgress.kind == LiveKind::Xref ? "Searching references"
                : liveProgress.kind == LiveKind::Pattern ? "Searching process bytes"
                : "Reading module",
            liveTotal ? liveDone : liveProgress.current, liveTotal ? liveTotal : liveProgress.total};
        if (ctx_.traceSeedPlanning || planting) activities[activityCount++] = {
            StatusActivity::Trace, ctx_.traceSeedPlanning ? "Finding trace blocks" : "Planting trace sites",
            ctx_.traceSeedPlanning ? ctx_.traceSeedCurrent : plantedDone,
            ctx_.traceSeedPlanning ? ctx_.traceSeedTotal : tr->plannedSites};
        if (exporting) activities[activityCount++] = {
            StatusActivity::Export, CodeExportPhaseName(exportProgress.phase), exportProgress.current, exportProgress.total};
        auto stopLabel = [](StatusActivity kind) {
            switch (kind) {
                case StatusActivity::Open: return "Stop opening binary";
                case StatusActivity::Static: return "Stop static analysis";
                case StatusActivity::Modules: return "Stop live-module analysis";
                case StatusActivity::Live: return "Stop live-memory scan";
                case StatusActivity::Trace: return "Stop trace preparation";
                case StatusActivity::Export: return "Stop source export";
            }
            return "Stop";
        };
        auto stopActivity = [&](StatusActivity kind) {
            switch (kind) {
                case StatusActivity::Open: ctx_.cancelBinaryLoad(); break;
                case StatusActivity::Static: ctx_.staticAnalysis().cancelPending(); break;
                case StatusActivity::Modules: ctx_.cancelModuleAnalysisPending(); break;
                case StatusActivity::Live: ctx_.livescan.cancelPending(); break;
                case StatusActivity::Export: ctx_.staticCodeExport().cancel(); break;
                case StatusActivity::Trace:
                    ctx_.requestedTraceCancel = true;
                    ctx_.requestedTraceCancelTarget = ctx_.frameDebugSnapshot
                        ? DebugTargetIdentity{ctx_.frameDebugSnapshot->pid,
                                              ctx_.frameDebugSnapshot->sessionGeneration}
                        : DebugTargetIdentity{};
                    break;
            }
        };
        char activityText[128]{};
        if (activityCount > 1)
            std::snprintf(activityText, sizeof(activityText), "%s +%zu", activities[0].label, activityCount - 1);
        else if (activityCount)
            std::snprintf(activityText, sizeof(activityText), "%s", activities[0].label);
        else if (analysisIssues)
            std::snprintf(activityText, sizeof(activityText), "Analysis issues");
        else if (saveFailure)
            std::snprintf(activityText, sizeof(activityText), "Save failed");
        else if (traceRecovery)
            std::snprintf(activityText, sizeof(activityText), "Trace cleanup needed");
        else if (statusIssues)
            std::snprintf(activityText, sizeof(activityText), "Status warning");
        else
            std::snprintf(activityText, sizeof(activityText), "Idle");
        const float activityHeight = ImGui::GetFrameHeight();
        const float stopWidth = activityCount ? activityHeight : 0.0f;
        const float statusRight = statusPos.x + ImGui::GetWindowSize().x - 12.0f * scale;
        const float maxActivityWidth = (std::max)(activityHeight,
            (std::min)(280.0f * scale, ImGui::GetWindowSize().x * 0.45f));
        const float labelWidth = (std::max)(activityHeight,
            (std::min)(ImGui::CalcTextSize(activityText).x + 24.0f * scale,
                       maxActivityWidth - stopWidth));
        const float activityLeft = statusRight - labelWidth - stopWidth;
        const float summaryRight = (std::max)(statusPos.x, activityLeft - 12.0f * scale);
        ImGui::PushClipRect(statusPos, ImVec2(summaryRight, statusPos.y + statusH), true);
        auto statusDot = [&] {
            ImGui::SameLine(0.0f, 9.0f * theme::UiScale());
            const ImVec2 p = ImGui::GetCursorScreenPos();
            dl->AddCircleFilled(ImVec2(p.x + 2.5f * theme::UiScale(),
                                       p.y + lh * 0.5f),
                                2.0f * theme::UiScale(),
                                ImGui::GetColorU32(theme::col::accent()));
            ImGui::Dummy(ImVec2(6.0f * theme::UiScale(), lh));
            ImGui::SameLine(0.0f, 9.0f * theme::UiScale());
        };

        const bool hasBinary = ctx_.staticBinary().loaded();
        if (!hasBinary && !d.attached()) {
            ui::StatePill("Ready", theme::col::muted());
            statusDot();
            ImGui::TextDisabled("Open a binary (Ctrl+O) or attach from Communications");
        } else {
            const char* architecture = hasBinary
                ? ArchName(ctx_.staticArch()) : (d.is32 ? "x86" : "x64");
            ImGui::Text("%s", architecture);
            if (hasBinary) {
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Architecture: %s\nDecoder: %s", architecture,
                                      ctx_.staticDisassembler()
                                          ? ctx_.staticDisassembler()->engineName() : "-");
                }
            } else {
                ui::ItemTooltip("Architecture inferred from the attached process", false);
            }
            statusDot();
            if (hasBinary)
                ImGui::TextUnformatted(ctx_.staticBinary().formatName());
            else
                ImGui::TextDisabled("Live process");

            statusDot();
            const char* stateText = !d.attached() ? "Static"
                                  : d.state == DbgState::Running ? "Running"
                                  : d.state == DbgState::Paused ? "Paused"
                                  : d.state == DbgState::Terminated ? "Terminated"
                                  : "Attached";
            const ImVec4 stateCol = !d.attached() ? theme::col::muted()
                                  : d.state == DbgState::Running ? theme::col::good()
                                  : d.state == DbgState::Paused ? theme::col::warn()
                                  : d.state == DbgState::Terminated ? theme::col::bad()
                                  : theme::col::warn();
            ui::StatePill(stateText, stateCol);
            if (ImGui::IsItemHovered() && d.attached()) {
                ImGui::BeginTooltip();
                ImGui::Text("PID %u  %s 0x%llX", d.pid, d.is32 ? "EIP" : "RIP",
                            (unsigned long long)d.regs.rip);
                if (!d.lastEvent.empty()) ImGui::TextWrapped("%s", d.lastEvent.c_str());
                if (!d.dllTargetError.empty())
                    ImGui::TextColored(theme::col::bad(), "%s", d.dllTargetError.c_str());
                if (d.jvmLoaded) ImGui::Text("JVM: %s", d.jvmPath.c_str());
                ImGui::EndTooltip();
            }

            statusDot();
            if (hasBinary) {
                const std::string& p = ctx_.staticBinary().path();
                const size_t slash = p.find_last_of("/\\");
                ImGui::TextUnformatted(slash == std::string::npos
                    ? p.c_str() : p.c_str() + slash + 1);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", p.c_str());
            } else {
                ImGui::Text("PID %u", d.pid);
            }
        }

        if (ctx_.staticBinary().loaded() && !ctx_.staticBinary().isMappedImage() &&
            (ctx_.projectSaveState != AppContext::ProjectSaveState::Clean ||
             !ctx_.projectSaveWarning.empty())) {
            statusDot();
            switch (ctx_.projectSaveState) {
                case AppContext::ProjectSaveState::Dirty:
                    ImGui::TextColored(theme::col::warn(), "Project: unsaved");
                    break;
                case AppContext::ProjectSaveState::Saving:
                    ImGui::TextColored(theme::col::accent(), "Project: saving...");
                    break;
                case AppContext::ProjectSaveState::Failed:
                    ImGui::TextColored(theme::col::bad(), "Project: save failed");
                    if (ImGui::IsItemHovered() && !ctx_.projectSaveError.empty())
                        ImGui::SetTooltip("%s", ctx_.projectSaveError.c_str());
                    break;
                case AppContext::ProjectSaveState::Clean: break;
            }
            if (!ctx_.projectSaveWarning.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(theme::col::warn(), "(recents warning)");
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", ctx_.projectSaveWarning.c_str());
            }
        }

        if (prefsSaveFailed_) {
            statusDot();
            ImGui::TextColored(theme::col::bad(), "Prefs: save failed");
            if (ImGui::IsItemHovered() && !prefsSaveError_.empty())
                ImGui::SetTooltip("%s", prefsSaveError_.c_str());
        }

        if (tr && !ctx_.traceSeedPlanning && !planting && (tr->active || tr->blockHitTotal > 0)) {
            statusDot();
            ImGui::TextColored(theme::col::good(), "Trace %s  %zu blocks / %llu hits",
                               tr->active ? "on" : "stopped", tr->hitSites,
                               (unsigned long long)tr->blockHitTotal);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::Text("%zu planned, %zu armed, %zu skipped, %zu cleared",
                    tr->plannedSites, tr->armedSites, tr->skippedSites, tr->retiredSites);
                ImGui::TextUnformatted("One-shot block entry coverage; hit totals are observations, not loop counts.");
                if (tr->planTruncated)
                    ImGui::TextColored(theme::col::warn(), "Additional sites exceeded the trace limit.");
                ImGui::EndTooltip();
            }
        }

        // Keep the analyst's current location anchored at the far edge when
        // there is room. It disappears before colliding with progress/status
        // content and doubles as a one-click copy target.
        if (ctx_.hasCursor) {
            char cursorText[40];
            std::snprintf(cursorText, sizeof(cursorText), "Cursor 0x%llX",
                          (unsigned long long)ctx_.cursorVA);
            const float cursorW = ImGui::CalcTextSize(cursorText).x;
            const float rightX = summaryRight - cursorW;
            const float contentEnd = ImGui::GetItemRectMax().x;
            if (contentEnd + 24.0f * theme::UiScale() < rightX) {
                const ImVec2 cursorPos(
                    rightX, statusPos.y + (statusH - lh) * 0.5f);
                ImGui::SetCursorScreenPos(cursorPos);
                if (ImGui::InvisibleButton("##status_cursor",
                                           ImVec2(cursorW, lh), ImGuiButtonFlags_EnableNav)) {
                    ImGui::SetClipboardText(cursorText + 7); // address only
                    ui::Toast(ui::ToastKind::Success,
                              "Cursor address copied to the clipboard.");
                }
                const bool hovered = ImGui::IsItemHovered();
                const bool focused = ImGui::IsItemFocused();
                dl->AddText(cursorPos,
                            ImGui::GetColorU32(hovered || focused ? theme::col::accent()
                                                      : theme::col::muted()),
                            cursorText);
                if (hovered) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                ui::ItemTooltip("Click to copy the cursor virtual address", false);
            }
        }
        ImGui::PopClipRect();

        auto activityDetails = [&](bool controls) {
            if (controls && ctx_.staticBinary().loaded()) {
                ImGui::TextWrapped("%s", ctx_.staticBinary().path().c_str());
                ImGui::TextDisabled("%s | %s | %s", ArchName(ctx_.staticArch()),
                    ctx_.staticBinary().formatName(), ctx_.staticDisassembler()
                        ? ctx_.staticDisassembler()->engineName() : "No decoder");
            }
            if (controls && d.attached()) {
                ImGui::Text("PID %u | %s | %s 0x%llX", d.pid,
                    d.state == DbgState::Running ? "Running" : d.state == DbgState::Paused ? "Paused"
                        : d.state == DbgState::Terminated ? "Terminated" : "Attached",
                    d.is32 ? "EIP" : "RIP", (unsigned long long)d.regs.rip);
                if (!d.lastEvent.empty()) ImGui::TextWrapped("%s", d.lastEvent.c_str());
                if (!d.dllTargetError.empty()) {
                    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::bad());
                    ImGui::TextWrapped("%s", d.dllTargetError.c_str());
                    ImGui::PopStyleColor();
                }
                if (d.jvmLoaded) ImGui::TextWrapped("JVM: %s", d.jvmPath.c_str());
            }
            if (controls && ctx_.hasCursor) {
                ImGui::Text("Cursor 0x%llX", (unsigned long long)ctx_.cursorVA);
                if (controls && ImGui::SmallButton("Copy cursor address")) {
                    char cursorAddress[32];
                    std::snprintf(cursorAddress, sizeof(cursorAddress), "0x%llX",
                                  (unsigned long long)ctx_.cursorVA);
                    ImGui::SetClipboardText(cursorAddress);
                }
            }
            for (size_t i = 0; i < activityCount; ++i) {
                const Activity& activity = activities[i];
                ImGui::Separator();
                ImGui::TextUnformatted(activity.label);
                if (activity.total)
                    ImGui::TextDisabled("%.1f%%  (%llu / %llu)",
                        100.0 * (std::min)(1.0, (double)activity.current / (double)activity.total),
                        (unsigned long long)activity.current, (unsigned long long)activity.total);
                else if (activity.current)
                    ImGui::TextDisabled("%llu processed", (unsigned long long)activity.current);
                else
                    ImGui::TextDisabled("In progress");
                if (activity.kind == StatusActivity::Static) {
                    if (analysisHealth.modulesTotal)
                        ImGui::TextDisabled("Modules: %u/%u | %s", analysisHealth.modulesDone,
                                             analysisHealth.modulesTotal, phaseLabel(analysisHealth.phase));
                } else if (activity.kind == StatusActivity::Modules) {
                    ImGui::TextDisabled("%zu live module%s | %s", modulesInFlight,
                                         modulesInFlight == 1 ? "" : "s", phaseLabel(moduleHealth.phase));
                } else if (activity.kind == StatusActivity::Trace && ctx_.traceSeedPlanning) {
                    ImGui::TextDisabled("%zu blocks found", ctx_.traceSeedFound);
                } else if (activity.kind == StatusActivity::Export && exportProgress.bytesWritten) {
                    ImGui::TextDisabled("%llu bytes written", (unsigned long long)exportProgress.bytesWritten);
                }
                if (controls) {
                    ImGui::PushID((int)activity.kind);
                    // A held click cannot transfer to another document's job
                    // when the active document changes between press/release.
                    const void* owner = activity.kind == StatusActivity::Static
                        ? static_cast<const void*>(&ctx_.staticAnalysis())
                        : activity.kind == StatusActivity::Export
                            ? static_cast<const void*>(&ctx_.staticCodeExport()) : static_cast<const void*>(&ctx_);
                    ImGui::PushID(owner);
                    if (ImGui::SmallButton(stopLabel(activity.kind))) stopActivity(activity.kind);
                    ImGui::PopID();
                    ImGui::PopID();
                }
            }
            if (!activityCount) ImGui::TextDisabled("No background work");
            auto healthDetails = [&](const char* owner, const ProgressSnapshot& health, const char* explanation) {
                ImGui::Text("%s: %u running / %u queued", owner, health.runningJobs, health.queuedJobs);
                ImGui::TextDisabled("View requests first  |  %llu yielded  |  %llu cache hits",
                    (unsigned long long)health.jobsYielded, (unsigned long long)health.cacheHits);
                if (!health.jobsFailed && !health.resultsDropped && !health.requestsRejected) return;
                ImGui::Separator();
                ImGui::TextColored(health.jobsFailed ? theme::col::bad() : theme::col::warn(),
                    "%s: %llu failed, %llu dropped", owner,
                    (unsigned long long)health.jobsFailed, (unsigned long long)health.resultsDropped);
                ImGui::TextDisabled("%llu request(s) coalesced", (unsigned long long)health.requestsCoalesced);
                if (controls) ImGui::TextWrapped("%s", explanation);
            };
            healthDetails("Analysis", analysisHealth,
                          "Dropped results mean the bounded UI result queue filled.");
            healthDetails("Modules", moduleHealth, "Incomplete modules remain retryable.");
            if (tr && (tr->active || tr->blockHitTotal > 0))
                ImGui::Text("Trace %s: %zu blocks / %llu hits", tr->active ? "on" : "stopped",
                            tr->hitSites, (unsigned long long)tr->blockHitTotal);
            if (traceRecovery) {
                ImGui::TextColored(theme::col::warn(), "%zu trace byte(s) still require restoration.",
                    d.traceOwnedSites);
                if (!d.lastEvent.empty()) ImGui::TextWrapped("%s", d.lastEvent.c_str());
                if (controls && ImGui::SmallButton("Retry Stop Trace")) {
                    ctx_.requestedTraceToggle = true;
                    ctx_.requestedTraceTarget = {d.pid, d.sessionGeneration};
                    ctx_.requestedTab = "Binary View";
                }
            }
            if (ctx_.projectSaveState == AppContext::ProjectSaveState::Dirty)
                ImGui::TextColored(theme::col::warn(), "Project: unsaved");
            else if (ctx_.projectSaveState == AppContext::ProjectSaveState::Saving)
                ImGui::TextDisabled("Project: saving...");
            else if (ctx_.projectSaveState == AppContext::ProjectSaveState::Failed) {
                ImGui::TextColored(theme::col::bad(), "Project: save failed");
                if (!ctx_.projectSaveError.empty()) ImGui::TextWrapped("%s", ctx_.projectSaveError.c_str());
            }
            if (!ctx_.projectSaveWarning.empty()) ImGui::TextWrapped("%s", ctx_.projectSaveWarning.c_str());
            if (prefsSaveFailed_) {
                ImGui::TextColored(theme::col::bad(), "Prefs: save failed");
                if (!prefsSaveError_.empty()) ImGui::TextWrapped("%s", prefsSaveError_.c_str());
            }
        };

        const ImVec2 activityPos(activityLeft, statusPos.y + (statusH - activityHeight) * 0.5f);
        ImGui::SetCursorScreenPos(activityPos);
        if (ImGui::InvisibleButton("##status_activity_details", ImVec2(labelWidth, activityHeight),
                                  ImGuiButtonFlags_EnableNav))
            ImGui::OpenPopup("##status_activity_popup");
        const bool activityHovered = ImGui::IsItemHovered();
        const bool activityFocused = ImGui::IsItemFocused();
        const ImVec4 issueColor = analysisHealth.jobsFailed || moduleHealth.jobsFailed || saveFailure
            ? theme::col::bad() : theme::col::warn();
        const ImVec4 jobColor = activityCount && (activities[0].kind == StatusActivity::Live ||
                                                  activities[0].kind == StatusActivity::Trace)
            ? theme::col::good()
            : activityCount && activities[0].kind == StatusActivity::Export
                ? theme::col::warn() : theme::col::accent();
        const ImVec4 activityColor = statusIssues ? issueColor
            : activityCount ? jobColor : theme::col::muted();
        const ImVec2 activityEnd(activityPos.x + labelWidth + stopWidth,
                                activityPos.y + activityHeight);
        const float activityRadius = activityHeight * 0.5f;
        dl->AddRectFilled(activityPos, activityEnd,
            ImGui::GetColorU32(theme::col::panelHeader()), activityRadius);
        ImVec4 activityTint = activityColor;
        activityTint.w = activityHovered || activityFocused ? 0.12f : 0.06f;
        dl->AddRectFilled(activityPos, activityEnd,
            ImGui::GetColorU32(activityTint), activityRadius);
        ImVec4 activityOutline = activityFocused ? theme::col::accent() : activityColor;
        activityOutline.w = activityFocused ? 1.0f : 0.45f;
        dl->AddRect(activityPos, activityEnd, ImGui::GetColorU32(activityOutline),
            activityRadius, 0, (std::max)(1.0f, std::round(scale)));
        const float dotX = activityPos.x + 8.0f * scale;
        const float midY = activityPos.y + activityHeight * 0.5f;
        {
            if (statusIssues) {
                dl->AddText(ImVec2(dotX - ImGui::CalcTextSize("!").x * 0.5f,
                                  midY - lh * 0.5f), ImGui::GetColorU32(activityColor), "!");
            } else {
                dl->AddCircleFilled(ImVec2(dotX, midY), 2.5f * scale, ImGui::GetColorU32(activityColor));
            }
            // Keep the stop hit target intact at narrow widths; only the label
            // elides. Complete phase names and counters remain in hover details.
            const float textWidth = (std::max)(0.0f, labelWidth - 19.0f * scale);
            char displayLabel[sizeof(activityText)];
            std::snprintf(displayLabel, sizeof(displayLabel), "%s", activityText);
            const size_t fullLength = std::strlen(displayLabel);
            size_t length = fullLength;
            while (length && ImGui::CalcTextSize(displayLabel).x > textWidth) {
                displayLabel[--length] = 0;
            }
            if (length < fullLength && length >= 3) {
                displayLabel[length - 1] = '.';
                displayLabel[length - 2] = '.';
                displayLabel[length - 3] = '.';
            }
            dl->AddText(ImVec2(activityPos.x + 16.0f * scale, midY - lh * 0.5f),
                        ImGui::GetColorU32(activityHovered || activityFocused
                            ? theme::col::accent() : theme::col::muted()),
                        displayLabel);
        }
        if (activityHovered) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f * scale, 10.0f * scale));
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                (std::max)(1.0f, (std::min)(430.0f * scale, vp->WorkSize.x - 48.0f * scale)));
            activityDetails(false);
            ImGui::Separator();
            ImGui::TextDisabled("Click for details and individual stop controls");
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
            ImGui::PopStyleVar();
        }
        if (activityCount) {
            const ImVec2 stopPos(activityPos.x + labelWidth, activityPos.y);
            ImGui::SetCursorScreenPos(stopPos);
            ImGui::PushID((int)activities[0].kind);
            const void* owner = activities[0].kind == StatusActivity::Static
                ? static_cast<const void*>(&ctx_.staticAnalysis())
                : activities[0].kind == StatusActivity::Export
                    ? static_cast<const void*>(&ctx_.staticCodeExport()) : static_cast<const void*>(&ctx_);
            ImGui::PushID(owner);
            if (ImGui::InvisibleButton("##status_activity_stop", ImVec2(stopWidth, activityHeight),
                                      ImGuiButtonFlags_EnableNav))
                stopActivity(activities[0].kind);
            const bool stopHovered = ImGui::IsItemHovered();
            const bool stopFocused = ImGui::IsItemFocused();
            if (stopFocused)
                dl->AddRect(stopPos, ImGui::GetItemRectMax(),
                    ImGui::GetColorU32(theme::col::accent()), 2.0f * scale, 0,
                    (std::max)(1.0f, std::round(scale)));
            ImGui::PopID();
            ImGui::PopID();
            const float halfSide = 3.25f * scale;
            const ImVec2 center(stopPos.x + stopWidth * 0.5f, midY);
            dl->AddRectFilled(ImVec2(center.x - halfSide, center.y - halfSide),
                              ImVec2(center.x + halfSide, center.y + halfSide),
                              ImGui::GetColorU32(stopHovered || stopFocused
                                  ? theme::col::bad() : theme::col::muted()), scale);
            if (stopHovered) {
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                ImGui::SetTooltip("%s", stopLabel(activities[0].kind));
            }
        }
        ImGui::SetNextWindowSizeConstraints(ImVec2(0, 0),
            ImVec2((std::max)(1.0f, (std::min)(480.0f * scale, vp->WorkSize.x - 24.0f * scale)),
                   (std::max)(1.0f, vp->WorkSize.y - statusH - 16.0f * scale)));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f * scale, 10.0f * scale));
        if (ImGui::BeginPopup("##status_activity_popup", ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                (std::max)(1.0f, (std::min)(440.0f * scale, vp->WorkSize.x - 64.0f * scale)));
            activityDetails(true);
            ImGui::PopTextWrapPos();
            ImGui::EndPopup();
        }
        ImGui::PopStyleVar();
        ui::PopMono();
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(4);
}

void App::renderRawLoadPopup() {
    if (openRawPopup_) { ImGui::OpenPopup("Open as Raw"); openRawPopup_ = false; }
    prepareWorkbenchDialog(680.0f, 0.0f);
    if (!ImGui::BeginPopupModal("Open as Raw", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    ImGui::TextDisabled("Map a flat code blob with an explicit architecture and analysis entry.");
    size_t slash = rawPendingPath_.find_last_of("/\\");
    ImGui::Text("File: %s", slash == std::string::npos ? rawPendingPath_.c_str() : rawPendingPath_.c_str() + slash + 1);
    ImGui::SameLine();
    ImGui::TextDisabled("(%llu bytes)", (unsigned long long)rawPendingSize_);

    auto applyDetectedDefaults = [&] {
        if (!rawFirmware_.detected() && rawFirmware_.architecture.mode == FirmwareCpuMode::Unknown)
            return;
        const FirmwareCpuMode m = rawFirmware_.entry.mode != FirmwareCpuMode::Unknown
                                ? rawFirmware_.entry.mode : rawFirmware_.architecture.mode;
        const Arch detectedArch = rawArchFromSelection(rawArchForFirmwareMode(m));
        uint64_t base = rawFirmware_.recommendedImageBaseValid
                      ? rawFirmware_.recommendedImageBase
                      : ((detectedArch == Arch::ARM || detectedArch == Arch::THUMB)
                            ? 0 : 0x140000000ull);
        if (!ArchMappingRangeFits(detectedArch, base, rawPendingSize_) &&
            (detectedArch == Arch::ARM || detectedArch == Arch::THUMB))
            base = 0;
        uint64_t entry = base;
        if (rawFirmware_.entry.detected && rawFirmware_.entry.location.valid &&
            rawFirmware_.entry.location.fileOffset < rawPendingSize_ &&
            rawFirmware_.entry.location.fileOffset <=
                (std::numeric_limits<uint64_t>::max)() - base)
            entry = base + rawFirmware_.entry.location.fileOffset;
        // Architecture-only evidence never changes a manually edited mapping.
        if (rawFirmware_.detected()) {
            formatHexU64(rawBaseBuf_, sizeof(rawBaseBuf_), base);
            formatHexU64(rawEntryBuf_, sizeof(rawEntryBuf_), entry);
        }
        rawArchSel_ = rawArchForFirmwareMode(m);
    };

    if (rawFirmware_.detected() || rawFirmware_.architecture.mode != FirmwareCpuMode::Unknown) {
        ImGui::SeparatorText(rawFirmware_.detected() ? "Firmware detector" : "Raw architecture probe");
        if (rawFirmware_.detected())
            ImGui::TextColored(theme::col::good(), "%s (%s confidence)",
                               FirmwareKindName(rawFirmware_.primaryKind),
                               FirmwareConfidenceName(rawFirmware_.confidence));
        else
            ImGui::TextColored(theme::col::warn(), "Instruction-set preselection (editable)");
        if (!rawFirmware_.mappingEvidence.empty())
            ImGui::TextWrapped("Mapping: %s", rawFirmware_.mappingEvidence.c_str());
        if (rawFirmware_.architecture.mode != FirmwareCpuMode::Unknown)
            ImGui::TextWrapped("Architecture: %s (%s confidence) - %s",
                               FirmwareCpuModeName(rawFirmware_.architecture.mode),
                               FirmwareConfidenceName(rawFirmware_.architecture.confidence),
                               rawFirmware_.architecture.evidence.c_str());
        if (rawFirmware_.entry.detected)
            ImGui::TextWrapped("Recovered entry: file +0x%llX (%s confidence) - %s",
                               (unsigned long long)rawFirmware_.entry.location.fileOffset,
                               FirmwareConfidenceName(rawFirmware_.entry.confidence),
                               rawFirmware_.entry.evidence.c_str());
        if (rawFirmware_.detected())
            ImGui::TextDisabled("%zu firmware volume(s), %zu option ROM(s), %zu flash descriptor(s)",
                                rawFirmware_.firmwareVolumes.size(), rawFirmware_.optionRoms.size(),
                                rawFirmware_.flashDescriptors.size());
        if (ImGui::SmallButton(rawFirmware_.detected()
                ? "Restore detected mapping / entry / architecture"
                : "Restore detected architecture"))
            applyDetectedDefaults();
        size_t codeLandmarks = 0;
        for (const FirmwareLandmark& lm : rawFirmware_.landmarks) if (lm.code) ++codeLandmarks;
        if (codeLandmarks) {
            ui::SameLineIfFits(ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x +
                               ImGui::CalcTextSize("Seed named code landmarks").x);
            ImGui::Checkbox("Seed named code landmarks", &rawSeedFirmwareLandmarks_);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Seed %zu bounded reset/boot/firmware-image root(s) into function discovery.", codeLandmarks);
        }
        if (ImGui::TreeNode("Detector evidence")) {
            const size_t shown = std::min<size_t>(rawFirmware_.evidence.size(), 12);
            for (size_t i = 0; i < shown; ++i) {
                const FirmwareEvidence& e = rawFirmware_.evidence[i];
                ImGui::BulletText("+0x%llX [%s] %s", (unsigned long long)e.fileOffset,
                                  FirmwareConfidenceName(e.confidence), e.summary.c_str());
            }
            if (shown < rawFirmware_.evidence.size())
                ImGui::TextDisabled("... %zu more evidence record(s)", rawFirmware_.evidence.size() - shown);
            ImGui::TreePop();
        }
    } else if (!rawFirmwareNote_.empty()) {
        ImGui::SeparatorText("Firmware detector");
        ImGui::TextColored(theme::col::muted(), "%s", rawFirmwareNote_.c_str());
    }
    if (rawFirmware_.detected() && !rawFirmwareNote_.empty())
        ImGui::TextColored(theme::col::warn(), "%s", rawFirmwareNote_.c_str());

    ImGui::SeparatorText("Raw mapping");
    ImGui::SetNextItemWidth(230.0f * theme::UiScale());
    ImGui::InputText("Base address", rawBaseBuf_, sizeof(rawBaseBuf_));
    ImGui::SetNextItemWidth(230.0f * theme::UiScale());
    ImGui::InputText("Entry point", rawEntryBuf_, sizeof(rawEntryBuf_));
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Editable mapped VA used as the first authoritative function root (VA 0 is valid).");
    ImGui::TextUnformatted("Architecture:");
    auto architectureChoice = [&](const char* label, int selection, bool newRow = false) {
        if (!newRow)
            ui::SameLineIfFits(ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x +
                               ImGui::CalcTextSize(label).x);
        ImGui::RadioButton(label, &rawArchSel_, selection);
    };
    architectureChoice("x86-16 real mode", 0, true);
    architectureChoice("x86", 1);
    architectureChoice("x64", 2);
    architectureChoice("ARM", 3);
    architectureChoice("Thumb/Thumb-2", 4);
    architectureChoice("ARM64", 5);
    architectureChoice("MIPS", 6, true);
    architectureChoice("MIPS64", 7);
    architectureChoice("PowerPC", 8);
    architectureChoice("PowerPC64", 9);
    architectureChoice("RISC-V 32", 10, true);
    architectureChoice("RISC-V 64", 11);
    const Arch selectedArch = rawArchFromSelection(rawArchSel_);
    const bool rawCanBeBigEndian = !ArchIsX86(selectedArch) &&
                                   selectedArch != Arch::RISCV32 &&
                                   selectedArch != Arch::RISCV64;
    if (!rawCanBeBigEndian) rawBigEndian_ = false;
    ImGui::BeginDisabled(!rawCanBeBigEndian);
    ImGui::Checkbox("Big-endian byte order", &rawBigEndian_);
    ImGui::EndDisabled();
    if (selectedArch == Arch::RISCV32 || selectedArch == Arch::RISCV64)
        ImGui::Checkbox("Enable compressed (RVC) instructions", &rawRiscvCompressed_);
    if (rawArchSel_ == 0)
        ImGui::TextDisabled("16-bit defaults: real-mode addressing, SP stack width, rel16 near transfers.");

    ImGui::Separator();
    if (ImGui::Button("Load", ImVec2(120, 0))) {
        uint64_t base = 0, entry = 0;
        const Arch a = rawArchFromSelection(rawArchSel_);
        if (!parseHexU64(rawBaseBuf_, base)) {
            ui::Toast(ui::ToastKind::Error, "Open Raw failed: enter a valid 64-bit hexadecimal base address.");
        } else if (!parseHexU64(rawEntryBuf_, entry)) {
            ui::Toast(ui::ToastKind::Error, "Open Raw failed: enter a valid 64-bit hexadecimal entry point.");
        } else if (!rawPendingSize_ || rawPendingSize_ - 1 >
                   (std::numeric_limits<uint64_t>::max)() - base) {
            ui::Toast(ui::ToastKind::Error, "Open Raw failed: base + file size overflows the 64-bit address space.");
        } else if (!ArchMappingRangeFits(a, base, rawPendingSize_)) {
            ui::Toast(ui::ToastKind::Error,
                      "Open Raw failed: ARM/Thumb mappings must fit entirely in the 32-bit address space.");
        } else if (entry < base || entry - base >= rawPendingSize_) {
            ui::Toast(ui::ToastKind::Error, "Open Raw failed: the entry point must be backed by the mapped file.");
        } else {
            std::vector<AnalysisLandmark> seeds;
            if (rawSeedFirmwareLandmarks_ && rawFirmware_.detected()) {
                for (const FirmwareLandmark& lm : rawFirmware_.landmarks) {
                    if (!lm.code || !lm.location.valid || lm.location.fileOffset >= rawPendingSize_)
                        continue;
                    const uint64_t va = base + lm.location.fileOffset; // mapping overflow checked above
                    auto existing = std::find_if(seeds.begin(), seeds.end(),
                        [&](const AnalysisLandmark& x) { return x.address == va; });
                    AnalysisLandmark candidate{va, lm.name, lm.evidence};
                    if (existing == seeds.end()) seeds.push_back(std::move(candidate));
                    else if (lm.kind == FirmwareLandmarkKind::BootEntry) *existing = std::move(candidate);
                }
            }
            if (std::none_of(seeds.begin(), seeds.end(),
                             [&](const AnalysisLandmark& x) { return x.address == entry; }))
                seeds.push_back({entry, rawFirmware_.detected() ? "firmware_entry" : "raw_entry",
                                 "analyst-selected raw entry point"});

            if (ctx_.beginRawLoadPath(rawPendingPath_, base, a, entry, std::move(seeds),
                                     rawFirmware_, true,
                                     rawBigEndian_ ? ByteOrder::Big : ByteOrder::Little,
                                     rawRiscvCompressed_)) {
                ctx_.requestedTab = "Binary View";
                ImGui::CloseCurrentPopup();
            } else {
                ui::Toast(ui::ToastKind::Error,
                          ctx_.documentCommandError().empty()
                              ? "Open Raw failed: the background load could not start."
                              : ctx_.documentCommandError());
            }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void App::browseDllCustomHost() {
    std::vector<wchar_t> file(kDialogPathChars, L'\0');
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = ::GetActiveWindow();
    ofn.lpstrFilter = L"Executable files (*.exe)\0*.exe\0All Files\0*.*\0";
    ofn.lpstrFile = file.data();
    ofn.nMaxFile = static_cast<DWORD>(file.size());
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;

    std::string path;
    if (!utf8FromWide(file.data(), path)) {
        dllDebugPopup_.error = "The custom-host path could not be encoded as UTF-8.";
        return;
    }
    if (path.size() >= sizeof(dllDebugPopup_.customHost)) {
        dllDebugPopup_.error = "The selected custom-host path is too long for this dialog.";
        return;
    }
    std::snprintf(dllDebugPopup_.customHost, sizeof(dllDebugPopup_.customHost), "%s", path.c_str());
    dllDebugPopup_.customBitness = 0;
    dllDebugPopup_.error.clear();

    BinaryFile host;
    if (!host.load(path) || host.isDll() ||
        (host.format() != BinFormat::PE32 && host.format() != BinFormat::PE32Plus)) {
        dllDebugPopup_.error =
            "The selected custom host is not a launchable PE executable; its bitness could not be validated.";
        return;
    }
    if (host.format() == BinFormat::PE32 && host.machine() == MachineArch::X86)
        dllDebugPopup_.customBitness = 1;
    else if (host.format() == BinFormat::PE32Plus && host.machine() == MachineArch::X64)
        dllDebugPopup_.customBitness = 2;
    else
        dllDebugPopup_.error = "Only x86 and x64 custom PE hosts are supported by this workflow.";
}

void App::renderDllDebugPopup() {
    if (ctx_.requestedDebugDll) {
        ctx_.requestedDebugDll = false;
        dllDebugPopup_ = {};
        dllDebugPopup_.inspection = InspectDllForDebug(ctx_.staticBinary());
        if (!dllDebugPopup_.inspection.callableExports.empty())
            dllDebugPopup_.selectedExport = 0;
        dllDebugPopup_.breakOnDllMain = dllDebugPopup_.inspection.dllMainRva.has_value();
        dllDebugPopup_.breakOnExport = !dllDebugPopup_.inspection.callableExports.empty();
        dllDebugPopup_.open = true;
    }
    if (dllDebugPopup_.open) {
        ImGui::OpenPopup("Debug DLL");
        dllDebugPopup_.open = false;
    }

    const float scale = theme::UiScale();
    prepareWorkbenchDialog(720.0f, 610.0f);
    if (!ImGui::BeginPopupModal("Debug DLL", nullptr, 0)) return;

    const DllInspection& inspection = dllDebugPopup_.inspection;
    const std::string& targetPath = ctx_.staticBinary().path();
    const size_t slash = targetPath.find_last_of("/\\");
    const char* targetName = slash == std::string::npos ? targetPath.c_str()
                                                         : targetPath.c_str() + slash + 1;
    ImGui::Text("%s", targetName);
    ImGui::SameLine();
    ImGui::TextDisabled("%s PE DLL", dllBitnessName(inspection.bitness));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", targetPath.c_str());
    ImGui::TextWrapped("A DLL needs a compatible host process. DisasmStudio will debug the host, match the target module at LOAD_DLL, then retarget the disassembly to its ASLR base.");

    if (!inspection.errors.empty()) {
        for (const std::string& value : inspection.errors)
            ImGui::TextColored(theme::col::bad(), "%s", value.c_str());
    }

    ImGui::SeparatorText("Callable export");
    const bool haveExports = !inspection.callableExports.empty();
    const bool validSelection = dllDebugPopup_.selectedExport >= 0 &&
                                dllDebugPopup_.selectedExport < (int)inspection.callableExports.size();
    // Keep the preview string alive across BeginCombo (dllExportLabel returns a temporary).
    const std::string selectedLabel = validSelection
        ? dllExportLabel(inspection.callableExports[dllDebugPopup_.selectedExport])
        : std::string("No callable export");
    ImGui::BeginDisabled(!haveExports);
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##dllexport", selectedLabel.c_str())) {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(inspection.callableExports.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const DllCallableExport& value = inspection.callableExports[i];
                const std::string label = dllExportLabel(value);
                char row[768];
                std::snprintf(row, sizeof(row), "%s   (#%llu, RVA %08X)", label.c_str(),
                              (unsigned long long)value.ordinal, value.rva);
                ImGui::PushID(i);
                if (ImGui::Selectable(row, dllDebugPopup_.selectedExport == i))
                    dllDebugPopup_.selectedExport = i;
                if (label != value.name && ImGui::IsItemHovered())
                    ImGui::SetTooltip("Raw export name used for invocation: %s", value.name.c_str());
                ImGui::PopID();
            }
        }
        ImGui::EndCombo();
    }
    ImGui::EndDisabled();
    if (!haveExports)
        ImGui::TextColored(theme::col::warn(),
                           "No non-forwarded, file-backed code export can be invoked by a host.");

    ImGui::SeparatorText("Host process");
    ImGui::RadioButton("Bitness-matched system rundll32", &dllDebugPopup_.hostMode, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Custom executable", &dllDebugPopup_.hostMode, 1);
    if (dllDebugPopup_.hostMode == 0) {
        const DllBitness native = nativeWindowsDllBitness();
        const DllSystemHostPath policy = inspection.bitness == DllBitness::X86 && native == DllBitness::X64
                                       ? DllSystemHostPath::Wow64SysWOW64
                                       : DllSystemHostPath::NativeSystem32;
        const auto systemHost = systemRundll32Path(policy);
        if (systemHost)
            ImGui::TextDisabled("Host: %s", systemHost->c_str());
        else
            ImGui::TextColored(theme::col::bad(),
                               "A trusted bitness-compatible system rundll32.exe was not found.");
        ImGui::TextColored(theme::col::warn(),
                           "The export must implement rundll32's callback ABI; executable code alone cannot prove its signature.");
    } else {
        ImGui::SetNextItemWidth(-108.0f * scale);
        if (ImGui::InputText("##dllcustomhost", dllDebugPopup_.customHost,
                             sizeof(dllDebugPopup_.customHost))) {
            dllDebugPopup_.customBitness = 0;
            dllDebugPopup_.error.clear();
        }
        ImGui::SameLine();
        if (ImGui::Button("Browse...")) browseDllCustomHost();
        const char* customBits = dllDebugPopup_.customBitness == 1 ? "x86"
                               : dllDebugPopup_.customBitness == 2 ? "x64" : "unknown";
        ImGui::TextDisabled("Host bitness: %s. Arguments: <DLL path> <export> [user arguments]",
                            customBits);
        if (dllDebugPopup_.customBitness == 0)
            ImGui::TextColored(theme::col::warn(),
                               "Host bitness is unverified; it must match the target DLL.");
    }

    ImGui::SeparatorText("Arguments and breakpoints");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##dllargs", dllDebugPopup_.userArguments,
                     sizeof(dllDebugPopup_.userArguments));
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Optional Windows command-line arguments. Quotes and backslashes use CommandLineToArgvW rules.");
    ImGui::BeginDisabled(!inspection.dllMainRva.has_value());
    ImGui::Checkbox("Break at DllMain", &dllDebugPopup_.breakOnDllMain);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!validSelection);
    ImGui::Checkbox("Break at selected export", &dllDebugPopup_.breakOnExport);
    ImGui::EndDisabled();
    if (!inspection.dllMainRva)
        ImGui::TextDisabled("This DLL has no validated executable entry point, so DllMain cannot be armed.");

    std::vector<std::string> userArguments;
    std::string argumentError;
    const bool argsOk = splitWindowsUserArguments(dllDebugPopup_.userArguments,
                                                   userArguments, argumentError);
    DllDebugLaunchRequest request;
    request.dllPath = targetPath;
    request.hostMode = dllDebugPopup_.hostMode == 0 ? DllHostMode::SystemRundll32
                                                    : DllHostMode::CustomExecutable;
    if (validSelection) {
        const DllCallableExport& selected = inspection.callableExports[dllDebugPopup_.selectedExport];
        request.exportToInvoke = selected.name.empty()
            ? DllExportSelector::ByOrdinal(selected.ordinal)
            : DllExportSelector::ByName(selected.name);
    }
    request.userArguments = std::move(userArguments);
    request.breakOnDllMain = dllDebugPopup_.breakOnDllMain;
    request.breakOnExport = dllDebugPopup_.breakOnExport;
    if (request.hostMode == DllHostMode::CustomExecutable) {
        request.customHost.executable = dllDebugPopup_.customHost;
        request.customHost.bitness = dllDebugPopup_.customBitness == 1 ? DllBitness::X86
                                   : dllDebugPopup_.customBitness == 2 ? DllBitness::X64
                                                                      : DllBitness::Unknown;
        request.customHost.arguments = {DllCustomArgument::DllPath(), DllCustomArgument::Export(),
                                        DllCustomArgument::UserArguments()};
    }
    DllHostEnvironment environment;
    environment.nativeWindowsBitness = nativeWindowsDllBitness();
    environment.resolveSystemRundll32 = [](DllSystemHostPath policy) {
        return systemRundll32Path(policy);
    };
    DllDebugLaunchPlan plan = BuildDllDebugLaunchPlan(ctx_.staticBinary(), request, environment);
    if (!argsOk) {
        plan.errors.push_back(argumentError);
        plan.valid = false;
    }
    if (request.hostMode == DllHostMode::CustomExecutable && *dllDebugPopup_.customHost) {
        std::wstring customHostWide;
        const DWORD attrs = wideFromUtf8(dllDebugPopup_.customHost, customHostWide)
                          ? GetFileAttributesW(customHostWide.c_str()) : INVALID_FILE_ATTRIBUTES;
        if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            plan.errors.emplace_back("The custom host executable does not exist or is not a file.");
            plan.valid = false;
        }
    }

    if (!dllDebugPopup_.error.empty())
        ImGui::TextColored(theme::col::bad(), "%s", dllDebugPopup_.error.c_str());
    if (ImGui::BeginChild("##dllplanmessages", ImVec2(0, 86.0f * scale),
                          ImGuiChildFlags_Borders)) {
        for (const std::string& value : plan.errors)
            ImGui::TextColored(theme::col::bad(), "%s", value.c_str());
        for (const std::string& value : plan.warnings)
            ImGui::TextColored(theme::col::warn(), "%s", value.c_str());
        if (plan.errors.empty() && plan.warnings.empty())
            ImGui::TextColored(theme::col::good(), "Launch plan is valid.");
    }
    ImGui::EndChild();

    const bool alreadyAttached = ctx_.frameDebugSnapshot && ctx_.frameDebugSnapshot->attached();
    ImGui::BeginDisabled(!plan.valid || alreadyAttached || ctx_.debug.lifecycleSnapshot().busy);
    if (ImGui::Button("Debug DLL", ImVec2(130.0f * scale, 0))) {
        std::string error;
        dllRetargetPid_ = 0;
        dllRetargetGeneration_ = 0;
        dllRetargetBase_ = 0;
        dllRetargetPending_.clear();
        dllRetargetFailure_.clear();
        if (ctx_.requestDebugDllLaunch(plan, error)) {
            ui::Toast(ui::ToastKind::Success,
                      "DLL host launch queued.");
            ImGui::CloseCurrentPopup();
        } else {
            dllDebugPopup_.error = "Launch failed: " + error;
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110.0f * scale, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void App::beginUnpackObservation() {
    unpackPopup_.error.clear();
    if (!ctx_.binaryLaunchable()) {
        unpackPopup_.error = !ctx_.binaryDebugArchitectureMatches()
            ? std::string("Adaptive Unpack requires a matching x86/x64 PE machine and decoder mode (active: ") +
              ArchName(ctx_.staticArch()) + "). Use Static Packed-PE Recovery for this architecture."
            : "Adaptive Unpack requires a launchable on-disk PE executable.";
        return;
    }
    unpackPopup_.result = {};
    unpackPopup_.previousImage.clear();
    unpackPopup_.previousValidPages.clear();
    unpackPopup_.writtenPages.clear();
    unpackPopup_.executablePages.clear();
    unpackPopup_.moduleBase = unpackPopup_.moduleSize = 0;
    unpackPopup_.startedTick = unpackPopup_.lastProbeTick = 0;
    unpackPopup_.runStartedTick = unpackPopup_.accumulatedRunMs = 0;
    unpackPopup_.previousRip = 0;
    unpackPopup_.hasPreviousRip = false;
    unpackPopup_.pauseRequested = false;
    unpackEngine_.reset();
    unpackPopup_.sourceDocument = ctx_.staticDocumentId();
    unpackPopup_.sourceImageGeneration = ctx_.staticImageGeneration();
    unpackPopup_.launchRequestId = 0;
    unpackPopup_.target = {};

    DbgSnapshot snap = ctx_.debug.snapshot();
    if (!snap.attached()) {
        std::string err;
        DbgLaunchRequest request;
        request.executable = ctx_.staticBinary().path();
        request.breakAtEntry = false;
        request.containedJob = unpackPopup_.containedLaunch;
        unpackPopup_.launchRequestId = ctx_.requestDebugLaunch(std::move(request), err);
        if (!unpackPopup_.launchRequestId) {
            unpackPopup_.error = "Launch failed: " + err;
            return;
        }
        unpackPopup_.waitingForInitialBreak = false;
        unpackPopup_.observing = false;
        return;
    }
    if (snap.state != DbgState::Paused) {
        unpackPopup_.error = "Pause the debuggee before starting unpack observation.";
        return;
    }
    unpackPopup_.target = {snap.pid, snap.sessionGeneration};
    unpackPopup_.waitingForInitialBreak = true; // initialized by the common sampler path
}

void App::sampleUnpackObservation() {
    const auto lifecycle = ctx_.debug.lifecycleSnapshot();
    DbgSnapshot snap = ctx_.debug.snapshot();
    if (unpackPopup_.launchRequestId || unpackPopup_.waitingForInitialBreak ||
        unpackPopup_.observing) {
        if (unpackPopup_.sourceDocument != ctx_.staticDocumentId() ||
            unpackPopup_.sourceImageGeneration != ctx_.staticImageGeneration()) {
            if (unpackPopup_.launchRequestId)
                ctx_.debug.cancelLifecycle(unpackPopup_.launchRequestId);
            unpackPopup_.launchRequestId = 0;
            unpackPopup_.waitingForInitialBreak = unpackPopup_.observing = false;
            unpackPopup_.error = "Unpack observation expired because its source document changed.";
            unpackEngine_.cancel();
            return;
        }
    }
    if (unpackPopup_.launchRequestId) {
        if (lifecycle.requestId != unpackPopup_.launchRequestId) {
            unpackPopup_.launchRequestId = 0;
            unpackPopup_.error = "Unpack startup was replaced by another debugger command.";
            return;
        }
        if (lifecycle.busy) return;
        unpackPopup_.launchRequestId = 0;
        if (!lifecycle.completed || !lifecycle.succeeded || lifecycle.cancelled ||
            !DebugTargetIdentityMatches(lifecycle.target, {snap.pid, snap.sessionGeneration}) ||
            (snap.state != DbgState::Running && snap.state != DbgState::Paused)) {
            unpackPopup_.error = lifecycle.error.empty()
                ? "The unpack target ended before startup completed." : lifecycle.error;
            return;
        }
        unpackPopup_.target = lifecycle.target;
        unpackPopup_.waitingForInitialBreak = true;
    }
    if ((unpackPopup_.waitingForInitialBreak || unpackPopup_.observing) &&
        !DebugTargetIdentityMatches(unpackPopup_.target, {snap.pid, snap.sessionGeneration})) {
        unpackPopup_.waitingForInitialBreak = unpackPopup_.observing = false;
        unpackPopup_.error = "Unpack observation expired because the debugger target changed.";
        unpackEngine_.cancel();
        return;
    }
    if (unpackPopup_.waitingForInitialBreak) {
        if (!snap.attached()) {
            unpackPopup_.error = "The debug session ended before the unpack probe initialized.";
            unpackPopup_.waitingForInitialBreak = false;
            return;
        }
        if (snap.state != DbgState::Paused) return;
        const DbgModule* main = unpackMainModule(snap, ctx_.staticBinary().path());
        if (!main || !main->base) {
            unpackPopup_.error = "The paused process main module does not match the loaded target.";
            unpackPopup_.waitingForInitialBreak = false;
            return;
        }
        uint64_t size = main->size;
        if (!size) {
            for (const auto& s : ctx_.staticBinary().sections())
                size = std::max<uint64_t>(size, s.virtualAddress + std::max(s.virtualSize, s.rawSize));
        }
        size = std::min<uint64_t>(size, 512ull * 1024ull * 1024ull);
        if (!size || main->base > UINT64_MAX - size) {
            unpackPopup_.error = "The main module has no safe mapped image range.";
            unpackPopup_.waitingForInitialBreak = false;
            return;
        }
        Registers regs = snap.regs;
        if (!regs.rip) ctx_.debug.sampleExecutionContext(regs);
        unpackPopup_.moduleBase = main->base;
        unpackPopup_.moduleSize = size;
        const uint64_t probeSize = std::min<uint64_t>(size, 64ull * 1024ull * 1024ull);
        if (!readMappedImage(ctx_.debug, main->base, probeSize,
                             unpackPopup_.previousImage, 64ull * 1024ull * 1024ull,
                             &unpackPopup_.previousValidPages)) {
            unpackPopup_.error = "No readable bytes were captured from the main module.";
            unpackPopup_.waitingForInitialBreak = false;
            return;
        }
        const size_t pages = (unpackPopup_.previousImage.size() + 0xfff) / 0x1000;
        unpackPopup_.writtenPages.assign(pages, 0);
        unpackPopup_.executablePages.assign(pages, 0);
        for (const auto& rg : ctx_.debug.regions()) if (rg.exec && rg.size && rg.base <= UINT64_MAX - rg.size) {
            const uint64_t lo = std::max(main->base, rg.base);
            const uint64_t hi = std::min(main->base + probeSize, rg.base + rg.size);
            for (uint64_t at = lo; at < hi; at += 0x1000)
                unpackPopup_.executablePages[static_cast<size_t>((at - main->base) / 0x1000)] = 1;
        }
        unpackEngine_.begin(static_cast<UnpackStrategy>(unpackPopup_.strategy),
                            { main->base, size }, regs.rsp);
        const uint64_t now = GetTickCount64();
        UnpackObservation first;
        first.timestampMs = 0;
        first.rip = regs.rip;
        first.rsp = regs.rsp;
        first.imageEntropy = sampledEntropy(unpackPopup_.previousImage,
                                            &unpackPopup_.previousValidPages);
        for (const auto& rg : ctx_.debug.regions())
            if (regs.rip >= rg.base && regs.rip - rg.base < rg.size) {
                first.executionRegion = { rg.base, rg.size };
                first.regionExecutable = rg.exec;
                first.regionPrivate = rg.type == MEM_PRIVATE;
                first.regionImageBacked = rg.type == MEM_IMAGE;
                break;
            }
        unpackEngine_.observe(first);
        unpackPopup_.startedTick = unpackPopup_.lastProbeTick = now;
        unpackPopup_.previousRip = regs.rip;
        unpackPopup_.baselineRsp = regs.rsp;
        unpackPopup_.hasPreviousRip = true;
        unpackPopup_.lastExceptionSequence = snap.exceptionSequence;
        unpackPopup_.waitingForInitialBreak = false;
        unpackPopup_.observing = unpackPopup_.autoRun;
        if (regs.rip >= main->base && regs.rip - main->base < size)
            formatHexU64(unpackPopup_.manualOep, sizeof(unpackPopup_.manualOep), regs.rip);
        else
            unpackPopup_.manualOep[0] = '\0'; // the initial system break is normally in ntdll
        if (unpackPopup_.autoRun) {
            unpackPopup_.runStartedTick = now;
            ctx_.debug.cont();
        }
        return;
    }

    if (!unpackPopup_.observing) return;
    if (!snap.attached() || snap.state == DbgState::Terminated) {
        unpackEngine_.cancel();
        unpackPopup_.observing = false;
        unpackPopup_.result = {};
        unpackPopup_.result.rawMappedImage = unpackPopup_.previousImage;
        unpackPopup_.result.repairs.failureArtifactOnly = true;
        unpackPopup_.result.issues.push_back({ PeUnpackSeverity::Error, "process-exit",
            "The debuggee exited before a final paused capture could be reconstructed." });
        unpackPopup_.result.report =
            "Adaptive unpack capture\nresult: raw failure artifact only\n"
            "reason: process exited before final reconstruction\n";
        unpackPopup_.error = "The process exited. The last readable probe remains available as a failure artifact.";
        return;
    }
    const uint64_t now = GetTickCount64();
    const bool finalPausedSample = snap.state != DbgState::Running;
    if (finalPausedSample) {
        if (unpackPopup_.runStartedTick) {
            unpackPopup_.accumulatedRunMs += now - unpackPopup_.runStartedTick;
            unpackPopup_.runStartedTick = 0;
        }
        unpackPopup_.pauseRequested = false;
        unpackPopup_.observing = false;
    }
    const uint64_t runningMs = unpackPopup_.accumulatedRunMs +
        (unpackPopup_.runStartedTick ? now - unpackPopup_.runStartedTick : 0);
    if (!finalPausedSample && unpackPopup_.autoPause &&
        runningMs >= static_cast<uint64_t>(unpackPopup_.timeoutMs) &&
        !unpackPopup_.pauseRequested) {
        // Enforce the run-free bound before any context or memory operation that
        // can fail. A target must not run forever merely because sampling failed.
        unpackPopup_.pauseRequested = true;
        ctx_.debug.pause();
    }
    if (!finalPausedSample &&
        now - unpackPopup_.lastProbeTick < static_cast<uint64_t>(unpackPopup_.intervalMs)) return;
    unpackPopup_.lastProbeTick = now;

    std::vector<Registers> contexts = ctx_.debug.sampleExecutionContexts(32);
    if (contexts.empty()) return;
    const Registers regs = contexts.front();
    std::vector<uint8_t> current;
    std::vector<uint8_t> currentValidPages;
    const uint64_t probeSize = std::min<uint64_t>(unpackPopup_.moduleSize, 64ull * 1024ull * 1024ull);
    if (!readMappedImage(ctx_.debug, unpackPopup_.moduleBase, probeSize, current,
                         64ull * 1024ull * 1024ull, &currentValidPages)) return;
    const size_t pages = (current.size() + 0xfff) / 0x1000;
    if (unpackPopup_.writtenPages.size() != pages) unpackPopup_.writtenPages.assign(pages, 0);
    std::vector<uint8_t> nowExec(pages, 0);
    UnpackRange executionRegion{};
    bool regionExec = false, regionPrivate = false, regionImage = false;
    const std::vector<MemRegion> currentRegions = ctx_.debug.regions();
    for (const auto& rg : currentRegions) {
        if (regs.rip >= rg.base && regs.rip - rg.base < rg.size) {
            executionRegion = { rg.base, rg.size };
            regionExec = rg.exec; regionPrivate = rg.type == MEM_PRIVATE; regionImage = rg.type == MEM_IMAGE;
        }
        if (!rg.exec || !rg.size || rg.base > UINT64_MAX - rg.size) continue;
        const uint64_t lo = std::max(unpackPopup_.moduleBase, rg.base);
        const uint64_t hi = std::min(unpackPopup_.moduleBase + probeSize, rg.base + rg.size);
        for (uint64_t at = lo; at < hi; at += 0x1000)
            nowExec[static_cast<size_t>((at - unpackPopup_.moduleBase) / 0x1000)] = 1;
    }
    uint64_t changed = 0;
    uint32_t changedPages = 0;
    for (size_t page = 0; page < pages; ++page) {
        if (page >= currentValidPages.size() || !currentValidPages[page] ||
            page >= unpackPopup_.previousValidPages.size() || !unpackPopup_.previousValidPages[page])
            continue;
        const size_t lo = page * 0x1000;
        const size_t hi = std::min(current.size(), lo + 0x1000);
        bool dirty = false;
        for (size_t i = lo; i < hi; ++i) if (i >= unpackPopup_.previousImage.size() ||
                                               current[i] != unpackPopup_.previousImage[i]) {
            dirty = true; ++changed;
        }
        if (dirty) { ++changedPages; unpackPopup_.writtenPages[page] = 1; }
    }
    const bool ripInProbe = regs.rip >= unpackPopup_.moduleBase &&
                            regs.rip - unpackPopup_.moduleBase < probeSize;
    const size_t ripPage = ripInProbe ? static_cast<size_t>((regs.rip - unpackPopup_.moduleBase) / 0x1000) : 0;
    const bool newExec = ripInProbe && ripPage < nowExec.size() && nowExec[ripPage] &&
                         (ripPage >= unpackPopup_.executablePages.size() || !unpackPopup_.executablePages[ripPage]);
    const bool wasWritten = ripInProbe && ripPage < unpackPopup_.writtenPages.size() && unpackPopup_.writtenPages[ripPage];

    UnpackObservation obs;
    obs.timestampMs = runningMs;
    obs.rip = regs.rip; obs.rsp = regs.rsp;
    obs.imageEntropy = sampledEntropy(current, &currentValidPages);
    obs.changedBytes = changed; obs.changedPages = changedPages;
    obs.executionRegion = executionRegion;
    obs.regionExecutable = regionExec;
    obs.regionPrivate = regionPrivate;
    obs.regionImageBacked = regionImage;
    obs.pageWasWritten = wasWritten;
    obs.protectionBecameExecutable = newExec;
    const uint64_t stackDistance = regs.rsp >= unpackPopup_.baselineRsp
        ? regs.rsp - unpackPopup_.baselineRsp : unpackPopup_.baselineRsp - regs.rsp;
    obs.stackNearBaseline = stackDistance <= 0x1000;
    const bool sampledReturn = unpackPopup_.hasPreviousRip &&
        !(unpackPopup_.previousRip >= unpackPopup_.moduleBase &&
          unpackPopup_.previousRip - unpackPopup_.moduleBase < unpackPopup_.moduleSize) &&
        regs.rip >= unpackPopup_.moduleBase && regs.rip - unpackPopup_.moduleBase < unpackPopup_.moduleSize;
    obs.controlTransfer = unpackPopup_.hasPreviousRip && ((unpackPopup_.previousRip >> 12) != (regs.rip >> 12));
    // Classic ESP/RSP unpacking stubs often remain in the same PE image, so the
    // meaningful return signal is a restored stack plus a transfer into bytes
    // seen changing—not merely an outside-to-inside module transition.
    obs.returnedToOriginalImage = sampledReturn ||
        (obs.stackNearBaseline && obs.controlTransfer && wasWritten);
    // Periodic samples are not exact branch edges; feeding adjacent samples as
    // source/target pairs would invent VM loops. Exact transition producers can
    // use these fields, while this sampler contributes honest hot-RIP evidence.
    obs.hasTransitionSource = false;
    // The debug event identifies a fault site, not the eventual SEH/VEH handler
    // entry. Keep the sequence for diagnostics but do not mislabel a later polled
    // RIP as an exact handler.
    obs.exceptionHandlerEntry = false;
    unpackPopup_.lastExceptionSequence = snap.exceptionSequence;
    obs.runFreeStop = runningMs >= static_cast<uint64_t>(unpackPopup_.timeoutMs);
    unpackEngine_.observe(obs);
    // Packers commonly hand off to a worker. Sample every live thread (bounded)
    // against the same bounded page probe; only the primary carries interval
    // deltas/run-free state so aggregate entropy/write counters are not multiplied.
    for (size_t ci = 1; ci < contexts.size(); ++ci) {
        UnpackObservation worker = obs;
        worker.rip = contexts[ci].rip;
        // A worker thread has a different stack origin; zero RSP prevents the
        // engine from comparing it with the main thread's initial baseline.
        worker.rsp = 0;
        worker.changedBytes = 0;
        worker.changedPages = 0;
        worker.executionRegion = {};
        worker.regionExecutable = worker.regionPrivate = worker.regionImageBacked = false;
        for (const auto& rg : currentRegions)
            if (worker.rip >= rg.base && worker.rip - rg.base < rg.size) {
                worker.executionRegion = { rg.base, rg.size };
                worker.regionExecutable = rg.exec;
                worker.regionPrivate = rg.type == MEM_PRIVATE;
                worker.regionImageBacked = rg.type == MEM_IMAGE;
                break;
            }
        const bool inProbe = worker.rip >= unpackPopup_.moduleBase &&
                             worker.rip - unpackPopup_.moduleBase < probeSize;
        const size_t page = inProbe ? static_cast<size_t>((worker.rip - unpackPopup_.moduleBase) / 0x1000) : 0;
        worker.pageWasWritten = inProbe && page < unpackPopup_.writtenPages.size() && unpackPopup_.writtenPages[page];
        worker.protectionBecameExecutable = inProbe && page < nowExec.size() && nowExec[page] &&
            (page >= unpackPopup_.executablePages.size() || !unpackPopup_.executablePages[page]);
        worker.stackNearBaseline = false;
        worker.returnedToOriginalImage = false;
        worker.controlTransfer = false;
        worker.hasTransitionSource = false;
        worker.exceptionHandlerEntry = false;
        worker.runFreeStop = false;
        unpackEngine_.observe(worker);
    }
    unpackPopup_.previousImage.swap(current);
    unpackPopup_.previousValidPages.swap(currentValidPages);
    unpackPopup_.executablePages.swap(nowExec);
    unpackPopup_.previousRip = regs.rip;
    unpackPopup_.hasPreviousRip = true;

    const UnpackReport report = unpackEngine_.report();
    const bool confident = report.status.hasBestOep && report.status.bestConfidence == UnpackConfidence::High;
    if (!finalPausedSample && unpackPopup_.autoPause && (confident || obs.runFreeStop)) {
        unpackPopup_.pauseRequested = true;
        ctx_.debug.pause();
    }
}

void App::rebuildUnpackImage(uint64_t oep, bool hasOep) {
    unpackPopup_.error.clear();
    DbgSnapshot snap = ctx_.debug.snapshot();
    uint64_t dumpBase = unpackPopup_.moduleBase;
    uint64_t dumpSize = unpackPopup_.moduleSize;
    bool originalLayout = true;
    if (hasOep && !(oep >= dumpBase && oep - dumpBase < dumpSize)) {
        originalLayout = false;
        dumpBase = dumpSize = 0;
        const std::vector<MemRegion> regions = ctx_.debug.regions();
        for (const auto& region : regions) {
            if (!region.read || !region.size || region.type == MEM_IMAGE ||
                oep < region.base || oep - region.base >= region.size) continue;
            dumpBase = region.allocationBase ? region.allocationBase : region.base;
            uint64_t allocationEnd = dumpBase;
            for (const auto& part : regions) {
                const uint64_t partAllocation = part.allocationBase ? part.allocationBase : part.base;
                if (partAllocation != dumpBase || !part.size || part.base > UINT64_MAX - part.size) continue;
                allocationEnd = std::max(allocationEnd, part.base + part.size);
            }
            if (allocationEnd <= dumpBase || allocationEnd - dumpBase > 512ull * 1024ull * 1024ull) {
                dumpBase = dumpSize = 0;
                break;
            }
            dumpSize = allocationEnd - dumpBase;
            // A private/manual-mapped payload often carries a complete PE at the
            // allocation base. Prefer its declared SizeOfImage so neighboring
            // allocations are not swept into the dump; non-PE allocations still
            // fall through to a useful raw failure artifact.
            uint8_t dos[0x40]{};
            if (ctx_.debug.readMemory(dumpBase, dos, sizeof(dos)) == sizeof(dos) &&
                dos[0] == 'M' && dos[1] == 'Z') {
                uint32_t pe = 0; std::memcpy(&pe, dos + 0x3c, 4);
                uint32_t sig = 0, sizeImage = 0;
                if (pe < 0x100000 && ctx_.debug.readMemory(dumpBase + pe, &sig, 4) == 4 &&
                    sig == 0x00004550 &&
                    ctx_.debug.readMemory(dumpBase + pe + 24 + 56, &sizeImage, 4) == 4 &&
                    sizeImage && sizeImage <= dumpSize)
                    dumpSize = sizeImage;
            }
            break;
        }
    }
    if (!originalLayout && (!dumpBase || !dumpSize)) {
        unpackPopup_.result = {};
        unpackPopup_.error =
            "The external OEP is not inside a bounded readable private/mapped allocation; image modules are intentionally rejected.";
        return;
    }
    std::vector<uint8_t> mapped;
    std::vector<uint8_t> validPages;
    if (snap.attached() && dumpBase && dumpSize)
        readMappedImage(ctx_.debug, dumpBase, dumpSize,
                        mapped, 512ull * 1024ull * 1024ull, &validPages);
    if (mapped.empty() && originalLayout) {
        mapped = unpackPopup_.previousImage;
        validPages = unpackPopup_.previousValidPages;
    }
    PeUnpackOptions options;
    options.runtimeImageBase = dumpBase;
    options.oepVA = oep;
    options.hasOep = hasOep;
    options.observedImports = recoverLiveImports(ctx_, dumpBase, mapped, snap, originalLayout);
    unpackPopup_.result = RebuildMappedPe(mapped, options);
    std::string coverageReason;
    if (unpackPopup_.result.success && !mappedPeCoverageComplete(mapped, validPages, coverageReason)) {
        unpackPopup_.result.success = false;
        unpackPopup_.result.repairs.failureArtifactOnly = true;
        unpackPopup_.result.issues.push_back({ PeUnpackSeverity::Error, "partial-capture",
            coverageReason + "; refusing to label the rebuilt file runnable." });
        unpackPopup_.result.report += "\nresult downgraded: raw failure artifact only\nreason: " +
                                      coverageReason + "\n";
    }
    if (unpackPopup_.result.success && hasOep &&
        (oep < dumpBase || oep - dumpBase >= mapped.size() ||
         (oep - dumpBase) / 0x1000 >= validPages.size() ||
         !validPages[static_cast<size_t>((oep - dumpBase) / 0x1000)])) {
        unpackPopup_.result.success = false;
        unpackPopup_.result.repairs.failureArtifactOnly = true;
        unpackPopup_.result.issues.push_back({ PeUnpackSeverity::Error, "unreadable-oep",
            "The selected OEP page was not fully readable; refusing to label the rebuilt file runnable." });
        unpackPopup_.result.report +=
            "\nresult downgraded: raw failure artifact only\nreason: selected OEP page was unreadable\n";
    }
    if (unpackPopup_.result.success) {
        if (hasOep) {
            if (originalLayout) {
                unpackEngine_.selectManualOep(oep, unpackPopup_.accumulatedRunMs,
                                              "Analyst-approved dump entry");
            } else {
                unpackEngine_.selectValidatedExternalOep(
                    oep, { dumpBase, dumpSize }, unpackPopup_.accumulatedRunMs,
                    "Analyst-approved OEP in a fully captured and reconstructed private image");
            }
        }
        unpackEngine_.complete(oep, hasOep);
        ui::Toast(unpackPopup_.result.issues.empty() ? ui::ToastKind::Success : ui::ToastKind::Warn,
                  "Mapped PE rebuilt; review the repair report before saving.");
    } else {
        unpackPopup_.error = "Runnable PE reconstruction was refused. Save the raw capture and report for manual recovery.";
    }
}

bool App::saveUnpackArtifacts(bool loadAfterSave) {
    const bool success = unpackPopup_.result.success;
    const std::vector<uint8_t>& bytes = success ? unpackPopup_.result.image
                                                : unpackPopup_.result.rawMappedImage;
    if (bytes.empty()) return false;
    std::string leaf = pathLeafLower(ctx_.staticBinary().path());
    size_t dot = leaf.find_last_of('.');
    if (dot != std::string::npos) leaf.resize(dot);
    leaf += success ? ".unpacked.exe" : ".unpack-failure.mapped.bin";
    std::ostringstream reportFile;
    reportFile << unpackPopup_.result.report;
    const UnpackReport telemetry = unpackEngine_.report();
    reportFile << "\ntelemetry samples: " << telemetry.status.totalSamples
               << "\nOEP candidates: " << telemetry.candidates.size()
               << "\nentropy settled: " << (telemetry.entropy.settled ? "yes" : "no")
               << "\nVM-like trace: " << (telemetry.vmTrace.vmLike ? "yes" : "no")
               << " (score " << telemetry.vmTrace.score << ")\n";
    reportFile << "entropy window: " << telemetry.entropy.windowStartMs << ".."
               << telemetry.entropy.windowEndMs << " ms, spread " << telemetry.entropy.spread
               << ", changed bytes/pages " << telemetry.entropy.changedBytes << "/"
               << telemetry.entropy.changedPages << "\n";
    for (const auto& candidate : telemetry.candidates) {
        reportFile << "OEP 0x" << std::hex << candidate.va << std::dec
                   << ": score " << candidate.score << " ("
                   << UnpackConfidenceName(candidate.confidence) << "), observations "
                   << candidate.observations << "\n";
        for (const auto& evidence : candidate.evidence)
            reportFile << "  +" << evidence.score << " " << OepEvidenceName(evidence.kind)
                       << " x" << evidence.occurrences << ": " << evidence.detail << "\n";
    }
    for (const auto& evidence : telemetry.vmTrace.evidence)
        reportFile << "VM evidence: " << evidence << "\n";
    for (const auto& rip : telemetry.vmTrace.hotRips)
        reportFile << "hot RIP 0x" << std::hex << rip.rip << std::dec
                   << ": " << rip.hits << " hit(s)\n";
    for (const auto& handler : telemetry.vmTrace.handlers)
        reportFile << "handler 0x" << std::hex << handler.rip << std::dec
                   << ": " << handler.hits << " hit(s), fan-in " << handler.fanIn << "\n";
    for (const auto& loop : telemetry.vmTrace.loops)
        reportFile << "loop 0x" << std::hex << loop.from << " -> 0x" << loop.to
                   << std::dec << ": " << loop.hits << " hit(s)\n";
    const auto document = ctx_.staticDocumentId();
    const auto generation = ctx_.staticImageGeneration();
    const auto revision = ctx_.staticBinary().imageRevision();
    std::string message;
    const bool queued = ctx_.saveBytesFile(leaf, bytes, message,
        success ? L"PE executable\0*.exe\0All Files\0*.*\0" : L"Raw mapped image\0*.bin\0All Files\0*.*\0",
        success ? L"exe" : L"bin",
        [this, document, generation, revision, success, loadAfterSave](const ArtifactWriteResult& saved) {
            if (!saved.success || !saved.warning.empty() || !success || !loadAfterSave ||
                ctx_.staticDocumentId() != document || ctx_.staticImageGeneration() != generation || ctx_.staticBinary().imageRevision() != revision ||
                ctx_.binaryLoadPending()) return;
            std::string path;
            if (utf8FromWide(saved.path.c_str(), path) && ctx_.beginBinaryLoadPath(path)) {
                ctx_.requestedTab = "Binary View";
                pendingDocumentLoadOwner_ = PendingDocumentLoadOwner::AdaptiveUnpack;
            } else ui::Toast(ui::ToastKind::Error, "Artifact saved, but its background load could not start.");
        }, ".unpack-report.txt", reportFile.str());
    if (!queued && !message.empty()) unpackPopup_.error = message;
    if (queued) ui::Toast(ui::ToastKind::Info, message);
    return queued;
}

void App::renderUnpackPopup() {
    if (unpackPopup_.open) {
        if (unpackPopup_.launchRequestId)
            ctx_.debug.cancelLifecycle(unpackPopup_.launchRequestId);
        const bool contained = unpackPopup_.containedLaunch;
        unpackPopup_ = {};
        unpackPopup_.containedLaunch = contained;
        unpackPopup_.autoRun = unpackPopup_.autoPause = unpackPopup_.loadAfterSave = true;
        unpackPopup_.intervalMs = 300; unpackPopup_.timeoutMs = 30000;
        unpackEngine_.reset();
        ImGui::OpenPopup("Adaptive Unpacker");
    }
    sampleUnpackObservation();
    prepareWorkbenchDialog(760.0f, 680.0f, ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Adaptive Unpacker", nullptr, ImGuiWindowFlags_NoSavedSettings)) {
        if ((unpackPopup_.launchRequestId || unpackPopup_.observing || unpackPopup_.waitingForInitialBreak) &&
            !ImGui::IsPopupOpen("Adaptive Unpacker")) {
            const DbgSnapshot snap = ctx_.debug.snapshot();
            if (unpackPopup_.launchRequestId)
                ctx_.debug.cancelLifecycle(unpackPopup_.launchRequestId);
            else if (snap.state == DbgState::Running)
                ctx_.debug.pauseForSession(unpackPopup_.target);
            unpackPopup_.launchRequestId = 0;
            unpackPopup_.observing = unpackPopup_.waitingForInitialBreak = false;
            unpackEngine_.cancel();
        }
        return;
    }
    if (unpackPopup_.closeAfterDocumentLoad) {
        unpackPopup_.closeAfterDocumentLoad = false;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    const DbgSnapshot snap = ctx_.debug.snapshot();
    const bool active = unpackPopup_.launchRequestId || unpackPopup_.observing || unpackPopup_.waitingForInitialBreak;
    ImGui::TextWrapped("Adaptive live unpacking fuses stack-return, write-to-execute, entropy-settle and run-free evidence. OEP choices remain scored hypotheses until you approve a dump.");
    if (unpackPopup_.launchRequestId) {
        ImGui::TextDisabled("Starting unpack target; waiting for debugger initialization...");
        if (ImGui::SmallButton("Cancel unpack startup"))
            ctx_.debug.cancelLifecycle(unpackPopup_.launchRequestId);
    }
    ImGui::Spacing();
    const char* strategies[] = { "Hybrid (adaptive)", "Stack return (ESP/RSP)", "Write -> execute (NX)",
                                 "Entropy settle", "Run free", "Manual OEP" };
    ImGui::BeginDisabled(active);
    ImGui::Combo("Strategy", &unpackPopup_.strategy, strategies, IM_ARRAYSIZE(strategies));
    ImGui::Checkbox("Contain new launch in a Windows job", &unpackPopup_.containedLaunch);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("One process, kill-on-close containment. This limits child-process escape and lifetime; it does not virtualize filesystem or network access.");
    ImGui::Checkbox("Continue automatically after initial loader capture", &unpackPopup_.autoRun);
    ImGui::Checkbox("Pause on high-confidence evidence / timeout", &unpackPopup_.autoPause);
    ImGui::SetNextItemWidth(180.0f * theme::UiScale());
    ImGui::InputInt("Probe interval (ms)", &unpackPopup_.intervalMs, 50, 250);
    unpackPopup_.intervalMs = std::clamp(unpackPopup_.intervalMs, 100, 5000);
    ImGui::SetNextItemWidth(180.0f * theme::UiScale());
    ImGui::InputInt("Run-free timeout (ms)", &unpackPopup_.timeoutMs, 1000, 5000);
    unpackPopup_.timeoutMs = std::clamp(unpackPopup_.timeoutMs, 1000, 10 * 60 * 1000);
    ImGui::EndDisabled();

    const bool targetOk = ctx_.binaryLaunchable();
    const UnpackState engineState = unpackEngine_.state();
    const bool canStartFresh = engineState == UnpackState::Idle ||
        engineState == UnpackState::Completed || engineState == UnpackState::Failed ||
        engineState == UnpackState::Cancelled;
    ImGui::BeginDisabled(active || ctx_.debug.lifecycleSnapshot().busy || !canStartFresh || !targetOk ||
                         (snap.attached() && snap.state == DbgState::Running));
    if (ImGui::Button("Start observation", ImVec2(150.0f * theme::UiScale(), 0))) beginUnpackObservation();
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (unpackPopup_.observing && !unpackPopup_.pauseRequested) {
        if (ImGui::Button("Pause and review")) { unpackPopup_.pauseRequested = true; ctx_.debug.pause(); }
    } else if (!active && snap.state == DbgState::Paused && unpackEngine_.state() != UnpackState::Idle &&
               unpackEngine_.state() != UnpackState::Completed) {
        if (ImGui::Button("Resume observation")) {
            unpackPopup_.observing = true;
            unpackPopup_.runStartedTick = unpackPopup_.lastProbeTick = GetTickCount64();
            ctx_.debug.cont();
        }
    }
    if (!targetOk) {
        if (!ctx_.binaryDebugArchitectureMatches())
            ImGui::TextColored(theme::col::warn(),
                "Adaptive Unpack requires a matching x86/x64 PE machine/mode (active: %s). Static recovery remains available.",
                ArchName(ctx_.staticArch()));
        else
            ImGui::TextColored(theme::col::warn(), "Open an on-disk PE executable (not a DLL) to use this workflow.");
    }
    if (snap.containedJob) ImGui::TextColored(theme::col::good(), "Target is running in the unpack containment job.");
    if (!unpackPopup_.error.empty()) ImGui::TextColored(theme::col::bad(), "%s", unpackPopup_.error.c_str());

    const UnpackReport telemetry = unpackEngine_.report();
    ImGui::SeparatorText("Evidence");
    ImGui::Text("State: %s   Samples: %llu   Candidates: %zu", UnpackStateName(telemetry.status.state),
                static_cast<unsigned long long>(telemetry.status.totalSamples), telemetry.candidates.size());
    ImGui::Text("Entropy %.3f..%.3f (spread %.3f)   %s", telemetry.entropy.minimum,
                telemetry.entropy.maximum, telemetry.entropy.spread,
                telemetry.entropy.settled ? "SETTLED" : "changing");
    if (telemetry.vmTrace.vmLike)
        ImGui::TextColored(theme::col::warn(), "VM-like dispatcher/handler behavior: score %d/100", telemetry.vmTrace.score);
    uint64_t selectedCandidateVa = 0;
    const bool hasSelectedCandidate = parseHexU64(unpackPopup_.manualOep, selectedCandidateVa);
    if (ImGui::BeginChild("##unpackCandidates", ImVec2(0, 190.0f * theme::UiScale()), ImGuiChildFlags_Borders)) {
        for (int i = 0; i < static_cast<int>(telemetry.candidates.size()); ++i) {
            const auto& c = telemetry.candidates[i];
            char label[160];
            std::snprintf(label, sizeof(label), "0x%llX  score %d  %s##oep%d",
                          static_cast<unsigned long long>(c.va), c.score,
                          UnpackConfidenceName(c.confidence), i);
            if (ImGui::Selectable(label, hasSelectedCandidate && selectedCandidateVa == c.va)) {
                formatHexU64(unpackPopup_.manualOep, sizeof(unpackPopup_.manualOep), c.va);
            }
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                for (const auto& e : c.evidence)
                    ImGui::Text("+%d %s (%u): %s", e.score, OepEvidenceName(e.kind), e.occurrences, e.detail.c_str());
                ImGui::EndTooltip();
            }
        }
        if (telemetry.candidates.empty()) ImGui::TextDisabled("No OEP candidate yet. Keep running, or enter one manually.");
    }
    ImGui::EndChild();

    ImGui::SetNextItemWidth(220.0f * theme::UiScale());
    ImGui::InputText("OEP VA", unpackPopup_.manualOep, sizeof(unpackPopup_.manualOep), ImGuiInputTextFlags_CharsHexadecimal);
    uint64_t oep = 0;
    const bool hasOep = parseHexU64(unpackPopup_.manualOep, oep);
    const bool oepInOriginal = hasOep && oep >= unpackPopup_.moduleBase &&
        oep - unpackPopup_.moduleBase < unpackPopup_.moduleSize;
    if (hasOep && !oepInOriginal)
        ImGui::TextColored(theme::col::warn(),
            "OEP is outside the original image; only its containing private/mapped allocation will be probed for a PE (otherwise saved raw). ");
    ImGui::BeginDisabled(active || snap.state != DbgState::Paused || !unpackPopup_.moduleBase || !hasOep);
    if (ImGui::Button("Rebuild process image", ImVec2(180.0f * theme::UiScale(), 0))) {
        rebuildUnpackImage(oep, true);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(active || snap.state != DbgState::Paused || !unpackPopup_.moduleBase);
    if (ImGui::Button("Dump with current entry")) rebuildUnpackImage(0, false);
    ImGui::EndDisabled();

    if (!unpackPopup_.result.image.empty() || !unpackPopup_.result.rawMappedImage.empty()) {
        ImGui::SeparatorText("Reconstruction");
        const auto& rr = unpackPopup_.result.repairs;
        ImGui::TextColored(unpackPopup_.result.success ? theme::col::good() : theme::col::bad(),
                           "%s", unpackPopup_.result.success ? "Runnable disk-layout PE rebuilt" : "Raw failure artifact only");
        ImGui::Text("Sections %u | relocs %u | imports %u (+%u restored) | load-config fixed/cleared %u/%u",
                    rr.sectionsRebuilt, rr.relocationEntriesNormalized, rr.importsRebuilt,
                    rr.importSlotsRestored, rr.loadConfigPointersRepaired, rr.loadConfigPointersCleared);
        for (const auto& issue : unpackPopup_.result.issues) {
            ImVec4 col = issue.severity == PeUnpackSeverity::Error ? theme::col::bad() :
                         issue.severity == PeUnpackSeverity::Warning ? theme::col::warn() : theme::col::muted();
            ImGui::TextColored(col, "%s: %s", issue.code.c_str(), issue.message.c_str());
        }
        if (unpackPopup_.result.success)
            ImGui::Checkbox("Load saved unpacked PE into analysis", &unpackPopup_.loadAfterSave);
        if (ImGui::Button(unpackPopup_.result.success ? "Save unpacked PE + report" : "Save failure capture + report"))
            saveUnpackArtifacts(unpackPopup_.loadAfterSave);
    }
    ImGui::Separator();
    if (ImGui::Button("Close")) {
        if (active) {
            if (unpackPopup_.launchRequestId)
                ctx_.debug.cancelLifecycle(unpackPopup_.launchRequestId);
            else if (snap.state == DbgState::Running)
                ctx_.debug.pauseForSession(unpackPopup_.target);
            unpackEngine_.cancel();
        }
        unpackPopup_.launchRequestId = 0;
        unpackPopup_.observing = unpackPopup_.waitingForInitialBreak = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void App::rememberInvestigationQuery(std::string query,
                                     InvestigationIdentity identity) {
    const size_t first = query.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return;
    const size_t last = query.find_last_not_of(" \t\r\n");
    query = query.substr(first, last - first + 1);
    if (query.size() > 512) query.resize(512);

    investigationRecentQueries_.erase(
        std::remove_if(investigationRecentQueries_.begin(),
                       investigationRecentQueries_.end(),
                       [&](const InvestigationRecentQuery& item) {
                           return item.identity == identity &&
                                  queryEqualsInsensitive(item.query, query);
                       }),
        investigationRecentQueries_.end());
    investigationRecentQueries_.insert(investigationRecentQueries_.begin(),
                                       { identity, std::move(query) });
    if (investigationRecentQueries_.size() > 32)
        investigationRecentQueries_.resize(32);
    ++investigationRecentRevision_;
    if (!investigationRecentRevision_) ++investigationRecentRevision_;
    savePrefs();
}

void App::maintainInvestigationWorkspace() {
    if (!binaryView_) return;
    binaryView_->advanceInvestigationSnapshot(
        ctx_, investigationRecentQueries_, investigationRecentRevision_);

    const uint64_t generation = binaryView_->investigationSnapshotGeneration();
    const auto snapshot = binaryView_->investigationSnapshot();
    if (generation && snapshot && generation != investigationSubmittedGeneration_) {
        investigation_.beginSession(generation, snapshot);
        investigationSubmittedGeneration_ = generation;
        investigationSubmittedLiveTarget_ = snapshot->liveTarget;
    }
    palette_.updateInvestigationSession(&investigation_,
                                        investigationSubmittedGeneration_,
                                        investigationSubmittedLiveTarget_);

    const InvestigationServicePending pending = investigation_.pending();
    if (binaryView_->investigationSnapshotBuilding() || pending.buildQueued ||
        pending.searchQueued || pending.building || pending.searching)
        ctx_.wantContinuousRedraw = true;
}

// Build the Ctrl+K command palette. App actions stay immediate; all target-data
// matching comes from the worker-owned unified investigation index.
void App::openCommandPalette(const DbgSnapshot& dbg) {
    using ui::PaletteItem;
    std::vector<PaletteItem> items;
    const DebugTargetIdentity paletteTarget{ dbg.pid, dbg.sessionGeneration };
    auto add = [&](const char* icon, const char* label, const char* detail,
                   std::function<void()> fn, const char* searchAliases = nullptr) {
        PaletteItem it;
        it.label  = label;
        it.detail = detail ? detail : "";
        it.searchAliases = searchAliases ? searchAliases : "";
        it.icon   = icon;
        it.run    = std::move(fn);
        items.push_back(std::move(it));
    };

    // File
    add(DS_ICON_FOLDER, "Open Binary...", "Ctrl+O", [this] { openFileDialog(); });
    add(DS_ICON_FOLDER, "Open as Raw...", "shellcode / firmware", [this] { openRawFileDialog(); });
    if (ctx_.staticBinary().loaded()) {
        add(DS_ICON_SEARCH, "Open Crackme Triage", "auto-search endpoints / server trail", [this] {
            ctx_.openCrackmeTriage(TriageWorkspaceView::StartHere);
        });
        add(DS_ICON_SEARCH, "Open Validation / Pro-State Checks",
            "authorization / existing license", [this] {
                ctx_.openCrackmeStartupEntitlementLead();
            },
            "premium already validated registered existing license entitlement activation remembered access");
        add(DS_ICON_SAVE, "Save Binary As (apply patches)...", "File", [this] { saveBinaryAs(); });
        if (!ctx_.staticCodeExport().pending()) {
            add(DS_ICON_SAVE, "Save ASM...", "whole program / current function", [this] {
                ctx_.requestedCodeExport = true;
                ctx_.requestedCodeExportFormat = CodeExportFormat::Assembly;
                ctx_.requestedTab = "Binary View";
            });
            if (ArchIsX86_32Or64(ctx_.staticArch()))
                add(DS_ICON_SAVE, "Save C...", "readable / self-contained compilable C", [this] {
                    ctx_.requestedCodeExport = true;
                    ctx_.requestedCodeExportFormat = CodeExportFormat::C;
                    ctx_.requestedTab = "Binary View";
                });
        }
        add(nullptr, "Export Analysis (Markdown / HTML)...", "File", [this] {
            ctx_.requestedExportAnalysis = true;
            ctx_.requestedTab = "Binary View";
        });
        add(DS_ICON_CANCEL, "Close Document", "File", [this] { closeBinary(); });
        if (ctx_.staticJavaInfo().jarSize > 0) {
            add(DS_ICON_SAVE, ctx_.staticJavaInfo().isJar ? "Extract Embedded JAR..." : "Extract Embedded ZIP...",
                "Java wrapper", [this] { extractEmbeddedJar(); });
        }
        if (!ctx_.staticJavaInfo().entries.empty()) {
            add(DS_ICON_FOLDER, "Browse Embedded Archive...", "open / extract entries",
                [this] { ctx_.requestedBrowseArchive = true; });
        }
    }

    // Capture the selected source once. Commands opened for one document or
    // debugger session must not silently act on a later cursor/owner.
    if (binaryView_) {
        using Action = BinaryViewTab::ContextAction;
        const auto target = binaryView_->cursorActionTarget(ctx_);
        auto addContext = [&](const char* label, Action action, const char* aliases) {
            std::string reason;
            if (!binaryView_->contextualActionAvailable(ctx_, action, target, reason)) return;
            add(nullptr, label, target.live ? "selected LIVE address" : "selected FILE address",
                [this, target, action] {
                    if (binaryView_) binaryView_->dispatchContextAction(ctx_, action, target);
                }, aliases);
        };
        addContext("Rename selected symbol...", Action::Rename, "name annotation N");
        addContext("Comment on selected address...", Action::Comment, "annotation semicolon");
        addContext("Bookmark selected address", Action::Bookmark, "bookmark annotation");
        addContext("Show selected address in Live Assembly", Action::ShowLive, "runtime ASLR debugger");
        addContext("Show selected address in Assembly", Action::ShowStatic, "static FILE ASLR");
        addContext("Run to cursor", Action::RunToCursor, "Ctrl F9 continue selected instruction");
    }

    // Debug (gated on the snapshot, reusing the toolbar's exact calls)
    const bool attached = dbg.attached();
    const bool paused   = dbg.state == DbgState::Paused;
    const bool running  = dbg.state == DbgState::Running;
    add(nullptr, "Hide Debugger / Anti-Anti-Debug...", "Debug policy", [this] {
        antiDebugPopupOpen_ = true;
    });
    add(nullptr, "Passive Process Dump...", "read-only capture", [this] {
        passiveDumpPopup_.open = true;
    });
    add(DS_ICON_LIGHTNING, "Open Live Observation", "Communications / Server Watch", [this] {
        ctx_.openLiveObservation();
    });
    add(nullptr, "Open Backtrace / Call Stack", "Where we came from / paused native thread", [this] {
        ctx_.requestedBacktrace = true;
        ctx_.requestedTab = "Binary View";
    }, "backtrace back trace stack trace caller return frames where came from");
    add(nullptr, "Open GameMaker / GML connection", "Communications", [this] {
        ctx_.requestedGameMakerConnection = true;
        ctx_.requestedTab = "Communications";
    }, "gamemaker vm data.win bytecode nubby");
    add(nullptr, ctx_.gmlExecutionMode ? "Use Native execution controls" : "Use GML execution controls",
        "Toolbar / F5 / F10 / F11", [this] { ctx_.gmlExecutionMode = !ctx_.gmlExecutionMode; });
    if (ctx_.staticBinary().loaded() && !ctx_.staticBinary().isMappedImage() &&
        (ctx_.staticBinary().format() == BinFormat::PE32 || ctx_.staticBinary().format() == BinFormat::PE32Plus)) {
        add(DS_ICON_LIGHTNING, "Static Packed-PE Recovery...", "PACKER_INFO / LZMA", [this] {
            staticUnpackPopup_.open = true;
        });
    }
    if (ctx_.staticBinary().loaded() && !ctx_.staticBinary().isMappedImage() && !ctx_.staticBinary().isDll() &&
        (ctx_.staticBinary().format() == BinFormat::PE32 || ctx_.staticBinary().format() == BinFormat::PE32Plus) &&
        ArchSupportsDebugger(ctx_.staticArch())) {
        add(DS_ICON_LIGHTNING, "Adaptive Unpack...", "OEP / dump / IAT repair",
            [this] { unpackPopup_.open = true; });
    }
    if (!attached && !ctx_.debug.lifecycleSnapshot().busy && ctx_.binaryLaunchable()) {
        add(DS_ICON_PLAY, "Launch & Debug", "break at entry", [this] {
            std::string err;
            if (!ctx_.launchAndDebug(err)) ui::Toast(ui::ToastKind::Error, "Launch failed: " + err);
        });
    }
    if (!attached && ctx_.binaryDllDebuggable()) {
        add(DS_ICON_PLAY, "Debug DLL...", "hosted launch", [this] {
            ctx_.requestedDebugDll = true;
        });
    }
    if (attached) {
        add(DS_ICON_MEMORY, "Inspect Live RIP in Memory Tools",
            "hex editor / regions / pointer scan",
            [this, rip = dbg.regs.rip, pid = dbg.pid,
             generation = dbg.sessionGeneration] {
                ctx_.openMemoryToolsAt(rip, pid, generation);
            }, "memory viewer hex process address cheat engine");
        add(DS_ICON_STOP, "Detach", "Debug", [this, paletteTarget] {
            ctx_.debug.requestDetach(paletteTarget);
        });
        const auto gml = ctx_.debug.gameMakerSnapshot();
        const bool gmlOwner = DebugTargetIdentityMatches(gml.target, paletteTarget);
        const bool gmlPaused = paused && gmlOwner && gml.state == GameMakerSessionState::Paused &&
            gml.stop && gml.stop->identity.tid == dbg.activeTid;
        if (ctx_.gmlExecutionMode && gmlOwner && gml.ready()) {
            auto addGml = [&](const char* label, const char* hotkey, GmlControlCommand command) {
                const GmlPauseIdentity owner = gmlPaused ? gml.stop->identity : GmlPauseIdentity{};
                add(nullptr, label, hotkey, [this, owner, command] {
                    std::string error;
                    if (!ctx_.debug.gameMakerCommand(command, owner, error)) ui::Toast(ui::ToastKind::Warn, error);
                });
            };
            if (running) addGml("Pause GML", "F5", GmlControlCommand::Pause);
            if (gmlPaused) {
                addGml("Continue GML", "F5", GmlControlCommand::Continue);
                addGml("Step Into GML", "F11", GmlControlCommand::StepInto);
                addGml("Step Over GML", "F10", GmlControlCommand::StepOver);
                addGml("Step Out GML", "Shift+F11", GmlControlCommand::StepOut);
            }
        } else if (!ctx_.gmlExecutionMode) {
            if (running) add(DS_ICON_PAUSE, "Pause Native", "F5", [this, paletteTarget] {
                ctx_.debug.pauseForSession(paletteTarget);
            });
            else if (!gmlPaused) add(DS_ICON_PLAY, "Continue Native", "F5", [this, paletteTarget] {
                ctx_.debug.continueForSession(paletteTarget);
            });
        }
        if (paused && !gmlPaused && !ctx_.gmlExecutionMode) {
            add(nullptr, "Step Into", "F11", [this, paletteTarget] {
                ctx_.debug.stepIntoForSession(paletteTarget);
            });
            add(nullptr, "Step Over", "F10", [this, paletteTarget] {
                ctx_.debug.stepOverForSession(paletteTarget);
            });
            add(nullptr, "Step Out", "Shift+F11", [this, paletteTarget] {
                ctx_.debug.stepOutForSession(paletteTarget);
            });
            add(nullptr, "Record Execution Path", "Debug / slower single-step recording", [this, captured = dbg] {
                startExecutionHistory(captured);
            });
        }
        add(nullptr, "Execution History", "Inspect recorded instructions and registers", [this] {
            executionHistoryView_.open = true;
        });
        if (!executionHistory_.recording && executionHistoryView_.canStepBack(executionHistory_)) {
            add(nullptr, "Step Back in Recorded Path", "Inspection only", [this, paletteTarget] {
                if (DebugTargetIdentityMatches(executionHistory_.target, paletteTarget))
                    executionHistoryView_.stepBack(executionHistory_);
            });
        }
        const TraceCoverageSnapshot* tr = ctx_.frameTraceCoverageSnapshot;
        const bool traceOn = ctx_.traceSeedPlanning || (tr && tr->active) || dbg.traceOwnedSites != 0;
        uint64_t traceRuntimeBase = 0, traceRuntimeSize = 0;
        const bool exactTraceImage = ctx_.frameDebugSnapshot &&
            ctx_.debuggerRuntimeImage(*ctx_.frameDebugSnapshot,
                                      traceRuntimeBase, traceRuntimeSize);
        if (traceOn || (paused && !gmlPaused && !ctx_.gmlExecutionMode && ctx_.staticBinary().loaded() && exactTraceImage)) {
            add(DS_ICON_LIGHTNING, traceOn ? "Stop Trace Coverage" : "Start Trace Coverage",
                "Debug", [this, paletteTarget] {
                    ctx_.requestedTraceToggle = true;
                    ctx_.requestedTraceTarget = paletteTarget;
                    ctx_.requestedTab = "Binary View";
                });
        }
        if (tr && (!tr->instructions.empty() || !tr->blocks.empty())) {
            add(DS_ICON_CANCEL, "Clear Trace Coverage", "Debug", [this, paletteTarget] {
                ctx_.requestedTraceClear = true;
                ctx_.requestedTraceClearTarget = paletteTarget;
                ctx_.requestedTab = "Binary View";
            });
        }
    }

    // Open documents are first-class palette destinations as well as tabs. This
    // keeps every target reachable when the window is narrow or the analyst is
    // already working keyboard-first.
    for (const AppContext::StaticDocumentSummary& document :
         ctx_.staticDocuments()) {
        std::string title = document.title.empty() ? "Untitled" : document.title;
        std::string label = "Switch document: " + title;
        std::string detail = document.active ? "active"
            : document.format.empty() ? "document" : document.format;
        const DocumentId id = document.id;
        add(document.mapped ? DS_ICON_NETWORK : DS_ICON_CODE,
            label.c_str(), detail.c_str(), [this, id] {
                if (!ctx_.queueActivateStaticDocument(id))
                    ui::Toast(ui::ToastKind::Error, ctx_.documentCommandError());
            }, document.path.c_str());
    }

    // Sections (same switch the rail / Ctrl+N does)
    const char* workflows[] = {"Analyze", "Debug", "Memory", "Compare"};
    for (int preset = 0; preset < 4; ++preset) {
        const std::string label = std::string("Workflow: ") + workflows[preset];
        add(nullptr, label.c_str(), "Workspace preset", [this, preset] {
            ctx_.requestedWorkflow = preset;
            ctx_.requestedTab = "Binary View";
        });
    }
    add(nullptr, "Types: open workbench", "Structures, unions and enums", [this] {
        ctx_.requestedTypeWorkbench = true;
        ctx_.requestedTab = "Binary View";
    });
    for (int i = 0; i < (int)tabs_.size(); ++i) {
        char lbl[64], det[16];
        std::snprintf(lbl, sizeof(lbl), "Go to: %s", tabs_[i]->name());
        if (i < 9) std::snprintf(det, sizeof(det), "Ctrl+%d", i + 1);
        else       std::snprintf(det, sizeof(det), "Section");
        std::string nm = tabs_[i]->name();
        add(nullptr, lbl, det, [this, nm] { ctx_.requestedTab = nm; });
    }

    // View controls mirror the menu and persist across sessions.
    add(nullptr, "Zoom out", "Ctrl+-", [this] {
        setUiZoomPercent(theme::UiZoomPercent() - 5);
    });
    add(nullptr, "Zoom in", "Ctrl++", [this] {
        setUiZoomPercent(theme::UiZoomPercent() + 5);
    });
    add(nullptr, "Zoom: actual size (100%)", "Ctrl+0", [this] { setUiZoomPercent(100); });
    add(nullptr, "Zoom: 90% (default)", "View", [this] { setUiZoomPercent(kDefaultUiZoomPercent); });
    for (int i = 0; i < (int)theme::ThemeId::Count; ++i) {
        theme::ThemeId id = (theme::ThemeId)i;
        char lbl[64];
        std::snprintf(lbl, sizeof(lbl), "Theme: %s", theme::ThemeName(id));
        add(nullptr, lbl, "View", [this, id] { theme_ = id; theme::ApplyTheme(id); savePrefs(); });
    }
    {
        const theme::Density opts[] = { theme::Density::Compact,
                                        theme::Density::Comfortable,
                                        theme::Density::Spacious };
        for (theme::Density d : opts) {
            char lbl[64];
            std::snprintf(lbl, sizeof(lbl), "Density: %s", theme::DensityName(d));
            add(nullptr, lbl, "View", [this, d] {
                density_ = d;
                theme::SetDensity(d);
                theme::ApplyTheme();
                savePrefs();
            });
        }
    }

    palette_.open(std::move(items), &investigation_,
                  investigationSubmittedGeneration_, investigationRecentQueries_,
                  investigationSubmittedLiveTarget_,
                  [this](std::string query, InvestigationIdentity identity) {
                      rememberInvestigationQuery(std::move(query), identity);
                  });
}

bool App::wantsContinuousRedraw() {
    // Toasts fade out on a timer - freeze-frames would strand them on screen.
    if (exitPending_ || ui::ToastsActive()) return true;
    // Keep ticking through the short debounce interval so autosave fires even
    // when the user stops interacting immediately after an edit.
    if (ctx_.projectDirty() ||
        ctx_.projectSaveState == AppContext::ProjectSaveState::Saving) return true;
    // Background work in flight: progress spinners animate and results stream in.
    if (ctx_.artifactWrites.pending() || ctx_.binaryLoadPending() || ctx_.staticAnalysis().bulkPending() || ctx_.moduleAnalysisPending() ||
        ctx_.livescan.busy() || ctx_.staticCodeExport().pending() ||
        staticUnpackService_.pending() || passiveDumpService_.busy() ||
        ctx_.traceSeedPlanning) return true;
    {
        const InvestigationServicePending pending = investigation_.pending();
        if (pending.buildQueued || pending.searchQueued || pending.building || pending.searching)
            return true;
    }
    ctx_.debug.traceCoverageSnapshotIfChanged(traceSnapshot_);
    const size_t traceDone = traceSnapshot_.armedSites + traceSnapshot_.hitSites +
                             traceSnapshot_.skippedSites + traceSnapshot_.retiredSites;
    if (traceSnapshot_.active && traceSnapshot_.plannedSites > traceDone) return true;
    // An active debug session: the debug thread mutates the snapshot asynchronously
    // (breakpoint hits, steps) and the live view pulses the RIP/selection row.
    if (ctx_.debug.snapshot().attached()) return true;
    // A live JDWP (Java) session: events arrive asynchronously from the VM.
    if (ctx_.jdwp.snapshot().attached()) return true;
    // A tab asked to keep redrawing this frame (e.g. live connection monitor).
    if (ctx_.wantContinuousRedraw) return true;
    return false;
}

void App::renderHelpWindow() {
    if (!showHelp_) return;

    const float s = theme::UiScale();
    prepareWorkbenchDialog(760.0f, 640.0f, ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Keyboard Shortcuts & View Controls", &showHelp_)) {
        ImGui::TextColored(theme::col::accent(), "DisasmStudio quick reference");
        ImGui::SameLine();
        ImGui::TextDisabled("F1 opens this window from anywhere");
        ImGui::Separator();

        ImGui::BeginChild("##help_scroll", ImVec2(0, 0), ImGuiChildFlags_None);
        auto group = [&](const char* id, const char* title,
                         std::initializer_list<std::pair<const char*, const char*>> rows) {
            ImGui::SeparatorText(title);
            if (ImGui::BeginTable(id, 2,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                    ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Shortcut / control", ImGuiTableColumnFlags_WidthFixed, 190.0f * s);
                ImGui::TableSetupColumn("Action");
                ImGui::TableHeadersRow();
                for (const auto& row : rows) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextColored(theme::col::accent(), "%s", row.first);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextWrapped("%s", row.second);
                }
                ImGui::EndTable();
            }
        };

        group("##help_global", "Global", {
            { "F1",             "Open this grouped shortcut and interaction reference." },
            { "Ctrl+O",         "Open a binary." },
            { "Ctrl+K",         "Open or close the command palette." },
            { "Ctrl+1 ... 9",   "Switch directly to one of the first nine workbench tabs." },
            { "Ctrl+Tab",       "Switch to the next open document." },
            { "Ctrl+Shift+Tab", "Switch to the previous open document." },
            { "Ctrl+W",         "Close the active document." },
            { "Middle-click document tab", "Close that document without switching first." },
            { "Alt+F4",         "Save the current project sidecar and exit." },
            { "Palette Up/Down", "Move through command-palette matches; Enter runs one and Escape closes it." },
        });
        group("##help_debug", "Debugger", {
            { "F5",             "Continue a paused target, or pause a running target." },
            { "F10",            "Step over the current instruction." },
            { "F11",            "Step into the current instruction." },
            { "Shift+F11",      "Step out of the current function." },
            { "Record",         "Record this native thread to a breakpoint or the 10,000-record limit; slower than Continue." },
            { "Step Back",      "Inspect earlier recorded instructions and registers in Execution History; the target stays at its real stop." },
            { "Ctrl+F9",        "Run to the Binary View cursor." },
            { "Trace toolbar / Debug menu", "Start or stop one-shot basic-block coverage; Clear Trace removes the retained green execution map." },
        });
        group("##help_nav", "Navigation", {
            { "Ctrl+G",         "Open the fuzzy address/symbol picker." },
            { "Ctrl+Shift+F",   "Search disassembly text." },
            { "Alt+Left/Right", "Navigate backward or forward." },
            { "Mouse Back/Fwd", "Navigate backward or forward." },
            { "Double-click assembly/live row", "Follow that row's direct call or branch target." },
        });
        group("##help_asm", "Assembly / linear view", {
            { "Enter",          "Follow the cursor instruction's direct target." },
            { "J / K",          "Move to the next / previous instruction." },
            { "Shift+J / K",    "Move sixteen instructions at a time." },
            { ";",              "Add or edit the cursor instruction's comment." },
            { "N",              "Rename the symbol at the cursor." },
            { "B",              "Toggle a software breakpoint." },
            { "X",              "Find cross-references to the cursor address." },
            { "P",              "Open the instruction patch editor." },
            { "Shift/Ctrl+click","Extend a range selection / toggle a row in the selection." },
            { "Right-click",    "Follow, copy, patch, NOP, bookmark, define a function, or resolve a jump table." },
        });
        group("##help_live", "Live Assembly", {
            { "Ctrl+F",         "Search the attached process's memory." },
            { "Enter",          "Follow the selected live call or branch." },
            { "Backspace",      "Navigate back in the live cursor history." },
            { "Click gutter",   "Toggle a software breakpoint." },
            { "Double-click row","Follow the row's call or branch target." },
            { "Click register", "Follow the register value; right-click it to copy." },
        });
        group("##help_hex", "Hex editor", {
            { "Arrow keys",     "Move the byte caret (up/down moves one 16-byte row)." },
            { "Page Up/Down",   "Move the caret by one visible page." },
            { "Tab",            "Switch between the hex and ASCII caret columns." },
            { "0-9 / A-F",      "Overwrite the selected byte nibble in the hex column." },
            { "Printable text", "Overwrite bytes from the ASCII column." },
            { "Ctrl+C",         "Copy the selected byte range." },
            { "Escape",         "Cancel an in-progress nibble edit." },
            { "Click/drag",     "Select bytes; Shift+click extends the current selection." },
            { "Enter in Goto",  "Submit the file-offset field and move the caret there." },
        });
        group("##help_graph", "Control-flow graph", {
            { "Drag empty space","Pan the graph canvas." },
            { "Drag block",     "Move an individual basic-block card." },
            { "Double-click block", "Re-root the graph at that basic block." },
            { "Reset layout",   "Discard manual block offsets and restore the automatic layout." },
            { "Click caller/callee", "Navigate to that function in the Call Graph view." },
        });
        group("##help_decomp", "Pseudocode / Decompiler", {
            { "Click pseudo line", "Navigate the assembly cursor to the line's mapped source address." },
            { "Click asm row",  "Navigate from the compact synchronized assembly pane." },
            { "Hover either pane", "Cross-highlight the corresponding pseudo/assembly location." },
            { "Language",       "Switch instantly between Pseudo-C and source-oriented, non-executable Python." },
            { "Scope",          "Shows the exact analyzed function and owned chunks; an unowned address requires explicit bounded-range decompilation." },
            { "Python legend",  "Hover the approximation badge for native-memory, integer-width, division, and unresolved-flow notation." },
            { "Copy",           "Copy the complete current decompilation." },
            { "Right-click line", "Copy one pseudo line or show its mapped source in the listing." },
        });
        group("##help_diff", "Binary Diff", {
            { "F3",             "Move to the next changed region while the diff view is focused." },
            { "Shift+F3",       "Move to the previous changed region." },
        });
        ImGui::EndChild();
    }
    ImGui::End();
}

void App::render() {
    if (!ImGui::GetIO().WantTextInput &&
        !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId)) {
        if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Minus) ||
            ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_KeypadSubtract))
            setUiZoomPercent(theme::UiZoomPercent() - 5);
        else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Equal) ||
                 ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_Equal) ||
                 ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_KeypadAdd))
            setUiZoomPercent(theme::UiZoomPercent() + 5);
        else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_0))
            setUiZoomPercent(100);
    }
    if (ctx_.workbenchPrefsDirty) {
        ctx_.workbenchPrefsDirty = false;
        savePrefs();
    }
    // Cleared each frame; a tab rendered this frame may set it to request that the
    // idle throttle keep redrawing (e.g. the live connection monitor's auto-refresh).
    ctx_.wantContinuousRedraw = false;
    const AppContext::BinaryLoadPoll binaryLoad = ctx_.pollBinaryLoad();
    if (binaryLoad.completed) {
        if (binaryLoad.success)
            ui::Toast(ui::ToastKind::Info, "Loaded binary; opening document: " + binaryLoad.path);
        else if (binaryLoad.cancelled)
            ui::Toast(ui::ToastKind::Info, "Binary load cancelled.");
        else if (binaryLoad.offerRaw) {
            ui::Toast(ui::ToastKind::Warn,
                      binaryLoad.error.empty() ? "Structured load rejected; opening explicit Raw options."
                                               : binaryLoad.error);
            if (!prepareRawLoadPath(binaryLoad.path))
                ui::Toast(ui::ToastKind::Error,
                          "The structured file was rejected and its Raw options could not be prepared.");
        } else
            ui::Toast(ui::ToastKind::Error,
                      binaryLoad.error.empty() ? "The binary could not be loaded."
                                               : binaryLoad.error);
    }
    // One lock-guarded debug snapshot per frame, shared by the toolbar and status bar
    // (each used to take its own deep copy of registers/threads/breakpoints).
    const auto lifecycle = ctx_.debug.lifecycleSnapshot();
    DbgSnapshot dbg = ctx_.debug.snapshot();
    if (lifecycle.busy) ctx_.wantContinuousRedraw = true;
    if (lifecycle.completed && lifecycle.requestId != lastDebugLifecycleCompletion_) {
        lastDebugLifecycleCompletion_ = lifecycle.requestId;
        if (lifecycle.cancelled) ui::Toast(ui::ToastKind::Info, "Debugger startup cancelled.");
        else if (!lifecycle.succeeded) ui::Toast(ui::ToastKind::Error, lifecycle.error.empty()
            ? "Debugger command failed." : lifecycle.error);
        else if (lifecycle.command != DbgLifecycleCommand::Detach &&
                 (dbg.state == DbgState::Running || dbg.state == DbgState::Paused) &&
                 DebugTargetIdentityMatches(lifecycle.target, {dbg.pid, dbg.sessionGeneration})) {
            const bool sourceCurrent = lifecycle.command == DbgLifecycleCommand::Attach ||
                ctx_.debugLaunchSourceCurrent(lifecycle.requestId);
            if (sourceCurrent) {
                suppressedLaunchNavigation_ = {};
                if (!ctx_.staticBinary().loaded())
                    ctx_.setStaticDecoderConfiguration(ctx_.staticEngine(), dbg.is32 ? Arch::X86 : Arch::X64);
                ctx_.openLiveAssemblyView();
                ui::Toast(ui::ToastKind::Success, lifecycle.command == DbgLifecycleCommand::Attach
                    ? "Debugger attached." : "Debugger launch completed.");
            } else {
                suppressedLaunchNavigation_ = lifecycle.target;
                ui::Toast(ui::ToastKind::Info,
                    "Debugger launch completed; the source document changed, so navigation was kept in place.");
            }
        }
    }
    const bool launchHandoffAllowed =
        !(lifecycle.busy && (lifecycle.command == DbgLifecycleCommand::Launch ||
                             lifecycle.command == DbgLifecycleCommand::LaunchDll)) &&
        !DebugTargetIdentityMatches(suppressedLaunchNavigation_, {dbg.pid, dbg.sessionGeneration}) &&
        // A DLL host can finish initialization long before its target DLL loads.
        // Its delayed handoff still belongs to the document that requested it.
        (lifecycle.command != DbgLifecycleCommand::LaunchDll ||
         !DebugTargetIdentityMatches(lifecycle.target, {dbg.pid, dbg.sessionGeneration}) ||
         ctx_.debugLaunchSourceCurrent(lifecycle.requestId));
    // A debuggee that exited leaves the session "attached" to a dead process: the
    // debug thread is gone but the state stays Terminated, so the toolbar would
    // keep its (now dead) pause/step controls, Launch & Debug would never come
    // back, and the continuous-redraw throttle would spin forever. Finalize the
    // session asynchronously so slow observation cleanup cannot block the UI.
    // This also ensures the UI
    // drops back to the static state and the Binary View's detach edge releases
    // the per-session live caches + module registry.
    if (dbg.state == DbgState::Terminated && !lifecycle.busy) {
        if (ctx_.debug.requestDetach({dbg.pid, dbg.sessionGeneration}))
            ui::Toast(ui::ToastKind::Info, "Debuggee exited - ending debug session");
    }
    ctx_.synchronizeModuleSession(dbg);
    if (!dbg.attached()) {
        dllRetargetPid_ = 0;
        dllRetargetGeneration_ = 0;
        dllRetargetBase_ = 0;
        dllRetargetPending_.clear();
        dllRetargetFailure_.clear();
        attachMainDocumentSessionValid_ = false;
        attachMainDocumentPid_ = 0;
        attachMainDocumentGeneration_ = 0;
        attachMainDocumentPending_.clear();
        attachMainDocumentFailure_.clear();
    } else if (launchHandoffAllowed && dbg.dllTargetMatched && dbg.dllTargetBase) {
        const bool retargetHandled = dllRetargetPid_ == dbg.pid &&
            dllRetargetGeneration_ == dbg.sessionGeneration &&
            dllRetargetBase_ == dbg.dllTargetBase;
        const bool retargetPending = dllRetargetPending_.matches(
            dbg.pid, dbg.sessionGeneration, dbg.dllTargetBase);
        const bool retargetFailedWithoutRecovery = dllRetargetFailure_.matches(
            dbg.pid, dbg.sessionGeneration, dbg.dllTargetBase) &&
            dllRetargetFailure_.retryRevision == ctx_.documentRetryRevision();
        if (!retargetHandled && !retargetPending &&
            !retargetFailedWithoutRecovery && !ctx_.documentCommandPending()) {
            const std::string modulePath = dbg.dllTargetPath;
            const size_t slash = modulePath.find_last_of("/\\");
            const std::string moduleName = modulePath.empty()
                ? std::string("target.dll")
                : (slash == std::string::npos
                    ? modulePath : modulePath.substr(slash + 1));
            if (ctx_.loadLiveModule(
                    dbg.dllTargetBase, dbg.dllTargetSize,
                    moduleName, modulePath,
                    LiveDocumentOpenOrigin::HostedDll)) {
                dllRetargetPending_ = {
                    true, dbg.pid, dbg.sessionGeneration,
                    dbg.dllTargetBase, 0
                };
            } else {
                dllRetargetFailure_ = {
                    true, dbg.pid, dbg.sessionGeneration,
                    dbg.dllTargetBase, ctx_.documentRetryRevision()
                };
                ui::Toast(ui::ToastKind::Error,
                          "The target DLL loaded, but its mapped image could not be read for analysis.");
            }
        }
    }

    // Reconcile the analysis document once per exact debugger session. A normal
    // attach keeps a matching on-disk PE (its full static analysis is richer),
    // while an empty, unrelated, or prior-session mapped document gets a fresh
    // ephemeral capture. The queued open retains the old document and is applied
    // only after this frame releases every tab-local reference.
    const bool mainDocumentSessionHandled = attachMainDocumentSessionValid_ &&
        SameAttachSession(
            {attachMainDocumentPid_, attachMainDocumentGeneration_},
            {dbg.pid, dbg.sessionGeneration});
    const bool mainDocumentPending = attachMainDocumentPending_.matches(
        dbg.pid, dbg.sessionGeneration);
    const bool mainDocumentFailedWithoutRecovery =
        attachMainDocumentFailure_.matches(dbg.pid, dbg.sessionGeneration) &&
        attachMainDocumentFailure_.retryRevision == ctx_.documentRetryRevision();
    if (launchHandoffAllowed && liveDocumentSessionState(dbg) && !mainDocumentSessionHandled &&
        !mainDocumentPending && !mainDocumentFailedWithoutRecovery) {
        if (dbg.dllHostedLaunch) {
            // The host is only a loader. The exact LOAD_DLL retarget path above
            // owns the analysis-document handoff for this session.
            attachMainDocumentSessionValid_ = true;
            attachMainDocumentPid_ = dbg.pid;
            attachMainDocumentGeneration_ = dbg.sessionGeneration;
            attachMainDocumentPending_.clear();
            attachMainDocumentFailure_.clear();
        } else if (!ctx_.documentCommandPending() && !dbg.modules.empty()) {
            const DbgModule& main = dbg.modules.front();
            if (main.base) {
                if (LoadedModule* registryMain = ctx_.modules.addOrUpdate(
                        main.name, main.base, main.size, main.path))
                    registryMain->isMain = true;
                const BinaryFile& active = ctx_.staticBinary();
                AttachMainImageState state;
                state.activeLoaded = active.loaded();
                state.activeMapped = active.loaded() && active.isMappedImage();
                state.activePe = active.loaded() &&
                    (active.format() == BinFormat::PE32 ||
                     active.format() == BinFormat::PE32Plus);
                state.activeArchitectureMatchesSession = active.loaded() &&
                    ctx_.binaryDebugArchitectureMatches() &&
                    ((active.machine() == MachineArch::X86 && dbg.is32) ||
                     (active.machine() == MachineArch::X64 && !dbg.is32));
                state.activeFullPathMatchesMain = active.loaded() &&
                    AttachedImagePathsMatch(active.path(), main.path);
                AttachedFileIdentity activeBackingIdentity;
                state.activeBackingFileMatchesMain =
                    state.activeFullPathMatchesMain &&
                    !hasEnabledProjectPatches(ctx_.staticProject()) &&
                    loadedBytesStillMatchDisk(active,
                                              &activeBackingIdentity) &&
                    SameAttachedFileIdentity(activeBackingIdentity,
                                             main.fileIdentity);

                const AttachMainImageAction action = DecideAttachMainImage(state);
                const bool handled =
                    action == AttachMainImageAction::KeepMatchingFileDocument;
                if (action == AttachMainImageAction::OpenEphemeralMainImage) {
                    if (ctx_.loadLiveModule(
                            main.base, main.size, main.name, main.path,
                            LiveDocumentOpenOrigin::AttachMain)) {
                        attachMainDocumentPending_ = {
                            true, dbg.pid, dbg.sessionGeneration,
                            main.base, 0
                        };
                    } else {
                        attachMainDocumentFailure_ = {
                            true, dbg.pid, dbg.sessionGeneration,
                            main.base, ctx_.documentRetryRevision()
                        };
                        ui::Toast(ui::ToastKind::Warn,
                                  "Attached to the process, but its main image could not be opened for static analysis.");
                    }
                }
                if (handled) {
                    ctx_.setStaticDebugImageIdentity(
                        debugImageIdentity(dbg, main));
                    attachMainDocumentSessionValid_ = true;
                    attachMainDocumentPid_ = dbg.pid;
                    attachMainDocumentGeneration_ = dbg.sessionGeneration;
                }
            }
        }
    }
    // Module results are app-global and must be adopted regardless of which
    // workbench tab is currently visible. This also retires incomplete spinners
    // after cancellation or bounded result loss.
    ctx_.drainModuleAnalysisResults();
    ctx_.debug.traceCoverageSnapshotIfChanged(traceSnapshot_);
    refreshExecutionHistory(dbg);
    ctx_.frameDebugSnapshot = &dbg;
    ctx_.frameTraceCoverageSnapshot = &traceSnapshot_;
    struct ResetFrameDebugSnapshot {
        AppContext& ctx;
        ~ResetFrameDebugSnapshot() {
            ctx.frameDebugSnapshot = nullptr;
            ctx.frameTraceCoverageSnapshot = nullptr;
        }
    } resetFrameDebugSnapshot{ ctx_ };

    // Application-wide shortcuts live here so they work regardless of the
    // selected workbench tab. F1 intentionally has no text-input guard; it is a
    // help key, not a character-producing key. Ctrl+O is suppressed while any
    // ImGui popup is open: modal editors retain ownership of their target state,
    // and loading another binary cannot leave them applying to a stale address.
    if (ImGui::IsKeyPressed(ImGuiKey_F1)) showHelp_ = true;
    const bool popupOpen = ImGui::IsPopupOpen(nullptr,
        ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel);
    if (!ImGui::GetIO().WantTextInput && !popupOpen && !palette_.isOpen()) {
        if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_O))
            openFileDialog();

        // Browser-style document controls match the visual document strip. All
        // transitions still go through the existing frame-boundary queue, so a
        // shortcut cannot invalidate a tab that is rendering this frame.
        const std::vector<AppContext::StaticDocumentSummary> documents =
            ctx_.staticDocuments();
        if (!ctx_.documentCommandPending() && !documents.empty()) {
            const bool previous = ImGui::IsKeyChordPressed(
                ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_Tab);
            const bool next = !previous && ImGui::IsKeyChordPressed(
                ImGuiMod_Ctrl | ImGuiKey_Tab);
            if (previous || next) {
                size_t active = 0;
                for (size_t i = 0; i < documents.size(); ++i) {
                    if (documents[i].active) {
                        active = i;
                        break;
                    }
                }
                const size_t target = previous
                    ? (active + documents.size() - 1) % documents.size()
                    : (active + 1) % documents.size();
                if (!ctx_.queueActivateStaticDocument(documents[target].id))
                    ui::Toast(ui::ToastKind::Error, ctx_.documentCommandError());
            } else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_W)) {
                auto active = std::find_if(documents.begin(), documents.end(),
                    [](const AppContext::StaticDocumentSummary& document) {
                        return document.active;
                    });
                if (active != documents.end() &&
                    !ctx_.queueCloseStaticDocument(active->id))
                    ui::Toast(ui::ToastKind::Error, ctx_.documentCommandError());
            }
        }
    }

    renderMenuBar();
    renderDebugToolbar(dbg);
    resolveWorkbenchNavigation();
    renderTabCardStrip(dbg);
    renderMainWindow(dbg);
    renderStatusBar(dbg);
    renderRawLoadPopup();
    renderDllDebugPopup();
    renderUnpackPopup();
    renderStaticUnpackPopup();
    renderAntiDebugPopup();
    renderPassiveDumpPopup();
    renderSymbolSettingsPopup();
    executionHistoryView_.render(executionHistory_, dbg);
    if (binaryView_ && binaryView_->renderTypeDraftPrompt(ctx_)) requestExit();

    // Binary View's Java banner can't open the Save dialog itself (it has no
    // access to App); it raises this flag instead (same pattern as
    // requestedExportAnalysis, but consumed here rather than in the tab).
    if (ctx_.requestedExtractJava) {
        ctx_.requestedExtractJava = false;
        extractEmbeddedJar();
    }

    // Same flag pattern for the archive-entries browser (banner button, File menu,
    // palette, and the standalone-.jar/.zip auto-open in loadBinaryPath).
    if (ctx_.requestedBrowseArchive) {
        ctx_.requestedBrowseArchive = false;
        openArchiveBrowser();
    }
    renderArchiveBrowser();
    renderHelpWindow();

    ctx_.pollProjectSave();
    ctx_.pollArtifactWrites();
    pollExit();

    // Debounced autosave. All serialized state has already been mirrored by the
    // active tab this frame; the atomic Project writer makes each attempt crash-
    // recoverable. A failure stays dirty and is retried after another debounce
    // interval while remaining visible in the global status bar.
    if (ctx_.projectDirty() && ctx_.staticBinary().loaded() && !ctx_.staticBinary().isMappedImage()) {
        constexpr auto kAutosaveDelay = std::chrono::milliseconds(1500);
        const auto now = std::chrono::steady_clock::now();
        if (now - ctx_.projectDirtySince >= kAutosaveDelay) {
            ctx_.beginProjectSave();
            if (ctx_.projectSaveState == AppContext::ProjectSaveState::Failed)
                ctx_.projectDirtySince = now;
        }
    }

    // Run after every target-mutating menu/tab/modal workflow. A replacement or
    // close retires the previous generation before Ctrl+K can open in this same
    // frame; the collector itself is bounded to a small render-time slice.
    maintainInvestigationWorkspace();

    // Modal editors retain ownership of their document and address. Opening the
    // palette above one would expose actions that replace that editor's target.
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_K)) {
        if (palette_.isOpen()) palette_.close();
        else if (!ImGui::IsPopupOpen(nullptr,
                     ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel))
            openCommandPalette(dbg);
    }
    palette_.render(ctx_);

    // Commit at the last safe point of the frame: every tab/popup which could
    // have borrowed the active BinaryFile has returned, while toasts and the
    // remaining diagnostic windows do not retain document references.
    applyPendingDocumentCommand();

    // Toast stack, bottom-right just above the status bar.
    ui::RenderToasts(ImGui::GetFrameHeight() + 8.0f);

    if (showDemo_)  ImGui::ShowDemoWindow(&showDemo_);
    if (showAbout_) {
        if (ImGui::Begin("About DisasmStudio", &showAbout_, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::SetWindowFontScale(1.6f);
            ImGui::TextColored(theme::col::accent(), "DisasmStudio");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::TextDisabled("Fast, GPU-accelerated reverse-engineering workbench");
            ImGui::Text("Version %s", DS_VERSION_STRING);
            ImGui::Separator();
            ImGui::SeparatorText("Feature overview");
            ImGui::BulletText("Static analysis for PE, ELF, Mach-O, raw blobs, and Java class files");
            ImGui::BulletText("Multi-architecture disassembly, CFGs, xrefs, decompilation, and patching");
            ImGui::BulletText("Live Win32 and JVM/JDWP debugging plus process-memory tools");
            ImGui::SeparatorText("Runtime");
            ImGui::Text("Disassembly   Zydis (x86 family) + Capstone (A32/Thumb/A64/MIPS/PPC/RISC-V)");
            ImGui::Text("Assembler     Keystone (x86/x64/A32/Thumb/A64)");
            ImGui::Text("UI            Dear ImGui + Direct3D 11");
#ifdef _DEBUG
            ImGui::Text("Build         Debug, Windows x64, C++20");
#else
            ImGui::Text("Build         Release, Windows x64, C++20");
#endif
            ImGui::Spacing();
            ImGui::TextDisabled("A static disassembler and a live Win32 debugger in one tool.");
        }
        ImGui::End();
    }
}

} // namespace ds
