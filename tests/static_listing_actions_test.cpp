// Headless integration against the actual Release application objects. No GPU,
// native window, target process, network, or user project files are required.
#include "App.h"
#include <fstream>
#include <list>
#include <map>
#include <sstream>
#include <stdexcept>
#include <functional>
#include "imgui.h"
#include "imgui_internal.h"
// The production UI intentionally has no scripting/test API. Expose this one
// class's existing internals in the fixture instead of adding a public seam.
#define private public
#include "Tabs/BinaryViewTab.h"
#undef private
#include "Ui/Widgets.h"
#include "Core/GameMakerArchive.h"
#include "gamemaker_fixture.h"
#include <windows.h>
#include <cstdio>

using namespace ds;
static int failures = 0;
#define CHECK(value) do { if (!(value)) { std::printf("FAIL line %d: %s\n", __LINE__, #value); ++failures; } } while (0)
static constexpr uint64_t kTarget = 20 * 4096 + 8;

static void frame(const std::function<void()>& body, const char* title = "Listing integration",
                  ImVec2 size = ImVec2(1440, 900)) {
    ImGui::GetIO().DisplaySize = size;
    ImGui::NewFrame();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(size);
    ImGui::Begin(title, nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings);
    body();
    ImGui::End();
    ImGui::Render();
}

struct Fixture {
    AppContext ctx;
    std::unique_ptr<BinaryViewTab> tab;
    DbgSnapshot detached;
    std::string path;

    explicit Fixture(const std::string& fixturePath, bool full = true,
                     const ProjectState* restored = nullptr) : path(fixturePath) {
        CHECK(ctx.beginRawLoadPath(path, 0, Arch::X64, 0, {}, {}));
        bool loaded = false;
        for (int i = 0; i < 1000; ++i) {
            const auto result = ctx.pollBinaryLoad();
            if (result.completed) { loaded = result.success; break; }
            Sleep(2);
        }
        CHECK(loaded);
        CHECK(ctx.applyPendingDocumentCommand().success);
        // Every case starts pristine. Previous cases exercise real mirroring and
        // may save a sidecar for the same content hash inside isolated APPDATA.
        ctx.staticProject() = restored ? *restored : ProjectState{};
        tab = std::make_unique<BinaryViewTab>(ctx.staticDocumentId());
        tab->synchronizeDocumentImage(ctx);
        ctx.staticAnalysis().cancelAndWaitIdle();
        tab->functions_.clear(); tab->funcIndex_.clear();
        tab->functionsDirty_ = false; tab->decompOwnershipPending_ = false;
        tab->codeDataMap_.reset();
        tab->asmFullProgram_ = full;
        tab->frameSnap_ = &detached;
        layout();
        tab->setStaticCursor(kTarget);
        if (full) CHECK(tab->ensureListingCodePage(ctx, 20) != nullptr);
        else {
            size_t available = 0;
            const auto* bytes = ctx.staticBinary().ptrFromVA(kTarget - 8, available);
            tab->asmWindowInsns_ = ctx.staticDisassembler()->disassemble(bytes, available, kTarget - 8, 256);
            tab->asmWindowBoundaryExact_ = false;
        }
    }

    ~Fixture() {
        ctx.staticAnalysis().cancelAndWaitIdle();
        ctx.staticProject().hash = 0;
        tab->frameSnap_ = nullptr;
    }

    void layout() {
        tab->listRows_.clear();
        for (uint64_t i = 0; i < 128; ++i) {
            BinaryViewTab::ListRow row{};
            row.type = ListingRowType::CodePage;
            row.addr = i * 4096; row.aux = 4096;
            row.sectionIndex = 0; row.codeRegion = 1;
            tab->listRows_.push_back(row);
        }
        tab->resetListingVirtualIndex(ctx, true);
        tab->listingTopologyPending_ = false;
        tab->listBuilt_ = true; tab->listSig_ = tab->listingSig(ctx);
    }

    void select(std::initializer_list<uint64_t> addresses) {
        tab->selVAs_ = addresses;
        tab->selView_ = 0;
        tab->rememberListingSelection(ctx);
    }

    void assemblyFrame(bool wholeUi = false) {
        frame([&] {
            tab->frameSnap_ = &detached;
            if (wholeUi) tab->render(ctx);
            else if (tab->asmFullProgram_) tab->renderAssemblyFull(ctx);
            else tab->renderAssemblyWindow(ctx);
        });
        tab->frameSnap_ = &detached;
    }

    void key(ImGuiKey key) {
        ImGui::GetIO().AddKeyEvent(key, true);
        assemblyFrame(true);
        ImGui::GetIO().AddKeyEvent(key, false);
        assemblyFrame(true);
    }

    bool clickRow(uint64_t address, bool gutter, ImGuiMouseButton button = ImGuiMouseButton_Left) {
        for (int i = 0; i < 4; ++i) assemblyFrame();
        for (const auto& row : tab->asmFlow_) if (row.addr == address) {
            const float x = gutter ? tab->asmLaneX_ - 12 : tab->asmAddrX_ + 48;
            const float y = row.y;
            ImGui::GetIO().AddMousePosEvent(x, y);
            assemblyFrame();
            ImGui::GetIO().AddMouseButtonEvent(button, true);
            assemblyFrame();
            ImGui::GetIO().AddMouseButtonEvent(button, false);
            assemblyFrame();
            return true;
        }
        std::printf("[diag] row 0x%llX absent from %zu displayed rows\n", address, tab->asmFlow_.size());
        return false;
    }

    void selectionMenu(const char* activate) {
        auto body = [&] { tab->asmSelectionMenu(ctx, detached); };
        frame(body, "Selection actions");
        ImGuiWindow* window = ImGui::FindWindowByName("Selection actions");
        CHECK(window != nullptr);
        if (window) { ImGui::FocusWindow(window); ImGui::ActivateItemByID(window->GetID(activate)); }
        frame(body, "Selection actions");
    }
};

#include "navigation_workflow_fixture.inc"
#include "context_action_regressions.inc"

static void checkRetainedActions(const std::string& path) {
    Fixture f(path);
    CHECK(!f.tab->listingInstructionBoundaryExact(kTarget));
    f.select({kTarget, kTarget + 2});
    CHECK(f.tab->listingSelectedInstructions_.size() == 2);
    for (size_t page = 21; page < 118; ++page)
        CHECK(f.tab->ensureListingCodePage(f.ctx, page) != nullptr);
    CHECK(f.tab->codePageCache_.count(20) == 0); // actual production LRU eviction
    Instruction in; std::string error;
    CHECK(f.tab->listingActionInstruction(f.ctx, kTarget, in, error));
    CHECK(in.address == kTarget && in.length == 2);
    f.tab->toggleBreakpoint(f.ctx, kTarget);
    CHECK(f.tab->breakpoints_.count(kTarget) == 1);
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    CHECK(!f.tab->listingBoundaryAuthority_.analystAccepted(kTarget + 1));
    CHECK(f.tab->acceptListingInstructionBoundary(f.ctx, kTarget + 2));
    CHECK(f.tab->applyStaticInstructionPatch(f.ctx, kTarget, {0x90, 0x90}, 2, false));
    CHECK(f.ctx.staticProject().patches.size() == 1);
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget + 2));
    CHECK(!f.tab->listingBoundaryAuthority_.analystAccepted(kTarget + 1));
    CHECK(f.tab->listingActionInstruction(f.ctx, kTarget, in, error) && in.length == 1);

    const uint8_t changed = 0xC3;
    CHECK(f.ctx.writeStaticImage(kTarget + 2, &changed, 1) == 1);
    CHECK(!f.tab->listingActionInstruction(f.ctx, kTarget + 2, in, error));
    CHECK(error.find("changed") != std::string::npos);
    CHECK(!f.tab->applyStaticInstructionPatch(f.ctx, kTarget + 2, {0x90}, 1, false));
    CHECK(f.ctx.staticProject().patches.size() == 1);

    CHECK(f.ctx.setStaticDecoderConfiguration(Engine::Capstone, Arch::X64));
    CHECK(!f.tab->listingActionInstruction(f.ctx, kTarget, in, error));
    CHECK(error.find("changed") != std::string::npos);
    const DocumentId original = f.tab->documentId_;
    f.tab->documentId_ = DocumentId{original.value + 100};
    CHECK(!f.tab->listingActionInstruction(f.ctx, kTarget, in, error));
    CHECK(error.find("document") != std::string::npos);
    f.tab->documentId_ = original;
}

static void checkSavedRestore(const std::string& path) {
    Fixture f(path);
    f.tab->breakpoints_.insert(kTarget);
    f.tab->listRows_.clear(); f.tab->listingRowsIndex_.reset({});
    frame([&] { f.tab->restoreSavedBreakpointBoundaries(f.ctx); });
    CHECK(f.tab->staticBreakpointSavedRestore_.count(kTarget) == 1);
    CHECK(!f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    f.layout();
    frame([&] { f.tab->armPendingStaticBreakpoints(f.ctx); });
    CHECK(f.tab->staticBreakpointSavedRestore_.empty());
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    CHECK(f.tab->staticBreakpointValidationErrors_.empty());
    std::string detail;
    CHECK(std::string(f.tab->staticBreakpointStatus(f.ctx, kTarget, detail)) == "saved; not debugging");

    f.tab->listingBoundaryAuthority_.clear();
    f.tab->listRows_[20].type = ListingRowType::DataDirective;
    f.tab->listRows_[20].dataSize = 4096;
    f.tab->resetListingVirtualIndex(f.ctx);
    frame([&] { f.tab->restoreSavedBreakpointBoundaries(f.ctx); });
    CHECK(!f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    CHECK(std::string(f.tab->staticBreakpointStatus(f.ctx, kTarget, detail)) == "saved; invalid instruction");
    CHECK(detail.find("data") != std::string::npos);
}

static void checkInputPaths(const std::string& path, bool full) {
    Fixture f(path, full);
    CHECK(f.clickRow(kTarget, false)); // native ImGui mouse selection
    CHECK(f.tab->selVAs_.count(kTarget) == 1);
    CHECK(!f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    CHECK(f.clickRow(kTarget, true)); // production gutter action on a ~ row
    CHECK(f.tab->breakpoints_.count(kTarget) == 1);
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    f.tab->toggleBreakpoint(f.ctx, kTarget);
    f.tab->listingBoundaryAuthority_.clear();
    f.key(ImGuiKey_B); // actual BinaryViewTab::render keyboard dispatch
    CHECK(f.tab->breakpoints_.count(kTarget) == 1);
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    f.tab->listingBoundaryAuthority_.clear();
    f.key(ImGuiKey_P);
    CHECK(f.tab->patchVA_ == kTarget && !f.tab->patchInstructionRecords_.empty());
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    // Close the actual popup so it cannot consume later input.
    ImGui::ClosePopupsOverWindow(nullptr, false);
    f.tab->openPatchPopup_ = false; f.tab->closePatchPopup_ = false;
}

static void checkSavedPatchReopen(const std::string& path) {
    ProjectState saved;
    {
        Fixture f(path);
        f.select({kTarget});
        f.tab->toggleBreakpoint(f.ctx, kTarget);
        CHECK(f.tab->applyStaticInstructionPatch(f.ctx, kTarget, {0x90, 0x90}, 2, false));
        f.tab->saveProjectState(f.ctx);
        saved = f.ctx.staticProject();
        CHECK(saved.patches.size() == 1 && saved.breakpoints.size() == 1);
    }
    Fixture reopened(path, true, &saved);
    size_t available = 0;
    const auto* bytes = reopened.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(available >= 2 && bytes[0] == 0x90 && bytes[1] == 0x90);
    frame([&] { reopened.tab->armPendingStaticBreakpoints(reopened.ctx); });
    const auto* accepted = reopened.tab->listingBoundaryAuthority_.acceptedSnapshot(kTarget);
    CHECK(accepted && accepted->instruction.length == 1 && accepted->bytes == std::vector<uint8_t>{0x90});
    CHECK(reopened.tab->staticBreakpointValidationErrors_.empty());
}

static void checkContextMenu(const std::string& path, bool full) {
    Fixture f(path, full);
    CHECK(f.clickRow(kTarget, false, ImGuiMouseButton_Right));
    f.assemblyFrame();
    CHECK(!GImGui->OpenPopupStack.empty());
    if (!GImGui->OpenPopupStack.empty()) {
        ImGuiWindow* popup = GImGui->OpenPopupStack.back().Window;
        CHECK(popup != nullptr);
        if (popup) {
            ImGui::FocusWindow(popup);
            ImGui::ActivateItemByID(popup->GetID("NOP out instruction (accept displayed boundary)"));
            f.assemblyFrame(); // patch invalidates the page currently being iterated
        }
    }
    CHECK(f.ctx.staticProject().patches.size() == 1);
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    size_t available = 0;
    const auto* bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(available >= 2 && bytes[0] == 0x90 && bytes[1] == 0x90);
    ImGui::ClosePopupsOverWindow(nullptr, false);
}

static void checkPopupAfterEviction(const std::string& path) {
    Fixture f(path);
    constexpr uint64_t patchAddress = kTarget + 8;
    CHECK(f.tab->cursorVA_ != patchAddress && !f.tab->selVAs_.count(patchAddress));
    CHECK(f.tab->beginStaticInstructionPatch(f.ctx, patchAddress));
    auto popupBody = [&] { f.tab->renderPatchPopup(f.ctx); };
    frame(popupBody);
    CHECK(f.tab->patchInstructionRecords_.size() == 1);
    for (size_t page = 21; page < 118; ++page)
        CHECK(f.tab->ensureListingCodePage(f.ctx, page) != nullptr);
    CHECK(f.tab->codePageCache_.count(20) == 0);
    Instruction in; std::string error;
    CHECK(!f.tab->listingActionInstruction(f.ctx, patchAddress, in, error));
    f.tab->patchMode_ = 0;
    std::snprintf(f.tab->patchHex_, sizeof(f.tab->patchHex_), "90 90");
    frame(popupBody);
    ImGuiWindow* popup = ImGui::FindWindowByName("Patch");
    CHECK(popup != nullptr);
    if (popup) { ImGui::FocusWindow(popup); ImGui::ActivateItemByID(popup->GetID("Apply")); }
    frame(popupBody);
    CHECK(f.ctx.staticProject().patches.size() == 1);
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(patchAddress));
    size_t available = 0;
    const auto* bytes = f.ctx.staticBinary().ptrFromVA(patchAddress, available);
    CHECK(available >= 2 && bytes[0] == 0x90 && bytes[1] == 0x90);
    ImGui::ClosePopupsOverWindow(nullptr, false);
}

static void checkSelectionMenu(const std::string& path, bool full) {
    Fixture f(path, full);
    f.select({kTarget, kTarget + 2});
    f.tab->codePageCache_.clear(); f.tab->asmWindowInsns_.clear();
    f.selectionMenu("Add breakpoints on selection");
    CHECK(f.tab->breakpoints_.count(kTarget) && f.tab->breakpoints_.count(kTarget + 2));
    CHECK(f.tab->listingBoundaryAuthority_.analystAccepted(kTarget));
    f.selectionMenu("NOP out selection");
    CHECK(f.ctx.staticProject().patches.size() == 2);
    size_t available = 0;
    const auto* bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(available >= 4 && bytes[0] == 0x90 && bytes[1] == 0x90 && bytes[2] == 0x90 && bytes[3] == 0x90);
}

static void checkGameMakerActions(const std::string& directory) {
    const auto bytes=gmltest::BuildArchive();
    const std::string path=directory+"\\gml-actions.win";
    {std::ofstream file(path,std::ios::binary);file.write(reinterpret_cast<const char*>(bytes.bytes.data()),bytes.bytes.size());}
    AppContext ctx;
    CHECK(ctx.beginBinaryLoadPath(path));bool loaded=false;
    for(int i=0;i<1000;++i){const auto result=ctx.pollBinaryLoad();if(result.completed){loaded=result.success;break;}Sleep(2);}
    CHECK(loaded);CHECK(ctx.applyPendingDocumentCommand().success);
    ctx.staticProject()=ProjectState{};
    BinaryViewTab tab(ctx.staticDocumentId());tab.synchronizeDocumentImage(ctx);ctx.staticAnalysis().cancelAndWaitIdle();
    CHECK(ctx.staticArch()==Arch::GML);
    tab.toggleBreakpoint(ctx,bytes.childOffset);
    CHECK(tab.hasGmlBreakpoint(ctx,bytes.childOffset));
    CHECK(tab.breakpoints_.empty() && ctx.staticProject().breakpoints.empty());
    CHECK(ctx.staticProject().gmlBreakpoints.size()==1);
    tab.addGmlBreakpoints(ctx,{bytes.rootOffset,bytes.childOffset,bytes.variableInstruction+4});
    CHECK(ctx.staticProject().gmlBreakpoints.size()==2); // reject operand words
    CHECK(tab.hasGmlBreakpoint(ctx,bytes.rootOffset));
    tab.toggleBreakpoint(ctx,bytes.childOffset);
    CHECK(!tab.hasGmlBreakpoint(ctx,bytes.childOffset));
    CHECK(ctx.staticProject().gmlBreakpoints.size()==1);
    size_t available=0;const auto* original=ctx.staticBinary().ptrFromVA(bytes.rootOffset,available);
    CHECK(original && available>=bytes.rootLength && std::memcmp(original,bytes.bytes.data()+bytes.rootOffset,bytes.rootLength)==0);
    for(int i=0;i<1000;++i){tab.advanceInvestigationSnapshot(ctx,{},0,256);if(!tab.investigationBuilding_)break;}
    CHECK(tab.investigationPublished_ && tab.investigationPublished_->functions.size()==2);
    if(tab.investigationPublished_){const auto archive=ctx.staticBinary().gameMakerArchive();for(const auto& code:archive->code){const auto& rows=tab.investigationPublished_->functions;CHECK(std::any_of(rows.begin(),rows.end(),[&](const auto& row){return row.name==code.name && row.location.valid && row.location.value==code.entryFileOffset();}));}}
    for(int mode=0;mode<8;++mode){tab.gmlBrowseKind_=mode;frame([&]{if(ImGui::BeginTabBar("gml_test")){tab.renderGameMakerTab(ctx);ImGui::EndTabBar();}});}
    ctx.staticAnalysis().cancelAndWaitIdle();ctx.staticProject().hash=0;
}

static AnalysisResult referenceResult(Fixture& f) {
    AnalysisResult result;
    result.epoch = f.ctx.staticAnalysis().epoch();
    result.xrefImageRevision = f.ctx.staticBinary().imageRevision();
    result.xrefDecoderSignature = AnalysisIsaSignature(f.ctx.staticDecoderConfig());
    const auto overrides = f.ctx.staticProject().analysisOverrides();
    result.xrefOverrideDigest = DigestAnalysisOverrides(&overrides);
    auto map = std::make_shared<CodeDataMap>();
    map->imageRevision = result.xrefImageRevision;
    map->scopeDigest = 0x1234;
    result.codeData = map;
    result.xref = std::make_shared<XrefIndex>();
    result.xref->classificationApplied = true;
    result.xref->classificationScopeDigest = map->scopeDigest;
    result.xref->toTarget[0] = {kTarget, kTarget + 2};
    result.xref->acceptedEdges = 2;
    return result;
}

static void checkReferenceWorkflow(const std::string& path) {
    Fixture f(path);
    auto result = referenceResult(f);
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, result));
    const auto accepted = f.ctx.staticAnalysisCache().xrefs;
    for (int wrong = 0; wrong < 4; ++wrong) {
        auto stale = result;
        if (wrong == 0) ++stale.epoch;
        if (wrong == 1) ++stale.xrefImageRevision;
        if (wrong == 2) ++stale.xrefDecoderSignature;
        if (wrong == 3) ++stale.xrefOverrideDigest;
        CHECK(!f.tab->adoptStaticXrefResult(f.ctx, stale));
        CHECK(f.ctx.staticAnalysisCache().xrefs == accepted);
    }
    auto wrongScope = referenceResult(f);
    wrongScope.xref->classificationScopeDigest++;
    CHECK(!f.tab->adoptStaticXrefResult(f.ctx, wrongScope));
    f.tab->startXrefSearch(f.ctx, 0, false);
    CHECK(f.tab->xrefPinned_ && f.tab->xrefTargetValid_ && f.tab->xrefTarget_ == 0);
    CHECK(f.tab->xrefHits_.size() == 2 && !f.tab->xrefFilePending_);
    std::snprintf(f.tab->xrefFilter_, sizeof(f.tab->xrefFilter_), "0x%llX",
                  static_cast<unsigned long long>(kTarget + 2));
    frame([&] {
        f.tab->renderPinnedXrefs(f.ctx);
        CHECK(!ImGui::IsPopupOpen("References", ImGuiPopupFlags_AnyPopupLevel));
    });
    CHECK(f.tab->xrefVisible_.size() == 1 && f.tab->xrefVisible_[0] == 1);
    CHECK(f.tab->followXrefSource(f.ctx, 1));
    CHECK(f.tab->cursorVA_ == kTarget + 2 && f.tab->mainView_ == 0);
    CHECK(f.tab->xrefPinned_ && f.tab->xrefTarget_ == 0);
    CHECK(f.tab->xrefSelectedValid_ && f.tab->xrefSelectedSource_ == kTarget + 2);
    CHECK(f.tab->xrefFilter_[0] && f.tab->xrefHits_.size() == 2);
    const auto originalScope = f.ctx.staticAnalysisCache().codeData;
    auto replacementScope = std::make_shared<CodeDataMap>(*originalScope);
    ++replacementScope->scopeDigest;
    f.ctx.staticAnalysisCache().codeData = replacementScope;
    frame([&] { f.tab->renderPinnedXrefs(f.ctx); });
    CHECK(!f.tab->xrefTargetValid_ && f.tab->xrefHits_.empty());
    CHECK(!f.tab->followXrefSource(f.ctx, 0));
    f.ctx.staticAnalysisCache().codeData = originalScope;
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, result));
    f.tab->startXrefSearch(f.ctx, 0, false);
    CHECK(f.tab->xrefTargetValid_ && f.tab->xrefHits_.size() == 2);
    f.ctx.staticAnalysis().bumpEpoch();
    frame([&] { f.tab->renderPinnedXrefs(f.ctx); });
    CHECK(!f.tab->xrefTargetValid_ && f.tab->xrefHits_.empty());
    CHECK(f.tab->xrefStatus_.find("retired") != std::string::npos);
    CHECK(!f.tab->followXrefSource(f.ctx, 0));

    // An already-completed LIVE search may not navigate under a new session,
    // even when that new session has the same numeric PID and source address.
    DbgSnapshot live;
    live.pid = 777; live.sessionGeneration = 8; live.state = DbgState::Paused;
    f.tab->frameSnap_ = &live;
    f.tab->xrefHitsLive_ = f.tab->xrefTargetValid_ = true;
    f.tab->xrefLiveOwner_ = {777, 7};
    f.tab->xrefHits_ = {kTarget};
    CHECK(!f.tab->followXrefSource(f.ctx, 0));
    CHECK(f.tab->xrefHits_.empty());
    f.tab->frameSnap_ = &f.detached;
}

static void checkListingColumns(const std::string& path) {
    Fixture f(path);
    for (float scale : {1.0f, 1.5f, 2.0f}) {
        theme::SetUiScale(scale);
        ImGuiID tableId = 0;
        frame([&] {
            tableId = ImGui::GetID("asm_full");
            f.tab->renderAssemblyFull(f.ctx);
        });
        ImGuiTable* table = ImGui::GetCurrentContext()->Tables.GetByKey(tableId);
        CHECK(table != nullptr);
        if (!table) continue;
        CHECK(table->Flags & ImGuiTableFlags_Resizable);
        CHECK(table->Flags & ImGuiTableFlags_Hideable);
        CHECK(!(table->Flags & ImGuiTableFlags_NoSavedSettings));
        CHECK(table->Columns[2].Flags & ImGuiTableColumnFlags_NoHide);
        CHECK(table->Columns[4].Flags & ImGuiTableColumnFlags_NoHide);
        CHECK(!(table->Columns[3].Flags & ImGuiTableColumnFlags_NoHide));
        CHECK(!(table->Columns[5].Flags & ImGuiTableColumnFlags_NoHide));
        // Hiding Bytes leaves cursor/branch geometry and action authority intact.
        table->Columns[3].IsUserEnabledNextFrame = false;
        f.assemblyFrame();
        CHECK(!table->Columns[3].IsEnabled);
        CHECK(f.tab->cursorVA_ == kTarget);
        CHECK(f.tab->codePageCache_.size() <= 96);
        size_t iniBytes = 0;
        const char* ini = ImGui::SaveIniSettingsToMemory(&iniBytes);
        CHECK(ini && iniBytes && std::string(ini, iniBytes).find("[Table][") != std::string::npos);
        frame([&] {
            f.tab->renderAssemblyFull(f.ctx);
            CHECK(ImGui::GetCurrentWindow()->RootWindow->Flags & ImGuiWindowFlags_NoSavedSettings);
        }, "Narrow listing integration", ImVec2(820, 560));
        CHECK(f.tab->codePageCache_.size() <= 96);
        table = ImGui::GetCurrentContext()->Tables.GetByKey(tableId);
        if (table) table->Columns[3].IsUserEnabledNextFrame = true;
    }
    theme::SetUiScale(1.0f);
}

int main() {
    char temporary[MAX_PATH]{};
    if (!GetEnvironmentVariableA("DS_STATIC_LISTING_TEST_ROOT", temporary, MAX_PATH)) return 2;
    const std::string path = std::string(temporary) + "\\listing.raw";
    { std::ofstream output(path, std::ios::binary); for (size_t i = 0; i < 128 * 4096 / 2; ++i) { output.put('\xFF'); output.put('\xC0'); } }
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr; io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.DeltaTime = 1.0f / 60.0f;
    io.Fonts->AddFontDefault();
    unsigned char* pixels = nullptr; int width = 0, height = 0;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    // Exercise Copy through an isolated clipboard so tests never replace the
    // analyst's desktop clipboard contents.
    static std::string testClipboard;
    ImGui::GetPlatformIO().Platform_SetClipboardTextFn = [](ImGuiContext*, const char* value) {
        testClipboard = value ? value : "";
    };
    ImGui::GetPlatformIO().Platform_GetClipboardTextFn = [](ImGuiContext*) -> const char* {
        return testClipboard.c_str();
    };
    theme::ApplyTheme();
    try {
        checkRetainedActions(path);
        checkSavedRestore(path);
        checkInputPaths(path, true);
        checkInputPaths(path, false);
        checkSelectionMenu(path, true);
        checkSelectionMenu(path, false);
        checkSavedPatchReopen(path);
        checkContextMenu(path, true);
        checkContextMenu(path, false);
        checkPopupAfterEviction(path);
        checkReferenceWorkflow(path);
        checkNavigationWorkflow(path);
        checkContextActionDispatcher(path);
        checkEffectivePatchPreview(path, false);
        checkEffectivePatchPreview(path, true);
        checkLivePatchMappingAndSkippedOutcome(path);
        checkListingColumns(path);
        checkGameMakerActions(temporary);
    } catch (const std::exception& error) { std::printf("EXCEPTION: %s\n", error.what()); ++failures; }
    ImGui::DestroyContext();
    std::printf("static_listing_actions_test: %s (%d failure(s))\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
