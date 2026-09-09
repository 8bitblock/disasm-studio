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
#include "Tabs/BinaryViewHostTab.h"
#undef private
#include "Ui/Widgets.h"
#include "Ui/Fonts.h"
#include "Ui/NotesEditor.h"
#include "Core/GameMakerArchive.h"
#include "Core/ApiInfo.h"
#include "gamemaker_fixture.h"
#include <windows.h>
#include <cstdio>
#include <cmath>

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
        ImGuiWindow* window = ImGui::FindWindowByName("Listing integration");
        ImGuiTable* table = window ? ImGui::GetCurrentContext()->Tables.GetByKey(
            window->GetID(tab->asmFullProgram_ ? "asm_full" : "asm")) : nullptr;
        CHECK(table != nullptr);
        if (!table) return false;
        // Flow now sits beside the decoded instruction. Hit the requested
        // native column instead of treating arrow anchors as input geometry.
        const ImGuiTableColumn& column = table->Columns[gutter ? 0 : 2];
        CHECK(column.IsEnabled && column.WorkMaxX > column.WorkMinX);
        if (!column.IsEnabled || column.WorkMaxX <= column.WorkMinX) return false;
        for (const auto& row : tab->asmFlow_) if (row.addr == address) {
            const float x = (column.WorkMinX + column.WorkMaxX) * 0.5f;
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
#include "workbench_workflow_fixture.inc"
#include "function_navigator_fixture.inc"
#include "static_xref_workflow_fixture.inc"
#include "seven_improvements_fixture.inc"
#include "notes_editor_fixture.inc"
#include "value_origin_ui_fixture.inc"
#include "string_trace_ui_fixture.inc"
#include "memory_value_hints_fixture.inc"
#include "instruction_copy_fixture.inc"
#include "release_workbench_fixture.inc"
#include "navigator_refinement_fixture.inc"
#include "hex_refinement_fixture.inc"
#include "context_action_regressions.inc"
#include "multi_row_patch_fixture.inc"
#include "patch_restoration_fixture.inc"
#include "patch_tab_visibility_fixture.inc"
#include "patch_panel_fixture.inc"
#include "live_scroll_fixture.inc"
#include "trace_workflow_fixture.inc"
#include "execution_history_fixture.inc"
#include "backtrace_ui_fixture.inc"

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

static void checkSavedPatchRecovery(const std::string& path) {
    ProjectState saved;
    saved.patchSets = {{9, "disabled saved experiment", false}};
    saved.patches = {{kTarget, {0xFF,0xC0}, {0x90,0x90}},
                     {kTarget + 8, {0x01,0x02}, {0x90,0x90}, 9}};
    Fixture f(path, true, &saved);
    auto& project = f.ctx.staticProject();
    CHECK(project.patchRecoveryPending && project.patches.size() == 2);
    CHECK(f.tab->projectPatchWarning_.find("patch #2") != std::string::npos);
    size_t available = 0;
    auto* bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(bytes && available >= 2 && bytes[0] == 0xFF && bytes[1] == 0xC0);
    const uint64_t revision = f.ctx.staticBinary().imageRevision();
    frame([&] { CHECK(!f.tab->restoreSavedPatches(f.ctx, true)); });
    CHECK(project.patches.size() == 2 && f.ctx.staticBinary().imageRevision() == revision);
    frame([&] {
        CHECK(!f.tab->applyPatchBytes(f.ctx, kTarget + 16, {0x90,0x90}, 2, false));
        f.tab->revertPatchAt(f.ctx, kTarget, 0);
    });
    CHECK(project.patches.size() == 2 && f.ctx.staticBinary().imageRevision() == revision);
    f.tab->saveProjectState(f.ctx);
    ProjectState roundtrip;
    CHECK(DeserializeProject(SerializeProject(project), roundtrip));
    CHECK(roundtrip.patches.size() == 2 && roundtrip.patchSets.size() == 1);
    CHECK(roundtrip.patches[1].orig == std::vector<uint8_t>({0x01,0x02}));
    frame([&] { CHECK(f.tab->forgetUnrestoredPatch(f.ctx, 1)); });
    CHECK(!project.patchRecoveryPending && project.patches.size() == 1);
    CHECK(f.tab->projectPatchWarning_.empty());
    bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(bytes && bytes[0] == 0x90 && bytes[1] == 0x90);
}

static void checkBigEndianPatchPadding(const std::string& path) {
    Fixture f(path);
    DecoderConfig machine;
    machine.arch = Arch::ARM;
    machine.byteOrder = ByteOrder::Big;
    machine.engine = Engine::Capstone;
    CHECK(f.ctx.setStaticDecoderConfiguration(machine));
    frame([&] {
        CHECK(f.tab->applyPatchBytes(f.ctx, kTarget, {0xE3,0xA0,0x00,0x01}, 8, true));
    });
    size_t available = 0;
    const auto* bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    const std::vector<uint8_t> expected{0xE3,0xA0,0x00,0x01,0xE3,0x20,0xF0,0x00};
    CHECK(bytes && available >= expected.size() && std::equal(expected.begin(), expected.end(), bytes));
    CHECK(f.ctx.staticProject().patches.size() == 1 && f.ctx.staticProject().patches[0].bytes == expected);
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
    f.tab->patchHex_ = "90 90";
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

    // Use actual archive-decoded rows and production ImGui widgets: readable
    // text must preserve the exact instruction identities used by navigation,
    // selections, and symbolic GML breakpoints.
    const auto instructions = ctx.staticDisassembler()->disassemble(original, bytes.rootLength, bytes.rootOffset, 0);
    const auto variable = std::find_if(instructions.begin(), instructions.end(), [&](const Instruction& in) {
        return in.address == bytes.variableInstruction;
    });
    CHECK(variable != instructions.end());
    if (variable != instructions.end()) {
        CHECK(variable->mnemonic == "push.v" && variable->operands == "self.money");
        CHECK(variable->comment == "VARI #0, id=0");
        CHECK(tab.gmlReadableInstructions_);
        DbgSnapshot detached;
        tab.frameSnap_ = &detached;
        tab.showHints_ = tab.showStringComments_ = true;
        tab.showFnNotes_ = false;
        float branchTargetX = 0.0f;
        const auto rowsFrame = [&]() {
            std::string text;
            tab.asmFullProgram_ = false;
            tab.asmWindowInsns_ = instructions;
            tab.asmWindowBoundaryExact_ = true;
            tab.listRows_.clear(); tab.listingRowsIndex_.reset({}); tab.codeDataMap_.reset();
            frame([&] {
                tab.asmFlow_.clear(); tab.rowGlow_.clear();
                tab.asmGotLaneX_ = tab.asmGotAddrX_ = false;
                ImGui::LogToBuffer();
                if (ImGui::BeginTable("GML instruction rows", 6,
                        ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoSavedSettings)) {
                    const char* names[] = {"", "", "Address", "Bytes", "Instruction", "Comment"};
                    const float widths[] = {18, 40, 115, 200, 500, 2200};
                    for (int i = 0; i < 6; ++i)
                        ImGui::TableSetupColumn(names[i], ImGuiTableColumnFlags_WidthFixed, widths[i]);
                    ImGui::TableHeadersRow();
                    std::string nextHover;
                    for (const auto& in : instructions)
                        tab.renderAsmRow(ctx, in, detached, {}, nextHover, false, true);
                    branchTargetX = ImGui::GetCurrentTable()->Columns[5].WorkMinX + 20.0f;
                    ImGui::EndTable();
                }
                text = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
            }, "GML readable instruction integration", ImVec2(3300, 900));
            return text;
        };
        const auto clickRow = [&](uint64_t address, bool gutter, bool followTarget = false) {
            rowsFrame();
            const auto found = std::find_if(tab.asmFlow_.begin(), tab.asmFlow_.end(), [&](const auto& row) {
                return row.addr == address;
            });
            CHECK(found != tab.asmFlow_.end());
            if (found == tab.asmFlow_.end()) return;
            const float x = followTarget ? branchTargetX : gutter ? tab.asmLaneX_ - 12.0f : tab.asmAddrX_ + 30.0f;
            const float y = found->y;
            ImGui::GetIO().AddMousePosEvent(x, y); rowsFrame();
            ImGui::GetIO().AddMouseButtonEvent(ImGuiMouseButton_Left, true); rowsFrame();
            ImGui::GetIO().AddMouseButtonEvent(ImGuiMouseButton_Left, false); rowsFrame();
        };
        const auto toggleReadableToolbar = [&]() {
            const auto body = [&] { tab.renderAssembly(ctx); };
            frame(body, "GML assembly toolbar integration");
            ImGuiWindow* window = ImGui::FindWindowByName("GML assembly toolbar integration");
            CHECK(window != nullptr);
            if (window) {
                ImGui::FocusWindow(window);
                ImGui::ActivateItemByID(window->GetID("Display##listing_display"));
            }
            frame(body, "GML assembly toolbar integration");
            frame(body, "GML assembly toolbar integration");
            ImGuiWindow* menu = GImGui->OpenPopupStack.empty()
                ? nullptr : GImGui->OpenPopupStack.back().Window;
            CHECK(menu != nullptr);
            if (menu) {
                ImGui::FocusWindow(menu);
                ImGui::ActivateItemByID(menu->GetID("Readable GML"));
            }
            frame(body, "GML assembly toolbar integration");
            frame(body, "GML assembly toolbar integration");
            CHECK(GImGui->OpenPopupStack.empty());
        };
        const char* variableExplanation = "Read this variable and keep its value on the temporary stack for the next operations.";
        for (bool readable : {true, false}) {
            CHECK(tab.gmlReadableInstructions_ == readable);
            ImGui::GetIO().AddMousePosEvent(3250.0f, 850.0f);
            rowsFrame();
            const std::string text = rowsFrame();
            // Operand tokens are separate ImGui items; its text logger inserts
            // spacing between them even when the listing paints them together.
            std::string compactText = text;
            std::erase_if(compactText, [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; });
            CHECK(text.find(readable ? "Read variable" : "push.v") != std::string::npos);
            CHECK(compactText.find("self.money") != std::string::npos);
            CHECK(text.find("VARI #0, id=0") != std::string::npos);
            CHECK(text.find(variableExplanation) != std::string::npos);
            CHECK(text.find(".v = dynamic GameMaker value") != std::string::npos);
            if (readable) CHECK(text.find("push.v") == std::string::npos);
            CHECK(tab.asmFlow_.size() == instructions.size());
            CHECK(!tab.asmFlow_.empty() && tab.asmFlow_[0].branch && tab.asmFlow_[0].target == bytes.stringInstruction);

            tab.showHints_ = false;
            const std::string withoutExplanation = rowsFrame();
            CHECK(withoutExplanation.find(variableExplanation) == std::string::npos);
            CHECK(withoutExplanation.find("VARI #0, id=0") != std::string::npos);
            CHECK(withoutExplanation.find(readable ? "Read variable" : "push.v") != std::string::npos);

            clickRow(bytes.variableInstruction, false);
            CHECK(tab.cursorVA_ == bytes.variableInstruction && tab.selVAs_.count(bytes.variableInstruction) == 1);
            CHECK(tab.listingCursorInstruction_.instruction.mnemonic == "push.v");
            Instruction action; std::string error;
            CHECK(tab.listingActionInstruction(ctx, bytes.variableInstruction, action, error));
            CHECK(action.address == bytes.variableInstruction && action.length == 8 && action.mnemonic == "push.v" &&
                  action.operands == "self.money");
            CHECK(!tab.hasGmlBreakpoint(ctx, bytes.variableInstruction));
            clickRow(bytes.variableInstruction, true);
            CHECK(tab.hasGmlBreakpoint(ctx, bytes.variableInstruction));
            CHECK(tab.breakpoints_.empty() && ctx.staticProject().breakpoints.empty());
            clickRow(bytes.variableInstruction, true);
            CHECK(!tab.hasGmlBreakpoint(ctx, bytes.variableInstruction));

            // The same target link follows the decoded branch destination
            // with either presentation, including the full saved navigation.
            clickRow(bytes.rootOffset, false);
            CHECK(tab.cursorVA_ == bytes.rootOffset);
            clickRow(bytes.rootOffset, false, true);
            CHECK(tab.cursorVA_ == bytes.stringInstruction);
            tab.setStaticCursor(bytes.variableInstruction);
            tab.showHints_ = true;
            toggleReadableToolbar();
            CHECK(tab.gmlReadableInstructions_ != readable);
            CHECK(tab.cursorVA_ == bytes.variableInstruction);
        }
        CHECK(tab.gmlReadableInstructions_);
        tab.frameSnap_ = nullptr;
    }
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
    CHECK(f.tab->pinnedXrefSources().size() == 2 && !f.tab->xrefFilePending_);
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
    CHECK(f.tab->xrefFilter_[0] && f.tab->pinnedXrefSources().size() == 2);
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
    CHECK(f.tab->xrefTargetValid_ && f.tab->pinnedXrefSources().size() == 2);
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

static bool sameRgb(ImU32 a, ImU32 b) {
    return (a & IM_COL32(255, 255, 255, 0)) == (b & IM_COL32(255, 255, 255, 0));
}

static void checkListingVisualSignals(const std::string& path) {
    Fixture f(path);
    const uint64_t first = kTarget;
    std::vector<Instruction> rows;
    for (size_t i = 0; i < 10; ++i) {
        Instruction in;
        in.address = first + i * 2;
        in.length = 2; in.bytes = "FF C0";
        in.mnemonic = "inc"; in.operands = "eax";
        rows.push_back(std::move(in));
    }
    rows[1].mnemonic = "jne"; rows[1].operands = "0x1400C";
    rows[1].isBranch = true; rows[1].branchTarget = rows[2].address;
    rows[1].comment = "decoder branch annotation retained";
    rows[6].mnemonic = "lea"; rows[6].operands = "rax, [0x1000]";
    rows[7].mnemonic = "call"; rows[7].operands = "[0x2000]";
    rows[7].isCall = rows[7].isBranch = true;
    rows[8].comment = "constant-pool annotation retained";
    const char string[] = "String evidence retained";
    CHECK(f.ctx.writeStaticImage(0x1000, reinterpret_cast<const uint8_t*>(string), sizeof(string)) == sizeof(string));
    f.tab->importMap_[0x2000] = "KERNEL32.ReadFile";
    f.tab->comments_[rows[5].address] = "User comment retained";
    BinaryViewTab::Func function{};
    function.address = first; function.size = 64; function.name = "visual_fixture";
    f.tab->functions_ = {function}; f.tab->funcIndexDirty_ = true;
    BinaryViewTab::AnnEntry annotation;
    annotation.fn = first;
    annotation.inlineText[rows[9].address] = "Cached analysis note retained";
    annotation.inlineTip[rows[9].address] = "fixture evidence; confidence high";
    f.tab->annLru_.push_back(std::move(annotation));
    f.tab->annSig_ = f.tab->listingSig(f.ctx);
    f.tab->showNames_ = false;
    f.tab->showStringComments_ = f.tab->showFnNotes_ = f.tab->showHints_ = true;
    f.tab->setStaticCursor(rows[1].address);
    f.tab->breakpoints_.insert(rows[0].address);
    f.tab->traceInstructionHitsFile_[rows[3].address] = 1;
    DbgSnapshot paused;
    paused.state = DbgState::Paused; paused.regs.rip = rows[0].address;
    paused.lastEvent = "Breakpoint hit";

    const auto priorTheme = theme::CurrentTheme();
    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        for (float scale : {1.0f, 1.5f, 2.0f}) {
            theme::SetUiScale(scale); theme::ApplyTheme(palette);
            std::string text;
            frame([&] {
                f.tab->frameSnap_ = &paused;
                f.tab->frameStaticRip_ = paused.regs.rip;
                f.tab->frameStaticRipValid_ = true;
                f.tab->hlJumpVA_ = rows[2].address; f.tab->hlJumpValid_ = true;
                f.tab->navFlashVA_ = rows[4].address; f.tab->navFlashValid_ = true;
                f.tab->navFlashT0_ = ImGui::GetTime();
                f.tab->asmFlow_.clear(); f.tab->rowGlow_.clear();
                f.tab->asmGotLaneX_ = f.tab->asmGotAddrX_ = false;
                const ImVec2 origin = ImGui::GetCursorScreenPos();
                const ImVec2 available = ImGui::GetContentRegionAvail();
                ImDrawList* listingDrawList = nullptr;
                ImGui::LogToBuffer();
                if (ImGui::BeginTable("Visual signal rows", 6,
                        ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoSavedSettings)) {
                    const char* names[] = {"", "", "Address", "Bytes", "Instruction", "Comment"};
                    const float widths[] = {18, 40, 115, 80, 240, 1100};
                    for (int i = 0; i < 6; ++i)
                        ImGui::TableSetupColumn(names[i], ImGuiTableColumnFlags_WidthFixed, widths[i] * scale);
                    ImGui::TableHeadersRow();
                    std::string nextHover;
                    for (const auto& in : rows)
                        f.tab->renderAsmRow(f.ctx, in, paused, {}, nextHover, false, true);
                    listingDrawList = ImGui::GetWindowDrawList();
                    ImGui::EndTable();
                }
                text = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
                CHECK(f.tab->asmFlow_.size() == rows.size());
                CHECK(f.tab->rowGlow_.size() == 5);
                if (f.tab->rowGlow_.size() != 5) return;
                const auto glows = f.tab->rowGlow_;
                // Every palette uses the shared Axiom execution marker; trace
                // coverage retains its independent green success signal.
                CHECK(sameRgb(glows[0].colorPacked, ImGui::GetColorU32(theme::col::accent())));
                CHECK(sameRgb(glows[1].colorPacked, ImGui::GetColorU32(theme::col::accent())));
                CHECK(sameRgb(glows[2].colorPacked, ImGui::GetColorU32(theme::col::jump())));
                CHECK(sameRgb(glows[3].colorPacked, ImGui::GetColorU32(theme::col::good())));
                CHECK(glows[0].intensity > glows[3].intensity);
                CHECK(glows[4].intensity >= 1.0f);
                CHECK(!sameRgb(glows[4].colorPacked, glows[1].colorPacked));
                for (size_t i = 0; i < glows.size(); ++i) {
                    CHECK(std::abs(glows[i].y - f.tab->asmFlow_[i].y) < 0.01f);
                    CHECK(glows[i].h > 0.0f && glows[i].intensity > 0.0f);
                }
                ImDrawList* foreground = ImGui::GetForegroundDrawList();
                const int foregroundBefore = foreground->VtxBuffer.Size;
                CHECK(listingDrawList != nullptr);
                if (!listingDrawList) return;
                const int beforeGlow = listingDrawList->VtxBuffer.Size;
                f.tab->drawRowGlows(origin.x, origin.y, origin.x + available.x, origin.y + available.y,
                                   listingDrawList);
                CHECK(f.tab->rowGlow_.empty());
                CHECK(listingDrawList->VtxBuffer.Size > beforeGlow);
                // Inspect actual post-table draw vertices, not only the queued
                // records: every signal must reach the row-wide glow painter.
                for (const auto& glow : glows) {
                    bool painted = false;
                    for (int i = beforeGlow; i < listingDrawList->VtxBuffer.Size; ++i) {
                        const auto& vertex = listingDrawList->VtxBuffer[i];
                        if (sameRgb(vertex.col, glow.colorPacked) &&
                            (vertex.col & IM_COL32(0, 0, 0, 255)) &&
                            std::abs(vertex.pos.y - glow.y) <= glow.h * 0.5f + 1.0f &&
                            vertex.pos.x < f.tab->asmAddrX_) painted = true;
                    }
                    CHECK(painted);
                }
                const int beforeArrow = listingDrawList->VtxBuffer.Size;
                f.tab->drawAsmArrows(origin.x, origin.y, origin.x + available.x, origin.y + available.y,
                                    listingDrawList);
                CHECK(listingDrawList->VtxBuffer.Size > beforeArrow);
                CHECK(f.tab->asmFlow_[1].branch && f.tab->asmFlow_[1].target == rows[2].address);
                for (int i = beforeArrow; i < listingDrawList->VtxBuffer.Size; ++i) {
                    const auto& vertex = listingDrawList->VtxBuffer[i];
                    CHECK(vertex.pos.x >= f.tab->asmLaneX_ - 2.0f * scale);
                    CHECK(vertex.pos.x < f.tab->asmAddrX_);
                }
                // These signals remain part of the listing's window order;
                // they must never paint through menus or the command palette.
                CHECK(foreground->VtxBuffer.Size == foregroundBefore);
                // Arrival flashes expire through the production time check.
                f.tab->navFlashT0_ = ImGui::GetTime() - 1.2;
                CHECK(f.tab->navFlashAt(rows[4].address) == 0.0f);
                CHECK(!f.tab->navFlashValid_);
            }, "Visual signal integration", ImVec2(3000, 1000));
            for (const char* expected : {"User comment retained", "String evidence retained",
                    "KERNEL32.ReadFile", "constant-pool annotation retained",
                    "decoder branch annotation retained", "Cached analysis note retained"})
                CHECK(text.find(expected) != std::string::npos);
            CHECK(text.find(ApiPurpose("KERNEL32.ReadFile")) != std::string::npos);
            CHECK(text.find("jumps if zero flag is clear; otherwise falls through") != std::string::npos);
            CHECK(text.find('*') != std::string::npos); // breakpoint marker was rendered

            // Exercise the actual LIVE row renderer from a retained display
            // cache. There is no attached process; identity-checked reads return
            // empty and the existing matching cache supplies all rendered rows.
            f.tab->liveInsns_.assign(rows.begin(), rows.begin() + 5);
            f.tab->liveIdxOf_.clear(); f.tab->liveFuncSet_.clear();
            for (size_t i = 0; i < f.tab->liveInsns_.size(); ++i)
                f.tab->liveIdxOf_[f.tab->liveInsns_[i].address] = static_cast<int>(i);
            f.tab->liveBrowseValid_ = false;
            f.tab->liveCacheStart_ = first;
            f.tab->liveCacheSig_ = first ^ (paused.regs.rip * 0x9E3779B97F4A7C15ull) ^
                (static_cast<uint64_t>(f.tab->liveGen_) << 1) ^
                (f.tab->functionsGen_ * 0xD6E8FEB86659FD93ull) ^
                (static_cast<uint64_t>(f.tab->symPid_) << 33) ^
                (static_cast<uint64_t>(f.ctx.staticEngine()) << 56);
            paused.breakpoints = {{first, {}, 1, 1}};
            f.tab->lastScrolledRip_ = first; f.tab->lastScrolledRipValid_ = true;
            f.tab->showRegHints_ = false;
            f.tab->setLiveCursor(rows[1].address);
            int withoutTrace = 0, withTrace = 0;
            for (bool traced : {false, true}) {
                f.tab->traceInstructionHitsLive_.clear();
                if (traced) f.tab->traceInstructionHitsLive_[rows[3].address] = 1;
                frame([&] {
                    f.tab->frameSnap_ = &paused;
                    f.tab->navFlashVA_ = rows[4].address; f.tab->navFlashValid_ = true;
                    f.tab->navFlashT0_ = ImGui::GetTime();
                    const ImGuiID liveTableId = ImGui::GetCurrentWindow()->GetID("live_asm");
                    const int foregroundBefore = ImGui::GetForegroundDrawList()->VtxBuffer.Size;
                    ImGui::LogToBuffer();
                    f.tab->renderLiveListing(f.ctx, paused, first);
                    const std::string liveText = ImGui::GetCurrentContext()->LogBuffer.c_str();
                    ImGui::LogFinish();
                    CHECK(liveText.find("decoder branch annotation retained") != std::string::npos);
                    CHECK(liveText.find('*') != std::string::npos);
                    CHECK(liveText.find("Could not read process memory") == std::string::npos);
                    CHECK(f.tab->rowGlow_.empty()); // the actual LIVE post-table pass consumed them
                    const ImGuiTable* liveTable = ImGui::TableFindByID(liveTableId);
                    CHECK(liveTable && liveTable->InnerWindow && liveTable->InnerWindow != liveTable->OuterWindow);
                    if (!liveTable || !liveTable->InnerWindow) return;
                    const ImDrawList* listingDrawList = liveTable->InnerWindow->DrawList;
                    for (const auto color : {theme::col::good(), theme::col::accent(), theme::col::jump()}) {
                        bool painted = false;
                        for (const auto& vertex : listingDrawList->VtxBuffer)
                            if (sameRgb(vertex.col, ImGui::GetColorU32(color))) painted = true;
                        CHECK(painted);
                    }
                    CHECK(ImGui::GetForegroundDrawList()->VtxBuffer.Size == foregroundBefore);
                    (traced ? withTrace : withoutTrace) = listingDrawList->VtxBuffer.Size;
                }, "Live visual signal integration", ImVec2(3000, 1000));
            }
            CHECK(withTrace > withoutTrace); // coverage adds real rendered glow geometry
            f.tab->setStaticCursor(rows[1].address);
        }
    }
    f.tab->frameSnap_ = &f.detached;
    theme::SetUiScale(1.0f); theme::ApplyTheme(priorTheme);
}

// Exercise the real shell through its public entry point. Window inspection is
// confined to ImGui's own rendered layout; App gets no private fixture access.
static void workbenchFrame(App& app, ImVec2 size) {
    ImGui::GetIO().DisplaySize = size;
    ImGui::NewFrame();
    app.render();
    ImGui::Render();
}

static ImGuiWindow* activeWorkbenchContent() {
    ImGuiWindow* main = ImGui::FindWindowByName("##main");
    if (!main) return nullptr;
    ImGuiWindow* content = nullptr;
    for (ImGuiWindow* child : main->DC.ChildWindows) {
        if (child->LastFrameActive != ImGui::GetFrameCount() ||
            !std::strstr(child->Name, "##tabcontent")) continue;
        CHECK(content == nullptr);
        content = child;
    }
    return content;
}

static void checkWorkbenchDestination(const char* name) {
    ImGuiWindow* main = ImGui::FindWindowByName("##main");
    ImGuiWindow* content = activeWorkbenchContent();
    CHECK(main && content);
    if (!main || !content) return;
    // The ID identifies the tab's retained content owner, including destinations
    // whose empty-state text is intentionally similar.
    const ImGuiID owner = ImHashStr(name, 0, main->ID);
    const ImGuiID expected = ImHashStr("##tabcontent", 0, owner);
    CHECK(content->ChildId == expected);
}

static void workbenchChord(App& app, ImVec2 size, ImGuiKey key) {
    ImGuiIO& io = ImGui::GetIO();
    io.AddKeyEvent(ImGuiMod_Ctrl, true);
    io.AddKeyEvent(key, true);
    workbenchFrame(app, size);
    io.AddKeyEvent(key, false);
    io.AddKeyEvent(ImGuiMod_Ctrl, false);
    workbenchFrame(app, size);
    workbenchFrame(app, size);
}

static void checkWorkbenchBounds(ImVec2 size) {
    const char* bands[] = {"##MainMenuBar", "##tabstrip",
                          "##debugbar", "##main", "##status"};
    ImGuiWindow* documents = ImGui::FindWindowByName("##document-strip");
    CHECK(!documents || documents->LastFrameActive != ImGui::GetFrameCount());
    float previousBottom = 0.0f;
    for (const char* name : bands) {
        ImGuiWindow* window = ImGui::FindWindowByName(name);
        CHECK(window && window->LastFrameActive == ImGui::GetFrameCount());
        if (!window) continue;
        CHECK(window->Size.x > 0.0f && window->Size.y > 0.0f);
        CHECK(window->Pos.x >= -1.0f && window->Pos.y >= previousBottom - 1.0f);
        CHECK(window->Pos.x + window->Size.x <= size.x + 1.0f);
        if (window->Pos.y + window->Size.y > size.y + 1.0f)
            std::printf("[diag] shell %s y=%.1f h=%.1f viewport=%.1f min=%.1f\n",
                name, window->Pos.y, window->Size.y, size.y, ImGui::GetStyle().WindowMinSize.y);
        CHECK(window->Pos.y + window->Size.y <= size.y + 1.0f);
        previousBottom = window->Pos.y + window->Size.y;
    }
    CHECK(std::abs(previousBottom - size.y) <= 1.0f);
}

static void checkWorkbenchShell() {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    const auto priorTheme = theme::CurrentTheme();
    App app;
    const char* destinations[] = {"Projects", "Communications", "Sig Scanner", "Binary View",
                                 "Memory Tools", "Binary Diff", "Binary Tech", "Cortex", "Prism"};
    for (float scale : {1.0f, 1.5f, 2.0f}) {
        // Include the actual UI/mono atlas sizes, rather than only scaling the
        // empty spacing around an unchanged test font.
        ui::LoadFonts(scale);
        unsigned char* pixels = nullptr; int atlasWidth = 0, atlasHeight = 0;
        ImGui::GetIO().Fonts->GetTexDataAsRGBA32(&pixels, &atlasWidth, &atlasHeight);
        CHECK(pixels && atlasWidth > 0 && atlasHeight > 0);
        theme::SetUiScale(scale);
        for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
            theme::ApplyTheme(palette);
            for (ImVec2 size : {ImVec2(820, 560), ImVec2(1600, 960)}) {
                std::printf("[ui] workbench %s %.1fx %.0fx%.0f\n",
                            theme::ThemeName(palette), scale, size.x, size.y);
                for (int i = 0; i < 3; ++i) workbenchFrame(app, size);
                for (int tab = 0; tab < 9; ++tab) {
                    workbenchChord(app, size, static_cast<ImGuiKey>(ImGuiKey_1 + tab));
                    checkWorkbenchDestination(destinations[tab]);
                    checkWorkbenchBounds(size);
                }

                // The palette must remain usable when its preferred size is
                // larger than the available window, including at 200% DPI.
                workbenchChord(app, size, ImGuiKey_K);
                ImGuiWindow* paletteWindow = ImGui::FindWindowByName("##cmdpalette");
                CHECK(paletteWindow && paletteWindow->LastFrameActive == ImGui::GetFrameCount());
                if (!paletteWindow) continue;
                CHECK(paletteWindow->Pos.x >= 0.0f && paletteWindow->Pos.y >= 0.0f);
                CHECK(paletteWindow->Pos.x + paletteWindow->Size.x <= size.x + 1.0f);
                CHECK(paletteWindow->Pos.y + paletteWindow->Size.y <= size.y + 1.0f);
                CHECK(paletteWindow->ScrollMax.x <= 0.5f && paletteWindow->ScrollMax.y <= 0.5f);
                CHECK(ImGui::GetActiveID() == paletteWindow->GetID("##palq"));
                ImGuiWindow* blocker = ImGui::FindWindowByName("##cmdpalette_blocker");
                CHECK(blocker && blocker->LastFrameActive == ImGui::GetFrameCount());
                if (blocker) {
                    const int blockerOrder = ImGui::FindWindowDisplayIndex(blocker);
                    CHECK(ImGui::FindWindowDisplayIndex(paletteWindow) > blockerOrder);
                    for (const char* name : {"##MainMenuBar", "##tabstrip",
                                             "##debugbar", "##main", "##status"}) {
                        ImGuiWindow* underlying = ImGui::FindWindowByName(name);
                        CHECK(underlying && ImGui::FindWindowDisplayIndex(underlying) < blockerOrder);
                    }
                }
                ImGuiWindow* results = nullptr;
                for (ImGuiWindow* child : paletteWindow->DC.ChildWindows)
                    if (child->LastFrameActive == ImGui::GetFrameCount() &&
                        std::strstr(child->Name, "##palresults")) results = child;
                CHECK(results != nullptr);
                if (results) {
                    CHECK(results->Size.y > 0.0f && results->ScrollMax.x <= 0.5f);
                    CHECK(results->Pos.y > paletteWindow->Pos.y);
                    CHECK(results->Pos.y + results->Size.y + ImGui::GetTextLineHeight() <=
                          paletteWindow->Pos.y + paletteWindow->Size.y);
                }
                // While typing in the palette, the underlying workspace must
                // ignore the same shortcut which normally selects Projects.
                workbenchChord(app, size, ImGuiKey_1);
                checkWorkbenchDestination("Prism");

                ImGuiWindow* strip = ImGui::FindWindowByName("##tabstrip");
                CHECK(strip != nullptr);
                if (!strip) continue;
                // The left edge of the Projects cell is outside the centered
                // palette. Clicking it first dismisses; the identical click
                // after dismissal must activate Projects, proving that the
                // first click was consumed rather than reaching an inert area.
                const ImVec2 projectsPoint(strip->Pos.x + 10.0f * scale,
                                            strip->Pos.y + strip->Size.y * 0.5f);
                CHECK(!paletteWindow->Rect().Contains(projectsPoint));
                ImGuiIO& io = ImGui::GetIO();
                io.AddMousePosEvent(projectsPoint.x, projectsPoint.y);
                workbenchFrame(app, size);
                io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
                workbenchFrame(app, size);
                io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
                workbenchFrame(app, size);
                workbenchFrame(app, size);
                CHECK(paletteWindow->LastFrameActive != ImGui::GetFrameCount());
                checkWorkbenchDestination("Prism");
                // Retire a failed overlay through its real shortcut so one
                // dismissal regression does not invalidate later scenarios.
                if (paletteWindow->LastFrameActive == ImGui::GetFrameCount())
                    workbenchChord(app, size, ImGuiKey_K);
                io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
                workbenchFrame(app, size);
                io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
                workbenchFrame(app, size);
                workbenchFrame(app, size);
                checkWorkbenchDestination("Projects");
                CHECK(!app.wantsExit());
                io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
            }
        }
    }
    theme::SetUiScale(1.0f); theme::ApplyTheme(priorTheme);
}

#include "shell_refinement_fixture.inc"
#include "ui_consistency_fixture.inc"

namespace ds {
// Observe the real App/service close boundary without exposing a product API.
struct AppExitTestAccess {
    static AppContext& context(App& app) { return app.ctx_; }
    static void poll(App& app) { app.ctx_.pollArtifactWrites(); app.pollExit(); }
};
namespace debugger_detail {
struct LifecycleTestAccess {
    static void publish(Debugger& debugger, DbgLifecycleSnapshot snapshot) {
        // This fixture never queues native work, changes DbgState or gives the
        // idle lifecycle worker a target. Only public completion evidence varies.
        std::lock_guard lock(debugger.lifecycleMtx_);
        debugger.lifecycle_ = std::move(snapshot);
    }
    static void setCleanupOnly(Debugger& debugger, bool value) {
        // Retain only the public cleanup evidence; this fixture owns no target.
        std::lock_guard lock(debugger.mtx_);
        debugger.cleanupOnly_ = value;
    }
};
}
}

static void checkApplicationExit(const std::string& path) {
    enum class ArtifactCase { Success, Failure, ReportFailure };
    const auto root = std::filesystem::path(path).parent_path();
    for (const auto scenario : {ArtifactCase::Success, ArtifactCase::Failure, ArtifactCase::ReportFailure}) {
        App app;
        auto& ctx = AppExitTestAccess::context(app);
        std::promise<void> release;
        const auto gate = release.get_future().share();
        bool completed = false, callbackBeforeExit = false;
        std::string completionFailure;
        DbgLifecycleSnapshot historical;
        historical.requestId = 899;
        historical.command = DbgLifecycleCommand::Launch;
        historical.completed = true;
        historical.error = "unrelated historical launch failure";
        debugger_detail::LifecycleTestAccess::publish(ctx.debug, historical);
        std::string message;
        CHECK(ctx.queueArtifactWrite([gate, root, scenario] {
            gate.wait();
            const std::vector<uint8_t> bytes{0x12, 0x34};
            if (scenario == ArtifactCase::Failure)
                return WriteArtifactBytes(root / L"exit-missing-parent" / L"failed.bin", bytes);
            auto result = WriteArtifactBytes(root / L"exit-artifact.bin", bytes);
            if (scenario == ArtifactCase::ReportFailure) {
                const auto report = WriteArtifactBytes(root / L"exit-missing-parent" / L"report.txt", bytes);
                if (!report.success) result.warning = "Artifact saved, but report failed: " + report.error;
            }
            return result;
        }, message, [&](const ArtifactWriteResult& result) {
            completed = true;
            callbackBeforeExit = !app.wantsExit();
            completionFailure = result.success ? result.warning : result.error;
        }));
        app.requestExit();
        AppExitTestAccess::poll(app);
        CHECK(!app.wantsExit()); // the accepted writer is still gated
        release.set_value();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!completed && std::chrono::steady_clock::now() < deadline) {
            AppExitTestAccess::poll(app);
            Sleep(1);
        }
        CHECK(completed && callbackBeforeExit);
        CHECK(app.wantsExit() == (scenario == ArtifactCase::Success));
        if (scenario != ArtifactCase::Success) {
            CHECK(!completionFailure.empty() && app.exitFailureReason() == completionFailure);
            AppExitTestAccess::poll(app);
            CHECK(!app.wantsExit()); // failure cancels rather than defers close
            app.requestExit();      // a new explicit close can acknowledge it
            CHECK(app.wantsExit());
        }
    }

    enum class LifecycleCase { Success, Failure, Superseded };
    for (const auto scenario : {LifecycleCase::Success, LifecycleCase::Failure, LifecycleCase::Superseded}) {
        App app;
        auto& ctx = AppExitTestAccess::context(app);
        DbgLifecycleSnapshot lifecycle;
        lifecycle.requestId = 900;
        lifecycle.command = DbgLifecycleCommand::Detach;
        lifecycle.state = DbgLifecycleState::Stopping;
        lifecycle.busy = true;
        debugger_detail::LifecycleTestAccess::publish(ctx.debug, lifecycle);
        app.requestExit();
        CHECK(!app.wantsExit());
        lifecycle.busy = false;
        lifecycle.completed = true;
        lifecycle.succeeded = scenario != LifecycleCase::Failure;
        lifecycle.state = lifecycle.succeeded ? DbgLifecycleState::Detached : DbgLifecycleState::Failed;
        if (scenario == LifecycleCase::Superseded) ++lifecycle.requestId;
        debugger_detail::LifecycleTestAccess::publish(ctx.debug, lifecycle);
        AppExitTestAccess::poll(app);
        CHECK(app.wantsExit() == (scenario == LifecycleCase::Success));
        if (scenario != LifecycleCase::Success) {
            AppExitTestAccess::poll(app);
            CHECK(!app.wantsExit());
        }
        debugger_detail::LifecycleTestAccess::publish(ctx.debug, {});
    }
    for (const bool cleanupFailed : {false, true}) {
        App app;
        auto& ctx = AppExitTestAccess::context(app);
        DbgLifecycleSnapshot startup;
        startup.requestId = 901;
        startup.command = DbgLifecycleCommand::Launch;
        startup.state = DbgLifecycleState::Starting;
        startup.busy = true;
        debugger_detail::LifecycleTestAccess::publish(ctx.debug, startup);
        app.requestExit();
        CHECK(!app.wantsExit());
        const auto cancelled = ctx.debug.lifecycleSnapshot();
        CHECK(cancelled.requestId == startup.requestId && cancelled.busy &&
              cancelled.state == DbgLifecycleState::Stopping);
        startup.busy = false;
        startup.completed = true;
        startup.cancelled = true;
        startup.state = cleanupFailed ? DbgLifecycleState::Failed : DbgLifecycleState::Detached;
        if (cleanupFailed) startup.error = "Startup cancellation could not restore the target.";
        debugger_detail::LifecycleTestAccess::setCleanupOnly(ctx.debug, cleanupFailed);
        debugger_detail::LifecycleTestAccess::publish(ctx.debug, startup);
        AppExitTestAccess::poll(app);
        CHECK(app.wantsExit() == !cleanupFailed);
        CHECK(!app.exitPending());
        if (cleanupFailed) {
            CHECK(app.exitFailureReason() == startup.error);
            AppExitTestAccess::poll(app);
            CHECK(!app.wantsExit() && !app.exitPending());
            const auto retained = ctx.debug.lifecycleSnapshot();
            CHECK(retained.requestId == startup.requestId &&
                  retained.command == DbgLifecycleCommand::Launch && !retained.busy);
        }
        debugger_detail::LifecycleTestAccess::setCleanupOnly(ctx.debug, false);
        debugger_detail::LifecycleTestAccess::publish(ctx.debug, {});
    }
}

int main() {
    char patchRestorationChild[8]{};
    if (GetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD", patchRestorationChild,
                               static_cast<DWORD>(sizeof(patchRestorationChild))) &&
        patchRestorationChild[0] == '1') {
        Sleep(30000);
        return 0;
    }
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
        char liveScrollOnly[8]{};
        const bool onlyLiveScroll = GetEnvironmentVariableA("DS_LIVE_SCROLL_ONLY",
            liveScrollOnly, sizeof(liveScrollOnly)) && liveScrollOnly[0] == '1';
        if (onlyLiveScroll) {
            checkLiveAssemblyScrolling(path);
        } else {
        checkRetainedActions(path);
        checkSavedRestore(path);
        checkInputPaths(path, true);
        checkInputPaths(path, false);
        checkSelectionMenu(path, true);
        checkSelectionMenu(path, false);
        checkSavedPatchReopen(path);
        checkSavedPatchRecovery(path);
        checkBigEndianPatchPadding(path);
        checkContextMenu(path, true);
        checkContextMenu(path, false);
        checkPopupAfterEviction(path);
        checkMultiRowPatch(path);
        checkReferenceWorkflow(path);
        checkNavigationWorkflow(path);
        checkIntentWorkflows(path);
        checkWorkflowRefinement(path);
        checkNavigatorRefinement(path);
        checkFunctionNavigator(path);
        checkStaticXrefWorkflow(path);
        checkNotesAndTypesPreservation(path);
        checkCompletePinnedReferences(path);
        checkTypesClosePrompt(path);
        checkNotesEditorBoundaries();
        checkValueOriginWorkbench(path);
        checkStringTraceWorkbench(path);
        checkMemoryValueHints(path);
        checkInstructionCopy(path);
        checkContextActionDispatcher(path);
        checkEffectivePatchPreview(path, false);
        checkEffectivePatchPreview(path, true);
        checkLivePatchMappingAndSkippedOutcome(path);
        checkStaticPatchRestoration(path);
        checkLivePatchByteRestoration(path);
        checkPatchTabVisibility(path);
        checkLiveAssemblyScrolling(path);
        checkTraceWorkflow(path);
        checkExecutionHistoryView();
        checkBacktraceWorkbench(path);
        checkListingColumns(path);
        checkListingVisualSignals(path);
        checkGameMakerActions(temporary);
        checkReleaseWorkbench(path);
        checkRegisterEditorPresentation(path);
        checkInspectorObservationValidity(path);
        checkWorkbenchShell();
        checkApplicationExit(path);
        checkPaletteActionRetention();
        checkShellKeyboardNavigation();
        checkUiConsistencyMatrix();
        checkHexRefinement(path); // actual-font matrix runs after default-font fixtures
        checkPatchPanelRestoration(path);
        }
    } catch (const std::exception& error) { std::printf("EXCEPTION: %s\n", error.what()); ++failures; }
    ImGui::DestroyContext();
    std::printf("static_listing_actions_test: %s (%d failure(s))\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
