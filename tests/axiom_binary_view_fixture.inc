// Include after static_listing_actions_test.cpp in the production-object harness.
#include "ui_capture.h"
// Synthetic snapshots only: no process is launched, attached, or written.
static void checkAxiomThemeRetainedDraft(const std::string& path) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    Fixture draft(path);
    DbgSnapshot paused;
    paused.state = DbgState::Paused;
    paused.pid = 0xFFFFFFF0; paused.sessionGeneration = 113;
    paused.activeTid = paused.tid = 42;
    paused.regs.rip = kTarget + 10;
    paused.regs.rax = 0x1234;
    draft.ctx.frameDebugSnapshot = &paused;
    draft.tab->stringsAutoPid_ = paused.pid;
    draft.tab->stringsAutoSessionGeneration_ = paused.sessionGeneration;
    draft.tab->focusRegistersTab_ = true;
    draft.tab->lowerAdvancedMode_ = false;
    draft.tab->lowerDockCollapsed_ = false;
    draft.tab->bottomDockH_ = 400;
    auto paint = [&] {
        frame([&] { draft.tab->render(draft.ctx); }, "Axiom retained draft QA", ImVec2(1920, 1200));
        draft.tab->frameSnap_ = &paused;
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    settle(); // establish the authored pause owner before creating its draft

    // Real navigation commands leave both history directions populated, with
    // FILE address zero and multiple representations retained in the back stack.
    draft.tab->navigateToStaticView(0, DocumentView::Assembly);
    draft.tab->navigateToStaticView(kTarget + 2, DocumentView::Hex);
    draft.tab->navigateToStaticView(kTarget + 4, DocumentView::Assembly);
    draft.tab->navigateToStaticView(kTarget + 6, DocumentView::Graph);
    draft.tab->navBack();
    settle();
    CHECK(draft.tab->canNavigateBack() && draft.tab->canNavigateForward());
    CHECK(draft.ctx.staticNavigation().backStack().size() >= 2);
    CHECK(draft.ctx.staticNavigation().forwardStack().size() == 1);
    CHECK(draft.tab->mainView_ == 0 && draft.tab->cursorVA_ == kTarget + 4);

    ImGuiWindow* registers = releaseWindow("/regs_");
    CHECK(registers != nullptr);
    if (registers) {
        const ImGuiID row = registers->GetID(4); // the production RAX row
        ImGui::FocusWindow(registers);
        ImGui::ActivateItemByID(ImHashStr("Edit", 0, row));
        settle();
        CHECK(draft.tab->regEditIdx_ == 4);
        const ImGuiID input = ImHashStr("##re", 0, row);
        CHECK(ImGui::GetActiveID() == input);
        CHECK(std::string(draft.tab->regEditBuf_.data()) == "1234");
        // Type into the real retained ImGui InputText. Enter/Save is never sent.
        io.AddKeyEvent(ImGuiMod_Ctrl, true);
        io.AddKeyEvent(ImGuiKey_A, true); paint();
        io.AddKeyEvent(ImGuiKey_A, false);
        io.AddKeyEvent(ImGuiMod_Ctrl, false); paint();
        const std::string unsaved = "FEDCBA9876543210";
        io.AddInputCharactersUTF8(unsaved.c_str()); settle();
        CHECK(std::string(draft.tab->regEditBuf_.data()) == unsaved);
        const auto back = draft.ctx.staticNavigation().backStack();
        const auto forward = draft.ctx.staticNavigation().forwardStack();
        const DocumentLocation selection = draft.ctx.staticNavigation().current();
        CHECK(selection.valid && selection.va == kTarget + 4 &&
              selection.view == DocumentView::Assembly && selection.addressSpace == DocumentAddressSpace::File);
        for (const auto palette : {theme::ThemeId::Axiom, theme::ThemeId::Midnight,
                                   theme::ThemeId::Light, theme::ThemeId::Axiom}) {
            theme::ApplyTheme(palette);
            settle();
            CHECK(theme::CurrentTheme() == palette);
            CHECK(draft.tab->regEditIdx_ == 4);
            CHECK(std::string(draft.tab->regEditBuf_.data()) == unsaved);
            CHECK(DebugTargetIdentityMatches(draft.tab->regEditOwner_, {paused.pid, paused.sessionGeneration}));
            CHECK(draft.tab->regEditTid_ == paused.activeTid);
            CHECK(draft.tab->regEditRip_ == paused.regs.rip);
            CHECK(draft.tab->regEditIs32_ == paused.is32);
            CHECK(draft.tab->regEditStatus_.empty());
            CHECK(draft.ctx.staticNavigation().backStack() == back);
            CHECK(draft.ctx.staticNavigation().forwardStack() == forward);
            CHECK(draft.ctx.staticNavigation().current() == selection);
            CHECK(draft.tab->mainView_ == 0 && draft.tab->cursorValid_ &&
                  !draft.tab->cursorLive_ && draft.tab->cursorVA_ == selection.va);
            CHECK(paused.regs.rax == 0x1234);
            CHECK(!draft.ctx.debug.snapshot().attached() && !draft.ctx.debug.lifecycleSnapshot().busy);
        }
    }
    // Cancellation and invalidation remain covered separately by
    // checkRegisterEditorPresentation; this case never submits the dirty draft.
    ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    draft.ctx.frameDebugSnapshot = nullptr;
    draft.tab->frameSnap_ = &draft.detached;
}

static void checkAxiomReferenceBreakpoints(const std::string& path) {
    ImGuiIO& io = ImGui::GetIO();
    auto colorPresent = [&](ImU32 color, float belowY) {
        const ImDrawData* data = ImGui::GetDrawData();
        for (int list = 0; data && list < data->CmdListsCount; ++list)
            for (const ImDrawVert& vertex : data->CmdLists[list]->VtxBuffer)
                if (vertex.col == color && vertex.pos.y >= belowY) return true;
        return false;
    };
    for (bool liveSchema : {false, true}) for (bool startMidnight : {false, true}) {
        ImGui::ClosePopupsOverWindow(nullptr, false); ImGui::ClearActiveID();
        io.ClearInputKeys(); io.ClearInputMouse();
        Fixture f(path);
        if (liveSchema) {
            f.detached.state = DbgState::Paused; f.detached.pid = 0xFFFFFFF0;
            f.detached.sessionGeneration = 180; f.detached.activeTid = f.detached.tid = 42;
            SwBreakpointInfo live; live.address = kTarget + 32;
            f.detached.breakpoints = {live};
        }
        f.tab->breakpoints_.insert(0); // valid FILE VA zero, selected independently of stop state
        f.tab->setStaticCursor(0);
        const char* title = liveSchema ? (startMidnight ? "Reference legacy live QA" : "Reference fresh live QA")
                                      : (startMidnight ? "Reference legacy breakpoint QA" : "Reference fresh breakpoint QA");
        const int stateColumn = liveSchema ? 6 : 5, symbolColumn = liveSchema ? 7 : 6;
        auto paint = [&] {
            frame([&] { f.tab->frameSnap_ = &f.detached; f.tab->renderLowerTabs(f.ctx, false); }, title, ImVec2(1200, 480));
            CHECK(GImGui->ErrorCountCurrentFrame == 0);
        };
        auto settle = [&] { paint(); paint(); paint(); };
        auto tableFor = [&]() -> ImGuiTable* {
            for (int i = 0; i < GImGui->Tables.GetBufSize(); ++i) {
                ImGuiTable* table = GImGui->Tables.GetByIndex(i);
                if (table && table->LastFrameActive == GImGui->FrameCount && table->OuterWindow &&
                    std::strcmp(table->OuterWindow->RootWindow->Name, title) == 0) return table;
            }
            return nullptr;
        };
        theme::ApplyTheme(startMidnight ? theme::ThemeId::Midnight : theme::ThemeId::Axiom);
        settle();
        ImGuiTable* table = tableFor(); CHECK(table && table->ColumnsCount == (liveSchema ? 8 : 7));
        const ImGuiID originalId = table ? table->ID : 0;
        theme::ApplyTheme(theme::ThemeId::Axiom); settle();
        CHECK(f.tab->breakpointDisplayCount(f.ctx) == (liveSchema ? 2u : 1u));
        if (ImGuiWindow* window = ImGui::FindWindowByName(title)) {
            const ImGuiTabBar* bar = GImGui->TabBars.GetByKey(window->GetID("lower_primary"));
            CHECK(bar != nullptr);
            if (bar) {
                const ImGuiID originalTab = ImHashStr("Breakpoints", 0, bar->ID);
                const ImGuiTabItem* item = ImGui::TabBarFindTabByID(const_cast<ImGuiTabBar*>(bar), originalTab);
                CHECK(item != nullptr);
                if (item) CHECK(item->RequestedWidth > ImGui::CalcTextSize("Breakpoints").x + 25.0f);
            }
        }
        table = tableFor(); CHECK(table && table->ID == originalId && table->ColumnsCount == (liveSchema ? 8 : 7));
        if (liveSchema && table) {
            // Untouched defaults survive palette changes before customization.
            CHECK(!table->Columns[3].IsUserEnabled);
            theme::ApplyTheme(theme::ThemeId::Midnight); settle();
            theme::ApplyTheme(theme::ThemeId::Axiom); settle();
            table = tableFor();
            CHECK(table && !table->Columns[3].IsUserEnabled);
        }
        if (table) {
            CHECK(table->DisplayOrderToIndex[0] == stateColumn && table->DisplayOrderToIndex[1] == 0 && table->DisplayOrderToIndex[2] == symbolColumn);
            CHECK(table->OuterWindow->RootWindow->Flags & ImGuiWindowFlags_NoSavedSettings);
            CHECK(!(table->Flags & ImGuiTableFlags_NoSavedSettings));
            CHECK(colorPresent(ImGui::GetColorU32(theme::col::breakpointFill()), table->InnerRect.Min.y));
            f.tab->cursorValid_ = false; settle();
            CHECK(!colorPresent(ImGui::GetColorU32(theme::col::breakpointFill()), table->InnerRect.Min.y));
            f.tab->setStaticCursor(0);
            table->Columns[0].WidthRequest = 191.0f;
            table->Columns[symbolColumn].StretchWeight = 2.75f;
            table->Columns[1].IsUserEnabledNextFrame = false;
            const int reordered[] = {symbolColumn, stateColumn, 0, 1, 2, liveSchema ? 5 : 4, liveSchema ? 4 : 3, 3};
            for (int position = 0; position < table->ColumnsCount; ++position) {
                table->Columns[reordered[position]].DisplayOrder = static_cast<ImGuiTableColumnIdx>(position);
                table->DisplayOrderToIndex[position] = static_cast<ImGuiTableColumnIdx>(reordered[position]);
            }
            table->IsSettingsDirty = true;
            settle(); // production EndTable serializes the complete customization
            CHECK(ImGui::TableSettingsFindByID(originalId) != nullptr);
            for (int themeIndex = 0; themeIndex < static_cast<int>(theme::ThemeId::Count); ++themeIndex) {
                theme::ApplyTheme(static_cast<theme::ThemeId>(themeIndex)); settle();
                table = tableFor();
                CHECK(table && table->ID == originalId && table->ColumnsCount == (liveSchema ? 8 : 7));
                if (table) {
                    CHECK(colorPresent(ImGui::GetColorU32(theme::col::breakpointFill()), table->InnerRect.Min.y));
                    CHECK(std::fabs(table->Columns[0].WidthRequest - 191.0f) < 1.0f);
                    CHECK(std::fabs(table->Columns[symbolColumn].StretchWeight - 2.75f) < 0.01f);
                    CHECK(!table->Columns[1].IsUserEnabled);
                    for (int position = 0; position < table->ColumnsCount; ++position)
                        CHECK(table->DisplayOrderToIndex[position] == reordered[position]);
                }
            }
        }
        // The header action adds at the selected address, and cannot turn an
        // existing breakpoint off when activated again.
        f.tab->setStaticCursor(kTarget);
        releaseActivate(ImGui::FindWindowByName(title), "+ Add breakpoint"); settle();
        CHECK(f.tab->breakpoints_.count(kTarget) == 1);
        releaseActivate(ImGui::FindWindowByName(title), "+ Add breakpoint"); settle();
        CHECK(f.tab->breakpoints_.count(kTarget) == 1);
    }

    Fixture f(path);
    f.detached.state = DbgState::Paused; f.detached.pid = 0xFFFFFFF0;
    f.detached.sessionGeneration = 181; f.detached.activeTid = f.detached.tid = 42;
    DbgModule module; module.base = 0x100000; module.size = 128 * 4096;
    module.name = "authored-breakpoint-fixture"; module.path = f.path; module.loadGeneration = 4;
    f.detached.modules = {module};
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = true; identity.pid = f.detached.pid; identity.sessionGeneration = f.detached.sessionGeneration;
    identity.moduleBase = module.base; identity.moduleSize = module.size; identity.moduleName = module.name;
    identity.modulePath = module.path; identity.moduleLoadGeneration = module.loadGeneration;
    f.ctx.setStaticDebugImageIdentity(identity);
    f.tab->frameSnap_ = &f.detached;
    f.tab->breakpoints_.insert(0); f.tab->setStaticCursor(0);
    uint64_t runtime = 0;
    CHECK(f.tab->staticBreakpointRuntimeVA(f.ctx, 0, runtime) && runtime == module.base);
    f.tab->condBuf_[0] = "rax ==";
    auto& failure = f.tab->staticBreakpointArming_[0];
    failure.pid = f.detached.pid; failure.sessionGeneration = f.detached.sessionGeneration;
    failure.runtimeVA = runtime; failure.moduleBase = module.base; failure.moduleLoadGeneration = module.loadGeneration;
    failure.error = "Authored invalid condition";
    auto paint = [&] {
        frame([&] { f.tab->frameSnap_ = &f.detached; f.tab->renderLowerTabs(f.ctx, false); }, "Reference owned breakpoint QA", ImVec2(1200, 480));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    auto tableFor = [&]() -> ImGuiTable* {
        for (int i = 0; i < GImGui->Tables.GetBufSize(); ++i) {
            ImGuiTable* table = GImGui->Tables.GetByIndex(i);
            if (table && table->LastFrameActive == GImGui->FrameCount && table->ColumnsCount == 8 &&
                table->OuterWindow && std::strcmp(table->OuterWindow->RootWindow->Name, "Reference owned breakpoint QA") == 0) return table;
        }
        return nullptr;
    };
    auto openLastAction = [&] {
        ImGuiTable* table = tableFor(); CHECK(table != nullptr); if (!table) return;
        const ImVec2 point((table->Columns[4].MinX + table->Columns[4].MaxX) * 0.5f,
                          table->RowPosY1 + ImGui::GetTextLineHeight() * 0.5f + ImGui::GetStyle().CellPadding.y);
        io.AddMousePosEvent(point.x, point.y); paint(); paint();
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, true); paint();
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, false); settle();
        CHECK(!GImGui->OpenPopupStack.empty() && f.tab->breakpointActionsPopupId_ != 0);
    };
    settle();
    ImGuiTable* table = tableFor(); CHECK(table && table->DisplayOrderToIndex[0] == 6 && !table->Columns[3].IsUserEnabled);
    f.tab->condEditDraft_[0] = "rax == 0";
    openLastAction();
    if (!GImGui->OpenPopupStack.empty()) {
        releaseActivate(GImGui->OpenPopupStack.back().Window, "Apply condition"); settle();
        CHECK(f.tab->condBuf_[0] == "rax == 0" && !f.tab->condEditDraft_.count(0));
        const auto attempt = f.tab->staticBreakpointArming_.find(0);
        CHECK(attempt == f.tab->staticBreakpointArming_.end() || attempt->second.error != "Authored invalid condition");
        // Installation does not change FILE row ownership or collide with a
        // separate LIVE breakpoint whose numeric address equals that FILE VA.
        const ImGuiID popupId = f.tab->breakpointActionsPopupId_;
        SwBreakpointInfo installed; installed.address = runtime; installed.armed = true;
        SwBreakpointInfo liveZero; liveZero.address = 0; liveZero.armed = false;
        f.detached.breakpoints = {installed, liveZero};
        settle();
        CHECK(f.tab->breakpointDisplayCount(f.ctx) == 2); // mapped FILE marker merges with installed LIVE row
        CHECK(f.tab->breakpointActionsPopupId_ == popupId && !GImGui->OpenPopupStack.empty());
        ++f.detached.sessionGeneration; settle();
        CHECK(f.tab->breakpointActionsPopupId_ == 0 && GImGui->OpenPopupStack.empty());
    }
    // A matching authored RIP/stop count cannot produce verified Stopped chrome.
    f.detached.regs.rip = 0; f.detached.breakpoints = {SwBreakpointInfo{}};
    f.detached.breakpoints[0].hits = f.detached.breakpoints[0].stops = 3;
    f.tab->cursorValid_ = false; settle();
    table = tableFor(); CHECK(table != nullptr);
    if (table) CHECK(!colorPresent(ImGui::GetColorU32(theme::col::breakpointFill()), table->InnerRect.Min.y));
    CHECK(!f.ctx.debug.snapshot().attached() && !f.ctx.debug.lifecycleSnapshot().busy);
    ImGui::ClosePopupsOverWindow(nullptr, false); ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
}

// Exercise the actual breakpoint controls with saved FILE intent. Native LIVE
// execution is covered by the debugger fixture; authored UI snapshots below
// must never grant a detached debugger permission to change that saved intent.
static void checkAxiomBreakpointEnableUi(const std::string& path) {
    ImGuiIO& io = ImGui::GetIO();
    const auto priorTheme = theme::CurrentTheme();
    ImGui::ClosePopupsOverWindow(nullptr, false); ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    theme::ApplyTheme(theme::ThemeId::Axiom);
    Fixture f(path);
    f.tab->breakpoints_.insert(0);
    f.tab->condBuf_[0] = "rax == 0x10";
    f.tab->everyNBuf_[0] = 7;
    f.tab->condEditDraft_[0] = "rax >=";
    f.tab->setStaticCursor(0);
    f.tab->projectDirty_ = false;
    const char* title = "Breakpoint enable controls QA";
    std::string visibleText;
    auto paint = [&] {
        frame([&] {
            f.tab->frameSnap_ = &f.detached;
            ImGui::LogToBuffer();
            f.tab->renderLowerTabs(f.ctx, false);
            visibleText = GImGui->LogBuffer.c_str();
            ImGui::LogFinish();
        }, title, ImVec2(1400, 480));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    auto tableFor = [&]() -> ImGuiTable* {
        for (int i = 0; i < GImGui->Tables.GetBufSize(); ++i) {
            ImGuiTable* table = GImGui->Tables.GetByIndex(i);
            if (table && table->LastFrameActive == GImGui->FrameCount && table->OuterWindow &&
                std::strcmp(table->OuterWindow->RootWindow->Name, title) == 0) return table;
        }
        return nullptr;
    };
    auto clickCell = [&](bool state) {
        ImGuiTable* table = tableFor(); CHECK(table != nullptr); if (!table) return;
        const bool live = table->ColumnsCount == 8;
        const int column = state ? (live ? 6 : 5) : (live ? 4 : 3);
        CHECK(column < table->ColumnsCount);
        const float x = state ? table->Columns[column].WorkMinX + 16.0f * theme::UiScale()
            : (table->Columns[column].MinX + table->Columns[column].MaxX) * 0.5f;
        const float y = table->RowPosY1 + ImGui::GetStyle().CellPadding.y + ImGui::GetTextLineHeight() * 0.5f;
        io.AddMousePosEvent(x, y); paint(); paint();
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, true); paint();
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, false); settle();
        io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    };
    auto chooseAction = [&](const char* label) {
        ImGui::ClosePopupsOverWindow(nullptr, false); ImGui::ClearActiveID(); settle();
        clickCell(false);
        CHECK(!GImGui->OpenPopupStack.empty());
        CHECK(visibleText.find(label) != std::string::npos);
        if (!GImGui->OpenPopupStack.empty()) {
            releaseActivate(GImGui->OpenPopupStack.back().Window, label);
            settle();
        }
    };
    auto retainedMetadata = [&] {
        CHECK(f.tab->breakpoints_.size() == 1 && f.tab->breakpoints_.count(0));
        CHECK(f.tab->condBuf_.at(0) == "rax == 0x10");
        CHECK(f.tab->everyNBuf_.at(0) == 7);
        CHECK(f.tab->condEditDraft_.at(0) == "rax >=");
        CHECK(f.tab->breakpointDisplayCount(f.ctx) == 1);
    };

    settle();
    clickCell(true); // enabled ring -> paused, with the FILE marker retained
    CHECK(f.tab->disabledBreakpoints_.count(0) == 1 && f.tab->projectDirty_);
    retainedMetadata();
    f.tab->saveProjectState(f.ctx);
    CHECK(f.ctx.staticProject().bpDisabled.count(0) == 1);
    CHECK(f.ctx.staticProject().breakpoints == std::vector<uint64_t>{0});
    CHECK(f.ctx.staticProject().bpConditions.at(0) == "rax == 0x10");
    CHECK(f.ctx.staticProject().bpEveryN.at(0) == 7);
    const ProjectState savedDisabled = f.ctx.staticProject();
    for (int themeIndex = 0; themeIndex < static_cast<int>(theme::ThemeId::Count); ++themeIndex) {
        theme::ApplyTheme(static_cast<theme::ThemeId>(themeIndex)); settle();
        CHECK(f.tab->disabledBreakpoints_.count(0) == 1);
        retainedMetadata();
        std::string detail;
        const std::string status = f.tab->staticBreakpointStatus(f.ctx, 0, detail);
        CHECK(status.find("disabled") != std::string::npos || status.find("paused") != std::string::npos);
        ImGuiTable* table = tableFor(); CHECK(table && table->ColumnsCount == 7);
        clickCell(true);
        CHECK(f.tab->disabledBreakpoints_.empty()); retainedMetadata();
        clickCell(true);
        CHECK(f.tab->disabledBreakpoints_.count(0) == 1); retainedMetadata();
        chooseAction("Enable breakpoint");
        CHECK(f.tab->disabledBreakpoints_.empty()); retainedMetadata();
        chooseAction("Pause breakpoint");
        CHECK(f.tab->disabledBreakpoints_.count(0) == 1); retainedMetadata();
    }
    chooseAction("Enable breakpoint");
    CHECK(!f.tab->disabledBreakpoints_.count(0)); retainedMetadata();
    chooseAction("Pause breakpoint");
    CHECK(f.tab->disabledBreakpoints_.count(0) == 1); retainedMetadata();
    ImGui::ClosePopupsOverWindow(nullptr, false); ImGui::ClearActiveID(); settle();
    clickCell(true); // paused ring -> enabled
    CHECK(!f.tab->disabledBreakpoints_.count(0)); retainedMetadata();
    f.tab->saveProjectState(f.ctx);
    CHECK(f.ctx.staticProject().bpDisabled.empty());

    // Project mirroring/loading keeps disabled intent and applied conditions;
    // uncommitted condition drafts remain session state, not sidecar data.
    {
        Fixture restored(path, true, &savedDisabled);
        CHECK(restored.tab->breakpoints_.count(0) == 1 && restored.tab->disabledBreakpoints_.count(0) == 1);
        CHECK(restored.tab->condBuf_.at(0) == "rax == 0x10" && restored.tab->everyNBuf_.at(0) == 7);
        CHECK(restored.tab->condEditDraft_.empty());
        CHECK(restored.tab->staticBreakpointSavedRestore_.count(0) == 1);
        auto restoredPaint = [&] {
            frame([&] { restored.tab->renderLowerTabs(restored.ctx, false); },
                  "Reopened disabled breakpoint QA", ImVec2(1400, 480));
        };
        restoredPaint(); restoredPaint(); restoredPaint();
        ImGuiTable* restoredTable = nullptr;
        for (int i = 0; i < GImGui->Tables.GetBufSize(); ++i) {
            ImGuiTable* table = GImGui->Tables.GetByIndex(i);
            if (table && table->LastFrameActive == GImGui->FrameCount && table->OuterWindow &&
                std::strcmp(table->OuterWindow->RootWindow->Name, "Reopened disabled breakpoint QA") == 0)
                restoredTable = table;
        }
        CHECK(restoredTable != nullptr);
        if (restoredTable) {
            const float x = restoredTable->Columns[5].WorkMinX + 16.0f * theme::UiScale();
            const float y = restoredTable->RowPosY1 + ImGui::GetStyle().CellPadding.y +
                ImGui::GetTextLineHeight() * 0.5f;
            io.AddMousePosEvent(x, y); restoredPaint(); restoredPaint();
            io.AddMouseButtonEvent(ImGuiMouseButton_Left, true); restoredPaint();
            io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
            restoredPaint(); restoredPaint(); restoredPaint();
            io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
            CHECK(restored.tab->disabledBreakpoints_.empty() && restored.tab->breakpoints_.count(0) == 1);
            CHECK(restored.tab->staticBreakpointSavedRestore_.empty());
            CHECK(restored.tab->listingBoundaryAuthority_.analystAccepted(0));
            CHECK(restored.tab->staticBreakpointValidationErrors_.empty());
            CHECK(restored.tab->condBuf_.at(0) == "rax == 0x10" && restored.tab->everyNBuf_.at(0) == 7);
            std::string detail;
            CHECK(std::string(restored.tab->staticBreakpointStatus(restored.ctx, 0, detail)) ==
                  "saved; not debugging");
        }
    }

    // An authored matching module maps the FILE marker onto a displayed LIVE
    // row. The real debugger is detached: neither control may convert a rejected
    // exact-session action into a saved disabled marker or erase its metadata.
    f.detached.state = DbgState::Paused; f.detached.pid = 0xFFFFFFE0;
    f.detached.sessionGeneration = 194; f.detached.activeTid = f.detached.tid = 42;
    DbgModule module; module.base = 0x200000; module.size = 128 * 4096;
    module.name = "authored-enable-refusal"; module.path = f.path; module.loadGeneration = 3;
    f.detached.modules = {module};
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = true; identity.pid = f.detached.pid; identity.sessionGeneration = f.detached.sessionGeneration;
    identity.moduleBase = module.base; identity.moduleSize = module.size; identity.moduleName = module.name;
    identity.modulePath = module.path; identity.moduleLoadGeneration = module.loadGeneration;
    f.ctx.setStaticDebugImageIdentity(identity);
    SwBreakpointInfo installed;
    installed.address = module.base; installed.condition = "rax == 0x10";
    installed.everyN = 7; installed.hits = 12; installed.stops = 2; installed.armed = true; installed.enabled = true;
    f.detached.breakpoints = {installed};
    f.tab->projectDirty_ = false; settle();
    uint64_t runtime = 0;
    CHECK(f.tab->staticBreakpointRuntimeVA(f.ctx, 0, runtime) && runtime == module.base);
    clickCell(true);
    CHECK(!f.tab->disabledBreakpoints_.count(0) && !f.tab->projectDirty_); retainedMetadata();
    chooseAction("Pause breakpoint");
    CHECK(!f.tab->disabledBreakpoints_.count(0) && !f.tab->projectDirty_); retainedMetadata();
    CHECK(f.detached.breakpoints.size() == 1 && f.detached.breakpoints[0].enabled &&
          f.detached.breakpoints[0].condition == "rax == 0x10" && f.detached.breakpoints[0].everyN == 7 &&
          f.detached.breakpoints[0].hits == 12 && f.detached.breakpoints[0].stops == 2);
    CHECK(!f.ctx.debug.snapshot().attached() && !f.ctx.debug.lifecycleSnapshot().busy);
    ImGui::ClosePopupsOverWindow(nullptr, false); ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    theme::ApplyTheme(priorTheme);
}

static void checkAxiomBinaryView(const std::string& path) {
    ImGuiIO& io = ImGui::GetIO();
    const auto originalTheme = theme::CurrentTheme();
    const float originalScale = theme::UiScale();
    const float originalFontScale = io.FontGlobalScale;
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    theme::SetUiScale(1.0f);
    io.FontGlobalScale = 1.0f;
    theme::ApplyTheme(theme::ThemeId::Axiom);

    Fixture f(path);
    DbgSnapshot live;
    live.state = DbgState::Paused;
    live.pid = 777; live.sessionGeneration = 9; live.activeTid = live.tid = 11;
    // No RIP means the live view renders its real toolbar and waiting state,
    // without attempting to resolve or read any process address.
    live.regs.rip = 0;
    bool liveToolbar = false;
    ImVec2 size(760, 560);
    std::string text;
    float toolbarHeight = 0;
    auto paintToolbar = [&] {
        frame([&] {
            f.tab->frameSnap_ = liveToolbar ? &live : &f.detached;
            const float start = ImGui::GetCursorPosY();
            ImGui::LogToBuffer();
            f.tab->renderListingToolbar(f.ctx, liveToolbar);
            toolbarHeight = ImGui::GetCursorPosY() - start;
            text = ImGui::GetCurrentContext()->LogBuffer.c_str();
            ImGui::LogFinish();
        }, "Axiom listing toolbar QA", size);
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settleToolbar = [&] { paintToolbar(); paintToolbar(); paintToolbar(); };
    auto menuWindow = [&]() -> ImGuiWindow* {
        return GImGui->OpenPopupStack.empty() ? nullptr : GImGui->OpenPopupStack.back().Window;
    };
    auto openToolbarMenu = [&](const char* label) {
        releaseActivate(ImGui::FindWindowByName("Axiom listing toolbar QA"), label);
        settleToolbar();
        CHECK(menuWindow() != nullptr);
    };

    settleToolbar();
    CHECK(text.find("Display") != std::string::npos);
    CHECK(text.find("More") != std::string::npos);
    CHECK(text.find("Rebuild listing") == std::string::npos);
    CHECK(text.find("Explain") == std::string::npos);
    CHECK(toolbarHeight <= ImGui::GetFrameHeightWithSpacing() * 1.5f);
    const bool initialStrings = f.tab->showStringComments_;
    openToolbarMenu("Display##listing_display");
    for (const char* label : {"Full program", "Explain", "Notes", "Strings", "Values", "Arrows"})
        CHECK(text.find(label) != std::string::npos);
    releaseActivate(menuWindow(), "Strings");
    settleToolbar();
    CHECK(f.tab->showStringComments_ != initialStrings);
    CHECK(menuWindow() == nullptr);

    f.tab->asmWindowBrowseValid_ = true;
    f.tab->asmWindowPanScrollValid_ = true;
    f.tab->asmWindowScrollSampleValid_ = true;
    openToolbarMenu("Display##listing_display");
    releaseActivate(menuWindow(), "Full program");
    settleToolbar();
    CHECK(!f.tab->asmFullProgram_);
    CHECK(!f.tab->asmWindowBrowseValid_ && !f.tab->asmWindowPanScrollValid_ &&
          !f.tab->asmWindowScrollSampleValid_);
    const uint64_t revision = f.tab->listingLayoutRevision_;
    openToolbarMenu("More##listing_more");
    CHECK(text.find("Previous instruction") != std::string::npos);
    CHECK(text.find("Rename symbol") != std::string::npos);
    releaseActivate(menuWindow(), "Rebuild listing");
    settleToolbar();
    CHECK(f.tab->listingLayoutRevision_ != revision && !f.tab->listBuilt_);

    liveToolbar = true;
    settleToolbar();
    CHECK(text.find("Follow RIP") != std::string::npos);
    CHECK(text.find("Continue") == std::string::npos);
    CHECK(text.find("Step into") == std::string::npos);
    CHECK(text.find("Step over") == std::string::npos);
    CHECK(text.find("Step out") == std::string::npos);
    CHECK(toolbarHeight <= ImGui::GetFrameHeightWithSpacing() * 1.5f);
    openToolbarMenu("Display##listing_display");
    for (const char* label : {"Assembly", "Pseudocode", "Register side pane", "Hints", "Names", "Values"})
        CHECK(text.find(label) != std::string::npos);
    releaseActivate(menuWindow(), "Register side pane");
    settleToolbar();
    CHECK(f.tab->showRegBox_);
    // The full live representation also has only view controls, so a future
    // accidental reintroduction of its own Continue/Step bar is caught.
    f.tab->showRegBox_ = false;
    frame([&] {
        f.tab->frameSnap_ = &live;
        ImGui::LogToBuffer();
        f.tab->renderLiveAssembly(f.ctx);
        text = GImGui->LogBuffer.c_str();
        ImGui::LogFinish();
    }, "Axiom live view QA", size);
    CHECK(GImGui->ErrorCountCurrentFrame == 0);
    CHECK(text.find("Follow RIP") != std::string::npos);
    CHECK(text.find("Continue") == std::string::npos && text.find("Step into") == std::string::npos);
    CHECK(text.find("LIVE address") == std::string::npos);

    // A retained live frame may offer a flag hint, but cannot claim a freshly
    // verified outcome. Both flag values use the actual live row renderer.
    const uint8_t branchBytes[] = {0x75, 0x02, 0x90, 0x90, 0xC3};
    live.regs.rip = kTarget;
    f.tab->liveInsns_ = f.ctx.staticDisassembler()->disassemble(branchBytes, sizeof(branchBytes), kTarget, 16);
    f.tab->liveIdxOf_.clear();
    for (size_t i = 0; i < f.tab->liveInsns_.size(); ++i)
        f.tab->liveIdxOf_[f.tab->liveInsns_[i].address] = static_cast<int>(i);
    f.tab->liveBrowseValid_ = false;
    f.tab->liveCacheStart_ = kTarget;
    f.tab->liveCacheSig_ = kTarget ^ (live.regs.rip * 0x9E3779B97F4A7C15ull) ^
        (uint64_t(f.tab->liveGen_) << 1) ^ (f.tab->functionsGen_ * 0xD6E8FEB86659FD93ull) ^
        (uint64_t(f.tab->symPid_) << 33) ^ (uint64_t(f.ctx.staticEngine()) << 56);
    f.tab->setLiveCursor(kTarget);
    for (const bool zero : {false, true}) {
        live.regs.rflags = zero ? 0x40 : 0;
        frame([&] {
            f.tab->frameSnap_ = &live;
            ImGui::LogToBuffer();
            f.tab->renderLiveListing(f.ctx, live, kTarget);
            text = GImGui->LogBuffer.c_str(); ImGui::LogFinish();
        }, "Axiom captured flags QA", ImVec2(1440, 600));
        CHECK(text.find(zero ? "Captured flags: condition false" : "Captured flags: condition true") != std::string::npos);
        CHECK(text.find("Jump will") == std::string::npos);
    }
    f.tab->setStaticCursor(kTarget);

    {
        Fixture pseudo(path);
        pseudo.tab->functions_ = {{kTarget, "authored_long_line", 32}};
        ++pseudo.tab->functionsGen_; pseudo.tab->funcIndexDirty_ = true;
        pseudo.tab->decompOwnershipValid_ = true;
        pseudo.tab->decompVA_ = kTarget; pseudo.tab->decompValid_ = true;
        pseudo.tab->decompPending_ = false;
        pseudo.tab->setDecompContent("result = " + std::string(240, 'x') + ";", {kTarget});
        ImVec2 pseudoSize(1200, 600);
        auto paintPseudo = [&] {
            frame([&] { pseudo.tab->renderDecompiler(pseudo.ctx); }, "Axiom pseudocode access QA", pseudoSize);
            CHECK(GImGui->ErrorCountCurrentFrame == 0);
        };
        paintPseudo(); paintPseudo(); paintPseudo();
        ImGuiWindow* left = releaseWindow("##decleft");
        ImGuiWindow* right = releaseWindow("##decright");
        ImGuiWindow* assembly = releaseWindow("##decasm");
        CHECK(left && right && assembly);
        if (left && right && assembly) {
            CHECK(left->Size.x > right->Size.x);
            CHECK(left->ScrollMax.x > 0);
            CHECK(left->Flags & ImGuiWindowFlags_HorizontalScrollbar);
            CHECK(assembly->Flags & ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::SetScrollX(left, left->ScrollMax.x);
            paintPseudo(); paintPseudo();
            CHECK(left->Scroll.x > 0);
            CHECK(pseudo.tab->cursorVA_ == kTarget);
            CHECK(pseudo.tab->decompLineVA_.size() == 1 && pseudo.tab->decompLineVA_[0] == kTarget);
        }
        pseudo.tab->decompSplitW_ = 410;
        pseudoSize = ImVec2(420, 600); paintPseudo(); paintPseudo();
        CHECK(pseudo.tab->decompSplitW_ == 410);
        pseudoSize = ImVec2(1200, 600); paintPseudo(); paintPseudo();
        left = releaseWindow("##decleft");
        CHECK(left && std::fabs(left->Size.x - 410) < 1.0f);
    }

    // Settings and table IDs survive palette changes. Axiom's first-use
    // defaults must not reset hidden columns, per-view pins or manual panes.
    f.tab->frameSnap_ = &f.detached;
    f.tab->asmFullProgram_ = true;
    f.layout();
    ImGuiID tableId = 0;
    auto paintColumns = [&] {
        frame([&] {
            tableId = ImGui::GetID("asm_full");
            f.tab->renderAssemblyFull(f.ctx);
        }, "Axiom retained columns QA", ImVec2(1000, 600));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    paintColumns(); paintColumns();
    ImGuiTable* table = ImGui::TableFindByID(tableId);
    CHECK(table != nullptr);
    if (table) {
        CHECK(!(table->Flags & ImGuiTableFlags_NoSavedSettings));
        CHECK(table->Columns[2].Flags & ImGuiTableColumnFlags_NoHide);
        CHECK(table->Columns[4].Flags & ImGuiTableColumnFlags_NoHide);
        table->Columns[3].IsUserEnabledNextFrame = false;
        paintColumns();
        CHECK(!table->Columns[3].IsEnabled);
    }
    f.tab->bottomDockH_ = 177;
    f.tab->evidenceInspectorW_ = 281;
    f.tab->evidenceInspectorCollapsed_ = true;
    f.tab->lowerDockCollapsed_ = false;
    f.tab->navigatorOptionalMask_ = 3;
    f.tab->viewPins_[0] = {0, true, DocumentView::Assembly, DocumentAddressSpace::File};
    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Axiom}) {
        theme::ApplyTheme(palette);
        paintColumns();
        CHECK(ImGui::TableFindByID(tableId) == table);
        if (table) CHECK(!table->Columns[3].IsEnabled);
        CHECK(f.tab->bottomDockH_ == 177 && f.tab->evidenceInspectorW_ == 281);
        CHECK(f.tab->evidenceInspectorCollapsed_ && !f.tab->lowerDockCollapsed_);
        CHECK(f.tab->navigatorOptionalMask_ == 3);
        CHECK(f.tab->viewPins_[0].valid && f.tab->viewPins_[0].va == 0);
    }

    // Compact layouts retain independent panes and both permanent navigator
    // regions. Representation reachability is exercised through real input below.
    f.ctx.navigatorOptionalMask = 0;
    f.tab->navigatorOptionalMask_ = 0;
    f.tab->functions_ = {{kTarget, "analyst_named_function", 16}};
    ++f.tab->functionsGen_; f.tab->funcIndexDirty_ = true;
    f.tab->strings_ = {{kTarget + 64, "Evidence string"}};
    ++f.tab->stringsGen_;
    f.tab->stringsScanned_ = true;
    f.tab->stringsScanning_ = f.tab->stringsLive_ = false;
    f.tab->evidenceInspectorCollapsed_ = false;
    f.tab->mainView_ = 7;
    std::function<void()> beforeWorkbench;
    auto paintWorkbench = [&] {
        frame([&] {
            if (beforeWorkbench) beforeWorkbench();
            f.tab->render(f.ctx);
        }, "Axiom workbench QA", size);
        f.tab->frameSnap_ = f.ctx.frameDebugSnapshot ? f.ctx.frameDebugSnapshot : &f.detached;
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    for (const ImVec2 viewport : {ImVec2(1920, 1200), ImVec2(1440, 900), ImVec2(1366, 800)}) {
        size = viewport;
        paintWorkbench(); paintWorkbench(); paintWorkbench();
        ImGuiWindow* functions = releaseWindow("navigator_functions");
        ImGuiWindow* strings = releaseWindow("navigator_strings");
        ImGuiWindow* center = releaseWindow("##analysis_viewport");
        ImGuiWindow* evidence = releaseWindow("##evidence_inspector");
        CHECK(functions && strings && center && evidence);
        if (functions && strings) CHECK(functions->Pos.y + functions->Size.y <= strings->Pos.y + 1);
        if (center && evidence) {
            CHECK(center->Pos.x + center->Size.x <= evidence->Pos.x);
            CHECK(evidence->Pos.x + evidence->Size.x <= size.x + 1);
        }
    }
    // An authored, exact retained snapshot enables the LIVE tab without an
    // attach, process read, or target operation. RIP zero keeps its waiting state.
    size = ImVec2(1920, 1200);
    live.pid = 0xFFFFFFF0;
    live.regs.rip = 0;
    f.ctx.frameDebugSnapshot = &live;
    f.tab->stringsAutoPid_ = live.pid;
    f.tab->stringsAutoSessionGeneration_ = live.sessionGeneration;
    paintWorkbench(); paintWorkbench(); paintWorkbench();
    struct RepresentationTarget {
        ImGuiWindow* owner = nullptr;
        ImGuiID bar = 0, tab = 0;
        ImRect bounds;
    };
    const std::pair<const char*, int> representations[] = {
        {"Overview", 7}, {"Assembly", 0}, {"Pseudocode", 1}, {"Hex", 2},
        {"Graph", 3}, {"Call Graph", 5}, {"Live Assembly", 4}
    };
    auto findRepresentation = [&](const char* label) {
        RepresentationTarget target;
        target.owner = ImGui::FindWindowByName("Axiom workbench QA");
        CHECK(target.owner != nullptr);
        if (!target.owner) return target;
        target.bar = ImHashStr("##tabs", 0, target.owner->GetID("##codeviews"));
        ImGuiTabBar* bar = GImGui->TabBars.GetByKey(target.bar);
        CHECK(bar && bar->Tabs.Size == 7);
        if (!bar) return target;
        for (ImGuiTabItem& item : bar->Tabs) {
            if (std::strcmp(ImGui::TabBarGetTabName(bar, &item), label) != 0) continue;
            target.tab = item.ID;
            target.bounds = ImRect(
                ImVec2(bar->BarRect.Min.x + item.Offset - bar->ScrollingAnim, bar->BarRect.Min.y),
                ImVec2(bar->BarRect.Min.x + item.Offset - bar->ScrollingAnim + item.Width, bar->BarRect.Max.y));
            CHECK(item.LastFrameVisible == GImGui->FrameCount);
            CHECK(!(item.Flags & ImGuiTabItemFlags_Button));
            CHECK(target.bounds.Min.x >= bar->BarRect.Min.x && target.bounds.Max.x <= bar->BarRect.Max.x);
            break;
        }
        CHECK(target.tab != 0);
        return target;
    };
    auto checkRepresentation = [&](const RepresentationTarget& target, int view) {
        ImGuiTabBar* bar = GImGui->TabBars.GetByKey(target.bar);
        CHECK(bar && bar->SelectedTabId == target.tab);
        CHECK(f.tab->mainView_ == view);
        CHECK(releaseWindow("navigator_functions") && releaseWindow("navigator_strings"));
    };
    for (const auto& [label, view] : representations) {
        const auto target = findRepresentation(label);
        if (!target.tab) continue;
        ImGui::ClearActiveID();
        ImGui::FocusWindow(target.owner);
        const ImVec2 point = target.bounds.GetCenter();
        io.AddMousePosEvent(point.x, point.y); paintWorkbench(); paintWorkbench();
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, true); paintWorkbench();
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, false); paintWorkbench(); paintWorkbench();
        checkRepresentation(target, view);
    }

    // Establish keyboard focus at the observed first tab, then use actual Right
    // and Space events to traverse and activate every native tab. No selected-tab
    // or Binary View representation state is assigned by this interaction test.
    const ImGuiConfigFlags savedConfig = io.ConfigFlags;
    const bool savedNavCursor = GImGui->NavCursorVisible;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.AddMousePosEvent(-100, -100);
    ImGui::ClearActiveID();
    const auto firstTab = findRepresentation("Overview");
    if (firstTab.tab) {
        beforeWorkbench = [&] {
            ImRect relative = firstTab.bounds;
            relative.Translate(ImVec2(-firstTab.owner->Pos.x, -firstTab.owner->Pos.y));
            ImGui::FocusWindow(firstTab.owner);
            ImGui::SetNavID(firstTab.tab, ImGuiNavLayer_Main, firstTab.owner->NavRootFocusScopeId, relative);
            ImGui::SetNavCursorVisible(true);
        };
        paintWorkbench();
        beforeWorkbench = {};
        for (const auto& [label, view] : representations) {
            const auto target = findRepresentation(label);
            if (!target.tab) continue;
            for (int step = 0; GImGui->NavId != target.tab && step < 7; ++step) {
                io.AddKeyEvent(ImGuiKey_RightArrow, true); paintWorkbench();
                io.AddKeyEvent(ImGuiKey_RightArrow, false); paintWorkbench();
            }
            CHECK(GImGui->NavId == target.tab);
            io.AddKeyEvent(ImGuiKey_Space, true); paintWorkbench();
            io.AddKeyEvent(ImGuiKey_Space, false); paintWorkbench(); paintWorkbench();
            checkRepresentation(target, view);
        }
    }
    io.ConfigFlags = savedConfig;
    ImGui::SetNavCursorVisible(savedNavCursor);
    f.ctx.frameDebugSnapshot = nullptr;
    f.tab->frameSnap_ = &f.detached;
    f.ctx.staticAnalysis().cancelAndWaitIdle();
    checkAxiomThemeRetainedDraft(path);
    checkAxiomReferenceBreakpoints(path);
    checkAxiomBreakpointEnableUi(path);
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    io.FontGlobalScale = originalFontScale;
    theme::SetUiScale(originalScale);
    theme::ApplyTheme(originalTheme);
}

// Optional visual QA: real production frames, authored file bytes and retained
// synthetic debugger observations. These images never imply a real attachment.
static void captureAxiomBinaryView(const std::string&, const std::string& captureDirectory) {
    const std::filesystem::path directory(captureDirectory);
    std::filesystem::create_directories(directory);
    const auto previousTheme = theme::CurrentTheme();
    const std::filesystem::path samplePath = directory / "authored-ui-fixture.raw";
    std::vector<uint8_t> bytes(128 * 4096, 0x90);
    const uint8_t function[] = {0x55,0x48,0x89,0xE5,0x48,0x83,0xEC,0x20,
        0x85,0xC9,0x74,0x0E,0x83,0xF9,0x10,0x75,0x09,0xB8,1,0,0,0,
        0xC9,0xC3,0x90,0x90,0x31,0xC0,0xC9,0xC3};
    for (uint64_t offset : {kTarget, kTarget + 64, kTarget + 128, kTarget + 192})
        std::copy(std::begin(function), std::end(function), bytes.begin() + offset);
    auto call = [&](uint64_t from, uint64_t to) {
        bytes[from] = 0xE8;
        const int32_t displacement = static_cast<int32_t>(to - (from + 5));
        std::memcpy(bytes.data() + from + 1, &displacement, sizeof(displacement));
        bytes[from + 5] = 0xC3;
    };
    call(kTarget - 128, kTarget);
    call(kTarget + 256, kTarget - 128);
    const char evidence[] = "Accepted token\0Invalid token\0Configuration loaded\0";
    std::memcpy(bytes.data() + kTarget + 400, evidence, sizeof(evidence));
    { std::ofstream output(samplePath, std::ios::binary);
      output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
    auto capture = [&](const char* name) {
        std::string error;
        const bool ok = ds::test::captureUiFrame(directory / (std::string(name) + ".bmp"), &error);
        if (!ok) std::printf("Capture %s: %s\n", name, error.c_str());
        CHECK(ok);
    };
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys(); ImGui::GetIO().ClearInputMouse();
    theme::ApplyTheme(theme::ThemeId::Axiom);

    // Genuine App shell with its own document owner and normal load pipeline.
    {
        App app;
        // App construction restores its isolated fixture preferences. Apply the
        // capture palette afterwards; no preference file is edited or saved.
        theme::ApplyTheme(theme::ThemeId::Axiom);
        AppContext& ctx = AppExitTestAccess::context(app);
        CHECK(ctx.beginRawLoadPath(samplePath.string(), 0, Arch::X64, kTarget, {}, {}));
        bool loaded = false;
        for (int i = 0; i < 1000; ++i) {
            const auto result = ctx.pollBinaryLoad();
            if (result.completed) { loaded = result.success; break; }
            Sleep(2);
        }
        CHECK(loaded);
        CHECK(ctx.applyPendingDocumentCommand().success);
        ctx.requestedTab = "Binary View";
        for (int i = 0; i < 40; ++i) { workbenchFrame(app, ImVec2(1920, 1200)); Sleep(5); }
        // Advance the headless frame clock through the real toast expiry path,
        // so notifications inherited from earlier assertions cannot pollute QA.
        if (ui::ToastsActive()) {
            const float delta = ImGui::GetIO().DeltaTime;
            ImGui::GetIO().DeltaTime = 4.1f;
            workbenchFrame(app, ImVec2(1920, 1200));
            ImGui::GetIO().DeltaTime = delta;
            workbenchFrame(app, ImVec2(1920, 1200));
        }
        CHECK(!ui::ToastsActive());
        CHECK(theme::CurrentTheme() == theme::ThemeId::Axiom);
        capture("binary-shell-axiom");
        for (int i = 0; i < 3; ++i) workbenchFrame(app, ImVec2(1440, 900));
        CHECK(!ui::ToastsActive());
        CHECK(theme::CurrentTheme() == theme::ThemeId::Axiom);
        capture("binary-shell-axiom-1440");
        ctx.staticAnalysis().cancelAndWaitIdle();
        ctx.staticProject().hash = 0;
    }

    Fixture f(samplePath.string());
    f.tab->functions_ = {{kTarget - 128, "startup", 6}, {kTarget, "verify_token", sizeof(function)},
        {kTarget + 64, "parse_header", sizeof(function)}, {kTarget + 128, "check_crc", sizeof(function)},
        {kTarget + 192, "read_configuration", sizeof(function)}, {kTarget + 256, "report_result", 6}};
    ++f.tab->functionsGen_; f.tab->funcIndexDirty_ = true;
    f.tab->strings_ = {{kTarget + 400, "Accepted token"}, {kTarget + 415, "Invalid token"},
                       {kTarget + 429, "Configuration loaded"}};
    ++f.tab->stringsGen_;
    f.tab->stringsScanned_ = true; f.tab->stringsScanning_ = f.tab->stringsLive_ = false;
    f.tab->comments_[kTarget + 8] = "Analyst note: check the input before choosing a path";
    f.tab->comments_[kTarget + 10] = "Authored QA bytes; LIVE observations are synthetic";
    f.tab->breakpoints_.insert(kTarget + 10);
    f.tab->decompOwnershipValid_ = true;
    f.tab->functionsDirty_ = f.tab->decompOwnershipPending_ = false;
    f.tab->showHints_ = f.tab->showFnNotes_ = false;
    f.tab->setStaticCursor(kTarget + 10);
    f.tab->buildCallGraph(f.ctx);
    const auto graph = BuildCFG(function, sizeof(function), kTarget, *f.ctx.staticDisassembler());
    const DecompResult decomp = DecompileWithMap(graph);
    f.tab->decompLruPut(kTarget, f.tab->decompScopeContext(false), decomp);
    f.tab->decompVA_ = kTarget; f.tab->decompValid_ = true; f.tab->decompPending_ = false;
    f.tab->applyDecompLang(decomp);
    f.layout();
    ImVec2 size(1920, 1200);
    std::function<void()> beforePaint;
    auto paint = [&] {
        frame([&] {
            if (beforePaint) beforePaint();
            f.tab->render(f.ctx);
        }, "Binary View production visual QA", size);
        f.tab->frameSnap_ = f.ctx.frameDebugSnapshot ? f.ctx.frameDebugSnapshot : &f.detached;
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    f.tab->mainView_ = 0;
    for (const auto palette : {theme::ThemeId::Axiom, theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette); settle();
        capture(palette == theme::ThemeId::Axiom ? "binary-assembly-axiom" :
                palette == theme::ThemeId::Midnight ? "binary-assembly-midnight" : "binary-assembly-light");
    }
    theme::ApplyTheme(theme::ThemeId::Axiom);
    // Reference-directed navigator/drawer capture. These are saved FILE
    // markers on authored bytes; selection is deliberately distinct from stop.
    f.ctx.navigatorOptionalMask = 1u << 2; // real, explicitly enabled Sections
    f.tab->lowerAdvancedMode_ = false; f.tab->lowerDockCollapsed_ = false;
    f.tab->bottomDockH_ = 210.0f;
    f.tab->setStaticCursor(kTarget + 10);
    settle(); capture("binary-reference-saved-file");
    size = ImVec2(1440, 900);
    settle(); capture("binary-reference-saved-file-1440");
    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette); settle();
        capture(palette == theme::ThemeId::Midnight ? "binary-reference-saved-file-midnight-1440"
                                                   : "binary-reference-saved-file-light-1440");
    }
    theme::ApplyTheme(theme::ThemeId::Axiom);
    size = ImVec2(1920, 1200);
    f.ctx.navigatorOptionalMask = 0;
    for (const auto view : {std::pair{7, "binary-overview"}, std::pair{1, "binary-pseudocode"},
                           std::pair{2, "binary-hex"}, std::pair{3, "binary-graph"},
                           std::pair{5, "binary-call-graph"}}) {
        f.tab->frameSnap_ = &f.detached;
        f.tab->selectRepresentation(f.ctx, view.first);
        if (view.first == 5) f.tab->setStaticCursor(kTarget - 128);
        settle(); capture(view.second);
    }
    f.tab->selectRepresentation(f.ctx, 0);
    f.tab->setStaticCursor(kTarget + 10);
    settle();
    for (const auto menu : {std::pair{"Display##listing_display", "binary-display-menu"},
                           std::pair{"More##listing_more", "binary-more-menu"}}) {
        ImGuiWindow* owner = releaseWindow("##active_analysis_view");
        CHECK(owner != nullptr);
        if (!owner) continue;
        const ImGuiID button = owner->GetID(menu.first);
        // Let native item submission publish the focused button's exact bounds,
        // then click those bounds. OpenPopup receives the genuine mouse anchor.
        beforePaint = [&] {
            ImGui::FocusWindow(owner);
            ImGui::SetNavID(button, ImGuiNavLayer_Main, owner->NavRootFocusScopeId,
                            ImRect(ImVec2(0, 0), ImVec2(1, 1)));
            ImGui::SetNavCursorVisible(true);
        };
        paint();
        beforePaint = {};
        CHECK(GImGui->NavId == button);
        ImRect buttonBounds = owner->NavRectRel[ImGuiNavLayer_Main];
        buttonBounds.Translate(owner->Pos);
        CHECK(buttonBounds.GetWidth() > 0 && buttonBounds.GetHeight() > 0);
        CHECK(buttonBounds.Min.x >= owner->Pos.x && buttonBounds.Min.y >= owner->Pos.y);
        const ImVec2 point = buttonBounds.GetCenter();
        ImGui::SetNavCursorVisible(false);
        ImGui::GetIO().AddMousePosEvent(point.x, point.y); paint(); paint();
        ImGui::GetIO().AddMouseButtonEvent(ImGuiMouseButton_Left, true); paint();
        ImGui::GetIO().AddMouseButtonEvent(ImGuiMouseButton_Left, false); settle();
        CHECK(!GImGui->OpenPopupStack.empty());
        if (!GImGui->OpenPopupStack.empty()) {
            ImGuiWindow* popup = GImGui->OpenPopupStack.back().Window;
            CHECK(popup && popup->Pos.x >= owner->Pos.x && popup->Pos.y >= owner->Pos.y);
        }
        capture(menu.second);
        ImGui::ClosePopupsOverWindow(nullptr, false); ImGui::ClearActiveID(); settle();
    }
    size = ImVec2(1366, 800); settle(); capture("binary-compact");
    size = ImVec2(1920, 1200);

    DbgSnapshot paused;
    paused.pid = 0xFFFFFFF0; paused.sessionGeneration = 71;
    paused.state = DbgState::Paused; paused.activeTid = paused.tid = 42;
    paused.regs.rip = kTarget + 10; paused.regs.rax = 1; paused.regs.rcx = 0x10;
    paused.regs.rsp = 0x12FF80; paused.regs.rbp = 0x12FFA0; paused.regs.rflags = 0x246;
    paused.breakpoints = {{kTarget + 10, {}, 1, 1}, {kTarget + 26, {}, 1, 1}};
    for (const bool wow64 : {false, true}) {
        paused.is32 = wow64;
        f.ctx.frameDebugSnapshot = &paused;
        f.tab->frameSnap_ = &paused;
        f.tab->stringsAutoPid_ = paused.pid;
        f.tab->stringsAutoSessionGeneration_ = paused.sessionGeneration;
        f.tab->selectRepresentation(f.ctx, 4);
        settle(); // retire the previous session before publishing the owned cache
        auto decoder = MakeDisassembler(Engine::Zydis, wow64 ? Arch::X86 : Arch::X64);
        f.tab->liveInsns_ = decoder->disassemble(bytes.data() + kTarget, 128, kTarget, 128);
        f.tab->liveIdxOf_.clear();
        for (size_t i = 0; i < f.tab->liveInsns_.size(); ++i)
            f.tab->liveIdxOf_[f.tab->liveInsns_[i].address] = static_cast<int>(i);
        f.tab->followLiveRip_ = false;
        f.tab->liveNavigate(kTarget);
        f.tab->setLiveCursor(paused.regs.rip);
        f.tab->liveBrowseValid_ = true; f.tab->liveBrowseVA_ = kTarget;
        f.tab->liveCacheStart_ = kTarget;
        f.tab->liveCacheSig_ = kTarget ^ (paused.regs.rip * 0x9E3779B97F4A7C15ull) ^
            (uint64_t(f.tab->liveGen_) << 1) ^ (f.tab->functionsGen_ * 0xD6E8FEB86659FD93ull) ^
            (uint64_t(paused.pid) << 33) ^ (uint64_t(f.ctx.staticEngine()) << 56);
        f.tab->lastScrolledRip_ = paused.regs.rip; f.tab->lastScrolledRipValid_ = true;
        f.tab->liveMode_ = 0;
        f.tab->focusRegistersTab_ = true; f.tab->lowerAdvancedMode_ = false;
        f.tab->lowerDockCollapsed_ = false;
        settle(); capture(wow64 ? "binary-live-wow64" : "binary-live-x64");
    }
    // Real production drawer with authored enabled/disabled records. The
    // detached core still rejects interaction against this synthetic pause.
    SwBreakpointInfo disabled;
    disabled.address = kTarget + 64; disabled.enabled = false; disabled.armed = false;
    disabled.condition = "rax == 0x10"; disabled.everyN = 7; disabled.hits = 19; disabled.stops = 3;
    paused.breakpoints.push_back(disabled);
    f.tab->disabledBreakpoints_.insert(kTarget + 10);
    f.tab->condBuf_[kTarget + 10] = "rcx == 0x10";
    f.tab->everyNBuf_[kTarget + 10] = 7;
    f.tab->focusRegistersTab_ = false;
    f.tab->lowerAdvancedMode_ = false;
    for (int i = 0; i < 3; ++i) {
        frame([&] {
            f.tab->frameSnap_ = &paused;
            f.tab->renderLowerTabs(f.ctx, false);
        }, "Breakpoint pause controls - authored QA records", ImVec2(1440, 480));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    }
    CHECK(!f.ctx.debug.snapshot().attached());
    CHECK(paused.breakpoints.back().enabled == false && paused.breakpoints.back().everyN == 7);
    CHECK(f.tab->disabledBreakpoints_.count(kTarget + 10) == 1);
    capture("binary-breakpoints-disabled");
    f.ctx.frameDebugSnapshot = nullptr;
    f.tab->frameSnap_ = &f.detached;

    // Visit every native drawer through ImGui's tab-selection queue. This also
    // exercises overflow scrolling in the long analysis-tool rail: we never
    // assign SelectedTabId or invoke a selected tool body in isolation.
    // Fixtures are labelled, FILE-only analyst data; the debugger stays detached.
    const auto oldWatches = f.tab->watches_;
    const auto oldSearchHits = f.tab->searchHits_;
    const auto oldNotes = f.tab->notes_;
    const bool oldNotesReload = f.tab->notesReloadEditor_;
    const auto oldOutput = f.detached.debugOutput;
    f.tab->watches_ = {"rax", "rcx", "[rsp+8]", "0x1000"};
    f.tab->recompileWatches();
    f.tab->searchHits_ = {kTarget, kTarget + 64, kTarget + 128, kTarget + 192};
    f.tab->notes_ = "Authored UI review fixture\n\n"
        "Compare verify_token and parse_header using the FILE listing.\n"
        "The saved markers and byte-search locations refer to the authored sample.\n\n"
        "No target has been launched, attached or executed for these captures.";
    f.tab->notesReloadEditor_ = true;
    f.detached.debugOutput = {
        "[Authored UI sample] Output pane line wrapping and contrast.",
        "[Authored UI sample] These lines were not emitted by a running process.",
        "[Authored UI sample] Debugger remains detached."};
    f.tab->focusRegistersTab_ = false;
    f.tab->lowerDockCollapsed_ = false;
    f.tab->selectRepresentation(f.ctx, 0);
    f.tab->setStaticCursor(kTarget + 10);
    const char* drawerTitle = "Binary View drawers - authored FILE data / detached debugger";
    const DbgSnapshot* drawerSnapshot = &f.detached;
    auto paintDrawer = [&] {
        frame([&] {
            f.tab->frameSnap_ = drawerSnapshot;
            f.tab->renderLowerTabs(f.ctx, false);
        }, drawerTitle, ImVec2(1440, 660));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
        CHECK(!f.ctx.debug.snapshot().attached() && !f.ctx.debug.lifecycleSnapshot().busy);
    };
    auto settleDrawer = [&] { paintDrawer(); paintDrawer(); paintDrawer(); };
    auto selectDrawer = [&](const char* label, bool advanced) {
        ImGui::ClosePopupsOverWindow(nullptr, false);
        ImGui::ClearActiveID();
        ImGui::GetIO().ClearInputKeys(); ImGui::GetIO().ClearInputMouse();
        ImGui::GetIO().AddMousePosEvent(-100, -100);
        f.tab->lowerAdvancedMode_ = advanced;
        settleDrawer();
        ImGuiWindow* owner = ImGui::FindWindowByName(drawerTitle);
        CHECK(owner != nullptr);
        if (!owner) return false;
        const ImGuiID barId = owner->GetID(advanced ? "lower_secondary" : "lower_primary");
        ImGuiTabBar* bar = GImGui->TabBars.GetByKey(barId);
        CHECK(bar != nullptr);
        if (!bar) return false;
        const ImGuiID target = ImHashStr(label, 0, barId);
        ImGuiTabItem* item = ImGui::TabBarFindTabByID(bar, target);
        CHECK(item != nullptr);
        if (!item) return false;
        ImGui::TabBarQueueFocus(bar, item);
        settleDrawer();
        bar = GImGui->TabBars.GetByKey(barId);
        const bool visible = bar && bar->SelectedTabId == target && bar->VisibleTabId == target;
        CHECK(visible);
        return visible;
    };
    struct DrawerCapture { const char* label; const char* file; bool advanced; };
    const DrawerCapture drawers[] = {
        {"Threads", "binary-drawer-threads-detached", false},
        {"Call Stack", "binary-drawer-call-stack", false},
        {"Functions", "binary-drawer-functions", false},
        {"Watch", "binary-drawer-watch", false},
        {"Notes", "binary-drawer-notes", false},
        {"Results###lower_results", "binary-drawer-results", false},
        {"Patches###lower_patches", "binary-drawer-patches", false},
        {"Imports", "binary-drawer-imports", false},
        {"Resources", "binary-drawer-resources", false},
        {"Hotkeys", "binary-drawer-hotkeys", false},
        {"Modules", "binary-drawer-modules-detached", true},
        {"Debug Output", "binary-drawer-debug-output", true},
        {"Stack", "binary-drawer-stack", true},
        {"Xrefs", "binary-drawer-xrefs", true},
        {"PDB / Symbols", "binary-drawer-pdb-symbols", true},
        {"Address Inspector", "binary-drawer-address-inspector", true},
        {"Types", "binary-drawer-types", true},
        {"Algorithms", "binary-drawer-algorithms", true},
        {"Annotations", "binary-drawer-annotations", true},
        {"Triage", "binary-drawer-triage", true},
        {"Synthesis", "binary-drawer-synthesis", true},
        {"Hot-Patch", "binary-drawer-hot-patch", true},
        {"Path Explorer", "binary-drawer-path-explorer", true},
    };
    for (const auto& drawer : drawers)
        if (selectDrawer(drawer.label, drawer.advanced)) capture(drawer.file);

    // Explicit authored running records show the thread and module table
    // presentation without inventing a verified stop or invoking any action.
    DbgSnapshot authoredRunning;
    authoredRunning.state = DbgState::Running;
    authoredRunning.pid = 0xFFFFFFF0; authoredRunning.sessionGeneration = 201;
    authoredRunning.tid = authoredRunning.activeTid = 42;
    authoredRunning.threads = {{42, kTarget + 10, false}, {57, kTarget + 64, false},
                               {68, kTarget + 128, true}};
    DbgModule authoredModule;
    authoredModule.name = "authored-ui-fixture.raw";
    authoredModule.path = samplePath.string();
    authoredModule.base = 0; authoredModule.size = bytes.size();
    authoredModule.loadGeneration = 1;
    authoredRunning.modules = {authoredModule};
    drawerSnapshot = &authoredRunning;
    drawerTitle = "Binary View drawers - authored running records / detached debugger";
    if (selectDrawer("Threads", false)) capture("binary-drawer-threads-authored");
    if (selectDrawer("Modules", true)) capture("binary-drawer-modules-authored");
    CHECK(authoredRunning.threads.size() == 3 && authoredRunning.threads.back().suspended);
    CHECK(!f.ctx.debug.snapshot().attached() && !f.ctx.debug.lifecycleSnapshot().busy);

    f.tab->watches_ = oldWatches; f.tab->recompileWatches();
    f.tab->searchHits_ = oldSearchHits;
    f.tab->notes_ = oldNotes; f.tab->notesReloadEditor_ = oldNotesReload;
    f.detached.debugOutput = oldOutput;
    f.tab->frameSnap_ = &f.detached;
    f.ctx.staticAnalysis().cancelAndWaitIdle();
    theme::ApplyTheme(previousTheme);
}
