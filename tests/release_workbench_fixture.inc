// Production ImGui composition and input regressions for the approved workbench.
// Synthetic register snapshots exercise presentation/edit cancellation only; this
// fixture never attaches, executes a target, or requests a register write.
static ImGuiWindow* releaseWindow(const char* fragment) {
    for (ImGuiWindow* window : ImGui::GetCurrentContext()->Windows)
        if (window->LastFrameActive == ImGui::GetFrameCount() &&
            std::strstr(window->Name, fragment)) return window;
    return nullptr;
}

static void releaseActivate(ImGuiWindow* window, const char* label,
                            const char* scope = nullptr) {
    CHECK(window != nullptr);
    if (!window) return;
    const ImGuiID id = scope
        ? ImHashStr(label, 0, window->GetID(scope)) : window->GetID(label);
    ImGui::FocusWindow(window);
    ImGui::ActivateItemByID(id);
}

static void checkReleaseWorkbench(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    for (ImVec2 size : {ImVec2(1920, 1200), ImVec2(1366, 800)}) {
        Fixture f(path);
        f.tab->mainView_ = 7; // Overview keeps this composition test decoder-light.
        f.tab->functions_ = {{kTarget, "check_activation", 16},
                             {kTarget + 16, "check_key", 16}};
        ++f.tab->functionsGen_;
        f.tab->funcIndexDirty_ = true;
        f.tab->strings_ = {{kTarget + 40, "Activated"},
                           {kTarget + 56, "Invalid key"}};
        ++f.tab->stringsGen_;
        f.tab->stringsScanned_ = true;
        f.tab->stringsScanning_ = f.tab->stringsLive_ = false;
        f.tab->cursorValid_ = false;
        std::string visibleText;
        auto paint = [&] {
            frame([&] {
                ImGui::LogToBuffer();
                f.tab->render(f.ctx);
                visibleText = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
            }, "Release workbench QA", size);
            CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
            f.tab->frameSnap_ = &f.detached;
        };
        auto settle = [&] { paint(); paint(); paint(); };
        auto permanentNavigator = [&] {
            ImGuiWindow* navigator = releaseWindow("##right_inspector");
            ImGuiWindow* functions = releaseWindow("navigator_functions");
            ImGuiWindow* strings = releaseWindow("navigator_strings");
            ImGuiWindow* queue = releaseWindow("navigator_analysis_queue");
            CHECK(navigator && functions && strings && queue);
            if (!navigator || !functions || !strings || !queue) return;
            CHECK(functions->Size.y > ImGui::GetTextLineHeight() * 3);
            CHECK(strings->Size.y > ImGui::GetTextLineHeight() * 3);
            CHECK(functions->Pos.y + functions->Size.y <= strings->Pos.y + 1.0f);
            CHECK(strings->Pos.y + strings->Size.y <= queue->Pos.y + 1.0f);
            for (ImGuiWindow* child : {functions, strings, queue}) {
                CHECK(child->Pos.x >= navigator->Pos.x - 1.0f);
                CHECK(child->Pos.x + child->Size.x <= navigator->Pos.x + navigator->Size.x + 1.0f);
                CHECK(child->Pos.y + child->Size.y <= navigator->Pos.y + navigator->Size.y + 1.0f);
            }
            CHECK(visibleText.find("Functions") != std::string::npos);
            CHECK(visibleText.find("Strings") != std::string::npos);
        };
        settle();
        permanentNavigator();
        CHECK(visibleText.find("check_activation") != std::string::npos);
        CHECK(visibleText.find("Activated") != std::string::npos);
        CHECK(releaseWindow("navigator_optional") == nullptr);
        ImGuiWindow* navigator = releaseWindow("##right_inspector");
        ImGuiWindow* viewport = releaseWindow("##analysis_viewport");
        ImGuiWindow* evidence = releaseWindow("##evidence_inspector");
        CHECK(navigator && viewport && evidence);
        if (navigator && viewport && evidence) {
            CHECK(navigator->Pos.x + navigator->Size.x <= viewport->Pos.x);
            CHECK(viewport->Pos.x + viewport->Size.x <= evidence->Pos.x);
            CHECK(evidence->Pos.x + evidence->Size.x <= size.x + 1.0f);
        }

        // Intermediate widths used to keep the inspector open while squeezing
        // instruction text. Collapse only its presentation, retaining the user's
        // chosen width and independent pane state for the return to a wide window.
        const ImVec2 wideSize = size;
        const float scale = theme::UiScale();
        const float retainedEvidenceWidth = f.tab->evidenceInspectorW_;
        size = ImVec2(1200.0f * scale, 800.0f * scale);
        settle();
        evidence = releaseWindow("##evidence_inspector");
        viewport = releaseWindow("##analysis_viewport");
        CHECK(evidence && viewport);
        if (evidence && viewport) {
            CHECK(std::fabs(evidence->Size.x - 34.0f * scale) <= 1.0f);
            CHECK(viewport->Size.x >= 760.0f * scale);
        }
        CHECK(!f.tab->evidenceInspectorCollapsed_ && !f.tab->lowerDockCollapsed_);
        CHECK(f.tab->evidenceInspectorW_ == retainedEvidenceWidth);
        permanentNavigator();
        size = wideSize;
        settle();
        evidence = releaseWindow("##evidence_inspector");
        CHECK(evidence != nullptr);
        if (evidence) CHECK(evidence->Size.x >= 245.0f * scale);
        CHECK(!f.tab->evidenceInspectorCollapsed_ && !f.tab->lowerDockCollapsed_);
        CHECK(f.tab->evidenceInspectorW_ == retainedEvidenceWidth);

        // Actual workflow and rail actions must leave the two navigator lists
        // present and must not couple subsequent independent expand operations.
        releaseActivate(releaseWindow("##binary_command_band"), "Focus code");
        settle();
        CHECK(f.tab->evidenceInspectorCollapsed_ && f.tab->lowerDockCollapsed_);
        CHECK(f.tab->analysisQueueCollapsed_ && f.ctx.analysisQueueCollapsed);
        permanentNavigator();
        // The narrow rail must retain the complete rotated label. Measuring its
        // emitted vertical extent catches clipping before text rotation, which
        // can otherwise leave only the first one or two letters visible.
        ImGuiWindow* collapsedEvidence = releaseWindow("##evidence_inspector");
        CHECK(collapsedEvidence != nullptr);
        if (collapsedEvidence) {
            float labelTop = FLT_MAX, labelBottom = -FLT_MAX;
            const ImU32 labelColor = ImGui::GetColorU32(theme::col::muted());
            for (const ImDrawVert& vertex : collapsedEvidence->DrawList->VtxBuffer)
                if (vertex.col == labelColor) {
                    labelTop = std::min(labelTop, vertex.pos.y);
                    labelBottom = std::max(labelBottom, vertex.pos.y);
                }
            const float expectedHeight = ImGui::CalcTextSize("Evidence inspector").x;
            CHECK(labelBottom - labelTop >= expectedHeight - ImGui::GetFontSize() * 2.0f);
            CHECK(labelBottom - labelTop > collapsedEvidence->Size.x * 2.0f);
            CHECK(labelBottom <= collapsedEvidence->Pos.y + collapsedEvidence->Size.y + 1.0f);
        }
        releaseActivate(releaseWindow("##evidence_inspector"), "###evidence_toggle");
        settle();
        CHECK(!f.tab->evidenceInspectorCollapsed_ && f.tab->lowerDockCollapsed_);
        CHECK(f.tab->analysisQueueCollapsed_);

        // Registers remain a direct destination even with the drawer collapsed.
        releaseActivate(releaseWindow("##evidence_inspector"), "Open register editor");
        settle();
        CHECK(!f.tab->lowerDockCollapsed_ && !f.tab->lowerAdvancedMode_);
        CHECK(!f.tab->focusRegistersTab_);
        CHECK(f.tab->analysisQueueCollapsed_ && !f.tab->evidenceInspectorCollapsed_);
        CHECK(visibleText.find("Attach a process to view registers and stack.") != std::string::npos);
        releaseActivate(releaseWindow("##bottom_tool_drawer"), "##button", "lower_dock_edge_toggle");
        settle();
        CHECK(f.tab->lowerDockCollapsed_);
        releaseActivate(releaseWindow("navigator_analysis_queue"), "###queue_toggle");
        settle();
        CHECK(!f.tab->analysisQueueCollapsed_ && !f.ctx.analysisQueueCollapsed);
        CHECK(f.tab->lowerDockCollapsed_ && !f.tab->evidenceInspectorCollapsed_);
        permanentNavigator();

        // The real menu is the only action opening an optional category. The
        // same choice then survives representation/preset changes and resizing.
        releaseActivate(releaseWindow("##right_inspector"), "Customize##navigator");
        settle();
        ImGuiWindow* menu = ImGui::GetCurrentContext()->OpenPopupStack.empty()
            ? nullptr : ImGui::GetCurrentContext()->OpenPopupStack.back().Window;
        releaseActivate(menu, "Bookmarks");
        settle();
        CHECK(releaseWindow("navigator_optional") != nullptr);
        CHECK(f.ctx.navigatorOptionalMask != 0);
        const uint32_t manualChoice = f.ctx.navigatorOptionalMask;
        permanentNavigator();
        frame([&] { f.tab->applyWorkflow(f.ctx, 1); }, "Workflow transition");
        CHECK(f.ctx.requestedTab == "Communications");
        settle();
        CHECK(f.ctx.navigatorOptionalMask == manualChoice);
        frame([&] { f.tab->selectRepresentation(f.ctx, 2); }, "Representation transition");
        f.tab->mainView_ = 7;
        size = size.x > 1400 ? ImVec2(1366, 800) : ImVec2(1920, 1200);
        settle();
        CHECK(f.ctx.navigatorOptionalMask == manualChoice);
        CHECK(releaseWindow("navigator_optional") != nullptr);
        permanentNavigator();

        // Recreating a document UI must read the workspace preference before
        // its first frame writes state back; it cannot silently erase the menu.
        auto priorTab = std::move(f.tab);
        f.tab = std::make_unique<BinaryViewTab>(f.ctx.staticDocumentId());
        CHECK(f.tab->synchronizeDocumentImage(f.ctx));
        f.ctx.staticAnalysis().cancelAndWaitIdle();
        f.tab->mainView_ = 7;
        settle();
        CHECK(f.ctx.navigatorOptionalMask == manualChoice);
        CHECK(f.tab->navigatorOptionalMask_ == manualChoice);
        CHECK(releaseWindow("navigator_optional") != nullptr);
        permanentNavigator();
        ImGui::ClosePopupsOverWindow(nullptr, false);
        ImGui::ClearActiveID();
    }
}

static void checkRegisterEditorPresentation(const std::string& path) {
    Fixture f(path);
    f.detached.state = DbgState::Paused;
    f.detached.pid = 424242;
    f.detached.sessionGeneration = 7;
    f.detached.activeTid = 3;
    f.detached.regs.rax = 0x1234;
    f.tab->focusRegistersTab_ = true;
    f.tab->lowerAdvancedMode_ = false;
    std::string visibleText;
    auto paint = [&] {
        frame([&] {
            f.tab->frameSnap_ = &f.detached;
            ImGui::LogToBuffer();
            f.tab->renderLowerTabs(f.ctx, false);
            visibleText = ImGui::GetCurrentContext()->LogBuffer.c_str();
            ImGui::LogFinish();
        }, "Register editor QA");
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    auto activateRax = [&](const char* label) {
        ImGuiWindow* registers = releaseWindow("/regs_");
        CHECK(registers != nullptr);
        if (!registers) return;
        ImGui::FocusWindow(registers);
        ImGui::ActivateItemByID(ImHashStr(label, 0, registers->GetID(4)));
        settle();
    };
    settle();
    CHECK(visibleText.find("Paused / register editing available") != std::string::npos);
    CHECK(visibleText.find("RAX") != std::string::npos);
    CHECK(visibleText.find("0000000000001234") != std::string::npos);
    activateRax("Edit");
    CHECK(f.tab->regEditIdx_ == 4);
    CHECK(visibleText.find("Editing RAX") != std::string::npos);
    CHECK(visibleText.find("Save") != std::string::npos && visibleText.find("Cancel") != std::string::npos);
    activateRax("Cancel");
    CHECK(f.tab->regEditIdx_ == -1);
    CHECK(visibleText.find("RAX edit cancelled") != std::string::npos);
    CHECK(f.detached.regs.rax == 0x1234);

    // A captured value remains visible after resuming, while its edit affordance
    // is disabled and a pending edit retires rather than crossing a pause owner.
    activateRax("Edit");
    CHECK(f.tab->regEditIdx_ == 4);
    f.detached.state = DbgState::Running;
    settle();
    CHECK(f.tab->regEditIdx_ == -1);
    CHECK(visibleText.find("Last captured registers / read-only while running") != std::string::npos);
    activateRax("Edit");
    CHECK(f.tab->regEditIdx_ == -1);
    f.detached.state = DbgState::Paused;
    settle();
    activateRax("Edit");
    CHECK(f.tab->regEditIdx_ == 4);
    ++f.detached.activeTid;
    settle();
    CHECK(f.tab->regEditIdx_ == -1);
    CHECK(visibleText.find("Edit cancelled: the target, thread, or paused instruction changed.") != std::string::npos);
    CHECK(!f.ctx.debug.snapshot().attached());
    CHECK(!f.ctx.debug.lifecycleSnapshot().busy);
    f.detached = {};
    ImGui::ClearActiveID();
}

static void checkInspectorObservationValidity(const std::string& path) {
    Fixture f(path);
    const uint64_t branchAddress = 0x1018;
    const uint8_t branchBytes[] = {0x75, 0x16}; // jne 0x1030, decoded by production Zydis/Capstone
    Instruction branch;
    CHECK(f.ctx.staticDisassembler()->decodeOne(branchBytes, sizeof(branchBytes), branchAddress, branch));
    CHECK(branch.flow.kind == FlowKind::ConditionalBranch);
    f.detached.state = DbgState::Paused;
    f.detached.pid = 424242;
    f.detached.sessionGeneration = 88;
    f.detached.activeTid = 3;
    f.detached.regs.rip = branchAddress;
    f.detached.regs.rflags = 0; // JNE would be taken if this were a current verified pause.
    f.tab->cursorVA_ = branchAddress;
    f.tab->cursorValid_ = f.tab->cursorLive_ = true;
    f.tab->mainView_ = 4;
    f.tab->liveMode_ = 0;
    f.tab->liveSessionPidSeen_ = f.detached.pid;
    f.tab->liveSessionGenerationSeen_ = f.detached.sessionGeneration;
    f.tab->liveInsns_ = {branch};
    f.tab->liveIdxOf_ = {{branchAddress, 0}};
    AuthorizationTrailConclusion conclusion;
    conclusion.kind = AuthorizationTrailConclusionKind::FeaturePermitted;
    conclusion.status = AuthorizationTrailConclusionStatus::Supported;
    f.tab->crackmeTriage_.authorizationTrail.conclusions = {conclusion};
    f.tab->crackmeTriageValid_ = true;
    std::string visibleText;
    auto paint = [&] {
        frame([&] {
            f.tab->frameSnap_ = &f.detached;
            ImGui::LogToBuffer();
            f.tab->renderEvidenceInspector(f.ctx, false);
            visibleText = ImGui::GetCurrentContext()->LogBuffer.c_str();
            ImGui::LogFinish();
        }, "Inspector validity QA", ImVec2(600, 900));
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    auto unknownOutcome = [&] {
        CHECK(visibleText.find("Branch outcome unknown") != std::string::npos);
        CHECK(visibleText.find("Jump will be taken") == std::string::npos);
        CHECK(visibleText.find("Jump will not be taken") == std::string::npos);
    };
    paint();
    unknownOutcome();
    CHECK(visibleText.find("Current paused context or instruction bytes could not be verified") != std::string::npos);
    CHECK(visibleText.find(AuthorizationTrailConclusionKindText(conclusion.kind)) != std::string::npos);
    CHECK(!f.ctx.debug.snapshot().attached()); // cached UI state is deliberately not debugger authority
    f.detached.regs.rflags = 1ull << 6;
    paint();
    unknownOutcome();
    f.detached.state = DbgState::Running;
    paint();
    unknownOutcome();
    CHECK(visibleText.find("Execution is not paused") != std::string::npos);
    f.detached.state = DbgState::Paused;
    ++f.detached.regs.rip;
    paint();
    unknownOutcome();
    CHECK(visibleText.find("This selection is not the paused instruction") != std::string::npos);
    f.tab->functionsDirty_ = true;
    paint();
    CHECK(visibleText.find("Previous analysis / refresh pending") != std::string::npos);
    CHECK(visibleText.find(AuthorizationTrailConclusionKindText(conclusion.kind)) == std::string::npos);
    f.tab->functionsDirty_ = false;
    f.detached = {};
}
