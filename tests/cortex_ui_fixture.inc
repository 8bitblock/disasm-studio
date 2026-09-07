// Actual Cortex rendering over a retained synthetic report. No target executes
// and no worker is started; result identity still follows the production path.
static void checkCortexProductionUi(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    AppContext ctx;
    featureLoadRaw(ctx, path);
    CortexTab tab;
    const auto identity = MakeDocumentResultIdentity(ctx.staticDocumentId(),
        ctx.staticImageGeneration(), true, ctx.staticBinary().contentHash(),
        ctx.staticBinary().imageRevision());
    tab.observedIdentity_ = tab.analyzedIdentity_ = identity;
    tab.analyzed_ = true;
    tab.analyzedEngine_ = ctx.staticEngine();
    tab.analyzedArch_ = ctx.staticArch();
    tab.rep_.headline = "Static Cortex fixture";
    tab.rep_.verdict = "This report contains bounded synthetic evidence for UI verification.";
    tab.rep_.facts = {"Raw", "x64", "Entry 0x0"};
    CortexBehavior behavior;
    behavior.title = "Network##literal communication";
    behavior.confidence = 0.75f;
    behavior.explanation = "A network import suggests communication capability.";
    behavior.evidence = "Exact DLL-qualified import evidence";
    behavior.specifics = {"Winsock"};
    behavior.addresses = {0, 16};
    tab.rep_.behaviors.push_back(behavior);
    tab.behSel_ = 0;
    for (size_t i = 0; i < 16384; ++i) {
        CortexFuncBrief function;
        function.address = i * 16;
        function.name = i == 0 ? "Entry##literal" : i == 1 ? "Read Settings" : "helper_" + std::to_string(i);
        function.brief = i == 1 ? "Reads the configuration file" : "General function brief";
        function.basis = "Synthetic static evidence";
        function.guessed = i != 0;
        tab.rep_.functions.push_back(function);
    }
    tab.rep_.highlights.assign(tab.rep_.functions.begin(), tab.rep_.functions.begin() + 2);
    ImVec2 size(1200, 800);
    std::string visibleText;
    auto paint = [&](bool log = false) {
        featureFrame([&] {
            if (log) ImGui::LogToBuffer();
            tab.render(ctx);
            if (log) {
                visibleText = GImGui->LogBuffer.c_str();
                ImGui::LogFinish();
            }
        }, size);
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    auto windowWith = [](const char* text) -> ImGuiWindow* {
        for (ImGuiWindow* window : GImGui->Windows)
            if (window->LastFrameActive == GImGui->FrameCount && std::strstr(window->Name, text))
                return window;
        return nullptr;
    };
    auto directPane = [](const char* label) -> ImGuiWindow* {
        ImGuiWindow* host = ImGui::FindWindowByName("Feature UI integration");
        if (!host) return nullptr;
        const ImGuiID childId = host->GetID(label);
        for (ImGuiWindow* window : GImGui->Windows)
            if (window->LastFrameActive == GImGui->FrameCount &&
                window->ParentWindow == host && window->ChildId == childId)
                return window;
        return nullptr;
    };
    settle();
    paint(true);
    CHECK(tab.analyzed_);
    CHECK(tab.functionRows_.size() == 2);
    CHECK(visibleText.find("Selected evidence") != std::string::npos);
    CHECK(visibleText.find("Exact DLL-qualified import evidence") != std::string::npos);
    CHECK(visibleText.find("0x0") != std::string::npos);
    CHECK(visibleText.find("Network##literal communication") != std::string::npos);
    CHECK(visibleText.find("Entry##literal") != std::string::npos);

    // Evidence is actionable, including valid FILE zero.
    ImGuiWindow* evidence = windowWith("cx_evidence");
    CHECK(evidence != nullptr);
    if (evidence) {
        ImGui::FocusWindow(evidence);
        ImGui::ActivateItemByID(evidence->GetID("Copy evidence"));
        paint();
        CHECK(std::string(ImGui::GetClipboardText()).find("Exact DLL-qualified import evidence") != std::string::npos);
        CHECK(std::string(ImGui::GetClipboardText()).find("Winsock") != std::string::npos);
        CHECK(std::string(ImGui::GetClipboardText()).find("FILE:0x0") != std::string::npos);
        const int firstAddress = 0;
        const ImGuiID seed = ImHashData(&firstAddress, sizeof(firstAddress), evidence->IDStack.back());
        ImGui::ActivateItemByID(ImHashStr("0x0", 0, seed));
        paint();
        CHECK(ctx.hasGotoRequest && ctx.requestedGotoVA == 0 && !ctx.requestedGotoLive);
        CHECK(ctx.requestedTab == "Binary View");
    }

    // All briefs are available without submitting every row to ImGui each frame.
    tab.allFunctions_ = true;
    tab.functionRowsDirty_ = true;
    settle();
    CHECK(tab.functionRows_.size() == 16384);
    CHECK(ImGui::GetDrawData()->TotalVtxCount < 100000);
    const size_t* retainedRows = tab.functionRows_.data();
    paint();
    CHECK(tab.functionRows_.data() == retainedRows && !tab.functionRowsDirty_);
    std::snprintf(tab.functionFilter_, sizeof(tab.functionFilter_), "%s", "\"READ SETTINGS\" 0x10 -helper");
    tab.functionRowsDirty_ = true;
    paint(true);
    CHECK(tab.functionRows_ == std::vector<size_t>{1});
    CHECK(visibleText.find("Read Settings") != std::string::npos);
    std::snprintf(tab.functionFilter_, sizeof(tab.functionFilter_), "%s", "no-such-function");
    tab.functionRowsDirty_ = true;
    paint(true);
    CHECK(tab.functionRows_.empty());
    CHECK(visibleText.find("No matching functions") != std::string::npos);
    ImGuiWindow* functions = windowWith("##empty_state");
    CHECK(functions != nullptr);
    if (functions) {
        ImGui::FocusWindow(functions);
        ImGui::ActivateItemByID(functions->GetID("Clear filter"));
        settle();
        CHECK(tab.functionFilter_[0] == 0 && tab.functionRows_.size() == 16384);
    }

    // Compact layouts expose every destination and preserve manual wide splits.
    tab.behaviorPaneRatio_ = 0.39f;
    tab.chatPaneRatio_ = 0.36f;
    for (const ImVec2 dimensions : {ImVec2(720, 640), ImVec2(1200, 440)}) {
        size = dimensions;
        for (int pane = 0; pane < 3; ++pane) {
            tab.compactPane_ = pane;
            settle();
            CHECK(directPane("cx_compact_content") != nullptr);
            // Table children named cx_behtbl/cx_hitbl remain valid in compact
            // mode; substring lookup must not mistake them for the wide panes.
            CHECK(directPane("cx_beh") == nullptr);
            CHECK(directPane("cx_hi") == nullptr);
            CHECK(tab.behaviorPaneRatio_ == 0.39f && tab.chatPaneRatio_ == 0.36f);
        }
    }

    // The composer rejects whitespace and retains the newest 64 questions.
    size = ImVec2(720, 640);
    tab.compactPane_ = 2;
    tab.chat_.assign(64, {"Older question", "Older answer"});
    auto submit = [&](const char* question) {
        ImGui::ClearActiveID();
        std::snprintf(tab.input_, sizeof(tab.input_), "%s", question);
        tab.focusQuestion_ = true;
        paint(); paint();
        ImGui::GetIO().AddKeyEvent(ImGuiKey_Enter, true);
        paint();
        ImGui::GetIO().AddKeyEvent(ImGuiKey_Enter, false);
        paint();
    };
    submit("   ");
    CHECK(tab.chat_.size() == 64 && tab.chat_.back().first == "Older question");
    submit("  what does it do?  ");
    CHECK(tab.chat_.size() == 64 && tab.chat_.back().first == "what does it do?");
    CHECK(tab.input_[0] == 0);
    CHECK(!tab.chat_.back().second.empty());

    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        for (const float scale : {1.0f, 1.5f, 2.0f}) {
            theme::SetUiScale(scale);
            theme::ApplyTheme(palette);
            size = ImVec2(1200.0f * scale, 800.0f * scale);
            settle();
            CHECK(directPane("cx_beh") != nullptr && directPane("cx_hi") != nullptr);
            size = ImVec2(220.0f * scale, 640.0f * scale);
            tab.compactPane_ = 2;
            settle();
            ImGuiWindow* compact = directPane("cx_compact_content");
            CHECK(compact != nullptr);
            if (compact) {
                CHECK(compact->ScrollMax.x <= 1.0f);
                CHECK(compact->ScrollMax.y <= 1.0f);
            }
        }
    }
    theme::SetUiScale(1.0f);
    theme::ApplyTheme(theme::ThemeId::Midnight);

    size = ImVec2(1200, 800);
    settle();
    CHECK(directPane("cx_beh") != nullptr && directPane("cx_hi") != nullptr);
    CHECK(tab.behaviorPaneRatio_ == 0.39f && tab.chatPaneRatio_ == 0.36f);
    // Same image, changed analyst knowledge: stale results are hidden.
    ctx.staticProject().names[0] = "Changed analyst name";
    paint(true);
    CHECK(!tab.analyzed_);
    CHECK(visibleText.find("Ready to analyze") != std::string::npos);
    CHECK(directPane("cx_hi") == nullptr);
    ImGui::ClearActiveID();
    ImGui::ClosePopupsOverWindow(nullptr, false);
}
