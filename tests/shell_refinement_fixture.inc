// Public production-palette and shell interactions. No process is attached,
// launched, or written; injected search work only controls publication timing.
#include <atomic>

class ShellPaletteBackend final : public IInvestigationServiceBackend {
public:
    explicit ShellPaletteBackend(std::shared_ptr<std::atomic<bool>> release, size_t hitCount)
        : release_(std::move(release)), hitCount_(hitCount) {}

    InvestigationBuildResult build(const InvestigationSnapshot& snapshot,
        const InvestigationLimits& limits, const InvestigationCancel& cancelled) override {
        return InvestigationIndex::Build(snapshot, limits, cancelled);
    }

    InvestigationSearchResult search(const InvestigationIndex&, std::string_view,
        const InvestigationSearchOptions&, const InvestigationCancel& cancelled) override {
        while (!release_->load() && !cancelled()) Sleep(1);
        InvestigationSearchResult result;
        if (cancelled()) { result.cancelled = true; return result; }
        result.complete = true;
        for (size_t i = 0; i < hitCount_; ++i) {
            InvestigationResult hit;
            hit.score = 20000;
            hit.label = "Inspect evidence ## literal " + std::to_string(i);
            hit.detail = "Background search fixture";
            result.results.push_back(std::move(hit));
        }
        return result;
    }
private:
    std::shared_ptr<std::atomic<bool>> release_;
    size_t hitCount_;
};

static void checkPaletteActionRetention() {
    ImGuiIO& io = ImGui::GetIO();
    for (size_t hitCount : {size_t(3), size_t(64)}) {
        for (bool refreshSession : {false, true}) {
            ImGui::ClosePopupsOverWindow(nullptr, false);
            ImGui::ClearActiveID();
            io.ClearInputKeys(); io.ClearInputMouse();
            auto release = std::make_shared<std::atomic<bool>>(false);
            InvestigationService service([=] {
                return std::make_unique<ShellPaletteBackend>(release, hitCount);
            });
            auto snapshot = std::make_shared<const InvestigationSnapshot>();
            CHECK(service.beginSession(41, snapshot) != 0);
            AppContext ctx;
            ui::CommandPalette palette;
            int ran = -1;
            std::vector<ui::PaletteItem> actions(3);
            actions[0].label = "Inspect alpha";
            actions[0].run = [&] { ran = 0; };
            actions[1].label = "Inspect bravo";
            actions[1].run = [&] { ran = 1; };
            actions[2].label = "Inspect delta";
            actions[2].run = [&] { ran = 2; };
            palette.open(std::move(actions), &service, 41, {}, {});
            auto paint = [&] {
                io.DisplaySize = ImVec2(1000, 700);
                ImGui::NewFrame(); palette.render(ctx); ImGui::Render();
            };
            paint(); paint();
            io.AddInputCharactersUTF8("Inspect");
            paint(); paint();
            io.AddKeyEvent(ImGuiKey_DownArrow, true); paint();
            io.AddKeyEvent(ImGuiKey_DownArrow, false); paint();
            // Select the middle action. A positional clamp after a session
            // refresh would choose delta and must not accidentally pass.
            release->store(true);
            for (int retry = 0; retry < 1000 && !service.latestSearch(); ++retry) Sleep(1);
            CHECK(service.latestSearch() != nullptr);
            paint();
            if (refreshSession) {
                CHECK(service.beginSession(42, snapshot) != 0);
                palette.updateInvestigationSession(&service, 42, {});
                // Execute before another publication is adopted: removing the
                // previous evidence list must preserve the selected action too.
            }
            io.AddKeyEvent(ImGuiKey_Enter, true); paint();
            io.AddKeyEvent(ImGuiKey_Enter, false); paint();
            CHECK(ran == 1);
            CHECK(!palette.isOpen());
            palette.close();
            service.cancelAndWaitIdle();
        }
    }
    io.ClearInputKeys(); io.ClearInputMouse();
}

static void checkShellKeyboardNavigation() {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGuiIO& io = ImGui::GetIO();
    io.ClearInputKeys(); io.ClearInputMouse();
    const ImGuiConfigFlags savedConfig = io.ConfigFlags;
    const bool savedNavCursorVisible = ImGui::GetCurrentContext()->NavCursorVisible;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    App app;
    const ImVec2 size(1600, 960);
    for (int i = 0; i < 3; ++i) workbenchFrame(app, size);
    workbenchChord(app, size, ImGuiKey_4);
    ImGuiWindow* strip = ImGui::FindWindowByName("##tabstrip");
    CHECK(strip != nullptr);
    if (strip) {
        // NavUpdate clears unresolved requests at NewFrame. Request focus after
        // that boundary and before the real strip submits its navigable items.
        io.DisplaySize = size;
        ImGui::NewFrame();
        ImGui::FocusWindow(strip);
        ImGui::NavInitWindow(strip, true);
        app.render();
        ImGui::Render();
        workbenchFrame(app, size);
        CHECK(ImGui::GetCurrentContext()->NavWindow == strip);
        CHECK(ImGui::GetFocusID() != 0);
        const int projectsIndex = 0;
        const ImGuiID projectsOwner = ImHashData(&projectsIndex, sizeof(projectsIndex), strip->ID);
        const ImGuiID projectsButton = ImHashStr("##tabcard", 0, projectsOwner);
        std::printf("[nav] focused=%08X Projects=%08X active=%08X cursor-visible=%d\n",
            ImGui::GetFocusID(), projectsButton,
            ImGui::GetActiveID(),
            ImGui::GetCurrentContext()->NavCursorVisible ? 1 : 0);
        CHECK(ImGui::GetFocusID() == projectsButton);
        // Programmatic focus does not switch from mouse mode to keyboard mode.
        // Space activates only a visible navigation cursor, as after Tab/arrows.
        ImGui::SetNavCursorVisible(true);
        io.AddKeyEvent(ImGuiKey_Space, true); workbenchFrame(app, size);
        io.AddKeyEvent(ImGuiKey_Space, false); workbenchFrame(app, size);
        checkWorkbenchDestination("Projects");
    }
    // The document inventory is now a title-bar capsule. Its custom hit target
    // must remain on the menu navigation layer and open the same real inventory.
    ImGuiWindow* header = ImGui::FindWindowByName("##MainMenuBar");
    CHECK(header && (header->DC.NavLayersActiveMask & (1 << ImGuiNavLayer_Menu)) != 0);
    ImGuiWindow* documents = ImGui::FindWindowByName("##document-strip");
    CHECK(!documents || documents->LastFrameActive != ImGui::GetFrameCount());
    if (header) {
        // ImGui 1.91.9 BeginMenuBar pushes this case-sensitive native ID scope.
        const ImGuiID menuScope = ImHashStr("##MenuBar", 0, header->ID);
        const ImGuiID documentButton = ImHashStr("##document_list", 0, menuScope);
        const ImGuiID inventoryPopup = ImHashStr("##all_documents", 0, menuScope);
        io.DisplaySize = size;
        ImGui::NewFrame();
        GImGui->NavActivateId = documentButton;
        GImGui->NavActivateDownId = documentButton;
        GImGui->NavActivatePressedId = documentButton;
        app.render();
        CHECK(ImGui::IsPopupOpen(inventoryPopup, ImGuiPopupFlags_AnyPopupLevel));
        ImGui::Render();
        CHECK(header->DC.CursorMaxPos.x <= header->Pos.x + header->Size.x + 1.0f);
        ImGui::ClosePopupsOverWindow(nullptr, false);
    }
    ImGuiWindow* status = ImGui::FindWindowByName("##status");
    CHECK(status && (status->DC.NavLayersActiveMask & 1) != 0);
    io.ConfigFlags = savedConfig;
    ImGui::SetNavCursorVisible(savedNavCursorVisible);
    io.ClearInputKeys(); io.ClearInputMouse();
}
