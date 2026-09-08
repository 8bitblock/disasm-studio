// Authored debugger observations exercise the production shell without ever
// attaching to, starting, suspending, or editing a target process.
#include "ui_capture.h"

namespace ds {
struct AxiomShellTestAccess {
    static AppContext& context(App& app) { return app.ctx_; }
    static void prime(App& app, const DbgSnapshot& snap, bool paused = true) {
        app.toolbarThreadPopupTarget_ = {snap.pid, snap.sessionGeneration};
        app.toolbarThreadPopupTid_ = snap.activeTid;
        app.toolbarThreadPopupRip_ = snap.regs.rip;
        app.toolbarThreadPopupPaused_ = paused;
    }
    static bool select(App& app, const DbgSnapshot& snap, uint32_t tid) {
        return app.selectDebugToolbarThread(snap, tid);
    }
    static void controls(App& app, const DbgSnapshot& snap, float width, bool blocked = false) {
        app.renderDebugSessionControls(snap, width,
            std::max({30.0f * theme::UiScale(), ImGui::GetFrameHeight(),
                ImGui::GetTextLineHeight() * 2.0f + 4.0f * theme::UiScale()}), blocked);
    }
    static void shell(App& app, const DbgSnapshot& snap) {
        app.ctx_.frameDebugSnapshot = &snap;
        app.renderMenuBar();
        app.renderDocumentStrip();
        app.renderTabCardStrip(snap);
        app.renderDebugToolbar(snap);
        app.renderStatusBar(snap);
        app.ctx_.frameDebugSnapshot = nullptr;
    }
};
}

static DbgSnapshot authoredShellPause() {
    DbgSnapshot snapshot;
    snapshot.state = DbgState::Paused;
    snapshot.pid = 900042;
    snapshot.sessionGeneration = 71;
    snapshot.tid = snapshot.activeTid = 6240;
    snapshot.regs.rip = 0x140001040;
    snapshot.lastEvent = "Authored breakpoint at 0x140001040";
    snapshot.threads = {{6240, 0x140001040, false}, {6241, 0x140002040, true}};
    return snapshot;
}

static void checkAxiomShellReference() {
    ImGuiIO& io = ImGui::GetIO();
    const auto priorTheme = theme::CurrentTheme();
    const auto priorDensity = theme::CurrentDensity();
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID(); io.ClearInputKeys(); io.ClearInputMouse();
    App app;
    theme::ApplyTheme(theme::ThemeId::Axiom);
    const DbgSnapshot paused = authoredShellPause();
    auto& ctx = AxiomShellTestAccess::context(app);

    // A plausible retained UI snapshot is never target authority. The real
    // detached debugger must refuse even a matching popup and listed thread.
    AxiomShellTestAccess::prime(app, paused);
    CHECK(!AxiomShellTestAccess::select(app, paused, 6241));
    CHECK(!ctx.debug.setActiveThreadForSession({paused.pid, paused.sessionGeneration}, 6241));
    CHECK(ctx.debug.snapshot().state == DbgState::Detached);
    for (int variation = 0; variation < 7; ++variation) {
        DbgSnapshot changed = paused;
        AxiomShellTestAccess::prime(app, paused);
        if (variation == 0) changed.state = DbgState::Running;
        if (variation == 1) changed.cleanupOnly = true;
        if (variation == 2) ++changed.sessionGeneration;
        if (variation == 3) ++changed.pid;
        if (variation == 4) ++changed.activeTid;
        if (variation == 5) ++changed.regs.rip;
        if (variation == 6) changed.threads.clear();
        CHECK(!AxiomShellTestAccess::select(app, changed, 6241));
    }
    AxiomShellTestAccess::prime(app, paused, false);
    CHECK(!AxiomShellTestAccess::select(app, paused, 6241));

    auto controlsFrame = [&](float available, bool openPopup, const DbgSnapshot& snapshot,
                             bool blocked = false, std::string* text = nullptr) {
        io.DisplaySize = ImVec2(820, 560);
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Authored shell controls", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings);
        const ImVec2 before = ImGui::GetCursorScreenPos();
        if (openPopup) {
            AxiomShellTestAccess::prime(app, snapshot);
            ImGui::OpenPopup("##toolbar_session_popup");
        }
        if (text) ImGui::LogToBuffer();
        AxiomShellTestAccess::controls(app, snapshot, available, blocked);
        if (text) { *text = GImGui->LogBuffer.c_str(); ImGui::LogFinish(); }
        if (!ImGui::IsPopupOpen("##toolbar_session_popup"))
            CHECK(ImGui::GetItemRectMax().x <= before.x + available + 1.0f);
        const bool popup = ImGui::IsPopupOpen("##toolbar_session_popup");
        ImGui::End(); ImGui::Render();
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
        return popup;
    };
    for (int palette = 0; palette < static_cast<int>(theme::ThemeId::Count); ++palette) {
        theme::ApplyTheme(static_cast<theme::ThemeId>(palette));
        for (const auto state : {DbgState::Detached, DbgState::Paused, DbgState::Running,
                                 DbgState::Terminated}) {
            DbgSnapshot observation = state == DbgState::Detached ? DbgSnapshot{} : paused;
            observation.state = state;
            if (state == DbgState::Running) observation.lastEvent = "Authored process running";
            if (state == DbgState::Terminated) observation.lastEvent = "Authored process exit";
            for (float available : {380.0f, 260.0f, 140.0f, 90.0f}) {
                controlsFrame(available, false, observation);
                controlsFrame(available, false, observation);
            }
        }
    }
    std::string text;
    CHECK(controlsFrame(380, true, paused, false, &text));
    CHECK(text.find(paused.lastEvent) != std::string::npos);
    CHECK(text.find("Thread 6240") != std::string::npos);
    CHECK(text.find("Thread 6241 (suspended)") != std::string::npos);
    CHECK(text.find("step complete") == std::string::npos);
    CHECK(!controlsFrame(380, false, paused, true)); // same-frame execution retires the popup
    controlsFrame(380, true, paused);
    DbgSnapshot changed = paused; ++changed.sessionGeneration;
    CHECK(!controlsFrame(380, false, changed));
    controlsFrame(380, true, paused);
    changed = paused; changed.state = DbgState::Running;
    CHECK(!controlsFrame(380, false, changed));
    controlsFrame(380, true, paused);
    changed = paused; changed.cleanupOnly = true;
    CHECK(!controlsFrame(380, false, changed));
    ImGui::ClosePopupsOverWindow(nullptr, false);

    for (int palette = 0; palette < static_cast<int>(theme::ThemeId::Count); ++palette) {
        for (auto density : {theme::Density::Compact, theme::Density::Comfortable, theme::Density::Spacious}) {
            theme::SetDensity(density); theme::ApplyTheme(static_cast<theme::ThemeId>(palette));
            for (const ImVec2 size : {ImVec2(640, 560), ImVec2(820, 560), ImVec2(1440, 900), ImVec2(1920, 1080)}) {
                for (int settle = 0; settle < 3; ++settle) {
                    io.DisplaySize = size; ImGui::NewFrame();
                    AxiomShellTestAccess::shell(app, paused);
                    ImGui::Render();
                }
                ImGuiWindow* toolbar = ImGui::FindWindowByName("##debugbar");
                CHECK(toolbar);
                if (toolbar) {
                    CHECK(toolbar->ScrollMax.x <= 1.0f && toolbar->ScrollMax.y <= 1.0f);
                    CHECK(toolbar->DC.CursorMaxPos.x <= toolbar->Pos.x + toolbar->Size.x + 1.0f);
                }
                CHECK(GImGui->ErrorCountCurrentFrame == 0);
            }
        }
        // Activating the production toolbar's status item must open the checked
        // popup in every palette, including ones that formerly omitted it.
        ImGuiWindow* toolbar = ImGui::FindWindowByName("##debugbar");
        CHECK(toolbar);
        if (toolbar) {
            const ImGuiID statusId = ImHashStr("##toolbar_debug_status", 0, toolbar->ID);
            const ImGuiID popupId = ImHashStr("##toolbar_session_popup", 0, toolbar->ID);
            ImGui::NewFrame();
            GImGui->NavActivateId = statusId;
            GImGui->NavActivateDownId = statusId;
            GImGui->NavActivatePressedId = statusId;
            AxiomShellTestAccess::shell(app, paused);
            CHECK(ImGui::IsPopupOpen(popupId, ImGuiPopupFlags_AnyPopupLevel));
            ImGui::Render();
            ImGui::ClosePopupsOverWindow(nullptr, false);
        }
    }
    CHECK(!ctx.gmlExecutionMode);
    CHECK(ctx.debug.snapshot().state == DbgState::Detached);
    io.ClearInputKeys(); io.ClearInputMouse();
    theme::SetDensity(priorDensity); theme::ApplyTheme(priorTheme);
}

static void captureAxiomShellReference(const std::string& outputDirectory) {
    const auto priorTheme = theme::CurrentTheme();
    const auto priorDensity = theme::CurrentDensity();
    const std::filesystem::path directory(outputDirectory);
    std::filesystem::create_directories(directory);
    App app;
    theme::SetDensity(theme::Density::Compact);
    ImGuiIO& io = ImGui::GetIO();
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID(); io.ClearInputKeys(); io.ClearInputMouse();
    const DbgSnapshot paused = authoredShellPause();
    for (const auto palette : {theme::ThemeId::Axiom, theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        for (const auto state : {DbgState::Paused, DbgState::Detached, DbgState::Running}) {
            DbgSnapshot observation = state == DbgState::Detached ? DbgSnapshot{} : paused;
            observation.state = state;
            if (state == DbgState::Running) observation.lastEvent = "Authored process running";
            for (const ImVec2 size : {ImVec2(1920, 400), ImVec2(1440, 400), ImVec2(820, 400)}) {
                for (int settle = 0; settle < 4; ++settle) {
                    io.DisplaySize = size; ImGui::NewFrame();
                    AxiomShellTestAccess::shell(app, observation);
                    ImGui::GetBackgroundDrawList()->AddText(ImVec2(12, size.y - 65),
                        ImGui::GetColorU32(theme::col::muted()),
                        "Authored UI snapshot: session state and native thread IDs. No target is attached or executed.");
                    ImGui::Render();
                }
                std::string error;
                const std::string prefix = palette == theme::ThemeId::Axiom ? "shell-reference-"
                    : std::string("shell-reference-") + theme::ThemeName(palette) + "-";
                const std::string stateName = state == DbgState::Paused ? "paused"
                    : state == DbgState::Running ? "running" : "detached";
                const std::string filename = prefix + stateName + "-" + std::to_string(static_cast<int>(size.x)) + ".bmp";
                const bool captured = ds::test::captureUiFrame(directory / filename, &error);
                if (!captured) std::printf("Capture %s: %s\n", filename.c_str(), error.c_str());
                CHECK(captured);
            }
        }
    }
    CHECK(AxiomShellTestAccess::context(app).debug.snapshot().state == DbgState::Detached);
    theme::SetDensity(priorDensity); theme::ApplyTheme(priorTheme);
}
