// Production Call Stack presentation with authored snapshots and a detached
// debugger. Actions must reject these snapshots; no target or user clipboard is
// touched. Optional capture uses the production DX11 renderer offscreen.
#include "ui_capture.h"

static void checkBacktraceWorkbench(const std::string& path) {
    Fixture f(path, false);
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    ImGui::GetIO().AddMousePosEvent(-100, -100);

    DbgSnapshot paused;
    paused.state = DbgState::Paused;
    paused.pid = 0xfffffff0; paused.sessionGeneration = 701;
    paused.activeTid = 41; paused.tid = 99;
    paused.regs.rip = 0x140001130;
    paused.regs.rsp = 0x28f080; paused.regs.rbp = 0x28f100;
    paused.stackRevision = 18; paused.stackTid = paused.activeTid;
    paused.stackRip = paused.regs.rip; paused.stackRsp = paused.regs.rsp;
    paused.stackRbp = paused.regs.rbp;
    DbgModule module;
    module.name = "authored-ui-fixture.exe";
    module.base = 0x140000000; module.size = 0x10000; module.loadGeneration = 7;
    paused.modules = {module};
    paused.frames = {
        {paused.regs.rip, paused.regs.rbp, paused.regs.rsp, "parse_reply"},
        {0x140001285, 0x28f180, 0x28f120, "read_settings"},
        {0x140002105, 0x28f200, 0x28f1a0, "initialize_session"},
        {0x140003180, 0x28f290, 0x28f220, "main"},
    };
    std::string visibleText;
    ImVec2 size(920, 360);
    const char* title = "Backtrace QA - authored snapshot / detached debugger";
    auto paint = [&] {
        f.tab->frameSnap_ = &paused;
        frame([&] {
            ImGui::LogToBuffer();
            f.tab->renderCallStack(f.ctx);
            visibleText = ImGui::GetCurrentContext()->LogBuffer.c_str();
            ImGui::LogFinish();
        }, title, size);
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    paint(); paint();
    CHECK(f.tab->callStackReal_);
    CHECK(f.tab->callStack_.size() == 4);
    CHECK(f.tab->callStack_[0].pc == paused.regs.rip);
    CHECK(f.tab->callStack_[1].pc == 0x140001285);
    CHECK(f.tab->callStack_[1].module == "authored-ui-fixture.exe+0x1284");
    CHECK(visibleText.find("Backtrace / TID 41 / unwound callers") != std::string::npos);
    CHECK(visibleText.find("parse_reply") != std::string::npos);
    CHECK(visibleText.find("read_settings") != std::string::npos);
    CHECK(visibleText.find("Current") != std::string::npos);
    CHECK(visibleText.find("Caller") != std::string::npos);
    CHECK(visibleText.find("Possible CALL") != std::string::npos);

    const auto copied = f.tab->copyBacktrace(paused);
    CHECK(copied.find("PID 4294967280 | session 701 | TID 41 | x64") != std::string::npos);
    CHECK(copied.find("#0  current  0x140001130") != std::string::npos);
    CHECK(copied.find("#1  return continuation  0x140001285") != std::string::npos);
    CHECK(copied.find("read_settings") != std::string::npos);
    CHECK(copied.find("not a recording of earlier execution") != std::string::npos);

    // A retained frame, button activation and clipboard click must all refuse
    // an unrelated real debugger, even when the authored view remains paused.
    const int originalView = f.tab->mainView_;
    const uint64_t originalCursor = f.tab->cursorVA_;
    CHECK(!f.tab->navigateCallFrame(f.ctx, 1));
    CHECK(f.tab->mainView_ == originalView && f.tab->cursorVA_ == originalCursor);
    ImGuiWindow* window = ImGui::FindWindowByName(title);
    CHECK(window != nullptr);
    if (window) {
        ImGui::FocusWindow(window);
        ImGui::ActivateItemByID(window->GetID("Caller"));
        paint();
        CHECK(f.tab->mainView_ == originalView && f.tab->cursorVA_ == originalCursor);
        const std::string clipboard = ImGui::GetClipboardText();
        ImGui::ActivateItemByID(window->GetID("Copy backtrace"));
        paint();
        CHECK(std::string(ImGui::GetClipboardText()) == clipboard);
        CHECK(f.tab->callStackStatus_.find("Copy retired") != std::string::npos);
    }

    // Same-size stacks with identical PC/SP but a new revision cannot reuse an
    // old caller. A displayed-thread change cannot use event-thread frames.
    ++paused.stackRevision;
    paused.frames[1].pc = 0x1400012a5;
    paused.frames[1].name = "read_configuration";
    paint();
    CHECK(f.tab->callStack_[1].pc == 0x1400012a5);
    CHECK(f.tab->callStack_[1].name == "read_configuration");
    const auto beforeThread = paused;
    ++paused.activeTid;
    paint();
    CHECK(!f.tab->callStackReal_ && f.tab->callStack_.size() == 1);
    CHECK(visibleText.find("current frame only") != std::string::npos);
    CHECK(f.tab->copyBacktrace(beforeThread).empty());
    paused = beforeThread;
    ++paused.modules[0].loadGeneration;
    paint();
    CHECK(f.tab->callStackStop_.modules[0].generation == paused.modules[0].loadGeneration);

    // Copy is honest about an explicitly inferred stack value. These candidates
    // cannot enable Caller/Younger ordering in the production presentation.
    paused.frames.resize(1);
    ++paused.stackRevision;
    paint();
    CHECK(!f.tab->callStackReal_ && f.tab->callStack_.size() == 1);
    auto candidate = f.tab->callStack_.front();
    candidate.pc = 0x140001285; candidate.candidate = true; candidate.name = "possible_old_return";
    f.tab->callStack_.push_back(candidate);
    f.tab->callStackScanRequested_ = true;
    const auto inferred = f.tab->copyBacktrace(paused);
    CHECK(inferred.find("stack candidate") != std::string::npos);
    CHECK(inferred.find("not an unwound caller chain") != std::string::npos);
    CHECK(!f.tab->callStackReal_);
    paused = beforeThread;
    ++paused.stackRevision;
    paint();

    char captureDirectory[MAX_PATH]{};
    const bool capture = GetEnvironmentVariableA("DS_BACKTRACE_CAPTURE_DIR", captureDirectory, MAX_PATH) != 0;
    const auto priorTheme = theme::CurrentTheme();
    for (auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        for (bool compact : {false, true}) {
            size = compact ? ImVec2(620, 290) : ImVec2(1100, 390);
            f.tab->callStackStatus_.clear();
            paint(); paint();
            CHECK(visibleText.find("read_configuration") != std::string::npos);
            if (capture) {
                std::filesystem::create_directories(captureDirectory);
                const std::string label = std::string("backtrace-") +
                    (palette == theme::ThemeId::Light ? "light" : "midnight") +
                    (compact ? "-compact.bmp" : "-desktop.bmp");
                std::string error;
                const bool ok = ds::test::captureUiFrame(std::filesystem::path(captureDirectory) / label, &error);
                if (!ok) std::printf("Backtrace capture: %s\n", error.c_str());
                CHECK(ok);
            }
        }
    }
    theme::ApplyTheme(priorTheme);
    paused.state = DbgState::Running;
    paint();
    CHECK(f.tab->callStack_.empty());
    CHECK(visibleText.find("Backtrace is unavailable") != std::string::npos);
    paused = {};
    paint();
    CHECK(f.tab->callStack_.empty());
    CHECK(visibleText.find("No backtrace") != std::string::npos);

    f.tab->mainView_ = 7; // keep the full-shell handoff decoder-light
    f.tab->lowerDockCollapsed_ = true;
    f.tab->lowerAdvancedMode_ = true;
    f.ctx.requestedBacktrace = true;
    for (int i = 0; i < 3; ++i) frame([&] { f.tab->render(f.ctx); }, "Backtrace drawer handoff");
    CHECK(!f.ctx.requestedBacktrace);
    CHECK(!f.tab->lowerDockCollapsed_ && !f.tab->lowerAdvancedMode_);
    CHECK(!f.tab->focusCallStackTab_);
    CHECK(f.tab->mainView_ == 7);
    CHECK(!f.ctx.debug.snapshot().attached());
    CHECK(!f.ctx.debug.lifecycleSnapshot().busy);
    f.tab->frameSnap_ = &f.detached;
}
