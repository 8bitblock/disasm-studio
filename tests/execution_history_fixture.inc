// Real production history presentation with synthetic, immutable snapshots.
// No process attachment or mutable debugger seam is involved in inspection.
static void checkExecutionHistoryView() {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();

    ui::ExecutionHistoryView view;
    ExecutionHistorySnapshot history;
    DbgSnapshot live;
    std::string visibleText;
    auto paint = [&](ImVec2 size = ImVec2(1280, 900), bool log = true) {
        frame([&] {
            if (log) ImGui::LogToBuffer();
            view.render(history, live);
            if (log) {
                visibleText = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
            }
        }, "Execution history QA", size);
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    auto activate = [&](const char* label) {
        auto* window = ImGui::FindWindowByName("Execution History");
        CHECK(window != nullptr);
        if (!window) return;
        ImGui::FocusWindow(window);
        ImGui::ActivateItemByID(window->GetID(label));
        paint();
    };

    view.open = true;
    paint(); paint();
    CHECK(!view.canStepBack(history));
    CHECK(visibleText.find("No recorded path") != std::string::npos);

    history.target = {81, 9}; history.tid = 82;
    history.generation = 1; history.revision = 1;
    history.status = "Breakpoint reached. Recording stopped.";
    for (size_t i = 0; i < 4; ++i) {
        ExecutionHistoryEntry entry;
        entry.sequence = 100 + i;
        // A branch goes backward and a loop repeats the same address. The
        // history cursor must follow observations, never address arithmetic.
        entry.regs.rip = i == 0 ? 0x2000 : i == 3 ? 0x5000 : 0x1000;
        entry.regs.rax = 0x123456789ABC0000ull + i;
        entry.regs.rsp = 0x8000 + i;
        if (i < 2) { entry.bytes[0] = 0x90; entry.byteCount = 1; }
        if (i == 2) { entry.bytes[0] = 0x0f; entry.byteCount = 1; }
        history.entries.push_back(entry);
    }
    live.state = DbgState::Paused; live.pid = 81; live.sessionGeneration = 9;
    live.tid = 82; live.regs.rip = 0x5000;
    live.regs.rax = 0xFEEDFACE;
    view.sync(history);
    CHECK(view.selectedIndex() == 3);
    CHECK(view.canStepBack(history));
    view.stepBack(history);
    CHECK(view.open && view.selectedIndex() == 2);
    paint(); paint();
    CHECK(visibleText.find("inspection only") != std::string::npos);
    CHECK(visibleText.find("Live TID 82") != std::string::npos);
    CHECK(visibleText.find("0000000000005000") != std::string::npos);
    CHECK(visibleText.find("undecodable / partial capture") != std::string::npos);
    CHECK(visibleText.find("instruction bytes unavailable") != std::string::npos);
    CHECK(visibleText.find("123456789ABC0002") != std::string::npos);
    CHECK(visibleText.find("past memory is not recorded") != std::string::npos);
    CHECK(visibleText.find("may not have executed") != std::string::npos);

    activate("Step Back"); CHECK(view.selectedIndex() == 1);
    activate("Step Back"); CHECK(view.selectedIndex() == 0);
    CHECK(!view.canStepBack(history));
    view.stepBack(history); CHECK(view.selectedIndex() == 0);
    activate("Forward"); CHECK(view.selectedIndex() == 1);
    activate("Latest"); CHECK(view.selectedIndex() == 3);

    // Live publication follows the tail until the user starts browsing. A
    // repeated RIP does not erase chronological order or the selected state.
    auto appended = history.entries.back(); appended.sequence = 104;
    history.entries.push_back(appended); ++history.revision;
    view.sync(history); CHECK(view.selectedIndex() == 4);
    view.stepBack(history); CHECK(view.selectedIndex() == 3);
    appended.sequence = 105; history.entries.push_back(appended); ++history.revision;
    view.sync(history); CHECK(view.selectedIndex() == 3);
    CHECK(live.regs.rip == 0x5000 && live.regs.rax == 0xFEEDFACE);
    CHECK(history.entries[3].regs.rax == 0x123456789ABC0003ull);

    // New recordings, threads and PID-reused sessions all retire old cursors.
    ++history.generation; ++history.revision;
    view.sync(history); CHECK(view.selectedIndex() == 5);
    view.stepBack(history); ++history.tid; ++history.revision;
    view.sync(history); CHECK(view.selectedIndex() == 5);
    view.stepBack(history); ++history.target.sessionGeneration; ++history.revision;
    view.sync(history); CHECK(view.selectedIndex() == 5);
    paint();
    CHECK(visibleText.find("another session") != std::string::npos);

    // Mode comes only from the history owner, even if the current live target
    // uses another architecture. 0x40 is INC EAX in x86, not a complete x64 op.
    history.is32 = true; ++history.generation; ++history.revision;
    history.entries.resize(1);
    history.entries[0].bytes[0] = 0x40;
    history.entries[0].byteCount = 1;
    history.entries[0].regs.rax = 0xFFFFFFFF89ABCDEFull;
    live.is32 = false;
    paint(); paint();
    CHECK(visibleText.find("inc eax") != std::string::npos);
    CHECK(visibleText.find("89ABCDEF") != std::string::npos);
    CHECK(visibleText.find("FFFFFFFF89ABCDEF") == std::string::npos);
    CHECK(visibleText.find("EFLAGS") != std::string::npos);
    CHECK(!view.canStepBack(history));

    // A full buffer renders a clipped code table, keeping draw work bounded.
    history.is32 = false; ++history.generation; ++history.revision;
    history.entries.resize(Debugger::kExecutionHistoryMaxEntries);
    for (size_t i = 0; i < history.entries.size(); ++i) {
        history.entries[i].sequence = i + 1;
        history.entries[i].regs.rip = 0x1000 + i;
        history.entries[i].bytes[0] = 0x90;
        history.entries[i].byteCount = 1;
    }
    paint(ImVec2(1280, 900), false); paint(ImVec2(1280, 900), false);
    CHECK(view.selectedIndex() == history.entries.size() - 1);
    CHECK(ImGui::GetDrawData()->TotalVtxCount < 50000);

    const auto priorTheme = theme::CurrentTheme();
    for (const auto palette : {theme::ThemeId::Axiom, theme::ThemeId::Paper}) {
        theme::ApplyTheme(palette);
        for (const ImVec2 size : {ImVec2(640, 480), ImVec2(440, 360)}) {
            paint(size, false); paint(size, false);
            const auto* window = ImGui::FindWindowByName("Execution History");
            CHECK(window != nullptr);
            if (window) {
                CHECK(window->Size.x <= size.x);
                CHECK(window->Size.y <= size.y);
                CHECK(window->Pos.x >= 0 && window->Pos.y >= 0);
                CHECK(window->Pos.x + window->Size.x <= size.x + 1);
                CHECK(window->Pos.y + window->Size.y <= size.y + 1);
                if (size.y < 400) CHECK(window->ScrollMax.y > 0); // fields remain reachable
            }
            CHECK(ImGui::GetDrawData()->TotalVtxCount < 50000);
        }
    }
    theme::ApplyTheme(priorTheme);
    ++history.generation; ++history.revision; history.entries.clear();
    view.sync(history); CHECK(!view.canStepBack(history));
    view.open = false;
    paint();
}
