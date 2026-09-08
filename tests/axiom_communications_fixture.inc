// Populated runtime presentation checks. Publications are authored in-process;
// no debug attachment, JVM connection, network probe or file log is started.
#include "Core/GameMakerArchive.h"
#include "ui_capture.h"

static ImGuiWindow* axiomCommunicationsWindow(const char* fragment) {
    for (ImGuiWindow* window : GImGui->Windows)
        if (window->LastFrameActive == ImGui::GetFrameCount() &&
            std::strstr(window->Name, fragment)) return window;
    return nullptr;
}

static std::string axiomCommunicationsText(const std::function<void()>& render, ImVec2 size) {
    for (int i = 0; i < 3; ++i) featureFrame(render, size);
    std::string text;
    featureFrame([&] {
        ImGui::LogToBuffer();
        render();
        text = GImGui->LogBuffer.c_str();
        ImGui::LogFinish();
    }, size);
    CHECK(GImGui->ErrorCountCurrentFrame == 0);
    return text;
}

static void checkAxiomCommunicationsUi() {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    const auto priorTheme = theme::CurrentTheme();
    const float scale = theme::UiScale();
    const ImVec2 narrow(520.0f * scale, 700.0f * scale);
    const ImVec2 wide(1280.0f * scale, 800.0f * scale);
    AppContext ctx;
    CommunicationsTab communications;
    communications.jdwpBrowseRatio_ = 0.29f;
    communications.jdwpSessionRatio_ = 0.31f;
    JdwpSnapshot java;
    java.state = JdwpState::Suspended;
    java.stopThread = 7;
    java.stopLoc = {1, 11, 22, 350};
    java.threads.push_back({7, "Fixture worker", JDWP_TS_RUNNING});
    java.frames.push_back({99, java.stopLoc, "Fixture.main bci=350"});
    java.breakpoints.push_back({123, java.stopLoc, "Fixture breakpoint", 2});
    java.events.push_back("Fixture Java pause event");
    java.classes = std::make_shared<const std::vector<JdwpClassRow>>(
        std::vector<JdwpClassRow>{{11, "fixture/Example", "Lfixture/Example;"}});
    communications.jdwpSelClass_ = communications.jdwpInsnsClass_ = 11;
    communications.jdwpInsnsMethod_ = 22;
    communications.jdwpInsnsLabel_ = "Fixture.main";
    communications.jdwpMethods_.push_back({22, "main", "()V", 0});
    for (uint64_t bci = 0; bci < 400; ++bci) {
        Instruction instruction;
        instruction.address = bci;
        instruction.mnemonic = "nop";
        if (bci == 350) instruction.comment = "Fixture stopped bytecode";
        communications.jdwpInsns_.push_back(std::move(instruction));
    }

    ConnectionsTab network;
    network.auto_ = false;
    network.observationEventsRatio_ = 0.56f;
    NetworkObservationEvent event;
    event.sequence = 1; event.pid = 42; event.sessionGeneration = 5; event.tid = 7;
    event.api = NetworkProbeApi::Recv; event.stage = NetworkObservationStage::Receive;
    event.resultValid = true; event.rawResult = 4; event.pointerWidthBits = 64;
    event.transferredValid = true; event.transferred = 4;
    event.payload = {'t', 'e', 's', 't'};
    event.endpoint = "127.0.0.1:9000";
    event.detail = "Fixture received payload";
    network.observation_.events.push_back(event);
    network.observationSelectedSequence_ = 1;
    network.observation_.coverage.requested = true;
    network.observation_.coverage.probesAvailable = 8;
    network.observation_.coverage.probesArmed = 4;
    network.observation_.coverage.eventsDropped = 7;
    network.observation_.coverage.pendingReturnsDropped = 2;
    network.observation_.coverage.limitations.push_back("Fixture custom TLS remains opaque");
    DbgSnapshot debug;
    debug.state = DbgState::Paused; debug.pid = 42; debug.sessionGeneration = 5; debug.activeTid = 7;

    for (const auto palette : {theme::ThemeId::Axiom, theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        // Wide Java prioritizes bytecode; compact views retain the same method,
        // class, stop and manual pane dimensions.
        for (int i = 0; i < 3; ++i)
            featureFrame([&] { communications.renderJdwpConsole(ctx, java); }, wide);
        auto* browser = axiomCommunicationsWindow("/jdwp_browse_");
        auto* bytecode = axiomCommunicationsWindow("/jdwp_bytecode_");
        CHECK(browser && bytecode && axiomCommunicationsWindow("/jdwp_session_"));
        if (browser && bytecode) CHECK(bytecode->Size.x > browser->Size.x * 1.8f);
        const float retainedWidth = communications.jdwpBrowseWidth_;
        const float retainedHeight = communications.jdwpSessionHeight_;
        for (int view = 0; view < 3; ++view) {
            communications.jdwpCompactView_ = view;
            const auto text = axiomCommunicationsText([&] { communications.renderJdwpConsole(ctx, java); }, narrow);
            CHECK(axiomCommunicationsWindow("/jdwp_compact_"));
            CHECK(!axiomCommunicationsWindow("/jdwp_browse_"));
            CHECK(communications.jdwpInsnsClass_ == 11 && communications.jdwpInsnsMethod_ == 22);
            if (view == 0) CHECK(text.find("fixture/Example") != std::string::npos);
            if (view == 2) CHECK(text.find("Fixture worker") != std::string::npos);
        }
        CHECK(communications.jdwpBrowseWidth_ == retainedWidth);
        CHECK(communications.jdwpSessionHeight_ == retainedHeight);
        for (const ImVec2 resized : {ImVec2(1560.0f * scale, 930.0f * scale), narrow, wide}) {
            for (int i = 0; i < 3; ++i)
                featureFrame([&] { communications.renderJdwpConsole(ctx, java); }, resized);
            CHECK(communications.jdwpBrowseRatio_ == 0.29f);
            CHECK(communications.jdwpSessionRatio_ == 0.31f);
        }
        // A fresh stop reveals bytecode even from Browse and includes the
        // stopped row when the clipper would otherwise skip it.
        communications.jdwpCompactView_ = 0;
        communications.jdwpScrollToStop_ = true;
        for (int i = 0; i < 3; ++i)
            featureFrame([&] { communications.renderJdwpConsole(ctx, java); }, narrow);
        CHECK(communications.jdwpCompactView_ == 1 && !communications.jdwpScrollToStop_);
        if (auto* code = axiomCommunicationsWindow("/jdwp_code_")) CHECK(code->Scroll.y > 0);
        else CHECK(false);
        const char* expected[] = {"Fixture worker", "Fixture.main bci=350", "Fixture breakpoint", "Fixture Java pause event"};
        communications.jdwpCompactView_ = 2;
        for (int sessionView = 0; sessionView < 4; ++sessionView) {
            communications.jdwpSessionView_ = sessionView;
            const auto text = axiomCommunicationsText([&] { communications.renderJdwpConsole(ctx, java); }, narrow);
            CHECK(text.find(expected[sessionView]) != std::string::npos);
        }
        communications.jdwpSessionView_ = 0;

        // Events/details are independent scroll regions. Reading details never
        // promotes an API's successful return into license acceptance.
        for (int i = 0; i < 3; ++i)
            featureFrame([&] { network.renderObservationWorkspace(ctx, debug, false, false, 0, 0); }, wide);
        CHECK(axiomCommunicationsWindow("/##observation_events_") &&
              axiomCommunicationsWindow("/##observation_details_"));
        const float retainedEventsWidth = network.observationEventsWidth_;
        for (int view = 0; view < 2; ++view) {
            network.observationCompactView_ = view;
            const auto text = axiomCommunicationsText([&] {
                network.renderObservationWorkspace(ctx, debug, false, false, 0, 0);
            }, narrow);
            CHECK((axiomCommunicationsWindow("/##observation_events_") != nullptr) == (view == 0));
            CHECK((axiomCommunicationsWindow("/##observation_details_") != nullptr) == (view == 1));
            if (view == 0) CHECK(text.find("Fixture received payload") != std::string::npos);
            else {
                CHECK(text.find("Expected API result:") != std::string::npos);
                CHECK(text.find("does not prove that the server accepted") != std::string::npos);
            }
        }
        CHECK(network.observationEventsWidth_ == retainedEventsWidth);
        CHECK(network.observationSelectedSequence_ == 1 && network.observation_.events.size() == 1);
        for (const ImVec2 resized : {ImVec2(1560.0f * scale, 930.0f * scale), narrow, wide}) {
            for (int i = 0; i < 3; ++i)
                featureFrame([&] { network.renderObservationWorkspace(ctx, debug, false, false, 0, 0); }, resized);
            CHECK(network.observationEventsRatio_ == 0.56f);
            // Contract prose must rewrap to the pane after a resize instead of
            // retaining an earlier horizontal width and clipping its evidence.
            if (auto* details = axiomCommunicationsWindow("/##observation_details_"))
                CHECK(details->ScrollMax.x <= 1.0f);
        }
        network.observationCompactView_ = 1;
        ++debug.sessionGeneration;
        const auto stale = axiomCommunicationsText([&] {
            network.renderObservationWorkspace(ctx, debug, false, false, 0, 0);
        }, narrow);
        CHECK(stale.find("Expected API result:") == std::string::npos);
        CHECK(stale.find("Select an observed call") != std::string::npos);
        --debug.sessionGeneration;
        const auto coverage = axiomCommunicationsText([&] { network.renderObservationCoverage(false); }, narrow);
        CHECK(coverage.find("7 event(s)") != std::string::npos);
        CHECK(coverage.find("2 return frames dropped") != std::string::npos);
        CHECK(coverage.find("1 coverage limitation(s)") != std::string::npos);

        // The full detached workspace still exposes the log footer in either
        // compact mode. All actions remain disabled without a debugger target.
        network.observationNextRefresh_ = 1.0e12;
        // The old table lived directly in the renderPayloadCapture parent.
        // Keep that exact ID and its resized column across the new nesting and
        // wide/compact presentation, rather than silently creating a new table.
        ImGuiID legacyTableId = 0;
        network.observationCompactView_ = 0;
        for (int frame = 0; frame < 3; ++frame)
            featureFrame([&] {
                legacyTableId = ImGui::GetID("server_watch_events");
                network.renderPayloadCapture(ctx);
            }, wide);
        auto* legacyTable = GImGui->Tables.GetByKey(legacyTableId);
        CHECK(legacyTable && legacyTable->LastFrameActive == ImGui::GetFrameCount());
        if (legacyTable) legacyTable->Columns[0].WidthRequest = 130.0f * scale;
        for (const auto size : {narrow, wide}) {
            for (int frame = 0; frame < 3; ++frame)
                featureFrame([&] { network.renderPayloadCapture(ctx); }, size);
            legacyTable = GImGui->Tables.GetByKey(legacyTableId);
            CHECK(legacyTable && legacyTable->LastFrameActive == ImGui::GetFrameCount());
            if (legacyTable) CHECK(std::abs(legacyTable->Columns[0].WidthRequest - 130.0f * scale) < 1.0f);
        }
        for (int view = 0; view < 2; ++view) {
            network.observationCompactView_ = view;
            const auto text = axiomCommunicationsText([&] { network.renderPayloadCapture(ctx); }, narrow);
            auto* footer = axiomCommunicationsWindow("/##observation_log_footer_");
            CHECK(footer && text.find("Start watch + file log") != std::string::npos);
            if (footer) CHECK(footer->Pos.y + footer->Size.y <= narrow.y + 1.0f);
        }
        CHECK(!ctx.debug.netTapEnabled() && !ctx.debug.netCaptureLogEnabled());

        GameMakerSessionSnapshot gml;
        gml.target = {42, 5}; gml.state = GameMakerSessionState::Running;
        gml.runnerName = "Fixture runner"; gml.status = "Fixture GML runtime verified";
        gml.capabilities.runtimeVerified = true;
        gml.instructionStopsVerified = true; gml.mappingRetained = true;
        gml.requestedBreakpoints = 3; gml.boundBreakpoints = 2;
        for (const auto size : {narrow, wide}) {
            const auto nativePause = axiomCommunicationsText([&] {
                communications.renderGameMakerSession(ctx, debug, gml);
            }, size);
            CHECK(nativePause.find("This is a native pause") != std::string::npos);
            CHECK(nativePause.find("3 requested / 2 bound") != std::string::npos);
            CHECK(nativePause.find("Packed operand-stack values") != std::string::npos);
            CHECK(nativePause.find("Use GML execution controls") != std::string::npos);
            gml.state = GameMakerSessionState::Disabling;
            gml.error = "Fixture helper draining warning";
            const auto disabling = axiomCommunicationsText([&] {
                communications.renderGameMakerSession(ctx, debug, gml);
            }, size);
            CHECK(disabling.find("Waiting for callback draining") != std::string::npos);
            CHECK(disabling.find(gml.error) != std::string::npos);
            gml.state = GameMakerSessionState::Running; gml.error.clear();
        }
        // A real GML stop shape exposes the location only while the captured
        // native thread agrees, and retains the inactive-archive navigation guard.
        auto archive = std::make_shared<GameMakerArchive>();
        GameMakerCode code; code.name = "Fixture GML stopped code";
        code.bytecodeOffset = 0x100; code.bytecodeLength = 32;
        archive->code.push_back(code);
        auto stop = std::make_shared<GmlHelperStop>();
        stop->identity = {42, 7, 5, 1, 1};
        stop->location.codeIndex = 0; stop->location.byteOffset = 4;
        gml.state = GameMakerSessionState::Paused; gml.archive = archive; gml.stop = stop;
        const auto gmlPause = axiomCommunicationsText([&] {
            communications.renderGameMakerSession(ctx, debug, gml);
        }, narrow);
        CHECK(gmlPause.find("Fixture GML stopped code") != std::string::npos);
        CHECK(gmlPause.find("Activate the connected archive document") != std::string::npos);
        ++debug.activeTid;
        const auto wrongThread = axiomCommunicationsText([&] {
            communications.renderGameMakerSession(ctx, debug, gml);
        }, narrow);
        CHECK(wrongThread.find("Fixture GML stopped code") == std::string::npos);
        CHECK(wrongThread.find("This is a native pause") != std::string::npos);
        --debug.activeTid;
        CHECK(!ctx.debug.snapshot().attached() && !ctx.jdwp.snapshot().attached());
    }
    // Actual production fonts at the requested physical compact viewport:
    // loss summaries and file-log actions must remain above the viewport edge.
    theme::SetUiScale(1.0f);
    theme::ApplyTheme(theme::ThemeId::Axiom);
    ui::LoadFonts(1.0f);
    unsigned char* pixels = nullptr; int atlasWidth = 0, atlasHeight = 0;
    ImGui::GetIO().Fonts->GetTexDataAsRGBA32(&pixels, &atlasWidth, &atlasHeight);
    for (int view = 0; view < 2; ++view) {
        network.observationCompactView_ = view;
        const auto text = axiomCommunicationsText([&] { network.renderPayloadCapture(ctx); }, ImVec2(820, 560));
        auto* footer = axiomCommunicationsWindow("/##observation_log_footer_");
        CHECK(footer && text.find("Start watch + file log") != std::string::npos);
        CHECK(text.find("7 event(s)") != std::string::npos);
        if (footer) CHECK(footer->Pos.y + footer->Size.y <= 561.0f);
    }
    CHECK(communications.jdwpBrowseRatio_ == 0.29f && communications.jdwpSessionRatio_ == 0.31f);
    CHECK(network.observationEventsRatio_ == 0.56f);
    theme::SetUiScale(scale);
    theme::ApplyTheme(priorTheme);
    ui::LoadFonts(scale);
    ImGui::GetIO().Fonts->GetTexDataAsRGBA32(&pixels, &atlasWidth, &atlasHeight);
}

// Call after the real UI fonts are loaded, at UiScale 1 for the 820-pixel
// compact captures. Every process, endpoint, instruction and runtime state
// below is authored fixture data; only the production presentation is rendered.
static void captureAxiomCommunicationsPages(const std::filesystem::path& captureDirectory) {
    const auto priorTheme = theme::CurrentTheme();
    theme::ApplyTheme(theme::ThemeId::Axiom);
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    AppContext ctx;
    CommunicationsTab communications;
    communications.enumerated_ = true;
    communications.selProc_ = 0;
    for (uint32_t i = 0; i < 15; ++i)
        communications.procs_.push_back({900042 + i, 0,
            "Authored target " + std::to_string(i + 1) + ".exe", i % 3 != 0, i % 4 != 3});
    communications.modsForPid_ = 900042;
    communications.mods_.push_back({"Authored target 1.exe", 0x140000000, 0x24000, "C:\\AuthoredFixture\\target.exe"});
    communications.mods_.push_back({"Authored runtime.dll", 0x180000000, 0x81000, "C:\\AuthoredFixture\\runtime.dll"});
    communications.connsForPid_ = communications.connsRequestedPid_ = 900042;
    communications.connAutoRefresh_ = false;
    communications.conns_.push_back({"127.0.0.1:49152", "127.0.0.1:9000", "TCP", "IPv4", "ESTABLISHED", false});
    communications.conns_.push_back({"[::1]:5353", "*", "UDP", "IPv6", "listen", true});

    ConnectionsTab history;
    history.auto_ = false;
    for (uint32_t i = 0; i < 20; ++i) {
        ConnectionsTab::ConnRecord row;
        row.proto = i % 3 ? "TCP" : "UDP6";
        row.proc = "Authored target " + std::to_string(i + 1) + ".exe";
        row.pid = 900042 + i; row.local = "127.0.0.1:" + std::to_string(49152 + i);
        row.remote = "127.0.0.1:9000"; row.state = i % 2 ? "ESTABLISHED" : "LISTEN";
        row.active = true; row.lastSeen = GetTickCount();
        history.log_.push_back(row);
    }

    JdwpSnapshot java;
    java.state = JdwpState::Suspended; java.vmName = "Authored JVM snapshot";
    java.stopThread = 7; java.stopLoc = {1, 11, 22, 18};
    java.threads = {{7, "Authored main thread", JDWP_TS_RUNNING}, {8, "Authored worker", JDWP_TS_WAIT}};
    java.frames = {{99, java.stopLoc, "AuthoredExample.decode bci=18"}, {100, {1, 11, 23, 4}, "AuthoredExample.main bci=4"}};
    java.breakpoints = {{1, java.stopLoc, "AuthoredExample.decode bci=18", 3}};
    java.events = {"Authored session connected", "Authored breakpoint reached at bci=18"};
    std::vector<JdwpClassRow> classes;
    for (uint64_t i = 0; i < 14; ++i)
        classes.push_back({11 + i, "authored/Example" + std::to_string(i + 1), "Lauthored/Example;"});
    java.classes = std::make_shared<const std::vector<JdwpClassRow>>(std::move(classes));
    communications.jdwpSelClass_ = communications.jdwpInsnsClass_ = 11;
    communications.jdwpInsnsMethod_ = 22; communications.jdwpInsnsLabel_ = "AuthoredExample.decode";
    communications.jdwpMethods_ = {{22, "decode", "([B)I", 0}, {23, "main", "([Ljava/lang/String;)V", 0},
                                   {24, "readHeader", "()I", 0}, {25, "close", "()V", 0}};
    const char* mnemonics[] = {"aload_0", "arraylength", "istore_1", "iload_1", "iconst_1", "isub", "ireturn"};
    for (uint64_t i = 0; i < 45; ++i) {
        Instruction instruction; instruction.address = i;
        instruction.mnemonic = mnemonics[i % 7];
        if (i == 18) instruction.comment = "Authored stopped instruction";
        communications.jdwpInsns_.push_back(std::move(instruction));
    }

    ConnectionsTab watch;
    watch.auto_ = false;
    watch.observationNextRefresh_ = 1.0e12;
    watch.observation_.coverage.requested = true;
    watch.observation_.coverage.probesAvailable = 28; watch.observation_.coverage.probesArmed = 21;
    watch.observation_.coverage.winsock = watch.observation_.coverage.winHttp = true;
    watch.observation_.coverage.payloads = true;
    watch.observation_.coverage.eventsDropped = 2;
    watch.observation_.coverage.pendingReturnsDropped = 1;
    watch.observation_.coverage.retainedPayloadBytes = 32;
    watch.observation_.coverage.limitations = {"Authored coverage example: custom TLS payloads remain opaque."};
    for (uint64_t i = 1; i <= 28; ++i) {
        NetworkObservationEvent event;
        event.sequence = i; event.pid = 900042; event.sessionGeneration = 5; event.tid = 7;
        event.api = NetworkProbeApi::Recv; event.stage = NetworkObservationStage::Receive;
        event.endpoint = "127.0.0.1:9000"; event.detail = "Authored receive event " + std::to_string(i);
        event.pointerWidthBits = 64; event.resultValid = true; event.rawResult = 4;
        event.transferredValid = true; event.transferred = 4; event.payload = {'D', 'E', 'M', 'O'};
        watch.observation_.events.push_back(event);
    }
    watch.observationSelectedSequence_ = 28;
    watch.capLogStatus_ = "Authored capture: file logging is stopped.";

    DbgSnapshot native;
    native.state = DbgState::Paused; native.pid = 900042; native.sessionGeneration = 5; native.activeTid = 7;
    GameMakerSessionSnapshot gml;
    gml.target = {900042, 5}; gml.state = GameMakerSessionState::Paused;
    gml.runnerName = "Authored verified runner";
    gml.status = "Authored GML session paused at an instruction boundary.";
    gml.capabilities.runtimeVerified = true; gml.instructionStopsVerified = true; gml.mappingRetained = true;
    gml.requestedBreakpoints = gml.boundBreakpoints = 3;
    auto archive = std::make_shared<GameMakerArchive>();
    GameMakerCode gmlCode; gmlCode.name = "AuthoredExample.update"; gmlCode.bytecodeOffset = 0x100;
    archive->code.push_back(gmlCode); gml.archive = archive;
    auto stop = std::make_shared<GmlHelperStop>();
    stop->identity = {900042, 7, 5, 1, 1}; stop->location.codeIndex = 0; stop->location.byteOffset = 16;
    gml.stop = stop;

    auto capture = [&](const char* name, ImVec2 size, const std::function<void()>& body) {
        for (int frame = 0; frame < 4; ++frame) featureFrame([&] {
            ImGui::SetScrollY(0);
            ImGui::TextDisabled("Authored UI fixture - no target is attached or executed");
            body();
        }, size);
        std::string error;
        const auto path = captureDirectory / (std::string(name) + (size.x > 1000 ? "-1440.bmp" : "-820.bmp"));
        const bool saved = ds::test::captureUiFrame(path, &error);
        if (!saved) std::printf("Capture failed: %s\n", error.c_str());
        CHECK(saved);
    };
    for (const ImVec2 size : {ImVec2(1440, 900), ImVec2(820, 560)}) {
        capture("communications-processes", size, [&] { communications.render(ctx); });
        capture("communications-process-connections", size, [&] { communications.renderConnections(ctx); });
        capture("communications-history", size, [&] { history.render(ctx); });
        const char* names[] = {"communications-jdwp-browse", "communications-jdwp-bytecode", "communications-jdwp-session"};
        for (int view = 0; view < 3; ++view) {
            communications.jdwpCompactView_ = view;
            communications.jdwpSessionView_ = view == 2 ? 1 : 0;
            if (view == 1) communications.jdwpScrollToStop_ = true;
            capture(names[view], size, [&] {
                ui::PanelHeader("Java / JDWP", "Authored suspended JVM publication");
                communications.renderJdwpConsole(ctx, java);
            });
        }
        communications.jdwpCompactView_ = 2;
        communications.jdwpSessionView_ = 2;
        capture("communications-jdwp-breakpoints", size, [&] {
            ui::PanelHeader("Java / JDWP", "Authored suspended JVM publication");
            communications.renderJdwpConsole(ctx, java);
        });
        for (int view = 0; view < 2; ++view) {
            watch.observationCompactView_ = view;
            capture(view ? "communications-watch-details" : "communications-watch-events", size,
                    [&] { watch.renderPayloadCapture(ctx); });
        }
        capture("communications-gml-verified", size, [&] { communications.renderGameMakerSession(ctx, native, gml); });
        GameMakerSessionSnapshot unverified;
        unverified.runnerName = "Authored unverified runner";
        unverified.state = GameMakerSessionState::Failed;
        unverified.status = "Authored runner verification could not complete.";
        unverified.error = "Authored failure: runner identity does not match the supported archive.";
        capture("communications-gml-unverified", size, [&] { communications.renderGameMakerSession(ctx, native, unverified); });
    }
    CHECK(!ctx.debug.snapshot().attached() && !ctx.jdwp.snapshot().attached());
    CHECK(!ctx.debug.netTapEnabled() && !ctx.debug.netCaptureLogEnabled());
    theme::ApplyTheme(priorTheme);
}
