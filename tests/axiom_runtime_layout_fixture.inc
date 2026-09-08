// Production Prism composition: tall flames must not push report tables out of
// a short viewport. Memory's existing fixture exercises real readable holes.
#include "ui_capture.h"

static void axiomRuntimeFonts(float scale) {
    ui::LoadFonts(scale);
    unsigned char* pixels = nullptr;
    int width = 0, height = 0;
    ImGui::GetIO().Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    CHECK(pixels && width > 0 && height > 0);
}

static PrismReport axiomRuntimeReport() {
    PrismReport report;
    report.totalSamples = 40;
    report.headline = "Authored observations";
    report.verdict = "A retained report with deep stacks and long symbols.";
    report.states.push_back({ThreadState::Waiting, 30, 75.0f});
    report.states.push_back({ThreadState::Running, 10, 25.0f});
    report.functions.push_back({"fixture!process_frame", 0x1000, 40, 40, 100, 100});
    report.threads.push_back({7, 40, 100, ThreadState::Waiting, 75, "fixture!process_frame"});
    report.modules.push_back({"fixture", 40, 100});
    report.hotPaths.push_back({{"fixture!process_frame", std::string(180, 'x')}, 40, 100});
    report.flame.push_back({});
    for (uint16_t depth = 1; depth <= 40; ++depth) {
        PrismFlameNode node;
        node.depth = depth;
        node.symbol = "fixture!stack_frame_" + std::to_string(depth);
        node.address = 0x1000 + depth;
        node.samples = 40;
        report.flame.push_back(node);
    }
    report.timeline.resize(16);
    for (size_t i = 0; i < report.timeline.size(); ++i) {
        report.timeline[i].startMs = i * 100;
        report.timeline[i].samples = 4;
        report.timeline[i].dominant = i % 2 ? ThreadState::Waiting : ThreadState::Running;
    }
    return report;
}

static ImGuiTable* axiomRuntimeActiveTable(const char* childName) {
    for (int index = 0; index < GImGui->Tables.GetMapSize(); ++index) {
        ImGuiTable* table = GImGui->Tables.TryGetMapData(index);
        if (table && table->LastFrameActive == ImGui::GetFrameCount() && table->InnerWindow &&
            std::strstr(table->InnerWindow->Name, childName)) return table;
    }
    return nullptr;
}

static void checkAxiomMemoryTableViewport() {
    ImGuiTable* table = axiomRuntimeActiveTable("/##memory_address_table_");
    CHECK(table && table->InnerWindow);
    if (!table || !table->InnerWindow) return;
    const float header = table->InstanceDataFirst.LastTopHeadersRowHeight;
    const float editableRow = ImGui::GetFrameHeight() + 2.0f * ImGui::GetStyle().CellPadding.y;
    const ImGuiWindow* window = table->InnerWindow;
    CHECK(header > 0.0f && window->ScrollbarX && window->ScrollbarSizes.y > 0.0f);
    // InnerClipRect excludes the allocated scrollbar. A complete frozen header
    // plus a real framed edit/checkbox row must fit above that scrollbar.
    CHECK(window->InnerClipRect.GetHeight() + 1.0f >= header + editableRow);
    CHECK(window->Size.y + 1.0f >= header + editableRow + window->ScrollbarSizes.y);
}

static void checkAxiomCompactMemoryLayouts() {
    AppContext ctx;
    MemoryToolsTab memory;
    alignas(16) std::array<uint32_t, 64> values{};
    values.fill(100);
    std::string error;
    const bool opened = memory.passive_.open(GetCurrentProcessId(), {false, true}, &error);
    CHECK(opened);
    if (!opened) return;
    memory.targetSource_ = MemoryToolsTab::TargetSource::Passive;
    const auto target = memory.currentTarget(ctx);
    CHECK(target.valid() && !target.canWrite);
    memory.handleTargetTransition(target);
    memory.navigateViewer(reinterpret_cast<uint64_t>(values.data()), true, 4);
    memory.viewAutoRefresh_ = false;
    for (size_t index = 0; index < 5; ++index) {
        MemoryToolsTab::TableRow row;
        row.id = index + 1;
        row.record.description = "Authored row " + std::to_string(index);
        row.record.address.absoluteAddress = reinterpret_cast<uint64_t>(&values[index]);
        row.record.type = MemoryValueType::UInt32;
        row.record.enabled = true;
        row.absoluteOwner = target;
        memory.table_.push_back(std::move(row));
    }
    theme::SetUiScale(1.5f);
    axiomRuntimeFonts(1.5f);
    for (const auto palette : {theme::ThemeId::Axiom, theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        memory.inspectorSelectRequest_ = 1;
        for (int frame = 0; frame < 4; ++frame)
            featureFrame([&] { memory.render(ctx); }, ImVec2(720, 780));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
        checkAxiomMemoryTableViewport();
        ImGuiTable* regions = axiomRuntimeActiveTable("/##memory_regions_");
        CHECK(regions && regions->InnerWindow);
        if (regions && regions->InnerWindow) {
            CHECK((regions->Flags & ImGuiTableFlags_ScrollX) != 0);
            CHECK(regions->InnerWindow->ScrollMax.x > 0.0f);
            CHECK(regions->Columns[0].WidthGiven >= 135.0f * theme::UiScale());
            CHECK(regions->Columns[1].WidthGiven >= 135.0f * theme::UiScale());
        }
    }
    memory.passive_.close();
}

static void checkAxiomRuntimeLayouts() {
    AppContext ctx;
    PrismTab prism;
    const PrismReport report = axiomRuntimeReport();
    auto activeWindow = [](const char* fragment) -> ImGuiWindow* {
        for (ImGuiWindow* window : GImGui->Windows)
            if (window->LastFrameActive == ImGui::GetFrameCount() &&
                std::strstr(window->Name, fragment)) return window;
        return nullptr;
    };
    const auto priorTheme = theme::CurrentTheme();
    const float priorScale = theme::UiScale();
    ImGuiID legacyIds[3]{};
    featureFrame([&] {
        ImGui::BeginChild("pr_funcs", ImVec2(300, 300));
        legacyIds[0] = ImGui::GetID("pr_ftbl");
        ImGui::EndChild();
        ImGui::BeginChild("pr_mid", ImVec2(300, 300));
        legacyIds[1] = ImGui::GetID("pr_thr");
        legacyIds[2] = ImGui::GetID("pr_mod");
        ImGui::EndChild();
    });
    for (float scale : {0.75f, 0.9f, 1.5f, 2.0f}) {
        theme::SetUiScale(scale);
        axiomRuntimeFonts(scale);
        for (const auto palette : {theme::ThemeId::Axiom, theme::ThemeId::Midnight, theme::ThemeId::Light}) {
            theme::ApplyTheme(palette);
            const float chartRatio = prism.chartHeightRatio_;
            const float firstRatio = prism.firstPaneSplit_, secondRatio = prism.secondPaneSplit_;
            for (int view = 0; view < 3; ++view) {
                prism.compactWorkspaceView_ = view;
                for (int frame = 0; frame < 3; ++frame)
                    featureFrame([&] { prism.renderReportWorkspace(ctx, report, {}, 0, false); },
                                 ImVec2(720 * scale, 390 * scale));
                CHECK(GImGui->ErrorCountCurrentFrame == 0);
                ImGuiWindow* root = activeWindow("Feature UI integration");
                CHECK(root && root->ScrollMax.y <= 1.0f && root->ScrollMax.x <= 1.0f);
                CHECK((activeWindow("/pr_flame_") != nullptr) == (view == 0));
                CHECK((activeWindow("/pr_funcs_") != nullptr) == (view == 1));
                if (view == 0) {
                    ImGuiWindow* flame = activeWindow("/pr_flame_");
                    CHECK(flame && flame->ScrollMax.y > 0);
                }
            }
            prism.compactWorkspaceView_ = 1;
            for (int pane = 0; pane < 3; ++pane) {
                prism.compactReportView_ = pane;
                for (int frame = 0; frame < 3; ++frame)
                    featureFrame([&] { prism.renderReportWorkspace(ctx, report, {}, 0, false); },
                                 ImVec2(720 * scale, 390 * scale));
                const char* panes[] = {"/pr_funcs_", "/pr_mid_", "/pr_paths_"};
                for (int expected = 0; expected < 3; ++expected)
                    CHECK((activeWindow(panes[expected]) != nullptr) == (pane == expected));
                for (int table = 0; table < 3; ++table)
                    CHECK(prism.reportTableIds_[table] == legacyIds[table]);
                CHECK(GImGui->ErrorCountCurrentFrame == 0);
            }
            prism.compactReportView_ = 0;
            CHECK(prism.chartHeightRatio_ == chartRatio);
            CHECK(prism.firstPaneSplit_ == firstRatio && prism.secondPaneSplit_ == secondRatio);
            for (int frame = 0; frame < 3; ++frame)
                featureFrame([&] { prism.renderReportWorkspace(ctx, report, {}, 0, false); },
                             ImVec2(1440 * scale, 900 * scale));
            CHECK(activeWindow("##prism_charts") && activeWindow("##prism_reports"));
            CHECK(activeWindow("/pr_funcs_") && activeWindow("/pr_mid_") && activeWindow("/pr_paths_"));
            ImGuiWindow* charts = activeWindow("##prism_charts");
            ImGuiWindow* reports = activeWindow("##prism_reports");
            if (charts && reports) {
                CHECK(reports->Pos.y >= charts->Pos.y + charts->Size.y);
                CHECK(reports->Pos.y + reports->Size.y <= 900 * scale + 1);
            }
            CHECK(GImGui->ErrorCountCurrentFrame == 0);
            for (int table = 0; table < 3; ++table)
                CHECK(prism.reportTableIds_[table] == legacyIds[table]);
            prism.chartView_ = 1;
            for (int frame = 0; frame < 3; ++frame)
                featureFrame([&] { prism.renderReportWorkspace(ctx, report, {}, 0, false); },
                             ImVec2(1440 * scale, 900 * scale));
            CHECK(activeWindow("##prism_charts") && activeWindow("##prism_reports"));
            CHECK(!activeWindow("/pr_flame_"));
            CHECK(activeWindow("/pr_funcs_") && activeWindow("/pr_mid_") && activeWindow("/pr_paths_"));
            CHECK(GImGui->ErrorCountCurrentFrame == 0);
            prism.chartView_ = 0;
        }
    }
    checkAxiomCompactMemoryLayouts();
    theme::SetUiScale(priorScale);
    theme::ApplyTheme(priorTheme);
    axiomRuntimeFonts(priorScale);
}

// Authored data rendered by production objects at fixed physical viewport
// sizes. Only this fixture process is opened, with a read-only passive handle.
static void captureAxiomRuntimePages(const std::string& path,
                                     const std::filesystem::path& outputDirectory) {
    (void)path;
    const auto priorTheme = theme::CurrentTheme();
    const float priorScale = theme::UiScale();
    AppContext ctx;
    PrismTab prism;
    PrismReport report = axiomRuntimeReport();
    report.quality.collector = PrismCollectorKind::SuspendWalk;
    report.quality.degraded = true;
    report.quality.sampledEvents = 40;
    report.quality.samplesWithStacks = 30;
    report.quality.lostEvents = 2;
    report.quality.lostBuffers = 1;
    report.quality.stackCoveragePct = 75.0f;
    report.quality.summary = "Authored visual fixture: 40 observations, 75% stack coverage; no collector ran.";
    report.quality.fallbackReason = "Authored fallback fixture: ETW was unavailable.";
    report.quality.warning = "Authored quality fixture: 2 lost events, 1 lost buffer; partial coverage.";
    // The constructor starts only report aggregation. Join that worker before
    // publishing an immutable authored report; never start a collector.
    prism.sampler_.reportStop_.store(true, std::memory_order_release);
    prism.sampler_.reportCv_.notify_all();
    if (prism.sampler_.reportThread_.joinable()) prism.sampler_.reportThread_.join();
    {
        std::lock_guard lock(prism.sampler_.mtx_);
        prism.sampler_.samples_.resize(40);
        prism.sampler_.quality_ = report.quality;
        prism.sampler_.report_ = std::make_shared<const PrismReport>(report);
        prism.sampler_.pid_ = 0xFFFFFFFEu; // synthetic; deliberately has no debugger owner
        prism.sampler_.generation_.store(1, std::memory_order_release);
        prism.sampler_.reportGeneration_.store(1, std::memory_order_release);
    }
    std::snprintf(prism.pidBuf_, sizeof(prism.pidBuf_), "%u", prism.sampler_.pid());
    MemoryToolsTab memory;
    alignas(16) std::array<uint32_t, 128> values{};
    for (size_t i = 0; i < values.size(); ++i) values[i] = static_cast<uint32_t>(100 + i);
    std::string error;
    const bool opened = memory.passive_.open(GetCurrentProcessId(), {false, true}, &error);
    CHECK(opened);
    if (!opened) {
        std::printf("Memory capture target failed: %s\n", error.c_str());
        return;
    }
    memory.targetSource_ = MemoryToolsTab::TargetSource::Passive;
    auto target = memory.currentTarget(ctx);
    CHECK(target.valid() && !target.canWrite);
    memory.handleTargetTransition(target);
    memory.viewAutoRefresh_ = false;
    memory.navigateViewer(reinterpret_cast<uint64_t>(values.data()), true, 4);
    std::snprintf(memory.scanValue_, sizeof(memory.scanValue_), "100");
    std::snprintf(memory.scanStart_, sizeof(memory.scanStart_), "%llX",
                  reinterpret_cast<unsigned long long>(values.data()));
    std::snprintf(memory.scanEnd_, sizeof(memory.scanEnd_), "%llX",
                  reinterpret_cast<unsigned long long>(values.data()) + sizeof(values) - 1);
    memory.scanStatus_ = "Authored local buffer. Press First scan to begin; no scan has run.";
    for (size_t i = 0; i < 5; ++i) {
        MemoryToolsTab::TableRow row;
        row.id = i + 1;
        row.record.description = "Fixture value " + std::to_string(i);
        row.record.group = "Authored local buffer";
        row.record.type = MemoryValueType::UInt32;
        row.record.address.absoluteAddress = reinterpret_cast<uint64_t>(&values[i]);
        row.record.enabled = true;
        row.absoluteOwner = target;
        memory.table_.push_back(std::move(row));
    }
    const auto capture = [&](const std::string& name, const std::function<void()>& body, ImVec2 size) {
        ImGui::ClosePopupsOverWindow(nullptr, false);
        ImGui::ClearActiveID();
        ImGui::GetIO().ClearInputKeys();
        ImGui::GetIO().ClearInputMouse();
        ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
        for (int frame = 0; frame < 3; ++frame) featureFrame(body, size);
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
        if (name.starts_with("memory-") && size.x == 720 && theme::UiScale() == 1.5f)
            checkAxiomMemoryTableViewport();
        std::string captureError;
        const auto destination = outputDirectory / (name + ".bmp");
        const bool saved = ds::test::captureUiFrame(destination, &captureError);
        CHECK(saved);
        std::printf("UI capture %s: %s\n", name.c_str(), saved ? destination.string().c_str() : captureError.c_str());
    };
    for (float scale : {0.9f, 1.5f}) {
        theme::SetUiScale(scale);
        theme::ApplyTheme(theme::ThemeId::Axiom);
        axiomRuntimeFonts(scale);
        const std::string zoom = scale < 1 ? "-90" : "-150";
        for (const ImVec2 size : {ImVec2(1440, 900), ImVec2(720, 780)}) {
            const std::string suffix = zoom + (size.x > 1000 ? "-wide" : "-compact");
            for (int view = 0; view < 3; ++view) {
                prism.compactWorkspaceView_ = view;
                prism.chartView_ = view == 2 ? 1 : 0;
                const char* names[] = {"prism-charts", "prism-report", "prism-summary"};
                capture(names[view] + suffix, [&] {
                    ImGui::LogToBuffer();
                    prism.render(ctx);
                    const std::string text = GImGui->LogBuffer.c_str();
                    ImGui::LogFinish();
                    CHECK(text.find("Process activity and sampled call paths") != std::string::npos);
                    CHECK(text.find("Start") != std::string::npos);
                    CHECK(text.find("Authored visual fixture: 40 observations") != std::string::npos);
                    CHECK(text.find("Authored fallback fixture") != std::string::npos);
                    CHECK(text.find("2 lost events, 1 lost buffer") != std::string::npos);
                    CHECK(!prism.sampler_.running() && !ctx.hasGotoRequest);
                }, size);
            }
            memory.compactUpperView_ = 0;
            memory.inspectorSelectRequest_ = -1;
            capture("memory-scanner" + suffix, [&] {
                // After a width transition the first frame restores inspector
                // state; choose Scanner again on the settled capture frames.
                memory.compactUpperView_ = 0;
                memory.inspectorSelectRequest_ = -1;
                memory.render(ctx);
            }, size);
            memory.compactUpperView_ = 1;
            memory.inspectorSelectRequest_ = 0;
            capture("memory-inspector" + suffix, [&] { memory.render(ctx); }, size);
            memory.inspectorSelectRequest_ = 1;
            capture("memory-regions" + suffix, [&] { memory.render(ctx); }, size);
        }
    }
    memory.passive_.close();
    theme::SetUiScale(priorScale);
    theme::ApplyTheme(priorTheme);
    axiomRuntimeFonts(priorScale);
}
