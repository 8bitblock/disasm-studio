// Populated feature-tab regression against the actual application objects.
// Uses isolated APPDATA and authored raw bytes; no target process is started.
#include "App.h"
#include <fstream>
#include <functional>
#include <list>
#include <map>
#include <sstream>
#include <stdexcept>
#include "imgui.h"
#include "imgui_internal.h"
#include "Core/PrismSampler.h"
#define private public
#include "Tabs/CortexTab.h"
#include "Tabs/SigScannerTab.h"
#include "Tabs/BinaryTechTab.h"
#include "Tabs/BinaryDiffTab.h"
#include "Tabs/ProjectsTab.h"
#include "Tabs/MemoryToolsTab.h"
#include "Tabs/PrismTab.h"
#include "Tabs/CommunicationsTab.h"
#undef private
#include "Ui/Fonts.h"
#include "Ui/Theme.h"
#include "Ui/Widgets.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <bit>

using namespace ds;
static int failures = 0;
#define CHECK(value) do { if (!(value)) { std::printf("FAIL line %d: %s\n", __LINE__, #value); ++failures; } } while (0)

static void featureFrame(const std::function<void()>& body, ImVec2 size = ImVec2(1200, 800)) {
    ImGui::GetIO().DisplaySize = size;
    ImGui::NewFrame();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(size);
    ImGui::Begin("Feature UI integration", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings);
    body();
    ImGui::End();
    ImGui::Render();
}

static void featureLoadRaw(AppContext& ctx, const std::string& path) {
    CHECK(ctx.beginRawLoadPath(path, 0, Arch::X64, 0, {}, {}));
    bool loaded = false;
    for (int i = 0; i < 1000; ++i) {
        const auto result = ctx.pollBinaryLoad();
        if (result.completed) { loaded = result.success; break; }
        Sleep(2);
    }
    CHECK(loaded);
    CHECK(ctx.applyPendingDocumentCommand().success);
    ctx.staticAnalysis().cancelAndWaitIdle();
}

#include "cortex_ui_fixture.inc"
#include "sigscanner_ui_fixture.inc"
#include "tech_diff_ui_fixture.inc"

static void checkResponsiveFeatureTools() {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    AppContext ctx;
    PrismTab prism;
    PrismReport report;
    report.functions.push_back({"application!render_frame", 0x1000, 4, 4, 100.0f, 100.0f});
    report.threads.push_back({7, 4, 100.0f, ThreadState::Running, 100.0f, "application!render_frame"});
    report.modules.push_back({"application", 4, 100.0f});
    report.hotPaths.push_back({{"application!render_frame", std::string(140, 'x')}, 4, 100.0f});
    MemoryToolsTab memory;
    MemoryToolsTab::TargetToken target;
    const float scale = theme::UiScale();
    auto activeWindow = [](const char* fragment) -> ImGuiWindow* {
        for (ImGuiWindow* window : GImGui->Windows)
            if (window->LastFrameActive == ImGui::GetFrameCount() &&
                std::strstr(window->Name, fragment)) return window;
        return nullptr;
    };
    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        const float firstSplit = prism.firstPaneSplit_, secondSplit = prism.secondPaneSplit_;
        for (int pane = 0; pane < 3; ++pane) {
            prism.compactReportView_ = pane;
            for (int frame = 0; frame < 3; ++frame) {
                featureFrame([&] { prism.renderReportPanes(ctx, report, {}, 0, false); },
                             ImVec2(520.0f * scale, 700.0f * scale));
                CHECK(GImGui->ErrorCountCurrentFrame == 0);
            }
            const char* names[] = {"/pr_funcs_", "/pr_mid_", "/pr_paths_"};
            for (int i = 0; i < 3; ++i) {
                ImGuiWindow* window = activeWindow(names[i]);
                CHECK((window != nullptr) == (i == pane));
                if (window) {
                    CHECK(window->Size.x > 470.0f * scale);
                    if (i == 2) CHECK(window->ScrollMax.x > 0.0f);
                    else CHECK(window->ScrollMax.x <= 1.0f);
                }
            }
        }
        CHECK(prism.firstPaneSplit_ == firstSplit && prism.secondPaneSplit_ == secondSplit);
        for (int frame = 0; frame < 3; ++frame)
            featureFrame([&] { prism.renderReportPanes(ctx, report, {}, 0, false); },
                         ImVec2(1200.0f * scale, 700.0f * scale));
        CHECK(activeWindow("/pr_funcs_") && activeWindow("/pr_mid_") && activeWindow("/pr_paths_"));
        for (int frame = 0; frame < 3; ++frame) {
            featureFrame([&] { memory.renderPointerScanner(ctx, target); },
                         ImVec2(360.0f * scale, 700.0f * scale));
            CHECK(GImGui->ErrorCountCurrentFrame == 0);
        }
        if (ImGuiWindow* window = activeWindow("Feature UI integration"))
            CHECK(window->ScrollMax.x <= 1.0f);
    }
    theme::ApplyTheme(theme::ThemeId::Midnight);
}

static void checkNetworkFilterRecovery() {
    AppContext ctx;
    CommunicationsTab communications;
    communications.enumerated_ = true;
    communications.procs_.push_back({42, 1, "analysis-target.exe", true, true});
    communications.selProc_ = 0;
    communications.connsRequestedPid_ = communications.connsForPid_ = 42;
    communications.connAutoRefresh_ = false;
    communications.conns_.push_back({"127.0.0.1:9000", "127.0.0.1:80", "TCP", "IPv4", "ESTABLISHED", false});
    ConnectionsTab history;
    history.auto_ = false;
    ConnectionsTab::ConnRecord record;
    record.proto = "UDP"; record.proc = "analysis-target.exe"; record.pid = 42;
    record.local = "127.0.0.1:9000"; record.remote = "*";
    history.log_.push_back(record);

    // Exercise the actual reset button through keyboard activation. Each
    // synthetic snapshot is retained; no process/network collection is started.
    auto reset = [&](const std::function<void()>& render, const char* title, const char* action) {
        ImGuiID actionId = 0;
        for (int frame = 0; frame < 3; ++frame)
            featureFrame(render, ImVec2(520, 700));
        featureFrame([&] {
            ImGui::LogToBuffer();
            render();
            CHECK(std::string(GImGui->LogBuffer.c_str()).find(title) != std::string::npos);
            ImGui::LogFinish();
            for (ImGuiWindow* window : GImGui->Windows)
                if (window->LastFrameActive == ImGui::GetFrameCount() &&
                    std::strstr(window->Name, "##empty_state")) actionId = window->GetID(action);
        }, ImVec2(520, 700));
        CHECK(actionId != 0);
        ImGui::ActivateItemByID(actionId);
        featureFrame(render, ImVec2(520, 700));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    std::snprintf(communications.filter_, sizeof(communications.filter_), "missing");
    reset([&] { communications.renderProcesses(ctx); }, "No matching processes", "Clear filter");
    CHECK(communications.filter_[0] == '\0' && communications.procs_.size() == 1);
    communications.connShowV4_ = false;
    std::snprintf(communications.connFilter_, sizeof(communications.connFilter_), "missing");
    reset([&] { communications.renderConnections(ctx); }, "No matching endpoints", "Reset filters");
    CHECK(communications.connFilter_[0] == '\0' && communications.connShowV4_ &&
          communications.connShowV6_ && communications.connShowTcp_ && communications.connShowUdp_);
    CHECK(communications.conns_.size() == 1);
    history.activeOnly_ = history.tcpOnly_ = true;
    std::snprintf(history.filter_, sizeof(history.filter_), "missing");
    reset([&] { history.render(ctx); }, "No matching connections", "Reset filters");
    CHECK(history.filter_[0] == '\0' && !history.activeOnly_ && !history.tcpOnly_ && !history.attachedOnly_);
    CHECK(history.log_.size() == 1 && !history.auto_ && !history.pollRunning_.load());
}

static void checkProjectsProductionUi() {
    AppContext ctx;
    ProjectsTab tab;
    tab.loaded_ = true;
    tab.lastSeenHash_ = ctx.staticProject().hash;
    RecentEntry entry;
    entry.hash = 123;
    entry.name = "firmware##literal-name.bin";
    entry.path = "C:\\Analyses\\reference-images\\firmware-investigation\\September\\firmware##literal-name.bin";
    entry.arch = "x64";
    tab.recents_.push_back(entry);
    tab.selectedHash_ = entry.hash;
    tab.selectedHashValid_ = true;
    std::snprintf(tab.filter_, sizeof(tab.filter_), "no-match");
    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        for (const ImVec2 size : {ImVec2(520, 700), ImVec2(1200, 800)}) {
            for (int i = 0; i < 3; ++i) featureFrame([&] { tab.render(ctx); }, size);
            featureFrame([&] {
                ImGui::LogToBuffer();
                tab.render(ctx);
                const std::string text = ImGui::GetCurrentContext()->LogBuffer.c_str();
                CHECK(text.find("No matching projects") != std::string::npos);
                CHECK(text.find("hidden by your search") != std::string::npos);
                CHECK(text.find("firmware##literal-name.bin") != std::string::npos);
                ImGui::LogFinish();
            }, size);
            for (ImGuiWindow* window : GImGui->Windows) {
                if (window->LastFrameActive == ImGui::GetFrameCount() &&
                    (std::strstr(window->Name, "proj_detail") || std::strstr(window->Name, "proj_list")))
                    CHECK(window->ScrollMax.x <= 1.0f);
            }
        }
    }
    theme::ApplyTheme(theme::ThemeId::Midnight);
}

static void checkGmlMemoryToolsHandoff() {
    GmlHelperNumericSlot slot;
    slot.kind = GmlNumericKind::Real;
    slot.value.payload = std::bit_cast<uint64_t>(100.0);
    MemoryScanValue preset;
    uint32_t width = 0;
    CHECK(BuildGmlMemoryScanPreset(slot, preset, width));
    CHECK(width == 8 && preset.type == MemoryValueType::Float64);
    CHECK(preset.bytes.size() == 8 && FormatMemoryScanValue(preset) == "100");

    slot.kind = GmlNumericKind::Int32;
    slot.value.payload = static_cast<uint32_t>(static_cast<int32_t>(-123));
    CHECK(BuildGmlMemoryScanPreset(slot, preset, width));
    CHECK(width == 4 && preset.type == MemoryValueType::Int32);
    CHECK(FormatMemoryScanValue(preset) == "-123");

    slot.kind = GmlNumericKind::Int64;
    slot.value.payload = static_cast<uint64_t>(-INT64_C(9007199254740993));
    CHECK(BuildGmlMemoryScanPreset(slot, preset, width));
    CHECK(width == 8 && preset.type == MemoryValueType::Int64);
    CHECK(FormatMemoryScanValue(preset) == "-9007199254740993");

    slot.kind = GmlNumericKind::Boolean;
    slot.value.payload = std::bit_cast<uint64_t>(1.0);
    CHECK(BuildGmlMemoryScanPreset(slot, preset, width));
    CHECK(width == 8 && preset.type == MemoryValueType::Float64);
    CHECK(FormatMemoryScanValue(preset) == "1");

    slot.kind = GmlNumericKind::None;
    CHECK(!BuildGmlMemoryScanPreset(slot, preset, width));
    CHECK(width == 1 && !preset.valid());

    AppContext ctx;
    MemoryToolsTab tab;
    MemoryToolsTab::TargetToken target;
    target.source = MemoryToolsTab::TargetSource::Debugger;
    target.pid = 44;
    target.generation = 9;

    // Plain Inspect only changes viewer navigation/selection. Existing scanner
    // inputs and scope remain untouched.
    tab.valueKind_ = 3;
    tab.signedIntegers_ = false;
    tab.scanMode_ = static_cast<int>(MemoryScanMode::NotEqual);
    std::snprintf(tab.scanValue_, sizeof(tab.scanValue_), "%s", "unchanged");
    std::snprintf(tab.scanStart_, sizeof(tab.scanStart_), "%s", "1111");
    std::snprintf(tab.scanEnd_, sizeof(tab.scanEnd_), "%s", "2222");
    ctx.openMemoryToolsAt(0x123f, target.pid, target.generation, 8);
    CHECK(ctx.requestedMemory.pending && !ctx.requestedMemory.prepareScan);
    CHECK(ctx.requestedMemory.target.pid == target.pid &&
          ctx.requestedMemory.target.sessionGeneration == target.generation);
    tab.consumeMemoryRequest(ctx, target);
    CHECK(!ctx.requestedMemory.pending);
    CHECK(tab.viewBase_ == 0x1230 && tab.viewSelectionBegin_ == 15 &&
          tab.viewSelectionEnd_ == 22);
    CHECK(tab.valueKind_ == 3 && !tab.signedIntegers_ &&
          tab.scanMode_ == static_cast<int>(MemoryScanMode::NotEqual));
    CHECK(std::strcmp(tab.scanValue_, "unchanged") == 0);
    CHECK(std::strcmp(tab.scanStart_, "1111") == 0 &&
          std::strcmp(tab.scanEnd_, "2222") == 0);

    // Explicit preparation replaces only scan shape/value, retaining scope and
    // waiting for the analyst to press First scan.
    slot.kind = GmlNumericKind::Real;
    slot.value.payload = std::bit_cast<uint64_t>(100.0);
    CHECK(BuildGmlMemoryScanPreset(slot, preset, width));
    tab.firstScanDone_ = true;
    tab.floatTolerance_ = true;
    ctx.prepareMemoryToolsScanAt(0x2008, {target.pid, target.generation},
                                 preset, width);
    CHECK(ctx.requestedMemory.pending && ctx.requestedMemory.prepareScan);
    tab.consumeMemoryRequest(ctx, target);
    CHECK(!ctx.requestedMemory.pending && !tab.firstScanDone_ &&
          !tab.scanRunning_.load());
    CHECK(tab.valueKind_ == 5 && !tab.signedIntegers_ && !tab.scanHex_ &&
          tab.scanMode_ == static_cast<int>(MemoryScanMode::Exact));
    CHECK(std::strcmp(tab.scanValue_, "100") == 0 && tab.alignment_ == 1 &&
          !tab.floatTolerance_);
    CHECK(std::strcmp(tab.scanStart_, "1111") == 0 &&
          std::strcmp(tab.scanEnd_, "2222") == 0);
    CHECK(tab.viewBase_ == 0x2000 && tab.viewSelectionBegin_ == 8 &&
          tab.viewSelectionEnd_ == 15);

    // A delayed preset cannot affect another debugger attachment.
    const int retainedKind = tab.valueKind_;
    const uint64_t retainedBase = tab.viewBase_;
    ctx.prepareMemoryToolsScanAt(0x4000, {55, 10}, preset, width);
    tab.consumeMemoryRequest(ctx, target);
    CHECK(!ctx.requestedMemory.pending && tab.valueKind_ == retainedKind &&
          tab.viewBase_ == retainedBase);
    CHECK(tab.targetStatus_.find("expired") != std::string::npos);
}

static void checkMemoryViewerProductionUi() {
    AppContext ctx;
    MemoryToolsTab tab;
    // The last byte of the address space remains a selectable byte, without
    // wrapping the grid or allowing an overflowing multi-byte selection.
    tab.navigateViewer(UINT64_MAX, true, 8);
    CHECK(tab.viewBase_ == UINT64_MAX - 255 && tab.viewSelectionBegin_ == 255 &&
          tab.viewSelectionEnd_ == 255);
    CHECK(!tab.viewerRangeReadable(-1, 1) && !tab.viewerRangeReadable(255, 2));
    tab.lastTarget_.source = MemoryToolsTab::TargetSource::Debugger;
    tab.lastTarget_.pid = 1; tab.lastTarget_.generation = 1; tab.lastTarget_.is32 = true;
    tab.navigateViewer(UINT32_MAX, true, 8);
    CHECK(tab.viewBase_ == UINT32_MAX - 255 && tab.viewSelectionBegin_ == 255 &&
          tab.viewSelectionEnd_ == 255);
    const size_t historySize = tab.viewHistory_.size();
    tab.navigateViewer(uint64_t{UINT32_MAX} + 1);
    CHECK(tab.viewBase_ == UINT32_MAX - 255 && tab.viewHistory_.size() == historySize);
    tab.lastTarget_ = {};
    for (uint64_t i = 0; i < 300; ++i) tab.navigateViewer(0x1000 + i * 0x100, true, 4);
    CHECK(tab.viewHistory_.size() == 256 && tab.viewHistoryIndex_ == 255);
    CHECK(tab.viewHistory_.back().selectionBytes == 4);
    std::snprintf(tab.viewEdit_, sizeof(tab.viewEdit_), "AA BB CC DD");
    tab.selectViewerByte(7, true);
    CHECK(tab.viewEdit_[0] == '\0');
    CHECK(tab.viewHistory_.back().selectionBytes == 8);
    tab.viewHistoryIndex_ -= 2;
    tab.navigateViewer(0x1234, true, 2);
    CHECK(tab.viewHistoryIndex_ == tab.viewHistory_.size() - 1);
    CHECK(tab.viewHistory_.back().address == 0x1234);

    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const size_t page = info.dwPageSize;
    auto* allocation = static_cast<uint8_t*>(VirtualAlloc(nullptr, page * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    CHECK(allocation != nullptr);
    if (!allocation) return;
    allocation[page] = 10;
    allocation[page + 4] = 'A';
    allocation[page + 5] = 'B';
    DWORD oldProtection = 0;
    CHECK(VirtualProtect(allocation, page, PAGE_NOACCESS, &oldProtection));
    std::string error;
    CHECK(tab.passive_.open(GetCurrentProcessId(), {false, true}, &error));
    tab.targetSource_ = MemoryToolsTab::TargetSource::Passive;
    auto target = tab.currentTarget(ctx);
    CHECK(target.valid() && !target.canWrite);
    tab.handleTargetTransition(target);
    tab.navigateViewer(reinterpret_cast<uint64_t>(allocation + page - 128), true, 256);
    featureFrame([&] { tab.refreshViewer(ctx, target, true); });
    CHECK(tab.viewBytesRead_ == 128);
    CHECK(!tab.viewerRangeReadable(0, 1) && !tab.viewerRangeReadable(127, 2));
    CHECK(tab.viewerRangeReadable(128, 128));
    CHECK(!tab.viewerSelectionText(false).size());
    const std::string pattern = tab.viewerSelectionText(true);
    CHECK(pattern.starts_with("?? ?? ??") && pattern.find("0A 00 00 00 41 42") != std::string::npos);
    CHECK(!tab.viewStatus_.empty());

    tab.selectViewerByte(128, false);
    tab.selectViewerByte(131, true);
    CHECK(tab.viewerSelectionText(false) == "0A 00 00 00");
    tab.viewWildcard_[129] = 1;
    CHECK(tab.viewerSelectionText(true) == "0A ?? 00 00");
    CHECK(tab.viewerSelectionText(false) == "0A 00 00 00");
    tab.selectViewerByte(132, false); tab.selectViewerByte(134, true);
    CHECK(tab.viewerSelectionText(false, true) == "AB.");
    tab.selectViewerByte(128, false); tab.selectViewerByte(131, true);
    tab.viewAutoRefresh_ = false;
    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        for (const ImVec2 size : {ImVec2(520, 700), ImVec2(1200, 800)}) {
            for (int i = 0; i < 3; ++i)
                featureFrame([&] { tab.renderHexViewer(ctx, target); }, size);
            featureFrame([&] {
                ImGui::LogToBuffer();
                tab.renderHexViewer(ctx, target);
                const std::string text = ImGui::GetCurrentContext()->LogBuffer.c_str();
                CHECK(text.find("128/256 bytes readable") != std::string::npos);
                CHECK(text.find("Value at selection") != std::string::npos);
                CHECK(text.find("little-endian") != std::string::npos);
                CHECK(text.find("10") != std::string::npos);
                ImGui::LogFinish();
            }, size);
        }
    }
    // Exercise the actual focused-grid shortcut path, including a manually
    // wildcarded byte, rather than only calling its formatter directly.
    featureFrame([&] {
        tab.renderHexViewer(ctx, target);
        for (ImGuiWindow* window : GImGui->Windows)
            if (window->LastFrameActive == ImGui::GetFrameCount() &&
                std::strstr(window->Name, "memory_hex_grid")) ImGui::FocusWindow(window);
    });
    ImGuiIO& io = ImGui::GetIO();
    io.AddKeyEvent(ImGuiMod_Ctrl, true);
    io.AddKeyEvent(ImGuiKey_C, true);
    featureFrame([&] { tab.renderHexViewer(ctx, target); });
    CHECK(std::string(ImGui::GetClipboardText()) == "0A 00 00 00");
    io.AddKeyEvent(ImGuiKey_C, false);
    featureFrame([&] { tab.renderHexViewer(ctx, target); });
    io.AddKeyEvent(ImGuiMod_Shift, true);
    io.AddKeyEvent(ImGuiKey_C, true);
    featureFrame([&] { tab.renderHexViewer(ctx, target); });
    CHECK(std::string(ImGui::GetClipboardText()) == "0A ?? 00 00");
    io.AddKeyEvent(ImGuiKey_C, false);
    io.AddKeyEvent(ImGuiMod_Ctrl, false);
    io.AddKeyEvent(ImGuiMod_Shift, false);
    featureFrame([&] { tab.renderHexViewer(ctx, target); });
    // Newly readable bytes never inherit a zero-filled previous sample as
    // evidence of a change. Previously readable bytes keep a real baseline.
    CHECK(VirtualProtect(allocation, page, PAGE_READWRITE, &oldProtection));
    allocation[page - 128] = 9;
    allocation[page] = 11;
    featureFrame([&] { tab.refreshViewer(ctx, target, true); });
    CHECK(tab.viewBytesRead_ == 256 && tab.viewValid_[0] && !tab.viewPreviousValid_[0]);
    CHECK(tab.viewPreviousValid_[128] && tab.viewPrevious_[128] == 10 &&
          tab.viewBytes_[128] == 11);
    tab.passive_.close();
    featureFrame([&] { tab.refreshViewer(ctx, target, true); });
    CHECK(tab.viewBytesRead_ == 0 && !tab.viewerRangeReadable(128, 4));
    CHECK(tab.viewerSelectionText(false).empty());
    tab.handleTargetTransition({});
    CHECK(tab.viewHistory_.empty() && tab.viewEdit_[0] == '\0' &&
          !tab.viewBaseValid_ && !tab.viewWildcard_[129]);
    VirtualFree(allocation, 0, MEM_RELEASE);
    theme::ApplyTheme(theme::ThemeId::Midnight);
}

int main() {
    char temporary[MAX_PATH]{};
    if (!GetEnvironmentVariableA("DS_STATIC_LISTING_TEST_ROOT", temporary, MAX_PATH)) return 2;
    const std::string path = std::string(temporary) + "\\feature.raw";
    { std::ofstream output(path, std::ios::binary); for (size_t i = 0; i < 4096; ++i) output.put('\xC3'); }
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.DeltaTime = 1.0f / 60.0f;
    io.Fonts->AddFontDefault();
    unsigned char* pixels = nullptr; int width = 0, height = 0;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    static std::string clipboard;
    ImGui::GetPlatformIO().Platform_SetClipboardTextFn = [](ImGuiContext*, const char* value) { clipboard = value ? value : ""; };
    ImGui::GetPlatformIO().Platform_GetClipboardTextFn = [](ImGuiContext*) -> const char* { return clipboard.c_str(); };
    theme::ApplyTheme();
    try {
        checkProjectsProductionUi();
        checkGmlMemoryToolsHandoff();
        checkMemoryViewerProductionUi();
        checkCortexProductionUi(path);
        checkSigScannerProductionUi(path);
        checkTechDiffProductionUi(path);
        checkResponsiveFeatureTools();
        checkNetworkFilterRecovery();
    } catch (const std::exception& error) {
        std::printf("EXCEPTION: %s\n", error.what()); ++failures;
    }
    ImGui::DestroyContext();
    std::printf("feature_tabs_ui_test: %s (%d failure(s))\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
