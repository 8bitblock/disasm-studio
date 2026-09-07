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
#define private public
#include "Tabs/CortexTab.h"
#include "Tabs/SigScannerTab.h"
#include "Tabs/BinaryTechTab.h"
#include "Tabs/BinaryDiffTab.h"
#include "Tabs/ProjectsTab.h"
#include "Tabs/MemoryToolsTab.h"
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
        checkCortexProductionUi(path);
        checkSigScannerProductionUi(path);
        checkTechDiffProductionUi(path);
    } catch (const std::exception& error) {
        std::printf("EXCEPTION: %s\n", error.what()); ++failures;
    }
    ImGui::DestroyContext();
    std::printf("feature_tabs_ui_test: %s (%d failure(s))\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
