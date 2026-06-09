#include "App.h"
#include "Tabs/ITab.h"

#include "Tabs/ProjectsTab.h"
#include "Tabs/CommunicationsTab.h"
#include "Tabs/SigScannerTab.h"
#include "Tabs/BinaryViewTab.h"
#include "Tabs/MemoryToolsTab.h"
#include "Tabs/BinaryDiffTab.h"
#include "Tabs/BinaryTechTab.h"

#include "Ui/Theme.h"
#include "imgui.h"

#include <windows.h>
#include <commdlg.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

namespace ds {

App::App() {
    loadPrefs();                 // restore the last-used theme, if any
    theme::ApplyTheme(theme_);
    ctx_.rebuildDisassembler();

    tabs_.emplace_back(std::make_unique<ProjectsTab>());
    tabs_.emplace_back(std::make_unique<CommunicationsTab>());
    tabs_.emplace_back(std::make_unique<SigScannerTab>());
    tabs_.emplace_back(std::make_unique<BinaryViewTab>());
    tabs_.emplace_back(std::make_unique<MemoryToolsTab>());
    tabs_.emplace_back(std::make_unique<BinaryDiffTab>());
    tabs_.emplace_back(std::make_unique<BinaryTechTab>());
}

App::~App() {
    ctx_.saveProject();   // flush analysis on shutdown (window close / Alt+F4)
}

namespace {
// Small persisted-prefs file alongside the project sidecars in %APPDATA%.
std::string prefsPath() {
    char appdata[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) return "";
    std::string dir = std::string(appdata) + "\\DisasmStudio";
    CreateDirectoryA(dir.c_str(), nullptr);   // ensure it exists (no-op if already there)
    return dir + "\\prefs.ini";
}
} // namespace

void App::loadPrefs() {
    std::string path = prefsPath();
    if (path.empty()) return;
    std::ifstream f(path);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("theme=", 0) == 0) {
            int v = std::atoi(line.c_str() + 6);
            if (v >= 0 && v < (int)theme::ThemeId::Count) theme_ = (theme::ThemeId)v;
        }
    }
}

void App::savePrefs() const {
    std::string path = prefsPath();
    if (path.empty()) return;
    std::ofstream f(path, std::ios::trunc);
    if (f) f << "theme=" << (int)theme_ << "\n";
}

static Arch archFromMachine(MachineArch m, bool is64) {
    switch (m) {
        case MachineArch::X86:     return Arch::X86;
        case MachineArch::X64:     return Arch::X64;
        case MachineArch::ARM:     return Arch::ARM;
        case MachineArch::ARM64:   return Arch::ARM64;
        case MachineArch::MIPS:    return Arch::MIPS;
        case MachineArch::MIPS64:  return Arch::MIPS64;
        case MachineArch::PPC:     return Arch::PPC;
        case MachineArch::PPC64:   return Arch::PPC64;
        case MachineArch::RISCV:   return Arch::RISCV32;
        case MachineArch::RISCV64: return Arch::RISCV64;
        default:                   return is64 ? Arch::X64 : Arch::X86;
    }
}

void AppContext::loadProjectForBinary(bool applySavedArchEngine) {
    project.reset();
    if (!binary.loaded()) return;
    uint64_t h = binary.contentHash();
    ProjectState loaded;
    if (LoadProject(h, loaded)) {
        project = std::move(loaded);   // restore saved analysis
        // Reapply the saved engine/arch so the binary reopens exactly as last
        // analyzed - especially valuable for raw blobs and mis-detected images
        // where the header gives the wrong arch. Skipped on the raw-load path,
        // where the dialog's explicit choice must win.
        if (applySavedArchEngine) {
            Arch   savedArch;   if (ArchFromName(project.arch.c_str(), savedArch))   arch   = savedArch;
            Engine savedEngine; if (EngineFromName(project.engine.c_str(), savedEngine)) engine = savedEngine;
            rebuildDisassembler();
        }
    }
    project.hash       = h;
    project.binaryPath = binary.path();
    project.arch       = ArchName(arch);
    project.engine     = EngineNameOf(engine);
    size_t s = binary.path().find_last_of("/\\");
    project.name       = (s == std::string::npos) ? binary.path() : binary.path().substr(s + 1);
    project.lastOpenedUnix = (int64_t)std::time(nullptr);
}

void AppContext::saveProject() {
    // Live (memory-mapped) modules are not sidecar-persisted: their content hash is a
    // memory image, not the on-disk file, so a sidecar would never re-match and would
    // litter %APPDATA% with junk keyed to a one-off mapping.
    if (!binary.loaded() || !project.hash || binary.isMappedImage()) return;
    // Refresh the engine/arch so a choice made via the Engine menu since load is
    // persisted (these are stamped at load but the menu mutates the live context).
    project.arch   = ArchName(arch);
    project.engine = EngineNameOf(engine);
    SaveProject(project);
}

bool AppContext::loadBinaryPath(const std::string& path) {
    saveProject();                 // persist the outgoing target's analysis first
    analysis.cancelAndWaitIdle();  // no worker may be reading the old image when load() frees its bytes
    if (!binary.load(path)) return false;
    arch = archFromMachine(binary.machine(), binary.is64Bit());
    rebuildDisassembler();
    loadProjectForBinary();
    binaryJustLoaded = true;       // Binary View re-homes to the entry point + auto-analyzes
    return true;
}

bool AppContext::loadRawPath(const std::string& path, uint64_t base, Arch a) {
    saveProject();
    analysis.cancelAndWaitIdle();  // see loadBinaryPath
    if (!binary.loadRaw(path, base)) return false;
    arch = a;
    rebuildDisassembler();
    loadProjectForBinary(/*applySavedArchEngine=*/false);   // the dialog's arch choice wins
    binaryJustLoaded = true;
    return true;
}

bool AppContext::loadLiveModule(uint64_t base, uint64_t size, const std::string& name) {
    if (!debug.snapshot().attached() || !base) return false;
    if (!size) size = 0x10000;
    if (size > 256ull * 1024 * 1024) size = 256ull * 1024 * 1024;   // cap pathological sizes
    // Read the module's mapped image straight from the debuggee (masked so our own
    // 0xCC breakpoints don't corrupt the decode). This is one module (a few MB), so the
    // brief read on the UI thread is acceptable; "analyze all modules" uses the worker.
    std::vector<uint8_t> img(size);
    size_t got = debug.readMemoryMasked(base, img.data(), img.size());
    if (!got) return false;
    img.resize(got);

    saveProject();                 // persist the OUTGOING target (no-op for a live module)
    analysis.cancelAndWaitIdle();  // no worker may be reading the image we're about to replace
    if (!binary.loadFromMemory(std::move(img), base, name)) return false;
    arch = archFromMachine(binary.machine(), binary.is64Bit());
    rebuildDisassembler();
    // Live modules are in-session only: start from a clean project (no sidecar load),
    // and register/activate this module so the browser tracks the active one.
    project.reset();
    modules.addOrUpdate(name, base, size);
    if (LoadedModule* m = modules.byBase(base)) m->arch = binary.machine();
    modules.setActiveByBase(base);
    binaryJustLoaded = true;       // Binary View re-homes to the entry point + auto-analyzes
    return true;
}

void AppContext::analyzeModule(LoadedModule& m, bool guess) {
    if (!m.imageLoaded || !m.bin.loaded()) return;
    Arch a = archFromMachine(m.bin.machine(), m.bin.is64Bit());   // per-module bitness (WOW64 etc.)
    // moduleBase tag routes the results to ModuleRegistry's per-module cache (not the
    // active tab). Uses the current epoch so it isn't dropped unless a load/patch bumps it.
    analysis.requestBulk(&m.bin, engine, a, K_Funcs | K_Strings | K_Listing | K_Xref,
                         guess, analysis.epoch(), m.base);
}

bool AppContext::openBinaryDialog() {
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Executables\0*.exe;*.dll;*.sys;*.bin\0All Files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return false;

    char path[MAX_PATH * 2] = {0};
    WideCharToMultiByte(CP_UTF8, 0, file, -1, path, sizeof(path), nullptr, nullptr);
    return loadBinaryPath(path);
}

void App::openFileDialog() {
    if (ctx_.openBinaryDialog()) ctx_.requestedTab = "Binary View";
}

void App::openRawFileDialog() {
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"All Files\0*.*\0Shellcode/bin\0*.bin;*.shc;*.dat\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    char path[MAX_PATH * 2] = {0};
    WideCharToMultiByte(CP_UTF8, 0, file, -1, path, sizeof(path), nullptr, nullptr);
    rawPendingPath_ = path;
    openRawPopup_   = true;   // prompt for base + arch
}

// Splice accumulated patches into a copy of the loaded image's bytes.
static std::vector<uint8_t> buildPatchedImage(const BinaryFile& bin,
                                              const std::vector<PjPatch>& patches,
                                              int& applied, int& skipped) {
    std::vector<uint8_t> out = bin.bytes();
    applied = skipped = 0;
    for (const auto& p : patches) {
        uint64_t off = 0;
        if (!bin.vaToOffset(p.address, off) || off + p.bytes.size() > out.size()) { ++skipped; continue; }
        for (size_t i = 0; i < p.bytes.size(); ++i) out[off + i] = p.bytes[i];
        ++applied;
    }
    return out;
}

void App::saveBinaryAs() {
    if (!ctx_.binary.loaded()) return;
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    char path[MAX_PATH * 2] = {0};
    WideCharToMultiByte(CP_UTF8, 0, file, -1, path, sizeof(path), nullptr, nullptr);

    int applied = 0, skipped = 0;
    std::vector<uint8_t> img = buildPatchedImage(ctx_.binary, ctx_.project.patches, applied, skipped);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    char msg[256];
    if (f && f.write(reinterpret_cast<const char*>(img.data()), (std::streamsize)img.size()))
        std::snprintf(msg, sizeof(msg), "Wrote %zu bytes with %d patch(es) applied%s%s.",
                      img.size(), applied,
                      skipped ? ", " : "", skipped ? (std::to_string(skipped) + " unmapped/skipped").c_str() : "");
    else
        std::snprintf(msg, sizeof(msg), "Failed to write file (check the path / permissions).");
    saveResultMsg_  = msg;
    openSaveResult_ = true;
}

bool AppContext::exportAnalysisFile(const std::string& defaultBaseName,
                                    const std::string& markdown, const std::string& html,
                                    std::string& msg) {
    // Seed the dialog with "<binary>_analysis.md".
    std::wstring def;
    {
        std::string base = defaultBaseName.empty() ? std::string("analysis") : defaultBaseName;
        base += "_analysis.md";
        int n = MultiByteToWideChar(CP_UTF8, 0, base.c_str(), -1, nullptr, 0);
        def.resize(n > 0 ? n - 1 : 0);
        if (n > 0) MultiByteToWideChar(CP_UTF8, 0, base.c_str(), -1, def.data(), n);
    }
    wchar_t file[MAX_PATH] = L"";
    wcsncpy_s(file, def.c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Markdown (*.md)\0*.md\0HTML (*.html)\0*.html\0All Files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = L"md";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) { msg.clear(); return false; }   // cancelled

    char path[MAX_PATH * 2] = {0};
    WideCharToMultiByte(CP_UTF8, 0, file, -1, path, sizeof(path), nullptr, nullptr);
    std::string p(path);

    // HTML when the chosen name ends in .htm/.html (case-insensitive), else Markdown.
    auto endsWithCI = [&](const char* suf) {
        size_t ls = std::strlen(suf);
        if (p.size() < ls) return false;
        for (size_t i = 0; i < ls; ++i)
            if (std::tolower((unsigned char)p[p.size() - ls + i]) != (unsigned char)suf[i]) return false;
        return true;
    };
    const std::string& body = (endsWithCI(".html") || endsWithCI(".htm")) ? html : markdown;

    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (f && f.write(body.data(), (std::streamsize)body.size())) {
        msg = "Wrote " + std::to_string(body.size()) + " bytes to " + p;
        return true;
    }
    msg = "Failed to write " + p + " (check the path / permissions).";
    return false;
}

void App::renderMenuBar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open Binary...", "Ctrl+O")) openFileDialog();
            if (ImGui::MenuItem("Open as Raw...")) openRawFileDialog();
            if (ImGui::MenuItem("Save Binary As...", nullptr, false, ctx_.binary.loaded()))
                saveBinaryAs();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Write a copy of the loaded file with all accumulated patches applied.");
            if (ImGui::MenuItem("Export Analysis...", nullptr, false, ctx_.binary.loaded())) {
                ctx_.requestedExportAnalysis = true;
                ctx_.requestedTab = "Binary View";
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Export comments, renames, bookmarks, notes and decompiled named functions to Markdown / HTML.");
            if (ImGui::MenuItem("Close Binary", nullptr, false, ctx_.binary.loaded())) {
                ctx_.saveProject();          // flush analysis before unloading
                ctx_.analysis.cancelAndWaitIdle();  // drain the worker before clear() frees the bytes
                ctx_.binary.clear();
                ctx_.project.reset();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) { ctx_.saveProject(); exit_ = true; }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Engine")) {
            // ARM/ARM64 force Capstone (Zydis is x86-only); reflect the *effective*
            // engine in the check marks so the menu never disagrees with reality.
            const bool nonX86 = !ArchIsX86(ctx_.arch);
            const Engine effective = ctx_.disasm ? ctx_.disasm->engine() : ctx_.engine;
            bool z = effective == Engine::Zydis;
            bool c = effective == Engine::Capstone;
            ImGui::BeginDisabled(nonX86);
            if (ImGui::MenuItem("Zydis", nullptr, z)) { ctx_.engine = Engine::Zydis; ctx_.rebuildDisassembler(); }
            ImGui::EndDisabled();
            if (nonX86 && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Zydis decodes x86/x64 only - Capstone is used for every other architecture.");
            if (ImGui::MenuItem("Capstone", nullptr, c)) { ctx_.engine = Engine::Capstone; ctx_.rebuildDisassembler(); }
            ImGui::Separator();
            ImGui::TextDisabled("Architecture");
            auto archItem = [&](const char* label, Arch a) {
                if (ImGui::MenuItem(label, nullptr, ctx_.arch == a)) { ctx_.arch = a; ctx_.rebuildDisassembler(); }
            };
            archItem("x86",       Arch::X86);
            archItem("x64",       Arch::X64);
            archItem("ARM",       Arch::ARM);
            archItem("ARM64",     Arch::ARM64);
            archItem("MIPS",      Arch::MIPS);
            archItem("MIPS64",    Arch::MIPS64);
            archItem("PowerPC",   Arch::PPC);
            archItem("PowerPC64", Arch::PPC64);
            archItem("RISC-V 32", Arch::RISCV32);
            archItem("RISC-V 64", Arch::RISCV64);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::BeginMenu("Theme")) {
                for (int i = 0; i < (int)theme::ThemeId::Count; ++i) {
                    theme::ThemeId id = (theme::ThemeId)i;
                    if (ImGui::MenuItem(theme::ThemeName(id), nullptr, theme_ == id)) {
                        theme_ = id;
                        theme::ApplyTheme(id);
                        savePrefs();
                    }
                }
                ImGui::EndMenu();
            }
            ImGui::MenuItem("ImGui Demo", nullptr, &showDemo_);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            ImGui::MenuItem("About", nullptr, &showAbout_);
            ImGui::EndMenu();
        }

        // Right-aligned status text.
        const char* eng = ctx_.disasm ? ctx_.disasm->engineName() : "-";
        char status[128];
        snprintf(status, sizeof(status), "Engine: %s   |   %s",
                 eng, ctx_.binary.loaded() ? ctx_.binary.formatName() : "no binary");
        float w = ImGui::CalcTextSize(status).x;
        ImGui::SameLine(ImGui::GetWindowWidth() - w - 20.0f);
        ImGui::TextDisabled("%s", status);
        ImGui::EndMainMenuBar();
    }
}

void App::renderDebugToolbar(const DbgSnapshot& s) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, 0));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking;
    if (ImGui::Begin("##debugbar", nullptr, flags)) {
        Debugger& d = ctx_.debug;
        const bool attached = s.attached();
        const bool paused   = s.state == DbgState::Paused;
        const bool running  = s.state == DbgState::Running;

        // Colored button helper (base color + auto hover/active tints + tooltip).
        auto cbutton = [](const char* label, ImVec4 base, const char* tip = nullptr) -> bool {
            ImVec4 hov(base.x * 1.2f, base.y * 1.2f, base.z * 1.2f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Button, base);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, base);
            bool r = ImGui::Button(label);
            ImGui::PopStyleColor(3);
            if (tip && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("%s", tip);
            return r;
        };
        // Button bases derived from the active theme (dimmed so the auto hover/active
        // tints read), so the toolbar stays on-palette in every theme incl. Light.
        auto dim = [](ImVec4 c, float f) { return ImVec4(c.x * f, c.y * f, c.z * f, 1.0f); };
        const ImVec4 cGreen = dim(theme::col::good(),   0.55f);
        const ImVec4 cRed   = dim(theme::col::bad(),    0.55f);
        const ImVec4 cBlue  = dim(theme::col::accent(), 0.55f);

        if (!attached) {
            if (ctx_.binary.loaded()) {
                if (cbutton("Launch & Debug", cGreen, "Launch the loaded binary and break at its entry point")) {
                    std::string err;
                    if (ctx_.debug.launchAndAttach(ctx_.binary.path(), err)) { launchMsg_.clear(); ctx_.openLiveAssemblyView(); }
                    else launchMsg_ = "Launch failed: " + err;
                }
                ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();
            }
            if (!launchMsg_.empty())
                ImGui::TextColored(theme::col::bad(), "%s", launchMsg_.c_str());
            else
                ImGui::TextDisabled("Not attached - launch the loaded binary, or attach a process in the Communications tab.");
        } else {
            if (cbutton("Detach", cRed, "Stop debugging and detach from the process")) d.detach();
            ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();

            if (cbutton(running ? "Pause" : "Continue (F5)", running ? cBlue : cGreen,
                        running ? "Break into the running process" : "Resume execution until the next breakpoint")) {
                if (running) d.pause(); else d.cont();
            }
            ImGui::SameLine();
            ImGui::BeginDisabled(!paused);
            if (cbutton("Step Into (F11)", cBlue, "Execute one instruction, following calls"))      d.stepInto();
            ImGui::SameLine();
            if (cbutton("Step Over (F10)", cBlue, "Execute one instruction, stepping over calls"))   d.stepOver();
            ImGui::SameLine();
            if (cbutton("Step Out (Shift+F11)", cBlue, "Run until the current function returns")) d.stepOut();
            ImGui::SameLine();
            if (cbutton("Run to Cursor (Ctrl+F9)", cBlue,
                        "Run until execution reaches the address at the Binary View cursor"))
                if (ctx_.runtimeCursorVA) d.runToCursor(ctx_.runtimeCursorVA);
            ImGui::EndDisabled();

            ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();
            const char* st = running ? "RUNNING"
                           : paused  ? "PAUSED"
                           : s.state == DbgState::Terminated ? "TERMINATED" : "ATTACHED";
            ImGui::Text("PID %u%s  %s  %s 0x%016llX  %s 0x%llX  (%s)",
                        s.pid, s.is32 ? " (32-bit)" : "", st,
                        s.is32 ? "EIP" : "RIP", (unsigned long long)s.regs.rip,
                        s.is32 ? "ESP" : "RSP", (unsigned long long)s.regs.rsp, s.lastEvent.c_str());

            if (!ImGui::GetIO().WantTextInput) {
                if (ImGui::IsKeyPressed(ImGuiKey_F5)) { if (running) d.pause(); else d.cont(); }
                if (paused && ImGui::IsKeyPressed(ImGuiKey_F11) && ImGui::GetIO().KeyShift) d.stepOut();
                else if (paused && ImGui::IsKeyPressed(ImGuiKey_F11)) d.stepInto();
                if (paused && ImGui::IsKeyPressed(ImGuiKey_F10)) d.stepOver();
                if (paused && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F9) && ctx_.runtimeCursorVA)
                    d.runToCursor(ctx_.runtimeCursorVA);
            }
        }
    }
    ImGui::End();
}

void App::renderMainWindow() {
    // One fixed, full-size window with a browser-style tab strip. No docking,
    // no floating panels - the tabs always live in the same place.
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float barH    = ImGui::GetFrameHeightWithSpacing() + 6.0f; // toolbar at top
    float statusH = ImGui::GetFrameHeight() + 8.0f;            // status bar at bottom
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + barH));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, vp->WorkSize.y - barH - statusH));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
                             ImGuiWindowFlags_NoSavedSettings;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("##main", nullptr, flags);

    ImGuiTabBarFlags tbflags = ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_FittingPolicyScroll;
    if (ImGui::BeginTabBar("##tabs", tbflags)) {
        for (auto& tab : tabs_) {
            const bool selectRequested = ctx_.requestedTab == tab->name();
            ImGuiTabItemFlags itemFlags = selectRequested ? ImGuiTabItemFlags_SetSelected : 0;
            if (selectRequested) ctx_.requestedTab.clear();

            if (ImGui::BeginTabItem(tab->name(), nullptr, itemFlags)) {
                // Padded content area beneath the tab strip.
                ImGui::BeginChild("##tabcontent", ImVec2(0, 0), ImGuiChildFlags_None);
                tab->render(ctx_);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
    ImGui::PopStyleVar();
}

void App::renderStatusBar(const DbgSnapshot& d) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float statusH = ImGui::GetFrameHeight() + 8.0f;
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + vp->WorkSize.y - statusH));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, statusH));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
                             ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, theme::col::menubar());   // on-palette (incl. Light)
    if (ImGui::Begin("##status", nullptr, flags)) {
        // Colored state dot.
        ImVec4 dot = !d.attached()        ? theme::col::muted()
                   : d.state == DbgState::Running ? theme::col::good()
                   : d.state == DbgState::Paused  ? theme::col::warn()
                   : theme::col::bad();
        const char* st = !d.attached()    ? "detached"
                   : d.state == DbgState::Running ? "running"
                   : d.state == DbgState::Paused  ? "paused"
                   : d.state == DbgState::Terminated ? "terminated" : "attached";
        // Draw a status dot with the draw list (no font-glyph dependency).
        ImVec2 cp = ImGui::GetCursorScreenPos();
        float  lh = ImGui::GetTextLineHeight();
        ImGui::GetWindowDrawList()->AddCircleFilled(
            ImVec2(cp.x + 6.0f, cp.y + lh * 0.5f), 5.0f, ImGui::ColorConvertFloat4ToU32(dot));
        ImGui::Dummy(ImVec2(16.0f, lh));
        ImGui::SameLine(); ImGui::TextUnformatted(st);
        if (d.attached()) { ImGui::SameLine(); ImGui::TextDisabled("PID %u  RIP 0x%llX", d.pid, (unsigned long long)d.regs.rip); }

        ImGui::SameLine(); ImGui::TextDisabled("  |  ");
        ImGui::SameLine(); ImGui::Text("Engine: %s", ctx_.disasm ? ctx_.disasm->engineName() : "-");
        ImGui::SameLine(); ImGui::TextDisabled("  |  ");
        ImGui::SameLine();
        ImGui::Text("Arch: %s", ArchName(ctx_.arch));
        ImGui::SameLine(); ImGui::TextDisabled("  |  ");
        ImGui::SameLine();
        if (ctx_.binary.loaded()) {
            const std::string& p = ctx_.binary.path();
            size_t slash = p.find_last_of("/\\");
            ImGui::Text("%s  (%s)", slash == std::string::npos ? p.c_str() : p.c_str() + slash + 1,
                        ctx_.binary.formatName());
        } else {
            ImGui::TextDisabled("no binary loaded");
        }
        if (ctx_.hasCursor) {
            ImGui::SameLine(); ImGui::TextDisabled("  |  ");
            ImGui::SameLine();
            if (!ctx_.cursorFuncName.empty())
                ImGui::Text("Cursor: 0x%llX  (%s)", (unsigned long long)ctx_.cursorVA, ctx_.cursorFuncName.c_str());
            else
                ImGui::Text("Cursor: 0x%llX", (unsigned long long)ctx_.cursorVA);
        }

        // Background analysis progress (worker pool): phase label + bar + cancel. The
        // module counters drive the bar during an "analyze all modules" batch; otherwise
        // the per-pass byte/instruction count does, falling back to an indeterminate bar.
        if (ctx_.analysis.bulkPending()) {
            ProgressSnapshot pr = ctx_.analysis.progress();
            char lbl[64];
            if (pr.modulesTotal > 0)
                std::snprintf(lbl, sizeof(lbl), "Modules %u/%u", pr.modulesDone, pr.modulesTotal);
            else {
                const char* ph = pr.phase == AnalysisPhase::Strings   ? "Scanning strings"
                               : pr.phase == AnalysisPhase::Functions ? "Discovering functions"
                               : pr.phase == AnalysisPhase::Listing   ? "Building listing"
                               : pr.phase == AnalysisPhase::Xref      ? "Building xrefs"
                               : "Analyzing";
                std::snprintf(lbl, sizeof(lbl), "%s", ph);
            }
            ImGui::SameLine(); ImGui::TextDisabled("  |  ");
            ImGui::SameLine(); ImGui::TextColored(theme::col::accent(), "%s", lbl);
            ImGui::SameLine();
            float frac = (pr.modulesTotal > 0) ? (float)pr.modulesDone / (float)pr.modulesTotal
                       : (pr.total > 0 ? (float)pr.current / (float)pr.total : -1.0f);
            float w = 150.0f * theme::UiScale();
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, theme::col::accent());
            if (frac >= 0.0f) {
                ImGui::ProgressBar(frac, ImVec2(w, 0.0f));
            } else {
                // Indeterminate (no known total, e.g. function discovery): sliding fill.
                float t = (float)ImGui::GetTime();
                ImGui::ProgressBar(t - (float)(long long)t, ImVec2(w, 0.0f), "");
            }
            ImGui::PopStyleColor();
            ImGui::SameLine();
            if (ImGui::SmallButton("Cancel")) ctx_.analysis.cancelPending();
        }

        // Live-memory scan progress (process string scan / xref sweep / "analyze all
        // modules" image reads, on the LiveScanService pool). Green to distinguish it
        // from the static-analysis bar above.
        if (ctx_.livescan.busy()) {
            LiveProgress lp = ctx_.livescan.progress();
            uint32_t bd = ctx_.livescan.batchDone(), bt = ctx_.livescan.batchTotal();
            char lbl[64];
            if (bt > 0) std::snprintf(lbl, sizeof(lbl), "Reading modules %u/%u", bd, bt);
            else        std::snprintf(lbl, sizeof(lbl), "%s",
                            lp.kind == LiveKind::Strings ? "Scanning process strings"
                          : lp.kind == LiveKind::Xref    ? "Searching references"
                          : "Reading module image");
            ImGui::SameLine(); ImGui::TextDisabled("  |  ");
            ImGui::SameLine(); ImGui::TextColored(theme::col::good(), "%s", lbl);
            ImGui::SameLine();
            float frac = (bt > 0) ? (float)bd / (float)bt
                       : (lp.total > 0 ? (float)lp.current / (float)lp.total : -1.0f);
            float w = 150.0f * theme::UiScale();
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, theme::col::good());
            if (frac >= 0.0f) {
                ImGui::ProgressBar(frac, ImVec2(w, 0.0f));
            } else {
                float t = (float)ImGui::GetTime();
                ImGui::ProgressBar(t - (float)(long long)t, ImVec2(w, 0.0f), "");
            }
            ImGui::PopStyleColor();
            ImGui::SameLine();
            if (ImGui::SmallButton("Cancel##live")) ctx_.livescan.cancelPending();
        }
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
}

void App::renderRawLoadPopup() {
    if (openRawPopup_) { ImGui::OpenPopup("Open as Raw"); openRawPopup_ = false; }
    ImVec2 c = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(c, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("Open as Raw", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    ImGui::TextDisabled("Map a flat code blob (shellcode / firmware) with no header parsing.");
    size_t slash = rawPendingPath_.find_last_of("/\\");
    ImGui::Text("File: %s", slash == std::string::npos ? rawPendingPath_.c_str() : rawPendingPath_.c_str() + slash + 1);
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("Base address", rawBaseBuf_, sizeof(rawBaseBuf_));
    ImGui::TextUnformatted("Architecture:");
    ImGui::RadioButton("x86", &rawArchSel_, 0);   ImGui::SameLine();
    ImGui::RadioButton("x64", &rawArchSel_, 1);   ImGui::SameLine();
    ImGui::RadioButton("ARM", &rawArchSel_, 2);   ImGui::SameLine();
    ImGui::RadioButton("ARM64", &rawArchSel_, 3);

    ImGui::Separator();
    if (ImGui::Button("Load", ImVec2(120, 0))) {
        unsigned long long base = 0;
        std::sscanf(rawBaseBuf_, "%llx", &base);                 // accepts 0x-prefixed or bare hex
        if (rawBaseBuf_[0] == '0' && (rawBaseBuf_[1] == 'x' || rawBaseBuf_[1] == 'X')) std::sscanf(rawBaseBuf_ + 2, "%llx", &base);
        Arch a = rawArchSel_ == 0 ? Arch::X86 : rawArchSel_ == 1 ? Arch::X64 : rawArchSel_ == 2 ? Arch::ARM : Arch::ARM64;
        ctx_.loadRawPath(rawPendingPath_, (uint64_t)base, a);
        ctx_.requestedTab = "Binary View";
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void App::renderSaveResultPopup() {
    if (openSaveResult_) { ImGui::OpenPopup("Save Binary"); openSaveResult_ = false; }
    ImVec2 c = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(c, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("Save Binary", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::TextUnformatted(saveResultMsg_.c_str());
    ImGui::Separator();
    if (ImGui::Button("OK", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

bool App::wantsContinuousRedraw() {
    // Background work in flight: progress spinners animate and results stream in.
    if (ctx_.analysis.bulkPending() || ctx_.livescan.busy()) return true;
    // An active debug session: the debug thread mutates the snapshot asynchronously
    // (breakpoint hits, steps) and the live view pulses the RIP/selection row.
    if (ctx_.debug.snapshot().attached()) return true;
    return false;
}

void App::render() {
    // One lock-guarded debug snapshot per frame, shared by the toolbar and status bar
    // (each used to take its own deep copy of registers/threads/breakpoints).
    DbgSnapshot dbg = ctx_.debug.snapshot();
    renderMenuBar();
    renderDebugToolbar(dbg);
    renderMainWindow();
    renderStatusBar(dbg);
    renderRawLoadPopup();
    renderSaveResultPopup();

    if (showDemo_)  ImGui::ShowDemoWindow(&showDemo_);
    if (showAbout_) {
        if (ImGui::Begin("About DisasmStudio", &showAbout_, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::SetWindowFontScale(1.6f);
            ImGui::TextColored(theme::col::accent(), "DisasmStudio");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::TextDisabled("Fast, GPU-accelerated reverse-engineering workbench");
            ImGui::Separator();
            ImGui::Text("Disassembly   Zydis (x86/x64) + Capstone (ARM/ARM64/MIPS/PPC/RISC-V)");
            ImGui::Text("Assembler     Keystone (x86/x64/ARM/ARM64)");
            ImGui::Text("UI            Dear ImGui + Direct3D 11 (hardware)");
            ImGui::Spacing();
            ImGui::TextDisabled("A static disassembler and a live Win32 debugger in one tool.");
        }
        ImGui::End();
    }
}

} // namespace ds
