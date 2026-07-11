#include "App.h"
#include "Tabs/ITab.h"

#include "Tabs/ProjectsTab.h"
#include "Tabs/CommunicationsTab.h"
#include "Tabs/ConnectionsTab.h"
#include "Tabs/SigScannerTab.h"
#include "Tabs/BinaryViewTab.h"
#include "Tabs/MemoryToolsTab.h"
#include "Tabs/BinaryDiffTab.h"
#include "Tabs/BinaryTechTab.h"
#include "Tabs/CortexTab.h"
#include "Tabs/PrismTab.h"

#include "Ui/Theme.h"
#include "Ui/Fonts.h"
#include "Ui/Icons.h"
#include "Ui/Widgets.h"
#include "imgui.h"

#include <windows.h>
#include <commdlg.h>
#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

namespace ds {

App::App() {
    loadPrefs();                 // restore the last-used theme + density, if any
    theme::SetDensity(density_);
    theme::ApplyTheme(theme_);
    ctx_.rebuildDisassembler();

    tabs_.emplace_back(std::make_unique<ProjectsTab>());
    tabs_.emplace_back(std::make_unique<CommunicationsTab>());
    tabs_.emplace_back(std::make_unique<ConnectionsTab>());
    tabs_.emplace_back(std::make_unique<SigScannerTab>());
    {   // keep a typed handle: the command palette pulls its symbol index from here
        auto bv = std::make_unique<BinaryViewTab>();
        binaryView_ = bv.get();
        tabs_.emplace_back(std::move(bv));
    }
    tabs_.emplace_back(std::make_unique<MemoryToolsTab>());
    tabs_.emplace_back(std::make_unique<BinaryDiffTab>());
    tabs_.emplace_back(std::make_unique<BinaryTechTab>());
    tabs_.emplace_back(std::make_unique<CortexTab>());   // RE brain (additions.md #3)
    tabs_.emplace_back(std::make_unique<PrismTab>());    // explanatory profiler (additions.md #5)
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
        } else if (line.rfind("density=", 0) == 0) {
            int v = std::atoi(line.c_str() + 8);
            if (v >= (int)theme::Density::Compact && v <= (int)theme::Density::Spacious)
                density_ = (theme::Density)v;
        }
    }
}

void App::savePrefs() const {
    std::string path = prefsPath();
    if (path.empty()) return;
    std::ofstream f(path, std::ios::trunc);
    if (f) f << "theme=" << (int)theme_ << "\n"
             << "density=" << (int)density_ << "\n";
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
        case MachineArch::JVM:     return Arch::JVM;
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
    // A still-attached debug session belongs to the previous target: end it so the
    // new binary starts from a clean static state (the Binary View's detach edge
    // then releases the per-session live caches + module registry). Done after a
    // successful load so a failed open doesn't tear down the running session.
    {
        DbgSnapshot s = debug.snapshot();
        if (s.attached()) {
            debug.detach();
            ui::Toast(ui::ToastKind::Info,
                      "Detached from pid " + std::to_string(s.pid) + " (new target loaded)");
        }
    }
    arch = archFromMachine(binary.machine(), binary.is64Bit());
    rebuildDisassembler();
    loadProjectForBinary();
    // Java wrapper / embedded-JAR detection: cheap (EOCD + CD walk + a few BMH
    // string scans), so it runs synchronously here -- after cancelAndWaitIdle,
    // before any worker touches the new image. Not pushed into AnalysisService.
    javaInfo = ScanJava(binary);
    runtimeInfo = ScanRuntimes(binary, javaInfo);
    // Opening a .jar/.zip directly: land the user in the archive-entries browser.
    if (runtimeInfo.isStandaloneArchive && !javaInfo.entries.empty())
        requestedBrowseArchive = true;
    binaryJustLoaded = true;       // Binary View re-homes to the entry point + auto-analyzes
    return true;
}

bool AppContext::loadRawPath(const std::string& path, uint64_t base, Arch a) {
    saveProject();
    analysis.cancelAndWaitIdle();  // see loadBinaryPath
    if (!binary.loadRaw(path, base)) return false;
    {   // see loadBinaryPath: a leftover session belongs to the previous target
        DbgSnapshot s = debug.snapshot();
        if (s.attached()) {
            debug.detach();
            ui::Toast(ui::ToastKind::Info,
                      "Detached from pid " + std::to_string(s.pid) + " (new target loaded)");
        }
    }
    arch = a;
    rebuildDisassembler();
    loadProjectForBinary(/*applySavedArchEngine=*/false);   // the dialog's arch choice wins
    javaInfo = JavaScanResult{};   // raw blobs: no PE overlay semantics
    runtimeInfo = RuntimeScanResult{};
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
    javaInfo = JavaScanResult{};   // live mapping: rawOffset is an RVA, overlay math is meaningless
    runtimeInfo = RuntimeScanResult{};
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
    ofn.lpstrFilter = L"Executables\0*.exe;*.dll;*.sys;*.bin;*.class;*.jar;*.zip\0All Files\0*.*\0";
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
// INVARIANT: ctx.project.patches order = application order. Overlapping patches
// resolve by later-wins, matching the in-memory image (applyPatchBytes captures
// pristine origs via SubstitutePristine; revertPatchAt re-applies survivors in
// the same order). Do not re-sort the patch list.
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
    if (f && f.write(reinterpret_cast<const char*>(img.data()), (std::streamsize)img.size())) {
        std::snprintf(msg, sizeof(msg), "Wrote %zu bytes with %d patch(es) applied%s%s.",
                      img.size(), applied,
                      skipped ? ", " : "", skipped ? (std::to_string(skipped) + " unmapped/skipped").c_str() : "");
        ui::Toast(skipped ? ui::ToastKind::Warn : ui::ToastKind::Success, msg);
    } else {
        ui::Toast(ui::ToastKind::Error, "Save failed: could not write the file (check the path / permissions).");
    }
}

// Carve the detected embedded JAR/ZIP (ctx_.javaInfo's [jarOffset, +jarSize)
// span of the loaded file's bytes) out to a file the user picks. The span was
// validated by ScanJava (EOCD + central-directory math, trailing Authenticode
// cert excluded), so this is a plain byte copy -- no re-parsing here.
void App::extractEmbeddedJar() {
    const JavaScanResult& ji = ctx_.javaInfo;
    if (!ctx_.binary.loaded() || !ji.jarSize) return;
    const auto& bytes = ctx_.binary.bytes();
    if (ji.jarOffset >= bytes.size() || ji.jarSize > bytes.size() - ji.jarOffset) {
        ui::Toast(ui::ToastKind::Error, "Extract failed: archive span is out of bounds (stale scan?).");
        return;
    }

    // Default name: "<binary stem>.jar" (".zip" when there is no JAR manifest).
    std::wstring def;
    {
        std::string base = ctx_.binary.path();
        size_t slash = base.find_last_of("/\\");
        if (slash != std::string::npos) base = base.substr(slash + 1);
        size_t dot = base.find_last_of('.');
        if (dot != std::string::npos && dot > 0) base = base.substr(0, dot);
        base += ji.isJar ? ".jar" : ".zip";
        int n = MultiByteToWideChar(CP_UTF8, 0, base.c_str(), -1, nullptr, 0);
        def.resize(n > 0 ? n - 1 : 0);
        if (n > 0) MultiByteToWideChar(CP_UTF8, 0, base.c_str(), -1, def.data(), n);
    }
    wchar_t file[MAX_PATH] = L"";
    wcsncpy_s(file, def.c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = ji.isJar ? L"JAR archive (*.jar)\0*.jar\0ZIP archive (*.zip)\0*.zip\0All Files\0*.*\0"
                               : L"ZIP archive (*.zip)\0*.zip\0All Files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = ji.isJar ? L"jar" : L"zip";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    char path[MAX_PATH * 2] = {0};
    WideCharToMultiByte(CP_UTF8, 0, file, -1, path, sizeof(path), nullptr, nullptr);

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (f && f.write(reinterpret_cast<const char*>(bytes.data() + ji.jarOffset),
                     (std::streamsize)ji.jarSize)) {
        char msg[256];
        std::snprintf(msg, sizeof(msg), "Extracted %llu bytes (%zu entr%s)%s%s.",
                      (unsigned long long)ji.jarSize, ji.entries.size(),
                      ji.entries.size() == 1 ? "y" : "ies",
                      ji.mainClass.empty() ? "" : ", Main-Class ",
                      ji.mainClass.c_str());
        ui::Toast(ui::ToastKind::Success, msg);
    } else {
        ui::Toast(ui::ToastKind::Error, "Extract failed: could not write the file (check the path / permissions).");
    }
}

// ---- Archive entry browser ("Archive Entries" popup) ------------------------

namespace {

// Re-read the archive's container file from disk and decompress one entry. The
// browser snapshot may outlive the loaded binary ("Open as binary" replaces it),
// so the bytes always come fresh from sourcePath, never from ctx_.binary.
bool extractArchiveEntryBytes(const std::string& srcPath, uint64_t zipBase,
                              const JavaZipEntry& e, std::vector<uint8_t>& out,
                              std::string& err) {
    std::ifstream f(srcPath, std::ios::binary | std::ios::ate);
    if (!f) { err = "could not open " + srcPath; return false; }
    std::streamsize n = f.tellg();
    if (n <= 0) { err = "could not read " + srcPath; return false; }
    f.seekg(0);
    std::vector<uint8_t> bytes(static_cast<size_t>(n));
    if (!f.read(reinterpret_cast<char*>(bytes.data()), n)) { err = "could not read " + srcPath; return false; }
    return ExtractZipEntry(bytes.data(), bytes.size(), zipBase, e, out, &err);
}

// "lib/app.jar" -> "app.jar" with Windows-invalid filename chars replaced.
std::string sanitizeEntryBaseName(const std::string& entryName) {
    size_t s = entryName.find_last_of("/\\");
    std::string b = (s == std::string::npos) ? entryName : entryName.substr(s + 1);
    for (char& c : b)
        if ((unsigned char)c < 0x20 || std::strchr("<>:\"/\\|?*", c)) c = '_';
    if (b.empty()) b = "entry";
    return b;
}

// Write extracted entry bytes to %TEMP%\DisasmStudio\extracted\<name>, prefixing a
// counter on collision so a re-extract never clobbers a file that may still be the
// loaded binary. Returns the path, empty on failure.
std::string writeExtractedTemp(const std::string& name, const std::vector<uint8_t>& bytes) {
    char tmp[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("TEMP", tmp, sizeof(tmp))) return {};
    std::string dir = std::string(tmp) + "\\DisasmStudio";
    CreateDirectoryA(dir.c_str(), nullptr);
    dir += "\\extracted";
    CreateDirectoryA(dir.c_str(), nullptr);
    std::string path = dir + "\\" + name;
    for (int counter = 1; GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES && counter < 1000; ++counter)
        path = dir + "\\" + std::to_string(counter) + "_" + name;
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return {};
    if (!bytes.empty() &&
        !f.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size())) return {};
    return path;
}

} // namespace

void App::openArchiveBrowser() {
    if (!ctx_.binary.loaded() || ctx_.javaInfo.entries.empty()) return;
    archiveBrowser_ = {};
    archiveBrowser_.sourcePath = ctx_.binary.path();
    size_t s = archiveBrowser_.sourcePath.find_last_of("/\\");
    archiveBrowser_.sourceName = (s == std::string::npos) ? archiveBrowser_.sourcePath
                                                          : archiveBrowser_.sourcePath.substr(s + 1);
    archiveBrowser_.zipBase = ctx_.javaInfo.jarOffset;
    archiveBrowser_.entries = ctx_.javaInfo.entries;
    archiveBrowser_.open    = true;
}

// Save-dialog flow for one archive entry: extractEmbeddedJar's shape, but
// writing the DECOMPRESSED entry bytes rather than the raw archive span.
void App::extractArchiveEntryToFile(const JavaZipEntry& e) {
    std::vector<uint8_t> bytes;
    std::string err;
    if (!extractArchiveEntryBytes(archiveBrowser_.sourcePath, archiveBrowser_.zipBase, e, bytes, err)) {
        ui::Toast(ui::ToastKind::Error, "Extract failed: " + err);
        return;
    }

    std::string base = sanitizeEntryBaseName(e.name);
    std::wstring def;
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, base.c_str(), -1, nullptr, 0);
        def.resize(n > 0 ? n - 1 : 0);
        if (n > 0) MultiByteToWideChar(CP_UTF8, 0, base.c_str(), -1, def.data(), n);
    }
    wchar_t file[MAX_PATH] = L"";
    wcsncpy_s(file, def.c_str(), _TRUNCATE);

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

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (f && (bytes.empty() ||
              f.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size()))) {
        char msg[512];
        std::snprintf(msg, sizeof(msg), "Extracted %s (%zu bytes).", e.name.c_str(), bytes.size());
        ui::Toast(ui::ToastKind::Success, msg);
    } else {
        ui::Toast(ui::ToastKind::Error, "Extract failed: could not write the file (check the path / permissions).");
    }
}

void App::renderArchiveBrowser() {
    if (archiveBrowser_.open) { ImGui::OpenPopup("Archive Entries"); archiveBrowser_.open = false; }
    const float s = theme::UiScale();
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(700.0f * s, 440.0f * s), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Archive Entries", nullptr, 0)) return;

    ImGui::TextDisabled("%s \xE2\x80\x94 %zu entr%s", archiveBrowser_.sourceName.c_str(),
                        archiveBrowser_.entries.size(),
                        archiveBrowser_.entries.size() == 1 ? "y" : "ies");
    ImGui::SameLine();
    ui::SearchBox("##arcfilter", "filter name...", archiveBrowser_.filter,
                  sizeof(archiveBrowser_.filter), 240.0f * s);

    // Case-insensitive substring filter over entry names.
    auto lc = [](std::string v) { for (char& ch : v) ch = (char)std::tolower((unsigned char)ch); return v; };
    const std::string needle = lc(archiveBrowser_.filter);
    std::vector<int> rows;
    rows.reserve(archiveBrowser_.entries.size());
    for (int i = 0; i < (int)archiveBrowser_.entries.size(); ++i)
        if (needle.empty() || lc(archiveBrowser_.entries[i].name).find(needle) != std::string::npos)
            rows.push_back(i);

    const float footer = ImGui::GetFrameHeightWithSpacing() + 4.0f * s;
    if (ImGui::BeginTable("##arcentries", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY,
                          ImVec2(0, -footer))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 64.0f * s);
        ImGui::TableSetupColumn("Size",   ImGuiTableColumnFlags_WidthFixed, 90.0f * s);
        ImGui::TableSetupColumn("Packed", ImGuiTableColumnFlags_WidthFixed, 90.0f * s);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin((int)rows.size());
        while (clip.Step()) {
            for (int r = clip.DisplayStart; r < clip.DisplayEnd; ++r) {
                const int i = rows[r];
                const JavaZipEntry& e = archiveBrowser_.entries[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(i);   // entry names can repeat across directories
                if (ImGui::Selectable(e.name.c_str(), archiveBrowser_.selected == i,
                                      ImGuiSelectableFlags_SpanAllColumns))
                    archiveBrowser_.selected = i;
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%s", e.method == 0 ? "stored" : e.method == 8 ? "deflate" : "other");
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%u", e.uncompSize);
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%u", e.compSize);
            }
        }
        ImGui::EndTable();
    }

    const bool hasSel = archiveBrowser_.selected >= 0 &&
                        archiveBrowser_.selected < (int)archiveBrowser_.entries.size();
    ImGui::BeginDisabled(!hasSel);
    if (ImGui::Button("Open as binary") && hasSel) {
        const JavaZipEntry& e = archiveBrowser_.entries[archiveBrowser_.selected];
        std::vector<uint8_t> bytes;
        std::string err;
        if (!extractArchiveEntryBytes(archiveBrowser_.sourcePath, archiveBrowser_.zipBase, e, bytes, err)) {
            ui::Toast(ui::ToastKind::Error, "Extract failed: " + err);
        } else {
            std::string tmpPath = writeExtractedTemp(sanitizeEntryBaseName(e.name), bytes);
            if (tmpPath.empty()) {
                ui::Toast(ui::ToastKind::Error,
                          "Could not write the extracted entry to %TEMP%\\DisasmStudio\\extracted.");
            // NOTE: loadBinaryPath re-runs the scans, so a nested .jar/.zip entry
            // re-raises requestedBrowseArchive and reopens this browser for it —
            // the Native EXE -> JAR -> class chain is intended.
            } else if (!ctx_.loadBinaryPath(tmpPath)) {
                ui::Toast(ui::ToastKind::Error, "Extracted, but the entry could not be loaded: " + tmpPath);
            } else {
                ctx_.requestedTab = "Binary View";
                char msg[512];
                std::snprintf(msg, sizeof(msg), "Opened %s (%zu bytes) from the archive.",
                              e.name.c_str(), bytes.size());
                ui::Toast(ui::ToastKind::Success, msg);
                ImGui::CloseCurrentPopup();
            }
        }
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Decompress the selected entry to %%TEMP%% and load it as the active binary.");
    ImGui::SameLine();
    if (ImGui::Button("Extract...") && hasSel)
        extractArchiveEntryToFile(archiveBrowser_.entries[archiveBrowser_.selected]);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Save the selected entry's decompressed bytes to a file you pick.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
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

void App::closeBinary() {
    // An active debug session belongs to the binary being closed: end it first so
    // the Binary View's detach edge releases the live caches + module registry
    // and the app drops back to a clean welcome state.
    if (ctx_.debug.snapshot().attached()) ctx_.debug.detach();
    ctx_.saveProject();                 // flush analysis before unloading
    ctx_.analysis.cancelAndWaitIdle();  // drain the worker before clear() frees the bytes
    ctx_.binary.clear();
    ctx_.project.reset();
    ctx_.javaInfo = JavaScanResult{};
    ctx_.runtimeInfo = RuntimeScanResult{};
    // Stale cross-tab requests must not fire into the next binary.
    ctx_.requestedGotoVA = 0; ctx_.hasGotoRequest = false; ctx_.requestedGotoLive = false;
    ctx_.requestedLiveAssembly = false; ctx_.binaryJustLoaded = false;
    ctx_.pendingSignature.clear(); ctx_.pendingSignatureLive = false;
    ctx_.requestedExtractJava = false; ctx_.requestedBrowseArchive = false;
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
            if (ImGui::MenuItem(ctx_.javaInfo.isJar ? "Extract Embedded JAR..." : "Extract Embedded ZIP...",
                                nullptr, false, ctx_.javaInfo.jarSize > 0))
                extractEmbeddedJar();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(ctx_.javaInfo.jarSize > 0
                                      ? "Carve the appended archive a Java launcher embedded in this EXE out to a file."
                                      : "Enabled when an appended JAR/ZIP archive is detected in the loaded binary.");
            if (ImGui::MenuItem("Browse Embedded Archive...", nullptr, false, !ctx_.javaInfo.entries.empty()))
                ctx_.requestedBrowseArchive = true;
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(!ctx_.javaInfo.entries.empty()
                                      ? "List the embedded archive's entries; open one as a binary or extract it decompressed."
                                      : "Enabled when a JAR/ZIP archive with entries is detected in the loaded binary.");
            if (ImGui::MenuItem("Close Binary", nullptr, false, ctx_.binary.loaded()))
                closeBinary();
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
            if (ImGui::BeginMenu("Density")) {
                const theme::Density opts[] = { theme::Density::Compact,
                                                theme::Density::Comfortable,
                                                theme::Density::Spacious };
                for (theme::Density d : opts) {
                    if (ImGui::MenuItem(theme::DensityName(d), nullptr, density_ == d)) {
                        density_ = d;
                        theme::SetDensity(d);
                        theme::ApplyTheme();   // re-derive spacing live (same as theme switch)
                        savePrefs();
                    }
                }
                ImGui::EndMenu();
            }
            if (ImGui::MenuItem("Reset Layout"))
                ctx_.requestResetDockLayout = true;
            ImGui::MenuItem("ImGui Demo", nullptr, &showDemo_);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            ImGui::MenuItem("About", nullptr, &showAbout_);
            ImGui::EndMenu();
        }

        // Right side: browser-style tab for the loaded file (wireframe wf-file-tab),
        // mono name + format, with a close glyph that unloads the binary.
        const float k = theme::UiScale();
        if (ctx_.binary.loaded()) {
            const std::string& p = ctx_.binary.path();
            size_t slash = p.find_last_of("/\\");
            const char* fname = slash == std::string::npos ? p.c_str() : p.c_str() + slash + 1;
            char info[160];
            std::snprintf(info, sizeof(info), "%s  \xC2\xB7 %s", fname, ctx_.binary.formatName());
            ui::PushMono();
            const ImVec2 ts = ImGui::CalcTextSize(info);
            ui::PopMono();
            const float h  = ImGui::GetFrameHeight();
            const float xs = ts.y * 0.62f;                 // close-glyph box
            const float w  = 9.0f * k + ts.x + 8.0f * k + xs + 9.0f * k;
            ImGui::SameLine(ImGui::GetWindowWidth() - w - 12.0f * k);
            const ImVec2 pos = ImGui::GetCursorScreenPos();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h),
                              ImGui::GetColorU32(theme::col::panel()), 5.0f * k,
                              ImDrawFlags_RoundCornersTop);
            dl->AddRect(pos, ImVec2(pos.x + w, pos.y + h),
                        ImGui::GetColorU32(theme::col::line()), 5.0f * k,
                        ImDrawFlags_RoundCornersTop, 1.0f);
            ui::PushMono();
            dl->AddText(ImVec2(pos.x + 9.0f * k, pos.y + (h - ts.y) * 0.5f),
                        ImGui::GetColorU32(ImGuiCol_Text), info);
            ui::PopMono();
            // Close glyph (drawn cross; hover = bad).
            const ImVec2 xp(pos.x + 9.0f * k + ts.x + 8.0f * k, pos.y + (h - xs) * 0.5f);
            ImGui::SetCursorScreenPos(xp);
            bool xClick = ImGui::InvisibleButton("##filetabclose", ImVec2(xs, xs));
            bool xHov   = ImGui::IsItemHovered();
            const ImU32 xc = ImGui::GetColorU32(xHov ? theme::col::bad() : theme::col::muted());
            const float in = xs * 0.22f;
            dl->AddLine(ImVec2(xp.x + in, xp.y + in), ImVec2(xp.x + xs - in, xp.y + xs - in), xc, 1.4f);
            dl->AddLine(ImVec2(xp.x + xs - in, xp.y + in), ImVec2(xp.x + in, xp.y + xs - in), xc, 1.4f);
            if (xHov) ImGui::SetTooltip("Close binary");
            else if (ImGui::IsMouseHoveringRect(pos, ImVec2(pos.x + w, pos.y + h)))
                ImGui::SetTooltip("%s", p.c_str());
            if (xClick) closeBinary();
        } else {
            const char* none = "no binary";
            float w = ImGui::CalcTextSize(none).x;
            ImGui::SameLine(ImGui::GetWindowWidth() - w - 20.0f * k);
            ImGui::TextDisabled("%s", none);
        }
        ImGui::EndMainMenuBar();
    }
}

// Toolbar height: room for the 30px square tool buttons + padding (the wireframe
// wf-toolbar is 44px); never smaller than a frame row so inline text still fits.
static float ToolbarHeight() {
    const float k = theme::UiScale();
    const float h = 44.0f * k;
    const float m = ImGui::GetFrameHeight() + 14.0f * k;
    return h > m ? h : m;
}

// Tab-card strip height: room for a section label + a small mono sub-text line
// (wireframe wf-vtab cards). Sits as its own full-width band below the toolbar.
static float TabStripHeight() {
    const float k = theme::UiScale();
    const float h = 54.0f * k;
    const float m = ImGui::GetFrameHeight() + 26.0f * k;
    return h > m ? h : m;
}

void App::renderDebugToolbar(const DbgSnapshot& s) {
    const float k    = theme::UiScale();
    const float barH = ToolbarHeight();
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, barH));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f * k, (barH - 30.0f * k) * 0.5f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, theme::col::panel());
    if (ImGui::Begin("##debugbar", nullptr, flags)) {
        // Bottom border line (wireframe panel chrome).
        ImGui::GetWindowDrawList()->AddLine(
            ImVec2(vp->WorkPos.x, vp->WorkPos.y + barH - 1.0f),
            ImVec2(vp->WorkPos.x + vp->WorkSize.x, vp->WorkPos.y + barH - 1.0f),
            ImGui::GetColorU32(theme::col::line()));

        Debugger& d = ctx_.debug;
        const bool attached = s.attached();
        const bool paused   = s.state == DbgState::Paused;
        const bool running  = s.state == DbgState::Running;
        const bool loaded   = ctx_.binary.loaded();
        // Inline (non-button) items center against the 30px tool buttons.
        auto centerY = [&](float itemH) {
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (30.0f * k - itemH) * 0.5f);
        };

        // File group.
        if (ui::ToolButton("open", DS_ICON_FOLDER, "O", "Open Binary... (Ctrl+O)")) openFileDialog();
        ImGui::SameLine(0.0f, 4.0f * k);
        if (ui::ToolButton("save", DS_ICON_SAVE, "S", "Save Binary As... (apply patches)", false, loaded))
            saveBinaryAs();
        ImGui::SameLine(0.0f, 8.0f * k);
        ui::ToolbarDivider();
        ImGui::SameLine(0.0f, 8.0f * k);

        // Debug control group - the same actions/hotkeys as before, square icon buttons now.
        if (!attached) {
            const bool canLaunch = ctx_.binaryLaunchable();
            const char* launchTip = (canLaunch || !loaded)
                ? "Launch & Debug - launch the loaded binary and break at its entry point"
                : "Launch & Debug - this image can't be started directly (only a PE .exe opened\n"
                  "from disk can); attach to a running process in the Communications tab instead";
            if (ui::ToolButton("launch", DS_ICON_PLAY, ">", launchTip, canLaunch, canLaunch)) {
                std::string err;
                if (!ctx_.launchAndDebug(err)) ui::Toast(ui::ToastKind::Error, "Launch failed: " + err);
            }
            // Java wrapper detected: suggest (never auto-enable) the JVM-init break,
            // which must be armed before launch to catch jvm.dll's load event.
            if (loaded && ctx_.javaInfo.kind != JavaWrapKind::None) {
                ImGui::SameLine(0.0f, 10.0f * k);
                centerY(ImGui::GetFrameHeight());
                bool jvmInit = ctx_.debug.breakOnJvmInit();
                if (ImGui::Checkbox("Break on JVM init", &jvmInit)) ctx_.debug.setBreakOnJvmInit(jvmInit);
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Java wrapper detected (%s): one-shot breakpoint on jvm.dll!JNI_CreateJavaVM\nwhen the VM module loads. Arm it before Launch & Debug.",
                                      JavaWrapKindName(ctx_.javaInfo.kind));
            }
            if (!loaded) {
                ImGui::SameLine(0.0f, 10.0f * k);
                centerY(ImGui::GetTextLineHeight());
                ImGui::TextDisabled("Open a binary, or attach a process in Communications.");
            }
        } else {
            if (ui::ToolButton("detach", DS_ICON_STOP, "X", "Stop debugging and detach from the process"))
                d.detach();
            ImGui::SameLine(0.0f, 4.0f * k);
            if (running) {
                if (ui::ToolButton("pause", DS_ICON_PAUSE, "||", "Pause - break into the running process (F5)", true))
                    d.pause();
            } else {
                if (ui::ToolButton("cont", DS_ICON_PLAY, ">", "Continue - resume until the next breakpoint (F5)", true))
                    d.cont();
            }
            ImGui::SameLine(0.0f, 8.0f * k);
            ui::ToolbarDivider();
            ImGui::SameLine(0.0f, 8.0f * k);
            if (ui::ToolButton("stepin", DS_ICON_DOWN, "v", "Step Into (F11) - one instruction, following calls", false, paused))
                d.stepInto();
            ImGui::SameLine(0.0f, 4.0f * k);
            if (ui::ToolButton("stepover", DS_ICON_REDO, ">>", "Step Over (F10) - one instruction, stepping over calls", false, paused))
                d.stepOver();
            ImGui::SameLine(0.0f, 4.0f * k);
            if (ui::ToolButton("stepout", DS_ICON_UP, "^", "Step Out (Shift+F11) - run until the current function returns", false, paused))
                d.stepOut();
            ImGui::SameLine(0.0f, 4.0f * k);
            if (ui::ToolButton("runcur", DS_ICON_PIN, "rc",
                               "Run to Cursor (Ctrl+F9) - run until the Binary View cursor address",
                               false, paused && ctx_.runtimeCursorVA != 0))
                if (ctx_.runtimeCursorVA) d.runToCursor(ctx_.runtimeCursorVA);

            if (!ImGui::GetIO().WantTextInput) {
                if (ImGui::IsKeyPressed(ImGuiKey_F5)) { if (running) d.pause(); else d.cont(); }
                if (paused && ImGui::IsKeyPressed(ImGuiKey_F11) && ImGui::GetIO().KeyShift) d.stepOut();
                else if (paused && ImGui::IsKeyPressed(ImGuiKey_F11)) d.stepInto();
                if (paused && ImGui::IsKeyPressed(ImGuiKey_F10)) d.stepOver();
                if (paused && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F9) && ctx_.runtimeCursorVA)
                    d.runToCursor(ctx_.runtimeCursorVA);
            }
        }

        // Right-aligned group: [JVM badge] [arch/engine pill] [state pill]
        // (wireframe wf-arch / wf-state). Widths measured first to right-align.
        char archTxt[64];
        std::snprintf(archTxt, sizeof(archTxt), "%s \xC2\xB7 %s", ArchName(ctx_.arch),
                      ctx_.disasm ? ctx_.disasm->engineName() : "-");
        const char* st = !attached ? "STATIC"
                       : running   ? "RUNNING"
                       : paused    ? "PAUSED"
                       : s.state == DbgState::Terminated ? "TERMINATED" : "ATTACHED";
        const ImVec4 stc = !attached ? theme::col::muted()
                         : running   ? theme::col::good()
                         : paused    ? theme::col::warn()
                         : s.state == DbgState::Terminated ? theme::col::bad() : theme::col::accent();
        char detail[192] = {0};
        if (attached)
            std::snprintf(detail, sizeof(detail), "pid %u%s  %s %llX%s%s",
                          s.pid, s.is32 ? " (32)" : "",
                          s.is32 ? "eip" : "rip", (unsigned long long)s.regs.rip,
                          s.lastEvent.empty() ? "" : "  \xC2\xB7 ",
                          s.lastEvent.c_str());
        auto monoW = [](const char* t) {
            ui::PushMono();
            float w = ImGui::CalcTextSize(t).x;
            ui::PopMono();
            return w;
        };
        const float wArch  = monoW(archTxt) + 20.0f * k;
        const float wState = monoW(st) + (detail[0] ? monoW(detail) + 8.0f * k : 0.0f) + 24.0f * k;
        const float wJvm   = s.jvmLoaded ? monoW("JVM") + 20.0f * k + 8.0f * k : 0.0f;
        const float xRight = ImGui::GetWindowContentRegionMax().x - (wJvm + wArch + 8.0f * k + wState);
        ImGui::SameLine();
        if (ImGui::GetCursorPosX() < xRight) ImGui::SetCursorPosX(xRight);
        if (s.jvmLoaded) {
            // The debuggee loaded a Java VM module; tooltip = module path + passed faults.
            char jtip[320];
            std::snprintf(jtip, sizeof(jtip), "%s\n%llu JVM-internal exception(s) passed through silently",
                          s.jvmPath.c_str(), (unsigned long long)s.jvmExceptionsPassed);
            ImVec4 acc = theme::col::accent();
            ui::Pill("##jvmbadge", "JVM", &acc, jtip);
            ImGui::SameLine(0.0f, 8.0f * k);
        }
        if (ui::Pill("##archpill", archTxt, nullptr, "Architecture / decode engine - click to change"))
            ImGui::OpenPopup("##archpopup");
        if (ImGui::BeginPopup("##archpopup")) {
            // Mirrors the Engine menu exactly (incl. the non-x86 Zydis gating).
            const bool nonX86 = !ArchIsX86(ctx_.arch);
            const Engine effective = ctx_.disasm ? ctx_.disasm->engine() : ctx_.engine;
            ImGui::TextDisabled("Engine");
            ImGui::BeginDisabled(nonX86);
            if (ImGui::MenuItem("Zydis", nullptr, effective == Engine::Zydis)) { ctx_.engine = Engine::Zydis; ctx_.rebuildDisassembler(); }
            ImGui::EndDisabled();
            if (ImGui::MenuItem("Capstone", nullptr, effective == Engine::Capstone)) { ctx_.engine = Engine::Capstone; ctx_.rebuildDisassembler(); }
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
            ImGui::EndPopup();
        }
        ImGui::SameLine(0.0f, 8.0f * k);
        ui::StatePill(st, stc, detail[0] ? detail : nullptr);
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
}

// Horizontal tab-card strip (wireframe wf-vtabs): one bordered card per section,
// each a section label over a small mono sub-text. The active card gets an ink/
// accent border, panel-2 background, an accent underline, and a soft drop shadow.
// Tabs stay identified by their name() string, so the ITab interface and every
// requestedTab call site are untouched. Drawn as its own full-width band below
// the toolbar; cards are painted with the window draw list + InvisibleButton hit
// targets (like the old rail), so the look matches the wireframe exactly.
void App::renderTabCardStrip(const DbgSnapshot& dbg) {
    const float k = theme::UiScale();
    const float barH    = ToolbarHeight();
    const float stripH  = TabStripHeight();
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + barH));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, stripH));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
                             ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, theme::col::panel());
    if (ImGui::Begin("##tabstrip", nullptr, flags)) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec2 win = ImGui::GetWindowPos();
        // Bottom border line (wireframe panel chrome).
        dl->AddLine(ImVec2(win.x, win.y + stripH - 1.0f),
                    ImVec2(win.x + vp->WorkSize.x, win.y + stripH - 1.0f),
                    ImGui::GetColorU32(theme::col::line()));

        // Section icon by tab name.
        struct CardIcon { const char* name; const char* icon; };
        static const CardIcon kIcons[] = {
            { "Projects",       DS_ICON_FOLDER  },
            { "Communications", DS_ICON_NETWORK },
            { "Connections",    DS_ICON_LIGHTNING },
            { "Sig Scanner",    DS_ICON_SEARCH  },
            { "Binary View",    DS_ICON_CODE    },
            { "Memory Tools",   DS_ICON_MEMORY  },
            { "Binary Diff",    DS_ICON_SWITCH  },
            { "Binary Tech",    DS_ICON_SHIELD  },
            { "Cortex",         DS_ICON_INFO    },
            { "Prism",          DS_ICON_LIGHTNING },
        };
        auto iconFor = [&](const char* nm) -> const char* {
            for (const auto& ki : kIcons) if (std::strcmp(ki.name, nm) == 0) return ki.icon;
            return nullptr;
        };

        // Mono sub-text per section. Binary View shows the loaded basename.
        std::string binBase;
        {
            const std::string& bp = ctx_.binary.path();
            if (!bp.empty()) {
                size_t slash = bp.find_last_of("/\\");
                binBase = (slash == std::string::npos) ? bp : bp.substr(slash + 1);
            }
        }
        const char* dbgWord = !dbg.attached()              ? "detached"
                            : dbg.state == DbgState::Paused ? "paused"
                            : dbg.state == DbgState::Running ? "running" : "attached";
        auto subFor = [&](const char* nm) -> std::string {
            if (std::strcmp(nm, "Projects") == 0)       return "recent";
            if (std::strcmp(nm, "Communications") == 0) return dbgWord;
            if (std::strcmp(nm, "Connections") == 0)    return dbg.attached() ? "live" : "tcp/udp";
            if (std::strcmp(nm, "Sig Scanner") == 0)    return "scan";
            if (std::strcmp(nm, "Binary View") == 0)    return binBase.empty() ? "no binary" : binBase;
            if (std::strcmp(nm, "Memory Tools") == 0)   return "scan";
            if (std::strcmp(nm, "Binary Diff") == 0)    return "a/b";
            if (std::strcmp(nm, "Binary Tech") == 0)    return "caps";
            if (std::strcmp(nm, "Cortex") == 0)         return "insight";
            if (std::strcmp(nm, "Prism") == 0)          return "profile";
            return "";
        };

        const ImVec4 acc      = theme::col::accent();
        const float  pad      = 6.0f * k;       // wf-vtab vertical padding (6px)
        const float  sidePad  = 10.0f * k;
        const float  roomyGap = 8.0f * k;
        const float  compactGap = 4.0f * k;
        const float  roomyCard = 120.0f * k;
        const bool   compact  = vp->WorkSize.x < sidePad * 2.0f +
                                roomyCard * (float)tabs_.size() +
                                roomyGap * (float)(tabs_.empty() ? 0 : tabs_.size() - 1);
        const float  hpad     = (compact ? 8.0f : 14.0f) * k;
        const float  gap      = compact ? compactGap : roomyGap;
        const float  rounding = 5.0f * k;
        const float  cardH    = stripH - 2.0f * pad;
        const float  cardTop  = win.y + pad;
        const float  iconSz   = 16.0f * k;      // sub-glyph drawn to the card's left
        const float  usableW  = (std::max)(1.0f, vp->WorkSize.x - sidePad * 2.0f -
                                          gap * (float)(tabs_.empty() ? 0 : tabs_.size() - 1));
        const float  fitCardW = tabs_.empty() ? usableW : usableW / (float)tabs_.size();
        // New sections must not disappear beyond the right edge. Cards share the
        // available strip width on compact windows and stop growing on wide ones.
        const float  cardW    = (std::max)(1.0f, (std::min)(190.0f * k, fitCardW));
        float        x        = win.x + sidePad;

        for (int i = 0; i < (int)tabs_.size(); ++i) {
            const char* nm = tabs_[i]->name();
            const bool active = (i == activeTab_);
            const char* ic = ui::IconsLoaded() ? iconFor(nm) : nullptr;
            const bool drawIcon = (ic && ui::gIconFontLarge && cardW >= 104.0f * k);

            // Measure: label (normal font) over mono sub-text. Card width fits both.
            ImVec2 labelSz = ImGui::CalcTextSize(nm);
            std::string sub = subFor(nm);
            ui::PushMono();
            const float subScale = 0.82f;       // smaller mono sub-line (wf-vtab-sub ~9.5px)
            ImFont* monoFont = ImGui::GetFont();
            const float subFontSz = ImGui::GetFontSize() * subScale;
            ImVec2 subSz = monoFont->CalcTextSizeA(subFontSz, FLT_MAX, 0.0f, sub.c_str());
            ui::PopMono();

            const float iconW    = drawIcon ? (iconSz + 8.0f * k) : 0.0f;

            const ImVec2 a(x, cardTop);
            const ImVec2 b(x + cardW, cardTop + cardH);

            ImGui::PushID(i);
            ImGui::SetCursorScreenPos(a);
            bool clicked = ImGui::InvisibleButton("##tabcard", ImVec2(cardW, cardH));
            bool hovered = ImGui::IsItemHovered();

            // Soft drop shadow (wf-vtab.is-active box-shadow: 2px 2px lineSoft) under
            // the active card.
            if (active) {
                ImVec4 sh = theme::col::lineSoft();
                dl->AddRectFilled(ImVec2(a.x + 2.0f * k, a.y + 2.0f * k),
                                  ImVec2(b.x + 2.0f * k, b.y + 2.0f * k),
                                  ImGui::GetColorU32(sh), rounding);
            }

            // Card body: active = panel-2-ish (brighter panel), inactive = panelHeader.
            ImVec4 bodyCol = active ? theme::col::panel() : theme::col::panelHeader();
            if (active) { bodyCol.x *= 1.10f; bodyCol.y *= 1.10f; bodyCol.z *= 1.10f; }
            else if (hovered) { bodyCol.x *= 1.06f; bodyCol.y *= 1.06f; bodyCol.z *= 1.06f; }
            dl->AddRectFilled(a, b, ImGui::GetColorU32(bodyCol), rounding);

            // Border: ink line; accent when active (wf-vtab.is-active border-color:ink,
            // brought toward accent for the workbench palette).
            ImU32 border = active ? ImGui::GetColorU32(acc)
                                  : ImGui::GetColorU32(theme::col::line());
            dl->AddRect(a, b, border, rounding, 0, (active ? 1.5f : 1.0f) * k);

            // Accent underline along the card bottom for the active section.
            if (active)
                dl->AddRectFilled(ImVec2(a.x + rounding, b.y - 2.0f * k),
                                  ImVec2(b.x - rounding, b.y),
                                  ImGui::GetColorU32(acc));

            // Content origin (after the left icon column).
            const float contentX = a.x + hpad + iconW;
            const float blockH   = labelSz.y + 2.0f * k + subSz.y;
            const float blockY   = a.y + (cardH - blockH) * 0.5f;

            // Left icon glyph, vertically centered in the card.
            if (drawIcon) {
                ImVec2 gsz = ui::gIconFontLarge->CalcTextSizeA(iconSz, FLT_MAX, 0.0f, ic);
                const ImVec4 igc = active ? acc : theme::col::muted();
                dl->AddText(ui::gIconFontLarge, iconSz,
                            ImVec2(a.x + hpad, a.y + (cardH - gsz.y) * 0.5f),
                            ImGui::GetColorU32(igc), ic);
            }

            // Label (bold-ish: normal text color when active, muted otherwise).
            // Ellipsize in compact mode so long labels never paint over neighbours.
            const ImVec4 labCol = active ? ImGui::GetStyleColorVec4(ImGuiCol_Text)
                                         : theme::col::muted();
            const float labelAvail = (std::max)(1.0f, (b.x - hpad) - contentX);
            std::string label = nm;
            if (ImGui::CalcTextSize(label.c_str()).x > labelAvail) {
                if (ImGui::CalcTextSize("...").x > labelAvail) label.clear();
                else {
                    while (label.size() > 1 &&
                           ImGui::CalcTextSize((label + "...").c_str()).x > labelAvail)
                        label.pop_back();
                    label += "...";
                }
            }
            dl->AddText(ImVec2(contentX, blockY), ImGui::GetColorU32(labCol), label.c_str());

            // Mono sub-text, ellipsized to the card width.
            {
                const float subAvail = (std::max)(1.0f, (b.x - hpad) - contentX);
                std::string st = sub;
                ui::PushMono();
                ImFont* mf = ImGui::GetFont();
                if (monoFont->CalcTextSizeA(subFontSz, FLT_MAX, 0.0f, st.c_str()).x > subAvail) {
                    if (mf->CalcTextSizeA(subFontSz, FLT_MAX, 0.0f, "...").x > subAvail) st.clear();
                    else {
                        while (st.size() > 1 &&
                               mf->CalcTextSizeA(subFontSz, FLT_MAX, 0.0f, (st + "...").c_str()).x > subAvail)
                            st.pop_back();
                        st += "...";
                    }
                }
                dl->AddText(mf, subFontSz, ImVec2(contentX, blockY + labelSz.y + 2.0f * k),
                            ImGui::GetColorU32(theme::col::muted()), st.c_str());
                ui::PopMono();
            }

            // Status badge at the card's top-right corner.
            bool   badge = false;
            ImVec4 bc(0, 0, 0, 1);
            if (std::strcmp(nm, "Communications") == 0 && dbg.attached()) {
                badge = true;
                bc = dbg.state == DbgState::Paused ? theme::col::warn() : theme::col::good();
            } else if (std::strcmp(nm, "Binary View") == 0 &&
                       (ctx_.analysis.bulkPending() || ctx_.livescan.busy())) {
                badge = true;   // pulsing "analysis running" dot (redraw already continuous)
                bc = acc;
                bc.w = 0.45f + 0.55f * (0.5f + 0.5f * std::sin((float)ImGui::GetTime() * 3.0f));
            }
            if (badge)
                dl->AddCircleFilled(ImVec2(b.x - 9.0f * k, a.y + 9.0f * k),
                                    4.0f * k, ImGui::GetColorU32(bc));

            if (clicked) activeTab_ = i;
            if (hovered) {
                if (i < 9) ImGui::SetTooltip("%s  (Ctrl+%d)", nm, i + 1);
                else       ImGui::SetTooltip("%s", nm);
            }
            ImGui::PopID();

            x += cardW + gap;
        }
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);   // WindowRounding + WindowPadding
}

void App::renderMainWindow(const DbgSnapshot& dbg) {
    // One fixed, full-size window: the horizontal tab-card strip above selects the
    // section, the content fills the rest. No docking, no floating panels - every
    // section always lives in the same place.
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float barH    = ToolbarHeight();                           // toolbar at top
    float stripH  = TabStripHeight();                          // tab-card strip below it
    float statusH = ImGui::GetFrameHeight() + 8.0f;            // status bar at bottom
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + barH + stripH));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, vp->WorkSize.y - barH - stripH - statusH));
    (void)dbg;   // section switching now lives in the tab-card strip band above

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
                             ImGuiWindowFlags_NoSavedSettings;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    // Zero window padding so the content sits flush against the tab strip/status
    // bar; the content child re-adds the normal padding for the section UIs.
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##main", nullptr, flags);
    ImGui::PopStyleVar();   // WindowPadding (only matters at Begin)

    // Cross-tab navigation: consume requestedTab BEFORE drawing, so menu items,
    // gotoAddress(), and scan-result clicks switch sections exactly as before.
    if (!ctx_.requestedTab.empty()) {
        for (int i = 0; i < (int)tabs_.size(); ++i)
            if (ctx_.requestedTab == tabs_[i]->name()) { activeTab_ = i; break; }
        ctx_.requestedTab.clear();
    }
    // Ctrl+1..9 jumps straight to a section (mirrors the tab-card tooltips).
    if (!ImGui::GetIO().WantTextInput && ImGui::GetIO().KeyCtrl)
        for (int i = 0; i < (int)tabs_.size() && i < 9; ++i)
            if (ImGui::IsKeyPressed((ImGuiKey)(ImGuiKey_1 + i))) activeTab_ = i;
    if (activeTab_ < 0 || activeTab_ >= (int)tabs_.size()) activeTab_ = 0;

    // PushID is load-bearing: BeginTabItem used to scope each tab's
    // "##tabcontent" ID (scroll position, child state); keep that per-section.
    ImGui::PushID(tabs_[activeTab_]->name());
    ImGui::BeginChild("##tabcontent", ImVec2(0, 0), ImGuiChildFlags_AlwaysUseWindowPadding);
    tabs_[activeTab_]->render(ctx_);
    ImGui::EndChild();
    ImGui::PopID();

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
        // Mono segments with thin dividers (wireframe wf-statusbar).
        ui::PushMono();
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
        if (d.attached()) { ImGui::SameLine(); ImGui::TextDisabled("pid %u  rip 0x%llX", d.pid, (unsigned long long)d.regs.rip); }

        ui::StatusDivider();
        ImGui::Text("%s", ctx_.disasm ? ctx_.disasm->engineName() : "-");
        ui::StatusDivider();
        ImGui::Text("%s", ArchName(ctx_.arch));
        ui::StatusDivider();
        if (ctx_.binary.loaded()) {
            const std::string& p = ctx_.binary.path();
            size_t slash = p.find_last_of("/\\");
            ImGui::Text("%s  (%s)", slash == std::string::npos ? p.c_str() : p.c_str() + slash + 1,
                        ctx_.binary.formatName());
        } else {
            ImGui::TextDisabled("no binary loaded");
        }
        if (ctx_.hasCursor) {
            ui::StatusDivider();
            if (!ctx_.cursorFuncName.empty())
                ImGui::Text("cursor 0x%llX  (%s)", (unsigned long long)ctx_.cursorVA, ctx_.cursorFuncName.c_str());
            else
                ImGui::Text("cursor 0x%llX", (unsigned long long)ctx_.cursorVA);
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
            ui::StatusDivider();
            ImGui::TextColored(theme::col::accent(), "%s", lbl);
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
            ui::StatusDivider();
            ImGui::TextColored(theme::col::good(), "%s", lbl);
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
        ui::PopMono();
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

// Build the Ctrl+K command palette: app actions (gated on the current state,
// mirroring the menu/toolbar handlers exactly) + a snapshot of the Binary
// View's symbol index for fuzzy goto.
void App::openCommandPalette(const DbgSnapshot& dbg) {
    using ui::PaletteItem;
    std::vector<PaletteItem> items;
    auto add = [&](const char* icon, const char* label, const char* detail, std::function<void()> fn) {
        PaletteItem it;
        it.label  = label;
        it.detail = detail ? detail : "";
        it.icon   = icon;
        it.run    = std::move(fn);
        items.push_back(std::move(it));
    };

    // File
    add(DS_ICON_FOLDER, "Open Binary...", "Ctrl+O", [this] { openFileDialog(); });
    add(DS_ICON_FOLDER, "Open as Raw...", "shellcode / firmware", [this] { openRawFileDialog(); });
    if (ctx_.binary.loaded()) {
        add(DS_ICON_SAVE, "Save Binary As (apply patches)...", "File", [this] { saveBinaryAs(); });
        add(nullptr, "Export Analysis (Markdown / HTML)...", "File", [this] {
            ctx_.requestedExportAnalysis = true;
            ctx_.requestedTab = "Binary View";
        });
        add(DS_ICON_CANCEL, "Close Binary", "File", [this] { closeBinary(); });
        if (ctx_.javaInfo.jarSize > 0) {
            add(DS_ICON_SAVE, ctx_.javaInfo.isJar ? "Extract Embedded JAR..." : "Extract Embedded ZIP...",
                "Java wrapper", [this] { extractEmbeddedJar(); });
        }
        if (!ctx_.javaInfo.entries.empty()) {
            add(DS_ICON_FOLDER, "Browse Embedded Archive...", "open / extract entries",
                [this] { ctx_.requestedBrowseArchive = true; });
        }
    }

    // Debug (gated on the snapshot, reusing the toolbar's exact calls)
    const bool attached = dbg.attached();
    const bool paused   = dbg.state == DbgState::Paused;
    const bool running  = dbg.state == DbgState::Running;
    if (!attached && ctx_.binaryLaunchable()) {
        add(DS_ICON_PLAY, "Launch & Debug", "break at entry", [this] {
            std::string err;
            if (!ctx_.launchAndDebug(err)) ui::Toast(ui::ToastKind::Error, "Launch failed: " + err);
        });
    }
    if (attached) {
        add(DS_ICON_STOP, "Detach", "Debug", [this] { ctx_.debug.detach(); });
        if (running) add(DS_ICON_PAUSE, "Pause", "F5", [this] { ctx_.debug.pause(); });
        else         add(DS_ICON_PLAY, "Continue", "F5", [this] { ctx_.debug.cont(); });
        if (paused) {
            add(nullptr, "Step Into", "F11", [this] { ctx_.debug.stepInto(); });
            add(nullptr, "Step Over", "F10", [this] { ctx_.debug.stepOver(); });
            add(nullptr, "Step Out", "Shift+F11", [this] { ctx_.debug.stepOut(); });
        }
    }

    // Sections (same switch the rail / Ctrl+N does)
    for (int i = 0; i < (int)tabs_.size(); ++i) {
        char lbl[64], det[16];
        std::snprintf(lbl, sizeof(lbl), "Go to: %s", tabs_[i]->name());
        if (i < 9) std::snprintf(det, sizeof(det), "Ctrl+%d", i + 1);
        else       std::snprintf(det, sizeof(det), "Section");
        std::string nm = tabs_[i]->name();
        add(nullptr, lbl, det, [this, nm] { ctx_.requestedTab = nm; });
    }

    // View: themes + density (mirrors the View menu, incl. prefs persistence)
    for (int i = 0; i < (int)theme::ThemeId::Count; ++i) {
        theme::ThemeId id = (theme::ThemeId)i;
        char lbl[64];
        std::snprintf(lbl, sizeof(lbl), "Theme: %s", theme::ThemeName(id));
        add(nullptr, lbl, "View", [this, id] { theme_ = id; theme::ApplyTheme(id); savePrefs(); });
    }
    {
        const theme::Density opts[] = { theme::Density::Compact,
                                        theme::Density::Comfortable,
                                        theme::Density::Spacious };
        for (theme::Density d : opts) {
            char lbl[64];
            std::snprintf(lbl, sizeof(lbl), "Density: %s", theme::DensityName(d));
            add(nullptr, lbl, "View", [this, d] {
                density_ = d;
                theme::SetDensity(d);
                theme::ApplyTheme();
                savePrefs();
            });
        }
    }

    // Symbol snapshot (palette owns the copies while open).
    std::vector<ui::PaletteSymbol> syms;
    if (binaryView_) {
        const auto& src = binaryView_->paletteSymbols(ctx_);
        syms.reserve(src.size());
        for (const auto& e : src) syms.push_back({ e.addr, e.name, e.lower, e.live });
    }
    palette_.open(std::move(items), std::move(syms));
}

bool App::wantsContinuousRedraw() {
    // Toasts fade out on a timer - freeze-frames would strand them on screen.
    if (ui::ToastsActive()) return true;
    // Background work in flight: progress spinners animate and results stream in.
    if (ctx_.analysis.bulkPending() || ctx_.livescan.busy()) return true;
    // An active debug session: the debug thread mutates the snapshot asynchronously
    // (breakpoint hits, steps) and the live view pulses the RIP/selection row.
    if (ctx_.debug.snapshot().attached()) return true;
    // A live JDWP (Java) session: events arrive asynchronously from the VM.
    if (ctx_.jdwp.snapshot().attached()) return true;
    // A tab asked to keep redrawing this frame (e.g. live connection monitor).
    if (ctx_.wantContinuousRedraw) return true;
    return false;
}

void App::render() {
    // Cleared each frame; a tab rendered this frame may set it to request that the
    // idle throttle keep redrawing (e.g. the live connection monitor's auto-refresh).
    ctx_.wantContinuousRedraw = false;
    // One lock-guarded debug snapshot per frame, shared by the toolbar and status bar
    // (each used to take its own deep copy of registers/threads/breakpoints).
    DbgSnapshot dbg = ctx_.debug.snapshot();
    // A debuggee that exited leaves the session "attached" to a dead process: the
    // debug thread is gone but the state stays Terminated, so the toolbar would
    // keep its (now dead) pause/step controls, Launch & Debug would never come
    // back, and the continuous-redraw throttle would spin forever. Finalize the
    // session here (the join is instant - the thread already returned) so the UI
    // drops back to the static state and the Binary View's detach edge releases
    // the per-session live caches + module registry.
    if (dbg.state == DbgState::Terminated) {
        ctx_.debug.detach();
        ui::Toast(ui::ToastKind::Info, "Debuggee exited - debug session ended");
        dbg = ctx_.debug.snapshot();
    }
    ctx_.frameDebugSnapshot = &dbg;
    struct ResetFrameDebugSnapshot {
        AppContext& ctx;
        ~ResetFrameDebugSnapshot() { ctx.frameDebugSnapshot = nullptr; }
    } resetFrameDebugSnapshot{ ctx_ };
    renderMenuBar();
    renderDebugToolbar(dbg);
    renderTabCardStrip(dbg);
    renderMainWindow(dbg);
    renderStatusBar(dbg);
    renderRawLoadPopup();

    // Binary View's Java banner can't open the Save dialog itself (it has no
    // access to App); it raises this flag instead (same pattern as
    // requestedExportAnalysis, but consumed here rather than in the tab).
    if (ctx_.requestedExtractJava) {
        ctx_.requestedExtractJava = false;
        extractEmbeddedJar();
    }

    // Same flag pattern for the archive-entries browser (banner button, File menu,
    // palette, and the standalone-.jar/.zip auto-open in loadBinaryPath).
    if (ctx_.requestedBrowseArchive) {
        ctx_.requestedBrowseArchive = false;
        openArchiveBrowser();
    }
    renderArchiveBrowser();

    // Ctrl+K command palette (toggle; safe unguarded - the chord types nothing).
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_K)) {
        if (palette_.isOpen()) palette_.close();
        else                   openCommandPalette(dbg);
    }
    palette_.render(ctx_);

    // Toast stack, bottom-right just above the status bar.
    ui::RenderToasts(ImGui::GetFrameHeight() + 8.0f);

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
