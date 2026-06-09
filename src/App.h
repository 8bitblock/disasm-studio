#pragma once
//
// App.h
// Top-level application shell: owns shared state (loaded binary, debug
// controller, active disassembler engine) and the collection of tabs. Renders
// the menu bar, the debug-control toolbar, and the docked tab windows.
//
#include <memory>
#include <string>
#include <vector>

#include "Core/AnalysisService.h"
#include "Core/BinaryFile.h"
#include "Core/Debugger.h"
#include "Core/LiveScanService.h"
#include "Core/ModuleRegistry.h"
#include "Core/Project.h"
#include "Disasm/DisassemblerFactory.h"
#include "Ui/Theme.h"

namespace ds {

class ITab;

// Shared, app-wide state passed by reference to every tab.
struct AppContext {
    BinaryFile                     binary;
    Debugger                       debug;
    // Live-memory scan worker pool (process string scan / xref sweep / module-image
    // reads, off the render thread). Declared AFTER `debug` so its dtor joins the
    // workers before the Debugger — whose readMemoryMasked the workers call — is gone.
    LiveScanService                livescan{ [](Engine e, Arch a) { return MakeDisassembler(e, a); } };
    Engine                         engine = Engine::Zydis;
    Arch                           arch   = Arch::X64;
    std::unique_ptr<IDisassembler> disasm;
    std::string                    requestedTab;
    bool                           requestedLiveAssembly = false;
    bool                           requestedExportAnalysis = false; // File > Export Analysis, consumed by Binary View
    bool                           binaryJustLoaded      = false; // set on load, consumed by Binary View
    uint64_t                       requestedGotoVA       = 0;     // cross-tab "view this address" request
    bool                           hasGotoRequest        = false; // distinguishes "go to VA 0" from "no request"
    bool                           requestedGotoLive     = false; // goto target is a runtime VA -> open the live view (no file-VA translation)
    std::string                    pendingSignature;             // Binary View -> Sig Scanner pattern handoff
    bool                           pendingSignatureLive  = false; // pendingSignature was built from live process memory -> scan live, not the file

    // Binary View cursor, mirrored here each frame so the status bar can show it
    // (the tab's cursorVA_ is private). cursorFuncName is the enclosing function.
    uint64_t                       cursorVA       = 0;
    bool                           hasCursor      = false;
    std::string                    cursorFuncName;
    // Runtime (ASLR-translated) cursor address for the debug toolbar's Run to Cursor.
    // Equals cursorVA in the static view; the live view sets it to the runtime VA.
    uint64_t                       runtimeCursorVA = 0;

    // Ask the Binary View to focus an address (from another tab). Also switches
    // to the Binary View tab.
    void gotoAddress(uint64_t va) { requestedGotoVA = va; hasGotoRequest = true; requestedTab = "Binary View"; }

    // Like gotoAddress, but `va` is a live (ASLR-relocated) runtime address — e.g. a
    // live-mode Sig Scanner hit. The Binary View opens the live view at it instead of
    // feeding the runtime VA into the file-VA static listing (which would land on the
    // wrong bytes for a relocated process).
    void gotoAddressLive(uint64_t va) { requestedGotoVA = va; hasGotoRequest = true; requestedGotoLive = true; requestedTab = "Binary View"; }

    // Per-binary analysis state (comments, renames, bookmarks, breakpoints,
    // patches, notes, cursor) persisted as a JSON sidecar keyed by content hash.
    ProjectState                   project;

    // All modules of the attached process (the whole app: EXE + DLLs), each loadable
    // from live memory into the disassembler. Declared BEFORE `analysis` so the worker
    // pool's threads are joined before the registry frees the module images they read.
    ModuleRegistry                 modules;

    // Background analysis worker (string scan + function discovery/naming, etc.) so
    // loading a large binary doesn't freeze the UI. Declared after `binary`, so it is
    // destroyed (its thread joined) before `binary`'s bytes are freed. The worker
    // builds its own decoder via this factory and never shares `disasm`.
    AnalysisService                analysis{ [](Engine e, Arch a) { return MakeDisassembler(e, a); } };

    void rebuildDisassembler() {
        disasm = MakeDisassembler(engine, arch);
        // The Debugger owns its own decoder, so it is not wired to the UI engine.
    }

    void openLiveAssemblyView() {
        requestedTab = "Binary View";
        requestedLiveAssembly = true;
    }

    // Opens a Win32 file dialog and loads the chosen binary. Returns true on
    // success. Defined in App.cpp (uses commdlg). Callable from any tab.
    bool openBinaryDialog();

    // Load a binary by path (saving the current project first, picking the arch
    // from the file header, and loading any saved analysis). Shared by the file
    // dialog and the Projects tab. Returns false if the file can't be loaded.
    bool loadBinaryPath(const std::string& path);
    // Load a flat code blob at `base` with an explicit arch (raw shellcode mode).
    bool loadRawPath(const std::string& path, uint64_t base, Arch a);
    // Load one module of the attached process into the disassembler by reading its
    // mapped image straight from live memory (BinaryFile::loadFromMemory). Picks the
    // arch from the PE machine field, makes the module the active registry entry, and
    // triggers the normal load-time analysis. Not sidecar-persisted (live image).
    // Returns false if not attached or the image can't be read.
    bool loadLiveModule(uint64_t base, uint64_t size, const std::string& name);
    // Kick off background analysis of a registry module whose image is already loaded
    // (its `bin` populated, e.g. by an "analyze all modules" ReadImage). Tags the job
    // with the module base so its results route to the registry's per-module cache.
    void analyzeModule(LoadedModule& m, bool guess);

    // Persist the current project to its sidecar (no-op if nothing is loaded).
    void saveProject();

    // Open a Save dialog (Markdown / HTML) and write the chosen analysis report.
    // The format is picked from the chosen file's extension. Returns true on
    // success; `msg` receives a human-readable result. Defined in App.cpp (commdlg).
    bool exportAnalysisFile(const std::string& defaultBaseName,
                            const std::string& markdown, const std::string& html,
                            std::string& msg);

private:
    // After binary is loaded: hash it, pull any saved sidecar into `project`,
    // and stamp fresh metadata. Resets `project` when there is no sidecar. When
    // `applySavedArchEngine` is true, a saved engine/arch choice is reapplied to
    // the live context (so a binary reopens as last analyzed); the raw-load path
    // passes false so the arch the user just picked in the dialog wins.
    void loadProjectForBinary(bool applySavedArchEngine = true);
};

class App {
public:
    App();
    ~App();

    void render();              // called once per frame
    bool wantsExit() const { return exit_; }

    // True when the UI should keep redrawing every frame rather than sleeping until
    // the next input event: background analysis / live-scan in progress (progress
    // spinners + incoming results), or an active debug session (async state changes
    // + the pulsing RIP/selection highlight). Drives the main loop's idle throttle.
    // Non-const: Debugger::snapshot() takes a lock.
    bool wantsContinuousRedraw();

private:
    void renderMenuBar();
    void renderDebugToolbar(const DbgSnapshot& snap);
    void renderMainWindow();
    void renderStatusBar(const DbgSnapshot& snap);
    void openFileDialog();
    void openRawFileDialog();   // pick a file, then prompt for base + arch
    void renderRawLoadPopup();
    void saveBinaryAs();        // splice accumulated patches into a copy on disk
    void renderSaveResultPopup();
    void loadPrefs();           // read persisted UI prefs (theme) from %APPDATA%
    void savePrefs() const;     // write them back

    AppContext                          ctx_;
    std::vector<std::unique_ptr<ITab>>  tabs_;
    bool                                exit_      = false;
    bool                                showDemo_  = false;
    bool                                showAbout_ = false;
    theme::ThemeId                      theme_     = theme::ThemeId::Midnight;

    // Raw-load prompt state.
    bool                                openRawPopup_ = false;
    std::string                         rawPendingPath_;
    char                                rawBaseBuf_[32] = "0x140000000";
    int                                 rawArchSel_   = 1;   // 0=x86 1=x64 2=ARM 3=ARM64

    // Save-binary result message.
    bool                                openSaveResult_ = false;
    std::string                         saveResultMsg_;

    // Last "Launch & Debug" error, shown in the toolbar until the next launch.
    std::string                         launchMsg_;
};

} // namespace ds
