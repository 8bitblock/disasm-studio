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
#include "Core/JavaScan.h"
#include "Core/JdwpClient.h"
#include "Core/LiveScanService.h"
#include "Core/ModuleRegistry.h"
#include "Core/Project.h"
#include "Core/RuntimeScan.h"
#include "Disasm/DisassemblerFactory.h"
#include "Disasm/JvmDisassembler.h"   // AttachJvmClass (JavaClass symbolication)
#include "Ui/CommandPalette.h"
#include "Ui/Theme.h"

namespace ds {

class ITab;
class BinaryViewTab;

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
    bool                           requestResetDockLayout = false; // View > Reset Layout, consumed by Binary View's dockspace
    bool                           requestedExportAnalysis = false; // File > Export Analysis, consumed by Binary View
    bool                           binaryJustLoaded      = false; // set on load, consumed by Binary View
    uint64_t                       requestedGotoVA       = 0;     // cross-tab "view this address" request
    bool                           hasGotoRequest        = false; // distinguishes "go to VA 0" from "no request"
    bool                           requestedGotoLive     = false; // goto target is a runtime VA -> open the live view (no file-VA translation)
    std::string                    pendingSignature;             // Binary View -> Sig Scanner pattern handoff
    bool                           pendingSignatureLive  = false; // pendingSignature was built from live process memory -> scan live, not the file

    // Live JVM debugger (JDWP over a socket): attach via the Communications
    // tab's "Java debug (JDWP)" console. Independent of `debug` (the Win32
    // debugger) — a JVM target can have both attached at once (native frames
    // via debug, bytecode-level control via jdwp).
    JdwpClient                     jdwp;
    // PID of the JVM the JDWP session is attached to (0 = none). JDWP itself is a
    // socket and carries no PID, so the inject path records it here so other views
    // (e.g. the Connections tab's "attached process only") can scope to it.
    uint32_t                       jdwpTargetPid = 0;

    // Java wrapper / embedded-JAR detection for the loaded binary. Recomputed on
    // every load (cheap, synchronous after cancelAndWaitIdle) and deliberately
    // NOT persisted to the sidecar. kind == None for non-Java targets.
    JavaScanResult                 javaInfo;
    // Multi-runtime wrapper/container verdict (RuntimeScan over javaInfo).
    // Recomputed with javaInfo on every load; not persisted.
    RuntimeScanResult              runtimeInfo;
    bool                           requestedExtractJava  = false; // banner button -> App::extractEmbeddedJar (same pattern as requestedExportAnalysis)
    bool                           requestedBrowseArchive = false; // banner/menu -> App opens the archive-entries popup

    // A tab sets this true during render() when it needs the UI to keep redrawing
    // even while idle (e.g. the live connection monitor's auto-refresh). Reset to
    // false at the top of every App::render(), so only a tab rendered this frame
    // can keep it on. Read by App::wantsContinuousRedraw().
    bool                           wantContinuousRedraw = false;

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
        // Java class: attach the parsed class file so the UI decoder resolves
        // constant-pool operands (no-op for every other backend).
        if (arch == Arch::JVM && binary.javaClass())
            AttachJvmClass(*disasm, binary.javaClass());
        // The Debugger owns its own decoder, so it is not wired to the UI engine.
    }

    void openLiveAssemblyView() {
        requestedTab = "Binary View";
        requestedLiveAssembly = true;
    }

    // True when Launch & Debug can hand the loaded binary to CreateProcess: a PE
    // image opened from disk. Live memory mappings have no launchable file behind
    // them, and Windows can't start ELF/Mach-O/.class/raw images directly.
    bool binaryLaunchable() const {
        return binary.loaded() && !binary.isMappedImage() &&
               (binary.format() == BinFormat::PE32 || binary.format() == BinFormat::PE32Plus);
    }

    // Launch the loaded binary under the debugger (break at entry) and open the
    // live view. The one shared path for the toolbar / command palette / Binary
    // View Run button. Returns false with `err` set on failure.
    bool launchAndDebug(std::string& err) {
        if (!debug.launchAndAttach(binary.path(), err)) return false;
        openLiveAssemblyView();
        return true;
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
    void renderMainWindow(const DbgSnapshot& snap);
    void renderTabCardStrip(const DbgSnapshot& snap);  // horizontal tab-card strip (section switcher)
    void renderStatusBar(const DbgSnapshot& snap);
    void openCommandPalette(const DbgSnapshot& snap);  // build the Ctrl+K action list + symbol snapshot
    void openFileDialog();
    void openRawFileDialog();   // pick a file, then prompt for base + arch
    void renderRawLoadPopup();
    void saveBinaryAs();        // splice accumulated patches into a copy on disk (result -> toast)
    void extractEmbeddedJar();  // carve ctx_.javaInfo's jar/zip span to a file (result -> toast)
    void openArchiveBrowser();  // snapshot ctx_.javaInfo's archive into archiveBrowser_ + open the popup
    void renderArchiveBrowser(); // "Archive Entries" modal: list / open-as-binary / extract one entry
    void extractArchiveEntryToFile(const JavaZipEntry& e);  // Save dialog writing the DECOMPRESSED entry bytes
    void loadPrefs();           // read persisted UI prefs (theme) from %APPDATA%
    void savePrefs() const;     // write them back
    void closeBinary();         // flush + unload the current binary (menu / file tab / palette)

    AppContext                          ctx_;
    std::vector<std::unique_ptr<ITab>>  tabs_;
    BinaryViewTab*                      binaryView_ = nullptr;  // typed handle into tabs_ (symbol source for the palette)
    ui::CommandPalette                  palette_;               // Ctrl+K command palette
    int                                 activeTab_ = 0;   // index into tabs_ (rail selection)
    bool                                exit_      = false;
    bool                                showDemo_  = false;
    bool                                showAbout_ = false;
    theme::ThemeId                      theme_     = theme::ThemeId::Paper;
    theme::Density                      density_   = theme::Density::Comfortable;

    // Raw-load prompt state.
    bool                                openRawPopup_ = false;
    std::string                         rawPendingPath_;
    char                                rawBaseBuf_[32] = "0x140000000";
    int                                 rawArchSel_   = 1;   // 0=x86 1=x64 2=ARM 3=ARM64

    // Archive-entries browser state, snapshotted at open time: "Open as binary"
    // replaces the loaded binary while the popup is up, so entry extraction always
    // re-reads sourcePath from disk instead of touching ctx_.binary.
    struct ArchiveBrowserState {
        bool        open = false;          // open-request flag, consumed by renderArchiveBrowser
        std::string sourcePath;            // file containing the archive (UTF-8, as BinaryFile::path)
        std::string sourceName;            // display base name of sourcePath
        uint64_t    zipBase = 0;           // file offset of the zip start (javaInfo.jarOffset)
        std::vector<JavaZipEntry> entries; // central-directory snapshot (capped upstream)
        char        filter[128] = {};
        int         selected = -1;
    };
    ArchiveBrowserState                 archiveBrowser_;

};

} // namespace ds
