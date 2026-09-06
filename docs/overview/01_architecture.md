## 01. Architecture & Application Shell

DisasmStudio is a single-process, immediate-mode desktop application. There is no
web server, no embedded scripting runtime, and (by explicit design) no plugin API.
Everything runs in one Win32 process that owns a hardware Direct3D 11 device, drives
a Dear ImGui UI at the display refresh rate, and hangs all functional surfaces off a
fixed, browser-style top tab strip. This chapter covers the lowest two layers of the
stack: the **Win32 + D3D11 host** (`src/main.cpp`) and the **application shell**
(`src/App.h`, `src/App.cpp`, `src/Tabs/ITab.h`, `src/resource.h`, `src/app.rc`).

### The Win32 + Direct3D 11 host (`main.cpp`)

The program entry point is `wWinMain`. It is a Unicode `WinMain`, so the binary is a
GUI subsystem app (no console). `CommandLineToArgvW` reads an optional first target
argument and converts it to the UTF-8 path representation used by the loader; after
UI initialization that path is opened through the same `loadBinaryPath` flow as the
File menu. The rest of the flow is the canonical Dear ImGui
`example_win32_directx11` skeleton, adapted for this project:

1. **Register the window class** (`WNDCLASSEXW` with class name `DisasmStudioWnd`,
   `CS_CLASSDC`, `WndProc`). The class is given the embedded application icon: the
   large icon (`hIcon`) for alt-tab/taskbar and a separately sized small icon
   (`hIconSm`, sized via `GetSystemMetrics(SM_CXSMICON/SM_CYSMICON)`) for the
   window caption. Both come from resource `IDI_APPICON` via `LoadImageW` (see the
   icon section below).
2. **Create the top-level window** (`CreateWindowW`, `WS_OVERLAPPEDWINDOW`, initial
   1600×960) and **create the D3D11 device** (`CreateDeviceD3D`). On device-creation
   failure the code cleans up and returns `1` — there is no software-only ImGui
   fallback path.
3. The window is then shown **maximized** (`SW_SHOWMAXIMIZED`), matching the "fixed
   single full-window" UX intent.
4. **ImGui setup**: create the context; enable keyboard navigation, platform viewports,
   docking support, and `DpiEnableScaleViewports`; and point `io.IniFilename` at the
   durable `%APPDATA%\DisasmStudio\imgui.ini`. The app-owned workbench geometry remains
   explicit, while ImGui can preserve platform-window state and logical DPI geometry.
5. **Backends**: `ImGui_ImplWin32_Init(hwnd)` and `ImGui_ImplDX11_Init(device, ctx)`.
6. **Fonts** (`src/Ui/Fonts.h` globals `ds::ui::gUiFont` / `ds::ui::gMonoFont`): the
   host prefers crisp Windows system fonts — `segoeui.ttf` at `17px*dpi` for the
   proportional UI font and `consola.ttf` (or `cour.ttf`) at `16px*dpi` for the monospace
   code/hex font — checking each file exists first and falling back to the ImGui
   built-in font. The monospace handle may be null, in which case `PushMono()`
   callers fall back to the default font. This is why disassembly/hex views stay
   aligned: they explicitly push the monospace face.

`CreateDeviceD3D` builds a `DXGI_SWAP_CHAIN_DESC` with **two back buffers**,
`DXGI_FORMAT_R8G8B8A8_UNORM`, a 60 Hz refresh descriptor, and
`DXGI_SWAP_EFFECT_DISCARD`. It calls `D3D11CreateDeviceAndSwapChain` first with
`D3D_DRIVER_TYPE_HARDWARE` (the project's "must be GPU-accelerated" requirement), and
only if that returns `DXGI_ERROR_UNSUPPORTED` does it retry with
`D3D_DRIVER_TYPE_WARP` (Microsoft's software rasterizer) as a graceful degrade.
Feature levels requested are 11.0 then 10.0. `D3D11_CREATE_DEVICE_DEBUG` is added only
in `_DEBUG` builds. The render-target view is created from back-buffer 0 in
`CreateRenderTarget`.

**The render loop** is a classic `PeekMessage` pump:

- Drain all pending Win32 messages (`PeekMessage`/`TranslateMessage`/`DispatchMessage`);
  `WM_QUIT` ends the loop.
- **Deferred DPI rebuild**: after message draining and before a new ImGui frame, consume
  only the latest queued DPI, invalidate the old DX11 font objects, rebuild the atlas,
  rederive absolute theme metrics, and recreate the font texture. Failed creation remains
  queued and is retried without rendering against a missing texture.
- **Occlusion skip**: if the swapchain was occluded last frame and a
  `Present(0, DXGI_PRESENT_TEST)` still reports `DXGI_STATUS_OCCLUDED` (e.g. window
  minimized/covered), it `Sleep(10)`s and continues without rendering — saving GPU
  while hidden.
- **Deferred resize**: `WM_SIZE` only stashes the new width/height in
  `g_ResizeWidth/Height`; the loop performs the actual `ResizeBuffers` +
  `CreateRenderTarget`. If `ResizeBuffers` fails (device removed/reset), the RTV is
  left null and the frame is skipped rather than binding a dead target.
- **Frame**: `ImGui_ImplDX11_NewFrame` → `ImGui_ImplWin32_NewFrame` → `ImGui::NewFrame`
  → `app.render()` → (exit check) → `ImGui::Render`. If the RTV is valid it is bound
  and cleared to a near-black color `(0.07, 0.08, 0.10)` (pre-multiplied by alpha),
  then `ImGui_ImplDX11_RenderDrawData` draws the UI.
- **Present** with `Present(1, 0)` — vsync **on** — and the occluded flag is updated
  from the result. Vsync caps the frame rate to the display, keeping the app smooth
  without spinning the GPU.

`WndProc` first forwards every message to `ImGui_ImplWin32_WndProcHandler` so ImGui
receives input. It then handles `WM_SIZE` (ignoring `SIZE_MINIMIZED`), suppresses the
ALT application menu (`WM_SYSCOMMAND` / `SC_KEYMENU` returns 0 so ALT-key chords like
`Alt+←/→` are free for navigation), and posts quit on `WM_DESTROY`. For
`WM_DPICHANGED`, it applies Windows' suggested rectangle and stores only the latest DPI;
font/style/DX11 resource mutation remains outside `WndProc` at the between-frame boundary.

#### Embedded application icon (`app.rc`, `resource.h`)

`src/resource.h` defines exactly one identifier: `IDI_APPICON = 101`. The comment
notes it is intentionally the lowest-numbered icon resource so Windows Explorer uses
it as the executable's shell icon. `src/app.rc` declares
`IDI_APPICON ICON "app.ico"` (a multi-resolution `.ico`, regenerated by
`gen_app_icon.ps1`) plus a `VS_VERSION_INFO` block (file/product version `1.0.0.0`,
company/product `DisasmStudio`, `OriginalFilename DisasmStudio.exe`). The icon is thus
embedded into the EXE and loaded at startup for window, taskbar, and alt-tab use.

### The application shell: `App` and `AppContext`

`ds::App` is the top-level controller, instantiated once on the stack in `wWinMain`.
Its constructor (`App()`):

- `loadPrefs()` reads `%APPDATA%/DisasmStudio/prefs.ini` (a bounded `key=value` file storing
  theme/density, the opt-in symbol policy/cache, and up to 32 encoded investigation queries)
  and `theme::ApplyTheme(theme_)` restyles ImGui. Symbol-network access remains disabled by
  default.
- The initial scratch `DocumentContext` owns its decoder and empty analysis image.
- It constructs the **ten workbench sections in fixed order** and stores them as
  `std::vector<std::unique_ptr<ITab>>`: `ProjectsTab`, `CommunicationsTab`,
  `ConnectionsTab`, `SigScannerTab`, `BinaryViewHostTab`, `MemoryToolsTab`,
  `BinaryDiffTab`, `BinaryTechTab`, `CortexTab`, and `PrismTab`. This vector is the
  workbench-section order. `BinaryViewHostTab` retains one complete `BinaryViewTab`
  child per open static document.

The destructor (`~App()`) first asks the active Binary View child to mirror its retained
UI state, then calls `ctx_.saveProject()` so analysis is flushed when the window closes
(Alt+F4 / WM_DESTROY path).

#### `AppContext` — shared services and the active-document facade

`AppContext` is passed **by reference** to every tab's `render` each frame. It owns
app-global live services and a private `DocumentManager`; legacy tabs see the manager's
active document through narrow accessors rather than owning singleton static-analysis
state. Key members:

- `Debugger debug` — the live Win32 debugger (own thread, lock-guarded snapshot).
- `JdwpClient jdwp`, `LiveScanService livescan`, `ModuleRegistry modules`, and the
  app-global live-module analysis pool — these stay attached when the active static
  document changes.
- `DocumentManager documents_` — up to eight stable-ID static `DocumentContext`s. Each
  context owns its `BinaryFile`, project, decoder configuration, `AnalysisService`,
  `CodeExportService`, derived metadata, navigation state, and image generation.
- `staticBinary()`, `staticProject()`, `staticAnalysis()`, `staticCodeExport()`, and the
  other `static*` accessors — a compatibility facade for the document that is active at
  the current frame boundary. No tab may retain the returned object across a topology
  command.
- **Cross-tab request flags**: `requestedTab` (name of a tab to switch to next
  frame), `requestedLiveAssembly`, `requestedExportAnalysis`, `requestedCodeExport`
  plus `requestedCodeExportFormat`, `requestedDebugDll`, the trace toggle/clear/cancel
  flags, `binaryJustLoaded`, and `pendingSignature`
  (Binary View → Sig Scanner pattern handoff).
- **Go-to plumbing**: `requestedGotoVA` + `hasGotoRequest` (the bool distinguishes
  "go to VA 0" from "no request"). The helper `gotoAddress(va)` sets both and forces
  `requestedTab = "Binary View"` — this is the single canonical way any tab asks the
  app to focus an address.
- **Cursor mirroring**: `cursorVA`, `hasCursor`, `cursorFuncName` (enclosing function),
  and `runtimeCursorVA` (ASLR-translated address for "Run to Cursor", or zero when a
  static cursor has no exact matching x86/x64 module). Binary View's
  real cursor is private; it copies it here each frame so the status bar and debug
  toolbar can read it without reaching into the tab.

`AppContext` also owns the high-level commands shared across tabs:
`rebuildDisassembler()`, `openBinaryDialog()` (Win32 `commdlg` open),
`loadBinaryPath()`, `loadRawPath()`, `saveProject()`, `exportAnalysisFile()`,
`selectCodeExportPath()`, and `openLiveAssemblyView()`. Static open, activation, and
close requests are staged as one bounded pending topology command and committed only
after every tab has returned for the frame.

Direct launch eligibility deliberately distinguishes PE executables from DLLs:
`binaryLaunchable()` excludes `IMAGE_FILE_DLL`, while `binaryDllDebuggable()` requires
a file-backed x86/x64 PE DLL. The latter routes to the App-owned Debug DLL modal and
the validated hosted-launch plan instead of ever passing a DLL to `CreateProcessW`.

#### Binary loading & project lifecycle

`loadBinaryPath(path)` is the spine of opening a file, but it no longer mutates the
active document during a tab's render call:

1. Build and validate a complete staged `BinaryFile`, including backward-compatible raw
   mapping restoration and the selected architecture/decoder.
2. Load the matching project sidecar into the staged document and stamp fresh metadata.
3. Queue one `Open` topology command. The current document and its workers remain valid
   for the rest of the frame.
4. At the end-of-frame barrier, ask `BinaryViewHostTab` to mirror the outgoing child's UI
   state, then synchronously verify the exact asynchronous-save ticket for that document.
5. Publish through `DocumentManager::openStaged`. A duplicate pristine hash activates the
   existing document; otherwise a new stable-ID document is created up to the eight-document
   cap. Only after successful publication does the active compatibility facade change.
6. Retire the initial scratch after the first successful real open. On failure, keep the
   previous document active and preserve any producing workflow's result/error UI.

Closing follows the same prepare/save barrier and cancels and joins the closing document's
analysis, export, investigation, and symbol work before releasing its binary storage. Closing
the last document first creates a replacement scratch, so the active facade is never dangling.
Static topology changes do not detach the global Win32 debugger, JDWP connection, Prism
collector, or live-module registry.

Every worker result that can outlive a frame carries an exact document/image identity. Image
generation, decoder configuration, and service epoch checks reject stale results after a
reload, switch, or close; these checks complement, but never replace, joining a worker before
its borrowed image storage is released.

`openRawFileDialog()` first reads the selected file for a bounded firmware probe. The
interactive read is skipped above **512 MiB** (manual raw loading remains available);
`SniffFirmware` itself scans at most **64 MiB** of deterministic head/tail signature
windows by default while still performing its fixed-location reset-vector and flash-
descriptor checks. It reports confidence and evidence for legacy BIOS, PI/UEFI firmware
volumes, PCI option ROMs, and Intel Flash Descriptor images. Recommendations include a
top-of-4-GiB mapping for system firmware or `0xC0000` for a standalone option ROM, an
  x86-16/x86/x64 mode, and a boot target recovered through a bounded chain of common x86
  short/near/far jumps. These are suggestions, not loader facts.

A separate bounded motif scorer can recommend A32, Thumb/Thumb-2, or A64 when aligned call,
frame, and return evidence is coherent and clearly stronger than the competing modes. It
leaves ambiguous/random data unclassified and uses a 32-bit-safe default mapping for A32 or
Thumb so immediate branch targets remain representable.

The raw modal makes the **base, entry point, and architecture** editable, offers
**x86-16 real mode** alongside x86/x64/A32/Thumb/A64, can restore the detector defaults,
shows the evidence, and offers **Seed named code landmarks**. Only landmarks marked as
code are forwarded; the analyst-selected entry is always seeded if it is not already
present. The loader accepts VA 0, rejects a base+size overflow, and requires the entry
and every seed to be backed by bytes in the staged raw image. A32/Thumb mappings must fit
entirely below 4 GiB; both later architecture selectors disable those modes for an
already-loaded high-base raw image.

`loadRawPath(path, base, arch, entryVA, landmarks, firmware)` stages a temporary
`BinaryFile`, installs the explicit entry and named landmarks, and validates all of it
*before* queuing an open. Its staged project load deliberately keeps the dialog's
architecture choice authoritative over a saved decoder value. The approved detector
result is installed as metadata on the new `DocumentContext` only if publication succeeds.

`saveProject()` serializes the active document through an origin ticket containing its
stable document ID and image generation. It waits for any older asynchronous write before
starting the replacement snapshot, uses the atomic project writer, and acknowledges or
rejects the result on that exact origin document. Ephemeral live-memory documents are
marked clean without creating unusable sidecars.

### Per-frame rendering: `App::render()`

Called exactly once per loop iteration, `render()` draws the shell top-to-bottom:
`renderMenuBar()` → `renderDocumentStrip()` → `renderDebugToolbar()` →
`renderTabCardStrip()` → `renderMainWindow()` → `renderStatusBar()` → modal/tool
windows → investigation/palette maintenance → the document-command barrier, plus the
optional ImGui demo and About windows. The full-width bars are positioned manually against
`ImGui::GetMainViewport()` work area: a static-document strip and debug toolbar at the top,
the section-card strip below them, the main content window in the middle, and the status bar
pinned to the bottom. The shell windows are flagged
`NoTitleBar | NoResize | NoMove | NoSavedSettings | NoDocking` (the main window adds
`NoBringToFrontOnFocus | NoNavFocus`) and pushed to `WindowRounding = 0` so they read
as fixed chrome, not floating panels.

#### Menu bar (`renderMenuBar`)

A standard `BeginMainMenuBar`:

- **File**: *Open Binary…* (Ctrl+O, `openFileDialog`), *Open as Raw…*
  (`openRawFileDialog`), *Debug DLL…* (only for a validated file-backed x86/x64 PE
  DLL), *Save Binary As…* (enabled only when loaded; splices
  accumulated patches — see below), *Export Analysis…* (sets
  `requestedExportAnalysis` + switches to Binary View, which produces the report),
  *Close Document* (queued close with an exact save barrier), and *Exit* (mirror +
  flush before setting `exit_`). Disabled items carry hover tooltips (`AllowWhenDisabled`).
- **Engine**: Zydis / Capstone toggle and an Architecture submenu (x86-16, x86, x64, A32,
  Thumb/Thumb-2, A64, MIPS, MIPS64, PowerPC, PowerPC64, RISC-V 32, RISC-V 64). For non-x86 arches
  Zydis is disabled (it decodes the x86 family, including true 16-bit mode) and the check marks reflect the
  **effective** engine (`disasm->engine()`), so the menu never disagrees with what is
  actually decoding. Any effective ISA change calls `rebuildDisassembler()`, invalidates
  every decode-derived Binary View cache, and launches one epoch-consistent full analysis
  rebuild; a cosmetic non-x86 engine toggle does not discard identical Capstone results.
- **View**: Theme submenu (iterates `theme::ThemeId` up to `Count`, applies + persists
  via `savePrefs()`) and an *ImGui Demo* toggle.
- **Help**: *Keyboard Shortcuts* (F1, a grouped global/debugger/navigation/view
  reference) and *About* (version, feature overview, and runtime stack).
- A right-aligned status string (`Engine: … | <format or "no binary">`) is laid out by
  measuring text width and `SameLine`-offsetting from the window width.

#### Debug toolbar (`renderDebugToolbar`)

A full-width borderless window at the top. It reads a `DbgSnapshot` from the Debugger
and branches on attach state. When detached: an executable shows **Launch & Debug**
(calls `debug.launchAndAttach`), while a DLL opens **Debug DLL…** instead; successful
launches open the live assembly view and failures become toasts. Otherwise it shows a hint to attach via the
Communications tab. When attached it shows **Detach**, **Continue/Pause** (label and
color flip with run state), **Step Into / Step Over / Step Out / Run to Cursor** (the
stepping buttons disabled unless paused), plus **Trace / Clear Trace**. Trace is
startable only while paused with an analyzed image that has an exact matching x86/x64
module/bitness mapping, remains stoppable during discovery or planting, and forwards its
request to Binary View's incremental block planner. A live status line shows PID, bitness,
state, RIP/EIP, RSP/ESP, and the last debug event. Keyboard shortcuts are bound here
(only when ImGui is not capturing text input): **F5** continue/pause, **F11** step
into, **Shift+F11** step out, **F10** step over, **Ctrl+F9** run to cursor (using
`runtimeCursorVA`). A `cbutton` lambda gives each button a base color plus auto
hover/active tints and an optional tooltip.

#### Main window & the tab strip (`renderMainWindow`)

This realizes the "browser-style single window, no docking" design. One fixed
full-size child window holds an `ImGui::BeginTabBar` (`Reorderable | FittingPolicyScroll`).
It iterates `tabs_` and, for each, checks whether `ctx_.requestedTab == tab->name()`;
if so it passes `ImGuiTabItemFlags_SetSelected` (programmatic tab switch) and clears
the request. The selected tab's content is rendered inside a padded child
(`##tabcontent`) via `tab->render(ctx_)`. There is no docking, no tear-off, no floating
windows — tabs always live in the same place.

#### Status bar (`renderStatusBar`)

A bottom bar with a hand-drawn colored **state dot** (drawn with
`AddCircleFilled` so it needs no font glyph) reflecting debug state (muted/green/amber/red
→ detached/running/paused/bad), the state word, PID/RIP when attached, the engine name,
the arch name, the loaded file's base name + format, and — when `hasCursor` — the cursor
VA and enclosing function name. It reads everything from `ctx_`; the cursor info is the
mirrored copy Binary View writes each frame.

#### Modal popups

`renderRawLoadPopup` is the firmware-aware raw modal described above. Its base and entry
inputs accept `0x`-prefixed or bare hexadecimal values; detected mapping/mode/entry values
are prefilled but remain editable. It displays bounded evidence, supports restoring those
defaults and opting into named code-landmark seeding, then calls the validating
`loadRawPath` path and switches to Binary View. `renderSaveResultPopup` shows the result
message from *Save Binary As…*.

`renderDllDebugPopup` inspects the current image with `InspectDllForDebug`, offers a
callable export and user arguments, selects the bitness-matched trusted system
`rundll32.exe` or a browsed/bitness-checked custom host, and lets the analyst arm
DllMain and/or export stops. It displays planning warnings/errors before enabling
launch, then calls `Debugger::launchAndAttachDll` with the Windows-quoted plan.

#### Save Binary As — patch splicing

`saveBinaryAs()` opens a save dialog and calls the free function `buildPatchedImage`,
which copies `binary.bytes()` and, for each accumulated `PjPatch`, resolves its VA to a
file offset with `BinaryFile::vaToOffset`; patches that don't map or run past the buffer
are skipped and counted. The result is written to disk and the modal reports
"Wrote N bytes with M patch(es) applied[, K unmapped/skipped]". This is how
user edits become a real on-disk modified binary.

### The `ITab` contract & tab dispatch

`src/Tabs/ITab.h` defines a minimal interface: a virtual destructor,
`const char* name() const`, and `void render(AppContext& ctx)`. Each concrete tab
(`ProjectsTab`, etc.) is a `final` class deriving from `ITab`, returning its display
name and rendering itself given the shared context. The App owns the tabs as
`unique_ptr`s and dispatches them polymorphically inside the tab bar each frame. The
name string is doubly load-bearing: it is both the tab label *and* the key used by
`requestedTab` for cross-tab navigation — so `gotoAddress`, `openLiveAssemblyView`,
and the File-menu commands all coordinate purely through these string names plus the
boolean request flags on `AppContext`.

### Data flow & frame contract (summary)

Each frame, tabs read `ctx_`, write bounded request flags, and mirror active-view state.
`BinaryViewHostTab` renders only the child matching the frame's active `DocumentId`; inactive
children retain their independent navigation and analysis UI state. The App consumes ordinary
cross-tab requests during the frame, then applies at most one queued static-document topology
command after all tabs and modals have released borrowed references. Close wins over activation
when both are requested in one frame.

Background concurrency lives in the debugger/JDWP owners, per-document analysis/export/symbol
services, the host-owned investigation work, and app-global live-module services. Results are
adopted only when their document ID, image generation, decoder identity, and worker epoch still
match. The debugger session generation separately retires stale live-module analysis on detach
or reattach.

Full-listing requests add a second, narrower stale-work guard. Binary View passes
`AnalysisService::requestBulkWithListing` a `shared_ptr<const ListingLayout>` plus an
independent `listingRevision`. A visibility/fold toggle, manual rebuild, or manual
**Define Function** advances that revision immediately; the worker plans rows against
the immutable snapshot, and the UI atomically adopts only a result whose epoch *and*
listing revision still match. An obsolete layout can therefore be dropped without
cancelling unrelated function/string/xref work for the same image, and no full image
sweep is performed on the render thread.

Deterministic derived passes also share a bounded in-memory `AnalysisCache`. Its key
contains the pristine content hash, order-sensitive patch digest, exact architecture,
effective decoder backend, analysis-schema version, name-guess policy, authoritative
override digest, pass kind, and pass-specific immutable-input digest. The cache is a
thread-safe LRU bounded by both entry count and approximate retained bytes. Workers own
all lookup-time snapshot hashing and result cloning; a hit is still retagged with the
current epoch/listing revision and passes through the ordinary stale-result checks.

#### Limitations & notes

- **App-owned workbench layout**: the bars/panels are explicitly positioned rather than
  exposed as a user dockspace; ImGui's platform/layout state still persists in its ini file.
- **No plugin/scripting API**: excluded by project spec; the shell offers no extension
  point — tabs are compiled in.
- ImGui platform viewports and DPI geometry scaling are enabled, while the workbench's
  browser-style panel arrangement remains an explicit app layout rather than a user dockspace.
- **Hardware-first, WARP fallback**: if no D3D11 hardware device is available the app
  silently falls back to the WARP software rasterizer; if even that fails, startup aborts.
- The raw modal directly offers x86-16/x86/x64/A32/Thumb/A64; MIPS/PPC/RISC-V raw blobs can
  still be switched to their exact architecture through the Engine menu after loading.
- Firmware classification, mapping, CPU mode, and recovered entry are evidence-backed
  recommendations. A negative/ambiguous probe never prevents a manual raw load, and the
  analyst can edit every proposed value before the staged mapping is validated.
- Cross-tab state is a per-frame flag handshake, not a robust event bus; it works
  because the whole UI is single-threaded immediate mode, but it means requests are
  effectively "fire on the next frame" and one-shot.
