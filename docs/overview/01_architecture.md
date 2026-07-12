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
`gen_app_icon.ps1`) plus a `VS_VERSION_INFO` block (file/product version `0.1.0.0`,
company/product `DisasmStudio`, `OriginalFilename DisasmStudio.exe`). The icon is thus
embedded into the EXE and loaded at startup for window, taskbar, and alt-tab use.

### The application shell: `App` and `AppContext`

`ds::App` is the top-level controller, instantiated once on the stack in `wWinMain`.
Its constructor (`App()`):

- `loadPrefs()` reads `%APPDATA%/DisasmStudio/prefs.ini` (a tiny `key=value` file storing
  `theme=` and `density=`) and `theme::ApplyTheme(theme_)` restyles ImGui.
- `ctx_.rebuildDisassembler()` builds the initial disassembler.
- It constructs the **seven tabs in fixed order** and stores them as
  `std::vector<std::unique_ptr<ITab>>`: `ProjectsTab`, `CommunicationsTab`,
  `SigScannerTab`, `BinaryViewTab`, `MemoryToolsTab`, `BinaryDiffTab`,
  `BinaryTechTab`. This vector *is* the tab strip order.

The destructor (`~App()`) calls `ctx_.saveProject()` so analysis is flushed when the
window closes (Alt+F4 / WM_DESTROY path).

#### `AppContext` — the single shared-state struct

`AppContext` is passed **by reference** to every tab's `render` each frame; it is the
app's shared blackboard. Key members:

- `BinaryFile binary` — the loaded target (PE/ELF/Mach-O/raw); see chapter on loaders.
- `Debugger debug` — the live Win32 debugger (own thread, lock-guarded snapshot).
- `Engine engine` (default `Zydis`), `Arch arch` (default `X64`),
  `std::unique_ptr<IDisassembler> disasm` — the active decode engine. Note the
  Debugger owns its **own** decoder and is *not* wired to the UI's `disasm`.
- `ProjectState project` — the per-binary analysis sidecar (comments, renames,
  bookmarks, breakpoints, patches, notes, cursor), persisted as JSON keyed by content
  hash.
- **Cross-tab request flags**: `requestedTab` (name of a tab to switch to next
  frame), `requestedLiveAssembly`, `requestedExportAnalysis`, `binaryJustLoaded`,
  `pendingSignature` (Binary View → Sig Scanner pattern handoff).
- **Go-to plumbing**: `requestedGotoVA` + `hasGotoRequest` (the bool distinguishes
  "go to VA 0" from "no request"). The helper `gotoAddress(va)` sets both and forces
  `requestedTab = "Binary View"` — this is the single canonical way any tab asks the
  app to focus an address.
- **Cursor mirroring**: `cursorVA`, `hasCursor`, `cursorFuncName` (enclosing function),
  and `runtimeCursorVA` (ASLR-translated address for "Run to Cursor"). Binary View's
  real cursor is private; it copies it here each frame so the status bar and debug
  toolbar can read it without reaching into the tab.

`AppContext` also owns the high-level commands shared across tabs:
`rebuildDisassembler()` (`disasm = MakeDisassembler(engine, arch)`), `openBinaryDialog()`
(Win32 `commdlg` open), `loadBinaryPath()`, `loadRawPath()`, `saveProject()`,
`exportAnalysisFile()`, `openLiveAssemblyView()`, and the private
`loadProjectForBinary()`.

#### Binary loading & project lifecycle

`loadBinaryPath(path)` is the spine of opening a file:
1. `saveProject()` first — persist the **outgoing** target's analysis before swapping.
2. `binary.load(path)`; on failure return false.
3. `arch = archFromMachine(binary.machine(), binary.is64Bit())` — the architecture is
   auto-selected from the file header (the `archFromMachine` switch maps every
   `MachineArch` to an `Arch`, defaulting to x64/x86 by bitness).
4. `rebuildDisassembler()`, then `loadProjectForBinary()` to restore the sidecar.
5. `binaryJustLoaded = true` so Binary View re-homes to the entry point and re-analyzes.

`loadProjectForBinary(applySavedArchEngine=true)` resets `project`, hashes the binary
(`binary.contentHash()`), and `LoadProject(h, loaded)`. If a saved sidecar exists and
`applySavedArchEngine` is true, the **saved engine/arch are reapplied** (via
`ArchFromName`/`EngineFromName` + `rebuildDisassembler`) so a binary reopens exactly as
last analyzed — crucial for raw blobs and mis-detected headers. It then stamps fresh
metadata (hash, path, arch/engine names, display name, `lastOpenedUnix`).

`loadRawPath(path, base, arch)` is the "Open as Raw" path: it calls `binary.loadRaw`,
sets the user-chosen arch, and calls `loadProjectForBinary(false)` so the **dialog's
arch choice wins** over any saved value.

`saveProject()` is a no-op unless a binary is loaded with a non-zero hash; it refreshes
the persisted arch/engine (so an Engine-menu change since load is captured) and calls
`SaveProject(project)`.

### Per-frame rendering: `App::render()`

Called exactly once per loop iteration, `render()` draws the shell top-to-bottom:
`renderMenuBar()` → `renderDebugToolbar()` → `renderMainWindow()` → `renderStatusBar()`
→ `renderRawLoadPopup()` → `renderSaveResultPopup()`, plus the optional ImGui demo and
About windows. The three full-width bars are positioned manually against
`ImGui::GetMainViewport()` work area: a debug toolbar pinned to the top, the tab window
filling the middle, and a status bar pinned to the bottom. All three are flagged
`NoTitleBar | NoResize | NoMove | NoSavedSettings | NoDocking` (the main window adds
`NoBringToFrontOnFocus | NoNavFocus`) and pushed to `WindowRounding = 0` so they read
as fixed chrome, not floating panels.

#### Menu bar (`renderMenuBar`)

A standard `BeginMainMenuBar`:

- **File**: *Open Binary…* (Ctrl+O, `openFileDialog`), *Open as Raw…*
  (`openRawFileDialog`), *Save Binary As…* (enabled only when loaded; splices
  accumulated patches — see below), *Export Analysis…* (sets
  `requestedExportAnalysis` + switches to Binary View, which produces the report),
  *Close Binary* (flush, `binary.clear()`, `project.reset()`), and *Exit* (flush +
  `exit_=true`). Disabled items carry hover tooltips (`AllowWhenDisabled`).
- **Engine**: Zydis / Capstone toggle and an Architecture submenu (x86, x64, ARM,
  ARM64, MIPS, MIPS64, PowerPC, PowerPC64, RISC-V 32, RISC-V 64). For non-x86 arches
  Zydis is disabled (it decodes x86/x64 only) and the check marks reflect the
  **effective** engine (`disasm->engine()`), so the menu never disagrees with what is
  actually decoding. Any change calls `rebuildDisassembler()`.
- **View**: Theme submenu (iterates `theme::ThemeId` up to `Count`, applies + persists
  via `savePrefs()`) and an *ImGui Demo* toggle.
- **Help**: *Keyboard Shortcuts* (F1, a grouped global/debugger/navigation/view
  reference) and *About* (version, feature overview, and runtime stack).
- A right-aligned status string (`Engine: … | <format or "no binary">`) is laid out by
  measuring text width and `SameLine`-offsetting from the window width.

#### Debug toolbar (`renderDebugToolbar`)

A full-width borderless window at the top. It reads a `DbgSnapshot` from the Debugger
and branches on attach state. When detached: if a binary is loaded it shows
**Launch & Debug** (calls `debug.launchAndAttach`, on success opens the live assembly
view, on failure stores `launchMsg_` shown in red); otherwise a hint to attach via the
Communications tab. When attached it shows **Detach**, **Continue/Pause** (label and
color flip with run state), **Step Into / Step Over / Step Out / Run to Cursor** (the
stepping buttons disabled unless paused), and a live status line with PID, bitness,
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

`renderRawLoadPopup` is the "Open as Raw" modal: it shows the chosen file, a base-address
hex input (accepts `0x`-prefixed or bare hex via `sscanf("%llx")`), and x86/x64/ARM/ARM64
radio buttons, then calls `loadRawPath` and switches to Binary View. The chosen architecture
is retained as the exact worker/discovery architecture; the loader creates the complete
executable `.raw` section and rejects a base+length range that would overflow. `renderSaveResultPopup`
shows the result message from *Save Binary As…*.

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

Each frame: tabs read `ctx_` to render and write request flags / mirror state back
into it; the App consumes those flags (e.g. clears `requestedTab` when it switches a
tab, Binary View consumes `requestedGotoVA`/`binaryJustLoaded`/`requestedExportAnalysis`
and writes back `cursorVA`/`hasCursor`/`runtimeCursorVA`). Because everything is
immediate-mode and single-threaded on the UI side, this "set a flag this frame, consume
it next frame" handshake is the entire inter-tab messaging system — there are no
signals, callbacks, or event queues. Background concurrency lives in the `Debugger` and
the epoch-guarded `AnalysisService`; the latter runs the same selected-architecture
function/string/listing pipeline for structured and raw images.

#### Limitations & notes

- **App-owned workbench layout**: the bars/panels are explicitly positioned rather than
  exposed as a user dockspace; ImGui's platform/layout state still persists in its ini file.
- **No plugin/scripting API**: excluded by project spec; the shell offers no extension
  point — tabs are compiled in.
- ImGui platform viewports and DPI geometry scaling are enabled, while the workbench's
  browser-style panel arrangement remains an explicit app layout rather than a user dockspace.
- **Hardware-first, WARP fallback**: if no D3D11 hardware device is available the app
  silently falls back to the WARP software rasterizer; if even that fails, startup aborts.
- `Open as Raw` exposes only **x86/x64/ARM/ARM64** in its radio set, even though the
  Engine menu offers more architectures (MIPS/PPC/RISC-V); raw blobs of those arches
  would need the Engine-menu arch switch after loading.
- The base-address parser in the raw popup tolerant-parses hex and does not reason about
  overlap with another real image; `BinaryFile` still rejects a flat range whose final VA
  would overflow.
- Cross-tab state is a per-frame flag handshake, not a robust event bus; it works
  because the whole UI is single-threaded immediate mode, but it means requests are
  effectively "fire on the next frame" and one-shot.
