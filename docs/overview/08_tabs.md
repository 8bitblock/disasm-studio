## 08. The Other Workbench Tabs

DisasmStudio is a browser-style single window with a top tab strip. Chapter 07 covered the **Binary View** — the analysis centerpiece. This chapter documents the other six top-level tabs that surround it: **Projects**, **Communications**, **Sig Scanner**, **Memory Tools**, **Binary Diff**, and **Binary Tech**. Each is implemented as an `ITab` subclass with a `name()` and a `render(AppContext&)` method (one file per tab under `src/Tabs/`), and each leans on the shared `AppContext` for cross-tab state: the loaded `BinaryFile` (`ctx.binary`), the live `Debugger` (`ctx.debug`), the active disassembler (`ctx.disasm`), the persisted `ProjectState` (`ctx.project`), and the cross-tab navigation helpers `ctx.gotoAddress(va)` and `ctx.requestedTab`.

A recurring design choice across all of them: the tabs are thin, immediate-mode UI shells over reusable, testable Core logic. The Projects tab is just a view over `LoadRecents()`; Binary Tech is a view over `ScanCapabilities()`; the scanners and process tools are views over `ProcessManager`/`Debugger`. None of these tabs invent data — where a result is heuristic or unavailable, the UI says so in dimmed text.

---

### Projects tab

**File:** `src/Tabs/ProjectsTab.h/.cpp`. Backed by the on-disk recents index.

The Projects tab is the landing/dashboard view. It is *real* — not a mock list — because it reads the same JSON recents index that `SaveProject()` upserts every time a binary is analyzed. `ProjectsTab::refresh()` simply calls `LoadRecents()` (from `Core/Project`) into a `std::vector<RecentEntry>`. Each `RecentEntry` carries `hash`, `path`, `name`, `arch`, `status`, and `lastOpenedUnix`. The index lives alongside the per-binary sidecars under `%APPDATA%/DisasmStudio/projects/`.

**Auto-refresh.** The tab caches the last-seen project hash in `lastSeenHash_`. On first paint, and whenever `ctx.project.hash` changes (i.e. a different binary became the active project), it re-reads the index. So opening or saving a target makes it appear in the recents list without a manual refresh.

**Layout.** A two-pane split. Top toolbar: **Open Binary…** (calls `ctx.openBinaryDialog()`, and on success switches to the Binary View via `ctx.requestedTab`), **Refresh**, and a hint pointing at *File ▸ Open as Raw…* for shellcode/firmware. Any open error is shown in red.

The **left pane** is a three-column table (Name / Arch / Opened) listing the recents. Interactions:
- Single click selects a row (`selected_`).
- Double-click opens it (`ctx.loadBinaryPath(r.path)`, then jump to Binary View; failure stores an `openError_`).
- Right-click context menu: **Open**, **Copy path** (to the clipboard), **Remove from list** (calls `RemoveRecent(hash)` and refreshes). Timestamps are formatted by a small `whenStr()` helper using `localtime_s`.

The **right pane** shows two detail blocks. *Selected* echoes the highlighted recent's name, path, arch, content hash (printed as `%016llX`), and last-opened time, with an **Open this project** button. *Loaded Binary* describes the currently open binary — path, `formatName()`, image base, entry point (`imageBase + entryPoint`), section count — followed by a *Saved analysis* summary pulled straight from `ctx.project`: counts of comments, renames, bookmarks, breakpoints, and patches. A **Save project now** button calls `ctx.saveProject()`, and a dimmed note reminds the user that the sidecar is auto-saved on close/exit.

**Why this design.** The recents index gives the tool a memory of past targets keyed by *content hash*, not path — so a binary moved or copied still resolves to the same analysis sidecar. The summary block makes the dashboard a quick "what have I done to this file" glance.

---

### Communications tab

**File:** `src/Tabs/CommunicationsTab.h/.cpp`. Native-process backend plus an AMD-V hypervisor channel.

This tab is the live-system side of the tool. Its main `render()` splits the area: a 55%-width left child for the process list, and a right child stacking **Modules**, **Connections**, and the **AMD-V Hypervisor** panel.

**Process list (`renderProcesses`).** Enumeration is real, via `ProcessManager::enumerate()` (Toolhelp32). Results are sorted by name for stable ordering. A subtle correctness detail: the selection follows the **PID**, not the row index — on re-enumerate the code records the previously selected PID and re-locates it, so its modules/connections never get listed against the wrong process after a re-sort. A name filter box (`filter_`) narrows the table. Each row shows PID, name, Arch (`is64 ? "x64" : "x86"`, WOW64-aware best-effort), an **Access** column (green "ok" / red "denied" from `ProcessInfo::canOpen`), and an **Attach**/**Detach** action. Attach calls `ctx.debug.attach(pid, err)` (the real Win32 debug API, `DebugActiveProcess`). On success: if no file is loaded, it points `ctx.arch` at the debuggee's bitness and calls `ctx.rebuildDisassembler()` so generic decode paths are correct, then `ctx.openLiveAssemblyView()`. A green "| debugging PID N" badge appears when a session is live.

**Modules (`renderModules`).** For the selected process, lazily fetches `pm_.modules(pid)` (Toolhelp32 module snapshot), caching per PID. Columns: Module / Base / Size (KB). If empty, it tells the user this usually means a bitness or rights mismatch and suggests running as Administrator.

**Connections (`renderConnections` / `refreshConnections`).** Live per-process TCP/UDP endpoints, real, via the IP Helper API. `GetExtendedTcpTable(... TCP_TABLE_OWNER_PID_ALL)` and `GetExtendedUdpTable(... UDP_TABLE_OWNER_PID)` are each called twice — once to size the buffer, once to fill it — then filtered to rows whose `dwOwningPid` matches the selected PID. Addresses are formatted with `inet_ntop` and `ntohs`; TCP state strings come from `tcpStateName()` mapping the `MIB_TCP_STATE_*` enum (LISTEN, ESTABLISHED, TIME_WAIT, …). UDP rows are listed as "listening". **Scope/limitation:** IPv4 only — there is no IPv6 connection table here (consistent with the project's stated out-of-scope list).

**AMD-V Hypervisor (`renderHvDbg`).** This panel talks to the SVM kernel driver over `\\.\HvDbg` via `HvDbgClient`. It surfaces connection state, an SCM-driven **Load driver / Unload driver** lifecycle (`HvDbgLoader`, greyed out unless `isElevated()`), a handshake/`ping()` that fills `HVDBG_INFO`, and capability flags (SVM supported, NPT, active, SVM-locked-in-firmware, another hypervisor present), plus **Virtualize all CPUs** / **Devirtualize** actions. Critically, if `ping()` reports an **ABI mismatch** the panel refuses to drive VMRUN IOCTLs and tells the user to rebuild the driver. When the driver isn't loaded the panel degrades gracefully to an informational "not present" state. Per the project spec, **driver packaging, signing, loading, and runtime validation are out of scope** for the normal app target — this panel is the user-mode client surface, not a turnkey hypervisor.

---

### Sig Scanner tab

**File:** `src/Tabs/SigScannerTab.h/.cpp`. Byte-pattern scanning with `??` wildcards.

The top bar holds a pattern input (defaulting to `48 89 5C 24 ?? 57 48 83 EC 20`), a **Scan** button, a **Live** checkbox, a signature-name box, **Save Sig**, and a progress bar. Below is a four-way sub-tab bar.

**Pattern parsing.** `parsePattern()` converts a string like `"48 89 ?? 24"` into a `bytes` vector plus a parallel `mask` of bools. Whitespace is skipped; a `?` (single or `??`) pushes a wildcard (mask=false); a hex pair is parsed with `sscanf("%x")`. A malformed pattern returns false (and is reported as health "malformed", count `-1`).

**Scan (`scan`).** Two modes:
- **File mode** (default): linear search over `ctx.binary.bytes()`; each file-offset hit is mapped back to a VA with `BinaryFile::offsetToVA` (the same mapping strings/byte-search use) so results are clickable. Capped at 4096 results.
- **Live mode**: walks the attached process's committed regions (`ctx.debug.regions()`), reading in 1 MB chunks with a `(pattern-1)`-byte **overlap** so a match straddling two chunks is never dropped. It skips non-readable/non-`MEM_COMMIT` regions, enforces a 512 MB byte budget and a 4096-result cap to stay responsive, and labels each hit with the module it falls in (resolved against `ProcessManager::modules`, defaulting to "live"). Works whether the target is paused or running.

**Sub-tabs.**
- **Results** — table of Address / Signature / Module. Clicking an address calls `ctx.gotoAddress()` (navigates the Binary View). A caption notes whether results came from "(live process memory)" or "(file on disk)".
- **Current Scan** — shows the active pattern, total bytes loaded, and the progress bar (mainly useful for the chunked live scan).
- **Sig Health** — a saved-signature scorecard. `refreshHealth()` re-counts each signature against the loaded binary via `countMatches()` (capped at 100k for speed), and `healthFromCount()` maps the count to a label: `malformed` (−1) / `none` (0) / `unique` (1) / `multiple` (>1), color-coded green/amber/red. This is the real, match-count-based "is my signature still good" check that makes saved patterns trustworthy across rebuilds. Three starter signatures ship pre-populated.
- **All Functions** — runs `FunctionAnalyzer::analyze(ctx.binary, *ctx.disasm)` (recursive-descent + prologue + export sweep) and lists Address / Name / Size with a name filter; the analyzer's `lastSummary()` is shown. Clicking a row navigates to it.

**Cross-tab handoff.** If the Binary View's right-click "create signature" sets `ctx.pendingSignature`, this tab loads it into the pattern box and scans immediately on next paint.

---

### Memory Tools tab

**File:** `src/Tabs/MemoryToolsTab.h/.cpp`. A Cheat-Engine-style live-memory toolkit. All four panels operate on the **attached process** (via `Debugger::readMemory/writeMemory/regions`); without an attach they show a "attach a process first" hint.

**Value scanner (`renderScanner` / `firstScan` / `nextScan`).** Combo boxes pick a **value type** (`Byte/Word/Dword/Qword/Float/Double`) and a **scan type** (`Exact / Bigger than / Smaller than / Changed / Unchanged / Unknown initial`), with a value box and a **Hex** toggle. `parseNeedle()` turns the text into a little-endian needle (floats/doubles `memcpy`'d; integers `strtoull` in base 10/16).

- **First Scan** walks committed regions in 1 MB chunks (512 MB byte budget, 2 M result cap). For ordered types it compares each candidate to the entered value; for Changed/Unchanged/Unknown it captures everything (there is no prior value yet, Cheat-Engine style). Each kept hit stores `{address, prevBits}`.
- **Next Scan** re-reads each stored address and applies `matches()` against the *previous* captured value (or the needle for Exact), keeping survivors. Crucially, integer comparisons are **signed** — the low bytes are sign-extended before widening to `double`, so `-1 < 0` rather than `-1` looking like 4.29e9.
- **New Scan** clears state.

Results show up to 1000 of `totalFound_`, re-reading live values each frame; right-click adds a result to the address table.

**Viewer/Editor (`renderViewerEditor`).** A hex+ASCII dump of 8 rows × 16 bytes from a user-entered base address, read live each frame; unreadable bytes render as `--`/`.`.

**Memory browser (`renderBrowser`).** Lists committed regions from `ctx.debug.regions()` with base, size (KB), and RWX protection flags; clicking a region drops its base into the viewer address.

**Address table (`renderAddressTable`).** A persistent (in-tab) table of `{active, desc, address, type, value, frozen}` rows. Each frame, **frozen** rows are re-written to the process (`writeMemory`) — the freeze loop. Non-frozen rows display the live value and accept edits (Enter writes through). An **Add Row** box appends a new hex address. Note: this address table lives in the tab instance and is *not* persisted to the project sidecar.

---

### Binary Diff tab

**File:** `src/Tabs/BinaryDiffTab.h/.cpp`. Compare two binaries with synchronized hex panes.

Before a diff exists, `renderLoadZone()` draws a centered "drop zone" — two cards (LEFT / RIGHT) each with a **Load…** button (a `GetOpenFileNameW` dialog into `BinaryFile::load`), plus a **Compute Diff** button enabled only when both are loaded. The block is sized to half the tab width and centered on both axes.

`computeDiff()` walks the byte vectors of both files up to the shorter length, recording mismatching offsets into `diffs_` (`{offset, a, b}`, capped at 5000 stored rows but `totalDiff_` counts all of them, plus the size delta of the tail). After computing, a compact toolbar lets you swap either side or **Recompute** without leaving the view.

The diff view is two equal bordered panes rendered by `renderPane()`, each a clipper-driven (`ImGuiListClipper`) 16-byte-per-row hex+ASCII dump. A byte is highlighted **red** when it differs from the other file (or lies past the other's end); matching bytes are muted. **Synchronized scrolling:** only the hovered ("master") pane shows a scrollbar and drives `scrollY_`; the follower is positioned with `SetScrollY` to match. Hovering either pane hands it the master role, so scrolling either side keeps both aligned. This is a byte-offset diff (not a structural/section-aware diff); it is most meaningful for builds of the same layout.

---

### Binary Tech tab

**File:** `src/Tabs/BinaryTechTab.h/.cpp`. Real capability/technique detection.

**Run Tech Scan** calls `ScanCapabilities(ctx.binary)` from `Core/TechScan` — pure, unit-testable logic that detects capabilities three ways: **imported-API grouping** (anti-debug / network / crypto / injection / dynamic-API / spawn), **packer section-name signatures**, and **distinctive byte patterns** (direct-syscall stub, AES S-box, SHA-256 constants). Each `Capability` carries `name`, `category`, a `confidence` (0..1), a representative `address` (an IAT slot or pattern hit, or 0), and a human-readable `detail` listing the evidence. Results are sorted by descending confidence, and the scan returns an **empty list for a clean binary** — no fabricated findings.

**Layout.** A category filter box and a count caption, then a two-pane split. The **left** table lists Capability / Cat / Conf, where confidence is color-coded (green >85%, amber >65%, red below). Selecting a row populates the **right** detail pane: name, category, confidence, address, a **View in disassembly** button, and the wrapped `detail` evidence. Below that is an inline preview: if the capability's address lands in an executable section (`vaIsExecutable`), it disassembles ~10 instructions there with `ctx.disasm`; otherwise it shows a 64-byte hex dump and suggests using *Find references* in the Binary View. Double-clicking a capability (or the button) calls `ctx.gotoAddress(c.address)` to jump to the code.

**What is real vs heuristic.** The detection is real (it reads actual imports, section names, and byte patterns), but the `confidence` percentage is a heuristic score, and the categorization is best-effort — the UI presents it as such (a percentage, not a verdict).

---

#### Limitations & notes

- **Communications connections are IPv4-only** (no IPv6 table), per the project's out-of-scope list. Module/connection visibility depends on having matching bitness and sufficient rights (often requires Administrator).
- **The AMD-V hypervisor panel** is the user-mode client surface only; driver packaging, signing, loading, and runtime validation are outside the normal app target, and the panel refuses VMRUN IOCTLs on an ABI mismatch.
- **Live scans are bounded** for responsiveness: the Sig Scanner caps at 512 MB scanned / 4096 results with chunk overlap to avoid missing straddling matches; the Memory Tools scanner caps at 512 MB / 2 M results and displays at most 1000 rows.
- **Memory Tools and Binary Diff need their inputs present** — Memory Tools requires an attached process; Binary Diff does a flat byte-offset comparison (not section-aware), so it is most useful for two builds with the same layout.
- **The Memory Tools address table is per-session** (not written to the project sidecar), unlike comments/bookmarks/breakpoints/patches which are persisted.
- **Binary Tech `confidence` is a heuristic score**; the detected evidence (imports/sections/patterns) is real, and a clean binary yields an empty list rather than invented capabilities.
