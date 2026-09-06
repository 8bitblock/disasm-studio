## 08. The Other Workbench Tabs

DisasmStudio is a browser-style single window with a top tab strip. Chapter 07 covered the **Binary View** — the analysis centerpiece. This chapter documents the surrounding workbench tabs, including **Projects**, **Communications**, **Sig Scanner**, **Memory Tools**, **Binary Diff**, **Binary Tech**, and **Prism**. Each is implemented as an `ITab` subclass with a `name()` and a `render(AppContext&)` method (one file per tab under `src/Tabs/`), and each leans on the shared `AppContext` for cross-tab state: the loaded `BinaryFile` (`ctx.binary`), the live `Debugger` (`ctx.debug`), the active disassembler (`ctx.disasm`), the persisted `ProjectState` (`ctx.project`), and the cross-tab navigation helpers `ctx.gotoAddress(va)` and `ctx.requestedTab`.

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

The **right pane** shows two detail blocks. *Selected* echoes the highlighted recent's name, path, arch, content hash (printed as `%016llX`), and last-opened time, with an **Open this project** button. *Loaded Binary* describes the currently open binary — path, `formatName()`, image base, entry point (`imageBase + entryPoint`), section count — followed by a *Saved analysis* summary pulled straight from `ctx.project`: counts of comments, renames, bookmarks, breakpoints, and patches. A **Save project now** button forces a synchronous commit; the normal path is a short debounced autosave plus a verified final commit on close/exit/switch.

**Why this design.** The recents index gives the tool a memory of past targets keyed by *content hash*, not path — so a binary moved or copied still resolves to the same analysis sidecar. The summary block makes the dashboard a quick "what have I done to this file" glance.

---

### Communications tab

**File:** `src/Tabs/CommunicationsTab.h/.cpp`. Native-process backend: processes, modules, and live connections.

This tab is the live-system side of the tool. Its main `render()` splits the area: a 55%-width left child for the process list, and a right child stacking **Modules** above **Connections**.

**Process list (`renderProcesses`).** Enumeration is real, via `ProcessManager::enumerate()` (Toolhelp32). Results are sorted by name for stable ordering. A subtle correctness detail: the selection follows the **PID**, not the row index — on re-enumerate the code records the previously selected PID and re-locates it, so its modules/connections never get listed against the wrong process after a re-sort. A name filter box (`filter_`) narrows the table. Each row shows PID, name, Arch (`is64 ? "x64" : "x86"`, WOW64-aware best-effort), an **Access** column (green "ok" / red "denied" from `ProcessInfo::canOpen`), and an **Attach**/**Detach** action. Attach calls `ctx.debug.attach(pid, err)` (the real Win32 debug API, `DebugActiveProcess`). On success: if no file is loaded, it points `ctx.arch` at the debuggee's bitness and calls `ctx.rebuildDisassembler()` so generic decode paths are correct, then `ctx.openLiveAssemblyView()`. A green "| debugging PID N" badge appears when a session is live.

**Modules (`renderModules`).** For the selected process, lazily fetches `pm_.modules(pid)` (Toolhelp32 module snapshot), caching per PID. Columns: Module / Base / Size (KB). If empty, it tells the user this usually means a bitness or rights mismatch and suggests running as Administrator.

**Connections (`renderConnections`).** Live per-process IPv4+IPv6 TCP/UDP endpoints, real, via the IP Helper API. An owned latest-PID-wins worker queries the four owner-PID tables (`AF_INET`/`AF_INET6` × TCP/UDP) through bounded size/fetch/retry and allocation caps, then filters on `dwOwningPid`; epochs prevent a late result from replacing the newly selected process. One failed table produces an honest partial-refresh warning without suppressing successful rows. `Core/NetworkEndpoint` formats canonical bracketed IPv6 endpoints with numeric scope IDs and IPv4-mapped addresses. The pane separates local/remote, protocol, family, and TCP state, auto-refreshes once per second, and offers IPv4/IPv6/TCP/UDP plus text filters. Whole-table queries and result sorting never run in `render()`.

**Server Watch.** A crackme Triage or Ctrl+K command can open the live-observation surface, bound
to the active document and its exact matching attached module. An unrelated attachment leaves Start
disabled until the analyst attaches/launches the matching target or explicitly chooses ordinary
attached-process observation. Observation remains off until **Start Server Watch** is pressed. The
table displays typed DNS/Winsock/WinHTTP/WinINet/URLMon events, endpoint/method/object, an interpreted
Outcome, documented expected returns/output parameters, validity-bearing observed results/counts,
bounded payloads, continuation navigation, coverage/drops/limitations, and optional file logging. It
supports native x64 and WOW64 ABI capture; overlapped work is marked partial and custom TLS can
remain opaque. This is guided observation, not execution containment or a claim that every network
path is visible.


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

**Files:** `src/Tabs/MemoryToolsTab.*`, `src/Core/ProcessMemorySession.*`, `src/Core/MemoryScan.*`, `src/Core/MemoryPointer.*`, and `src/Core/MemoryTable.*`. Memory Tools can reuse the exact active debugger session or open a **passive process-memory session** by PID. Passive open uses query/read/write process rights but never `DebugActiveProcess`, consumes no debug events, and falls back to read-only when Windows grants that. Both target paths bind every operation to PID plus session generation (and process creation time for passive sessions), preventing an address, scan, or write from silently crossing a close/reopen or PID-reuse boundary.

**Value scanner.** The value model covers signed and unsigned 8/16/32/64-bit integers, `float`, `double`, AOB byte arrays with `??` wildcards, and validated UTF-8/UTF-16LE text with optional terminators. Numeric text can be decimal or raw-width hexadecimal; finite floats format with enough precision to round-trip their bits. Scan predicates are **Exact, Not equal, Greater/Less than value, Between, Changed, Unchanged, Increased, Decreased, Increased by, Decreased by, and Unknown initial**, with optional float tolerance.

- A first scan walks selected committed/readable memory on a cancellable worker. The analyst can include/exclude private, image, or mapped regions; require writable or non-executable memory; constrain an address range; select alignment; and set the scan-byte admission bound.
- `MemoryScanSnapshot` keeps previous bytes per owned chunk and one compact candidate bitmap. Boundary lookahead tests values that straddle read chunks exactly once. A next scan re-reads each retained chunk and refines its bitmap in bulk instead of issuing a process read per address.
- First-pass admission reserves conservative physical-memory headroom for the worst-case dense snapshot and its atomic refinement copy. Before each next scan, the actual retained chunk/bitmap footprint is checked again; insufficient headroom refuses the copy with a clear narrowing hint instead of pushing the machine into paging.
- The candidate count is exact for the admitted, readable scope. `MemoryScanSnapshot::page()` enumerates stable result ordinals on demand, so millions of matches do not require a materialized address vector or an arbitrary 1,000/2-million-result truncation. Results can open the viewer, copy an address, seed pointer search, or become table rows.

**Hex viewer/editor and regions.** The viewer reads a 256-byte hex/ASCII window with back/forward navigation, selection, copy, byte-array paste/edit, changed-byte highlighting, and pointer-follow actions. Writes use the same identity-bound path as the table. The cached, searchable region browser shows base/end/size, protection, allocation type, and containing module; a region can become the viewer address or scan range. The debug toolbar and Ctrl+K command **Inspect Live RIP in Memory Tools** hand the current identity-bound RIP directly to this view.

**Pointer scan.** A separate cancellable worker captures an admitted set of readable regions and performs deterministic 32- or 64-bit backlink discovery with explicit depth, maximum positive offset, result/frontier/read/comparison, and cancellation bounds. Results are ranked for stable module-relative roots and short chains, can be resolved through the current identity-bound reader, and can be added to the address table as relocatable module-plus-offset pointer records.

**Address table and freeze.** Rows support absolute or module-relative bases, optional pointer offsets, every scalar/text/AOB value type, grouping/description, hexadecimal display, and an explicit protection-change policy. **Save/Load Table** uses a strict bounded JSON format separate from the per-binary project sidecar. Loading always forces every row disabled and unfrozen—even if an untrusted file requests otherwise—so opening a table cannot read or write the target by itself. Module resolution prefers an exact normalized path and rejects ambiguous basename matches.

Enabled rows resolve only against the current target identity. A dedicated worker applies **Constant, Minimum, or Maximum** freeze policies even when the tab is not being painted; debugger-target writes are batched through one session check. Passive writes capture original bytes, write, verify, restore any temporarily changed protection, and attempt verified rollback after a post-write failure. The default authority permits already-writable, non-executable committed data only. Read-only or executable pages require the row's explicit **allow protection change** authority, while guard/no-access pages remain denied.

---

### Binary Diff tab

**File:** `src/Tabs/BinaryDiffTab.h/.cpp`. Compare two binaries with synchronized hex panes.

Before a diff exists, `renderLoadZone()` draws a centered "drop zone" — two cards (LEFT / RIGHT) each with a **Load…** button, plus a **Compute Diff** button enabled once two paths and their stable Win32 identities have been captured. The render thread never loads or parses either binary.

`computeDiff()` enqueues work on a persistent cancellable worker. The job contains only paths and stable Win32 file identities; the worker reloads owned `BinaryFile` objects, verifies identity before and after work, scans bytes once, counts every mismatch, keeps bounded samples, and coalesces navigable change regions. Optional section-aware mode aligns sections by name then RVA. After computing, a compact toolbar lets you swap either side or **Recompute** without leaving the view.

The diff view is two equal bordered panes rendered by `renderPane()`, each a clipper-driven (`ImGuiListClipper`) 16-byte-per-row hex+ASCII dump. A byte is highlighted **red** when it differs from the other file (or lies past the other's end); matching bytes are muted. **Synchronized scrolling:** only the hovered ("master") pane shows a scrollbar and drives `scrollY_`; the follower is positioned with `SetScrollY` to match. Hovering either pane hands it the master role, so scrolling either side keeps both aligned. Flat mode is exact by file offset; section-aware mode is better for changed layouts.

**Semantic mode.** Opting in builds immutable function models on the same worker and matches unique authoritative names first, then relocation-normalized typed-instruction hashes, canonical CFG structure, and already-matched call neighborhoods. The UI separates matched/added/removed functions, shows confidence and concrete evidence, lists instruction edit hunks, and presents a synchronized two-column instruction review. Persisted names, comments, prototypes, and bookmarks become proposals only: every checkbox starts clear, the user must explicitly select and apply each proposal, and application is rejected unless the destination image hash equals both the active binary and project identity.

---

### Binary Tech tab

**File:** `src/Tabs/BinaryTechTab.h/.cpp`. Real capability/technique detection.

**Run Tech Scan** calls `ScanCapabilities(ctx.binary)` from `Core/TechScan` — pure, unit-testable logic that detects capabilities three ways: **imported-API grouping** (anti-debug / network / crypto / injection / dynamic-API / spawn), **packer section-name signatures**, and **distinctive byte patterns** (direct-syscall stub, AES S-box, SHA-256 constants). Network imports use `NetworkApiCatalog`'s exact DLL-aware lookup rather than substring matching. Each `Capability` carries `name`, `category`, a `confidence` (0..1), a representative `address` (an IAT slot or pattern hit, or 0), and a human-readable `detail` listing the evidence. Results are sorted by descending confidence, and the scan returns an **empty list for a clean binary** — no fabricated findings.

**Layout.** A category filter box and a count caption, then a two-pane split. The **left** table lists Capability / Cat / Conf, where confidence is color-coded (green >85%, amber >65%, red below). Selecting a row populates the **right** detail pane: name, category, confidence, address, a **View in disassembly** button, and the wrapped `detail` evidence. Network findings also expose **Open crackme network trail**, handing the active document to Binary View's Triage/Network Trail view. Below that is an inline preview: executable addresses disassemble; other evidence shows a hex preview. Double-clicking a capability (or the button) still calls `ctx.gotoAddress(c.address)`.

**What is real vs heuristic.** The detection is real (it reads actual imports, section names, and byte patterns), but the `confidence` percentage is a heuristic score, and the categorization is best-effort — the UI presents it as such (a percentage, not a verdict).

---

### Cortex tab

Cortex consumes the current document's immutable `CrackmeTriageReport` when the report identity
matches, avoiding a weaker duplicate pass. Network/server/reply/license questions rank endpoint
trails by report confidence, five-stage completeness, correlations, and semantic artifacts, and
answer with an explicit **not contacted** qualifier plus partial-analysis warnings. If no cached
report exists, its worker builds the same bounded call graph and candidate set from exact network
import xrefs, endpoint/string owners, and a depth-2 neighborhood before annotating at most 256
candidate functions. Return/result questions instead report the exact documented API contract and
bounded downstream static use, while warning that read status is not reply-content acceptance;
typed return-use evidence feeds the fallback triage without fabricating content validation.

---

### Prism tab

**Files:** `src/Tabs/PrismTab.*`, `src/Core/PrismSampler.*`, and pure aggregation in `src/Core/Prism.*`.

Prism 2 profiles an entered PID on owned background threads. **Automatic** mode first requests a bounded real-time ETW kernel session and scopes sampled-profile, image/thread, context-switch-derived wait, and disk/file/network I/O events to the target. ETW stack coverage, resolved-frame coverage, and lost event/buffer counts are part of the report, so collection gaps are visible. Kernel profiling can require elevation or profile-system-performance policy; when setup fails, Automatic mode records the exact Win32 reason and switches to the clearly labelled suspend-and-walk fallback. **ETW only** and **Suspend-and-walk fallback** modes make that policy explicit. The fallback supports native x64 and WOW64 thread contexts.

Collection and report building are separate: the collector maintains a 10,000-observation rolling bound, while a throttled aggregation worker builds immutable function/state/module/path/timeline/flame results. `render()` only reads the latest report pointer and draws it; stopping is a non-blocking cancellation request. The timeline supports slice selection, and the pre-laid-out bounded flame graph exposes both inclusive and self weight. Clicking a hot function or flame node maps its runtime address back to the active static image only when debugger/image identity proves the mapping; otherwise it opens live assembly for the matching attached PID. Shift-click forces live navigation.

---

#### Limitations & notes

- **Communications connections cover IPv4 and IPv6 TCP/UDP.** Module/connection visibility still depends on having matching bitness and sufficient rights (often requires Administrator); individual table failures are shown as partial refreshes.
- **Live scans are bounded** for responsiveness: the Sig Scanner caps at 512 MB scanned / 4096 results with chunk overlap. Memory Tools instead has configurable byte/work admission bounds, retains the complete candidate bitmap for admitted readable chunks, reports the exact count, and pages display rows without a hit cap.
- **Memory Tools needs a live process, but not a debugger attach.** It can open a passive memory session or reuse the current debugger session. Windows rights, target exit, PID/session identity changes, and unreadable regions are surfaced explicitly. Binary Diff needs two file inputs and keeps its flat, section-aware, and semantic work cancellable.
- **Memory tables are durable JSON artifacts, not project-sidecar state.** Loading is intentionally inert: records remain disabled and unfrozen until the analyst enables them for the current target.
- **Binary Tech `confidence` is a heuristic score**; the detected evidence (imports/sections/patterns) is real, and a clean binary yields an empty list rather than invented capabilities.
- **Prism ETW availability is an OS-policy capability, not assumed.** Automatic mode surfaces the failure and falls back; ETW-only mode surfaces it and stops. Suspend-and-walk is intrusive and is always labelled as such.
