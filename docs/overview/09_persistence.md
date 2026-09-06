## 09. Persistence, Projects & Reporting

This chapter covers everything that survives a restart: the per-binary analysis
state DisasmStudio persists, the JSON sidecar format and its hand-rolled JSON
library, the recents index that backs the **Projects** tab, when state is saved
and reloaded, and the **Export Analysis** report generator (Markdown / HTML). The
guiding design idea is simple: a binary's content hash is the identity key, so the
analyst's annotations follow the *bytes*, not the file path — rename a file, move
it, copy it, and your comments, renames, bookmarks, breakpoints, named patch sets, notes,
and explicit listing-region choices come right back. There is no notion of a manually-saved `.dsproj` file the user
juggles; persistence is implicit and automatic.

Key files: `src/Core/Project.h`, `src/Core/Project.cpp` (state model + sidecar
I/O + recents), `src/Core/PatchSet.h` and `src/Core/PatchedImage.h` (bounded set
selection, pristine reconstruction, and comparison), `src/Core/AtomicFile.{h,cpp}` (flushed atomic replacement and
backup recovery), `src/Core/Preferences.{h,cpp}` (strict bounded `prefs.ini`
codec/store), `src/Core/Json.h`, `src/Core/Json.cpp` (the tiny JSON lib),
`src/Core/Report.h`, `src/Core/Report.cpp` (report formatters). Wiring lives in
`src/App.cpp` (`AppContext::loadProjectForBinary`, `saveProject`,
`exportAnalysisFile`), `src/Tabs/BinaryViewTab.cpp` (`loadProjectState`,
`saveProjectState`, `exportAnalysis`), and `src/Tabs/ProjectsTab.cpp` (the UI).

### What gets persisted: `ProjectState`

`ds::ProjectState` (in `Project.h`) is the single struct holding everything
worth saving for one binary. It splits into identity/metadata and the analysis
annotations themselves.

Identity / metadata:
- `hash` — the binary's 64-bit content hash; this is the sidecar's filename key
  (`0` means "no project").
- `binaryPath`, `arch` (`"x86"`/`"x64"`/`"ARM"`/`"ARM64"`/…), `engine`
  (`"Zydis"`/`"Capstone"`), `name` (display name, defaults to the file name),
  `status` (defaults to `"analyzed"`), and `lastOpenedUnix` (a Unix timestamp).
- Raw-layout identity: `rawMappingSaved`, the exact `rawImageBase`, an explicit-entry bit
  plus `rawEntry` (so VA 0 survives), and bounded named raw landmarks with evidence. A raw
  blob has no header from which any of these addresses can be reconstructed.

Analysis annotations (the part actually worth persisting):
- `comments` — `unordered_map<uint64_t,string>`, address → user comment.
- `names` — `unordered_map<uint64_t,string>`, address → user rename/symbol.
- `bookmarks` — `vector<PjBookmark>` (`{address, label}`).
- `breakpoints` — `vector<uint64_t>` of addresses.
- `bpConditions` — `unordered_map<uint64_t,string>`, address → condition
  expression, kept 1:1 with `breakpoints`.
- `patches` — `vector<PjPatch>`, each holding `{address, orig, bytes, patchSetId}` where
  `orig` and `bytes` are the original and replacement byte vectors. Vector order
  is application order and is preserved exactly because overlapping patches are later-wins.
- `patchSets` — ordered presentation records `{id, name, enabled}`. Id zero is reserved for
  the implicit **Ungrouped** compatibility set; named ids are stable project-local identities,
  not vector positions, so renaming/reordering the table never retargets patch bytes.
- `functionOverrides` — authoritative define/undefine decisions with an optional exact
  extent, tri-state noreturn, calling convention, prototype, and ARM/Thumb mode metadata.
- `dataOverrides` — non-overlapping, bounded analyst spans classified as code, data,
  string, pointer table, or jump table, with an optional type spelling.
- `lastCursor` — the last cursor VA, so reopening returns you where you were.
- `notes` — free-form text from the Notes tab.
- `watches` — the watch-panel expressions.
- `listingLayoutSaved` — an explicit marker that the analyst has changed/reset the
  listing layout. When set, `peHeaderVisible`/`peHeaderFolded` store the PE-header
  choice and `listingSections` stores `{rva, name, visible, folded}` for each section.
  The stable key is `(RVA, name)`, never a loader-vector position.

Two helpers shape the save policy. `reset()` clears the struct to defaults
(called when switching targets), and `hasContent()` returns true only if there is
real analysis present (any comment, name, bookmark, breakpoint, patch or patch set, note,
watch, an analyst override, a valid cursor, an explicitly saved listing layout, or a saved raw mapping). Crucially, *metadata
alone is not "content"* —
a freshly-opened binary with only an auto-stamped open time is considered empty.
This gate prevents `%APPDATA%` from filling with junk sidecars for binaries the
user merely glanced at (see save policy below).

### The JSON sidecar and where it lives

`ProjectsDir()` resolves the base directory: on Windows it is
`%APPDATA%\DisasmStudio\projects`, otherwise `$HOME/.disasmstudio/projects`
(with sensible relative fallbacks if the env vars are missing). It is overridable
via the `DS_PROJECTS_DIR` environment variable — used by the unit tests so they
can read/write to a sandbox directory without touching the real profile.

`ProjectPathForHash(hash)` creates the directory if needed and returns
`<dir>/<HASH>.json`, where the hash is formatted as a fixed 16-digit uppercase hex
string (`%016llX.json`). One file per binary, named purely by content. The
recents index is a sibling file, `index.json`, in the same directory.

The content hash itself comes from `BinaryFile::contentHash()` (in
`BinaryFile.cpp`): a 64-bit **FNV-1a** over the raw file bytes, mixing the length
in at the end so two blobs differing only in trailing zero padding still hash
differently. The value is computed once and cached (`hashValid_`) from the
*pristine* file at load time. This is a deliberate, load-bearing detail: when the
user applies patches, `BinaryFile::writeImage` rewrites the in-memory image but
`contentHash()` is intentionally left untouched. If patching changed the hash, the
sidecar key would move out from under a live project and the patches would orphan
their own annotations. Keeping the hash pinned to the original bytes means the
project key is stable across patch/revert cycles within a session.

### Serialization: addresses as hex strings (and why)

`SerializeProject` / `DeserializeProject` (split out from filesystem I/O so they
are unit-testable with no disk) convert `ProjectState` to and from a JSON object.
The serialized document carries `version: 4`, the metadata fields, an optional
`rawMapping` object, then arrays for annotations, named patch sets, ordered patches, and analyst
overrides. Maps are emitted as arrays of `{a, v}` (or `{a, label}`, etc.) sorted
by address, so unordered state remains stable and diff-friendly. The patch array
is deliberately *not* sorted: its order defines later-wins overlap precedence.
Versions 1–3 remain readable. Their patches have no membership field and load into the
implicit always-enabled Ungrouped set; every new save writes version 4 with an explicit
hex-string set id on each patch.

The single most important serialization decision: **every address is stored as a
hex string, not a JSON number.** The reasons:

- JSON has only one numeric type, and this codebase's JSON lib stores numbers as
  `double` (see below). A `double` has 53 bits of mantissa, so a 64-bit address
  above 2^53 cannot round-trip without precision loss. A high virtual address
  (common with PIE/ASLR images and 64-bit code) would silently corrupt.
- Storing `"0x1400123456"` as a string and parsing it back with `strtoull`
  guarantees an exact 64-bit round-trip. The project round-trip test specifically
  checks an address like `0x1400123456` for `lastCursor`.

Helpers enforce this: `hexU64` formats `0x%llX`; `parseU64` strips an optional
`0x`/`0X` prefix and parses base-16 with `strtoull`, returning `0` on no-digits or
overflow (it never fabricates a value). Patch byte vectors are stored as
space-separated hex pairs via `bytesToHex` / `hexToBytes`.

Deserialization is defensive — a corrupt or hand-edited sidecar must not be able
to drive bad behaviour:
- Breakpoints are de-duplicated on load so the `breakpoints` vector and the
  `bpConditions` map stay 1:1 (a duplicate address would break that invariant).
- `hexToBytes` requires *full* two-hex-digit bytes and stops on a lone trailing
  nibble rather than fabricating a wrong byte.
- Patches are validated before the file-splicer is ever allowed to trust them:
  `bytes` must be non-empty, `orig` and `bytes` must be the same length, and the
  size is capped at 1 MiB. Named set ids/names and membership are bounded and unique;
  original-byte overlap disagreement and conflicting enabled-set replacements are rejected.
  A malformed version-4 patch entry or invalid set plan rejects the sidecar rather than
  publishing a partial selection — this
  matters because saved patches are re-applied to the in-memory image on reopen
  and can be spliced into a written-out binary via **Save Binary As…**.
- Function/data overrides have bounded counts and string sizes; ranges are checked
  for overflow, duplicate function decisions are rejected, and data spans must not
  overlap. An explicit validity bit represents optional extents, so VA 0 remains valid.

### The hand-rolled JSON library (`Json.*`)

`src/Core/Json.{h,cpp}` is a tiny, dependency-free JSON value + parser +
serializer — "just enough" to back persistence, deliberately added so no new
vcpkg dependency was needed. `ds::json::Value` is a tagged union over
`Null/Bool/Num/Str/Arr/Obj`; numbers are `double`; objects are an
**insertion-ordered** `vector<pair<string,Value>>` (so emitted key order is
predictable, not hash-randomized). Construction helpers (`Value::Obj()`,
`Value::Arr()`, `Value::Str()`, `Value::Int()`, …), `set`/`find`/`push`, and typed
getters (`getStr`, `getInt`, `getBool` with defaults) make the (de)serializers
terse.

`Dump(value, pretty)` pretty-prints with two-space indentation by default,
escapes strings (including control chars as `\uXXXX`), and prints whole numbers
without a decimal point. The parser is a small recursive-descent `Parser` that is
hardened against hostile input: it caps nesting at `kMaxDepth = 200` to avoid
stack overflow, rejects trailing garbage after the root value, validates number
tokens (rejecting `"1e"`, `"."`, `"--5"`), correctly decodes `\u` escapes
including UTF-16 surrogate pairs into UTF-8, and rejects lone/invalid surrogates.
Because it stores numbers as `double`, the Project layer's hex-string-for-address
convention isn't a stylistic choice — it's what makes 64-bit fidelity possible at
all on top of this library.

### When state is saved and reloaded

Loading (`AppContext::loadProjectForBinary` in `App.cpp`): on opening a binary it
`reset()`s the project, computes the content hash, and calls `LoadProject(hash)`.
If a sidecar exists it is restored. On the normal open path, a raw candidate is first
re-staged at the saved base with the saved explicit entry and named landmarks, then the
saved arch/engine is applied. This prevents every VA-keyed annotation from shifting when a
recent raw blob is reopened. Invalid/corrupt saved raw metadata is ignored safely rather
than making the underlying file unopenable. On the interactive **Open as Raw…** path the
dialog's explicit mapping and architecture win. The loader then stamps fresh metadata
(hash, path, arch, engine, name, `lastOpenedUnix`). A bounded firmware rescan recreates
the evidence report on an ordinary raw reopen but never overrides the saved mapping.

The Binary View tab then mirrors `ctx.project` into its live editing state via
`loadProjectState` (comments, names, bookmarks, breakpoints + conditions, notes,
watches, named patch sets, and `lastCursor` → cursor). If a debugger is already attached, saved
breakpoints (with conditions) arm only when an exact x86/x64 path/module/bitness match
can translate their file VAs safely; otherwise they remain visible as pending. The enabled
patch-set selection is rebuilt from verified pristine bytes and written into the in-memory
image so the disassembly reflects that selection across sessions — and
because the hash was cached from the pristine file, those writes don't change the
sidecar key.

Mutations increment a project revision and mark the global save indicator dirty.
After a short debounce, `App` snapshots the state and runs serialization and disk
I/O on a background task, so even a large sidecar is not written on the render
thread. Saving also happens synchronously at every destructive boundary:
- **Window close / Alt+F4 / Exit** — `App` calls `ctx_.saveProject()` on
  shutdown.
- **File ▸ Close Binary** — flush, then unload and `reset()`.
- **Switching targets** — `loadBinaryPath` / `loadRawPath` call `saveProject()`
  for the *outgoing* binary before loading the new one.
- **Projects tab "Save project now"** button — an explicit manual flush.

Binary View mirrors live editing state into `ctx.project`, and mutation sites call
`markProjectDirty()`. The App tracks the in-flight revision separately: edits that
arrive during a save remain dirty and schedule another commit. A failed save is
surfaced in the status UI, retains the in-memory state, and prevents close/target
replacement from silently discarding it.

`SaveProject` itself enforces the empty-project policy: if `hasContent()` is
false it records the open in the recents index but writes **no** sidecar (and
leaves any pre-existing sidecar from a prior, content-bearing session untouched);
otherwise it writes the sidecar and upserts recents.

Project, recents, and preferences commits share `Core/AtomicFile` and use a
same-directory unique temporary file written through Win32 `WriteFile`, flushed with `FlushFileBuffers`,
closed, and atomically installed with `ReplaceFileW`/`MoveFileExW`. Replacement
preserves a `.bak` copy of the previous good file. Loads try the primary first and
fall back to that backup after corruption or a torn external edit; abandoned temp
files are cleaned up. Reads reject oversized inputs before allocation: project
sidecars are capped at 64 MiB, recents at 4 MiB, and preferences at 64 KiB.
`Preferences` validates every known field and encoded FILE/LIVE recent query before
accepting a primary or backup; malformed data cannot silently enable symbol-network
access. A sidecar, recents, or preferences failure propagates into visible dirty/error
state.

### The recents index and the Projects tab

`index.json` is a flat array of `RecentEntry` (`hash`, `path`, `name`, `arch`,
`status`, `lastOpenedUnix`). `upsertRecent` removes any existing entry for the
same hash, inserts the new one at the front (most-recent-first), and trims the
list to **50** entries. `LoadRecents` tolerates either a bare array or an object
with a `"projects"` array, skipping malformed entries. `RemoveRecent(hash)` drops
an entry and reports whether anything changed.

The **Projects** tab (`ProjectsTab.cpp`) is this index made visible. It re-reads
`index.json` on first paint and whenever the active project hash changes, so a
newly opened target shows up without a manual refresh. The layout is a left list
(Name / Arch / Opened, with human-readable local timestamps via `whenStr`) and a
right details pane. Interactions: **Open Binary…** and **Refresh** buttons;
double-click or right-click ▸ **Open** to reopen (which calls
`ctx.loadBinaryPath` and switches to Binary View); right-click ▸ **Copy path** /
**Remove from list**. The details pane shows the selected entry's metadata and,
for the currently loaded binary, a live "Saved analysis" summary (counts of
comments, renames, bookmarks, breakpoints, patches) plus the **Save project now**
button and a reminder that it auto-saves on close/exit.

### Save ASM / Save C (source export)

Source export is intentionally separate from the persisted project and the analysis
report below. **File ▸ Save ASM… / Save C…** exports either every analyzed function/
executable range or one selected function. ASM preserves resolved names and analyst
comments. On x86/x64, C has two contracts: `CodeExportCStyle::Readable` keeps the decompiler's
display pseudo-C, while `CodeExportCStyle::Compilable` produces a self-contained portable
C11 translation unit with normalized identifiers, declarations/stubs, and explicit
fallbacks where the lightweight decompiler cannot express an operation faithfully.

`Core/CodeExport` keeps generation independent of ImGui and Win32. The pure
`GenerateCodeExport(request, decoder, out, cancel, progress)` function streams into an
arbitrary `std::ostream`; `CodeExportService` wraps it in a dedicated one-job thread and
opens the path chosen by `AppContext::selectCodeExportPath`. A request snapshots the
engine/architecture, scope, function table, import/discovered/user name layers, comments,
source name, destination, and expected image revision. The worker creates its own decoder
through the injected factory, so a long whole-program export neither touches `ctx.disasm`
nor occupies the load-time `AnalysisService` worker.

Progress is structured (`Preparing`, `Assembly`, `Decompiling`, `Finalizing`) rather than
a spinner-only flag: assembly reports bytes, C reports functions and the current function
VA, and both expose bytes written. `cancel()` is non-blocking for the render thread;
`cancelAndWaitIdle()` is the stronger lifetime barrier used before loading, closing,
patching, or reverting the borrowed `BinaryFile`. The source files are write-out artifacts
only; their paths/options are not stored in the project sidecar and there is no import path.
The service writes a same-directory temporary file and commits it only after generation and
flush succeed; an existing destination is protected by a rollback backup during replacement,
and failure/cancellation cleans the staged artifacts without changing that destination.

### Export Analysis (Markdown / HTML report)

`Report.{h,cpp}` are pure formatters (no ImGui/Win32, hence sandbox-testable) that
turn analysis into a shareable document. `RenderReportMarkdown` and
`RenderReportHtml` consume a `ReportInput` containing the title (binary file name),
content hash (hex), arch, engine, function and string counts, and lists of
`renames`, `comments`, `bookmarks`, `notes`, plus a vector of `ReportFunction`
(`address`, `name`, inferred `signature`, decompiled `pseudocode`).

`BinaryViewTab::exportAnalysis` (triggered by **File ▸ Export Analysis…**, which
sets `requestedExportAnalysis` and routes to Binary View) assembles the input: it
takes the renames, comments and bookmarks (each sorted by address), the notes, and
the function/string counts. It then decompiles **only the analyst's user-named
functions** — for each it computes the heuristic `guessSignature` and the
structured `decompileFunctionText` — capped at 300 functions to keep a large
rename set fast (any beyond the cap are counted and reported as omitted). The
report deliberately scopes to *named* functions because those are the ones the
analyst cared about, keeping the document focused rather than dumping the entire
program.

Both renderers emit a metadata table (hash/arch/engine/function count/string
count), then sections for **Renamed symbols**, **Comments**, **Bookmarks**
(each as an address-keyed table, with `_none_` when empty), a **Notes** block,
and a **Decompiled functions** section with each function's name, address,
inferred signature (clearly italicized as heuristic) and pseudo-C body. The HTML
variant is a self-contained dark-themed page (inline `<style>`, no external
assets) and HTML-escapes all user text via `esc`; the Markdown variant fences
code/pseudocode and back-ticks addresses.

`AppContext::exportAnalysisFile` drives a Win32 **Save As** dialog seeded with
`<binary>_analysis.md`, offering Markdown and HTML filters. The chosen extension
decides the body: a case-insensitive `.htm`/`.html` suffix writes the HTML render,
anything else writes Markdown. On success it reports the byte count and path; a
cancelled dialog produces no popup.

#### Limitations & notes

- **Heuristic content is labelled.** The report's function signatures come from
  `guessSignature` (inferred, no full type recovery) and bodies from the
  lightweight decompiler; these are best-effort and the signature lines are
  presented in italics. The exported decompilation inherits all of the
  decompiler's structuring limitations.
- **Reports are export-only.** They are write-out artifacts; there is no import
  path, and they are not part of the persisted project state.
- **Sidecars and recents are crash-recoverable filesystem transactions.** Each
  commit is flushed and atomically replaced, with the prior good file retained as
  `.bak`; load falls back to it when the primary is invalid. Hand-edited content is
  still treated as hostile and subjected to the same schema/range validation.
- **The empty-project policy is intentional.** Opening a binary and doing nothing
  writes no sidecar; only real annotations create one. The first content-bearing
  save is what materializes `<hash>.json`.
- **Recents are capped at 50** and keyed by hash, so two copies of the same bytes
  collapse to one entry; conversely, an analyzed file that is later modified gets
  a *new* hash and therefore a fresh, separate project.
- A valid saved raw mapping is part of project content and is restored before annotations;
  versions 1–3 remain readable, while new saves use version 4. Legacy patches become Ungrouped.
- **The JSON lib is minimal by design** — `double`-backed numbers (hence the
  hex-string address convention), no comments, no streaming; it exists solely to
  back persistence without adding a dependency.
