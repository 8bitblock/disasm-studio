Now we're getting somewhere. Your answers draw a very specific profile: flagship-scale, at the intersection of systems + ML + engines, something you use and explore — and crucially, something where the polished "real thing" doesn't already exist to download. That last one explains most of the misses: torrent clients, password managers, git GUIs all lose to their real counterparts. So every pitch below is something that genuinely doesn't exist in polished form. Five ideas:

1. GlassBox — run real LLMs inside your own engine, with the case off. You write the inference engine yourself in C++ (load actual open-weight models — Llama, Qwen, Phi — from GGUF files, implement the transformer math, quantization, KV cache), but the point is what you wrap around it: every internal exposed. Watch attention heads light up across the prompt as it thinks, see the probability distribution over next tokens before it picks one, scrub back through a generation and fork it, drag sampling parameters live mid-sentence. LM Studio and Ollama run models as sealed black boxes; the interpretability world lives in Python notebooks. A desktop microscope for LLMs does not exist. It's NetLab grown up to flagship scale — same "see inside the net" soul, but the net is a real frontier-adjacent model, and the app doubles as your daily local chat tool. Systems + ML + engines in one box.

2. TensorLab — IDA Pro for neural networks. DisasmStudio opens binaries; this opens models. Load any ONNX / GGUF / safetensors file and get the full workbench: the compute graph visualized, every layer's weights inspectable as heatmaps and histograms, and — the part nothing else does — surgery: quantize it, prune it, merge two models, diff two checkpoints layer by layer, benchmark before/after on your hardware. Netron exists but is a read-only viewer; everything else is scattered CLI scripts. An integrated model workbench doesn't exist, and you'd actually use it on your own VisionForge models.

3. Cortex — a reverse-engineering brain for your disassembler. A local-LLM-powered binary explainer: point it at an executable and it names unnamed functions, writes plain-English summaries of what each one does, spots "this is an AES implementation / this parses JSON," and lets you chat with the binary. The commercial versions (Binary Ninja's Sidekick) are cloud-only and paid; a local, free one doesn't exist. It could stand alone or bolt straight into DisasmStudio as its biggest feature — your systems lane and your ML lane, welded together.

4. FaultLine — a visual fuzzing studio for Windows. Co-execution engine that hammers a target binary with mutated inputs and hunts for crashes, with a live UI: coverage lighting up on the disassembly, a corpus of interesting inputs breeding new ones, crashes auto-triaged and bucketed by root cause with the faulting instruction highlighted. This is what real vulnerability researchers do, but the tooling (AFL, libFuzzer) is command-line and Linux-first. A polished visual Windows fuzzer is genuinely missing. Systems + engines + a bit of ML for input generation, and it's a serious portfolio piece.

5. Prism — a profiler that shows you why, not just where. Sample any running process, but instead of the usual flame graph, reconstruct and animate what the program is actually doing over time — call patterns, memory allocations, threads fighting over locks, I/O waits — and layer a local model on top that reads the profile and tells you in English where the time really goes and what to fix. Existing profilers are famously hard to read; an explanatory one doesn't exist. Deep systems work, with ML as the interpreter.

The strongest fit for everything you said is #1 (GlassBox) or #2 (TensorLab) — both sit dead-center on systems + ML + engines, both are things that provably don't exist yet, both are flagship-worthy, and both are daily-usable and explorable. #3 leans hardest into your existing DisasmStudio strengths if you'd rather build on that muscle.

Which of these five pulls at you — or which should I open up in more detail?


7. Chronicle — a decompiler that rebuilds source, then explains it. Feed it a binary and it recovers readable, recompilable C — but the flagship twist is a local model sitting on top that renames variables meaningfully, reconstructs struct layouts, adds comments, and narrates the algorithm. Ghidra decompiles but produces alien code with iVar3 everywhere; nothing local closes that last mile into human code. Deep systems + engines (the decompilation core) + ML (the humanizer). Direct evolution of DisasmStudio's decompiler view into its own flagship.

11. Kernel — a visual OS-scheduler and memory sandbox. Not a real OS — a flagship simulator where you implement and then watch the deep magic: your own process scheduler, virtual-memory pager, and filesystem, with every context switch, page fault, and disk seek animated live, and pluggable policies you write and race against each other. The "understand computers all the way down" itch, but as a serious explorer's lab rather than a toy. Systems + engines, and genuinely nothing like it exists polished.

i like 5,3 and 5 begin to add these to disasmstudio project. also working on 11 but as a striped down vm giveing a simulated kernal level access

---

## Implementation status (added to DisasmStudio)

**#3 Cortex — RE brain** ✅ first cut shipped.
- `src/Core/Cortex.{h,cpp}` — a PURE reasoning layer over the analyzers we already have
  (TechScan capabilities + AlgoScan crypto/algorithm matches + FunctionNamer guesses +
  FuncAnnotate + imports/strings). Produces a plain-English headline + verdict, merged
  per-behaviour findings (confidence + evidence), per-function briefs, a ranked "notable
  functions" list, and `AskCortex()` — a deterministic keyword-routed "chat with the binary"
  (crypto? network? packed? strings? entry? ...). Unit-tested (`tests/cortex_test.cpp`).
- `src/Tabs/CortexTab.cpp` — the "Cortex" tab: Analyze button → verdict + behaviours +
  notable functions (click to jump to the disassembly) + an Ask box with quick chips.
- NOTE: deliberately **no LLM dependency** (keeps the app dependency-light + honest). The
  local-model backend you described is a drop-in behind `AskCortex()` / the verdict text —
  Cortex already hands it a structured, grounded fact base. That's the next step for #3.

**#5 Prism — explanatory profiler** ✅ Prism 2 shipped.
- `src/Core/Prism.{h,cpp}` — PURE: symbolized stack samples → self/inclusive hot-function
  table + a thread-state breakdown (running / waiting / lock-contention / allocation / I/O /
  GPU) + hot call paths + a "where the time goes and what to fix" verdict. Unit-tested
  (`tests/prism_test.cpp`).
- `src/Core/PrismSampler.{h,cpp}` — a worker-owned ETW collector is preferred (sampled
  profiles plus image/thread/context-switch/wait/I/O evidence); collection quality, stack/frame
  coverage, and lost events/buffers stay visible. If Windows policy blocks ETW, Automatic mode
  records the reason and uses the labelled suspend-and-walk fallback. The fallback walks native
  x64 and WOW64 contexts. A second worker builds immutable reports off the render thread.
- `src/Tabs/PrismTab.cpp` — enter a PID → Start; choose Automatic/ETW-only/fallback; inspect
  the flame graph, selectable timeline, state bars, hot functions/paths, and verdict. Function
  and flame-node clicks navigate to the exact static image when identity mapping is proven,
  otherwise to live assembly when the matching debugger target is attached.

Follow-ups: (Cortex) local-LLM backend behind AskCortex and reuse `AppContext::analysis` instead
of recomputing on Analyze. Prism symbol quality can use the opt-in symbol service; ETW remains
subject to Windows elevation/profile-policy constraints and reports those constraints honestly.

### Update 2 — deepening pass ✅

- **Cortex** now consumes the **per-function annotation engine** (`FuncAnnotate`): each function
  gets a real "what it does" brief from its annotation summary + high-level patterns (not just its
  guessed name), carries its calling convention, and pattern-derived tags feed the highlights ranking.
  `AskCortex()` gained **per-function Q&A** ("what does sub_401500 / 0x.. do?"). The tab builds the
  annotations (bounded to 200 functions) and has an **Export** button (Markdown/HTML).
- **Prism** now reports a **per-thread breakdown** (each thread's dominant state + hottest leaf —
  "threads fighting over locks"), **per-module self-time**, and an **over-time timeline** (samples are
  timestamped with GetTickCount64 and bucketed into 30 slices). The tab shows a timeline strip and a
  threads/modules column beside the hot functions.
- Both engines stay pure + unit-tested (cortex_test / prism_test extended); full `DisasmStudio.sln`
  builds clean (0 warnings / 0 errors).

### GameMaker VM debugging — integration and live validation, 2026-09-06

- Added bounded GameMaker archive metadata, dedicated GML decoding, symbolic script breakpoints and named watches, project version 5 persistence, and integrated GML connection/inspection panels.
- Added an embedded x64 helper and exact-build Nubby runner adapter with interpreter dispatch, entry, and instance lifetime hooks; native debug events remain the pause authority.
- Fixed helper initialization stack usage; added small-thread-stack and machine-state gate regressions.
- Added frozen instance registry inspection, canonical numeric writes with stop/revision/lifetime validation, and verified payload restoration in real Nubby tests.
- Fixed native/GML hook overlap rejection, post-write hook rollback ownership, original page-protection restoration, unreadable-thread rejection, and runtime code binding status.
- Added visible rejection of invalid claimed GML stops, module-lifetime checks, callback draining, asynchronous unload, and fresh-session reconnect handling.
- Real Nubby validation has exercised instruction stepping, step over/out, global and instance numeric edit/restore, native breakpoint coexistence, helper unload, and reconnect. Three-restart acceptance, final performance measurements, and the final Release/regression audit remain in progress.

- Verified the same symbolic breakpoint and ItemSfx watch across three real Nubby restarts, with different resolved heap addresses and an unchanged project intent file.
- Added guarded extended-state saves for all enabled XCR0 components, including AVX-512 registers/opmasks; production-MASM preservation tests and the small-stack initialization regression pass.
- Fixed frame-local watches to follow the same thread/frame incarnation across stepping while keeping numeric writes bound to the exact current stop.
- The latest x64 Release application, embedded-helper freshness check, headless GML listing integration, native x64 debugger suite, archive/decoder/runner/inspection/project regressions all pass. A fresh live run with the extended-state helper also passes.
- Added an opt-in production lifecycle harness for setup failure/cancellation, running/paused/pending-stop disconnect, debugger host disappearance and explicit test-target exit; its execution and the remaining edge-case audit are in progress.

- Passed production lifecycle tests for setup failure/cancellation, running/paused/pending-stop disconnect, and abrupt debugger-host loss while running or paused.
- Fixed process termination at a held GML stop: revoke pause authority and release the pending event when Windows reports the exit status, allowing EXIT_PROCESS cleanup to finish without target writes.
- Revalidated native x64 debugging and produced the current self-contained build/gml-verified/DisasmStudio.exe with verified embedded helper bytes.
- Extended helper frame-state fixtures for recursive frames, loop revisits, multiple-frame unwinding, reused anchors, and unrelated exception propagation.

- Extracted the production hook-write transaction into a bounded testable core and covered partial writes, rollback failure, protection/cache failure, and foreign-byte rejection.
- Removed allocation from remote write verification so a successful hook write cannot be followed by a throwing readback allocation.
- Added explicit compiled runner capability records and connection evidence; packed operand-stack values and complex edits remain visibly unavailable.
- Kept immutable GML snapshots readable during host instance-map inspection and fixed cancellation racing the first native pause publication.
- Broader live traces proved entry into a named GML callee, return to its original caller, and Step Over across a named GML call. The sampled menu contained no repeated instruction/frame; loop and unwind semantics are covered by deterministic model/helper fixtures, without claiming a live loop was observed.

- Completed the GameMaker requirement audit and documented the exact connection, stepping, variable-edit and persistent-watch workflow in docs/GAMEMAKER_DEBUGGING.md.
- Fixed Step Out for top-level GML events and complete-chain unwinds; live Nubby testing confirmed it stops at the next verified event after the original frame leaves the active call chain.
- Passed the final live trace through a real loop, named GML call entry/return, call Step Over and top-level Step Out; the full numeric edit/restore, native coexistence and reconnect harness also passes with the final embedded helper.
- Added helper shutdown refusal and duplicate-initialization coverage, and verified failed preparation can be cleared and retried without native reattachment. Removed a large automatic temporary from the new test fixture after its stack-overflow regression caught it.
- Revalidated 15 selected Core/native tests, the headless production GML panel/listing integration, x64 Release build and embedded-helper freshness. Preserved three-restart acceptance and recorded 12 final baseline/idle/armed CPU/cycle samples without claiming a precise slowdown percentage.
- Delivered build/gml-verified/DisasmStudio.exe and saved hashes, test results and supported limits in build/gamemaker-final-verification.json; the game executable/archive hashes are unchanged and the user's older running application was left open.
- Added a read-only score inspection utility under build/gml-inspect using the production archive parser/decoder. Verified scr_AddNumber updates PotentialNum from local _Recalculated at bytecode offsets +0x354 through +0x368; no game bytes or debugger behavior were changed.

- Made static cross-reference analysis respect code/data islands, share classification and analyst overrides with Cortex, and validate image/decoder/override/scope identities before adopting cached results.
- Centralized typed instruction references; prevented false FS/GS static targets and typed-to-text fallbacks while preserving LEA, EIP/RIP, and address-zero behavior.
- Connected Binary View to bounded document navigation with selected-source return anchors, representation restoration, explicit Hex offsets, and debugger-owner retirement; unified strict goto parsing and one-submission asynchronous symbol navigation.
- Replaced the References modal with a pinned, filterable Xrefs panel that retains the target and selected source while navigating, with explicit FILE/LIVE coverage and stale-result retirement.
- Added shared contextual annotation, bookmark, FILE/LIVE handoff, and checked Run to Cursor actions across code views and Ctrl+K; made patch preview, Copy, Apply, padding, and completion outcomes consistent.
- Added resizable, persistent, DPI-aware Assembly/Live Assembly columns and updated disassembly/workflow documentation; expanded Core and production-object UI regression coverage.
- Verified the completed workflow upgrade with 16 selected Core test binaries (instruction references, both native decoders, classification planning/service/cache, function analysis/annotations, triage, navigation/address parsing, project round-trips, lazy listing, and source export), plus the production-object headless ImGui suite with zero failures.
- Confirmed x64 Release build and embedded GameMaker helper verification. Headless UI checks cover 100/150/200% scaling, an 820x560 narrow listing, saved table settings, pinned-reference stale-scope retirement, first-follow history, one-submission symbols, source-bound actions, NOP-padded Copy/Apply, disabled sets, and identity-rejected live mirroring. New UI debugger cases use simulated snapshots and do not attach to a target.

### Binary loading performance — 2026-09-06

- Reused already-loaded Raw bytes and their pristine hash when restoring saved base/entry/landmark mappings, eliminating a second file read; invalid remaps leave the staging image intact.
- Moved initial content hashing to the binary-load worker so project staging does not hash a large image on the render thread.
- Removed quadratic duplicate-name suffix searches and repeated whole-map import-thunk propagation while preserving inferred names and evidence.
- Changed code/data padding scans to walk and skip covered spans, preserving the existing classification partition and ISA alignment.
- Accelerated short exact signatures used by runtime/Java discovery with vectorized byte searching and a bounded dense-input fallback; wildcard matching retains its existing behavior.
- Removed redundant function/string copies and repeated downstream xref hashing; rejected over-budget cache snapshots before allocating their copies and preserved scanned-string inputs for cached combined listing requests.
- Added a reproducible production-decoder load benchmark with pass timings, empty/retained analysis-cache modes, source fingerprints, and output checks; see tools/binary_load_benchmark.md for measurement scope and results.
- Generated a preview-only loading UI proposal with a ready-to-browse banner and per-stage progress details for user feedback; no visual redesign was applied.
- Verified nine selected Core test binaries, the production-object headless listing integration, and a clean x64 Release build with embedded-helper freshness verification. Saved build/source hashes and validation details in build/binary-load-verification.json.
- Confirmed identical function/string/call-edge/xref fingerprints across before/after production-decoder benchmarks. Focused stress fixtures show substantial reductions, but full-load timings varied with background machine activity; no general end-to-end speedup percentage is claimed.

### Cleaner disassembly and quiet activity — 2026-09-06

- Applied the approved cleaner Assembly and Live Assembly layout with softer column dividers and subtle alternating rows; retained saved column widths, visibility, controls, and all existing panels.
- Preserved pulsing breakpoint-hit/RIP, cursor, jump-target, navigation-arrival, and trace glows, including foreground halos above the listing.
- Unified static/live jump-arrow drawing with theme colors and DPI-scaled gutter geometry; retained backward/forward paths and off-screen destination indicators.
- Kept strings, API names and purposes, symbols, decoder annotations, function notes, JVM stack explanations, and user comments in the listing, using the active theme's semantic colors.
- Made conditional comments say jumps if the condition holds and otherwise falls through; paused live branches show jumps or falls through from current flags. Kept detailed static branch semantics honest and available on hover when the column clips text.
- Replaced large analysis bars with quiet phase text and small stop controls; the bottom-right activity area exposes exact progress and individual job cancellation on hover/click, retaining errors, trace/export status, metadata, and cursor-copy.
- Added production-object render regressions for static/live glow effects, breakpoint markers, trace, arrows at 100/150/200 percent scale in light/dark themes, and every existing annotation channel alongside conditional comments.
- Passed native/JVM annotation tests and the production-object headless listing suite with zero failures; verified the x64 Release build and inspected real static loading and compact progress in the native app.

### Full workbench UI overhaul — 2026-09-06

- Applied a consistent graphite Midnight theme, quieter shared buttons/inputs/tables/tabs, clearer splitters, and compact empty states across all nine workspaces; retained every palette, DPI scale, density setting, and semantic glow color.
- Reorganized the shell into document tabs, workspace tabs, grouped debugger commands, content, and compact status; added direct global search access, a full-name document list, and responsive document/debugger controls.
- Moved Binary View's Functions/Strings/Bookmarks navigator to the left, added name-first function browsing, and wrapped navigation, representation, Assembly, Live Assembly, Hex, and GML controls to keep them accessible at smaller widths.
- Kept all Binary View representations, metadata views, lower analysis/debug/data tools, context menus, annotations, API purposes, strings, user comments, jump arrows, branch wording, and breakpoint/RIP/cursor/target/arrival/trace glow effects.
- Updated Projects, Communications, Network Monitor, Signature Scanner, Memory Tools, Binary Diff, Binary Tech, Cortex, and Prism with consistent headers, action rows, results sections, and responsive master/detail layouts; preserved existing jobs, cancellation, evidence, navigation, persistence, and live-target authority checks.
- Redesigned Ctrl+K results with a second line of context and complete hover details; fixed overlay stacking so outside clicks dismiss search without activating the workbench underneath.
- Layered static/live listing glows and arrows after the scrolling table's rows so they remain visible over the listing and are properly covered by search, menus, and modal windows.
- Clamped App dialogs to the viewport, wrapped Raw architecture/firmware and symbol settings choices, kept the status strip inside the window, and widened the Memory Tools freeze interval input.
- Added production-object workbench regression checks for all nine shortcuts, shell geometry at 820x560 and 1600x960 with 100/150/200 percent DPI and dark/light themes, palette geometry/input ownership, and retained listing signals. Documented feature access in docs/UI_OVERHAUL.md.
- Passed the final x64 Release build with embedded-helper verification and the complete production-object ImGui integration suite with zero failures; inspected all nine native workspaces, populated static findings, and corrected search layering/dismissal. Saved the preview, logs, executable hash, and verification scope under build/ui-overhaul-*.

### Compact workbench refinement — 2026-09-07

- Made the narrow evidence rail open a viewport-bounded inspector popup, retaining manual pane choices and width and closing on navigation or drawer handoffs.
- Kept the containing function highlighted for internal instructions and exact owned chunks, with checked LIVE-to-FILE mapping and no highlight for unrelated addresses.
- Moved Strings counts, scan progress, partial-result warnings and empty-search guidance above results; added consistent Escape-to-clear search and retained clipped, generation-cached lists.
- Kept FILE/LIVE/FILE-offset labels and addresses visible in the breadcrumb, elided long context, enabled Tab/Space copying with confirmation, and measured workflow controls before wrapping.
- Passed the Release build with embedded-helper verification and the focused production-object UI suite; checked the refined static workflow in the native app. Candidate: build/x64/UIRefinement/DisasmStudio.exe. Details and verification scope: docs/UI_REFINEMENT.md.
- Passed the full production-object UI suite with zero failures and relinked the final candidate from the same 118 verified objects. Recorded source/executable hashes and test logs in build/ui-refinement-verification.json.

### Feature UI production polish — 2026-09-07

- Added selected Cortex evidence, complete evidence copy and FILE location actions, searchable notable/all function briefs with cached clipped rows, responsive pane tabs that preserve split preferences, and bounded question history with quick topics and clear/copy actions.
- Refined Signature Scanner with explicit FILE/LIVE targets, inline pattern validation and byte/wildcard counts, offline library access, retained result/function search, copy/navigation actions and useful empty states. Current Scan retains the pattern and target that actually produced its results.
- Improved Binary Tech evidence/occurrence presentation, image-and-decoder-keyed previews and retained filtering; added mapped-location navigation and FILE-address copy.
- Improved Binary Diff baseline/candidate setup, compact hex panes and horizontal preview access; added semantic result search, changed-only filtering, fixed headers and empty-state guidance, and prevented unrelated matched details from appearing under Added/Removed/Transfers.
- Made project metadata wrap and stack in narrow panes, clipped recent rows, preserved literal names, and added clear-search, reveal-hidden-selection and copy-path controls.
- Added populated production-object feature UI regressions and multi-scale detail-row checks. Build/test/native verification and release scope are recorded in docs/UI_PRODUCTION_POLISH.md.

### Automatic analysis and tracing improvements — 2026-09-07

- Fixed global analysis admission so work queued behind a busy document worker does not stall other documents; retained interactive preemption and the process-wide worker limit.
- Corrected call-graph, triage and decompiler cache identity for inferred non-returning functions, and preserved those inputs when unrelated requests coalesce.
- Fixed paused trace start/stop/restart servicing, checked instruction-pointer restoration, and simultaneous queued one-shot hits from multiple threads.
- Added executable-page admission, retained ownership and retry controls after restoration failure, and module-unload invalidation for historical trace addresses.
- Enforced the 65,536-site trace bound and removed repeated vector copying/sorting from unchanged per-frame trace snapshots.
- Bounded planner root/descriptor work per frame, excluded invalid decoder rows, retired boundary authority after decoding failures until independent roots, and prevented coverage from spanning data/folded/undecoded gaps.
- Added analysis, pure trace-plan, real x64/WOW64 debugger and production-object UI regressions; built a coherent isolated candidate without replacing the user's running Release session. Details and exact verification scope: docs/AUTO_ANALYSIS_TRACING.md.

### Feature UI final verification — 2026-09-07

- Final UI verification: packaged build/x64/UIProduction/DisasmStudio.exe; feature and full workbench suites passed with zero failures against 121 matching production objects per suite. Native Cortex, scanner, tech, diff and Projects flows passed; exact build/source hashes and QA scope are recorded in build/ui-production-verification.json and docs/UI_PRODUCTION_POLISH.md.

### GML value and live AOB scanning — 2026-09-07

- Replaced the synchronous live byte search with an asynchronous masked-pattern worker. `?` and `??` now remain real wildcard bytes instead of silently ending the parsed pattern, and matches spanning 1 MiB read boundaries are found exactly once.
- Removed the legacy 256 MiB Binary View and 512 MiB Sig Scanner AOB coverage cutoffs, retained a bounded 4,096-result cap, used breakpoint-masked exact-session reads, and surfaced complete byte coverage plus partial memory-map, short-read, unreadable-chunk, cancellation, and cap status.
- Kept Pattern completions bound to their requesting Binary View token so another document cannot consume them, and added targeted cancellation for replaced, cleared, or retired searches without stopping sibling live work.
- Made uncapped Pattern work cancel promptly during service teardown, retained token-owned completions independently of the bounded shared-result queue, and cancel a document's pending Pattern requests when that document closes.
- Extended GML numeric handoffs so Inspect selects the real 4- or 8-byte payload and an explicit **Prepare typed scan in Memory Tools (session)** action configures Exact Float64/Int32/Int64 scanning without auto-running or replacing the analyst's scope.
- Added worker regressions for wildcards, chunk boundaries, caps, partial reads, epochs, per-document routing, and targeted cancellation; added production-object UI coverage for retained search status and GML typed-scan ownership/selection behavior.

### Patch byte restoration — 2026-09-07

- Fixed live patch originals and rollback captures retaining physical debugger INT3 bytes; ordinary patches, hot patches and revert rollback now use exact-session breakpoint-masked reads.
- Fixed overlapping live patch restoration overwriting surviving patches outside the reverted span; compose only survivor intersections, with matching session and patch-set ownership and independent FILE set state.
- Added pure restoration regressions and opt-in production UI/debugger tests for armed breakpoints, breakpoint removal before revert and recovery after a rejected static commit. Details: docs/PATCH_BYTE_RESTORATION.md.
- Verified the x64 Release build with embedded-helper verification, all four focused patch test binaries, and the full production-object UI suite with live restoration tests enabled (zero failures). Built candidate: build/x64/PatchRestoration/DisasmStudio.exe.

### Main integration — 2026-09-07

- Collected the accumulated debugger lifecycle, trace, live AOB scanning, GML inspection, address navigation and patch restoration fixes with their supporting workbench, analysis, signature library, tests and documentation.
- Restored this source snapshot's Git history from `8bitblock/disasm-studio` so the changes can advance the existing `main` branch without replacing its history.
- Verified a fresh Release x64 build and embedded helper, the 142-entry test manifest, five focused Core suites, and both production-object UI suites with zero failures; the full workbench run included live patch restoration. Logs: `build/push-main-*.log`.

### Peggle helper integration — 2026-09-07

- Added the standalone offline Peggle cursor controller, read-only probe and VS2022 build wrapper, with documented native capture/release behavior and collision verification.
- Added the AOB trainer profile and release recipe, retaining the distinction between the helper's earlier live verification and the trainer group's untested gameplay behavior.
- Rebuilt the helper and probe successfully with VS2022 `/W4`, checked all seven profile patches for valid byte syntax, equal original/replacement lengths and in-pattern offsets, and removed a trailing blank line from the JSON. This integration did not run either tool against the game.

### Axiom-inspired UI implementation — 2026-09-08

- Added a separate Axiom theme with near-black code surfaces, navy panels, blue selection and restrained syntax colors; preserved previous theme IDs/defaults, readable font baselines, zoom and density.
- Applied shared compact headers and clearer action/evidence grouping across Projects, Communications, Sig Scanner, Binary View, Memory Tools, Binary Diff, Binary Tech, Cortex and Prism.
- Consolidated Assembly/Live Assembly display options into Display and instruction/rebuild actions into More; retained seven representations, Functions/Strings, independent drawers/inspector and checked shell execution controls.
- Added responsive JDWP Browse/Bytecode/Session layouts and Server Watch events/details layouts; retained GML verification, coverage/drop/error visibility and identity-checked logging behavior.
- Added independently scrollable Prism chart/report areas and compact views; preserved table identities and retained split choices. Corrected scaled Memory region columns with horizontal access.
- Added production-object interaction/retention fixtures and optional hardware DX11 captures with production fonts. Main-agent build, test and visual verification scope is recorded in docs/AXIOM_UI.md.
- Fixed the Core test runner's compiler discovery when multiple cl.exe paths are available by selecting the first resolved command.
- Corrected Pseudocode's initial space allocation and horizontal access while preserving manual split choices; clarified captured live-flag hints, retained a full Memory address-table row at compact 150% zoom, and replaced unsupported runtime-page glyphs.
- Verified the Release x64 candidate and embedded helper, preferences/shared-widget checks, and feature/full/release production UI suites with zero failures and 126 matching candidate objects per production suite. Main-agent visual review covered 75 hardware DX11 fixture captures; interactive live-target and physical multi-monitor DPI checks remain pending, and the optional live patch-restoration test was not rerun.
- Verified unsaved register-editor text, exact pause ownership, populated back/forward history and FILE selection across Axiom, Midnight and Light theme switching without submitting target writes.

### Axiom color and rounding refinement — 2026-09-08

- Increased Axiom's color with richer navy panels, bright blue selections and controls, violet document tabs and panel headers, and more vivid syntax/status accents.
- Rounded Axiom's shared controls/tabs, badges, search fields, panels and popups; removed theme-specific square-corner overrides while preserving existing themes, fonts, spacing, hit targets, IDs and state.
- Updated the custom shell's document/feature tabs, execution controls, search and address fields with rounded fills and clearer hover/focus outlines.
- Built the refreshed Release x64 candidate in build/x64/AxiomRounded, verified its embedded helper, reran all five preferences/widget/production UI suites with zero failures and matching objects, and refreshed the 75 hardware DX11 captures for main/page-agent visual review. Interactive live-target and physical monitor DPI checks remain pending.

### Multi-row instruction patching — 2026-09-08

- Fixed normal Patch, More > Patch and P to use the complete adjacent selection, including the last instruction, in FILE and LIVE assembly; disjoint selections remain refused.
- Enabled Shift/Ctrl selection and dragging across address, byte and instruction cells, preserved selected rows on right-click, and kept the listing stable under pointer selection.
- Replaced the small patch text buffers with complete assembly/hex drafts and retained exact session/byte validation for live region patches.
- Added production-object regressions for mouse selection, normal Patch dispatch, replacement bounds, retained instruction snapshots, long drafts and hex-only architectures; documented the workflow in docs/MULTI_ROW_PATCHING.md.
- Verified the final Release x64 build and embedded helper, then the full 126-production-object listing UI suite with zero failures, including address/byte/instruction drag selection and contained-child live multi-row apply/revert and stale-byte/session rejection. Logs: build/multi-row-patch-build.log and build/multi-row-patch-final-tests.log.

### Axiom screenshot reference correction — 2026-09-08

- Replaced the rejected broad violet/blue fills with screenshot-sampled near-black panels, neutral controls and restrained blue selection; limited rounding to compact controls, selected rows and status capsules.
- Refined the function and optional Sections navigator with function marks, right-aligned addresses, a blue selection keyline and actual section sizes; retained existing navigation, filters and analyst metadata.
- Restyled the breakpoint drawer with arming rings, muted red selected rows, explicit status capsules, Add breakpoint and row actions; preserved real FILE/LIVE ownership, arming failures, condition/every-N editing, hardware controls and exception settings.
- Added a genuine pause-reason capsule and compact thread selector, retaining normal text size and checking the popup's target and pause before using the existing checked debugger action.
- Added focused shell/breakpoint interaction and retained-table fixtures; main-agent candidate build, visual review and verification scope are recorded in docs/AXIOM_UI.md.
- Added the reference breakpoint tab's red dot and actual unique count capsule while preserving its original tab identity; corrected stale popup ownership, failed-condition retry and saved column retention across theme changes.
- Verified the final AxiomReference Release x64 candidate and embedded helper: all five preferences/widget/production UI suites passed, with 126 matching candidate objects per production suite. Main-agent and page-agent visual review covered 80 hardware DX11 fixture captures; interactive live-target and physical multi-monitor DPI checks remain pending, and the optional live patch-restoration test was not rerun.

### Axiom components across every theme — 2026-09-08

- Applied the Axiom breakpoint drawer, count tab, arming rings, row actions, function/section navigator and steady execution markers to all ten themes while retaining each palette's colors.
- Shared the checked thread selector and pause-reason capsule across the shell, with consistent Detached/Running/Paused status pills and an explicit clickable Idle activity capsule.
- Unified rounded controls, search fields, tabs, badges, state dots and quiet panel headers throughout the UI; preserved theme IDs, fonts, zoom, density, table columns, analyst drafts and checked debugger actions.
- Updated existing breakpoint/shell fixtures to exercise every theme and adjusted the listing regression for the shared accent execution marker; trace coverage retains its separate success color.
- Built `build/x64/AxiomAllThemes/DisasmStudio.exe` and verified its embedded GameMaker helper. Shared-widget, feature-page and focused release-workbench checks passed; dark/light breakpoint captures and twelve shell state/layout captures were visually reviewed without clipping or overlap defects.
- The full production workbench suite also passed with zero failures, including its all-theme/density/zoom matrix; all three production suites used 126 identical object snapshots. Logs: `build/axiom-all-themes-build.log`, `build/axiom-all-themes-feature-tests.log`, `build/axiom-all-themes-workbench-tests.log`, and `build/axiom-all-themes-full-final-tests.log`. The opt-in live patch-restoration test remained skipped; this presentation change did not perform a live-target walkthrough.

### Pause breakpoints without removal — 2026-09-08

- Added a clickable Enabled ring and Pause breakpoint / Enable breakpoint row actions across themes; retained breakpoint rows, conditions, every-N settings, counters and condition drafts.
- Persisted paused FILE breakpoint intent with backward-compatible optional enabled state; disabled saved sites stay out of automatic arming, and enabling after reopen preserves instruction-boundary validation.
- Added checked native software breakpoint enable/disable requests with retained metadata and separate byte ownership; shared internal hooks, stale-session refusal, failure reporting and instruction step-off remain authoritative.
- Added project save/reopen, production UI and native debugger regressions; verification details are recorded in docs/BREAKPOINT_PAUSE.md.
- Corrected held-instruction pause/re-enable and multi-thread queued-hit handling, kept disable/remove/re-add ordering consistent, preserved failed-install retry settings, and avoided an unnecessary exclusive step when continuing with the current breakpoint disabled.
- Verified the BreakpointPause Release x64 build and embedded helper, project round-trip checks, focused native pause/resume checks, and release/full production UI suites with zero failures; the UI suites retain 126 identical candidate object snapshots and 47 refreshed hardware DX11 captures. The broader native x64 suite still has four checked-RunTo assertions failing on a safe peer-suspension refusal, reproduced without pause/enable calls; this limitation is recorded in docs/BREAKPOINT_PAUSE.md.

### Consistent content styling across every tab — 2026-09-08

- Extended the Axiom presentation throughout Projects, Communications, Sig Scanner, Binary View, Memory Tools, Binary Diff, Binary Tech, Cortex and Prism, including their nested pages and data drawers.
- Shared quiet table headers, alternating rows, horizontal separators, compact section headings, real inventory counts and status capsules; retained native IDs, saved column choices, fonts, zoom, density and checked actions.
- Cleaned up Threads, Watch, Results, Patches, Call Stack, annotations, types, triage, references and other Binary View data panels; scaled fixed columns and kept specialized code, hex and graph views intact.
- Improved compact/high-zoom readability: Memory viewer actions stay accessible, region permission filters stay together, Communications module names can scroll, Server Watch details wrap to the viewport, and long annotation notes elide with full-text hover details.
- Preserved visible native tab overflow arrows/menu text and full count tooltips; added a focused shared-widget regression for menu glyph visibility and stable tab/nested-table identities.
- Built build/x64/AxiomAllTabs/DisasmStudio.exe and verified its embedded helper. Shared-widget, feature-page, focused release-workbench and full production-workbench suites passed with zero failures; the three production suites used 126 identical object snapshots before the final local annotation-text correction.
- Visually reviewed the feature pages plus 25 additional Binary View drawer captures, including compact 150% zoom and labelled authored records. Implementation, final focused recheck and verification scope are documented in docs/ALL_TABS_UI.md.
- The final annotation ellipsis build passed the focused release-workbench suite with zero failures, and refreshed hardware DX11 drawer captures confirmed clean text/confidence separation. Log: build/all-tabs-workbench-reviewed-tests.log. Final candidate SHA256: DF52D016FF5FDA626806E85EF1A8B939594471E826F08E735BCB572621EF14CB.

### Live Assembly scrolling after string references — 2026-09-08

- Fixed upward live browsing snapping back to an analyzed function start on the frame after a refill; committed window alignment now survives idle frames and content refreshes.
- Preserved the visible instruction position across bounded refills, retained decoded overlap when scrolling forward, and kept useful rows at unreadable/nonadvancing boundaries.
- Made manual scrolling release Follow RIP immediately and repeated reference navigation recenter its instruction, while preserving selected addresses and history during browsing.
- Added contained-child production-object tests for decoded LIVE string references, repeated wheel/Page navigation, viewport continuity, function boundaries, Follow RIP release and unreadable memory boundaries; implementation details are in docs/LIVE_ASSEMBLY_SCROLLING.md.
- Fixed process reads spanning an unreadable next page so the valid preceding instructions remain visible, using bounded page reads and checked session validation.
- Verified the final Release x64 build and embedded helper, focused contained-child live scrolling (32 stable refills), full production UI suite, and listing layout helpers with zero failures. All 126 test object snapshots match the final build; logs and scope are recorded in docs/LIVE_ASSEMBLY_SCROLLING.md.

### Patch revert controls, fit and permanent visibility — 2026-09-08

- Fixed the patch-row selection hitbox covering Revert; exact-row actions remain accessible before the scrollable byte columns.
- Put patch records first in short drawers and moved set management/comparison into a sized, scrollable manager, retaining action feedback in the patch panel.
- Kept Patches fixed in both lower tab groups, including empty projects and collapsed drawers, so presets and ordinary tab scrolling cannot hide it.
- Preserved precise restoration failures and stale-record feedback; FILE-only failures no longer report a fictional LIVE rollback.
- Added production regressions for actual mouse clicks, compact patch layout, permanent tab visibility, FILE refusal/recovery and contained-child LIVE restoration. Verification is recorded in docs/PATCH_BYTE_RESTORATION.md.
- Verified all five focused Core tests, production FILE/LIVE restoration and mouse/compact-layout checks, Release x64 build and the focused release-workbench suite. Reviewed 90%/150% DX11 captures. The broader suite reported one unrelated execution-history layout assertion; exact logs and snapshot scope are recorded in docs/PATCH_BYTE_RESTORATION.md.

### Recorded execution path and Step Back — 2026-09-08

- Added explicit native Record controls and a bounded, session/thread-owned instruction history for inspecting the path leading to a breakpoint.
- Added Step Back and forward history navigation with captured instruction bytes and read-only register observations, preserving repeated addresses and loop order.
- Kept the real target stop distinct from the selected historical record; history browsing never rewinds or writes process state, and ordinary Continue cannot reconstruct an earlier unrecorded path.
- Documented recording limits, single-step overhead, single-thread user-mode scope and ownership in docs/EXECUTION_HISTORY.md.
- Added real x64/WOW64 child-process regressions for chronological loops and calls/returns, captured code/registers, checked ownership, recording bounds, exception stops, unsupported transition guards and cleanup; the focused x64 history test and full WOW64 suite pass.
- Verified the Release x64 build and helper resource, plus isolated production UI/captured-byte tests and visually checked normal/narrow DX11 captures. The broader x64 suite reports six WinINet Network Watch assertions after peer-suspension access denied; its history case passes. Exact evidence and limitations are recorded in docs/EXECUTION_HISTORY.md.
- Verified the final 127-object production static-listing/UI integration suite with zero failures, including recorded-history controls, captured instruction decoding, viewport shrinking and existing all-theme compact shell checks (build/execution-history-ui-test.log).

### Function-name accuracy and native backtrace — 2026-09-09

- Replaced function-naming API substring matches with exact, decoration-normalized families; added combined file/registry operations, descriptor I/O, native memory/file calls, mapping, enumeration and library-resolution names while preserving user/export names and heuristic evidence.
- Restricted naming to bounded reachable function bodies; guarded neighboring functions, dead instructions, partial decodes/control flow, delay slots, return widths, merge points and register clobbers. Allocation/protection and token names no longer overstate executable memory or privilege changes.
- Added Debug/More/Ctrl+K access to the existing Call Stack drawer, with Current/Caller/Younger browsing, return continuations, module offsets, separately labelled possible CALLs and complete backtrace copying.
- Added worker-backed Refresh without executing the target, explicit current-frame seeding and exact session/thread/revision ownership. Register and checked memory writes, module changes and concurrent edits retire stale unwinds.
- Replaced automatic stack inference with an explicit bounded candidate scan; candidates retain uncertainty, disable caller-order controls and report partial/unreadable reads. Tables clip rendering and stale actions refuse changed owners.
- Added pure, naming-pipeline, production UI and native nested-call regressions; details and verification are recorded in docs/FUNCTION_NAMES_AND_BACKTRACE.md.
- Main-agent verification passed: final Release x64/helper build, six focused Core suites, 16,384-function benchmark, native seven-frame nested-call backtrace, isolated startup smoke and the full production UI suite with live scrolling/restoration enabled. Zero final test failures; all 129 production object snapshots match the build, and four Light/Midnight compact/desktop DX11 captures were visually reviewed. Final logs are under build/naming-backtrace-review/.

### Peggle one-shot AOB console — 2026-09-09

- Added the standalone `tools/peggle_zen` console and `build/peggle_zen/PeggleZen.exe`, with Give one Zen shot, Check game / rescan, and Exit choices plus explicit read-only check/file-verification and one-shot grant CLI modes.
- Resolve three unique executable-memory AOBs for the app global, Board/Logic layout and Zen consumer, decode their operands, and reject missing/ambiguous matches, unsupported objects, invalid players and incomplete reads. No fixed-address fallback, DLL injection, game-function call or executable patch is used.
- Add exactly one charge only with an aiming phase, verified loaded/held ball and no queued shot. Brief identity-checked thread suspension protects the four-byte verified data write; exception and console-close handling balance this tool's suspend counts.
- Verified the recovered-file and live AOB matches, console menu, and live grant from 0 to 1. All 26 focused resolver/readiness/one-charge tests pass. The user was asked to fire the granted shot; gameplay confirmation is pending. Usage, signatures and test scope are in `tools/peggle_zen/README.md`, with logs under `build/peggle_zen/`.
