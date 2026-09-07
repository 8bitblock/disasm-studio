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
