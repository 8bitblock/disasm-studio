# Analyst workflow and analysis foundations — 7 September 2026

This pass adds working native controls and analysis foundations to the existing fixed-window workbench. The imagegen concept is a design study, not a screenshot or an analysis result: [concept](workbench-workflows-concept.png), [exact generation prompt](workbench-workflows-concept-prompt.md). It was generated with the built-in imagegen tool.

## Workflow

Binary View now offers Analyze, Debug, Memory and Compare presets. Analyze opens Assembly, Functions and Triage; Debug opens Live Assembly and Registers when attached or routes to process selection; Memory opens the live memory workspace when attached or FILE Hex and Types otherwise; Compare routes to Binary Diff. These are presentation choices and never attach, launch or write memory automatically. Ctrl+K exposes each preset and the Types workbench. Existing specialist tools and workspace shortcuts remain accessible.

A persistent breadcrumb identifies document, FILE/LIVE/FILE-offset space, section or live module, known containing function and address. Click it to copy the location. Long context is clipped with the full text available on hover. Representation pins retain separate locations; unpinned FILE views share selection while LIVE keeps its own target location. Pins preserve navigation history and retire on image changes or incompatible live ownership. The tool drawer scales to available height, and workflow controls compact at narrow widths.

The Activation trail shortcut opens the existing authorization evidence workspace directly. Findings retain separate format, server acceptance, verification and feature-gate conclusions; the illustrative confidence percentages in the concept are not used.

## Scheduling and accuracy

One process-wide admission arbiter bounds executing analysis jobs to 1–8, depending on available CPUs. Requested functions and views rank first, active-document analysis second, and background-document/module analysis third. Each service admits at most 128 outstanding jobs. Overload produces explicit failure results; batch completion includes rejected work. Bulk passes yield cooperatively at existing cancellation checkpoints, and completed passes reuse the bounded cache. Coalescing checks image, epoch and decoder identity.

Typed instruction operations now survive in DataFlow results, retaining register widths and slices, signedness, memory effects, flags, calling convention, prefixes and unknown behavior. Unsupported operations preserve required inputs and invalidate affected knowledge; LOCK/REP semantics and authoritative direct-call targets receive explicit handling. Authorization evidence no longer silently collapses conflicting comparisons, destinations or completeness claims into one proven gate.

The separation is informed by [Ghidra's SLEIGH documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), which describes translating machine instructions to explicit p-code semantics. This implementation remains DisasmStudio's dependency-light pipeline; it does not embed Ghidra.

## Types

Types is a document-owned workbench with validated Integer, Float, Pointer, Array, Structure, Union, Enum and Function definitions. Add scalar types, create a definition, edit fields or parameters, and save it. Stable type/field IDs preserve references when names change. Drafts must be saved or discarded before another definition replaces them.

Named type applications cover explicitly selected backed FILE memory, including VA zero. Apply after saving the definition and entering a global name. Hex and Address Inspector resolve the same project definition, so renaming a field updates both. Definitions and applications persist in an optional versioned `typeRegistry` section of the project sidecar. Applying a type does not modify bytes or force code/data classification. Overlapping structures, invalid references, overflowing extents and value cycles are rejected; recursive pointers are supported. Ambiguous union members remain unresolved.

## Debugger responsiveness

Communications and the global Detach controls enqueue lifecycle commands. A separate state snapshot exposes Starting, Attached, Paused, Stopping, Failed and Detached, cancellation, completion and exact target identity. Successful attachment waits for initial process bitness/module publication before the app opens live code. Stale or cancelled completions do not navigate.

Network log file open/write/flush/close operations run on a separate bounded writer. Its queue is capped at 256 records and 4 MiB; pending status, dropped records and storage failures are visible. Target-free regression tests exercise lifecycle contention/cancellation, invalid-PID failure, file ordering and queue/error behavior.

## Remaining architecture work

- Immutable image versions and patch overlays are not implemented. Analysis/export readers still require the existing mutation barriers, and patches still use conservative epoch invalidation rather than dependency-local invalidation.
- The typed instruction layer is integrated, but string expressions, current control-flow structuring, C emission and display-side C-to-Python transformation remain. A complete typed expression/statement AST and independent Python emitter are future work.
- Type applications currently cover named FILE globals. Automatic argument/local typing, nested member reconstruction, cross-view expression replacement and live-memory type application remain to be built. Function signatures can be authored as structured definitions but are not yet assigned to functions through this workbench.
- Existing launch/DLL/unpack flows retain synchronous startup APIs. They fail fast while asynchronous lifecycle work is pending. Splitting the event owner, breakpoints, stepping and observers into separate subsystems remains future work.

## Verification

The following targeted executables passed during implementation: `analysis_service_test`, `dataflow_decomp_test`, `decompiler_linemap_test`, `decompiler_python_test`, `decompiler_fixes_test`, `authorization_trail_test`, `type_system_test`, `project_roundtrip_test`, `debugger_lifecycle_test`, `document_context_test`, `network_endpoint_test` and `network_api_catalog_test`. The core-test manifest validation also passed. This is targeted verification, not a claim that all 136 declared tests ran.

The integrated Release build passed with MSVC v143 (14.44), C++20 and the static CRT, including verification of the embedded GameMaker helper. See `build/workbench-release.log`. The production-object `static_listing_actions_test` passed with zero failures after correcting the fixture to allow ImGui's queued tab selection a second frame. It exercises all nine workspaces in Midnight and Light at 820×560 and 1600×960 with 1.0×, 1.5× and 2.0× scaling, plus listing/navigation/palette contracts.

Native inspection confirmed that the built app launches and loads/analyzes `C:\Windows\System32\where.exe`, displaying the workflow controls, FILE breadcrumb and assembly. The user stopped Computer Use with Escape before the planned Types-drawer inspection completed; no further native UI input was sent. Static fixtures and target-free lifecycle checks do not demonstrate a fresh end-to-end debugger or server activation session against a crackme.

A final review also fixed the exhausted-type-ID editor case and clarified the FILE/LIVE pin tooltip. The final executable is built separately under `build/x64/WorkbenchRelease/` to leave the already-open app undisturbed. The final Release build and embedded-resource verification passed; the final production-object integration suite, including the real New type button exhaustion regression, passed with zero failures. Results are recorded in `build/workbench-final-release.log` and `build/workbench-ui-tests-final.log`.
