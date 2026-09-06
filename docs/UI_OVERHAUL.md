# UI overhaul — 6 September 2026

This is a source-based layout and feature-access inventory for the current UI pass. Integrated Release-build, interaction, and visual verification are pending with the coordinating agent. This document does not claim that those checks have passed.

## Scope and shared layout

- The nine workspaces remain in the fixed single-window workbench. This pass changes presentation and access to existing tools; it does not add a scripting/plugin API or replace analysis/debugger backends.
- The shell separates open documents, workspace navigation, execution/address controls, and the bottom status strip. Document selection, close actions, path context menus, overflow selection, and save-failure protection remain.
- Workspace labels shorten when space is limited: Communications → Comms, Sig Scanner → Sig Scan, Binary View → Binary, Memory Tools → Memory, Binary Diff → Diff, and Binary Tech → Tech. Full names and Ctrl+1…9 shortcuts remain in tooltips.
- Continue/Pause or Launch & Debug, Step Into/Over/Out, Trace, the Native/GML selector, address entry/presets, and Detach retain their availability checks. Address presets include the cursor, entry point, image base, live RIP, and the Memory Tools RIP handoff when available.
- The compact status activity opens a details popup. Concurrent binary opening, static analysis, live-module analysis, live scanning, trace preparation, and source export keep separate stop controls. Hover/details retain phases, counters, project-save state, and coverage information.
- Ctrl+K remains the command and FILE/LIVE investigation palette, including recent queries and context actions. Enter opens, Up/Down selects, and Escape closes. Modal editors retain their document ownership and shortcut isolation.
- Shared controls use the selected theme and density, quiet borders, restrained selection accents, wrapping action lanes, and compact left-aligned empty states. Semantic warning/error, heuristic-confidence, and debugger-state colors retain their meaning. View still exposes Theme, Density, Architecture, Disassembler, Symbol Settings, and Reset Binary View Layout.

## Workspace inventory

| Workspace | Layout and feature access |
| --- | --- |
| **Projects** | Open Binary and Refresh lead the page. The searchable Recent targets list supports selection, double-click/Enter opening, and Open/Copy path/Remove context actions. Project details and Active binary and saved analysis retain path, format, architecture, hash, mapping/entry, firmware/runtime details, annotation totals, save status, and Save project now. |
| **Communications** | The internal rail selects Processes & Attach, Network Monitor, Java / JDWP, or GameMaker / GML. Native process search/Refresh, Attach/Detach, and Dump stay in the process list; the selected process has Modules and Connections panels. Per-process connections retain IPv4/IPv6, TCP/UDP, text filtering, refresh, and partial-result reporting. Java retains running-JVM injection and listening-agent connection, suspend/resume, steps, detach, classes/methods, threads, frames, breakpoints, events, and live bytecode. GML retains Start/Stop, Pause/Continue, steps, verified-session status, toolbar/follow preferences, and the selected-stop handoff. |
| **Sig Scanner** | The byte-pattern editor, Scan/Enter, Live toggle, signature name, and Save Sig remain together. Busy work shows progress and Cancel; completed progress is still available in Current Scan. Results, Current Scan, Sig Health, and All Functions retain match navigation, source identity, truncation/error states, health recomputation, signature editing/double-click scanning, and function analysis/filtering. Result tables have frozen headers and resizable, scaled columns. |
| **Binary View** | A left navigator leads with Functions, Strings, and Bookmarks. Metadata switches to Search, Sections, and Exports / Symbols; Navigate returns to the primary list. The active viewport offers Overview, Assembly, Pseudocode, Hex, Graph, Call Graph, and Live Assembly. The lower drawer groups Debug & data and Analysis tools; its edge control collapses the drawer without removing destinations. See the detailed access map below. |
| **Memory Tools** | The target bar retains Open Process, passive Close, debugger-session reuse, Communications handoff, target identity, and access status. Value scanner and Memory inspector sit above the independent Address table. First/Next/New scan, cancellation, all value types and predicates, paging, and scan-result context actions remain. Scan scope contains region classes, writable/executable filtering, alignment, range, and read-cap controls; it starts collapsed. Inspector retains Hex editor, Regions, and Pointer scan. Address records retain Load/Save, add/edit, enable, resolution, verified writes, freeze interval/mode/arming, and protected-page authority. Without a live target, offline table editing remains available. |
| **Binary Diff** | Setup is a full-width Baseline/Candidate source table followed by comparison options and Compute Diff. Byte/section-aware and semantic modes retain source replacement, Recompute, Cancel, phase/error reporting, change navigation, synchronized hex/ASM review, function matching/evidence, and individually selected metadata transfers. Source identity and transfer eligibility checks remain. |
| **Binary Tech** | Run Tech Scan, Cancel, filter, and result status lead into Findings and selected evidence. Category, confidence, address validity, analyzer source, detailed evidence, code/data preview, View in disassembly, and Open network trail remain. File-backed-image requirements and no-result/no-match guidance remain explicit. |
| **Cortex** | Analyze/Re-analyze, Cancel, and Export lead the report. The wrapped verdict/facts sit above resizable Behaviours and Notable functions panes, followed by Ask Cortex. Confidence, evidence tooltips, function navigation, quick questions, free-text questions, and chat history remain. Analysis ownership, cancellation, and invalidation are unchanged. |
| **Prism** | Start/Stop, PID, Use debugger PID, collection mode, Clear, and observation count remain above the report. Collector quality, fallback/error messages, selectable timeline, flame graph, and navigation checks remain. Thread-state percentages and counts use a compact responsive grid with thin bars and an explicit distinction from CPU utilization. Functions, Threads, Modules, and Hot call paths retain their detail panes and frozen table headings. |

### Binary View access map

- The Functions navigator uses name-first rows with an exact address column and user/known/guessed-origin indicators. Full names, addresses, and heuristic evidence remain in tooltips. Go, Rename, Copy VA/name, and Save ASM/C remain in the row menu.
- The command band keeps navigation history, goto/symbol/text search, and analysis actions. Assembly keeps Full program, Rebuild, Explain, Notes, Strings, Arrows, and Prev/Next. Live Assembly retains execution, navigation, register/string/display controls, and its exact live-session routes. Hex retains offset navigation, selection/copy, and editing through the patch system.
- **Debug & data:** Breakpoints, Registers, Threads, Call Stack, Functions, Watch, conditional GML, Notes, Results, Patches, Imports, Resources, and Hotkeys.
- **Analysis tools:** Modules, Debug Output, Stack, Xrefs, PDB / Symbols, Address Inspector, Algorithms, Annotations, conditional Java, Triage, Synthesis, Hot-Patch, and Path Explorer.
- Triage retains Start Here, Network Trail, Authorization, Strings, Functions, and Runtime. Authorization evidence and live return experiments remain distinct from transport/API success. Patch sets, user comments/renames, resource extraction, symbol inspection, and address provenance remain in their existing tools.
- Pseudocode, CFG, and Call Graph retain navigation and their existing view controls, including available pop-out/dock-back actions. Pseudocode is the single primary decompiler destination; retained state for the former duplicate Decompiler entry maps there. Assembly remains the default representation.

### Network Monitor access map

- **Connection History:** Refresh now, Auto, Active only, TCP only, Attached process only, Clear history, and text filtering remain above the connection table. Process, protocol, local/remote endpoints, state, byte totals, rates, and last-seen data remain. ESTATS and partial-refresh limitations are visible; Advanced: local API schema (inactive) remains inspectable.
- **Server Watch:** Start/Stop and Clear observation remain explicit. Triage-origin target matching and the explicit Watch attached process instead action retain their guards. Observation coverage retains armed/skipped/shared probes, event/payload retention, dropped counts, and coverage limits. Filtering, event selection, return contracts/outcomes, payload text/hex, continuation navigation, and file logging remain available.

## Responsive behavior

Thresholds below are logical widths multiplied by the current UI scale; they refer to available panel space, not the outer window width.

| Area | Compact behavior |
| --- | --- |
| Projects | Below 620 scaled pixels, the recent list stacks above details. Wider layouts retain the draggable list/detail split. |
| Communications | Below 800 scaled pixels, native processes stack above Modules/Connections. Wider layouts have a retained draggable split. JDWP's three-column console uses horizontal scrolling when its content needs more width. Native/JDWP/GML action lanes retain wrapping controls. |
| Network Monitor | Wide connection and observed-call tables scroll horizontally, retaining the first column and header while scrolling. Coverage/error text wraps. |
| Binary View | When the representation rail cannot fit, a combo exposes the same seven destinations and disabled-state explanations. Navigator and lower rails retain native overflow menus. The lower drawer can collapse to its rail; selecting a destination reopens it. Splitter dimensions rescale with DPI. |
| Memory Tools | Below 720 scaled pixels, the upper area switches between Value scanner and Memory inspector. Inspector navigation requests reveal the inspector; hidden value/pointer scans retain accessible cancellation. The Address table remains below both modes. Short heights use bounded pane proportions with scrolling. |
| Binary Tech | Below 660 scaled pixels, Findings stacks above evidence. Wider layouts retain the list/detail splitter. |
| Sig Scanner / Binary Diff | Action groups wrap, labels and columns scale, and wide detail views retain their existing scrolling. Diff setup no longer reserves a centered card or large top margin. |
| Cortex / Prism | Wrapped report copy and minimum detail-pane heights allow outer scrolling in short windows. Prism's state summary chooses one to four columns according to available width. |

## App menus and dialogs

The main App dialogs use a shared work-area size constraint and normal scrolling when the preferred size exceeds the display. This includes Symbol Settings, Archive Entries, Open as Raw, Debug DLL, Static Packed-PE Recovery, Passive Process Dump, Adaptive Unpacker, Hide Debugger / Anti-Anti-Debug, and Keyboard Shortcuts. This is implemented behavior awaiting integrated visual verification, not a claim that every field has been exercised at every DPI.

| Entry point | Retained dialog/workflow access |
| --- | --- |
| File → Open Binary / Open as Raw | Normal file selection; raw base, entry, architecture, endianness, applicable RVC option, detected firmware/architecture evidence, restore defaults, landmark seeding, Load/Cancel, and validation errors. |
| File → Save Binary As / Save ASM / Save C / Export Analysis | Patched-image save selection, whole-program/current-function source export, supported ASM/C formats, export progress/cancellation, and analysis-report export remain. Source-export options are rendered by Binary View after the App-menu request. |
| File → Extract Embedded JAR/ZIP / Browse Embedded Archive | Archive entry list and metadata, Open as binary, Extract, and Close retain entry validation and existing load/extraction behavior. |
| File or Debug → Debug DLL | Validated callable export selection, bitness-matched system/custom host, host browsing, arguments, DllMain/export stop options, launch validation, and close/cancel controls remain. |
| View → Symbol Settings | Explicit network-fetch opt-in, local cache/server fields, source/type/local collection options, Apply, Defaults, Cancel, and validation/save errors remain. |
| Debug → Hide Debugger / Anti-Anti-Debug | Recommended coverage, Disable all, environment/query/time options, current coverage/limitations, Apply for next session, and Close remain; existing session-policy checks are unchanged. |
| Debug → Passive Process Dump | Existing process or Launch and watch; target/arguments/working-directory selection; timing, coherent capture, import/relocation options, optional OEP, Start, Capture now, Cancel, result/report save, analysis handoff, and contained-launch termination remain. |
| Debug → Static Packed-PE Recovery | Strategy, output/dictionary bounds, disk-PE reconstruction, optional OEP, Recover, Cancel, progress/evidence, PE/mapped/raw artifact saves, and optional analysis handoff remain. Runnable versus analysis-only outcomes remain distinct. |
| Debug → Adaptive Unpack | Strategy, launch containment, auto-run/pause, timing, Start/Pause/Resume observation, OEP evidence/manual entry, reconstruction/current-entry dump, artifact/report save, analysis handoff, and Close remain. |
| Debug → Trace Coverage | Start/Stop and Clear retain debugger-state checks and recorded execution coverage. Trace preparation also remains cancellable from status details. |
| Help → Keyboard Shortcuts / Command Palette / About | F1 help, Ctrl+K commands/investigation, and version/runtime information remain. View → ImGui Demo remains available. |

## Verification

- The Windows x64 Release build passed, including embedded GameMaker-helper freshness verification. Build log: `build/ui-overhaul-release-build.log`.
- The production-object ImGui integration suite passed with zero failures. It exercises all nine workspace shortcuts and shell geometry at 820x560 and 1600x960, with actual 100/150/200 percent font atlases and Midnight/Light themes. Palette query/results/footer fit, overlay ordering, shortcut blocking, outside-click dismissal, and subsequent normal navigation are checked. Log: `build/ui-overhaul-ui-tests.log`.
- Existing integration cases still pass for navigation, references, patch actions, saved columns, static/live strings and annotation channels, jump arrows, breakpoint/RIP/cursor/target/arrival glows, and trace geometry. Listing decorations stay in the table's scrolling child drawlist beneath overlay windows.
- Native inspection covered all nine workspaces, a real static load of `C:\Windows\System32\where.exe`, populated function and capability findings, and the final palette layering and dismissal behavior. Preview: `build/ui-overhaul-preview.png`.
- This presentation pass does not claim a fresh end-to-end test of every live debugger, JVM, memory-write, network-observation, or profiler workflow. Those controls and their existing identity/authority checks were retained; live listing rendering uses simulated snapshots in the integration suite.

Source locations: `src/App.cpp`, `src/Ui/Theme.*`, `src/Ui/Widgets.*`, `src/Ui/CommandPalette.cpp`, and the corresponding workspace files under `src/Tabs/`.
