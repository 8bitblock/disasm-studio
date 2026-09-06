# Workflow and UI review — 5 September 2026

This pass reviewed the current, already modified workspace. Existing work was preserved. The fixed single-window layout, hardware D3D11 renderer, bounded analysis workers, and exclusion of a scripting/plugin API remain the project constraints.

## Repairs and completed interactions

| Workflow | Result of this pass |
| --- | --- |
| Open, switch, close documents | Repaired overlapping document close hit targets and context menus that disabled themselves while open. Retired document-specific navigation requests during switches. Pending-open feedback and live-image save messages now explain the actual state. |
| Ctrl+K and shortcuts | LIVE results retain their PID/session identity before the palette clears its state. Recent-query replay restores input focus and scroll position. Modal editors and the palette suppress underlying global shortcuts. |
| Projects | Improved narrow-window splitter bounds, DPI-scaled columns, keyboard opening, and error feedback. |
| Assembly → Graph → Assembly | Added cursor-anchored Ctrl+wheel zoom, Fit, 100%, Center, negative-coordinate panning and header dragging. Individual graph instructions can be selected and opened in Assembly or References. Switch edges have a distinct dashed/diamond appearance. Colors follow the selected theme; graph geometry uses logical pixels. |
| Call Graph | Caller/callee tables are clipped and resizable, with counts, useful empty states, and Assembly navigation. |
| Live Search and signature handoffs | Reads and memory-region queries use the displayed debugger session, with before/after ownership checks. A signature from an older attachment is discarded instead of scanning an unrelated process. |
| Sig Scanner | Enter starts a scan; new scans reveal Results. Save validates the pattern and reveals Sig Health, whose rows can populate the editor or start a scan. Session-only signature storage is stated explicitly. Controls wrap, statuses remain readable, and health colors follow the theme. File gaps no longer consume the mapped-result cap and hide later valid matches. |
| Binary Tech | In-flight scans have an independent document owner and cancel cleanly on a document change. Added Cancel, continuous progress redraw, thread-start failure handling, case-insensitive evidence/name/category filtering, clipped result rows, and a clear no-match state. Captured live images now receive explicit file-backed-input guidance instead of an invalid disk reload. |
| Binary Diff | Changing a source or mode retires old comparison totals and metadata proposals immediately. Source controls use bounded columns; onboarding and controls remain accessible in short/narrow windows. Raw data previews are bounded to 256 bytes. Byte colors follow the theme. |
| Communications | Restored the Java workspace process picker, made native process filters accept names/PIDs without case sensitivity, added module refresh, and cleared stale JDWP displays. Connection history uses its own full workspace instead of duplicating Server Watch. |
| Java attach | Automatic localhost connection requires confirmed agent loading and makes one attempt. Unconfirmed loads retain diagnostics and direct the analyst to explicit host/port connection without attributing an unverified session to the selected PID. |
| Memory Tools | Target changes retire old UI and freeze authority in the same frame. Address entry accepts Enter. Target controls wrap and resize; narrow address tables scroll horizontally. |
| Prism | Added an explicit debugger-PID shortcut, persistent collector errors, accurate collecting/empty states, and theme-aware flame colors. |
| Shared controls | Native scrolling tab strips expose overflowing destinations. Custom pills support keyboard activation. Empty panels measure wrapped copy so the primary action stays visible. Added a shared conditional toolbar-wrap helper. |

## Verification

- Full `Release|x64` solution build passed using VS2022 v143.
- All 119 default test programs passed.
- All three explicitly selected live programs passed with `DS_REQUIRE_LIVE_DEBUG_TESTS=1`: `x64_debug_test`, `wow64_debug_test`, and `authorization_watch_live_test`. These use their own test targets and local loopback network exchanges.
- The final executable remained alive through the startup smoke test.
- New `ui_widgets_test` drives the production widgets in real Dear ImGui frames: narrow/wide toolbar layout, wrapped onboarding, overflow tab selection, native tab clicks, disabled destinations, and keyboard pill activation.
- New `graph_viewport_test` covers anchored/clamped zoom, fit including negative coordinates, and exact row hit testing across pan/zoom/DPI.
- Signature regressions cover rejected prefix hits exceeding the display cap, overlapping and wildcard matches, VA-zero admission, and selective-admission randomized cases. Signature, capability, and algorithm tests were rerun after the matcher change.
- Isolated real-ImGui diagnostics reproduced the document hit-area/context-menu bugs before the fixes and verified the corrected behavior. Changed-file whitespace checks passed.

Logs are retained under `build/workflow-review/`. The built application is `build/x64/Release/DisasmStudio.exe`.

## Remaining limits

- This was source review, compiled regression/integration testing, real-ImGui headless interaction testing, and an application startup check. A complete native visual click-through and physical multi-monitor DPI inspection were not available in the tool environment and are not claimed.
- JDWP attach/browse operations still use bounded synchronous waits. The automatic retry loop was removed; fully asynchronous browsing needs a separate, tested connection/task lifecycle.
- Binary Tech currently requires a file-backed binary or reconstructed dump. It does not scan a captured live-image document directly.
- Graph text becomes an overview at extreme fit zoom. Switch recovery still depends on the existing bounded CFG analysis; the new edge style does not imply additional recovery coverage.
- The broader product gaps recorded in `MISSING_REQUESTED_FEATURES.md` remain distinct from this repair pass. They include larger features such as multiple IL levels and whole-address-space Hex display.
