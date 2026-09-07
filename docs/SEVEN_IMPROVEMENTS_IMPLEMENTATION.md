# Seven workbench improvements — September 2026

## Fixes and improvements

- **Preserve long notes.** Project notes use a dynamic UTF-8 editor instead of a fixed buffer. Untouched notes do not get copied back every frame. Edits exceeding the existing 1 MiB JSON string-token budget (including escapes) restore the complete previous text, including the tail after a middle insertion; external note changes reload the active editor. The editor and project reader share the budget without relaxing parser limits.
- **Preserve dirty Types drafts.** Document switches retain the draft. Close and exit offer Save, Discard and Cancel; validation or storage failures keep the draft and dialog. Saves address the owning document and image, including inactive documents. Session-only live images explicitly refuse a closing Save because they have no durable sidecar. Core image replacement, clear and close refuse unresolved drafts, and closing all documents checks for drafts before closing any owner.
- **Keep debugger startup responsive.** EXE, DLL-host, Authorization Watch and Adaptive Unpack launch through the bounded lifecycle worker, with owned options, cancellation and exact completion identity. Navigation validates the initiating document before acting. See [debugger implementation](SEVEN_IMPROVEMENTS_DEBUGGER.md).
- **Report incomplete memory coverage.** Debugger memory maps retain target identity, completeness and query failures; Memory Tools carries these limitations through regions, scans, refinement and pointer results. An incomplete map cannot silently appear to be the whole process.
- **Make every pinned FILE reference accessible.** Pinned references retain the complete immutable source list instead of copying only its first 3,000 entries. Unfiltered rows are clipped directly; text filtering advances with a bounded per-frame budget and shows progress. Publication, name, function and ownership changes invalidate the appropriate cached results.

## Additions

- **Persistent signature library.** Save, update, copy, remove, import and export named byte signatures. The versioned JSON library uses atomic saves and backup recovery; patterns persist independently of target-specific scan health and matches. See [signature implementation](SEVEN_IMPROVEMENTS_SIGNATURES.md).
- **Register value origins.** Select a FILE x86/x64 instruction and register to see possible source instructions, Assembly highlights and explicit uncertainty boundaries. Requests run on the analysis worker and retire when ownership changes. See [value-origin implementation](SEVEN_IMPROVEMENTS_VALUE_ORIGIN.md).

## Verification

- Release x64 build passed with MSVC v143 and the installed static dependencies. The embedded GameMaker helper verification passed (161,280 bytes, SHA-256 `B637AAE2BAEE32F8D3E98B3CEB7828DB777D967838DE48180546D7B8BE057F42`). Build log: `build/seven-improvements-release.log`.
- The final `run_static_listing_actions_test.ps1` run linked 121 production objects and passed with zero failures. It covers the new notes, dirty Types, 32,768-reference and value-origin fixtures alongside existing listing actions, navigation, patch review and workbench checks across Midnight/Light themes, 100/150/200% scales, and narrow/wide windows. Log: `build/seven-ui-integration.log`.
- Notes input regressions exercise the actual ImGui editor: unchanged long notes, accepted insertion, active-buffer reload, insertion at the beginning, UTF-8 paste in the middle, and undo after rejection at the encoded save budget. Project regressions also round-trip notes exactly at that budget, including every control-character escape and UTF-8, and reject overflow.
- Targeted core tests passed: `document_context_test`, `project_roundtrip_test`, `type_system_test`, `signature_library_test`, `value_origin_test`, `analysis_service_test`, and `debugger_lifecycle_test`. Live `x64_debug_test` and `authorization_watch_live_test` passed with queued startup and exact-session checks.
- The final executable passed the five-second startup smoke test with isolated APPDATA; the test closed only its own process. Log: `build/seven-startup-smoke.log`.
- Project/filter XML and the test manifest validate. This was targeted regression verification; the entire 140-test manifest was not rerun. No new target was left running and no detected remote endpoint was contacted.
