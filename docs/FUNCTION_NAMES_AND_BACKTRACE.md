# Function names and native backtrace — 2026-09-09

## Function-name guessing

- Semantic API families use exact, decoration-normalized names. Names such as a vendor's `MyReadFile` do not inherit the meaning of `ReadFile` merely by containing it.
- Combined file and registry operations can produce `read_write_file` and `read_write_registry`. POSIX `read`/`write` retain descriptor wording because the descriptor can represent a socket or pipe. Native file/memory APIs, memory mapping, module/thread enumeration and dynamic-library resolution have explicit families.
- Permission and privilege names retain the available evidence: allocation plus protection changes does not prove executable memory, and opening a token does not prove privilege adjustment.
- Evidence collection stops at the next known function and retains only instructions reachable from the current entry within the bounded decoded body. Decode gaps, missing successors, overflow and incomplete switch cases prevent narrow complete-body claims. Delay slots remain part of the executed body.
- Result-use evidence respects authoritative decoded targets, register widths, incoming branch boundaries and accumulator clobbers. An AL-only test cannot establish a full-width API predicate.
- Existing user/export/symbol names, deterministic name allocation, cancellation and string-action candidates remain intact. Guesses retain evidence and remain analyst-visible heuristics. Analysis cache schema is now 7; the project storage format is unchanged.

## Finding where the paused thread came from

- Open **Debug → Backtrace / Call Stack**, the execution row's **More → Backtrace / Call Stack**, or search **Backtrace** with **Ctrl+K**. These open the existing Call Stack drawer.
- **Current** selects the paused instruction; **Caller** moves one frame toward the outer caller; **Younger** returns toward the current frame. Selecting a row opens its LIVE address through normal navigation history.
- Frame zero is explicitly the captured instruction/stack context. Older unwound rows are return continuations. Caller symbol/module attribution uses the byte before a continuation to avoid attributing a boundary return to the next function.
- **Possible CALL** separately inspects a unique backward-decoded CALL ending at a return address. The UI marks this as a candidate instruction boundary; ambiguous decodes disable the action.
- **Refresh** asks the existing debug-event worker for a new unwind without resuming or stepping the thread. **Copy backtrace** includes target/session/thread, addresses, stack pointers and module offsets.
- When unwind information is unavailable, **Scan candidates** explicitly scans a bounded stack window. Candidates are labelled separately and do not enable caller-order navigation. Short reads and bounded coverage remain visible.
- Session, active thread, target bitness, unwind revision and module generations own the cache. Register writes, attempted checked memory writes and module changes retire it. Publication refuses an unwind crossed by a concurrent retirement; stale navigation/copy refuses the old owner.
- The debugger's local DbgHelp session stays on its existing worker under the process-wide DbgHelp mutex. Rendering clips the table and uses existing asynchronous symbol resolution. No code executes as a result of browsing a backtrace.
- This is a native paused call stack. Completed earlier calls require the existing **Record Execution Path / Execution History** workflow; static references show possible callers rather than runtime history.

## Verification

- Main-agent Release x64 build and embedded helper verification passed.
- Main-agent `function_namer_test`, `function_namer_pipeline_test`, `analysis_cache_test`, `backtrace_test`, `string_action_trace_test` and `analysis_service_test` passed.
- Main-agent native `x64_debug_test` with `DS_X64_BACKTRACE_ONLY=1` passed with seven frames and the exact nested caller continuation. It verifies refresh without execution, stale identity refusal, register-edit/restore retirement and checked stack-write retirement. The child process is the test executable itself.
- Main-agent 16,384-function benchmark passed, including duplicate-name allocation (293.278 ms) and long thunk chains (46.481 ms) during concurrent build/UI verification. These are local observations, not performance guarantees.
- The full production-object `static_listing_actions_test` passed with zero failures, including the new backtrace fixture, all-theme/density/zoom matrix, contained live scrolling and contained live patch restoration. All 129 copied production objects match the final Release build byte-for-byte.
- Main-agent visual review covered four hardware DX11 captures: Light/Midnight at 620×290 and 1100×390. These use explicitly authored display snapshots with a detached debugger; runtime evidence comes from the native nested-call test above. Controls and rows remain usable; long module labels obey resizable table-column clipping, with full text in copied backtraces.
- Startup smoke passed in an isolated application-data directory. Final executable SHA256: `D55610BDC4C60C5B5B8FD230D6CD30A120A6424BEB7C4F4872426FAFE8106BBC`.
- Final logs: `release-final-build.log`, `full-ui.log`, `startup-smoke.log`, `naming-benchmark.log`; final native run: `native/20260909T100602475Z-e8232d6ec7e94c0392f61c44c5fa271d/`. Earlier failed native attempts exposed fixture setup mistakes (waiting for the first pause and using an owned software breakpoint); those were corrected before the passing run.
- Main-agent build and test artifacts are retained under `build/naming-backtrace-review/`.
