# GameMaker implementation and acceptance record

Implemented scope: GML archive analysis and instruction debugging for the verified
installed x64 Nubby runner, with symbolic breakpoints/watches, paused numeric edits,
and a built-in helper distributed inside DisasmStudio.exe. See the
[usage guide](GAMEMAKER_DEBUGGING.md) and [runner evidence](GAMEMAKER_RUNNER.md).

The requirement audit and final acceptance pass are complete as of 2026-09-06.
The supported limits below are explicit capabilities of this first adapter.

## Target identity

- Steam build 25109973, app 3191030, `NNF_FULLVERSION.exe`.
- Executable SHA-256: `5664918EA125B0D1D763D51FE84CE10EF974DAB8DED1014026FFDA69FB433F1E`.
- Archive SHA-256: `B00A69FBE77812E6CAFF3AA0250C16D24D1E16E9C70CD563BD69ECA27506B982`.
- Archive content identity: `10369392253076995768`.
- 2,858 CODE entries, 2,241 shared roots, 8,534 variables, 990 functions,
  13,155 strings, 738 objects, 114,306 references and 311,512 instructions.

Game files remain unchanged. Tests use isolated project intent under `build`,
never the user's project sidecars. Live acceptance explicitly selects a test-owned
PID. There is no public scripting/plugin API, source reconstruction, YYC debugging
or complex-value editing in this implementation.

## Requirement audit

| Requirement | Implementation and verification |
| --- | --- |
| Bounded archive model | `GameMakerArchive` validates chunks, lengths, counts, references and cancellation; parses CODE/VARI/FUNC/STRG/OBJT/SCPT/event/local records and skips unrelated payloads. `gamemaker_archive_test` covers hostile counts, malformed references, shared/child bodies and unsupported formats. |
| Dedicated decoder and static integration | `GmlDisassembler`, `BinaryFile`, factory/architecture routing, `FunctionAnalyzer`, CFG and references use validated bytecode boundaries and file-offset navigation. Unsupported instructions are visibly unsupported with no native fallback. Archive, decoder, loader, xref/function and headless listing tests pass. |
| Stable breakpoints | `GmlCodeLocation` carries archive, CODE/parent identity and instruction offset. Helper bindings validate runtime CCode/name/body/entry before matching; code relocation does not change saved intent. Three actual restarts rebound the same breakpoint without rescanning. |
| Scoped watches | `GmlVariableTarget` saves named globals and unique-object intent. Instance allocation tokens and frame incarnations are transient. Ambiguous instances require selection; destroyed/recreated instances, moved storage and stale frames are covered by model/runner/inspection tests. |
| Actual interpreter adapter | `GameMakerRunner` verifies the exact executable/archive profile, hook bytes, runner image, pre-instruction PC, context/operand bounds, logical frames and canonical numeric maps. Compiled read-only probes validated 700 real dispatch events; production helper tests exercise the same adapter. |
| Checked insertion hooks | Four exact x64 sites cover instruction dispatch, interpreter entry and instance construction/destruction. `Debugger` owns hook ranges and rejects overlapping native breakpoints/writes. `GameMakerHookMutation` tests partial writes, failed rollback, page-protection/cache failure and foreign bytes. The existing replacement-only patch placer is not used as an insertion hook. |
| Native machine-state preservation | Production MASM gates preserve GPRs/flags and enabled XCR0 state using bounded XSAVE/XRSTOR (FXSAVE fallback), stack probing/alignment, displaced instructions and registered unwind records. Gate tests deliberately clobber SIMD state, including available AVX-512/opmask state, and check restoration/unwinding. |
| Bounded ordinary execution | Preallocated state, per-thread fast admission, Bloom prefilter and exact code/offset bitmaps avoid allocation, blocking and debugger communication on ordinary unselected instruction boundaries. Expensive frame/value projection occurs only for requested stepping/stops. |
| One pause authority | `DebuggerGameMaker` authenticates helper/module/session/thread/nonce/sequence/dispatch-site identities before consuming the private exception. Bounded snapshots and commands cross the mailbox. Frozen inspection does not invoke target functions or wait for helper acknowledgement. Native pauses revoke GML edit authority. |
| Into/Over/Out and resume | Progress distinguishes loop revisits; full ancestry and monotonic frame identities distinguish recursion/unwinding. Into stops at the next instruction, Over follows the original frame, Out stops when that frame leaves the complete active chain, including top-level events. Ordinary resume executes the stopped instruction once and still catches later loop iterations. Models, helper fixtures and live call/loop traces cover these transitions. |
| Variables and edits | Globals, selected registry instances and verified locals are immutable projections. Numeric writes revalidate the held stop, snapshot revision, owner/map binding, current full RValue and type/range; write only payload and verify readback. Copies, computed values and register-restored stack values cannot acquire edit authority. Numeric edits and restores were exercised in real Nubby. |
| UI and execution modes | Communications exposes GameMaker connection/capabilities/lifecycle; Binary View GML exposes scripts, variables, objects/events, breakpoints, watches, frames and instances. Toolbar and shortcuts explicitly route Native/GML modes. Headless production-object tests exercise symbolic listing actions and the GML panel. |
| Asynchronous work and lifecycle | Parsing/preparation run off the render thread; debugger service pumps events during load/init/unload. Inspection releases the shared snapshot lock during bounded traversal. Cleanup disables stops, restores only owned bytes, resumes/drains callbacks and unloads only after proof. Otherwise it retains an inert mapping. Live cancellation, paused/running/pending-stop disconnect, host-loss and target-exit tests pass. |
| Single executable | `GameMakerHelper.vcxproj` builds a static-CRT x64 helper embedded as RCDATA. `GameMakerHelperImage` verifies extraction to a private cache. Build-time resource freshness verification compares the embedded bytes against the built DLL. No separate helper file is required for distribution. |
| Project version 5 | `Project` saves semantic GML breakpoint/watch intent and reads versions 1–4. No heap pointer or numeric-write authority persists. Generic memory-table files are unchanged; Memory Tools handoffs are explicitly process/session-bound. Project roundtrip and GML persistence tests pass. |
| Unsupported capabilities | Capability records enable only the compiled, runtime-validated adapter. Packed operand-stack values and complex edits are explicitly unavailable; this is not claimed as a source-level debugger or a generic runner adapter. |

## Real Nubby acceptance

`tools/gamemaker/live_debugger_test.cpp` uses the production Debugger and embedded
helper. It stops in `gml_Script___scribble_tick` (CODE 345, offset 4), steps its
instructions, edits and restores a global number before further execution, steps
over/out, inspects and edits/restores a selected instance value, rejects stale
write/register authority, checks native hook overlap/breakpoint coexistence,
unloads a drained helper, reconnects with a new helper identity and detaches.

A single unchanged version-5 intent file saves CODE 345 offset 4 and global
`ItemSfx`. Following initial PID 10276, three restarts passed the entire harness:

| Restart | PID | Resolved ItemSfx address | Value | Harness |
| --- | --- | --- | --- | --- |
| 1 | 18344 | `0x1cf4a890` | 1 | Passed |
| 2 | 21988 | `0x1cf4d890` | 1 | Passed |
| 3 | 11052 | `0x1cf50890` | 1 | Passed |

The intent SHA-256 remained
`7B7767AB8C536CA8D08EF38307BC78320673EF34018F134AD3F76F23C918022C`.
Evidence: `build/gamemaker-restart-acceptance-2-4.json` and
`build/gamemaker-live-restart-{1,2,3,4}.log`. Later extended-state helper acceptance
also passed (`build/gamemaker-live-restart-5.log`). The exact original failing AOB
pattern was not supplied; these tests prove changing resolved addresses, not the
cause of that unspecified pattern failure.

The additional production call harness uses static named call-site breakpoints
when a bounded scene trace does not encounter the needed call. Its passing trace
on PID 14404 proves a same-frame loop in `__scribble_tick` at offset `0x68c`, Into
and Out through `scr_LocalEqualFont`, and Over through `scr_Text` back to the
original caller. The final helper also passed Out from a top-level Draw event
(frame 171) to the next verified event (frame 188), with the original frame absent
from complete ancestry. Evidence: `build/gamemaker-call-step-live-final.log`.
The complete numeric/edit/coexistence/reconnect harness passed again with that
same final helper in `build/gamemaker-live-final.log`.
It never requires a live AOB pattern. Recursion and multi-frame
exception unwinding are covered by deterministic models/helper fixtures; no
claim is made that a GML exception was deliberately triggered in Nubby.

## Failure and lifecycle acceptance

- `build/gamemaker-lifecycle-live-final.log`: failed archive preparation cleared
  and retried within the same native attachment, asynchronous cancellation,
  running/paused/pending-stop disconnect and verified helper unload; passed.
- `build/gamemaker-host-loss-running.log`: abrupt termination of the test debugger
  host; target survived and process cycle count advanced.
- `build/gamemaker-host-loss-paused.log`: same host-loss test while holding a GML
  exception; target survived and continued executing.
- `build/gamemaker-target-exit.log`: explicit test-owned process termination while
  paused. The native loop releases the pending event when Windows reports exit,
  drains EXIT_PROCESS and retires GML state without target writes.
- `gamemaker_hook_mutation_test`: each 0–6-byte partial hook write, rollback
  failure, protection/cache failures and foreign ownership; passed.
- `gamemaker_helper_state_test`: fixed-capacity collisions/overflow, frame and
  instance reincarnation, unrelated exceptions, small-stack initialization,
  duplicate initialization and shutdown refusal for active/stale/armed states.

## Performance and reproducible checks

The live harness records three one-second CPU-time/cycle samples in each mode:
baseline, native attachment idle, GML attachment idle and an armed, unhit
`scr_GiveMoney` breakpoint. These are paced-game measurements with scheduling and
scene outliers; they do not establish a precise percentage slowdown. The ordinary
dispatch path was optimized with preallocated exact bitmaps and an assembly fast
path before acceptance. Gate tests verify fast-path fallthrough/state preservation.

Run one manifest test per invocation, for example:

```powershell
cmd /c tests\run_core_tests.bat gamemaker_debug_test
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run_static_listing_actions_test.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools/gamemaker/build_live_debugger_test.ps1 -Test live_call_step_test
# Explicit test-owned PID required; the live harness attaches to it:
& build/gamemaker-live-test/live_call_step_test.exe <PID>
```

`build/gamemaker-final-regressions.json` records 15 passing selected tests:
archive, decoder, loader, protocol/steps/edits, runner, inspection, persistence,
helper image/state/gates, hook mutation, legacy project roundtrip, cross-architecture
xrefs, function analysis and native x64 debugging. The headless listing/GML test
passes in `build/gamemaker-headless-ui-final.log`. Build logs and individual
`build/*.final.log` files preserve detailed output. The manifest declares 134
binaries; this record does not claim all 134 were rerun in the final pass.

Build the helper before the application. The x64 Release deliverable is
`build/gml-verified/DisasmStudio.exe`; the user's already-open older application
was not closed or replaced. Its embedded-helper freshness check runs during the
build. Final executable/helper hashes and the latest live results are recorded
in `build/gamemaker-final-verification.json`.

Final executable SHA-256:
`BD6EE63D82B92183F119A6B6E25FE59E569E8730C3DBB3EB4DA31EE66F635C72`.
Embedded helper: 161,280 bytes, SHA-256
`C552D928E8F5B652FAB702A0A0E5BA081F811C1039C0BA5BEF4A152BC6FEB2EB`.

## Design references

Archive relationships were checked against the upstream
[UndertaleCode model](https://raw.githubusercontent.com/UnderminersTeam/UndertaleModTool/refs/heads/master/UndertaleModLib/Models/UndertaleCode.cs).
The original helper/runner adapter is implemented in this repository. The pause
protocol follows [Windows debug-event semantics](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events):
all target threads stay suspended until the event is continued, so host reads
and queued resume commands never depend on a frozen helper acknowledging work.

## GML instruction readability — 7 September 2026

- Added the display-only `Core/GmlInstructionText.h` formatter for all supported
  GML operations, type suffixes, resolved strings/functions, and conservative
  unresolved references. `push.v self.money` becomes `Read variable self.money`;
  `bf` becomes `Jump if false`. Quotient/remainder and special stack encodings
  retain their distinct meanings.
- Assembly and Graph default to **Readable GML**. Instruction tooltips and the
  evidence inspector show the full explanation and raw bytecode. **Explain**
  works alongside existing metadata; destination links and analyst comments
  retain priority within the clipped comment column. Raw decoding, addresses,
  branch destinations, selections, and symbolic breakpoint identities remain
  unchanged. Added **Copy readable GML** and documented the controls.
- `gml_disasm_test` passed with zero failures, including type meanings, resolved
  and unresolved references, comparisons, conversions, zero/invalid branch
  targets, array operations, stack rearrangements, and unsupported encodings.
- The production-object `static_listing_actions_test` GML checks passed:
  readable/raw toolbar switching, explanations beside metadata, exact operand
  preservation, selection, symbolic breakpoint controls, and branch navigation.
  The wider suite reported one separate existing keyboard-copy failure in
  `workbench_workflow_fixture.inc` (`FILE:0x0` breadcrumb clipboard check); it is
  not a clean pass of the entire integration suite. See
  `build/gml-readable-ui-tests.log`.
- The Release executable is built in
  `build/x64/GmlReadableRelease/DisasmStudio.exe` for use without replacing the
  running app. Build and embedded-helper verification output is recorded in
  `build/gml-readable-release.log`.
