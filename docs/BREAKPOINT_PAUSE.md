# Pause a breakpoint without removing it

In Binary View's Breakpoints drawer, click the **Enabled** ring or open the row's
`...` menu and choose **Pause breakpoint**. A paused breakpoint remains in the
list with a hollow gray ring and **Disabled** status. Click the ring again or
choose **Enable breakpoint** to use it again. These controls are available across
all themes. Existing gutter removal and keyboard shortcuts remain available.

Pausing retains the address, condition, every-N setting, counters and unsubmitted
condition draft. FILE breakpoint enable state is saved with the project; older
projects default to enabled. A disabled FILE breakpoint does not auto-arm on
attach or reopen. Enabling still validates its instruction and exact module.

Native software breakpoint changes run through the debugger's existing event
owner and exact-session checks. Disabled records retain metadata but own no
target bytes. Shared internal observation hooks keep their own authority, and
enabling verifies the current byte before installing a trap. A rejected or failed
transition remains visible and can be retried. Temporary disarming while the
debugger executes an instruction is distinct from the user's disabled state.

Disabling at the current instruction preserves the parked context for an
immediate re-enable. Continuing while it remains disabled executes normally
without a breakpoint step-off lease. Already-queued peer hits are retired only
against their exact exception/thread/address context; unrelated native traps
remain outside this handling.

## Candidate and validation

The Release x64 candidate is `build/x64/BreakpointPause/DisasmStudio.exe`, SHA256
`6ce63751686180716b238c6e5a452207f0e3438aeac412626f5bb5307645f4e0`.
Its embedded GameMaker helper passed resource verification. Existing workspace
changes were preserved in this candidate.

- Project round-trip checks passed, including actual sidecar save/reopen,
  legacy enabled defaults, re-enable, malformed input, VA zero and 64-bit values.
- The release-workbench and full production workbench suites passed with zero
  failures. Each uses the same 126 production objects as the candidate.
  Coverage includes ring/menu actions across all themes, retained metadata and
  drafts, saved-boundary restoration, stale-session refusal and the existing
  theme/density/zoom/DPI matrix.
- Hardware DX11 fixture captures were refreshed. Main and page-agent review
  checked disabled rows, conditions, hit counts and actions in compact/1440
  layouts and Axiom/Midnight/Light. These are authored UI fixture snapshots.
- The focused native pause/resume check **passed with zero failures** using
  `DS_X64_BREAKPOINT_PAUSE_ONLY=1`. It verifies immediate pause/re-enable and
  StepOver in a launched singleworker target, then running pause/enable in a
  separate attached multiworker target, including normal disabled Continue/exit.
- The full native x64 suite is **not clean**: four checked RunTo assertions fail
  when Windows refuses a peer suspension with error 5 and the debugger correctly
  keeps the target paused. The original multiworker/RunTo scenario reproduces
  this without pause/enable calls (`build/breakpoint-baseline-steps/baseline_steps.run.log`).
  This is recorded as a validation limitation, not a passing full native suite.

Build/test/source/object hashes and exact results are recorded in
`build/breakpoint-pause-verification.json`. The two production suites retain
identical object snapshots from this candidate build. Other workspace builds
subsequently advanced shared UI objects; those differences and the current
workspace source hashes are recorded separately from the validated candidate.
Interactive user-target walkthroughs,
physical monitor DPI transitions and the opt-in live patch-restoration test were
not run for this addition.
