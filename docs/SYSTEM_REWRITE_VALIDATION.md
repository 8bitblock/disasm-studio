# Patch, output, debugger, and verification rewrite

## File output

`ArtifactWrite` is the shared writer for Save Binary As, embedded archives,
archive entries, resources, analysis reports, and unpacked artifacts/reports.
It admits one owned background job, retains its completion until UI polling,
and joins accepted work on shutdown. A job cannot borrow a document, popup,
selection, or result buffer from the render thread.

Output is generated into an exclusively created sibling temporary file. Every
write, flush, close, and same-volume atomic destination installation is checked.
Failure deletes only that job's temporary file. Existing destination files are
never truncated or deleted as a fallback. Empty files and Unicode paths are
supported. Companion reports commit separately; a report failure is reported as
a partial success and prevents automatic loading.

`OwnedImage` gives `BinaryFile` copies and archive browser snapshots immutable
ownership of the captured bytes. Checked writes detach shared storage before
mutating it; load/clear/whole-image commits replace their own storage. Save Binary
As copies mapping and ordered patch metadata on admission, then performs checked
composition and complete image allocation on its worker. It refuses unresolved
saved-patch recovery. Archive extraction uses the retained byte snapshot and
performs decompression off the render thread.

Load-after-save callbacks run only after completion and validate document ID,
image generation, image revision, and competing loads. Passive-dump callbacks
also verify the captured result generation before changing launch ownership.

Application close waits for accepted output and its UI completion. A failed file
or companion report cancels that close attempt. It also follows the exact native
debugger lifecycle request, cancels pending startup when possible, and waits for
successful detach before saving the final document and leaving. A failed detach
keeps the application open with a Retry Detach control.

## Patch and debugger changes

See [PATCH_APPLICATION_RECOVERY.md](PATCH_APPLICATION_RECOVERY.md) for saved
record recovery and machine-aware encoding. The existing checked patch
composition, ordered overlaps, pristine originals, and live session gates remain
authoritative.

The debugger keeps its existing debug-event owner. Breakpoint operations,
execution/context policy, and network observation are extracted into dedicated
translation units. Mutation failures retain physical ownership and publish
diagnostics; execution cannot silently proceed after an unverified transition.
The memory adapter preflights every affected region, owns a duplicated process
handle and original bytes before mutation, verifies writes by reading back, and
retains incomplete byte rollback, original protection, or cache-flush recovery.
Recovery never overwrites bytes superseded by a later target-side change.

Failed detach retains cleanup authority and reports an unsuccessful lifecycle
attempt. Breakpoints, instruction-pointer repairs, context state and owned
suspension counts remain with the event owner until they can be reconciled. The
UI admits a cleanup retry while ordinary mutation and execution are disabled.

## Independent review

Rewriters and independent reviewers worked separately. Findings were reported
with source line locations and fixed before final verification, including:

- C++20 shared pointer API compatibility and the new image-owner allocation
  being outside `loadFromMemory`'s failure boundary.
- A step-over path mistaking an existing temporary breakpoint for successful
  installation of the requested continuation.
- Hardware rollback failures needing a retained reconciliation obligation.
- Observer Start/Stop requests needing the paused event-owner wake predicate.
- Queued execution commands needing retirement after a serviced mutation fails.
- Hardware add/remove requests needing last-intent ordering before owner drain.
- Partial context updates, failed instruction rewinds, and incomplete thread
  resume counts needing retained repair state before another execution attempt.
- Trace-to-temporary-breakpoint handoffs needing installation before retirement.
- Low-level writes needing checked protection restoration and cache flush, plus
  a retained rollback ledger for partial or unverifiable writes.
- Cleanup exceptions and failed detach needing the same retained event authority
  as ordinary execution failures.
- Live x64 testing exposed peers exiting while their held debug event kept the
  thread handle unsignaled. Exact-handle exit-status proof now retires only those
  peers, preserving failures for inaccessible live threads.
- Live trace testing exposed a missing final event acknowledgment. Cleanup now
  verifies restoration, acknowledges the event with its checked continuation
  status, and then removes the debug attachment. A failed attachment removal
  retries that release alone without repeating target mutations.
- Running the previously omitted integration matrix exposed a tab-strip minimum
  height mismatch at 90% scale, query arrow keys losing keyboard focus, and a
  headless navigation request submitted outside the ImGui frame. The layout and
  input fixes are bounded; the navigation request now uses the correct frame
  lifecycle and explicitly enters visible keyboard navigation before Space.
  The fixture checks the exact Projects focus ID and retains the original
  destination assertion.

The final independent patch/encoding, file-output/application-exit, debugger,
and build/CI reviews reported **no remaining actionable issues** after the
corrections. Review findings were applied before the final source build. Atomic
writer and owned-image regression checks passed, as did saved-patch recovery,
actual Keystone encoding, step policy and debugger lifecycle checks.

The native x64 suite also includes a real failed-detach fixture: a private page
containing an owned INT3 becomes inaccessible, cleanup must report failure and
reject execution/mutation, and an explicit retry must restore the original byte
after the page protection is repaired. The app-object suite checks actual file
completion before exit, output/report failure retention, exact lifecycle
completion and cancellation, and preservation of the current failure reason.

## Verification entry points

`build.ps1` builds Release with pinned dependency/toolset selection and bounded
project/compiler concurrency. `tests/run_core_tests.bat -Suite All` executes
every declaration. The default remains the quick Core selection with explicit
excluded counts. Individual test names and Core/Integration/Live categories are
also supported.

CI explicitly runs all three app-object integration suites and all live suites,
including authorization watch. CI integration and the full/required-live runner
also enable the real live patch-restoration fixture. A failed test category does
not suppress the other categories after a successful Release build. Logs and
machine-readable summaries are retained under `build/test-results`.

## Completed verification

Local verification completed on 8 September 2026 using the v143 14.44.35207
toolset. The final Release build and five-second application startup smoke check
passed. Every production source file predates the final executable.

| Manifest category | Passed | Failed |
| --- | ---: | ---: |
| Core | 141 | 0 |
| App-object integration | 3 | 0 |
| Native live debugger and authorization | 3 | 0 |
| **Distinct declared tests** | **147** | **0** |

Coverage was reconciled by exact test name against all 147 current manifest
declarations. Results combine the complete Core run, the added memory-mutation
suite, explicit integration/live runs, and focused reruns after corrections.
The final-source lifecycle rerun also passed. Superseded results and original
failure logs remain available; they are not counted as accepted results.

The three app-object suites are `static_listing_actions_test`,
`release_workbench_test`, and `feature_tabs_ui_test`. The three native live
suites are `x64_debug_test`, `wow64_debug_test`, and
`authorization_watch_live_test`. Live patch restoration ran inside the final
static integration suite and passed without skips. The following links refer to
locally retained `build/` artifacts, which are excluded from Git.

- [Consolidated results and executable SHA-256](../build/rewrite-verification-summary.json)
- [Final Release build](../build/rewrite-release-complete.log)
- [Final startup smoke check](../build/rewrite-smoke-complete.log)
- [Final static integration rerun](../build/rewrite-static-final.log)
- [Final debugger lifecycle rerun](../build/rewrite-lifecycle-final.log)

The GitHub workflow was updated and reviewed, but was not dispatched remotely
from this workspace. Graphics-device failure handling was source-reviewed;
the startup smoke check does not simulate device loss.
