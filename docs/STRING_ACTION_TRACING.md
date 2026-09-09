# String action tracing

In Binary View's **Strings** navigator, find a message such as `added!`, right-click it, and choose **Trace related value changes**. The nonmodal trace window shows ranked candidate instructions, a heuristic function-name hint, and clickable evidence paths. Select a candidate and use **Show instruction**, **Show function**, or **Open Live Assembly**.

FILE strings use the current analyzed image. LIVE strings require an exact mapping to that image; an unmatched heap string or a different module gives an explanation and retains the existing **Find references (where used)** route. Results describe FILE analysis even when started from a LIVE string. Opening an instruction in Live Assembly requires a fresh matching debugger/module identity. Neither tracing nor following its links executes, patches, or places breakpoints in the target.

The worker re-decodes indexed string references, builds owned function CFGs, and follows nearby direct callers and callees. Typed memory additions/subtractions, excluding direct stack/frame operands, rank above generic stores; arbitrary register aliases are not proved. A register addition followed by a same-width store in one basic block retains both the arithmetic producer and the write address. Register clobbers, calls, unsupported effects, and mismatched slices break that local chain. Mutually exclusive CFG paths and known non-returning calls cannot establish a route to an unreachable update. Known signed negative immediates invert the arithmetic direction.

The scope is bounded to 48 decoded functions, two direct-call hops, 96 instruction edges per anchor, 4,096 instructions per function, 32,768 total instructions, and 128 candidates. Ownership ambiguity, incomplete reference indexes, unreadable backing, and exhausted budgets remain visible. A completed search covers this bounded scope; it is not proof that every relevant operation in the program was found. Indirect calls, dynamic strings/code, and more distant dependencies can remain unresolved.

Names such as `add_value_candidate` require compatible string and typed arithmetic evidence. `add_points_candidate` requires point/points wording; `added!` alone does not identify a score field. Names remain heuristic, preserve stronger symbol/API/analyst names, and never prove that a particular runtime value changed. Candidate rows retain exact decoded instruction addresses for further inspection and debugger verification.

The request runs through the shared analysis scheduler with its own decoder and cancellation. Immutable reference/function snapshots avoid UI-thread decoding. Results retire when the document/image, decoder, analysis generation, classification/index publication, or originating LIVE session changes. Retry cannot carry old address/text evidence into a replacement image/session; reselect the string there.

LIVE reference searches also retain partial hits and report byte caps, short/unreadable reads, incomplete memory maps, and decoder errors. An empty partial search does not establish that the string has no users.

## Verification

- `string_action_trace_test`: local arithmetic, register-to-store lineage, caller/callee paths, unrelated and mutually exclusive branches, stack/unknown effects, negative immediates, actual worker decoding, non-returning calls, stale references, partial indexes, cancellation and budgets.
- `function_namer_test` and `function_namer_pipeline_test`: compatible message/action names and stronger-name preservation, including real evidence collection.
- `livescan_service_test`: complete versus capped/short/unreadable LIVE reference searches and useful partial results.
- `tests/string_trace_ui_fixture.inc`: actual production worker/UI integration, result ownership, stale publication retirement, FILE address-zero navigation, refused unmatched LIVE handoffs, and Retry ownership.
- `tests/live_scroll_fixture.inc`: actual renderer and checked reads against a contained test child, including continuous scrolling, arrow keys, held scrollbars, ambiguous prefix bytes, refresh stability, and traversal beyond 64 KiB in each direction.

Build Release x64 before running `tests/run_static_listing_actions_test.ps1`; set `DS_LIVE_SCROLL_TEST=1` to include the contained live scrolling case. The new core tests run through `tests/run_core_tests.ps1`.

The final Release x64 build passed (`build/live-review-final-scroll-build.log`). The full production-object UI suite, including string tracing and the contained live scrolling case, passed with zero failures (`build/live-review-final-full-suite.log`); all 129 linked production objects match the built application. The focused `string_action_trace_test`, `function_namer_test`, `function_namer_pipeline_test`, `livescan_service_test`, and `analysis_service_test` also passed. These are synthetic regression cases; the user's particular binary was not interactively traced during this verification.
