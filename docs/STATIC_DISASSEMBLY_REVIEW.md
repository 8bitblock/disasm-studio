# Static disassembly workflow review

7 September 2026

## Improvements

The two function lists share a parsed query matcher. Search is ASCII case-insensitive across the displayed name, original name, and hexadecimal address. Space-separated terms must all match; `-term` excludes matches and double quotes preserve phrases. Examples: `read -thunk`, `"read settings"`, `0x140010`. Original symbols remain searchable after analyst renames. Empty queries show every function; unmatched filters show a clear empty state and match counts.

Each query is parsed once when the filter cache changes. Matching uses string views and stack address formatting without allocating per function. Exact function and rename generations invalidate the cache, including changes to interior functions that leave the function count and endpoint addresses unchanged. Both lists remain clipped to visible rows.

Right-click a function in either list to open Assembly, Pseudocode, or its control-flow graph, or to pin references to its entry. These explicit destinations preserve FILE identity, address zero, and back/forward history. Unsupported decompiler architectures disable the Pseudocode action. Enter in the lower Functions filter opens its first match in Assembly.

The cursor-following Xrefs pane retains its Writers, Readers, Address taken, and Branches/calls groups and index edge count. It rebuilds when the target or published result changes, instead of repartitioning every incoming reference and recounting the entire index each frame. Cursor and enclosing-function groups have separate cache entries. The publication identity invalidates a same-signature rebuild, and stale epochs never display old results. Enclosing-function references also work for owned chunks more than 1 MiB from their entry. An exhausted analysis request offers an explicit retry.

Function naming previously retained up to 512 decoded instructions for every discovered function before processing evidence. It now probes the first non-padding instruction for thunk detection, then processes one bounded function body at a time. Existing named exports skip full-body decoding. Cancellation reaches prefix decoding, thunk resolution, evidence synthesis, and name allocation; a canceled naming pass returns no partial names. Output metadata still scales with the number of functions, but decoded-body storage no longer does.

## Verification

- `function_filter_test`: query semantics, address zero/full-width addresses, long symbols, owned query lifetime, and zero allocations during matching.
- `function_namer_test` and `function_namer_pipeline_test`: existing inference behavior, bounded streaming order, named exports, padded thunks, and cancellation.
- `analysis_service_test`: worker scheduling, cancellation, and publication integration.
- Production-object UI fixtures cover both function caches, explicit destinations and history, same-signature xref replacement, partial/empty results, a 32,768-reference hub, distant owned chunks, and retry behavior.

The Release x64 build passed using the installed VS Community host and MSVC v143 14.44, including embedded GameMaker helper verification. The build used existing installed dependencies after vcpkg restoration stalled; no dependency versions were changed. See `build/static-workflow-build.log`.

All five test executables listed above passed, including `static_listing_actions_test` with zero failures. The production-object UI suite exercised Midnight and Light themes at 820×560 and 1600×960 with 1.0×, 1.5×, and 2.0× scaling. See `build/static-workflow-ui-tests.log`. The integration runner now selects the production v143 toolset when a newer Visual Studio installation hosts the build. This was headless UI verification; a new native debugger session was not part of this static-workflow review.

## Remaining opportunities

Static Enter-follow currently handles control-flow targets; typed data-reference handoff to Hex would reduce additional navigation steps. Pinned reference searches retain the existing 3,000-hit display cap, even when the complete index contains more results. Those are separate changes from the cursor-following panel cache. No whole-app speed multiplier or peak-RSS benchmark is claimed by this review.
