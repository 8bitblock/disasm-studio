# Investigation index core

`Core/InvestigationIndex` is the dependency-light search foundation for the unified
investigation omnibox. Callers provide immutable snapshots of functions, strings,
imports, comments, resources, byte hits, xrefs, live modules, and recent queries.
The index does not read `BinaryFile`, project state, debugger state, or sockets;
snapshot collection and `Build()` belong on the owning document's background job.

Every result is typed, scored, evidence-bearing, and carries an explicit `FILE` or
`LIVE` address identity. Address validity is separate from its value, so VA zero is
navigable. Exact address expressions accept debugger-style hexadecimal plus
`file:`/`va:`/`live:` qualifiers; malformed and overflowing expressions are rejected
instead of being silently reinterpreted as fuzzy text.

Rebuild and search are cancellable. Fixed per-category, total-record, result, query,
field, normalized-key, and aggregate-text ceilings bound hostile snapshots. A
cancelled rebuild publishes no partial index, and a cancelled search publishes no
partial hits. Ranking is stable: exact address, exact text, prefix, token prefix,
substring, then ordered fuzzy matches, with category and snapshot order as explicit
tie-breakers.

`Core/InvestigationService` owns rebuild and search on one joined worker. Its queue
is fixed at one latest build plus one latest search; replacement commands coalesce
and cancel superseded work. Every command and immutable publication carries the
document generation and request ID, preventing an old document or query from
publishing into a replacement session. The UI only enqueues shared snapshots and
polls shared publications. Requested, coalesced, dropped, stale, failed, and
completed counters make overloads and failures visible.

## UI integration

`BinaryViewTab::advanceInvestigationSnapshot` collects the tab-owned analysis state
in time- and record-bounded slices. It stamps file images, debug sessions, xrefs,
and ephemeral byte/text search results with explicit owner generations, abandons a
slice when any owner changes, and publishes an empty replacement immediately when
the target changes. Large strings and xref sets are therefore never copied in one
render-frame operation, and an old target cannot remain searchable during a switch.

`App::maintainInvestigationWorkspace` hands each immutable completed snapshot to
the service and keeps the app awake only while collection/build/search is pending.
The Ctrl+K palette merges its small command list with worker-ranked investigation
results. Selecting a valid FILE result uses static navigation; selecting a valid
LIVE result uses runtime navigation. Results without a validated address remain
inspectable but cannot silently navigate, while recent queries refill the omnibox.
