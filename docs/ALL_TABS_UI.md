# Consistent tab presentation

- All feature pages share the compact Axiom component style across every palette:
  section headers, outlined task/status capsules, aligned controls and quiet data
  tables. Code, hex, graphs and layout grids keep their specialized presentation.
- `ui::BeginDataTable` / `BeginDataTableEx` preserve native IDs, schemas, widths,
  scroll flags and saved column choices. They replace heavy outer/vertical grids
  with subtle alternating rows and horizontal separators. Matching
  `EndDataTable` restores the style; a clipped Begin restores it immediately.
- `ui::BeginCountTabItem` keeps the original native label/ID and draws inventory
  counts separately. Its text is clipped to the actual tab and scrolling section;
  hover details use the normal text color. Counts do not become part of durable
  tab identity.
- Projects, Scanner, Tech, Diff and Cortex share clearer scope/action/result
  grouping, real progress/save-state badges, responsive tools and empty states.
- Communications applies the same treatment to processes, modules, connections,
  Server Watch and Java thread/stack/breakpoint tables. GML retains distinct
  unverified, preparing, connected, paused, stopping and failed states.
- Memory Tools and Prism use consistent viewer/report headings, inventory tabs,
  readable horizontally accessible columns and compact status/context rows.
  Memory keeps complete data rows and its selection actions accessible at high
  zoom; profiler percentages remain labelled observations.
- Binary View's drawer tables, type fields, GML records, overview coverage,
  annotations, authorization/triage, references and call graphs share the data
  style. Threads, watches, search results, patches and imports have matching
  inventory tabs; widths follow zoom and DPI. Results use clipped table rows.
  Long annotation notes use an ellipsis and full-text tooltip so confidence
  remains separate and readable.
- Existing checked actions, debugger ownership, analysis evidence, saved layouts,
  drafts, fonts, density and theme preferences remain authoritative.

Validation uses the existing shared-widget, feature-page, release-workbench and
full production-workbench suites. The optional hardware DX11 captures include
all feature pages and 25 additional native drawer views with labelled fixture
records; the debugger remains detached during those captures. Artifacts and the
final verification result are recorded in `additions.md`.

- Release x64 candidate: `build/x64/AxiomAllTabs/DisasmStudio.exe`; embedded
  GameMaker helper verification passed in `build/all-tabs-build.log`.
- Shared-widget, feature-page, release-workbench and full production-workbench
  tests passed with zero failures. Logs are `build/all-tabs-feature-final-tests.log`,
  `build/all-tabs-workbench-final-tests.log` and `build/all-tabs-full-final-tests.log`;
  the widget summary is under `build/all-tabs-tests/widgets-final`.
- The three production suites used 126 identical object snapshots. The later
  annotation ellipsis is a local presentation correction, rebuilt and checked
  with the focused release-workbench suite (zero failures in
  `build/all-tabs-workbench-reviewed-tests.log`) and fresh drawer captures.
  Candidate SHA256:
  `DF52D016FF5FDA626806E85EF1A8B939594471E826F08E735BCB572621EF14CB`.
- Visual review includes 62 feature captures under
  `build/all-tabs-feature-final-captures` and 25 added drawer views under
  `build/all-tabs-drawer-final-captures`. These cover wide and compact layouts,
  zoom, actual fixture inventory, empty views and pending analysis states.
  Authored running/paused records are explicitly labelled; no target was
  attached for these captures. Physical monitor DPI and interactive live-target
  walkthroughs were not part of this presentation pass.
