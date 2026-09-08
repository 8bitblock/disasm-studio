# Axiom-inspired UI

The subsequent [all-tabs refinement](ALL_TABS_UI.md) extends the shared style to
the content, tables, controls and inventories inside every feature page and
Binary View drawer. Its implementation and validation supersede the component-only
scope below.

The optional **Axiom** palette adapts the supplied SVG's near-black code canvas,
navy panels, blue selection and colorful syntax accents to DisasmStudio's
existing native workbench. Select it in the existing theme menu or through the
command palette. It is appended after the previous themes; the default and old
saved theme IDs are unchanged. Component styling and layout improvements now
apply to every theme; choosing a palette changes its colors.

## Shared components across all themes — 2026-09-08

- Promoted the compact breakpoint tab/count, arming rings, status capsules,
  selected rows and row actions to every palette. Theme changes retain the same
  table schema, column choices and checked FILE/LIVE actions.
- Applied the pause-reason capsule and native thread selector across themes,
  retaining exact target/pause validation and compact toolbar layouts.
- Shared rounded buttons, search fields, tabs, pills, state dots and quiet panel
  headers across all pages. Each theme retains its own semantic colors, fonts,
  zoom, density and saved identity; the Axiom palette remains optional.
- The original Axiom-only implementation and verification record below is
  historical. The shared-component follow-up is recorded in `additions.md`.
- Follow-up validation passed: Release x64 build and embedded helper, shared
  widgets, feature pages, focused release workbench, and full workbench matrix.
  All three production suites used the same 126 object snapshots. Dark/light
  breakpoint captures and twelve shell state/width captures were visually
  reviewed; artifacts are under `build/axiom-all-themes-tests/` and
  `build/axiom-all-themes-captures/`. The updated executable is
  `build/x64/AxiomAllThemes/DisasmStudio.exe`.

## What changed

- The reference correction follows the user's four component screenshots:
  near-black flat panels, neutral inputs, restrained blue selection and small
  cyan, amber and rose details. Broad violet/blue fills were removed. Inputs and
  compact tabs use 5px rounding, popups/dialogs 6px, while large child panels stay
  square; all metrics scale with DPI/zoom. All themes now share these components
  while retaining their colors. Font baselines and retained layout settings remain authoritative.
- Axiom's function navigator uses cyan function marks and right-aligned addresses,
  with a slim blue bar on the selected row. Its optional Sections destination uses
  the actual file's section names and sizes.
- Breakpoints use a compact dot/count tab, muted red rows, enable rings, explicit
  status capsules and row actions. Saved FILE requests, live arming, failures and paused ownership keep
  their real meanings. The debugger's temporary unarmed state is not relabeled
  as a user-disabled breakpoint.
  The later [breakpoint pause addition](BREAKPOINT_PAUSE.md) makes the ring
  interactive and adds Pause/Enable actions while retaining breakpoint metadata.
- The Axiom shell has an amber pause capsule with the debugger's actual event
  reason and a compact native-thread selector. The popup revalidates its target
  and pause before calling the checked thread-selection API. Narrow layouts keep
  the reason and thread inventory reachable through the capsule.
- Shared compact panel headers separate content, actions and context. Existing
  search, status, focus, table and action widgets use the centralized palette.
- Projects separates the selected recent target from the active file's saved
  analysis. Signature Scanner gives the pattern and Scan action a primary row.
- Binary View keeps Functions/Strings, all seven representations, the center-only
  lower drawer and the independently collapsible evidence inspector. Assembly
  and Live Assembly expose display choices through **Display**, and instruction
  and rebuild actions through **More**. The checked shell owns live execution.
- New listing columns favor instruction space; saved column choices remain
  authoritative. Syntax, comments, FILE/LIVE provenance and execution markers
  remain visible. Axiom uses steady, distinct breakpoint/RIP markers.
- Pseudocode starts with more space for source and provides horizontal access to
  long lines in both panes. A temporary narrow window preserves the chosen split.
  Live inline branch hints explicitly describe captured flags; the evidence
  inspector still requires fresh checked observations for a definite outcome.
- Communications retains Processes & Attach, Network Monitor, Java/JDWP and
  GameMaker/GML. Process selection and attachment remain separate concepts.
  JDWP gives bytecode more space and provides Browse/Bytecode/Session views when
  narrow. GML groups target/archive, verified session status and execution.
- Server Watch has adjustable events/details panes and retained compact views.
  Coverage, losses, errors and logging health remain outside scrolling details.
  File logging retains its existing observation-start and identity checks.
- Memory Tools keeps the scanner, inspector and independent address table;
  compact controls and scaled, horizontally accessible region columns preserve
  full addresses at higher zoom.
- Binary Diff uses matching baseline/candidate headers and recessed byte/code
  panes, distinguishing changed bytes from selection. Binary Tech and Cortex
  separate findings from selected evidence while retaining honest source labels.
- Prism retains collection/quality/timeline context above independently
  scrollable charts and reports, with a retained splitter and compact views.
  Report tables keep their earlier saved identities across these wrappers.

## Preserved contracts

No debugger, analysis, memory or persistence implementation is changed by this
redesign. Presentation still calls the existing checked actions. Font baselines,
75–150% UI zoom, independent Windows DPI, density, keyboard shortcuts, document
tabs, all nine feature destinations and overflow navigation are retained.
Theme switching does not reset layouts, selections, drafts or navigation.

The SVG's example data, branding, tiny type, reduced feature set and register-only
inspector were excluded. Registers remains in its primary drawer.

## Validation

The main agent reviewed the exclusive page changes delivered by three page agents,
then built and tested one candidate using matching production objects. The
focused fixtures are `axiom_binary_view_fixture.inc`, `axiom_shell_reference_fixture.inc`,
`axiom_communications_fixture.inc` and `axiom_runtime_layout_fixture.inc`.
The existing preferences, widgets, feature-page, release-workbench and full
workbench checks remain part of validation.

Setting `DS_UI_CAPTURE_DIR` when running the feature-page or release-workbench
suite also renders authored, populated UI snapshots through the real ImGui DX11
backend on a hardware D3D11 device. Captures use the production fonts and page
objects. They are isolated fixture evidence, not observations of a user target.
Normal test runs do not require a graphics device.

The updated Release x64 candidate is `build/x64/AxiomReference/DisasmStudio.exe`, built with MSVC
v143 14.44.35207. Its SHA256 is
`65d810bf554d6322fada5827a2c8a90ffecfbd67da035681a39569f136f11264`.
The embedded GameMaker helper passed resource verification. Existing unrelated
uncommitted work was preserved and is included in this workspace candidate.

| Check | Result | Evidence under `build/axiom-tests/` |
|---|---|---|
| Preferences | Passed | `preferences/*/summary.json` |
| Shared widgets | Passed | `widgets/*/summary.json` |
| Production feature pages | Passed, zero failures | `feature-final/app-objects/run.log` |
| Full production workbench | Passed, zero failures | `full-final/app-objects/run.log` |
| Release workbench | Passed, zero failures | `workbench-final/app-objects/run.log` |

The three production suites each use the same 126 production objects as the
candidate. `build/axiom-verification.json` records their matching SHA256 hashes,
the executable and helper hashes, test results, source hashes and capture hashes.

Coverage includes all nine feature destinations by mouse and Ctrl+1 through
Ctrl+9, all seven Binary View representations by mouse and keyboard, Display/More
interactions, retained table identities and layout choices, JDWP compact views
and stop following, Server Watch splits and persistent status, and short-height
Prism. A real register-editor input fixture retains unsaved text, exact pause
ownership, populated back/forward history and FILE selection through
Axiom → Midnight → Light → Axiom without submitting a write. The shell matrix
covers all ten themes, three densities, three window
sizes (including 1440×900), and separate requested zoom/applied DPI cases. Focused
page fixtures also cover Axiom, unchanged Midnight and Light with production
fonts, compact windows and high zoom. Existing checked-state fixtures exercise
stale-session refusal, register draft cancellation, instruction observations,
FILE/LIVE provenance, unreadable memory, selection/copy and partial/error states.

Main-agent visual validation and page-agent reviews cover 80 populated hardware DX11 fixture captures
across every page and representation, including x64/WOW64 execution markers,
compact layouts and the 1440×900 shell. Full-resolution PNGs and contact sheets
are under `build/axiom-reference-captures/`. Review corrections included Pseudocode space
and scrolling, full Memory address-table row access at 150% zoom, captured-flag
wording, narrow logging visibility and unsupported glyphs.

The screenshot correction follows the four supplied component crops. Main and
page-agent review cover the neutral shell, blue navigator selection, selected
Saved FILE breakpoint row, distinct breakpoint/RIP markers, amber pause capsule
and native-thread selector, including the compact toolbar. These fixtures use
authored observations and never pretend to establish a real debugger stop.

New interaction coverage includes Add without toggling an existing breakpoint,
stale breakpoint/thread popup refusal, correction of failed saved conditions,
stable FILE row identity through installation, and both breakpoint table schemas
through Axiom, Midnight and Light. Custom column order, hiding, original widths
and appended-column widths are checked under the real shell's non-saving window
flags. The optional Every-N column retains its default visibility and its row
menu action. Independent review caught and corrected the ownership and table
retention issues before final validation.

All five checks above passed for the final screenshot correction. Final visual
acceptance also checked the breakpoint tab's red dot and actual count capsule,
the selected row and navigator, and the full and compact shell layouts.

An interactive live-target/debugger walkthrough and physical multi-monitor DPI
transitions remain **pending**. Fixture snapshots do not validate those native
interactions. The full workbench suite also explicitly skipped its opt-in live
patch-restoration test (`DS_PATCH_RESTORATION_LIVE_TEST`); this UI task does not
claim that test was rerun.
