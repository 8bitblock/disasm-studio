# Closer mockup implementation

The earlier import retained too much of the existing layout. This revision follows
the supplied Binary View mockup's composition and density, while preserving every
feature-page destination, command and context-menu action. The user explicitly
confirmed that Step Into, Step Over and Step Out should retain their current design.

| Area | Implementation |
| --- | --- |
| Shell | Compact header with document picker and real debugger state; slim top-level page strip; one primary execution row with overflow; compact footer. |
| Workbench header | Flat representation tabs, Go and Workspace menus, and a single selected-function row with Display/More actions. |
| Left rail | Functions and Strings share the whole rail in a 1.1:1 ratio. Rounded search, real name-category/encoding filters, leading string encoding chips and known reference counts. |
| Secondary navigator tools | Existing Bookmarks, Search, Sections, Exports, Imports, Resources, Types and analysis queue are reachable through the list-heading tools menu. |
| Listing | Smaller scoped typography, quiet rows without zebra/grid lines, cyan addresses, subdued bytes/comments, and flow arrows between addresses and instructions (after bytes when shown). |
| Right rail | Registers first: real state, flags, grouped values, existing copy/follow/edit handoffs. Selected instruction follows; longer value-origin and activation evidence lives under Details. |
| Proportions | Reference-inspired 248/252 logical-pixel side rails, 196/204 on narrower windows, a compact 168-pixel drawer, thin separators and square pane surfaces. |

The exact reference ink colors apply to Midnight. Other selected palettes remain
available. The font atlas and execution-button helpers are preserved; only the
Binary View body receives the smaller scoped font size. Listings hide the byte
column on first use while saved visibility remains authoritative. New tool popups
are constrained to the viewport, and long selected-function locations retain full
hover text while leaving room for the function name and Display/More actions.

Register values, flag outcomes, function names, string references and process
states come from application data. The design import adds no fabricated target
data and does not relax debugger or write ownership checks.

## Verification

| Check | Result |
| --- | --- |
| Release x64 build | Passed; embedded GameMaker helper verified. |
| Shared widget tests | Passed. |
| Production workbench suite | Passed, 0 failures. Toolbar bounds, moved tool access, filters, register editing and observation validity are checked. |
| Production feature-page suite | Passed, 0 failures. |
| Full combined regression suite | Passed, 0 failures, including contained-child live patch restoration, live multi-row patching and live scrolling (26 stable refills; about 69 KiB in both scrollbar directions). |
| Startup smoke check | Passed; Release app stayed alive for 5 seconds. |
| Native renders | 74 workbench and 62 feature-page captures; all converted to PNG and checked for exact pixel equality. |
| Production object identity | All 15 checks of the five edited UI object snapshots across three suites match the final build. |
| Source patch | Applied to the starting-source copy and byte-compared with all 18 edited files. |

The main agent and three subagents reviewed implementation, command retention,
and native output. Representative checks include full-shell 1440/900 layouts,
Midnight/Light, paused execution controls, x64/WOW64 register rails, Cortex,
Communications at 820 pixels, and Memory Tools at 150% scale. No blocking visual
or access regressions were found. A capture-time font check confirms the four
main workbench children inherit the intended scale exactly once (12.92 pixels
for the 17-pixel UI face at 100% scale).

All nine top-level pages and all 20 pre-existing Binary View context-menu bodies
remain. The step-button helpers/call sites, checked thread-selection logic,
FILE/LIVE action target validation and paused branch verification are unchanged.
Tests retain their ownership and action assertions; changed navigation assertions
follow the approved popup layout. Input fixtures now use native column bounds
instead of the old flow-lane position, explicitly reveal Bytes before testing a
byte-column drag, and use ImGui's exact case-sensitive menu-bar ID for keyboard
activation of the document inventory.

Feature and full test links run sequentially after the initial parallel attempt
exceeded the practical memory budget. They reuse the official runner's unchanged
fixture object, isolated production snapshot and linker response file. No test
assertions are bypassed. Captures use authored test data and synthetic debugger
snapshots; they do not claim a live attached session. Two live captures contain an
ordinary hover tooltip, so unobscured captures are used in the delivery previews.

The full rerun enabled `DS_LIVE_SCROLL_TEST=1` and
`DS_PATCH_RESTORATION_LIVE_TEST=1`. Those separate checks use real debugger
operations against a contained test child. The source patch includes the final
test geometry corrections; the application objects and Release executable are
the same ones that passed the workbench and feature-page suites.
