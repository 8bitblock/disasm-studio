# Binary View mockup import — historical v1 record

This document records the first UI import and its validation at that point in
time. It is superseded by [the v2 implementation and verification](MOCKUP_FIDELITY_V2.md).
The six failures recorded below were resolved before the final v2 validation.
Build logs, captures and delivery paths below refer to local historical artifacts
and are not included in this repository.

This update brings the supplied `DisasmStudio Binary View.dc.html` design into
the native C++/ImGui workbench. Three subagents compared the reference, implemented
the theme and workbench changes, and independently reviewed the result. The main
agent integrated the shared widget styling and validated the combined application.

## Comparison and implemented scope

| Reference feature | Native implementation |
| --- | --- |
| Recessed code canvas and contiguous dark panes | Separate code, panel, header and divider colors; Midnight uses the reference colors. Other palettes retain their own colors. |
| Quiet representation tabs and table headers | Subtle selected-tab fills and horizontal table rules across feature pages and drawers. Native IDs, overflow navigation and saved columns remain intact. |
| FILE/LIVE breadcrumb capsule | A source capsule, file/module context and full address, with existing copy/navigation behavior and a narrow-width layout. |
| Selected function above the listing | A context strip with the real selected location, function name and boundary metadata. Long text has a full tooltip. |
| Function navigator hierarchy | Inventory capsules, name-origin markers, aligned addresses and subdued function dividers. Guessed names remain explicitly distinguishable. |
| Green string rows and encoding labels | Source-aware selected rows, encoding chips with narrow-column fallbacks, and existing reference information. |
| Register and evidence hierarchy | Grouped optional live-register details, flag capsules, pointer hints, wrapped bytes and branch-status capsules with a narrow-width fallback. |
| Compact workbench controls | Existing button design is retained, including Step Into, Step Over and Step Out. |

The current application already provided permanent Functions/Strings, all seven
representations, a central lower drawer, an independent evidence inspector,
breakpoint counts, state capsules, and a checked thread selector. Those features
remain available. The mockup's example targets, addresses, process states and
register values are not imported as application data.

## Preserved behavior

Button helpers and execution-control calls are unchanged. Their palette inputs,
rounding, padding, borders, icon/text arrangement and interaction colors are also
unchanged. Fonts, theme IDs, density, zoom and Windows DPI handling remain intact.

UI rendering continues to use the existing ownership checks for FILE/LIVE data,
navigation, registers and branch outcomes. This design update does not add target
reads, execution commands or persistence behavior.

Concurrent live-listing, reference-scope and string-tracing edits were present
during this task. They are preserved in the working source and omitted from the
UI-only patch. The combined Release executable includes that working source.

## Files

- `src/Ui/Theme.h` and `Theme.cpp`: independent workbench surface colors.
- `src/Ui/Widgets.cpp`: shared tables, panel headers and representation tabs.
- `src/Tabs/BinaryViewWorkflow.cpp`: source breadcrumb presentation.
- `src/Tabs/BinaryViewTab.cpp`: navigator, context, listing and inspector details.
- `docs/MOCKUP_THEME_IMPORT.md`: theme comparison and preserved control inputs.

## Validation

Verification status as of 9 September 2026:

| Check | Status | Evidence |
| --- | --- | --- |
| Combined Release x64 application | Passed; executable produced and embedded GameMaker helper verified | [Build log](../build/live-review-release-final-build.log) |
| Shared widgets (`ui_widgets_test`) | Passed | [Test summary](../build/mockup-tests/widgets/20260909T025430825Z-05e86643294f4d4081726978ba52b5e6/summary.json) |
| Preferences (`preferences_test`) | Passed | [Test summary](../build/mockup-tests/preferences/20260909T025653218Z-b69bc52bfa534c22a532c36e808730cf/summary.json) |
| Release-workbench harness compilation | Passed compilation only; no linking or test execution in this precheck | [Precheck log](../build/mockup-import-compile-precheck.log) |
| Production release-workbench suite | Passed, 0 failures, including complete capture run | [Successful rerun](../build/mockup-import-workbench-rerun.log) |
| Production feature-page suite | Passed, 0 failures; production objects unchanged during the run | [Feature test log](../build/mockup-import-feature.log) |
| Application startup smoke check | Passed; alive after 5 seconds | [Smoke log](../build/mockup-import-smoke.log) |
| Native capture output and review | 72 workbench and 62 feature-page PNGs; representative layouts visually reviewed | [Workbench captures](../build/mockup-captures/workbench), [feature captures](../build/mockup-captures/feature) |
| Broader combined static-listing suite | Six failures in concurrent string-trace and live-scroll work; independent review found those paths outside the UI patch. That log predates subsequent fixes; no all-suite-green claim is made | [Broader run](../build/live-review-production-test/app-objects/run.log) |

The successful build used MSVC v143 `14.44.35207` from Visual Studio Community
under `C:/Program Files/Microsoft Visual Studio/18/Community`. The resulting
`build/x64/Release/DisasmStudio.exe` was 19,293,696 bytes with SHA-256
`5BDBAB9A54504260A2BC1823116E5264F3F1B5A43C6DBC00815896EEA9461E5E`
when inspected. The helper resource verification reported 161,280 bytes and
SHA-256 `808338B5B9B24B4C257339393D0319B7207C2D34D95F4595EC8132FBFFDBE021`.

Independent source review corrected three presentation issues before validation:
branch/encoding/flag capsules retain ImGui text logging, breadcrumb source text
retains its compact inset, and register flags wrap to fit the minimum pane width.
Existing button helpers and their style inputs were checked against the baseline.

The source-only patch at `../../ui-import-delivery/ui-design.patch` was reviewed
independently and passed `git apply --check` against the preserved baseline.
Its five staged source hashes match the patch manifest; concurrent live decode,
scrolling, reference and string-tracing changes are excluded. Patch SHA-256:
`64bc61074cfd900d1299b0e35725b091d0529d6a8f782f7eb59acc5acccfafcd`.
The first workbench attempts ran out of disk space while copying objects or
saving captures. A task-local runner avoided duplicate objects without changing
test assertions, and the existing executable then passed its complete capture
run. Generated build/test artifacts were compressed losslessly to recover space.

Visual checks covered Midnight/Light, compact layouts, all major representations,
menus, drawers and the paused execution toolbar. Physical monitor transitions and
a real live-target walkthrough were not performed. The optional 160-pixel
register-side-pane flag wrapping remains source-reviewed, not separately captured.

The v1 local delivery was [the reviewed UI-only patch and report](../../ui-import-delivery/README.md).
That historical patch excluded concurrent tracing/scrolling code and did not claim
that work was complete. See the v2 report linked above for the combined result.
