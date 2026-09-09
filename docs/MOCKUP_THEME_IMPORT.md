# Binary View mockup: shared theme import — historical v1 record

This document records the first theme import. The current layout and validation
are described in [the v2 report](MOCKUP_FIDELITY_V2.md), which supersedes this
record. The overline, zebra shading and broader-suite limitation described below
belong to v1; v2 uses an underline and quiet rows and passed the combined suite.

The reference is `../Disassembler UI mockup/DisasmStudio Binary View.dc.html`.
It distinguishes a recessed code canvas, contiguous pane backgrounds, quiet
column headers, fine structural lines and restrained selection colors. The
existing native UI already has compact density, monospaced code, semantic
syntax colors, native count tabs and rounded execution controls.

## Imported theme features

| Surface | Previous Midnight | Imported Midnight |
| --- | --- | --- |
| Code canvas | `#14161A` child background | `#090C12` |
| Pane body / title strip | Child / menu colors shared with controls | `#0F131B` |
| Table header | Brightened menu background | `#0C1016` |
| Structural divider | Shared control border | `#1C2331` |
| Supporting pane text | Disabled-control text color | `#8C97A9` |

`WorkbenchFor` resolves these colors independently of control colors. Other
themes use their own existing palette to express the same surface hierarchy;
light themes retain their bright code surface. The native tab colors use a
small accent wash and the existing selected overline. Table zebra shading is
quieter, with separate header and horizontal-divider tokens.

Shared renderers can use `theme::col::chrome`, `tableHeader`, `paneLine` and
`secondaryText`. `panel` and `code` provide the corresponding content surfaces.
`panelHeader` deliberately continues to expose the established control surface:
existing button helpers depend on it.

## Preserved controls and preferences

- `PaletteFor`, all spacing/rounding/border metrics, and font baselines remain
  unchanged. No fonts are downloaded or replaced.
- Native `Button` colors and `FrameBg` interaction colors remain unchanged.
  The execution buttons use the latter, plus unchanged text, muted, accent and
  `lineSoft` colors. Step Into, Step Over and Step Out retain their geometry,
  icon/text arrangement and interaction appearance.
- Theme IDs, theme names, density factors, saved choices and independent
  zoom/DPI application remain unchanged.
- Syntax, breakpoint, pause, error and trace colors keep their existing
  semantic meanings.

## Validation

The Release build, widget/preferences checks, production workbench and feature-page
UI suites, and startup smoke check passed. Native captures were visually reviewed
in Midnight, Light and compact layouts. Button helpers, palette inputs and metrics
were compared with the baseline and remain unchanged. See
[MOCKUP_UI_IMPORT.md](MOCKUP_UI_IMPORT.md#validation) for evidence and the separate
broader-suite limitation associated with concurrent live-tracing work.
