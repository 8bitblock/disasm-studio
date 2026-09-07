# Figma release design v2 — incomplete draft

**This Figma draft is not the final customer-review design.** Use the local interactive design in [design-release-v2.html](design-release-v2.html) as the primary deliverable.

Figma stopped the assembly-section write with an explicit Starter-plan MCP tool-call limit. The rejected call did not create the assembly content. No upgrade was requested and no repeated attempts were made.

- [Editable partial draft](https://www.figma.com/design/u3NZFPpL31hokMQ7oNQBMA?node-id=3-37)
- [Exact node and token ledger](figma-release-v2-state.json)

## Complete

- Code Connect search, blank-file inspection, available-library discovery and searches for components, variables and styles. No matching DisasmStudio assets were found.
- Code-derived Midnight graphite palette from `src/Ui/Theme.cpp`, scoped variable bindings, text styles and a restrained selection glow.
- Foundations notes and reusable tab, action, status, list-row and assembly-row components.
- All nine feature tabs: Projects, Communications, Sig Scanner, Binary View, Memory Tools, Binary Diff, Binary Tech, Cortex and Prism.
- Separate Analyze, Debug, Memory and Compare presets.
- Continue, Step into, Step over, Step out, Run to cursor and Trace controls with shortcut labels.
- Document tabs, a LIVE breadcrumb with module/function/address and an explicit pin control.
- Functions and Strings visible by default; optional navigator categories collapsed.
- Header and navigator screenshot inspection.

## Remaining

The composed assembly listing, breakpoint and flow-arrow overlays, branch prediction, evidence inspector, lower details drawer, analysis queue, independently collapsed variants, prototype interactions and full-screen validation were not completed before the quota block. Blank panes are construction state, not intentional design decisions.

## Typography

Segoe UI and Consolas are unavailable in the Figma renderer. The user approved best judgment on substitutes. This companion uses **Roboto** for UI and **Cascadia Mono** for code. The native application and local interactive design retain **Segoe UI** and **Consolas**. The Figma typography must not be described as pixel-identical to native.

## Intended evidence behavior

The paused fixture is a current `JNE` instruction with known `ZF=0`: it may say “Jump will be taken · ZF=0.” Static instructions and future conditional branches must show unknown outcome. Evidence should use Observed / Candidate / Unknown without invented confidence percentages.

## Resumption

Continue from the IDs in the ledger. The main wrapper is `3:37`, center pane `6:101`, inspector `6:102`, row kit `7:36`. Existing completed elements should be retained. The full screen is 1920 × 1200, with a 300 px navigator, 1210 px center pane and 410 px inspector.

Do not label this file ready for shipment until the remaining screen composition and visual checks are complete.
