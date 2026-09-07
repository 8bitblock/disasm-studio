# DisasmStudio — release design v2

This handoff records the customer-facing workbench design. The subsequent native integration and its actual verification are documented in [RELEASE_UI_IMPLEMENTATION.md](RELEASE_UI_IMPLEMENTATION.md). The design-artifact checks below remain distinct from native debugger QA and shipping approval.

- [Interactive design](design-release-v2.html)
- [Imagegen visual direction](workbench-workflows-concept-v2.png)
- [Partial Figma draft — incomplete](https://www.figma.com/design/u3NZFPpL31hokMQ7oNQBMA)

The local design preserves Segoe UI and Consolas. Figma uses Roboto and Cascadia Mono as practical font substitutes; this does not change the native app's font contract. The Figma draft hit the account's tool-call limit before assembly, inspector, and collapsed variants were complete, so it is not a final handoff. The local interactive design is the primary artifact. Sample binary names, addresses, registers, and activation evidence illustrate layout and are not observations from a live target.

## The ten requested refinements

| # | Existing native behavior | Refined design contract |
|---|---|---|
| 1 | Static and live listings already have jump arrows, enabled by default. | Retain a dedicated flow gutter with distinct lanes, destination arrowheads, and offscreen continuation stubs. Do not replace arrows with text-only links or paint them over instructions. |
| 2 | Selected rows already have a layered halo, outline, and left accent. | Preserve a restrained blue selection glow across the row with a clear focus edge. Keep glyphs, bytes, and breakpoints legible; glow does not identify execution by itself. |
| 3 | There are nine feature tabs and seven Binary View representations. | Keep the complete inventories below. Workflow presets supplement feature tabs. A compact layout must preserve access to every item through an explicit overflow control; Ctrl+K is also retained. |
| 4 | The right live register pane is resizable and can be hidden with a checkbox. | Give the right inspector a visible collapse/expand control. Collapse to a labeled rail; expand to its previous width and content. |
| 5 | Navigator separates Functions/Strings/Bookmarks from Search/Sections/Exports. | Keep Strings visible and expanded by default, alongside function navigation. Additional categories open only when the analyst opens them, and retain that manual choice. Include navigation to all existing tools. |
| 6 | The lower tools drawer already collapses to a tab rail. | Preserve independent collapse, selected tab, previous height, scroll position, and editor state. Clicking a tab in the collapsed rail reopens that tool. |
| 7 | Calls, branches, returns, registers, immediates, and punctuation already use semantic colors. | Make instruction syntax visibly differentiated. Preserve mnemonic/operand coloring and explicit LOCK/REP prefixes; color cannot be the only signal. |
| 8 | Paused live conditional branches show jumps/falls-through text from current flags. | At the paused current RIP, show “Jump will be taken” or “Jump will not be taken” with the known condition and destination/fallthrough. Unknown, running, stale, and static states must not assert a predicted outcome. |
| 9 | A breakpoint gutter precedes the flow gutter and address. | Keep a dedicated clickable breakpoint column. Expose armed, saved/inactive, disabled, conditional, hardware, pending, and error states without confusing them with RIP or selection. |
| 10 | Into/Over/Out and Trace already exist in live debugging. | Preserve labeled Continue/Pause, Step Into, Step Over, Step Out, and Trace controls. Into/Over/Out remain visible and are enabled only when the session permits the action. |

## Navigation and feature inventory

**Feature tabs:** Projects · Communications · Sig Scanner · Binary View · Memory Tools · Binary Diff · Binary Tech · Cortex · Prism.

**Application menus:** File · View · Debug · Help remain discoverable for opening/exporting binaries, settings, debugger commands, and help.

**Binary View representations:** Overview · Assembly · Pseudocode · Hex · Graph · Call Graph · Live Assembly. Disabled representations remain discoverable and explain the prerequisite. The former duplicate Decompiler view stays folded into Pseudocode.

**Workflow presets:** Analyze · Debug · Memory · Compare. Choosing a preset arranges relevant panes and navigation; it must not implicitly attach, launch, run, patch, or write target memory.

**Navigator:** Functions and Strings stay directly visible. Optional entries include Bookmarks, Search, Sections, Exports / Symbols, Imports, Resources, and Types. These may navigate to existing tool bodies instead of duplicating editors. Automated analysis refreshes, preset changes, and document reloads must not expand optional navigator categories or overwrite manually retained choices. An explicit user command to open a tool may reveal its requested destination.

**Debug/data drawer:** Breakpoints · Registers · Threads · Call Stack · Functions · Watch · Notes · Results · Patches · Imports · Resources · Hotkeys. GML appears when applicable.

**Analysis drawer:** Modules · Debug Output · Stack · Xrefs · PDB / Symbols · Address Inspector · Types · Algorithms · Annotations · Triage · Synthesis · Hot-Patch · Path Explorer. Java appears when applicable. Long inventories use an accessible tool picker or overflow; tools must not disappear when switching presets.

**Triage:** Start Here · Network Trail · Authorization · Strings · Functions · Runtime. “Activation trail” is the direct entry to Authorization, not a second analyzer with conflicting evidence.

## Pane, location, and observation contracts

The right inspector, lower detail drawer, and Analysis Queue collapse independently. Reopening restores the last user size, active tool, selection, scroll, and draft. Persist layout preferences per workspace and investigation contents per document; never transfer FILE selection or live state to an unrelated owner. A narrow window may temporarily constrain restored dimensions without overwriting the saved size. The navigator remains present and its Strings list stays visible, including in focus mode; only optional navigator categories collapse.

Keyboard focus cannot remain in a hidden body. Collapsing a pane moves focus to its collapse control or rail; expanding restores the previous valid focus when possible. Clicking an explicit tool command reveals and focuses that tool. Preserve dirty Types/Notes drafts through layout changes.

The breadcrumb remains visible: document → FILE/LIVE space → verified module/section → function → address. Unknown mappings stay unknown. Pinned representations show a pin indicator and location; unpinned views follow their shared selection within the correct address space. Live pins retire when their exact process/session/module owner changes. Back/forward history remains intact when views switch. Address zero remains a valid location.

| Visual state | Required distinction |
|---|---|
| Selected instruction | Blue accent fill, restrained glow, focus outline/left edge. |
| Current paused RIP | Green execution marker and explicit RIP label; independent of the selected row. |
| Selected branch destination | Violet destination highlight with connecting arrow. |
| Observed trace coverage | Subtle green coverage mark; not a claim that this row is the current RIP. |
| Armed software breakpoint | Filled red marker, with armed status available by tooltip and keyboard. |
| Saved FILE breakpoint, inactive | Hollow marker and saved/inactive label; exact runtime mapping is required before arming. |
| Disabled breakpoint | Muted outlined marker with disabled label. |
| Conditional / hardware breakpoint | Distinct badge or shape and descriptive text, retaining the armed/inactive state. |
| Pending / failed breakpoint | Pending indicator or error badge with the concrete reason; never displayed as successfully armed. |

Breakpoint, prediction, registers, and trace observations belong to an exact debugger target identity. Running views identify values as last captured. “Jump will be taken” is permissible only for the paused current RIP with recognized semantics and current valid registers/flags. For example, a current `jne` with known `ZF=0` may show “Jump will be taken · ZF=0.” For an unsupported instruction or unavailable state, show an unknown/unavailable explanation rather than a guessed outcome. Static activation evidence remains labeled candidate, proven, partial, or unresolved according to its actual evidence; no decorative confidence percentages.

## Keyboard, accessibility, and layout

Preserve existing shortcuts: **Ctrl+K** commands/search; **F5** Continue/Pause; **F11** Step Into; **F10** Step Over; **Shift+F11** Step Out; **Ctrl+F9** Run to cursor; **Alt+Left/Right** back/forward; **Enter** follow target; **B** breakpoint; **X** references; **N** rename; **;** comment. Preserve context-sensitive shortcuts without firing execution actions while text input owns focus. “Step Through” is not a separate existing command; the design uses the established Into/Over/Out names.

Every icon button needs a descriptive accessible name, tooltip, visible keyboard focus, and a hit area of at least 28 × 28 logical pixels. State must be conveyed by text/shape as well as color. Use at least 4.5:1 contrast for ordinary small text and 3:1 for state outlines and focus indicators; disabled controls remain distinguishable without suggesting availability. Preserve readable syntax and selected text in each theme. Reduced-motion preference removes pulsing and arrival animation while retaining a steady glow/focus outline and all state indicators.

Preferred review canvas: **1920 × 1200**. Minimum design QA viewport: **1366 × 800**. At both sizes, preserve readable monospaced instruction rows, the breakpoint/flow gutters, the breadcrumb address, all execution controls, Strings access, and independent collapse controls. Use explicit overflow and flexible pane widths rather than clipped tab labels or overlapping controls. Below the minimum, degrade gracefully with compact controls; do not claim the same density. Verify native DPI scaling independently of CSS/Figma dimensions.

## Release acceptance

- [ ] All ten annotations are visible in the design and have matching native behavior after integration.
- [ ] All nine feature tabs, seven representations, and complete tool inventories remain reachable at preferred and minimum viewports.
- [ ] Pane collapse/restore, resizing, manual navigator expansion, drafts, focus, and per-document navigation survive view and preset changes.
- [ ] Arrow routing, syntax colors, glow, RIP, destination, coverage, and breakpoint states remain distinct in dark/light themes and reduced-motion mode.
- [ ] Real paused x86/x64 sessions verify taken/not-taken/unknown predictions, Into/Over/Out, Continue/Pause, Trace, and breakpoint state transitions; running/stale data is never presented as current proof.
- [ ] FILE/LIVE mapping, ASLR, module unload/reload, process/session changes, address zero, and pin/history behavior pass native regression checks.
- [ ] Native layout, input/focus, accessibility, DPI, and interaction-responsiveness checks pass after integration; design inspection alone is not a release sign-off.

## Verified artifact UI QA

Reviewed the local HTML in the Codex browser at **1920 × 1200** and **1366 × 800** on 7 September 2026. Both layouts retain all nine feature tabs, all seven representations, the execution controls, colored instructions, breakpoint/flow gutters, selection glow, and the inspector. At 1366 × 800, DOM geometry confirmed every feature and representation fits within the viewport and the document has no page-level overflow. The instruction listing scrolls within its pane.

Interaction checks performed on the synthetic fixture:

- Focus code collapses the inspector, detail drawer, and Analysis Queue while keeping Functions and Strings visible. Reopening the inspector leaves the other two panes collapsed.
- Inspector collapse transfers keyboard focus to its visible expand control; expanding returns focus to the collapse control.
- Manually enabling Bookmarks adds the category, and the choice survives a page reload. Functions and Strings cannot be disabled by the navigator customization menu.
- Continue removes the asserted branch outcome and disables stepping. Pausing restores the fixture's valid JNE prediction. FILE mode reports unavailable flags and disables execution controls.
- Selecting the earlier JE reports an unknown outcome, displays its own destination, highlights the correct row, and follows to `1048`. The JMP at `1028` displays its decoded destination at `104A` without asserting observed execution. Running verifier evidence is explicitly labeled as an observation from the previous pause.
- The breakpoint menu changes an armed breakpoint to disabled; clicking its gutter control removes it and updates the displayed state.
- The complete specialist tool inventory is available in the command picker. Searching Path Explorer opens its clearly labeled sample workspace.
- Step Over advances the sample RIP from the JNE at `1018` to its taken destination at `1030`.

The fixture's 23 instruction boundaries and four branch targets were also checked against their encoded bytes; inline JavaScript passed a syntax check. These checks validate the design artifact and its simulated interactions. They do not establish native decompiler accuracy, real debugger execution, native DPI/accessibility conformance, persistence of editor drafts, or shipping readiness. The native acceptance checklist above remains open.

## Native audit references

Source references document retained capabilities, not new implementation claims: `src/App.cpp` (feature tabs at 467, step controls at 4723); `src/Tabs/BinaryViewTab.cpp` (branch evaluation at 640, glow at 1063/9510, breakpoint gutter at 8314/12710, arrows at 9415, syntax at 12356/12863, live controls at 12429, live prediction at 12913, navigator at 18388, drawer collapse at 22158/22222, representation rail at 23478); `src/Tabs/BinaryViewWorkflow.cpp` (presets, pins, breadcrumb). Line numbers reflect the audit and may move during integration.
