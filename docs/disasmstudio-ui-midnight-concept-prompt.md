# DisasmStudio Midnight UI concept prompt

Generated with the built-in ImageGen tool on 2026-08-30.

```text
Use case: ui-mockup
Asset type: project design reference for a Windows desktop application, one 16:9 landscape screen

Primary request: Create one polished, production-ready main-window UI mockup for “DisasmStudio”, a fast GPU-accelerated reverse-engineering workbench and live debugger. Show a single fixed Windows desktop window, straight-on, filling the canvas. This must look like a real shippable engineering tool, not concept art.

Scene/backdrop: only the application window; no desk, device frame, browser chrome, wallpaper, floating dialogs, detached panels, docking handles, or overlapping windows.

Style/medium: crisp realistic desktop product UI inspired by modern Dear ImGui tooling, refined and highly legible. Midnight dark graphite/navy palette: near-black navy canvas, slightly lighter panels, subtle one-pixel steel separators, soft 5–6 px corner radii. Cyan-blue active/accent state, green execution coverage, amber heuristic findings, red breakpoints, restrained violet jump accents. Clean compact sans-serif UI font and a crisp aligned monospace code font. Minimal gradients, subtle depth, no excessive glow.

Composition/framing:
- 1920×1080-style 16:9 full application screenshot.
- At top, a slim title/menu band with “DisasmStudio” and menu labels “File”, “View”, “Debug”, “Help”.
- A browser-style document strip with active tab “sample.exe”, inactive tab “network.dll”, and a small “+” button.
- A compact debugger toolbar with icon-and-text controls “Continue”, “Step Into”, “Step Over”, “Step Out”, “Trace”, plus an address field “0x140001000”.
- Directly below, a fixed full-width workbench tab-card strip with exact labels “Projects”, “Communications”, “Sig Scanner”, “Binary View”, “Memory Tools”, “Binary Diff”, “Binary Tech”, “Cortex”, “Prism”. Make “Binary View” active with a cyan-blue accent and the small subtitle “sample.exe”.
- In the Binary View, show mode tabs “Assembly”, “Pseudocode”, “Hex”, “Graph”, “Call Graph”, “Live Assembly”; “Assembly” is active.

Main content:
- Use about 72% of the upper workspace for a dense but readable x64 assembly listing. Column headers: “Address”, “Bytes”, “Instruction”, “Comment”.
- Include realistic aligned rows: “push rbp”, “mov rbp, rsp”, “sub rsp, 40h”, “lea rcx, [rip+config_path]”, “call ReadFile”, “test eax, eax”, “je loc_140001048”, “call parse_header”, “add rsp, 40h”, “pop rbp”, “ret”.
- Show a function divider “read_config” and a small amber “guessed” badge.
- Highlight one selected row in muted blue, one red breakpoint dot in the gutter, several thin green executed-address markers, subtle control-flow guide lines, and concise readable comments including “reads data from a file” and “branch if operation failed”.
- Make the code the visual hero: crisp, aligned, believable, and spacious enough to scan.

Right side panel:
- One fixed panel with tabs “Bookmarks”, “Functions”, “Strings”; “Functions” active.
- Search field labeled “Filter functions”.
- Function list with addresses and these exact names: “start”, “read_config”, “parse_header”, “decrypt_data”, “j_ReadFile”. Use tiny restrained confidence/status accents.

Bottom inspector:
- A fixed lower pane with exact tab row “Breakpoints”, “Registers”, “Threads”, “Call Stack”, “Functions”, “Watch”, “Notes”, “Results”, “Patches”, “Imports”, “Resources”, “Hotkeys”.
- “Breakpoints” active. Show a short table with headers “Address”, “Condition”, “Hits” and two credible breakpoint rows.
- Bottom status bar: “x64  •  PE32+  •  Paused  •  sample.exe”.

Constraints: fixed single-window layout; practical information density; tight 8 px spacing system; sharp small icons; clear hierarchy; excellent contrast without neon excess. Render supplied interface labels exactly and only once where specified. No fake corporate logo, watermark, random large text, illegible microcopy, sci-fi decoration, matrix-green styling, giant cards, charts, source-code editor aesthetics, browser URL bar, or macOS traffic-light buttons.
```
