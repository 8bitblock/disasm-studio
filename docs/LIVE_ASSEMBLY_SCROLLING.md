# Live Assembly scrolling

- Fixed the upward scrolling wall after following a LIVE string reference near an analyzed function start. The earlier-window request excluded the current function anchor once, but the next idle frame selected that anchor again and discarded the earlier instructions.
- Retain the committed live window's start through idle frames, manual browsing, register changes and content refreshes. Alignment reads and trial decoding now occur when choosing a new window, instead of on every rendered frame.
- Preserve an overlapping instruction's vertical position when the bounded buffer refills. Forward browsing starts from a decoded midpoint and retains half the old rows; backward browsing aligns up to 128 bytes before the old first instruction. Each decode remains bounded to 4 KiB and 256 instructions, with no total browsing-distance cap within contiguous readable memory.
- Focus and refill positioning allow up to three corrections for ImGui's deferred scrolling and frozen-header/cell layout, then retire. New manual input cancels remaining pan corrections. Verification measures actual address glyph positions after settling, rather than assuming every table row has the last row's height.
- Keep the previous extent visible when an edge refill cannot advance or read memory. A later input can retry; a failed candidate cannot silently replace the window on the next frame.
- Read the live decode buffer in page-bounded pieces and verify the debugger session before adoption, so an unreadable next page does not hide valid instructions preceding it.
- Release Follow RIP on manual wheel, keyboard or scrollbar scrolling within the current window. Viewport movement preserves the selected instruction and navigation history; explicitly following the same reference again brings it back into view.
- Reference handoffs retain their existing FILE/LIVE address spaces and debugger-session/module validation. This change does not alter execution or target memory.

## Verification

- The production-object `tests/live_scroll_fixture.inc` exercises the real Live Assembly renderer and checked debugger reads against a contained copy of the test harness. Its synthetic instructions and string occupy a test-owned allocation; it does not attach to an existing user process.
- Set `DS_LIVE_SCROLL_TEST=1` to include the live regression in `tests/run_static_listing_actions_test.ps1`, or `DS_LIVE_SCROLL_ONLY=1` for the focused run. Build Release x64 first so the harness links current production objects.
- Release x64 build and embedded GameMaker helper verification passed (`build/live-assembly-scroll-build.log`). The updated executable is `build/x64/Release/DisasmStudio.exe`.
- Focused live scrolling passed with zero failures and 32 stable refills (`build/live-assembly-scroll-final.log`). It exercises a decoded string reference, more than 2 KiB of backward and 4 KiB of forward wheel browsing, PageUp/PageDown, repeated-reference centering, retained selection/history, the analyzed function-start wall, Follow RIP release, and a real protected-page boundary.
- The full production-object `static_listing_actions_test` also passed with zero failures, including the live scrolling case and existing theme/density/zoom checks (`build/live-assembly-scroll-full.log`). All 126 snapshotted production objects match the final build. The unrelated opt-in live patch-restoration case remained skipped.
- `listing_layout_test` passed (`build/live-assembly-scroll-core.log`), including bounded readable lookback and decoder-boundary helpers. No existing user process was attached or modified during verification; an interactive walkthrough of the user's particular binary was not performed.
