# Patch byte restoration — 2026-09-07

- Fixed runtime-original capture for ordinary patches, hot-patch transactions, and revert rollback. These paths now use exact-session breakpoint-masked reads, matching the logical-byte contract of `Debugger::writeMemoryForSession`. Physical debugger `INT3` bytes must never become saved patch originals or rollback payloads.
- Fixed live overlap restoration by composing surviving intersections into the removed patch's runtime-original span before writing. For A covering bytes 0–1, B covering 1–3, and C covering 3–4, reverting A now writes only bytes 0–1; it cannot replay B's tail over C.
- Surviving live patches require both debugger-session and patch-set ownership. A static-only alternative at the same address is excluded; disabling a FILE experiment does not erase a patch already written into the live target.
- Retained runtime addresses, mapping/span validation, paused-session writes, rollback on failure, post-commit identity checks, and ownership retention until successful restoration remain in place. Persisted FILE originals and patch ordering are unchanged.

## Verification

- `tests/run_core_tests.bat live_patch_original_test`: bounded live restoration planning, overlap order and clipping, session/set ownership, FILE versus runtime originals, and invalid spans/mappings.
- `tests/run_core_tests.bat patched_image_test`, `patch_set_test`, and `patch_pristine_test`: FILE image reconstruction and ordered patch restoration.
- `tests/run_static_listing_actions_test.ps1` with `DS_PATCH_RESTORATION_LIVE_TEST=1`: production Binary View and debugger integration. The opt-in fixture launches its own contained child, uses allocated scratch memory, and exercises revert with a breakpoint armed, revert after breakpoint removal, and rollback after a rejected static commit. The target must remain paused with the same thread and instruction pointer throughout.
- Release x64 candidate: `build/x64/PatchRestoration/DisasmStudio.exe`. Build log: `build/patch-restoration-build.log`; integration log: `build/patch-restoration-ui-tests.log`.
- Verification completed successfully: all four focused test binaries passed, the full production-object UI suite passed with zero failures and live restoration enabled, and the Release candidate passed embedded-helper verification. The final rebuild includes only an indentation correction after the tested production build.

## Revert controls and permanent Patches tab — 2026-09-08

- Patches remains a fixed tab in both Debug & data and Analysis tools, including the collapsed rail and empty projects. It stays outside ordinary tab scrolling; clicking its collapsed tab opens the drawer.
- Patch records and their actions precede set management. Set creation, transitions and comparisons remain available through a separately sized, scrollable manager. Patch rows keep Revert visible when byte columns need horizontal scrolling.
- Row selection no longer covers the Revert control. Restoration still uses the exact selected record, ordered FILE reconstruction and checked session-owned LIVE originals.
- Failed restoration preserves the actual failed row and reason. FILE-only failures no longer claim a LIVE rollback, and missing records produce explicit feedback. The patch panel retains the latest action result.
- Production regressions exercise actual mouse input on Revert, compact drawer fit, permanent-tab visibility, unchanged bytes on refused transactions, same-address alternatives and contained-child LIVE restoration with debugger breakpoint overlays.
- Narrow headers allow ordinary tabs to scroll and omit the extra breakpoint shortcut so it cannot squeeze Patches out at high zoom. Native IDs, independent group selections, the Registers handoff and manual collapsed state are preserved.
- Verification: all five focused Core tests passed (`patch_pristine_test`, `patch_set_test`, `patched_image_test`, `live_patch_original_test`, `patch_recovery_test`); logs are under `build/patch-revert-core-review`. Release x64 and embedded-helper verification passed (`build/patch-revert-build.log`).
- The production FILE/LIVE restoration, exact mouse-click restoration, permanent-tab and 90%/150% fit checks passed with zero new failures. The focused release-workbench suite also passed with zero failures (`build/patch-revert-workbench-final.log`). Twelve offscreen DX11 captures were generated under `build/patch-revert-captures`; records and manager views were visually reviewed, including a 420-pixel drawer and the 1366x800 native workbench layout.
- The broader run in `build/patch-revert-tests-reviewed.log` had one unrelated assertion in the concurrently added `execution_history_fixture.inc` (`window->ScrollMax.y > 0`). All patch checks passed in that run. Its 127 production-object snapshots matched the build objects; tested executable SHA256: `A7C5881256ECB7018AF62C46E345A905818759A7F52F5F213B31C3849921A28C`.
