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
