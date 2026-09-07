# UI zoom and workspace fit

View > UI Zoom scales text, icons, and layout together from 75% to 150%.
The default is 90%; Ctrl+- and Ctrl++ adjust by five percentage points,
and Ctrl+0 restores 100%. Keypad plus/minus are also supported. Zoom commands
are available in Ctrl+K. Text-entry fields and open popups retain keyboard focus.

Windows DPI remains independent. The host rebuilds the font atlas at DPI times
zoom between frames, applies absolute theme metrics, and recreates DX11 device
objects before rendering. A failed recreation stays retryable. Zoom does not
resize the native window or change the Windows display settings.

The strict preferences codec stores `ui_zoom` and validates 75 through 150.
Older preferences inherit the 90% default. Density remains a separate saved
preference; this workspace was changed from Spacious to Compact.

The evidence inspector automatically folds into its existing rail when opening
it would leave less than 760 logical pixels for the central view. Resizing back
restores it without changing its retained width, manual collapse state, or the
independent lower drawer.

Verification on 2026-09-07:

- Release x64 build passed, including embedded helper-resource verification:
  `build/ui-zoom-build.log`.
- `preferences_test` and `ui_widgets_test` passed.
- Production-object `release_workbench_test` passed with zero failures, including
  narrow/wide resize and pane-state preservation: `build/ui-zoom-workbench-test.log`.
- Native UI checked at 75%, 80%, 85%, 90%, 95%, and 100%, using the zoom menu,
  keypad shortcuts and Ctrl+0. Text and layout resize together.
- Restart confirmed the saved 90% zoom and Compact density; the updated app is
  left open with those settings.
- Updated executable: `build/x64/ReleaseUIFinal/DisasmStudio.exe` (identical to
  `build/x64/Release/DisasmStudio.exe`). Previous executable retained in
  `build/ui-zoom-before-20260907-144924/DisasmStudio.exe`.
