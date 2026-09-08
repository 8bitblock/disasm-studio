# Memory viewer, assembly byte copying, and value hints

The Memory Tools hex editor supports direct address entry (including `0x`), Back/Forward history, keyboard navigation, ASCII selection, and a typed value preview. The readable-byte count and `??` cells distinguish inaccessible memory from real zero bytes. Reads are split at page boundaries, so an unreadable page does not hide readable bytes in the next page. Address navigation stays within representable addresses and rejects out-of-range input for 32-bit targets.

## Memory Tools controls

- Click or drag bytes/ASCII, or Shift-click, to select a span.
- With the hex/ASCII grid focused, arrow keys move the selection and Shift+arrows extend it. Home/End move within the row; Ctrl+Home/End and Ctrl+A operate on the 256-byte view.
- Ctrl+G focuses the address field. Alt+Left/Right revisit previous locations.
- With the grid focused, Ctrl+C copies exact hex bytes and Ctrl+Shift+C copies an AOB pattern. The copy controls also provide ASCII and the selected address.
- Mark selected bytes as wildcards to replace them with `??` in the AOB output. Marks remain while selecting other bytes and reset on navigation or a process-session change. Unreadable bytes also become `??` in patterns; literal copying requires every selected byte to be readable.
- The value preview supports signed/unsigned integers and floating point, copying the interpreted value, and adding that typed address to the address table.
- Live refresh samples every 250 ms. Changed-byte highlighting compares only bytes valid in both observations.

Byte editing lives in **Edit selected bytes**. Writes must match the complete selection length, cannot contain wildcards, and continue through the existing verified, session-checked writer. Changing the selection clears the write draft.

## Assembly copying

Static Assembly, Live Assembly, and instruction context menus offer **Copy bytes (without wildcards)** and **Copy bytes (with wildcards)**. The focused assembly views use Ctrl+C and Ctrl+Shift+C respectively. Copy operates on the selected instruction or selected rows. Graph and the assembly side view use the shared instruction copy menu.

Automatic wildcards support x86-16, x86 and x64. Zydis encoding offsets identify relative branch operands and absolute/IP-relative memory displacements; these become `??`. Opcodes, register-based offsets, and ordinary immediate constants remain literal. Other architectures still support literal byte copying.

Copying requires complete instruction bytes and is bounded to 64 KiB. Disjoint selected spans are separated by newlines, and a signature scan cannot silently include unselected gaps. A single-row context action copies the displayed instruction snapshot. LIVE keyboard/selection actions re-read exactly the displayed lengths from the captured session and require matching logical bytes before copying. Changed or unreadable instructions preserve the clipboard and request a refresh. Debugger software-breakpoint overlays are removed from these logical bytes.

## Direct memory values

The **Values** toggle adds numeric observations beside direct memory operands, including absolute and IP-relative references. For example:

```text
mov eax, [0x123456]    ; LIVE [0x123456] = 10 (u32, 0x0000000A)
```

FILE Assembly and Graph show loaded file bytes, including applied FILE patches. Live Assembly samples the exact debugger session. Hover shows the signed interpretation and, for 32/64-bit operands, the IEEE floating-point interpretation. These labels describe interpretations of stored bytes; the instruction width does not prove the application's variable type or the result of executing a store.

Only decoder-proven 8/16/32/64-bit memory operands qualify. LEA, bare immediates, unresolved register/index references, and thread-relative FS/GS references do not invent values. A full operand-width read is required; partial reads and unbacked FILE data show **unavailable**. LIVE observations use bounded session-owned caching, a 250 ms refresh interval, and at most 16 new reads per frame. Existing decoder and analyst comments remain present.

## Regression coverage

- `instr_dataref_test`: reference authority, width, address zero/overflow, little/big endian interpretation, signed extremes, floating-point alternatives, and partial reads.
- `instruction_byte_pattern_test`: actual x86 encoding masks, literal constants, selection gaps, malformed/truncated bytes, and unsupported architectures.
- `static_listing_actions_test`, including `memory_value_hints_fixture.inc`: production decoder, numeric hint renderer, comments, FILE updates, and LIVE ownership/cache checks.
- `feature_tabs_ui_test`: production memory viewer navigation, selection/copy, partial page validity, and typed preview.

Verified on Windows with MSVC v143 14.44.35207:

- Fresh and final incremental Release x64 builds passed, including embedded helper freshness verification.
- `instr_dataref_test`, `address_inspector_test`, and `instruction_byte_pattern_test` passed.
- Test manifest validation passed (143 declared tests).
- `feature_tabs_ui_test` passed with zero failures, including actual page-hole reads, clipboard shortcuts, and narrow Light/Midnight layouts.
- Full `static_listing_actions_test` passed with zero failures with `DS_PATCH_RESTORATION_LIVE_TEST=1`. The contained test child verified LIVE values changing from 10 to 11, exact-width reads at an inaccessible page boundary, partial-read rejection, and invalidation after detach. The existing workbench theme/size/scale matrix also passed.
- The rebuilt application passed the five-second startup smoke check.

Logs: `build/memory-viewer-release-build.log`, `build/memory-viewer-release-incremental.log`, `build/memory-viewer-feature-ui-test.log`, `build/memory-viewer-static-ui-test.log`, and `build/memory-viewer-startup-smoke.log`. The executable is `build/x64/Release/DisasmStudio.exe`. This checkout reused an identical-manifest, matching-v143 dependency installation read-only; all production objects were built from the updated sources.
