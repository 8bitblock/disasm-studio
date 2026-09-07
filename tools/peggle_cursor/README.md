# Peggle cursor-ball experiment

A separate native helper for the **English Steam Peggle Deluxe 1.01** running as `popcapgame1.exe`. It uses the game's existing mouse-ball implementation. This is an experiment for the user's offline game, not a DisasmStudio scripting/plugin API or a permanent game-file patch.

## Controls

1. Start `build/peggle_cursor/PeggleCursor.exe` while the actual game is open.
2. Choose **Arm**. If no ball has been fired, fire one normally.
3. Click once more anywhere in the playfield. The selected active ball attaches to the cursor without holding the mouse button.
4. Choose **Release**, then click once in the game to return the ball to normal flight. The helper waits for native release before closing while a ball is held.

The final build from this session is `build/peggle_cursor_updated/PeggleCursor.exe`; it was staged separately while the earlier collision-enabled helper remained open. Close the current helper through Release before starting that copy. `--arm` invokes the normal Arm handler after opening. Arm also clears an idle leftover drag-input flag once no ball is selected, so upgrading from an interrupted older helper does not leave shooting disabled.

The helper does not move or click the mouse. After native capture it clears the stationary flag on that exact ball, allowing Peggle's ordinary physics and peg collisions to run while its mouse-ball routine continues following the cursor. Collision response can briefly push the ball away from contact; each game update pulls it back toward the cursor. Large cursor jumps can skip pegs between the old and new positions. It applies to a ball in the current board, and stops moving when the game is paused.

Release before opening menus, replaying, or quitting. Peggle serializes its held-ball flag; this experiment does not establish how every save/replay path handles a ball left in that state.

## Native implementation and provenance

The [Thunderball decompilation](https://github.com/teampopwork/Thunderball) explicitly targets this game version. Its [DebugMgr implementation](https://github.com/teampopwork/Thunderball/blob/main/source/Thunderball/DebugMgr.cpp) identified existing mouse-ball behavior. Those addresses and instructions were independently decoded from the user's running game before the experiment.

- `DebugMgr::SetMouseBall`, `0043E4E0`, updates the game's intrusive reference ownership and held-ball flag. The helper never writes a ball pointer or reference count itself.
- `DebugMgr::UpdateMouseBall`, `00439AB0`, uses the game's mouse coordinates and synchronizes ball position, rendered position, and bounds. Zero mouse offsets put the ball directly on the cursor.
- During capture only, the radius-rejection branch at `004400C8` changes from `75 08` to the two-byte NOP `66 90`, allowing the next click to select the nearest active ball. The mouse-up branch at `0043E524` changes from `74 0C` to `EB 0C`, so that click's release cannot immediately discard the captured ball.
- After native capture, the helper retains the exact selected ball identity, disables the drag-input flag, sets the offsets to zero, and clears only that ball's stationary byte at `+140`. Both capture code sites are restored. There is no global collision patch: `Ball::Update`, `DoCollideUpdate` and `DoBallCollision` retain their original instructions.
- Live disassembly confirms `Board::Update` calls `DebugMgr::Update` through `00402AD0` before `Board::UpdateObjects` (`00410AE0`) invokes the regular collision manager. Peggle's mouse-ball routine does not reassert the stationary flag.
- Release verifies the retained native pointer, restores its stationary flag so click selection skips that ball, and enables the original input handlers. The game's native setter clears the flag and reference on release. A removed ball is retired through native release; the helper does not write old scene objects after ownership changes.

The app/board/debug-manager chain, object types, live process identity, and expected original code bytes are validation inputs. The byte patches are temporary in-process edits, with thread suspension around checked installation/restoration. Game files are not edited.

## Build and investigation

Run `tools/peggle_cursor/build.ps1` using the installed VS2022 C++ toolchain and repository vcpkg libraries; `-ProbeOnly` builds just the diagnostic. The read-only `probe.exe` uses DisasmStudio's ProcessMemorySession and Zydis decoder for narrow `state`, `pegs`, `read`, and `disasm` inspections, plus a bounded candidate scan. `probe PID state` reports current ball ownership and game mouse coordinates without modifying the process. `pegs` traverses the checked, bounded board object list and reports each `PegInfo+14` hit flag, allowing collision verification through actual false-to-true changes.

The original drag-only version was built with VS2022 `/W4` without diagnostics and exercised against PID 20464 on 7 September 2026. Native capture produced a reference count of 3 and exact mouse-relative positions; native release returned it to 2, cleared the held flag, restored original raw offsets, and resumed movement. Both code sites were verified as original after capture. That established reversible capture/release, but the original version deliberately skipped collisions and is superseded by the active-ball behavior above.

- Collision-enabled live verification used the restarted process PID 27956, creation identity `134332578164322216`. The captured ball `12C2A018` remained referenced by the native debug manager with `+140=0`, active-list membership, and reference count 3 while the user moved the cursor.
- Exact object/PegInfo pairs showed **58 false-to-true hit transitions**, increasing from 40 to 98 hit pegs. Evidence: `build/peggle_cursor/pegs-new-session-before.txt`, `pegs-new-session-after.txt`, and `verified-new-hits.txt`. This establishes real game collision effects, not just drawing the ball over pegs.
- The first ball subsequently left the active list and entered native release. A later capture of `12C2B998` again had active-list membership and `+140=0`; both temporary instruction sites still contained original bytes `75 08` and `74 0C`. These addresses are observations from that process, not durable ball pointers.
- The final source, including idle-mode normalization, compiled cleanly with `/W4` to `build/peggle_cursor_updated`; log `build/peggle_cursor/build-collisions-final.log`. The main collision behavior was live-verified; the final idle-flag upgrade branch was reviewed and compiled but was not separately exercised against a leftover flag in the restarted game. Build that separate output with `build.ps1 -BuildFolder peggle_cursor_updated`.
