# Peggle — One Zen Shot

A small standalone console for the English Steam Peggle Deluxe 1.01 build. It finds the running `popcapgame1.exe` process, resolves three AOB signatures, and adds one available Zen charge to the current player. The next ordinary shot uses the game's existing Zen path.

## Use

Run `build/peggle_zen/PeggleZen.exe` and open a Peggle level. Wait until the ball is loaded and you can aim.

```text
[1] Give one Zen shot
[2] Check game / rescan
[0] Exit
```

Enter `1`, return to Peggle, and fire. Each successful activation adds exactly one charge; it does not toggle, freeze the value, or repeatedly apply a patch. The console reports the previous and resulting counts. Opening or closing the console does not change the game.

This version supplies the mechanical charge. It does not reproduce the normal green-peg reward sound, floating text, or character-eye animation. It does not change an already flying ball.

The tool is an external x64 EXE reading the x86 game. It does not inject a DLL, call game functions, install jumps, or modify executable bytes or game files.

## Command line

```powershell
.\build\peggle_zen\PeggleZen.exe --check
.\build\peggle_zen\PeggleZen.exe --grant
.\build\peggle_zen\PeggleZen.exe --pid 1234 --check
.\build\peggle_zen\PeggleZen.exe --verify-file 'C:\path\popcapgame1.analysis.exe'
```

`--check` and `--verify-file` are read-only. `--grant` performs one activation and exits. If more than one actual game process is open, select its PID explicitly. The `Peggle.exe` launcher is rejected.

## AOB resolution

Each pattern must occur exactly once in readable executable memory belonging to the main game module. There is no fixed-address fallback. Wildcards cover the global address and relative branch/call displacements; fixed field offsets restrict support to the inspected layout.

| Purpose | Pattern | Decoded operands |
| --- | --- | --- |
| Board getter | `A1 ?? ?? ?? ?? 8B 80 B8 07 00 00 C3` | Absolute app-global slot at match + 1; App → Board displacement at + 7 |
| Object layout | `8B 87 B8 07 00 00 3B C3 74 ?? 8B 80 54 01 00 00 83 78 04 05` | Independent App → Board displacement at + 2; Board → Logic at + 12 |
| Zen shot consumer | `8B 96 28 01 00 00 88 86 A9 00 00 00 39 9C 96 0C 02 00 00 0F 8E ?? ?? ?? ?? 6A 0A 8B CE E8 ?? ?? ?? ??` | Current-player displacement at + 2; Zen-counter displacement at + 15 |

The resulting counter is `LogicMgr + countOffset + 4 * player`. Module-relative vtable identities and object back-links validate the App, Board, LogicMgr, Gun, and loaded Ball. The player index must be 0 or 1, the count must be 0–998, game state must be 1, and the ball must be held with no queued fire flags or timer.

The grant briefly suspends each thread once, verifies ownership and a stable thread list, rechecks the AOB bytes and objects, then uses `ProcessMemorySession` for a verified four-byte write to already-writable non-executable data. The RAII guard balances only this tool's suspends on success or failure. Console-close handling lets that guard resume the game before normal shutdown. Read-only scans do not suspend the game.

## Build and verification

```powershell
.\tools\peggle_zen\build.ps1
```

Requires Visual Studio 2022 C++ tools. The build uses the static MSVC runtime and produces the console plus its focused core tests. It does not rebuild DisasmStudio.

- 26 focused tests cover AOB uniqueness, relocated operands, partial reads, object and player identity, readiness, and exact one-charge plans.
- File verification found one match for each pattern in the recovered analysis EXE.
- Live verification on 2026-09-09 resolved all three AOBs, admitted an aiming state with a held ball, and changed the current player's Zen count from 0 to 1 with read-back verification.
- Gameplay confirmation is recorded below when the fired shot is checked.

Build/test and live verification logs are in `build/peggle_zen/`.
