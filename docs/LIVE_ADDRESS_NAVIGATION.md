# Live instruction navigation after a memory scan

- Fixed the shared Binary View address box and Ctrl+G interpreting unprefixed numeric input as a FILE address while Live Assembly was selected. All three goto controls now use the same routing: bare addresses follow the current view; `FILE:` / `VA:` and `LIVE:` explicitly choose the address space.
- Added exact runtime module expressions such as `Peggle.exe+1234`, `"Peggle.exe"+ABCD`, and `LIVE:"C:\Games\Peggle\Peggle.exe"+1234`. Offsets default to hexadecimal, matching the [module address notation documented by Cheat Engine](https://wiki.cheatengine.org/index.php?title=Cheat_Engine%3AMemory_Scanning). Names match the full basename including the extension, ignoring case; full paths can disambiguate duplicate basenames.
- Module resolution uses the attached debugger's current module snapshot and runtime load base. Missing or ambiguous modules, unknown mapped extents, out-of-module offsets, overflow, and addresses outside a WOW64 target's 32-bit range produce an explicit error. Failed input preserves the cursor and navigation history. It cannot fall through to fuzzy symbol search.
- Kept numeric parsing in the global investigation index unchanged. This fix concerns the address controls in Binary View; a symbol such as `deadbeef` still resolves as a name unless an explicit numeric form is used.
- Clarified Memory Tools' scan-result and address-table navigation tooltip: opening a found value in Live Assembly decodes bytes at that value's storage address. The code that reads or writes that storage has its own instruction address. Use that instruction address from an access/write capture when navigating to code.

## Reproduction and use

1. Attach DisasmStudio to the same process instance used for the memory investigation.
2. Select Live Assembly. Paste the accessing instruction's absolute address into the main address box or Ctrl+G. A prefix such as `LIVE:00401234` also selects runtime navigation from a FILE view.
3. Alternatively paste the exact loaded module name plus its hexadecimal offset, for example `Peggle.exe+1234`. This is an example only; it is not a verified Peggle instruction address.
4. Compare instruction bytes as well as the address. Runtime data addresses and absolute code addresses copied from an earlier process instance may no longer refer to the same allocation or mapping.

## Scope and verification

- The production-object `navigation_workflow_fixture.inc` exercises shared-toolbar/popup routing, prefixes, back/forward history, quoted names, full paths, case handling, remapped modules, duplicate names, malformed input, unknown extents, WOW64 bounds, and 64-bit addition overflow without attaching to a user process.
- The wider UI suite exposed a timing-dependent navigator assertion: an indeterminate progress bar can have no fill vertices at its zero phase. The fixture now observes a bounded animation cycle while retaining its fill-color and placement checks.
- Release x64 build passed with MSVC v143 14.44, including embedded GameMaker helper verification; see `build/peggle-live-navigation-build.log`. The final production-object `static_listing_actions_test` passed with zero failures, including the new navigation checks and existing Midnight/Light workbench checks at 1.0/1.5/2.0 scale; see `build/peggle-live-navigation-tests.log`. The executable is `build/x64/Release/DisasmStudio.exe`.
- The initial report lacked a concrete instruction address or bytes. The later open-session verification below identified the actual cause of the reported signature mismatch; the routing fix remains independently verified.
- Memory Tools does not yet provide a scan-result "find what accesses/writes this value" capture. The existing hardware-breakpoint path lacks structured data-access instruction evidence; a full access-capture workflow is separate work.

## Verified Peggle session — 7 September 2026

- The open DisasmStudio session was attached to `Peggle.exe` PID 13828, the Steam launcher. The visible `Peggle Deluxe 1.01` window belonged to `C:\ProgramData\PopCap Games\Peggle\popcapgame1.exe` PID 40076, whose parent was PID 13828. These PIDs identify this session only.
- The exact signature entered in Sig Scanner was `8B 4D 08 01 8C 86 7C 01 00 00 85 C9 8D 84 86 7C 01 00 00`. A bounded read-only diagnostic with executable-path validation found zero matches in the launcher and exactly one in the game, at `0045D88C`; see `build/peggle-target-diagnostic.ps1`. Neither read encountered a partial chunk or reached the diagnostic's memory budget.
- Detached DisasmStudio from the launcher and attached to the game. Repeating the unchanged signature in the actual application's LIVE scanner returned one match at `0045D88C`, reported under `popcapgame1.exe`, with complete 367.0 MiB coverage.
- Opened the result in Live Assembly and selected `0045D88F`: bytes `01 8C 86 7C 01 00 00`, instruction `add [esi+eax*4+0x17C], ecx`. This confirms the code exists in the game process; it does not by itself identify which gameplay quantity each indexed field represents.
- Resumed the debugger and left the instruction selected for the analyst. No game bytes, values, or breakpoints were changed. The earlier FILE/LIVE routing bug was real, but this live signature failure was caused by selecting the launcher.
- The existing process pickers filter executable basename/PID without showing parent relationships or game window titles. Searching only `Peggle` hides this differently named child; select the actual game PID or `popcapgame1.exe`.
