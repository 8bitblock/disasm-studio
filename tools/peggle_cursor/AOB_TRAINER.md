# Peggle AOB trainer recipe

This AOB Forge version-3 profile targets the verified English Steam Peggle Deluxe 1.01 `popcapgame1.exe` code. It resolves executable instruction signatures and changes the native routines that operate on each current ball; no heap address is embedded.

Status: instruction bytes and branch targets inspected against the running game; signatures independently checked where noted in the session. This complete six-patch trainer group has **not been live gameplay-tested**. The earlier standalone helper's cursor/collision behavior was live-tested, but it uses a different capture lifecycle. This profile is a reviewable trainer recipe, not a claim that the group has passed that same test.

## Use

1. Release any ball in the standalone helper and close that helper, or start a fresh game process. Start from restored game code and normal mouse input; force-closing an older helper can leave the native drag-input flag enabled. This profile does not normalize that leftover data flag. Do not combine these patches with the helper's capture patches.
2. Import `peggle-aob-trainer.json` in AOB Forge and target `popcapgame1.exe`.
3. Resolve **Cursor ball + collisions**. All six patches must resolve uniquely with their expected original bytes.
4. Enable it, fire normally, then click again to select the moving ball. Later clicks can reselect an active ball. The native setter initializes each selected ball with physics enabled and the native update follows the cursor.
5. To stop following: first turn **Cursor ball + collisions OFF**, then turn **Release AFTER turning cursor mode OFF ON**, click once inside Peggle's uncovered playfield, and turn the Release feature OFF.

Turning the main group off restores its code, but the game's native mouse-ball reference can remain selected. The separate Release feature is required for cleanup; it forces the native mouse-up handler to release that reference. Do not enable the main and Release groups together: their mouse-up patch spans overlap. Release before menus, level changes or quitting. Native physics can push the ball away during contact, and cursor jumps can skip intervening pegs.

## Patch entries

AOB Forge offsets below are decimal bytes relative to the pattern match. The profile uses small replacement payloads with exact original-byte guards. Equivalent full old/new patterns are shown for trainers with two AOB text fields.

### 1. Select a moving ball from anywhere

Observed pattern address: `004400C1`. Offset: **7**. Replacement payload: `66 90`.

```text
Old: D8 D9 DF E0 F6 C4 01 75 08 D9 5D FC 89 75 F8 EB 02 DD D8
New: D8 D9 DF E0 F6 C4 01 66 90 D9 5D FC 89 75 F8 EB 02 DD D8
```

### 2. Keep capture after mouse-up

Observed pattern address: `0043E520`. Offset: **4**. Replacement payload: `EB 0C`.

```text
Old: 80 79 04 00 74 0C 6A 00 E8 B3 FF FF FF B0 01 C2 0C 00 32 C0 C2 0C 00 CC
New: 80 79 04 00 EB 0C 6A 00 E8 B3 FF FF FF B0 01 C2 0C 00 32 C0 C2 0C 00 CC
```

### 3. Enable native capture without a data-address write

Observed pattern address: `0044B4EC`. Offset: **4**. Replacement payload: `66 90`.

```text
Old: 80 7E 04 00 74 53 DB 45 08 83 EC 08 8B CE D9 5D 0C
New: 80 7E 04 00 66 90 DB 45 08 83 EC 08 8B CE D9 5D 0C
```

### 4. Preserve ordinary shooting when no moving ball exists

Observed pattern address: `0044B510`. Offset: **18**. Replacement payload: `74 21`.

```text
Old: E8 FB 4A FF FF 50 8B CE E8 C3 2F FF FF 8B 46 08 85 C0 74 18
New: E8 FB 4A FF FF 50 8B CE E8 C3 2F FF FF 8B 46 08 85 C0 74 21
```

### 5. Center the ball on the cursor

Observed pattern address: `0044B524`. Offset: **0**. Replacement payload: `C7 46 0C 00 00 00 00 C7 46 10 00 00 00 00 66 90 66 90 66 90 66 90 66 90`.

```text
Old: D9 80 EC 00 00 00 D8 65 08 D9 5E 0C D9 80 F0 00 00 00 D8 65 0C D9 5E 10
New: C7 46 0C 00 00 00 00 C7 46 10 00 00 00 00 66 90 66 90 66 90 66 90 66 90
```

### 6. Keep physics and collisions active on each capture

Observed pattern address: `0043E500`. Offset: **12**. Replacement payload: `00`.

```text
Old: 8B 36 85 F6 74 07 C6 86 40 01 00 00 01 5E 5D C2 04 00
New: 8B 36 85 F6 74 07 C6 86 40 01 00 00 00 5E 5D C2 04 00
```

### Release after main mode is off

Use the same original mouse-up pattern as entry 2, offset **4**, with replacement `66 90`. This executes native release on the next real mouse-up instead of skipping it. Disabling Release restores `74 0C`.

## Validation boundary

The profile was loaded successfully by AOB Forge's actual `forge::loadProfile` implementation, compiled from the installed trainer's source: six main patches and one release patch. Log: `build/peggle_cursor/aob-profile-validation.log`. Exact signature scans found one match for the new gate, null-result, centering and setter patterns; the existing patched capture-site patterns also matched once. These were read-only checks, not activation of this trainer group.

The new centering block uses two `mov dword ptr [esi+offset],0` instructions and five two-byte NOPs, exactly replacing 24 bytes with balanced stack/x87 behavior. The null-ball branch changes its target to the existing false-return epilogue, allowing the normal first shot. The collision patch changes the setter's immediate from 1 to 0, so it applies to future native captures regardless of the new ball's heap address. No scripting/plugin API was added to DisasmStudio or AOB Forge.
