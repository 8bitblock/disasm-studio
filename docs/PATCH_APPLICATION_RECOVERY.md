# Patch application, saved recovery, and encoding

Patch application continues to use the checked `PatchSet`/`PatchedImage`
composition. Global record order, pristine originals, conflicting enabled-set
overlap rejection, exact debugger-session ownership, and live rollback remain
the transaction boundaries.

`Core/PatchRecovery.h` owns saved selection recovery. It builds and validates
the complete selection privately before the normal document commit. Validation
or commit failure retains every record, including disabled records, and leaves
recovery pending on the exact pristine image revision. Retrying after an
unrelated image mutation is refused. Pending state is session-only: the saved
ordered records remain ordinary project data and are revalidated on reopening.

The Patches tab displays the retained records as pending, shows the failed row
and reason, and offers **Retry saved patch recovery**. **Forget record** removes
only the selected unapplied record and retries the complete remaining selection.
Other patch application, reversion, set transitions, and hot patches are blocked
until recovery succeeds. Pending records do not appear as applied Hex or
inspector bytes, or contaminate the active analysis digest. Save Binary As also
refuses a pending selection. Recovery failure itself does not dirty the project
or replace its saved records with an empty list.

The assembler, patch compiler, popup preview, selection NOP actions and padded
application pass a complete `DecoderConfig`. Keystone receives ARM/Thumb mode,
byte order and ARMv8 mode. Unsupported combinations fail explicitly, including
big-endian x86 and M-class assembly (Keystone cannot enforce that restriction).
The fixed NOP encoder supports little- and big-endian A32/Thumb/A64 instructions;
Thumb reverses bytes within each halfword. Padding rejects partial alignment
units and preserves its input on failure. Engine and encoded-buffer ownership
are managed automatically, including failed or empty assembly results.

Regression coverage:

- `patch_recovery_test`: retained invalid disabled records, no prefix commit,
  repeated failure, JSON preservation, explicit exact-row removal, ordered
  overlapping recovery, failed commit/retry and stale-image refusal.
- `assembler_encoding_test`: actual Keystone output and patch compiler routing,
  byte-order-aware NOP/padding, unsupported machine settings, malformed/empty
  assembly and unchanged inputs on rejected padding.
- `static_listing_actions_test`: production Binary View recovery and refusal
  paths, project mirroring, explicit forget/retry and big-endian A32 padding.

The existing patch composition, pristine-original, live restoration and patch-set
tests continue to cover transaction behavior independently of the new recovery
state.
