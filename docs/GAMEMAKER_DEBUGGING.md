# Debugging Nubby's GML bytecode

DisasmStudio can stop before a GML instruction, step into/over/out of scripts,
inspect named variables, and edit validated numeric values while paused. Saved
breakpoints and watches resolve from archive/code/variable identities when the
game restarts; they do not depend on a remembered heap address or an AOB scan.

## Connect and stop

1. Start Nubby normally. In DisasmStudio, open the installed game's `data.win`
   using **File > Open**. The default Steam location is
   `C:\Program Files (x86)\Steam\steamapps\common\Nubby's Number Factory\data.win`.
2. In **Communications > Processes & Attach**, attach to `NNF_FULLVERSION.exe`.
   If attachment activates its native image document, select the `data.win`
   document again in the document strip.
3. Open **Communications > GameMaker / GML** and select **Start GML debugging**.
   Setup runs asynchronously. The connection displays build/layout validation
   and supported capabilities; a mismatched runner/archive is rejected.
4. In **Binary View**, open the lower **GML** panel. Choose **Scripts / code**,
   filter a script name, and select **Set BP**. Clicking its name opens its
   bytecode listing. **B** at a validated instruction toggles a symbolic GML
   breakpoint. It never inserts an x86 `0xCC` into archive bytecode.
5. Let the script execute, or use **Pause GML** to stop at the next observed
   instruction. The **Breakpoints** view shows saved intent and live binding
   status. A script such as `scr_GiveMoney` stops only when the game calls it.

The toolbar's **Native / GML** selector makes the execution domain explicit.
In GML mode, **F5** pauses/continues, **F11** steps into, **F10** steps over, and
**Shift+F11** steps out. Over follows the original frame through calls; Out waits
until that frame is left. For a top-level event without a GML caller, Out stops at
the next verified GML boundary after the event leaves the active chain. A native breakpoint is a separate native pause and
provides no GML variable-edit authority.

## Inspect, edit, and save watches

- **Live frames** selects a verified frame. **Live variables** shows its locals,
  globals and instance values, including type/storage and completeness status.
- **Live instances > Inspect** selects an instance from the checked registry.
  Multiple instances of the same object are not silently treated as one object.
- Use **Edit** beside an available canonical numeric value, enter the new value,
  and select **Apply**. The debugger verifies the current pause, storage owner,
  type/tag, range and readback. It preserves the existing numeric type and
  metadata. Continuing or changing inspection invalidates an old edit dialog.
- Right-click a named live value for **Save global watch**, **Save unique-object
  watch**, **Watch this instance (session)**, or **Watch this local (frame)**.
  The **Watches** view shows the value or the precise unresolved/ambiguous status.
  Global and unique-object watches are saved in the project; instance and local
  watches expire with their session or frame. An ambiguous object watch offers
  explicit instance selection.
- **Inspect address in Memory Tools (session)** hands off the current resolved
  address with its process/session identity. Generic memory-table files retain
  their existing format; this handoff does not make a raw address restart-stable.

Project sidecars are version 5 and retain versions 1–4 compatibility. Save intent
through the normal project workflow, then reopen the same archive, attach the
restarted game and start GML debugging again. No heap pointers or write authority
are restored from the sidecar.

## Stop and supported scope

**Stop GML debugging** disables stops, restores verified owned hook bytes, resumes
pending GML callbacks and attempts a checked asynchronous unload. Native detach
also cleans up. If callback draining cannot be proved, an explicitly disabled
mapping remains until the game exits. A setup failure before loading a helper can
be cleared with **Stop GML debugging** and retried within the native attachment.

The first compiled live adapter supports the installed x64 Nubby build 25109973:

- `NNF_FULLVERSION.exe` SHA-256:
  `5664918EA125B0D1D763D51FE84CE10EF974DAB8DED1014026FFDA69FB433F1E`
- `data.win` SHA-256:
  `B00A69FBE77812E6CAFF3AA0250C16D24D1E16E9C70CD563BD69ECA27506B982`

Other archives may be browsed when their format is understood. Other live runner
builds require a verified compiled adapter. Unknown bytecode remains visibly
unsupported. Packed operand-stack values, computed properties and complex-value
edits are unavailable; there is no GML source reconstruction, YYC debugger or
public scripting/plugin API in this version.

Distribute **DisasmStudio.exe** alone. Its helper is embedded, checked and extracted
to a private cache when needed. The game executable and archive remain unchanged.

See [implementation and acceptance evidence](GAMEMAKER_IMPLEMENTATION.md) and
[verified runner layout](GAMEMAKER_RUNNER.md) for development details.
