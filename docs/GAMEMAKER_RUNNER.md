# Exact Nubby x64 runner adapter

This adapter was derived from the installed executable and validated against the
running game on 5 September 2026. It is deliberately identified by the complete
executable SHA-256, not a guessed GameMaker version or an instruction signature.
The installed executable and `data.win` were never modified. Native probes used
temporary debugger-owned process breakpoints, restored before detach.

## Identity and scope

| Field | Observed value |
|---|---|
| File | `NNF_FULLVERSION.exe`, 7,888,896 bytes |
| SHA-256 | `5664918ea125b0d1d763d51fe84ce10ef974dab8ded1014026ffda69fb433f1e` |
| PE | AMD64, preferred base `0x140000000`, image size `0xa6f000` |
| Steam build | `25109973` |
| Archive | `data.win`, 69,017,884 bytes, WAD bytecode 17, 2,858 CODE records |
| GEN8 prefix | `01 11 00 00`: debugger disabled, bytecode 17 |

The file version `1.0.0.0` describes the game, not the runtime. GEN8's stored
major/minor version also does not identify this runner. CODE/VARI/FUNC and actual
VM dispatch prove this target is interpreted; the existence of `data.win` alone
would not prove that for a different GameMaker application.

`GameMakerRunner.{h,cpp}` contains independent, checked projections. It does not
call internal runner functions and does not include code copied from UndertaleModTool
or YYToolkit. Those projects have GPL-3.0 and AGPL-3.0 licensing respectively; use
them as separately reviewed format references, not implicitly compatible source.

The initial adapter supports the normal interpreter. A non-null debugger object
at image RVA `0x749768` selects a different built-in IDE debugger interpreter and
is refused. YYC code (`CCode+0x90` non-null) is refused. No protocol or release
attach support is inferred from the runner's built-in debugger strings.

## Native instruction boundary

`Code_Execute` at RVA `0x272850` routes VM code to context constructor `0x2857f0`,
which calls the normal interpreter `0x285c60`. The alternative debugger interpreter
starts at `0x286010` and has not been approved for instrumentation.

| Site | Original bytes | State |
|---|---|---|
| `0x285c60` | `48 89 54 24 10` | Interpreter entry, RCX=context, RDX=result RValue pointer; first prolog instruction |
| `0x285e16` | `89 8b 9c 00 00 00` | Pre-op dispatch, RBX=context, ECX=root byte offset, RDI=packed operand top, R11=next handler |

The dispatch instruction stores the current PC in `ctx+0x9c`. It is followed by
the opcode read from `ctx+0x50+ECX`, instruction-length calculation, advance of
`ctx+0x8c`, and `call r11` at `0x285e58`. The prior handler has returned and its
operand-stack result has been installed in RDI. Any required operand-buffer growth
and relocation completes before this site. This is a pre-instruction boundary,
not a stop in the middle of an opcode's side effects.

The handler ABI is `(encodedWord, packedSP, operandBytes, context)` in
`ECX/RDX/R8/R9`, returning packedSP in RAX. The stack is packed according to operand
type: it is not an array of 16-byte RValues. Do not enumerate arbitrary SP memory
as tagged variables.

Both displaced instructions are non-relative and can be replayed exactly. A
dispatch detour must preserve every GPR, flags, MXCSR, x87/SSE state and any enabled
extended state touched by its path. R11 is live across the hook. Ordinary C++ ABI
preservation of nonvolatile registers is insufficient. The helper must not wait
for an ACK, invoke the game, allocate, or take a loader lock while a debugger-held
private exception freezes the process.

The interpreter entry hook provides an incarnation for each native invocation.
Context/stack addresses are reused across events; `(context, Code, PC)` cannot
distinguish two event invocations. Logical nested-call identities additionally
need invocation tracking rather than depth alone.

### Relay unwind

The original runtime function is `[0x285c60,0x286007)`, unwind RVA `0x68ad20`.
Original unwind bytes (including padding, before handler data):

```
19 1c 09 00 1c 01 8a 00 15 f0 13 e0 11 d0 0f c0
0d 70 0c 60 0b 30 00 00
```

At dispatch, RSP equals entry RSP minus `0x488`: seven pushes
`RBX,RSI,RDI,R12,R13,R14,R15`, followed by `sub rsp,0x450`. A near relay entered
from this body needs body-state unwind metadata, with prolog offsets normalized
to zero and without transplanting original exception-handler scope tables:

```
01 00 09 00 00 01 8a 00 00 f0 00 e0 00 d0 00 c0
00 70 00 60 00 30 00 00
```

This is `kNubbyDispatchRelayUnwind`. The entry relay is leaf state before the
first original instruction; it must not use this body-state record. Register
helper/relay function tables before installing any detours and retain their
storage until quiescent removal. The normal interpreter has exception landings
at `0x285f2d` and `0x285fed`; a local catch must not invent a new entry incarnation.

## Runtime data projections

All offsets below are for the exact adapter only. Validate bounds, vtables,
root byte extent, code index/name/archive identity and pointers before publication.
The compiled reader functions fail closed on invalid bounds. Heap code operands
are resolved by the runner; they are not byte-for-byte identical to disk operands.

| VM context offset | Field |
|---|---|
| `0x08` | Native/reentrant parent context pointer |
| `0x10`, `0x88` | Operand buffer pointer and capacity |
| `0x20` | Locals YYObject pointer, possibly absent/unmaterialized |
| `0x28`, `0x30` | Self and other objects |
| `0x38` | Active CCode pointer |
| `0x40`, `0x48` | Canonical RValue argument array and count |
| `0x50` | Shared root bytecode base |
| `0x58` | Current logical call-record anchor |
| `0x60` | VM bytecode blob |
| `0x8c` | Current/next root byte offset |
| `0x94` | Logical call depth inside this context |
| `0x98` | Root bytecode byte length |
| `0x9c` | Last dispatched byte offset, written at hook site |

`CCode` has vtable RVA `0x633800`, blob pointer at `+0x68`, name char pointer
at `+0x80`, CODE index at `+0x88`, YYC descriptor at `+0x90`, root-relative entry
at `+0x9c`, local count at `+0xa0`, argument count at `+0xa4`. The blob stores byte
length at `+8` and bytecode pointer at `+0x18`. A child CCode can share its parent's
blob; retain active codeIndex plus canonical root parentIndex and root-relative PC.

### Logical frames and returns

Script-call setup `0x282690` often reuses the same context. It pushes a `0x78`-byte
record, changes the active Code/locals/PC, and increments `ctx+0x94`. Explicit RET
`0x284340` and implicit return/unwind `0x284670` restore that record and decrement
the depth. A record's fields are:

| Offset | Saved caller field |
|---|---|
| `0x00` | Magic `0xaabbccdd` |
| `0x04` | Return-continuation PC (after the call) |
| `0x0c` | Argument count |
| `0x10` | Previous anchor distance from operand buffer end; root sentinel `-1` |
| `0x18` | Argument-array distance from operand buffer end |
| `0x20`, `0x28` | Self, other |
| `0x30`, `0x38` | CCode, bytecode blob |
| `0x50` | Code-name pointer |
| `0x60` | Local object |

Walk exactly logicalDepth records before the root sentinel, then the native
parent chain. Buffer growth relocates raw pointers; buffer-end distances remain
the stable frame anchor within one invocation. Saved caller PC is a continuation,
not its call instruction and can equal code length. To display the call location,
find the preceding validated archive instruction and prove it is a call ending at
that continuation. Otherwise report an unavailable/partial ancestor location.

### Materialized variables

Locals, global object and instance members share YYObject storage. Ordinary
YYObject vtable is RVA `0x5e3340`; CInstance vtable is `0x5e32f0`. `object+0x48`
points to the variable hash map. Its header has capacity/count/mask at `+0/+4/+8`
and entries pointer at `+0x10`. Each 16-byte entry holds canonical RValue pointer
at `+0`, runtime variable ID at `+8`, signed hash at `+0xc`. Live entries have
positive hash, equal to `(runtimeID+1)&0x7fffffff`; absent/tombstone entries are
not values. Static lookup `0x19f30` and local load `0x27e72c` confirm this storage.

An optional direct RValue array exists at object `+8`; do not materialize it or
call fallback lookup `0xeb1b0`, which allocates missing members. The installed
target uses the map path for the observed values. Read only existing map slots.

Global object pointer is at image RVA `0x76ca40`. CInstance has type `+0x7c == 1`,
raw numeric instance ID at `+0xbc`, object asset index at `+0xc0`; the builtin
getters at `0xa8da0` and `0xa8f00` prove these offsets. Structs/method self objects
are not CInstances. Raw instance IDs/pointers alone do not prove a persistent
incarnation; retain session/stop scope unless lifecycle tracking proves reuse.

Runtime variable IDs are not archive VARI indices or stored VarID fields.
With modern flag at `0x75981b == 1`, runtime names are `char**` at `0xa1d970`,
count at `0xa1d968`, static-name extent at `0xa1d96c`. For represented static IDs,
name is `names[runtimeID-100000]`. Match this exact name and scope to archive
records. IDs outside that static extent use another dynamic-name map and remain
unresolved in this first projection; never guess a name/index.

RValue layout is payload `uint64`, flags `uint32`, tag `uint32` (16 bytes).
Real tag 0 and Boolean tag 13 use IEEE float64 payloads; Boolean true was observed
as `0x3ff0000000000000`. Tags 7/10 represent int32/int64. Strings, arrays, object
references and asset references remain opaque. Numeric writes must preserve the
exact tag/flags, revalidate the full canonical slot under the same held debug
event, write payload bytes only, verify readback, and revoke authority on resume.

### Complete instance registry and allocation incarnations

The raw-ID registry is the 16-byte global at image RVA `0x73dad0`: bucket-array
pointer at `+0`, uint32 mask at `+8`, uint32 count at `+0xc`. There are mask+1
16-byte buckets containing head/tail node pointers. Each 32-byte node contains
previous/next pointers at `+0/+8`, uint32 raw instance ID at `+0x10`, and CInstance
pointer at `+0x18`. Lookup `0x26c80` hashes with `ID & mask`; insertion `0xea030`
appends a node and increments the global count at `0xea0f3`; removal `0xea100`
unlinks and decrements it. Initialization `0x20e0` allocates and zeros 512 buckets.
Full cleanup `0xf5d70` traverses all buckets and destroys their instances.

This registry includes active and deactivated instances. The registered builtin
`instance_deactivate_all` (`0x1c7250`, registration `0x1cb994`) sets instance
flags `+0xb8` bit 1. Routine `0x1196f0..0x119980` moves the same allocated instances
between current-room active list (`room+0x88/0x90/0x98`, head/tail/count) and
inactive list (`room+0xa0/0xa8/0xb0`) without changing the registry. Both lists use
instance next/previous at `+0x1a0/+0x1a8`. The current-room pointer is at `0x9fc478`.
Therefore enumerating just the active room list would omit still-live instances.

`EnumerateGmlRunnerInstances` is an allocation-free bounded reader. It validates
bucket head/tail agreement, every previous link, ID bucket selection, instance
vtable/type/raw ID, exact final count, and an unchanged registry header. Its
caller supplies a visitor and record budget (maximum 65,536). A read failure,
malformed chain or count disagreement cannot produce a complete result. A
visitor/budget stop explicitly reports truncation. The caller must already hold
the target at a verified VM boundary; matching header reads alone are not thread
synchronization. Enumeration fixtures cover collisions, truncation, cycles,
backlinks, stale object IDs and count/tail disagreements. This registry projection
was derived statically and still requires a production held-stop live check.

Raw IDs are not allocation incarnations. Ordinary creation `0x117c50` increments
counter `0x76c834`, but cloning (`0xed440`, store `0xed49a`) and deserialization
(`0xf1a20`) copy supplied IDs. Heap addresses and the internal GC slot at `+0x78`
are also reused. Session watches must therefore use a helper-owned monotonic
token for each allocation lifetime, scoped to the helper/session generation.

The shared CInstance constructor is `0xeccd0..0xed05e`; RCX is the allocation
address and its first instruction is the five bytes `48 89 5c 24 10`
(`mov [rsp+0x10],rbx`). The destructor is `0xed0a0..0xed204`; RCX is again the
allocation address and its first instruction is `48 89 5c 24 08`. Both are leaf
state at entry before their first prolog instruction, so an entry relay uses
leaf unwind state, with the same full native-state preservation as interpreter
entry. The destructor retires the GC slot at `0xed17d` and ends in the base
YYObject destructor. Constructor callers allocate `0x208` bytes; construction
sets the instance vtable, raw ID, object asset, GC slot and type before return.

Lifecycle gates need only record RCX: constructor entry starts a fresh monotonic
token, destructor entry retires it. They must not project uninitialized fields,
call runner functions or raise host stop events. Assign tokens to preexisting
allocations when first observed after both hooks are installed. Deactivation,
registry removal and object-type changes do not by themselves start a new
allocation lifetime. If the bounded token table loses coverage or overflows,
invalidate affected session-instance bindings instead of silently reusing an
old token. These two hook sites are exported in the exact profile and covered by
`ValidateGmlRunnerImage`; actual lifecycle hook/reuse behavior requires live
production validation before advertising incarnation safety.

### Frozen host inspection

`GameMakerInspection` reads the committed helper lifetime table and enumerates
the registry again while the authenticated Win32 event is held. It refuses odd
or unpublished lifetime entries, duplicate addresses/tokens, destroyed/recreated
snapshot owners and changed table contents. It never calls the runner or writes
target memory. The limits are 16,384 lifetime entries, 4,096 registry instances,
131,072 map-entry reads per projection and 1,024 displayed numeric slots.

An explicit object selection projects every matching instance; an instance
selection uses its session allocation token. Prior inspected domains are rebuilt
from their current canonical maps under the same event, so several named object
watches can remain visible together. The newly requested domain gets capacity
first. Globals and frame locals are retained. Per-instance availability and
selected-domain completeness remain separate from registry completeness.
Unknown names, missing maps, bad counts and budget/slot exhaustion do not grant
complete coverage. Persistent unique-object watches must count registry instances,
including those without the requested numeric member, before resolving a value.

The ownership validator independently proves the captured slot's exact registry
object, allocation token, raw ID, object asset and unique runtime-variable-ID to
canonical-address map binding. The writer must still compare the full current
RValue and retain the same held-event authority. Inspection may reorder slots
without resuming execution, so queued edits and UI selection also need the
snapshot revision or full canonical slot identity; pause identity alone is not
sufficient. `gamemaker_inspection_test` exercises those read-only projections,
retained domains, token reuse, moved slots and bounded failure cases.

## Reproducible evidence

`tools/gamemaker/runner_inspect.py` provides bounded PE/string/reference/disassembly
inspection. `zydis_bridge.cpp` links the workspace's static Zydis; local binaries
are ignored under `.cache`. `probe_runner.py` requires the exact executable hash,
restores its native breakpoints, and detaches existing-process probes. Its newly
launched test processes are test-owned and terminated on completion.

Direct launch initially exited successfully because Steam relaunched the game;
production launch handling must follow the validated game image and never infer
success merely from the short-lived launcher PID. Controlled attach probes used
the relaunched PID 27028, thread 16540, module base `0x140000000`.

The compiled adapter (`adapter_bridge.cpp` plus `GameMakerRunner.cpp`) was called
at 700 held real dispatch events: context and saved logical frame validation
passed all 700. Records included `gml_Object_obj_GAME_Step_1` CODE1492 and
`gml_Script___scribble_tick` CODE345 (entry4, nested depth1). Existing locals
`_frames`, `_size`, `_ResetJitter`, instance `CursState`, and global maps were
validated with runtime names. Maps absent before first assignment remain explicitly
unmaterialized. Probe JSON is temporary local evidence under `.cache`, not a
redistributed copy of game assets.

These initial probes established the adapter and boundary. Subsequent production
helper acceptance passed instruction breakpoints, into/over/out, paused numeric
edit/restore, native coexistence, lifecycle cleanup and three-restart symbolic
rebinding. See [the complete acceptance record](GAMEMAKER_IMPLEMENTATION.md) for
the production tests and their remaining explicitly unsupported capabilities.
