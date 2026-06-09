## 02. Disassembly Engines & Assembler

This chapter covers the lowest layer of DisasmStudio's analysis stack: the code that turns raw bytes into decoded instructions, and the inverse path that turns typed assembly text back into bytes for patching. Everything above it — the function analyzer, CFG builder, call-graph, decompiler, xref engine, and the entire Binary View listing — consumes the small, engine-neutral data type defined here. The design goal is simple but load-bearing: **the rest of the app must never know or care whether a given instruction was decoded by Zydis or Capstone.** All of the source for this subsystem lives under `src/Disasm/`.

### The engine-agnostic interface (`IDisassembler.h`)

The contract is a pure virtual class, `ds::IDisassembler` (in `src/Disasm/IDisassembler.h`). It exposes only four methods:

- `Engine engine() const` and `const char* engineName() const` — identity, used for display and per-project persistence.
- `std::vector<Instruction> disassemble(const uint8_t* data, size_t size, uint64_t virtualAddress, size_t maxInstructions = 0)` — bulk-decode a buffer starting at a virtual address, stopping after `maxInstructions` (0 = "until the buffer is exhausted").
- `bool decodeOne(const uint8_t* data, size_t size, uint64_t virtualAddress, Instruction& out)` — decode exactly one instruction, returning `false` on a decode error.

The UI and Core always hold an `IDisassembler*` (or `std::unique_ptr<IDisassembler>`) and never `#include` a concrete backend. That keeps Zydis/Capstone headers out of the rest of the build and means a binary's engine can be swapped at runtime without touching call sites.

#### The `Instruction` model

The single struct every consumer sees is `ds::Instruction`, deliberately minimal and render-ready:

| Field | Type | Meaning |
|---|---|---|
| `address` | `uint64_t` | virtual address of the instruction |
| `length` | `uint32_t` | size in bytes |
| `bytes` | `std::string` | hex byte string, e.g. `"48 89 5C 24 08"` |
| `mnemonic` | `std::string` | e.g. `"mov"` |
| `operands` | `std::string` | e.g. `"rbx, [rsp+0x8]"` |
| `isBranch` | `bool` | any jmp/jcc/call/ret-family instruction |
| `isCall` | `bool` | call instruction |
| `isRet` | `bool` | ret/retf/iret family (returns from a call frame) |
| `isRepString` | `bool` | carries a REP/REPE/REPNE prefix (`rep movs/stos/cmps/scas/…`) |
| `branchTarget` | `uint64_t` | resolved absolute target if statically known, else 0 |

Two design choices are worth calling out. First, the text fields (`bytes`, `mnemonic`, `operands`) are already **formatted as strings** rather than carrying structured operand data — the UI renders them directly, and higher layers that need structure (e.g. the decompiler's operand lifter) re-parse the text. This keeps the struct cheap to copy and the interface trivial. Second, the four boolean flags plus `branchTarget` are the *only* semantic signals the CFG, call-graph, xref, function-discovery, and goto-navigation subsystems get. Getting these right across every architecture is therefore critical, and both backends go out of their way to normalise them (see below).

#### The `Arch` and `Engine` enums and helpers

`enum class Arch { X86, X64, ARM, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV32, RISCV64 }` enumerates every supported architecture; `enum class Engine { Zydis, Capstone }` the two backends. Several free helpers in the same header glue this to the rest of the app:

- `ArchIsX86(Arch a)` — `true` only for `X86`/`X64`. This single predicate drives backend routing (the factory) *and* assembler capability checks.
- `ArchName(Arch)` / `ArchFromName(const char*, Arch&)` — a name↔enum pair (e.g. `"RISC-V 32"` ↔ `RISCV32`). The inverse exists specifically so the chosen architecture can be saved into the per-binary JSON sidecar and restored exactly on reopen.
- `EngineNameOf(Engine)` / `EngineFromName(const char*, Engine&)` — the same round-trip for the engine choice.

The architecture is normally auto-selected from the loaded image header (`BinaryFile::machine()`), and non-x86 images route to Capstone automatically.

### The Zydis backend (x86/x64 only)

`ds::ZydisDisassembler` (`src/Disasm/ZydisDisassembler.{h,cpp}`) is the fast path for the common case. It is intentionally header-light: the Zydis types live behind an opaque `struct ZyState` (a `ZydisDecoder` + `ZydisFormatter`) held via `unique_ptr`, so `ZydisDisassembler.h` doesn't drag the Zydis headers into every translation unit that decodes.

The decoder and formatter depend only on the architecture, so they are **built once in the constructor and reused for every instruction** — a deliberate amortisation that matters when decoding very large listings. The constructor maps `Arch::X86` → `ZYDIS_MACHINE_MODE_LEGACY_32` + `ZYDIS_STACK_WIDTH_32` and everything else → `ZYDIS_MACHINE_MODE_LONG_64` + `ZYDIS_STACK_WIDTH_64`, and initialises the formatter to Intel syntax (`ZYDIS_FORMATTER_STYLE_INTEL`).

`decodeOne` calls `ZydisDecoderDecodeFull`, then formats into a 256-byte stack buffer with `ZydisFormatterFormatInstruction`. A subtle but important detail: the mnemonic is taken from Zydis *metadata* (`ZydisMnemonicGetString(insn.mnemonic)`), **not** by splitting the formatted string on the first space. The formatted text prefixes legacy-prefix tokens (`rep`, `lock`, `bnd`, …), so a naive first-space split would treat the prefix as the mnemonic (`"rep movsb"` → `"rep"`). The code finds the real mnemonic inside the formatted string and slices the remainder as `operands`, falling back to a first-space split only if the mnemonic string is unavailable.

Semantic flags come from Zydis's instruction category metadata:
- `isCall` ← `ZYDIS_CATEGORY_CALL`, `isRet` ← `ZYDIS_CATEGORY_RET`.
- `isBranch` ← call OR ret OR `COND_BR` OR `UNCOND_BR`.
- `isRepString` ← the `HAS_REP | HAS_REPE | HAS_REPNE` attribute bits. This flag exists so the debugger's step-over/step-out logic treats a `rep`-prefixed string op as one unit instead of single-stepping each iteration.
- `branchTarget` ← for each visible operand that is a *relative* immediate, `ZydisCalcAbsoluteAddress` resolves it to an absolute VA.

### The Capstone backend (everything else)

`ds::CapstoneDisassembler` (`src/Disasm/CapstoneDisassembler.{h,cpp}`) covers ARM, ARM64, MIPS/MIPS64, PPC/PPC64, RISC-V 32/64 — and can also handle x86/x64 if explicitly requested. `open()` maps `Arch` to Capstone's `cs_arch`/`cs_mode` pairs, enables full detail (`CS_OPT_DETAIL`), and pre-allocates **one reusable `cs_insn` scratch buffer via `cs_malloc`** so the decode loop uses `cs_disasm_iter` without a per-instruction malloc/free. The handle and scratch are stored as opaque `uintptr_t`/`void*` to keep the header clean.

One real-world correctness fix is baked in: every loadable image in this tool is little-endian (the ELF loader requires `ei_data==1`, Mach-O requires the LE magic, PE is LE), so PPC/PPC64 are opened with `CS_MODE_LITTLE_ENDIAN` rather than the old big-endian default, which had mis-decoded every loadable PPC binary (notably ppc64le ELF).

Because Capstone's generic groups don't cover every architecture's idioms, the backend does extra normalisation in `fillInstruction`:

- **Flags from groups:** `CS_GRP_CALL` → `isCall`+`isBranch`; `CS_GRP_RET` → `isRet`; `CS_GRP_JUMP`/`CS_GRP_RET`/`CS_GRP_BRANCH_RELATIVE` → `isBranch`.
- **Return detection by mnemonic** (`arch != X86/X64`): Capstone's generic `CS_GRP_RET` does not fire for several non-x86 returns, so they are detected textually — MIPS `jr $ra`, PPC `blr`/`blrl`/`bclr`, ARM `bx lr` / `pop {…pc}` / `ldm…{…pc}` / `mov pc, lr`, RISC-V `ret` / `jr ra` / `jalr zero, ra`. This is what keeps CFG block boundaries and step-out classification correct under Capstone for every architecture.
- **`branchTarget`** is read from the first immediate operand in the arch-specific detail union (`cs_x86`/`cs_arm64`/`cs_arm`/`cs_mips`/`cs_ppc`/`cs_riscv`) via `branchTargetFor`. Capstone resolves relative branches to absolute addresses for every architecture, so this yields the same `branchTarget` the Zydis path produces for x86 — and extends it to ARM/ARM64/MIPS/PPC/RISC-V, which is exactly what CFG, xref, call-graph, and goto navigation depend on.
- **`isRepString`** is computed only for x86/x64 via `isRepStringInsn`, which checks both the group-1 prefix byte (`cs_x86.prefix[0]`) *and* a `"rep"`-prefixed mnemonic, then requires a real string-op base (`movs/stos/cmps/scas/lods/ins/outs`) to avoid mis-flagging SSE instructions that carry a mandatory `0xF2`/`0xF3`.

### `decodeOne` vs `disassemble`, and never-stall decoding

`decodeOne` is the surgical path: one instruction from a buffer, `false` on failure. The debugger's live-assembly and step logic use it. `disassemble` is the bulk path used to build listings.

Both backends share a **resync-on-error** strategy so a bad byte never stalls the stream. On a decode failure, each emits a synthetic 1-byte pseudo-instruction with mnemonic `"db"` and operand `0xNN` (the raw byte), then advances exactly one byte and continues. This guarantees forward progress through data, padding, or genuinely undecodable bytes — important for a full-program listing that must cover every byte of a section. Both honour `maxInstructions` (the full-program listing caps at ~800k instructions per the project conventions).

### Backend selection (`DisassemblerFactory`)

`ds::MakeDisassembler(Engine engine, Arch arch)` (`src/Disasm/DisassemblerFactory.cpp`) is the only place a concrete backend is constructed. Its routing rule is blunt and safe:

```
if (!ArchIsX86(arch)) return CapstoneDisassembler(arch);   // forced
switch (engine) { Zydis -> ZydisDisassembler; Capstone -> CapstoneDisassembler; }
```

For any non-x86 architecture the requested engine is **ignored** and Capstone is forced — because Zydis can only decode x86/x64, and silently routing, say, ARM bytes through it would mis-decode them as x64. For x86/x64 the user/project preference (Zydis or Capstone) is honoured. This is why x86/x64 is the only place "which engine" is even a meaningful choice.

### The Keystone assembler (patching)

`ds::Assemble(Arch arch, const std::string& text, uint64_t address)` (`src/Disasm/Assembler.{h,cpp}`) is the inverse path — a thin wrapper over Keystone used by Binary View's live "Patch" feature (type `mov rax, 1`, get bytes). It returns an `AsmResult { bool ok; std::vector<uint8_t> bytes; size_t count; std::string error; }`: the encoded bytes, the number of statements encoded, and a human-readable error when `ok` is false. It accepts one or more instructions separated by `;` or newline, uses Intel syntax, and resolves relative operands against the supplied `address` (so a `jmp`/`call` patch lands correctly at its in-memory location).

The crucial asymmetry: **the assembler supports only x86/x64/ARM/ARM64.** Keystone has no encoder for MIPS/PPC/RISC-V here, so for any other architecture `Assemble` returns immediately with `ok=false` and the explicit message *"patch assembler supports x86 / x64 / ARM / ARM64 only"* — failing clearly rather than mis-encoding as x64. Keystone init failures and assembly errors are likewise surfaced as readable strings (`ks_strerror(ks_errno(ks))`), and the engine handle and encoded buffer are always freed (`ks_free`/`ks_close`) on every exit path. So **disassembly coverage (via Capstone) is strictly broader than assembly coverage (via Keystone)** — a deliberate, documented trade-off: you can read every supported arch but can only patch the four Keystone handles.

### Performance characteristics

- Zydis and Capstone both build their decoder/formatter (and Capstone its scratch `cs_insn`) **once per instance**, so the hot decode loop allocates nothing per instruction.
- The `Instruction` struct is small and string-based; bulk `disassemble` returns a `std::vector<Instruction>` sized to the work.
- Resync-on-error keeps worst-case decoding linear in bytes even on data-heavy regions.

#### Limitations & notes

- **Engine choice only matters for x86/x64.** All other architectures are forced to Capstone by the factory; the requested `Engine` is ignored for them.
- **Assembly is narrower than disassembly.** Keystone here supports only x86/x64/ARM/ARM64; patching any other arch fails with a clear "unsupported" message — by design, not a bug.
- **Operands are formatted strings, not structured data.** Consumers needing operand structure re-parse the text; the model carries no per-operand type/size information.
- **`branchTarget` is best-effort and static.** It is non-zero only when the target is a statically resolvable relative/immediate (register-indirect, memory-indirect, and computed jumps resolve to 0). Indirect control flow is handled by higher layers (e.g. jump-table recovery), not here.
- **PPC is decoded little-endian** to match every loadable image; big-endian PPC images are out of scope of the loaders, so this is consistent rather than a restriction in practice.
- Undecodable bytes surface as synthetic `db 0xNN` pseudo-instructions; these are real entries in the listing, not silent gaps.
