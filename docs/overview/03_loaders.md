## 03. Binary Loading & Formats

Everything in DisasmStudio starts with a file becoming a `BinaryFile`. This one class
(`src/Core/BinaryFile.h`, `src/Core/BinaryFile.cpp`) is the single source of truth for
*what the bytes are*: which executable format, which CPU architecture, where the image is
based, where it starts executing, how its sections map between file offsets and virtual
addresses, what it imports, and a stable content hash that keys all persisted analysis. It
is deliberately small and dependency-free (only `<cstdint>`, `<string>`, `<vector>`,
`<fstream>`, `<cstring>`, `<algorithm>`), which is why it is one of the Core modules that
can be unit-tested by compiling it standalone with no Windows/ImGui/Capstone dependencies.

### Supported formats and detection

`load(path)` slurps the whole file into a single `std::vector<uint8_t> data_` in one read
(seek-to-end to size it, then one `read`), then sniffs the format by magic bytes:

- **`MZ`** at offset 0 → attempt `parsePE()` (PE32 / PE32+).
- **`\x7FELF`** at offset 0 → attempt `parseELF()` (ELF32 / ELF64, little-endian only).
- **`0xFEEDFACE` / `0xFEEDFACF`** little-endian at offset 0 → attempt `parseMachO()` (thin
  Mach-O 32 / 64).
- Anything else → `BinFormat::Raw`.

The key robustness convention: if a recognized magic is present but the structured parse
*fails*, the format silently degrades to `BinFormat::Raw` rather than refusing the file
(`if (!parsePE()) format_ = BinFormat::Raw;`). A truncated or malformed PE/ELF/Mach-O still
loads as a flat blob you can stare at in hex and disassemble from offset 0. `load()` only
returns `false` for I/O failures (missing file, empty file, short read), never for a parse
mismatch.

`loadRaw(path, base)` is the explicit **Open as Raw…** path: no header parsing at all, the
caller supplies the load `base`, `format_ = Raw`, and `entryRVA_ = 0` (raw blobs have no
entry point — views simply start at `base`). This is the route for shellcode, firmware
dumps, and decrypted blobs where the user separately picks the disassembler arch.

`BinFormat` (`Unknown, PE32, PE32Plus, ELF, MachO, Raw`) and `formatName()` give the UI a
human label like `"PE32+ (x64)"` or `"Mach-O"`.

### Machine / architecture recovery

`MachineArch` (`X86, X64, ARM, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV, RISCV64, Unknown`)
is recovered from the *format header*, not inferred from the 32/64-bit class. This matters
because an ARM64 ELF and an x64 ELF are both 64-bit — only the `e_machine` field
distinguishes them, and `machine()` is what lets the UI auto-select Zydis for x86/x64 and
route everything else to Capstone instead of wrongly defaulting to x86.

- **PE** reads the COFF `Machine` field: `0x014C`→X86, `0x8664`→X64, ARM/Thumb/ARMNT
  (`0x01C0/01C2/01C4`)→ARM, `0xAA64`→ARM64, MIPS variants, PowerPC (`0x01F0/01F1`), and
  RISC-V (`0x5032`→RV32, `0x5064`→RV64).
- **ELF** reads `e_machine` at offset 18, mapping EM_386/EM_X86_64/EM_ARM/EM_AARCH64,
  EM_MIPS (64-bit-aware → MIPS64), EM_PPC/EM_PPC64, and EM_RISCV (→ RISCV64 when 64-bit).
  Unknown machines fall back to X64/X86 by `ei_class`.
- **Mach-O** reads `cputype`, mapping x86/x86_64/ARM/ARM64/PPC/PPC64, with the same
  64-vs-32 fallback.

ELF rejects big-endian outright (`ei_data != 1` → parse fails → degrades to Raw); this is a
stated limitation, not a bug.

### imageBase, entryPoint, and the imageBase_=0 convention

`imageBase()` and `entryPoint()` (the latter actually returns `entryRVA_`) describe where
the image loads and where it starts. The crucial design decision, called out in
`CLAUDE.md` and enforced here:

- **PE** keeps `imageBase_` as the real preferred load base (read from the optional header:
  8 bytes for PE32+, 4 for PE32) and stores **RVAs** in `Section::virtualAddress`.
- **ELF and Mach-O** keep `imageBase_ = 0` and store the **absolute** VM address in
  `Section::virtualAddress` (ELF `sh_addr`; Mach-O section `addr`).

Because every translation routine computes `rva = (va >= imageBase_) ? va - imageBase_ :
va`, setting `imageBase_ = 0` for ELF/Mach-O makes "rva == absolute va" — so the *same*
section-walk code handles all three formats uniformly. There is no per-format branch in the
hot translation path beyond the `Raw` special-case.

`entryRVA_` is the PE `AddressOfEntryPoint`, the ELF `e_entry`, or — for Mach-O — computed
from `LC_MAIN`'s `entryoff` (a *file* offset) translated through the `__TEXT` segment
(`textVmaddr + (entryFileoff - textFileoff)`), falling back to the first executable
section's VA when no `LC_MAIN` is present.

### Sections and the executable flag

Each `Section` carries `name`, `virtualAddress`, `virtualSize`, `rawOffset`, `rawSize`,
`characteristics`, and an `executable` bool. The parsers normalize the "is this code?"
decision per format:

- **PE**: `executable = characteristics & IMAGE_SCN_MEM_EXECUTE (0x20000000)`.
- **ELF**: `SHF_EXECINSTR (0x4)`. Non-loaded sections (`sh_addr == 0` and not
  `SHF_ALLOC`) such as `.symtab`/`.strtab` are skipped entirely. `.bss` (`SHT_NOBITS`)
  keeps `rawSize = 0` so it is recognized as virtual-only padding.
- **Mach-O**: a section is executable if its segment is exec, or the section flags carry
  `S_ATTR_PURE_INSTRUCTIONS (0x80000000)` / `S_ATTR_SOME_INSTRUCTIONS (0x400)`, or the
  section is literally named `__text`.

`firstCodeSection()` returns the first executable section, or — if none is flagged — the
first section, or `nullptr`. This is the default disassembly target when a binary opens.

A notable ELF resilience feature: if the section header table is missing or implausible
(`!e_shoff || !e_shnum || e_shnum > 4096`, i.e. a fully stripped binary), `parseELF()`
falls back to the **program header table** and synthesizes one `Section` per `PT_LOAD`
segment (using `p_vaddr/p_memsz/p_offset/p_filesz`, `PF_X` for executability) so the image
still maps and disassembles.

### VA ↔ file-offset translation

Four routines form the addressing core, and every other subsystem (disassembler, hex view,
string scanner, patcher, decompiler) goes through them:

- **`ptrFromVA(va, availOut)`** — VA → live pointer into `data_`, plus how many contiguous
  bytes are available. For `Raw`, it is just `data() + (va - base)`. For mapped formats it
  walks `sections_`, finds the containing section via *overflow-safe containment*
  (`rva >= s.virtualAddress && rva - s.virtualAddress < s.virtualSize` — the subtraction
  form avoids `base + size` wrapping on 64-bit ELF/Mach-O), returns `nullptr` if the VA
  falls in virtual padding (`delta >= rawSize`), and clamps both the returned base and the
  reported span to the bytes actually present so a malformed `rawOffset/rawSize` past EOF
  cannot over-read.
- **`ptrFromRVA(rva, availOut)`** — thin wrapper: `ptrFromVA(imageBase_ + rva, ...)`.
- **`offsetToVA(fileOffset, vaOut)`** — file index → VA. Used when something scans `data_`
  directly (strings, byte-pattern search) so reported hits line up with the disassembly
  instead of being mistaken for RVAs. It finds the section whose raw range contains the
  offset; for **PE only**, offsets before the first section's raw data are treated as
  headers mapping 1:1 (`offset == RVA`). For ELF/Mach-O an uncovered offset has no VA.
- **`vaToOffset(va, offOut)`** — the inverse, VA → file index, returning `false` for
  virtual-only padding or out-of-file VAs. This is what makes **patch-to-file** possible
  (see chapter on patching): a patch's VA must resolve to a concrete byte in a copy of the
  original file.

These routines are genuine inverses on backed bytes, which is exactly the property the Core
unit tests assert (round-tripping `vaToOffset`↔`offsetToVA`). The whole defensive style
here — the `rd<T>()` helper splits its bounds check into two halves
(`off <= size && sizeof(T) <= size - off`) precisely so a hostile `e_lfanew`/`e_shoff` near
`SIZE_MAX` cannot wrap the bound and trigger a wild `memcpy` — reflects that this code
parses untrusted, possibly adversarial binaries.

### contentHash — the persistence key

`contentHash()` is a 64-bit **FNV-1a** over the entire file, with the length mixed in at
the end so two blobs differing only by trailing zero padding still hash differently. It is
computed lazily on first call and **cached** (`hash_`, `hashValid_`). The caching is not
just an optimization — it is correctness: the hash is taken from the *pristine* file before
any in-memory patch, so it remains stable as the persistence key. Every saved-analysis
sidecar (`%APPDATA%/DisasmStudio/projects/<hash>.json`: comments, renames, bookmarks,
breakpoints, patches, notes) is keyed by this value, so a patched binary does not split its
analysis across two files. `clear()` resets `hashValid_` so the next loaded file recomputes.

### PE imports and base relocations

For PE, `parsePE()` reads the data directory (honoring `NumberOfRvaAndSizes` so it never
aliases the section table by reading an undeclared slot) and records export
(`exportDirRVA/Size`), import, and base-relocation directory locations. After sections are
parsed (imports need them for RVA translation):

- **`parseImports()`** walks `IMAGE_IMPORT_DESCRIPTOR`s, resolving each IAT slot to a
  `{ iatVA, dll, name }` `Import`. It handles bound imports (OFT may be 0, falls back to
  the IAT RVA) and ordinal imports (`#NN` when the high bit is set). `iatVA = imageBase_ +
  iatRVA + k*ptrSize` is the actual slot address, which lets the UI annotate `call [iat]`
  sites inline as `DLL.func` and populate the Imports tab. Hard caps (descriptor scan to
  64 KB, 50 000 thunks per DLL, 100 000 total imports) bound pathological inputs.
- **`parseRelocs()`** walks `IMAGE_BASE_RELOCATION` blocks into `(VA, type)` pairs (type =
  `IMAGE_REL_BASED_*`), skipping ABSOLUTE (type 0) padding entries, capped at 200 000.

ELF/Mach-O import and relocation tables are not parsed here — imports are a PE-only feature
in this loader.

### writeImage — in-memory patching that preserves identity

`writeImage(va, data, n)` maps the VA to a file offset via `vaToOffset` and overwrites up
to `n` bytes of the in-memory `data_`, returning the count written (0 if the VA is not
backed by on-disk bytes). After it runs, `bytes()` and `ptrFromVA()` return the patched
view, so the disassembly immediately reflects an applied (or reverted) patch. Two things it
**deliberately does not do**: it does not touch `contentHash()` (cached from the pristine
file, so saved analysis stays under one key) and it does not write the file on disk. Writing
to disk is a separate, explicit action (**File ▸ Save Binary As…**) that splices patches
into a copy via `vaToOffset`. This separation keeps "preview a patch" cheap and reversible
while keeping the original artifact untouched.

### User-facing surface

`BinaryFile` has no UI of its own; it is pure model. Its outputs drive the chrome:
`formatName()` and `machine()` populate the title/status, `firstCodeSection()` sets the
initial cursor, `imports()` feeds the Imports tab and inline IAT annotations, and the
addressing routines back every navigation, hex pane, and string/byte search. The two
user-visible entry points are **File ▸ Open** (auto-detect via `load`) and **Open as Raw…**
(`loadRaw` with a chosen base + arch).

#### Limitations & notes

- ELF is **little-endian only**; big-endian ELF degrades to Raw.
- Mach-O support is **thin only** — fat/universal binaries are not split here (magic
  `0xCAFEBABE` is not recognized and would load as Raw).
- Imports and relocations are parsed for **PE only**; ELF/Mach-O dynamic-symbol resolution
  is out of scope for this class.
- Inferred fallbacks (machine defaulting by bit-class for unknown `e_machine`/`cputype`,
  Mach-O entry derived from `__TEXT`, ELF program-header fallback for stripped binaries) are
  best-effort but unlabeled at this layer — they are internal robustness, not surfaced as
  "heuristic" to the user the way the decompiler/tech-scan output is.
- A failed structured parse becomes `Raw` rather than an error, by design.
- The whole file is held in one contiguous `data_` buffer; loading is O(file size) memory,
  which is fine for typical executables but is the limiting factor for very large images.
