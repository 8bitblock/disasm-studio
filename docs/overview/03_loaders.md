## 03. Binary Loading & Formats

Everything in DisasmStudio starts with a file becoming a `BinaryFile`. This one class
(`src/Core/BinaryFile.h`, `src/Core/BinaryFile.cpp`) is the single source of truth for
*what the bytes are*: which executable format, which CPU architecture, where the image is
based, where it starts executing, how its sections map between file offsets and virtual
addresses, what it imports/exports, and a stable content hash that keys all persisted
analysis. It uses only the C++ standard library (including `<filesystem>` for durable
Unicode paths), so it can be unit-tested standalone with no Windows/ImGui/Capstone
dependencies.

### Supported formats and detection

`load(path)` slurps the whole file into a single `std::vector<uint8_t> data_` in one read
(seek-to-end to size it, then one `read`), then sniffs the format by magic bytes:

- **`MZ`** at offset 0 → attempt `parsePE()` (PE32 / PE32+).
- **`\x7FELF`** at offset 0 → attempt `parseELF()` (ELF32 / ELF64, little-endian only).
- **Thin Mach-O magic** (`FEEDFACE`/`FEEDFACF` in either byte order) or **fat/universal
  Mach-O magic** (`CAFEBABE`/`CAFEBABF` in either byte order) → attempt `parseMachO()`.
- **`0xCAFEBABE`** → attempt `parseJavaClass()` (method-code sections backed by the parsed
  Java class model). A plausible class wins the ambiguous `CAFEBABE` signature; when its
  parser rejects the image, the bounded universal-Mach-O parser gets the next attempt.
- Anything else → `BinFormat::Raw`.

The key robustness convention: if a recognized magic is present but the structured parse
*fails*, the format silently degrades to `BinFormat::Raw` rather than refusing the file
(`if (!parsePE()) format_ = BinFormat::Raw;`). A truncated or malformed
PE/ELF/Mach-O/Java class still loads through the same complete raw-image model described
below. `load()` only returns `false` for I/O failures (missing file, empty file, short read)
or an unrepresentable flat address range, never merely for a parse mismatch. Successful file and raw loads retain a canonical
absolute UTF-8 path, so recents/debug launch remain valid after working-directory changes.

`loadRaw(path, base)` is the explicit **Open as Raw…** path: no header parsing at all, the
caller supplies the load `base`, and `initializeRawLayout` creates one executable/readable
section named `.raw`, with virtual/file offset zero and both sizes covering the complete
blob. The low-level layout starts with `entryRVA_ = 0` and `rawEntryExplicit_ = false` — no
header entry is fabricated. `AppContext::loadRawPath` stages that image, validates the
editable mapped entry through `setRawEntryPointVA`, validates/deduplicates named roots
through `setAnalysisLandmarks`, and only then replaces the current target. Consequently a
real entry at RVA/VA 0 is representable, and invalid metadata cannot partially mutate the
active image.

The exact selected `Arch` is passed to the worker decoder and gates architecture-specific
discovery. Raw images therefore use the normal background string/function/listing jobs and
the same full-program listing, xrefs, call graph, navigation, and patch mapping as structured
images. This is the route for shellcode, firmware dumps, and decrypted blobs. A load is
rejected, without leaving partial state, if `base + size - 1` would overflow `uint64_t`; a
mapping ending exactly at `UINT64_MAX` remains valid.

For A32 and Thumb, the dialog also requires a mapping representable by the architecture's
32-bit PC-relative target model. ARM motif preselection therefore uses a 32-bit-safe raw base
rather than inheriting the generic x64 raw default; a user-entered incompatible mapping is
rejected instead of silently truncating Capstone branch/call targets.

### Raw firmware sniffing and boot-entry recovery

Before showing the Open-as-Raw dialog, the app runs the pure `Core/FirmwareSniffer` over the
selected bytes. It reports a `FirmwareDetection`, not a yes/no magic match: detected kind
flags plus a primary presentation kind, overall and per-record confidence, explanatory
`FirmwareEvidence`, a conservative CPU-mode hint, an optional recommended mapping, an
explicit entry file offset/VA with its jump chain, and named `FirmwareLandmark`s whose
`code` bit separates function roots from structural headers.

The corroborated formats are deliberately narrow and bounds-checked:

- **Legacy BIOS** — a tail reset-vector instruction is resolved using x86 real-mode
  semantics and strengthened by the conventional tail date, whole-image checksum, and ROM
  shape. A lone jump opcode remains low-confidence evidence and is not enough to assert a
  legacy BIOS.
- **PI/UEFI firmware volumes** — `_FVH` is accepted only with sane bounded length/header
  fields. The known-FFS-GUID state is recorded; strict high confidence requires a complete
  volume, revision/reserved fields, a terminated block map, and a valid 16-bit header
  checksum. Embedded bounded PE/TE headers can justify x86/x64 hints, but an image header is
  not mislabeled as a function entry.
- **PCI option ROMs** — `55 AA` must be backed by bounded `PCIR` metadata (declared image
  length, vendor/device, code type, final-image flag, checksum state). Legacy code type 0
  supplies a real-mode initialization root; an uncompressed EFI image becomes a code entry
  only when a bounded PE/COFF entry RVA maps to file-backed bytes and agrees with the EFI
  machine field. Compressed payload locations remain structural landmarks.
- **Intel Flash Descriptor images** — `0FF0A55A` at descriptor + `10h` is checked together
  with a bounded FLMAP0 region-table pointer; a sane FLREG1 yields a named BIOS-region
  landmark. A signature without a trustworthy map remains medium-confidence evidence.

Independently of those container signatures, a bounded head window scores coherent **A32,
Thumb/Thumb-2, and A64 instruction motifs**: aligned call encodings, frame/prologue shapes,
and return forms. A mode is suggested only when it clears minimum-evidence and winner-margin
thresholds; random or repeated bytes remain unclassified. This is an architecture hint, not
a firmware-format claim, and it never locks the analyst's base, entry, or mode controls.

Common x86 boot transfers (`EB rel8`, `E9 rel16/rel32`, operand-size overrides, and
`EA ptr16:16/ptr16:32`) are followed through a depth-capped chain. Real-mode rel16 IP wrap
and the low-1-MiB alias are handled explicitly; overflow or an out-of-image target is
reported unresolved rather than wrapped into a fabricated address. Corroborated system
images may recommend `4 GiB - file_size`, mapping file `size-16` to `FFFFFFF0h`; a
standalone option ROM may recommend `C0000h`. A standalone FV alone does not claim a
top-of-address-space mapping.

All record vectors, evidence, landmarks, and jump depth are capped. Signature scanning uses
a configurable byte budget and deterministic head/tail windows when truncated, while fixed
reset-vector and descriptor-at-`10h` checks still run. The interactive file probe adds a
512 MiB read cap. These bounds and the confidence/evidence model are load-bearing: detector
defaults remain editable and must never be presented as format-header certainty.

`BinFormat` (`Unknown, PE32, PE32Plus, ELF, MachO, JavaClass, Raw`) and `formatName()`
give the UI a width-only format label like `"PE32+"` or `"Mach-O"`; the parsed machine architecture is displayed separately.

### Machine / architecture recovery

`MachineArch` (`X86, X64, ARM, THUMB, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV, RISCV64, JVM, Unknown`)
is recovered from the *format header*, not inferred from the 32/64-bit class. This matters
because an ARM64 ELF and an x64 ELF are both 64-bit — only the `e_machine` field
distinguishes them, and `machine()` is what lets the UI auto-select Zydis for x86/x64 and
route everything else to Capstone instead of wrongly defaulting to x86.

- **PE** reads the COFF `Machine` field: `0x014C`→X86, `0x8664`→X64, A32
  (`0x01C0`)→ARM, Thumb/ARMNT (`0x01C2/01C4`)→THUMB, `0xAA64`→ARM64, MIPS variants, PowerPC (`0x01F0/01F1`), and
  RISC-V (`0x5032`→RV32, `0x5064`→RV64).
- **ELF** reads `e_machine` at offset 18, mapping EM_386/EM_X86_64/EM_ARM/EM_AARCH64,
  EM_MIPS (64-bit-aware → MIPS64), EM_PPC/EM_PPC64, and EM_RISCV (→ RISCV64 when 64-bit).
  Unknown machines fall back to X64/X86 by `ei_class`.
- **Mach-O** reads `cputype`, mapping x86/x86_64/ARM/ARM64/PPC/PPC64, with the same
  64-vs-32 fallback. Thin images may use either byte order. Universal containers expose
  every inspected slice and select one supported slice deterministically (x64, A64, x86,
  A32, PPC64, PPC), independent of the Windows host architecture.

ELF rejects big-endian outright (`ei_data != 1` → parse fails → degrades to Raw); this is a
stated limitation, not a bug.

`Arch::X86_16` is intentionally not a `MachineArch`: PE/ELF/Mach-O headers do not select the
raw real-mode workflow. It is chosen explicitly in Open as Raw, normally preselected from a
corroborated firmware entry/architecture hint. `Arch::THUMB` can be selected by PE machine
metadata or explicitly for raw firmware. Both modes persist with the project like every
other `Arch`.

### imageBase, entryPoint, and the imageBase_=0 convention

`imageBase()` and `entryPoint()` (the latter retains its historical `entryRVA_` return
contract) describe where the image loads and where it starts. Consumers that need to
distinguish “no entry” from an explicit zero entry use `hasEntryPoint()` and
`entryPointVA()`. For raw images, `setRawEntryPointVA` accepts only a file-backed VA and sets
the separate explicit-entry bit, so base 0 / entry 0 remains authoritative. The crucial
mapping decision, called out in `CLAUDE.md` and enforced here:

- **PE** keeps `imageBase_` as the real preferred load base (read from the optional header:
  8 bytes for PE32+, 4 for PE32) and stores **RVAs** in `Section::virtualAddress`.
- **ELF and Mach-O** keep `imageBase_ = 0` and store the **absolute** VM address in
  `Section::virtualAddress` (ELF `sh_addr`; Mach-O section `addr`).

Relocatable ELF objects (`ET_REL`) are the intentional exception to literal `sh_addr` use:
their `SHF_ALLOC` sections commonly all report zero. The loader assigns each one a checked,
alignment-aware, non-overlapping synthetic analysis VA, and resolves its section-relative
symbols against exactly that base. `SHT_NOBITS` receives virtual extent but remains
unbacked; an overflowing or otherwise unrepresentable section and its symbols are skipped.

Because every translation routine computes `rva = (va >= imageBase_) ? va - imageBase_ :
va`, setting `imageBase_ = 0` for ELF/Mach-O makes "rva == absolute va" — so the *same*
section-walk code handles all three formats uniformly. There is no per-format branch in the
hot translation path beyond the `Raw` special-case.

`entryRVA_` is the PE `AddressOfEntryPoint`, the ELF `e_entry`, or — for Mach-O — computed
from `LC_MAIN`'s `entryoff` (a *file* offset) translated through the `__TEXT` segment
(`textVmaddr + (entryFileoff - textFileoff)`), falling back to the first executable
section's VA when no `LC_MAIN` is present. For Raw, it is the validated analyst/detector
selection; named `AnalysisLandmark { address, name, evidence }` values are likewise required
to map to at least one backed byte before they can reach function discovery.

### Sections and the executable flag

Each `Section` carries `name`, `virtualAddress`, `virtualSize`, `rawOffset`, `rawSize`,
`characteristics`, and an `executable` bool. The parsers normalize the "is this code?"
decision per format:

- **PE**: `executable = characteristics & IMAGE_SCN_MEM_EXECUTE (0x20000000)`.
- **ELF**: `SHF_EXECINSTR (0x4)`. Non-allocated tables such as `.symtab`/`.strtab` are
  retained only in the bounded private header model needed for symbol parsing; they are not
  exposed as mapped sections. `.bss` (`SHT_NOBITS`) keeps `rawSize = 0` so it is recognized
  as virtual-only padding.
- **Mach-O**: a section is executable if its segment is exec, or the section flags carry
  `S_ATTR_PURE_INSTRUCTIONS (0x80000000)` / `S_ATTR_SOME_INSTRUCTIONS (0x400)`, or the
  section is literally named `__text`.
- **Raw**: one synthetic `.raw` section spans every file byte and carries code/execute/read
  characteristics. It is deliberately complete so section-driven analysis does not need a
  separate raw-only path.

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

### PE imports/exports/resources/security/runtime metadata and ELF metadata

For PE, `parsePE()` reads only data-directory slots that fit both
`NumberOfRvaAndSizes` and the declared `SizeOfOptionalHeader`, so a truncated optional
header cannot alias the section table. It also preserves the COFF
`fileCharacteristics()` value; `isDll()` tests `IMAGE_FILE_DLL`, which prevents the App
from treating a DLL as a directly launchable executable and feeds the validated hosted
DLL-debug workflow. It records export
(`exportDirRVA/Size`), import, and base-relocation directory locations. After sections are
parsed (imports need them for RVA translation):

- **`parseExports()`** builds the shared `BinaryFile::Export` model from the complete EAT:
  named aliases, ordinal-only rows, forwarders, local code/data targets, and malformed or
  unmapped targets. RVA/name/ordinal walks are bounds-checked and hostile inputs are capped
  by row, stored-string, and aggregate string-scan budgets. The PE header span declared by
  `SizeOfHeaders` (clamped before the earliest raw section) maps 1:1, so a valid
  header-resident export directory is supported without treating the virtual gap before the
  first section as file-backed data.
- **`parseImports()`** walks `IMAGE_IMPORT_DESCRIPTOR`s, resolving each IAT slot to a
  `{ iatVA, dll, name }` `Import`. It handles bound imports (OFT may be 0, falls back to
  the IAT RVA) and ordinal imports (`#NN` when the high bit is set). `iatVA = imageBase_ +
  iatRVA + k*ptrSize` is the actual slot address, which lets the UI annotate `call [iat]`
  sites inline as `DLL.func` and populate the Imports tab. Hard caps (descriptor scan to
  64 KB, 50 000 thunks per DLL, 100 000 total imports) bound pathological inputs.
- **`parseDelayImports()`** walks data directory 13 as bounded
  `IMAGE_DELAYLOAD_DESCRIPTOR` records. Both modern RVA-based descriptors and legacy
  VA-based fields are resolved without narrowing. The immutable `delayImports()` model
  preserves descriptor attributes/timestamp, module/IAT/INT/bound/unload addresses, DLL
  name, ordinal/name symbols, termination/truncation state, and exact IAT slot VAs. Delay
  symbols are also appended to the normalized `imports()` model with `delayed == true`.
- **`parseTlsDirectory()`** decodes the PE32/PE32+ TLS directory (data directory 9), whose
  members are VAs rather than RVAs. `peTls()` exposes the raw-data/index/callback-table
  addresses, zero-fill/characteristics, validation state, and an ordered, image-backed,
  null-terminated callback list capped at 4,096 entries.
- **`parseDebugDirectory()`** retains bounded generic `IMAGE_DEBUG_DIRECTORY` rows and
  decodes CodeView **RSDS** payloads into GUID bytes/printable GUID, age, and a bounded PDB
  path. Payloads may be backed by `AddressOfRawData` or, for disk images only,
  `PointerToRawData`; mapped images never reinterpret a raw-file pointer. No path parser
  trusts an unbounded NUL terminator.
- **`parseLoadConfig()`** reads only the prefix proven by all three of the structure's
  declared `Size`, the directory size, and mapped bytes. `peLoadConfig()` exposes the
  dependent-load flags plus presence/mapping state for the security cookie, SafeSEH table,
  Guard CF check/dispatch pointers, Guard CF function table/count, and Guard flags for both
  PE32 and PE32+ layouts.
- **`parseRuntimeFunctions()`** materializes x64 `RUNTIME_FUNCTION` rows and bounded
  `UNWIND_INFO` prefixes: range VAs, version/flags, prologue size, frame register/offset,
  exact raw unwind-code slots, exception handlers, CHAININFO, and indirect parent records.
  The existing `pdataRanges()` compatibility API continues to omit continuation records
  when seeding function discovery and retains its current-image parsing behavior.
- **`parseRelocs()`** walks `IMAGE_BASE_RELOCATION` blocks into `(VA, type)` pairs (type =
  `IMAGE_REL_BASED_*`), skipping ABSOLUTE (type 0) padding entries, capped at 200 000.
- **`parseResources()`** walks the resource directory (data directory [2]) — the three-level
  `IMAGE_RESOURCE_DIRECTORY` tree Type → Name/ID → Language — into a flat `BinaryFile::Resource`
  list (`resources()`). Each leaf records its type/name (numeric id or decoded UTF-8 string), language
  id, data RVA/size/code page, `va = imageBase_ + dataRVA`, and backing `fileOffset`. Directory
  offsets are relative to the resource base RVA (only the leaf data entry carries a real RVA); a
  visited-entry cap plus a depth cap keep a self-referential or absurd tree from spinning. The
  payload decoders (RT_* names, version info, string tables, `.bmp`/`.ico` reconstruction) live in
  the pure `Core/ResourceDecode` module and drive the Binary View's Resources tab.

For ELF32 and ELF64, `parseELF()` also walks bounded `SHT_DYNSYM` and `SHT_SYMTAB`
records through each table's linked string table. It handles the class-specific record
layout, `SHN_XINDEX` companions, defined versus undefined symbols, and normalizes symbol
kind, binding, visibility, size, owning section, and dynamic/static-table provenance.
Defined mapped symbols populate the shared `Export`/symbol model; undefined non-local API
symbols populate `Import` with `addressKnown == false` and an honest `(dynamic)` or
`(undefined)` provider. Dynamic-table rows win duplicate precedence, while real aliases
remain distinct. Function and GNU IFUNC symbols are therefore available to the analyzer.

The same bounded section-header pass exposes deeper immutable ELF metadata without
reparsing display strings:

- `elfRelocationTables()` retains class-correct `SHT_REL` and `SHT_RELA` tables, symbol/type
  indices, signed explicit addends, bounded symbol names/values, and per-table
  valid/complete/truncated state. Executable/shared-object offsets are validated as VAs;
  `ET_REL` offsets resolve through the exact synthetic target-section base. A separate
  `targetValid` bit makes a real relocation at VA zero unambiguous.
- `elfLinkageSections()` models conventional `.plt`, `.plt.sec`, `.got`, and `.got.plt`
  ranges and bounded slots. Exact relocation targets associate with GOT slots; PLT ordinal
  association is made only when a `.rel[a].plt` count matches the ABI's zero/one-reserved-slot
  shape. Missing PLT entry sizes are not guessed, while GOT pointer size follows ELF class.
- `elfDynamic()` walks `SHT_DYNAMIC` for ordered `DT_NEEDED` dependencies and explicit
  termination/truncation. `elfVersions()` validates GNU VERDEF/VERNEED offset chains with
  visited-offset and string budgets, decodes VERSYM index/hidden bits, and associates
  definition/requirement names with the normalized dynamic `Export`/`Import` rows.
- `elfInitializers()` combines direct `DT_INIT`/`DT_FINI` targets with bounded
  PREINIT/INIT/FINI array slots from section and dynamic metadata. Slot/target validity and
  backing are separate, zero targets remain representable, and `ET_REL` placeholders are
  labelled `requiresRelocation`.

All row/table/string work has independent caps. This deeper path currently requires usable
section headers; recovery from a sectionless `PT_DYNAMIC` segment remains separate work.

For Mach-O, `parseMachO()` exposes a similarly bounded immutable model through `machO()`:

- Universal 32/64-bit architecture tables retain outer-file offsets/sizes, alignment,
  byte order, structural/support flags, and the selected slice. Selected section offsets
  are rebased to the outer file, preserving the normal VA↔file API.
- `LC_SYMTAB`/`nlist(_64)` rows retain type/section/description/value and mapped/code state;
  defined external rows and undefined dylib-ordinal rows also feed the shared
  `exports()`/`imports()` models with explicit Mach-O provenance.
- Classic `LC_DYLD_INFO(_ONLY)` bind/weak/lazy opcode streams retain symbol, library,
  segment+offset, addend, type, and explicit address validity. ULEB/SLEB, operation, row,
  and string work is capped; unsupported threaded/chained encoding is reported invalid.
- The dyld export trie supports regular exports, reexports, and stub/resolver terminals
  with visited-node/depth/name budgets. `LC_FUNCTION_STARTS` decodes checked ULEB deltas.
  `LC_ROUTINES(_64)` and `S_MOD_INIT_FUNC_POINTERS` sections populate bounded initializer
  records; explicit validity bits preserve target VA zero.

Every submodel independently reports present/valid/truncated state so malformed link-edit
metadata cannot erase otherwise usable sections, mappings, or entry-point recovery.

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
initial cursor, `imports()` feeds the Imports tab and inline IAT annotations, and
`exports()` feeds the unified **Exports / Symbols** panel and PE/ELF function discovery. The addressing routines back
every navigation, hex pane, and string/byte search. The file-opening routes are an optional
startup argument (`DisasmStudio.exe <path>`), **File ▸ Open** (both auto-detect via `load`),
and **Open as Raw…**. The raw dialog shows the firmware kind/confidence, mapping and CPU
evidence, recovered entry, bounded record counts, and a capped evidence tree; detected
base/entry/architecture are only defaults and remain editable. The optional “Seed named
code landmarks” control forwards only `FirmwareLandmark::code == true` records, and the
edited entry is always added as `firmware_entry`/`raw_entry` if no landmark already owns it.

### Focused verification

- `firmware_sniffer_test` covers clean/random rejection; legacy BIOS corroboration; valid
  and malformed `_FVH`; legacy and EFI PCIR images (including compressed-payload honesty);
  Intel descriptor/BIOS-region recovery; top/C0000 mappings; rel8/rel16/rel32/far targets,
  16-bit IP wrap, hostile overflow/truncation, scan budgets, caps, confidence, landmarks,
  coherent A32/Thumb/A64 motif selection, and adversarial repeated/random rejection.
- `functionanalyzer_test` exercises `setRawEntryPointVA`, atomic named-landmark validation,
  explicit-entry precedence over the historical base fallback, stable firmware names, and
  a legitimate VA 0 entry plus A32/Thumb/A64 prologues and literal-pool exclusion.
  `xref_arch_test` verifies real Zydis/Capstone x86-16 and Capstone Thumb widths/targets,
  while `project_roundtrip_test` covers persisted x86-16/Thumb names and NOP rules.
- `elf_symbols_test` covers ELF32/64 dynamic/static symbols, malformed bounds,
  dynamic-first de-duplication, undefined imports, exact function sizes, and multi-section
  zero-address `ET_REL` layout including BSS, alignment, and overflow rejection.
- `binaryfile_elf_metadata_test` covers ELF64 REL/RELA and PLT/GOT associations, dynamic
  dependencies, version definitions/requirements/hidden symbol indices, direct and array
  initializers (including valid VA zero), ELF32 `ET_REL` synthetic targets, and independent
  malformed/truncated-table reporting.
- `binaryfile_macho_metadata_test` covers thin x64 symbols, dylib ordinals, classic dyld
  binding, export-trie traversal, function-start deltas, initializer pointers including VA
  zero, big-endian thin PPC, universal/fat32 and fat64 slice selection/rebased mapping, and
  isolated malformed string, ULEB, trie-cycle, unterminated-start, and slice-bound states.
- `dll_debug_plan_test` builds bounded PE32/PE32+ DLL fixtures and verifies the DLL
  characteristic/bitness, executable callable-export filter, malformed/non-DLL rejection,
  host/argv planning, and exact-path ASLR retargeting used after `LOAD_DLL`.
- `binaryfile_pe_metadata_test` builds a synthetic PE32+ image with TLS callbacks,
  named/ordinal delay imports, RSDS data, security load-config fields, ordinary/chained/
  indirect x64 unwind records, and verifies every immutable model. Truncated structures,
  impossible payload sizes, unbacked pointers, maximal directory sizes, and an
  unterminated-but-bounded PDB path pin the hostile-input behavior.

#### Limitations & notes

- ELF is **little-endian only**; big-endian ELF degrades to Raw.
- A universal Mach-O opens one deterministic supported slice at a time; it exposes all
  inspected slice descriptors but does not merge architectures into one analysis image.
  Chained fixups, code signatures, Objective-C/Swift metadata, and UI presentation for the
  new immutable metadata remain separate work.
- ELF section-table symbols, REL/RELA, dynamic dependencies, GNU versions, PLT/GOT ranges,
  and initializer/finalizer arrays are parsed. Sectionless `PT_DYNAMIC` recovery remains
  out of scope.
- Inferred fallbacks (machine defaulting by bit-class for unknown `e_machine`/`cputype`,
  Mach-O entry derived from `__TEXT`, ELF program-header fallback for stripped binaries) are
  best-effort but unlabeled at this layer — they are internal robustness, not surfaced as
  "heuristic" to the user the way the decompiler/tech-scan output is.
- A failed structured parse becomes `Raw` rather than an error, by design.
- Explicit raw mappings whose final byte would wrap the 64-bit VA space are rejected.
- Firmware sniffing is heuristic/evidence-based; every detected default remains editable,
  and structural landmarks are never function roots.
- The whole file is held in one contiguous `data_` buffer; loading is O(file size) memory,
  which is fine for typical executables but is the limiting factor for very large images.
