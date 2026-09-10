# State names and comments — September 2026

Small native functions now receive names from the value they read, write, or
test, even when the binary has no useful strings or imports. Examples:

| Observed operation | Suggested name |
| --- | --- |
| Return the value at `[rcx + 0x1c]` | `read_field_1c` |
| Return 1 when that value equals 1, otherwise 0 | `is_field_1c_one` |
| Return 1 when that value is nonzero, otherwise 0 | `is_field_1c_nonzero` |
| Write 1 to that location | `write_field_1c_one` |
| Write 0 to that location | `write_field_1c_zero` |

The tooltip retains the operand width, base register or global address, source
instruction, and exact predicate. A field offset in a name is descriptive; it
does not establish a shared object type or field identity across functions.
These remain heuristic names, displayed through the existing guessed-name
channel. Exports, symbols and analyst renames retain their existing priority.
Existing stronger API and string evidence still takes precedence.

Recognition is bounded to complete, entry-reachable native leaf bodies of at
most 24 instructions. It supports direct/zero-extended reads, simple register
copies, equality `SETcc` with a sufficiently defined return register, and a
single conditional split whose two exits return complementary 0/1 values.
Unknown instructions, calls, loops, incomplete bodies, extra memory operations,
unbalanced frames and ambiguous partial-register flows prevent these guesses.
A field write followed by returning zero is retained as a write operation.

The existing **Notes** option in Binary View now adds state comments to the
comparison or store itself. The **Annotations** drawer shows the same findings,
including evidence and confidence. For example:

```text
cmp byte ptr [ecx + 0x44], 1
; state check: 8-bit value at [ecx + 0x44] equals 1 versus any other value

movzx eax, byte ptr [ecx + 0x44]
test eax, eax
; state check: 8-bit value loaded from [ecx + 0x44] is zero versus nonzero
```

Equality branches explain the taken condition and its opposite on fallthrough.
Mask tests distinguish a single bit being set from any bit in a wider mask being
set. Direct 0/1 memory stores describe the exact written value. Load provenance
follows at most 12 preceding instructions in the same block, respecting
register clobbers and widths; low-byte checks keep their narrower scope.
`SETE`/`SETNE` notes explain which condition produces 1 and which produces 0.
If a flag-preserving instruction overwrites the compared register before a
branch or `SETcc`, its comment explicitly refers to the value checked at the
earlier comparison address.
Unknown flag effects prevent reuse of an earlier comparison for a later branch.
Signed `TEST` branches retain their signed meaning. Named comparison calls use
their known equality-return contract rather than a name substring.

A bare 0/1 check cannot establish that a ball is normal or Zen. The new output
exposes the exact condition and location so that an analyst can identify and
name that game-specific state from further evidence. It does not assume every
nonzero value means 1, that every field is Boolean, or that 1 always means active.

Analysis cache schema is 8; the saved project format is unchanged. No new UI
controls, dependencies, target execution or target-memory writes are involved.

## Verification

The new `state_semantics_pipeline_test` exercises actual x86 and x64 machine-code
bytes through both Zydis and Capstone, then passes their output through naming,
CFG construction and annotation. It checks exact suggested names, branch
polarity, source-valid instruction notes at VA zero, loaded-field comments, and
rejection of clobbered/partial return values. It also verifies the earlier-value
wording after a flag-preserving register overwrite. All 40 real-decoder sample
combinations passed.

- `function_namer_test`: passed.
- `function_namer_pipeline_test`: passed, including the final field-write/zero-return regression.
- `funcannotate_test`: passed, including the final earlier-comparison regression.
- `analysis_cache_test`: passed with schema 8.
- `state_semantics_pipeline_test`: passed with Zydis/Capstone, x86/x64, VA zero, and both new subsystems.
- Release x64 solution build: passed with the final versions of both analysis modules and verified embedded GameMaker helper. The installed v143 14.44.35207 toolset was selected explicitly from Visual Studio 18 Community; existing static vcpkg dependencies were reused.
- Startup smoke: passed; the final executable stayed alive for five seconds with an isolated application-data directory, then the test closed its own process.

Main-agent logs are under `build/state-semantics-review/`. Final subagent logs
are under `build/namer-leaf-agent/`, `build/namer-leaf-agent-final/`, and
`build/state-comment-temporal-tests/`.
