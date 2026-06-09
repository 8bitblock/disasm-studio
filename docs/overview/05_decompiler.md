## 05. Decompiler & Data-Flow

DisasmStudio ships a **lightweight, in-house decompiler**: given a function's
control-flow graph, it recovers C-like control structures (`if/else`,
`while`/`do-while`, `for`, `switch`), lifts each instruction to a readable
statement, and — when enabled — runs a **data-flow pre-pass** that names locals,
propagates copies and constants, eliminates dead assignments, infers types, and
recovers return expressions. The result reads much closer to real C than a raw
instruction-by-instruction transliteration. This is deliberately *not* a
full-blown decompiler (no SSA, no global type lattice, no inter-procedural type
recovery) — it is a "good enough to read" structurer, and every heuristic edge is
labelled as such in the UI.

The subsystem lives in two pure-logic, UI-free Core modules (so they are
unit-testable in the sandbox):

- `src/Core/Decompiler.{h,cpp}` — the **structurer** plus the legacy per-instruction operand lifter.
- `src/Core/DataFlow.{h,cpp}` — the optional **data-flow pre-pass** (`AnalyzeDataFlow`).

The single public entry point is `ds::Decompile(const ControlFlowGraph&, const DecompileOptions&)`.

### Inputs and options — `DecompileOptions`

`Decompile` consumes a `ControlFlowGraph` (basic blocks + edges from
`src/Core/CFG.h`, built by `BuildCFG`) and a small option bundle
(`Decompiler.h`):

- `nameFor(uint64_t va)` — resolve a call/jump-target VA to a display name
  (e.g. `kernel32.CreateFileW`, a user rename, or `""` to fall back to
  `sub_<addr>`). The UI binds this to `BinaryViewTab::symbolFor`.
- `dataRefFor(uint64_t addr)` — resolve a constant data address to a display
  token: a quoted, escaped C-string literal, an import/global name, etc. The UI
  binds this to `BinaryViewTab::dataRefToken`, which checks the IAT/import map,
  user renames/symbols, and finally attempts to read a printable ASCII/UTF string
  at the address.
- `signature` — an optional inferred `"<rettype> (args)"` header (e.g.
  `"__int64 (a1, a2)"`). When present, the function name is spliced in at the
  `(`; otherwise the header falls back to `__int64 <name>()`.
- `deepDataFlow` (default **true**) — the **A/B kill-switch**. With it on,
  `Decompile` runs `AnalyzeDataFlow` and emits named/propagated/DCE'd statements;
  with it off (or if the data-flow pass returns `ok == false`), it falls back to
  the legacy per-instruction string lift. No instruction is ever lost in either
  mode.

The guessed name + inferred signature are what make the output read like a real
function: a header such as `__int64 sub_140001000(a1, a2)` over a body of named
locals and inlined string literals, rather than a wall of register mnemonics.

### The structurer (`Decompiler.cpp`)

#### Building the per-block model

`Structurer::build` walks the CFG once and, per block, computes:

- **Body statements** — from the data-flow pass when active (`df_.blockStmts[i]`),
  otherwise from `liftStmt` over every non-terminator instruction. A trailing
  `call` is treated as a normal statement, not a terminator, so it stays in the
  body.
- **Terminator kind** (`Term::{Return, Uncond, Cond, Fall, External, Switch}`) and
  its operands: true/false successor indices for conditionals, the unconditional
  jump target, the fallthrough block, switch case targets, or an `extTarget` VA
  when a branch leaves the analyzed window (rendered later as a `goto loc_<addr>`
  "tail" call).
- **Flag state** (`FlagState`) feeding the terminator, so a `Jcc` can be rendered
  as a real relational condition.
- **Forward adjacency** (`succ`) for the dominator analysis.

#### Dominators and post-dominators (Cooper/Harvey/Kennedy)

`computeIdom` implements the classic **Cooper, Harvey & Kennedy iterative
dominator algorithm**: an iterative DFS produces a postorder numbering, then the
immediate-dominator array is refined to a fixpoint over the reverse-postorder,
using the two-finger `intersect` walk up the dom-tree. Unreachable nodes stay
`-1`. `dominates(a, b)` is then a simple walk up `idom[]`.

**Post-dominators** are computed by running the same algorithm on the *reversed*
graph augmented with a virtual exit node (index `N`): every return / external /
sink block is linked to it. The resulting `ipdom[]` gives each block's immediate
post-dominator — i.e. the **join point** where an `if/else` reconverges, which is
the linchpin of structuring.

#### Natural-loop detection

`detectLoops` finds **back-edges** `u→v` (an edge whose head `v` dominates its
tail `u`), marks `v` a loop header, and grows the natural-loop body by walking
predecessors from `u` back to `v`. Multiple latches into the same header are
merged (OR'd) into one body set. Each header's **loop follow** is the
lowest-address block that an in-loop edge exits to — the post-loop continuation.

#### Emission: two passes, structured output

Emission runs **twice**. Pass 1 (`collecting = true`) discovers which blocks need
labels (i.e. are `goto` targets); pass 2 emits the text with those labels in
place. The `emitted` counter guards against pathological blow-up (truncates past
100,000 emitted blocks).

`emitFrom`/`emitTerminator` are a recursive structuring driver:

- **`Cond`** — renders `if (cond) { ... }` (and `else { ... }`) bounded by the
  post-dominator join `ipdom[n]`. Empty arms are detected and the condition is
  inverted to avoid an empty `then`. When there is no common join before exit, the
  then-arm is bounded by the else's entry so it can't run away and swallow the
  rest of the function. Branches whose targets exit (return/continue/break/goto)
  collapse to a single `if (cond) <jump>;` line.
- **`Switch`** — the recovered jump table becomes `switch (selector) { case N: ...
  break; }`. Cases run to the switch's post-dominator join; when no join exists,
  the case body is bounded by the next distinct case entry (otherwise `case 0`
  would swallow every later case and the tail). `switchVar` recovers the selector
  expression from the `jmp [base + reg*N]` form by finding the register scaled by
  8/4/2; failing that it emits `switch_index`.
- **Loops** (`emitLoop`) — emitted as **pre-tested** `while (cond) { ... }` when
  the header itself is a side-effect-free 2-way test with exactly one arm leaving
  the loop (the condition is negated as needed and the loop's real exit arm is
  used as the break target). Otherwise it falls back to `while (1) { ... }` with
  the exit handled inside via break/goto — the general form for `do-while` and
  multi-exit loops.
- **`continue` / `break` vs labelled `goto`** — `goTo` scans the loop stack
  innermost-first. Because C `continue`/`break` bind only to the innermost loop, a
  transfer to the innermost header/follow becomes `continue;`/`break;`, but a
  transfer to an *enclosing* loop's header/follow becomes a labelled `goto … /*
  continue outer */`. Any jump to an already-emitted block also becomes a labelled
  `goto`. This is exactly how production decompilers fall back on **irreducible
  control flow**: structure where possible, labelled gotos where not.

#### for-loop reconstruction (post-pass, data-flow mode only)

`reconstructForLoops` is a **purely textual, conservative** post-pass run only
when `deepDataFlow` is active. It rewrites a `while (COND) { …; i++; }` into
`for (; COND; i++) { … }` when: the last top-level body line is a recognized step
(`i++`, `i--`, `i += k`, `i -= k`), `i` appears as a word in `COND`, and the body
contains **no** `continue` or `goto` (which would skip the step in a `while` but
always run it in a `for`). Anything not matching the exact shape stays a `while` —
so the rewrite can never change semantics. (The data-flow pass also carries a
`DfForLoop` triple structure for header blocks, but the shipped emitter uses this
textual reconstruction.)

#### The legacy operand lifter (`liftStmt`)

When data-flow is off, `liftStmt` turns one instruction into a C-ish statement:

- `mov`/`movzx`/`movsx`/`movabs`/SSE moves → `A = B;`; `lea` → `A = &(addr);`.
- Arithmetic/logic → compound assignment (`+= -= &= |= ^= <<= >>=`); `xor x,x`
  special-cased to `x = 0;`. `inc`/`dec` → `++`/`--`; `neg`/`not` → `-`/`~`.
- `rol`/`ror` → `_rotl`/`_rotr` (single-operand form rotates by 1); `bswap`,
  `xchg`→`swap(...)`.
- `mul`/`imul`/`div`/`idiv` model the implicit accumulator pair, picking
  `rdx:rax`/`edx:eax`/`dx:ax`/`ah:al` from the operand width via `accPair`;
  3-operand `imul dst,src,imm` → `dst = src * imm`.
- `cmp`/`test` produce no statement — they set `FlagState` for the next branch.
- `setcc`/`cmovcc` render against the pending flag state via `condString` (e.g.
  `dst = (a < b);`, `if (a == b) dst = src;`).
- Anything unmodelled is preserved verbatim as `__asm { … };` so no instruction is
  silently dropped.
- `[mem]` is rewritten to `*(mem)` (`cOperand`) so memory reads look like C
  dereferences.

#### Condition rendering (`condString` / `condOp`)

`condOp` maps a `Jcc` mnemonic to a C operator and its negation (handling both
signed and unsigned families, e.g. `jg/jnle/ja/jnbe → >`). `condString` then
renders the taken condition against the `FlagState`: after `cmp a,b` it emits
`a <op> b`; after `test x,x` it emits `x <op> 0`; after `test x,y` it emits
`(x & y) <op> 0`; after an arithmetic op it tests the result against 0. `js`/`jns`
are special-cased to a signed `< 0` / `>= 0` (cast to `int64_t`). Unmodelled
branches (`jp`, `jo`, `loop`, `jcxz`, …) degrade to an exposed `<mnem>_cc`
predicate rather than a wrong comparison.

### The data-flow pre-pass (`DataFlow.cpp`)

`AnalyzeDataFlow` is the upgrade that makes the output read like C. It returns a
`DataFlowResult` consumed directly by the structurer (per-block statement lists,
terminator flags, inferred declarations, return expressions, for-loop triples).
If anything goes wrong it returns `ok == false` and the structurer silently falls
back to the legacy lift.

#### Typed operand model

Each Intel-syntax operand is parsed (`parseOperand`) into a typed `Operand`
(`Reg`/`Imm`/`Mem`/`Sym`), stripping size keywords (`byte/word/dword/qword/xmmword
ptr`) and `fs:`/`gs:` segment overrides. Registers are canonicalized to a 16-entry
index via `regTable()` so all sub-registers alias one location (`eax`/`ax`/`al`
all map to `RAX`), tracking width (8/4/2/1) and the `ah/bh/ch/dh` high-byte case.
Memory operands (`parseMem`) are decomposed into base/index*scale/disp with
rip-relative and disp-only flags. `[rbp/rsp ± disp]` slots with no index become
**tracked stack locations** (`stackLoc`), the basis for named locals.

#### Naming, propagation, and the value environment

Each block is lifted in isolation by `liftBlock`, maintaining an `Env` of
location→`Val` (an expression plus the variable names it reads and the locations
it depends on). Reading a tracked location returns its cached, propagated
expression — this is **intra-block constant/copy propagation**. Writes
(`emitDef`) record a new `Val`; `killDep`/`killMemory`/`killStackSlots`
invalidate cached values when their inputs change, a memory store happens, or a
`call` clobbers volatile registers and may alias a passed `&local`. Names come
from `nameOf`: arguments get `a1..aN`, register temporaries `v1, v2, …`, stack
slots `local_0, local_1, …`.

Width matters for correctness: a 32-bit write zero-extends, so it is a full
definition (propagatable); an 8/16-bit write is a read-modify-write rendered with
`LOBYTE`/`LOWORD`/`BYTE1` so the surviving upper bits aren't lost. Calls assign
`rax` and clobber the Win64 volatile set.

#### Argument detection

`detectArgs` scans the prologue linearly until the first `ret` and flags Win64
argument registers (`rcx, rdx, r8, r9`) that are **read before being written**
(self-zeroing `xor x,x`/`sub x,x` don't count as reads; registers inside memory
operands always count). Args are contiguous, so if a later register is an arg the
earlier ones are named too. This mirrors the UI's `guessSignature` so the arg
count matches the emitted header.

#### Dead-assignment elimination (live-variable analysis)

`eliminateDead` runs a standard **iterative backward live-variable analysis** over
the whole CFG (gen/kill per block, `liveOut = ∪ liveIn(succ)`, seeded at returns
with the variables a return reads). A backward sweep then deletes any non-side-
effecting assignment whose destination is dead, and — crucially — strips the
dead *result* of a `call` (turning `v3 = foo();` into `foo();`) while keeping the
call itself. Stores and calls (`side == true`) are never removed.

#### Type inference, return recovery, declarations

Types are inferred heuristically: a name used as a memory base is a `void *`
(`ptr_`); otherwise width ≤ 4 ⇒ `int`, else `__int64`. Only locals/temps
(`local_*`, `v<digit>*`) get declarations, emitted in first-appearance order at
the top of the function body. **Return-value recovery**: if `rax` is ever
assigned, each `return` reports `rax`'s value — the inlined propagated expression
when known (`return v3 + 1;`), else the variable name (`return v3;`); otherwise a
bare `return;`. The static Pseudocode view prefixes the result with
`// signature is heuristic (no full type recovery)`.

### User-facing surface

The decompiler appears in the **Binary View** tab as the **Pseudocode** main-view
radio (`mainView_ == 1`, `renderPseudocode`), alongside Assembly / Hex / Graph /
Call Graph / Live Assembly. It also drives the **Live Assembly → Pseudocode**
panel (`renderLivePseudocode`) for the running debuggee, which reads memory
masked for `0xCC` breakpoints and decodes with the debuggee-bitness decoder.

- The static view shows a `Refresh` button and explanatory disabled text
  ("if/else + while recovery via dominator analysis; goto fallback for irreducible
  flow"), then a read-only multiline box so the output can be selected and copied;
  the live view adds `Copy`.
- It decompiles the **function enclosing the cursor** (via `funcContaining`), not
  just the window under it, capped at a sensible window (`fnSize + 16`, ≤ 16 KB,
  else 4 KB). Results are cached per function start (`decompVA_` / `pseudoVA_`) and
  invalidated when the function changes, on rename, or on relevant edits.
- The view participates in the broader analysis: `nameFor`/`dataRefFor` pull in
  user renames, imports, and string literals, so renaming a function in the
  listing immediately improves the pseudocode (`decompVA_ = 0` invalidation).

### Performance characteristics

All passes are near-linear in instruction count for typical functions: dominators
iterate to a fixpoint over RPO, liveness to a fixpoint over blocks, and the
structurer emits each block roughly once (label-discovery + emit = two passes).
CFG construction is capped (`maxInsns = 2000`) and the structurer truncates past
100,000 emitted blocks. Output is cached per function, so scrolling the cursor
within a function is free. There is no whole-program decompile pass at idle; the
exported "Report" path decompiles the analyst's named functions on demand with a
cap to keep large rename sets fast.

#### Limitations & notes

- **Not a full decompiler.** No SSA, no global/inter-procedural type recovery, no
  cross-block value propagation (propagation is intra-block only), no stack-frame
  reconstruction beyond `[rbp/rsp ± disp]` slot naming. Output is explicitly
  labelled heuristic.
- **Argument/signature/return guesses are best-effort** and **x86/x64-only**
  (`guessSignature` returns `""` for other arches; `detectArgs` assumes the Win64
  ABI). The SysV path exists only in the UI's `guessSignature` arg-count estimate.
- High-half results of `mul`/`div`, the FPU/SSE/vector domain, and the stack
  (`push`/`pop`) are not modelled; unmodelled instructions are preserved verbatim
  as `__asm { … };` so nothing is dropped, but they read as opaque.
- Irreducible flow falls back to **labelled `goto`s** by design; deeply
  unstructured functions will contain `loc_<addr>:` labels rather than clean
  nesting.
- `for`-loop reconstruction is a conservative textual rewrite that only fires on an
  exact, jump-free shape; everything else stays a `while`.
- The data-flow pass is gated by `deepDataFlow` (default on); turning it off, or
  any internal failure, transparently yields the simpler register-level lift.
