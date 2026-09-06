#pragma once
//
// Decompiler.h
// A lightweight in-house structuring pass: turns a function's control-flow
// graph (basic blocks from CFG.h) into structured pseudo-C. It recovers
// if/else and while/do-while using dominator + immediate-post-dominator
// analysis and natural-loop detection, lifts each instruction to a C-like
// statement, and falls back to labelled gotos for irreducible flow (exactly as
// production decompilers do). This is not a full data-flow decompiler - there
// is no type recovery or expression propagation - but it produces real,
// per-binary structured output instead of a fixed template.
//
#include "CFG.h"
#include <functional>
#include <string>

namespace ds {

struct DecompileTarget {
    Arch         architecture = Arch::X64;
    DecompileABI abi = DecompileABI::Unknown;
};

struct DecompileOptions {
    // Resolve a call/jump target VA to a display name (e.g. "kernel32.CreateFileW"
    // or a user rename). Return "" to fall back to sub_<addr>.
    std::function<std::string(uint64_t)> nameFor;

    // Resolve a constant DATA address to a display token: a quoted C string
    // literal (e.g. "\"hello\""), an import/global name, etc. Used to inline
    // string/data references (lea / mov-imm / [const] loads). "" => no annotation.
    std::function<std::string(uint64_t)> dataRefFor;

    // Optional inferred signature in "<rettype> (args)" form (e.g. "__int64 (a1, a2)").
    // When set, it becomes the emitted function header with the name spliced in;
    // empty falls back to "__int64 <name>()".
    std::string signature;

    // Run the data-flow pre-pass (named locals, constant/copy propagation, dead-
    // assignment elimination, type inference) instead of the raw per-instruction
    // string lift. A global kill switch / A-B fallback: with it off, output is the
    // legacy register-level lift.
    bool deepDataFlow = true;

    // Exact architecture + ABI contract. Production derives this from the loaded
    // format (PE Win64, ELF/Mach-O SysV, Raw Unknown). Tests that do not care about
    // a platform ABI retain an explicit x64/Auto default. Deep data flow is enabled
    // only for Arch::X86 and Arch::X64.
    DecompileTarget target{ Arch::X64, DecompileABI::Auto };

    // Readability post-passes that run on the emitted line/VA vectors AFTER
    // structuring + for-reconstruction and BEFORE the result is returned (deep
    // data-flow path only — the legacy register lift is left byte-identical).
    // Each preserves the per-line VA map in lockstep. Conservative by design:
    //   prettyNames  — rename obvious loop-counter temporaries (v<N> bound in a
    //                  reconstructed `for` header) to i / j / k. Never renames a
    //                  detected argument (a<N>) or a stack local (local_<N>).
    //   foldTemps    — collapse `v<N> = a OP b;` immediately followed by the sole
    //                  use of v<N> in the same block into the use site (the dead
    //                  def line and its lineVA entry are removed together).
    //   conditionGloss — append a short heuristic `/* ... */` comment to simple
    //                  relational `if (...)` conditions (e.g. "x below 16"). The
    //                  condition expression itself is unchanged; DecompileToPython
    //                  turns the gloss into a Python `#` comment.
    bool prettyNames     = true;
    bool foldTemps       = true;
    bool conditionGloss  = true;

    // Recover and inline each call's arguments (deep data-flow path only). Win64
    // integer args are read from the propagated values left in rcx/rdx/r8/r9 at
    // the call site (a contiguous run from rcx); 32-bit cdecl/stdcall args are
    // taken from the `push` chain immediately preceding the call. The arguments
    // are rendered inside the call — `printf("hello", a1)` instead of `printf()` —
    // and counted as reads so a string/value marshalled into an argument register
    // survives dead-code elimination and folds into the call site (this is what
    // makes string literals appear at the point they are passed). Heuristic by
    // nature (no callee prototypes); a clean kill switch for the legacy `f()` form.
    bool callArgs        = true;
};

enum class SourceOriginGranularity : uint8_t {
    Synthetic,
    Instruction,
    BasicBlock
};

struct SourceOrigin {
    uint64_t va = 0;
    bool     valid = false;
    SourceOriginGranularity granularity = SourceOriginGranularity::Synthetic;
};

enum class DecompileDiagnosticKind : uint8_t {
    ClippedInput,
    InstructionLimit,
    DecodeFailure,
    MissingChunk,
    TruncatedOwnership,
    Other,
};

struct DecompileDiagnostic {
    DecompileDiagnosticKind kind = DecompileDiagnosticKind::Other;
    std::string message;
};

// Decompilation result with a per-line source map. `lineVA[i]` is retained for
// compatibility; `lineOrigins[i]` is authoritative and can distinguish an
// instruction at VA zero from a synthetic line. An origin identifies the
// instruction that produced line i. Deep propagation/folding/DCE carries the
// surviving statement's instruction origin; structural labels/gotos may retain
// basic-block granularity, and generated scaffolding is explicitly synthetic.
// of `text`; legacy lineVA still uses 0 for both synthetic lines and real VA zero.
// Lines are `text` split on '\n'; the empty segment after the trailing '\n' is
// not counted, so lineVA.size() == the number of real lines.
struct DecompResult {
    std::string           text;
    std::vector<uint64_t> lineVA;
    std::vector<SourceOrigin> lineOrigins;
    bool                  complete = true;
    std::string           incompleteReason;
    std::vector<DecompileDiagnostic> diagnostics;
};

// Produce structured pseudo-C for the function described by `g`, with the
// per-line VA map (backs pseudocode <-> assembly navigation in the UI).
DecompResult DecompileWithMap(const ControlFlowGraph& g, const DecompileOptions& opt = {});

DecompResult DecompileWithMap(const std::vector<CFGCodeChunk>& chunks,
                              IDisassembler& dis,
                              const DecompileOptions& opt = {},
                              size_t maxInsns = 2000,
                              const JumpTableResolver& resolveTable = {},
                              const NoreturnCallResolver& isNoreturnCall = {},
                              const DirectTargetResolver& resolveDirectTarget = {});

// Produce structured pseudo-C for the function described by `g`.
// Exactly DecompileWithMap(g, opt).text.
std::string Decompile(const ControlFlowGraph& g, const DecompileOptions& opt = {});

std::string Decompile(const std::vector<CFGCodeChunk>& chunks,
                      IDisassembler& dis,
                      const DecompileOptions& opt = {},
                      size_t maxInsns = 2000,
                      const JumpTableResolver& resolveTable = {},
                      const NoreturnCallResolver& isNoreturnCall = {},
                      const DirectTargetResolver& resolveDirectTarget = {});

// Translate a pseudo-C DecompResult (from DecompileWithMap) into source-oriented
// Python pseudocode: def/if/elif/else/while True/match with indentation, `range`
// for conservatively proven induction loops, Python Boolean/None identity,
// `#` comments, `and`/`or`/`not`, fixed-width sN/uN integer conversions,
// `mem[...]` for native dereferences, x += 1 for x++, and tuple assignment for
// swaps. Native TEST/CMP zero comparisons stay explicit (`x == 0` / `x != 0`)
// so branch intent remains visible. Partial-register writes become full-variable
// mask/shift assignments.
// Unstructurable direct flow keeps a `goto_label("loc_X")` placeholder (the
// target label is a `# loc_X:` marker); computed flow uses
// `indirect_jump(expression)`. Both remain valid Python syntax without
// pretending that Python has native goto semantics.
// A pure text transform over the structured C output — the C emission (and its
// byte-identical guarantee) is untouched — that preserves the per-line VA map:
// the result carries its own parallel lineVA (lines are added/dropped, e.g.
// braces vanish and a for-loop's step is re-materialized at the body's end).
DecompResult DecompileToPython(const DecompResult& c);

} // namespace ds
