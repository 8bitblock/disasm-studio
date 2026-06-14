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

    // The argument detection (Win64 register / x86 stack-slot) assumes x86/x64
    // semantics; on other arches an ARM/MIPS register name can collide with the x86
    // register table and produce spurious parameters. The caller sets this false for
    // non-x86 targets so the emitted header doesn't list bogus args. Default true keeps
    // the common (x86/x64) path and existing tests unchanged.
    bool x86 = true;

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

// Decompilation result with a per-line source map. `lineVA[i]` is the VA of the
// instruction (legacy lift) or basic block (deep data-flow path, which merges /
// eliminates statements so only block granularity survives) that produced line i
// of `text`; 0 marks synthetic lines (function header, braces, declarations).
// Lines are `text` split on '\n'; the empty segment after the trailing '\n' is
// not counted, so lineVA.size() == the number of real lines.
struct DecompResult {
    std::string           text;
    std::vector<uint64_t> lineVA;
};

// Produce structured pseudo-C for the function described by `g`, with the
// per-line VA map (backs pseudocode <-> assembly navigation in the UI).
DecompResult DecompileWithMap(const ControlFlowGraph& g, const DecompileOptions& opt = {});

// Produce structured pseudo-C for the function described by `g`.
// Exactly DecompileWithMap(g, opt).text.
std::string Decompile(const ControlFlowGraph& g, const DecompileOptions& opt = {});

// Translate a pseudo-C DecompResult (from DecompileWithMap) into Python-style
// pseudocode: def/if/elif/else/while True/match with `:` + indentation instead
// of braces, `#` comments, `and`/`or`/`not`, `//` integer division, `mem[...]`
// for dereferences, x += 1 for x++, swap -> tuple assignment. Unstructurable
// flow keeps explicit `goto loc_X` pseudo-statements (labels become `# loc_X:`).
// A pure text transform over the structured C output — the C emission (and its
// byte-identical guarantee) is untouched — that preserves the per-line VA map:
// the result carries its own parallel lineVA (lines are added/dropped, e.g.
// braces vanish and a for-loop's step is re-materialized at the body's end).
DecompResult DecompileToPython(const DecompResult& c);

} // namespace ds
