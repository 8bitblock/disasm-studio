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
};

// Produce structured pseudo-C for the function described by `g`.
std::string Decompile(const ControlFlowGraph& g, const DecompileOptions& opt = {});

} // namespace ds
