#pragma once
//
// DataFlow.h
// A lightweight data-flow pre-pass for the decompiler. It parses each
// instruction's Intel-syntax operand text into a typed operand model, lifts the
// function to named pseudo-C with constant/copy propagation, removes dead
// assignments via live-variable analysis, and infers local variable types. The
// existing Decompiler structurer consumes the per-block statement lists + the
// terminator flag state, so control-flow structuring (dominators / loops /
// if-else / switch) is unchanged. Anything that doesn't parse degrades to the
// original string-lift so no instruction is ever lost.
//
#include "CFG.h"
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ds {

// What an instruction did to the flags, so a following Jcc reads as a real
// condition. Shared with Decompiler.cpp's condString(); `lhs`/`rhs` carry the
// named/propagated operands the data-flow pass resolved.
enum class CmpKind { None, Cmp, TestZero, TestAnd, ArithZero };
struct FlagState { CmpKind kind = CmpKind::None; std::string lhs, rhs; };

// A reconstructed for-loop triple for a loop header block (Stage 4). When set,
// the emitter prints `for (init; cond; step)` and suppresses the duplicated
// init/step lines.
struct DfForLoop {
    bool        isFor = false;
    std::string init, cond, step;
};

struct DataFlowResult {
    bool                                  ok = false;     // false => caller uses the legacy lift
    std::vector<std::vector<std::string>> blockStmts;     // body statements per block (no terminator)
    std::vector<FlagState>                termFlag;       // flags feeding each block's terminator
    std::vector<std::string>              decls;          // inferred local declarations
    std::vector<std::string>              retExpr;        // per block: `return <expr>` text ("" => bare return)
    std::unordered_map<int, DfForLoop>    forLoops;       // header block index -> for-loop triple
    std::vector<std::string>              args;           // detected parameter names a1..aN (for the function header)
};

// Analyze a function CFG and produce named, propagated, type-annotated pseudo-C
// per basic block. `nameFor` resolves a call/branch target VA to a display name;
// `dataRefFor` resolves a constant data address to a string/import/global token.
DataFlowResult AnalyzeDataFlow(const ControlFlowGraph& g,
                               const std::function<std::string(uint64_t)>& nameFor,
                               const std::function<std::string(uint64_t)>& dataRefFor = {});

} // namespace ds
