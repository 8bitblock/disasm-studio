#pragma once
//
// DataFlow.h
// A lightweight data-flow pre-pass for the decompiler. It consumes the
// decoder's typed operands (with a text-only compatibility fallback for test /
// legacy decoders), lifts the
// function to named pseudo-C with constant/copy propagation, removes dead
// assignments via live-variable analysis, and infers local variable types. The
// existing Decompiler structurer consumes the per-block statement lists + the
// terminator flag state, so control-flow structuring (dominators / loops /
// if-else / switch) is unchanged. Anything that doesn't parse degrades to the
// original string-lift so no instruction is ever lost.
//
#include "CFG.h"
#include "InstructionSemantics.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ds {

// x86 condition flags have independent lifetimes.  In particular INC/DEC
// preserve CF while replacing ZF/SF/OF, so one aggregate "last comparison"
// record can silently attach an unsigned branch to the wrong instruction.
enum class CmpKind { None, Cmp, TestZero, TestAnd, LogicResult, AddResult,
                     SubResult, IncResult, DecResult, NegResult };
enum class X86Flag : uint8_t { Carry, Zero, Sign, Overflow, Parity, Count };

constexpr uint8_t X86FlagBit(X86Flag flag) {
    return static_cast<uint8_t>(1u << static_cast<uint8_t>(flag));
}
constexpr uint8_t kX86FlagCF = X86FlagBit(X86Flag::Carry);
constexpr uint8_t kX86FlagZF = X86FlagBit(X86Flag::Zero);
constexpr uint8_t kX86FlagSF = X86FlagBit(X86Flag::Sign);
constexpr uint8_t kX86FlagOF = X86FlagBit(X86Flag::Overflow);
constexpr uint8_t kX86FlagPF = X86FlagBit(X86Flag::Parity);
constexpr uint8_t kX86TrackedFlags = kX86FlagCF | kX86FlagZF | kX86FlagSF |
                                     kX86FlagOF | kX86FlagPF;

struct FlagProvenance {
    CmpKind kind = CmpKind::None;
    std::string lhs, rhs;
    // Width of the value that produced the flags. Zero means the decoder did
    // not report one. Signed/unsigned Jcc rendering must use this width rather
    // than silently widening every comparison to 64 bits.
    uint16_t widthBits = 0;
    // Variables whose definitions must remain live until a consuming branch,
    // setcc, or cmovcc. `valid` is cleared when this particular flag is
    // overwritten or becomes unknown.
    std::vector<std::string> reads;
    // Machine locations used by lhs/rhs (canonical register/stack ids plus
    // "MEM" for an untracked load). A flag can outlive its producer, but its
    // printable expression cannot outlive a mutation of one of these inputs.
    std::vector<std::string> dependencies;
    bool valid = false;

    bool sameOrigin(const FlagProvenance& other) const {
        return valid && other.valid && kind == other.kind && lhs == other.lhs &&
               rhs == other.rhs && widthBits == other.widthBits;
    }
};

struct FlagState {
    std::array<FlagProvenance, static_cast<size_t>(X86Flag::Count)> flags{};

    FlagState() = default;

    const FlagProvenance& get(X86Flag flag) const {
        return flags[static_cast<size_t>(flag)];
    }
    void clear(uint8_t mask = kX86TrackedFlags) {
        for (size_t i = 0; i < flags.size(); ++i)
            if (mask & static_cast<uint8_t>(1u << i)) flags[i] = {};
    }
    void write(uint8_t mask, CmpKind kind, const std::string& lhs,
               const std::string& rhs = {},
               const std::vector<std::string>& dependencies = {},
               uint16_t width = 0,
               const std::vector<std::string>& expressionDependencies = {}) {
        FlagProvenance value;
        value.kind = kind;
        value.lhs = lhs;
        value.rhs = rhs;
        value.widthBits = width;
        value.reads = dependencies;
        value.dependencies = expressionDependencies;
        value.valid = kind != CmpKind::None;
        for (size_t i = 0; i < flags.size(); ++i)
            if (mask & static_cast<uint8_t>(1u << i)) flags[i] = value;
    }
    void invalidateDependency(const std::string& dependency) {
        for (FlagProvenance& flag : flags) {
            if (!flag.valid) continue;
            if (std::find(flag.dependencies.begin(), flag.dependencies.end(), dependency) !=
                flag.dependencies.end())
                flag = {};
        }
    }
    void invalidateDependencyPrefix(const std::string& prefix) {
        for (FlagProvenance& flag : flags) {
            if (!flag.valid) continue;
            const bool matches = std::any_of(flag.dependencies.begin(), flag.dependencies.end(),
                [&](const std::string& dependency) { return dependency.rfind(prefix, 0) == 0; });
            if (matches) flag = {};
        }
    }
    std::vector<std::string> allReads() const {
        std::vector<std::string> result;
        for (const FlagProvenance& flag : flags) {
            if (!flag.valid) continue;
            for (const std::string& read : flag.reads)
                if (std::find(result.begin(), result.end(), read) == result.end())
                    result.push_back(read);
        }
        return result;
    }
};

// Shared by the deep data-flow lifter and the lightweight register-level
// lifter. Missing provenance is rendered as the explicit raw Jcc predicate;
// it is never guessed from whichever unrelated flag happened to be newest.
std::string RenderX86Condition(const std::string& mnemonic,
                               const FlagState& flags,
                               bool negate = false);

struct DataFlowStatement {
    std::string text;
    // The instruction that produced this statement. Propagation and DCE may
    // rewrite/eliminate statements, but surviving statements retain their
    // instruction origin; VA zero is therefore valid and not a sentinel.
    uint64_t sourceVA = 0;
    bool     sourceValid = false;
};

// A reconstructed for-loop triple for a loop header block (Stage 4). When set,
// the emitter prints `for (init; cond; step)` and suppresses the duplicated
// init/step lines.
struct DfForLoop {
    bool        isFor = false;
    std::string init, cond, step;
};

struct DataFlowResult {
    bool                                  ok = false;     // false => caller uses the legacy lift
    // One typed machine operation per original instruction, including block
    // transfers and instructions removed by presentation-only DCE.
    std::vector<std::vector<IntermediateOperation>> blockOperations;
    std::vector<std::vector<DataFlowStatement>> blockStmts; // body statements per block (no terminator)
    std::vector<FlagState>                termFlag;       // flags feeding each block's terminator
    std::vector<std::string>              decls;          // inferred local declarations
    std::vector<std::string>              retExpr;        // per block: `return <expr>` text ("" => bare return)
    std::vector<std::string>              retComment;     // per block: trailing "/* = 0x.. */" when retExpr folds to a constant ("" => none)
    std::unordered_map<int, DfForLoop>    forLoops;       // header block index -> for-loop triple
    std::vector<std::string>              args;           // detected parameter names a1..aN (for the function header)
};

// Analyze a function CFG and produce named, propagated, type-annotated pseudo-C
// per basic block. `nameFor` resolves a call/branch target VA to a display name;
// `dataRefFor` resolves a constant data address to a string/import/global token.
// `recoverCallArgs` enables per-call argument recovery (Win64 register args /
// x86 push-chain args inlined at the call site); false keeps bare `callee()`.
DataFlowResult AnalyzeDataFlow(const ControlFlowGraph& g,
                               const std::function<std::string(uint64_t)>& nameFor,
                               const std::function<std::string(uint64_t)>& dataRefFor = {},
                               bool recoverCallArgs = true);

// Exact-architecture/ABI overload for new callers. Only X86/X64 and compatible
// ABI pairs are accepted;
// the four-argument form retains the historical x86/x64 bitness heuristic.
DataFlowResult AnalyzeDataFlow(const ControlFlowGraph& g,
                               const std::function<std::string(uint64_t)>& nameFor,
                               const std::function<std::string(uint64_t)>& dataRefFor,
                               bool recoverCallArgs,
                               Arch targetArch,
                               DecompileABI targetABI = DecompileABI::Auto);

} // namespace ds
