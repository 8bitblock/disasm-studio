#pragma once
//
// PathExplore.h
// F3 "predictive look-ahead path explorer": from a paused state, explore the code
// ahead as a bounded path TREE, forking at input-dependent conditionals, tagging
// leaves (Safe / IntOverflow / HiddenCode / Escaped), and solving a chosen path's
// constraints into a concrete input. NOT thousands of OS forks — an in-emulator
// symbolic-state tree (the only feasible model on Windows). Pure-Core: the per-block
// terminator + reachability come through the ISymCfg facade (the Triton/CFG-backed
// implementation lives elsewhere), so the tree/tagging/solve logic is mock-tested.
//
#include "ExprAst.h"
#include "SymEngine.h"   // PathConstraint, ISolver, VarBinding

#include <cstdint>
#include <string>
#include <vector>

namespace ds {

enum class PathTag { Safe, IntOverflow, HiddenCode, Escaped };

const char* PathTagName(PathTag t);

// How a block ends, as seen by the symbolic explorer at the current state.
struct BranchInfo {
    enum Kind { Fallthrough, Jump, CondBranch, Return, Escape } kind = Return;
    uint64_t targetA = 0;   // fallthrough / jump / taken target
    uint64_t targetB = 0;   // not-taken target (CondBranch only)
    bool     targetAValid = false; // target addresses may legitimately be VA 0
    bool     targetBValid = false;
    ExprRef  pred;          // 1-bit predicate (CondBranch); may or may not depend on input
    bool     overflowFeasible = false; // block has an add/sub/mul that can exceed its width
};

// The symbolic view of the program the explorer walks. A mock implements it for tests;
// the real one is backed by SymEngine stepping + ds::BuildCFG + FunctionAnalyzer.
class ISymCfg {
public:
    virtual ~ISymCfg() = default;
    // The terminator of the block at `blockVA`, given the constraints accumulated so far.
    virtual BranchInfo blockTerminator(uint64_t blockVA, const std::vector<PathConstraint>& path) = 0;
    virtual bool isStaticallyReached(uint64_t va) = 0; // false => candidate "hidden code"
    virtual bool inAnyFunction(uint64_t va) = 0;       // false => candidate "hidden code"
};

struct PathNode {
    uint64_t blockVA = 0;
    ExprRef  edgePred;       // predicate that held to enter this node (null at root)
    bool     taken = true;
    uint32_t depth = 0;
    PathTag  tag = PathTag::Safe;
    std::vector<PathConstraint> pathConstraints; // full conjunction to reach this node
    std::vector<int>            children;        // indices into PathTree::nodes
};

struct PathTree {
    std::vector<PathNode> nodes;     // nodes[0] is the root
    bool truncated = false;          // a depth/node budget was hit
};

struct ExploreConfig {
    uint32_t maxDepth = 32;
    uint32_t maxNodes = 512;
};

// Build the bounded path tree rooted at `rootVA`. `solver` is used to prune infeasible
// branches and to gate the IntOverflow tag (overflow only matters on a reachable path).
PathTree Explore(uint64_t rootVA, ISymCfg& cfg, ISolver& solver, const ExploreConfig& cfg2);

// Solve a node's accumulated constraints into a concrete input model (or false if none).
bool SolvePath(const PathTree& tree, int nodeIndex, ISolver& solver, std::vector<VarBinding>& model);

// True if `e` references any symbolic Var (i.e. depends on input).
bool DependsOnInput(const ExprRef& e);

} // namespace ds
