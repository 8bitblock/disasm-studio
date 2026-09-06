//
// PathExplore.cpp — see PathExplore.h. Pure-Core F3 tree/tagging/solve logic.
//
#include "PathExplore.h"

namespace ds {

const char* PathTagName(PathTag t) {
    switch (t) {
        case PathTag::Safe:        return "Safe";
        case PathTag::IntOverflow: return "IntOverflow";
        case PathTag::HiddenCode:  return "HiddenCode";
        case PathTag::Escaped:     return "Escaped";
    }
    return "?";
}

bool DependsOnInput(const ExprRef& e) {
    if (!e) return false;
    if (e->op == ExprOp::Var) return true;
    for (const auto& k : e->kids) if (DependsOnInput(k)) return true;
    return false;
}

// 1-bit logical negation of a predicate (p ^ 1).
static ExprRef NotPred(const ExprRef& p) { return Un(ExprOp::Not, p, 1); }

// Is this path (its constraint conjunction) satisfiable? Empty => trivially yes.
static bool PathSat(const std::vector<PathConstraint>& pcs, ISolver& solver) {
    if (pcs.empty()) return true;
    std::vector<VarBinding> model;
    return solver.solveForInput(pcs, model);
}

// Tag a node from the properties of its block terminator + reachability + feasibility.
static PathTag Classify(uint64_t blockVA, const BranchInfo& bi,
                        const std::vector<PathConstraint>& pcs,
                        ISymCfg& cfg, ISolver& solver) {
    if (bi.kind == BranchInfo::Escape) return PathTag::Escaped;
    if (!cfg.isStaticallyReached(blockVA) || !cfg.inAnyFunction(blockVA))
        return PathTag::HiddenCode;
    if (bi.overflowFeasible && PathSat(pcs, solver)) return PathTag::IntOverflow;
    return PathTag::Safe;
}

PathTree Explore(uint64_t rootVA, ISymCfg& cfg, ISolver& solver, const ExploreConfig& cfg2) {
    PathTree t;
    PathNode root;
    root.blockVA = rootVA;
    t.nodes.push_back(root);

    std::vector<int> work = { 0 };
    while (!work.empty()) {
        const int idx = work.back();
        work.pop_back();

        if (t.nodes[idx].depth >= cfg2.maxDepth) { t.truncated = true; continue; }

        // Read a snapshot of this node's reach-constraints (copy: the vector may realloc).
        const uint64_t blockVA = t.nodes[idx].blockVA;
        const std::vector<PathConstraint> path = t.nodes[idx].pathConstraints;
        const uint32_t depth = t.nodes[idx].depth;

        BranchInfo bi = cfg.blockTerminator(blockVA, path);
        t.nodes[idx].tag = Classify(blockVA, bi, path, cfg, solver);

        auto addChild = [&](uint64_t tgt, ExprRef edgePred, bool taken,
                            std::vector<PathConstraint> pc, bool leaf) -> void {
            if (t.nodes.size() >= cfg2.maxNodes) { t.truncated = true; return; }
            PathNode c;
            c.blockVA = tgt;
            c.edgePred = edgePred;
            c.taken = taken;
            c.depth = depth + 1;
            c.pathConstraints = std::move(pc);
            const int ci = (int)t.nodes.size();
            t.nodes.push_back(std::move(c));
            t.nodes[idx].children.push_back(ci);
            if (!leaf) work.push_back(ci);
        };

        switch (bi.kind) {
            case BranchInfo::Return:
            case BranchInfo::Escape:
                break;  // leaf
            case BranchInfo::Fallthrough:
            case BranchInfo::Jump:
                if (!bi.targetAValid) { t.nodes[idx].tag = PathTag::Escaped; break; }
                addChild(bi.targetA, nullptr, true, path, /*leaf*/false);
                break;
            case BranchInfo::CondBranch: {
                if (!bi.targetAValid || !bi.targetBValid) {
                    t.nodes[idx].tag = PathTag::Escaped;
                    break;
                }
                if (DependsOnInput(bi.pred)) {
                    // FORK both feasible sides, accumulating the branch predicate.
                    std::vector<PathConstraint> pcA = path;
                    pcA.push_back({ bi.pred, true, blockVA, bi.targetA });
                    std::vector<PathConstraint> pcB = path;
                    ExprRef np = NotPred(bi.pred);
                    pcB.push_back({ np, false, blockVA, bi.targetB });
                    if (PathSat(pcA, solver)) addChild(bi.targetA, bi.pred, true, pcA, false);
                    if (PathSat(pcB, solver)) addChild(bi.targetB, np, false, pcB, false);
                } else {
                    // Concrete condition: follow only the side it selects.
                    uint64_t v = 0;
                    const bool taken = EvalConst(bi.pred, v) ? (v != 0) : true;
                    addChild(taken ? bi.targetA : bi.targetB, nullptr, taken, path, false);
                }
                break;
            }
        }
    }
    return t;
}

bool SolvePath(const PathTree& tree, int nodeIndex, ISolver& solver, std::vector<VarBinding>& model) {
    if (nodeIndex < 0 || nodeIndex >= (int)tree.nodes.size()) return false;
    return solver.solveForInput(tree.nodes[nodeIndex].pathConstraints, model);
}

} // namespace ds
