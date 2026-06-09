//
// PathExploreJob.cpp — see PathExploreJob.h. Structural (engine-free) path explorer
// backed by BuildCFG; the symbolic-engine version layers richer tags + input solving.
//
#include "PathExploreJob.h"
#include "CFG.h"
#include "BinaryFile.h"
#include "SymEngine.h"   // ISolver

#include <unordered_map>
#include <utility>

namespace ds {
namespace {

// For STRUCTURAL exploration every CFG edge is reachable by construction, so the
// feasibility check is optimistic (avoids the bounded DefaultSolver over-pruning deep
// paths). The engine-backed explorer uses a real solver for true symbolic feasibility.
class StructuralSolver : public ISolver {
public:
    bool solveForInput(const std::vector<PathConstraint>&, std::vector<VarBinding>& m) override { m.clear(); return true; }
    ExprRef simplify(const ExprRef& e) override { return e; }
    int isSat(const ExprRef&) override { return 1; }
};

// An ISymCfg whose branch structure comes straight from a control-flow graph. Each
// conditional forks BOTH ways (a per-block symbolic predicate keeps Explore's
// input-dependent fork path active without an engine); rets/indirect jumps terminate.
class CfgSymCfg : public ISymCfg {
public:
    explicit CfgSymCfg(ControlFlowGraph cfg) : cfg_(std::move(cfg)) {
        for (size_t i = 0; i < cfg_.blocks.size(); ++i) idx_[cfg_.blocks[i].start] = i;
    }

    BranchInfo blockTerminator(uint64_t blockVA, const std::vector<PathConstraint>&) override {
        BranchInfo bi;
        auto it = idx_.find(blockVA);
        if (it == idx_.end()) { bi.kind = BranchInfo::Return; return bi; }     // off the CFG
        const BasicBlock& b = cfg_.blocks[it->second];
        if (b.isReturn)                       { bi.kind = BranchInfo::Return; return bi; }
        if (b.isSwitch || b.succ.size() > 2)  { bi.kind = BranchInfo::Escape; return bi; } // multi-way: not modeled here
        if (b.succ.empty())                   { bi.kind = BranchInfo::Return; return bi; } // tail / unresolved
        if (b.succ.size() == 1) {
            bi.kind    = b.isUncond ? BranchInfo::Jump : BranchInfo::Fallthrough;
            bi.targetA = cfg_.blocks[b.succ[0]].start;
            return bi;
        }
        bi.kind    = BranchInfo::CondBranch;
        bi.targetA = cfg_.blocks[b.succ[0]].start;
        bi.targetB = cfg_.blocks[b.succ[1]].start;
        bi.pred    = Var(blockVA, 1);   // distinct per block -> Explore forks both edges
        return bi;
    }

    bool isStaticallyReached(uint64_t va) override { return idx_.count(va) != 0; }
    bool inAnyFunction(uint64_t) override { return true; }

private:
    ControlFlowGraph cfg_;
    std::unordered_map<uint64_t, size_t> idx_;
};

} // namespace

PathTree PathExploreJob(const BinaryFile& bin, IDisassembler& dis, Arch /*arch*/, uint64_t rootVA,
                        const ExploreConfig& cfg) {
    PathTree empty;
    size_t avail = 0;
    const uint8_t* p = bin.ptrFromVA(rootVA, avail);
    if (!p || avail == 0) return empty;

    ControlFlowGraph g = BuildCFG(p, avail, rootVA, dis, 2000);
    if (g.blocks.empty()) return empty;

    CfgSymCfg sc(std::move(g));
    StructuralSolver solver;
    return Explore(rootVA, sc, solver, cfg);
}

} // namespace ds
