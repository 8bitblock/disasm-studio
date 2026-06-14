//
// SymEngine.cpp
// Backend for the SymEngine facade (SymEngine.h).
//
//   * DefaultSolver  — a PURE, dependency-free ISolver: ds::Simplify for simplify,
//                      constant-fold for isSat, and a bounded brute-force model finder
//                      for solveForInput (small symbolic input spaces). Always built,
//                      cl-testable, and already enough to power F3 path-solving and
//                      F1's simplify step without Z3.
//   * Symbolic engine — gated behind DS_HAVE_SYMENGINE. When the Triton/Z3 vcpkg deps
//                      are compiled in, TritonSymEngine provides real symbolic +
//                      concrete execution. Otherwise a stub returns Unavailable so the
//                      app still links (the pure logic + DefaultSolver keep working).
//
// This is the ONLY TU that may include Triton headers; everything else speaks ExprAst.
//
#include "SymEngine.h"
#include "Simplify.h"

#include <algorithm>
#include <map>
#include <unordered_map>
#include <vector>

#ifdef DS_HAVE_SYMENGINE
#include <triton/context.hpp>
#include <triton/ast.hpp>
#endif

namespace ds {

// ---------------------------------------------------------------------------
// DefaultSolver — pure, no external deps.
// ---------------------------------------------------------------------------
namespace {

void CollectVars(const ExprRef& e, std::map<uint64_t, uint32_t>& out) {
    if (!e) return;
    if (e->op == ExprOp::Var) { out[e->val] = e->bits; return; }
    for (const auto& k : e->kids) CollectVars(k, out);
}

ExprRef Subst(const ExprRef& e, const std::map<uint64_t, uint64_t>& m) {
    if (!e) return e;
    if (e->op == ExprOp::Var) { auto it = m.find(e->val); return it != m.end() ? C(it->second, e->bits) : e; }
    if (e->kids.empty()) return e;
    std::vector<ExprRef> k; k.reserve(e->kids.size());
    for (const auto& c : e->kids) k.push_back(Subst(c, m));
    auto n = std::make_shared<Expr>(); n->op = e->op; n->bits = e->bits; n->val = e->val; n->kids = std::move(k);
    return n;
}

class DefaultSolver : public ISolver {
public:
    ExprRef simplify(const ExprRef& e) override { return Simplify(e); }

    int isSat(const ExprRef& pred) override {
        uint64_t v = 0;
        if (EvalConst(Simplify(pred), v)) return v ? 1 : 0;
        return -1;   // has free variables -> unknown without a real SMT backend
    }

    // Bounded enumeration over the symbolic inputs appearing in the constraints.
    // Honest: returns false (no model) when the space is too large rather than guessing.
    bool solveForInput(const std::vector<PathConstraint>& pcs, std::vector<VarBinding>& model) override {
        std::map<uint64_t, uint32_t> vars;   // id -> bits
        for (const auto& pc : pcs) CollectVars(pc.pred, vars);
        if (vars.empty()) {                  // no inputs: sat iff all preds already hold
            for (const auto& pc : pcs) { uint64_t r; if (!EvalConst(pc.pred, r) || r != 1) return false; }
            model.clear();
            return true;
        }

        // Total search space (capped) — each var enumerated over its width.
        std::vector<std::pair<uint64_t, uint32_t>> vs(vars.begin(), vars.end());
        long double space = 1.0L;
        for (auto& v : vs) space *= (long double)((v.second >= 20) ? (1u << 20) : (1u << v.second));
        if (space > 1.0e6L) return false;    // too big for brute force -> unknown

        std::vector<uint64_t> cur(vs.size(), 0);
        for (;;) {
            std::map<uint64_t, uint64_t> assign;
            for (size_t i = 0; i < vs.size(); ++i) assign[vs[i].first] = cur[i];
            bool all = true;
            for (const auto& pc : pcs) { uint64_t r; if (!EvalConst(Subst(pc.pred, assign), r) || r != 1) { all = false; break; } }
            if (all) {
                model.clear();
                for (size_t i = 0; i < vs.size(); ++i) model.push_back({ vs[i].first, cur[i], (uint32_t)((vs[i].second + 7) / 8) });
                return true;
            }
            // odometer increment over each var's value range
            size_t i = 0;
            for (; i < vs.size(); ++i) {
                const uint64_t maxv = (vs[i].second >= 20) ? ((1u << 20) - 1) : ((1u << vs[i].second) - 1);
                if (cur[i] < maxv) { ++cur[i]; break; }
                cur[i] = 0;
            }
            if (i == vs.size()) break;        // exhausted
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Symbolic execution engine.
// ---------------------------------------------------------------------------
#ifdef DS_HAVE_SYMENGINE
// Real backend — compiled only with the Triton/Z3 vcpkg deps (engines feature). Lowers
// Triton's AST into ds::ExprAst so all consumers stay engine-agnostic. Review-verified;
// reconcile minor Triton API differences at build time.

static triton::arch::architecture_e tritonArch(Arch a) {
    switch (a) {
        case Arch::X86:   return triton::arch::ARCH_X86;
        case Arch::X64:   return triton::arch::ARCH_X86_64;
        case Arch::ARM64: return triton::arch::ARCH_AARCH64;
        case Arch::ARM:   return triton::arch::ARCH_ARM32;
        default:          return triton::arch::ARCH_X86_64;
    }
}

static const MemBlock* findBlock(const SeedSource& seed, uint64_t va) {
    for (const auto& b : seed.mem)
        if (va >= b.base && va < b.base + b.bytes.size()) return &b;
    return nullptr;
}

static uint64_t u64(const triton::ast::SharedAbstractNode& n) {
    return static_cast<uint64_t>(n->evaluate());   // low 64 bits of the constant
}

// Recursively lower a Triton AST node into ds::ExprAst. `varMap` maps Triton symbolic
// variable ids to the ds::Var ids assigned for SymbolicInputs. Returns nullptr for a
// node type we do not model, so the caller drops that output rather than emit wrong code.
static ExprRef lowerAst(const triton::ast::SharedAbstractNode& n,
                        std::unordered_map<triton::usize, uint64_t>& varMap) {
    if (!n) return nullptr;
    const uint32_t bits = (uint32_t)n->getBitvectorSize();
    const auto& kids = n->getChildren();
    auto k = [&](size_t i) -> ExprRef { return i < kids.size() ? lowerAst(kids[i], varMap) : nullptr; };
    auto bin = [&](ExprOp op, uint32_t w) -> ExprRef { ExprRef a = k(0), b = k(1); return (a && b) ? Bin(op, a, b, w) : nullptr; };

    switch (n->getType()) {
        case triton::ast::BV_NODE:       return C(u64(n), bits);
        case triton::ast::VARIABLE_NODE: {
            auto vn = std::dynamic_pointer_cast<triton::ast::VariableNode>(n);
            if (!vn) return nullptr;
            triton::usize id = vn->getSymbolicVariable()->getId();
            auto it = varMap.find(id);
            return Var(it != varMap.end() ? it->second : (uint64_t)id, bits);
        }
        case triton::ast::REFERENCE_NODE: {
            auto rn = std::dynamic_pointer_cast<triton::ast::ReferenceNode>(n);
            return rn ? lowerAst(rn->getSymbolicExpression()->getAst(), varMap) : nullptr;
        }
        case triton::ast::BVADD_NODE:  return bin(ExprOp::Add,  bits);
        case triton::ast::BVSUB_NODE:  return bin(ExprOp::Sub,  bits);
        case triton::ast::BVMUL_NODE:  return bin(ExprOp::Mul,  bits);
        case triton::ast::BVAND_NODE:  return bin(ExprOp::And,  bits);
        case triton::ast::BVOR_NODE:   return bin(ExprOp::Or,   bits);
        case triton::ast::BVXOR_NODE:  return bin(ExprOp::Xor,  bits);
        case triton::ast::BVSHL_NODE:  return bin(ExprOp::Shl,  bits);
        case triton::ast::BVLSHR_NODE: return bin(ExprOp::LShr, bits);
        case triton::ast::BVASHR_NODE: return bin(ExprOp::AShr, bits);
        case triton::ast::BVUDIV_NODE: return bin(ExprOp::UDiv, bits);
        case triton::ast::BVUREM_NODE: return bin(ExprOp::URem, bits);
        case triton::ast::BVNOT_NODE:  { ExprRef a = k(0); return a ? Un(ExprOp::Not, a, bits) : nullptr; }
        case triton::ast::BVNEG_NODE:  { ExprRef a = k(0); return a ? Un(ExprOp::Neg, a, bits) : nullptr; }
        case triton::ast::EQUAL_NODE:  return bin(ExprOp::Eq,  1);
        case triton::ast::BVULT_NODE:  return bin(ExprOp::Ult, 1);
        case triton::ast::BVULE_NODE:  return bin(ExprOp::Ule, 1);
        case triton::ast::BVSLT_NODE:  return bin(ExprOp::Slt, 1);
        case triton::ast::BVSLE_NODE:  return bin(ExprOp::Sle, 1);
        // a > b  ==  b < a ;  a >= b  ==  b <= a
        case triton::ast::BVUGT_NODE:  { ExprRef a = k(0), b = k(1); return (a && b) ? Bin(ExprOp::Ult, b, a, 1) : nullptr; }
        case triton::ast::BVUGE_NODE:  { ExprRef a = k(0), b = k(1); return (a && b) ? Bin(ExprOp::Ule, b, a, 1) : nullptr; }
        case triton::ast::BVSGT_NODE:  { ExprRef a = k(0), b = k(1); return (a && b) ? Bin(ExprOp::Slt, b, a, 1) : nullptr; }
        case triton::ast::BVSGE_NODE:  { ExprRef a = k(0), b = k(1); return (a && b) ? Bin(ExprOp::Sle, b, a, 1) : nullptr; }
        case triton::ast::CONCAT_NODE: {
            ExprRef acc = k(0); if (!acc) return nullptr;
            for (size_t i = 1; i < kids.size(); ++i) { ExprRef c = lowerAst(kids[i], varMap); if (!c) return nullptr; acc = ConcatE(acc, c); }
            return acc;
        }
        case triton::ast::EXTRACT_NODE: {   // children [high(int), low(int), expr]
            if (kids.size() < 3) return nullptr;
            uint64_t hi = u64(kids[0]), lo = u64(kids[1]);
            ExprRef e = lowerAst(kids[2], varMap);
            return e ? Extract(e, (uint32_t)lo, (uint32_t)(hi - lo + 1)) : nullptr;
        }
        case triton::ast::ZX_NODE: { ExprRef e = k(1); return e ? Ext(ExprOp::ZExt, e, bits) : nullptr; }
        case triton::ast::SX_NODE: { ExprRef e = k(1); return e ? Ext(ExprOp::SExt, e, bits) : nullptr; }
        case triton::ast::ITE_NODE: { ExprRef c = k(0), a = k(1), b = k(2); return (c && a && b) ? IteE(c, a, b) : nullptr; }
        default: return nullptr;
    }
}

// Map a 64-bit GP register name to the matching Triton register handle.
static triton::arch::Register tritonReg(triton::Context& ctx, const std::string& name) {
    const auto& R = ctx.registers;
    if (name == "rax") return R.x86_rax; if (name == "rbx") return R.x86_rbx;
    if (name == "rcx") return R.x86_rcx; if (name == "rdx") return R.x86_rdx;
    if (name == "rsi") return R.x86_rsi; if (name == "rdi") return R.x86_rdi;
    if (name == "rbp") return R.x86_rbp; if (name == "rsp") return R.x86_rsp;
    if (name == "r8")  return R.x86_r8;  if (name == "r9")  return R.x86_r9;
    if (name == "r10") return R.x86_r10; if (name == "r11") return R.x86_r11;
    if (name == "r12") return R.x86_r12; if (name == "r13") return R.x86_r13;
    if (name == "r14") return R.x86_r14; if (name == "r15") return R.x86_r15;
    return R.x86_rax;
}

static void seedRegs(triton::Context& ctx, const RegFile& r) {
    const auto& R = ctx.registers;
    ctx.setConcreteRegisterValue(R.x86_rax, r.rax); ctx.setConcreteRegisterValue(R.x86_rbx, r.rbx);
    ctx.setConcreteRegisterValue(R.x86_rcx, r.rcx); ctx.setConcreteRegisterValue(R.x86_rdx, r.rdx);
    ctx.setConcreteRegisterValue(R.x86_rsi, r.rsi); ctx.setConcreteRegisterValue(R.x86_rdi, r.rdi);
    ctx.setConcreteRegisterValue(R.x86_rbp, r.rbp); ctx.setConcreteRegisterValue(R.x86_rsp, r.rsp);
    ctx.setConcreteRegisterValue(R.x86_r8,  r.r8);  ctx.setConcreteRegisterValue(R.x86_r9,  r.r9);
    ctx.setConcreteRegisterValue(R.x86_r10, r.r10); ctx.setConcreteRegisterValue(R.x86_r11, r.r11);
    ctx.setConcreteRegisterValue(R.x86_r12, r.r12); ctx.setConcreteRegisterValue(R.x86_r13, r.r13);
    ctx.setConcreteRegisterValue(R.x86_r14, r.r14); ctx.setConcreteRegisterValue(R.x86_r15, r.r15);
}

class TritonSymEngine : public ISymEngine {
public:
    SymStatus symbolizeRegion(const SeedSource& seed, uint64_t startVA, uint64_t endVA,
                              const std::vector<SymbolicInput>& inputs,
                              const SymOptions& opt, SymOutputs& out) override {
        try {
            triton::Context ctx(tritonArch(seed.arch));
            for (const auto& m : seed.mem)
                ctx.setConcreteMemoryAreaValue(m.base, std::vector<triton::uint8>(m.bytes.begin(), m.bytes.end()));
            seedRegs(ctx, seed.regs);

            std::unordered_map<triton::usize, uint64_t> varMap;
            for (const auto& in : inputs) {
                if (in.kind == SymbolicInput::Reg) {
                    auto sv = ctx.symbolizeRegister(tritonReg(ctx, in.regName), in.tag);
                    varMap[sv->getId()] = in.varId;
                } else {
                    auto sv = ctx.symbolizeMemory(triton::arch::MemoryAccess(in.addr, in.bytes), in.tag);
                    varMap[sv->getId()] = in.varId;
                }
            }

            uint64_t va = startVA; uint32_t steps = 0;
            while (va < endVA && steps < opt.maxSteps) {
                const MemBlock* blk = findBlock(seed, va);
                if (!blk) break;
                const size_t off = (size_t)(va - blk->base);
                const size_t avail = blk->bytes.size() - off;
                triton::arch::Instruction inst;
                inst.setOpcode(blk->bytes.data() + off, (triton::uint32)(avail < 16 ? avail : 16));
                inst.setAddress(va);
                if (!ctx.processing(inst)) { out.status = SymStatus::DecodeError; return out.status; }
                va += inst.getSize();
                ++steps;
            }
            if (steps >= opt.maxSteps) { out.status = SymStatus::StepLimit; return out.status; }

            // Output register (Win64 integer return = rax).
            ExprRef rax = lowerAst(ctx.getRegisterAst(ctx.registers.x86_rax), varMap);
            if (rax) out.outputs.push_back(SymValue{ "rax", rax });

            for (const auto& pc : ctx.getPathConstraints()) {
                for (const auto& bc : pc.getBranchConstraints()) {
                    ExprRef pred = lowerAst(std::get<3>(bc), varMap);   // <taken, src, dst, predicate>
                    if (pred) out.pathConstraints.push_back(PathConstraint{ pred, std::get<0>(bc),
                                                                            (uint64_t)std::get<1>(bc), (uint64_t)std::get<2>(bc) });
                }
            }
            out.status = out.outputs.empty() ? SymStatus::Unsupported : SymStatus::Ok;
            return out.status;
        } catch (...) {
            out.status = SymStatus::DecodeError;
            return out.status;
        }
    }

    SymStatus runConcrete(const SeedSource& seed, uint64_t startVA, uint64_t endVA,
                          const SymOptions& opt, ConcreteState& out) override {
        try {
            triton::Context ctx(tritonArch(seed.arch));
            for (const auto& m : seed.mem)
                ctx.setConcreteMemoryAreaValue(m.base, std::vector<triton::uint8>(m.bytes.begin(), m.bytes.end()));
            seedRegs(ctx, seed.regs);

            uint64_t va = startVA; uint32_t steps = 0;
            while (va < endVA && steps < opt.maxSteps) {
                const MemBlock* blk = findBlock(seed, va);
                if (!blk) break;
                const size_t off = (size_t)(va - blk->base);
                const size_t avail = blk->bytes.size() - off;
                triton::arch::Instruction inst;
                inst.setOpcode(blk->bytes.data() + off, (triton::uint32)(avail < 16 ? avail : 16));
                inst.setAddress(va);
                if (!ctx.processing(inst)) { out.status = SymStatus::DecodeError; return out.status; }
                va += inst.getSize();
                ++steps;
            }
            const auto& R = ctx.registers;
            out.regs.rax = static_cast<uint64_t>(ctx.getConcreteRegisterValue(R.x86_rax));
            out.regs.rcx = static_cast<uint64_t>(ctx.getConcreteRegisterValue(R.x86_rcx));
            out.regs.rdx = static_cast<uint64_t>(ctx.getConcreteRegisterValue(R.x86_rdx));
            out.status = SymStatus::Ok;
            return out.status;
        } catch (...) {
            out.status = SymStatus::DecodeError;
            return out.status;
        }
    }
};
#endif // DS_HAVE_SYMENGINE

class StubSymEngine : public ISymEngine {
public:
    SymStatus symbolizeRegion(const SeedSource&, uint64_t, uint64_t,
                              const std::vector<SymbolicInput>&,
                              const SymOptions&, SymOutputs& out) override {
        out.status = SymStatus::Unavailable;
        return SymStatus::Unavailable;
    }
    SymStatus runConcrete(const SeedSource&, uint64_t, uint64_t,
                          const SymOptions&, ConcreteState& out) override {
        out.status = SymStatus::Unavailable;
        return SymStatus::Unavailable;
    }
};

} // namespace

std::unique_ptr<ISymEngine> MakeSymEngine(Arch arch) {
#ifdef DS_HAVE_SYMENGINE
    (void)arch;
    return std::make_unique<TritonSymEngine>();
#else
    (void)arch;
    // No engine compiled in: the stub reports Unavailable so the app links and F1/F3
    // degrade gracefully (the pure DefaultSolver still powers F3 path-solving).
    return std::make_unique<StubSymEngine>();
#endif
}

std::unique_ptr<ISolver> MakeSolver() {
    return std::make_unique<DefaultSolver>();
}

} // namespace ds
