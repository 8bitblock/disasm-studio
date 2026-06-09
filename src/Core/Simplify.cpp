//
// Simplify.cpp — see Simplify.h. Sound, conservative ExprAst simplification.
//
#include "Simplify.h"

namespace ds {

static bool isConstVal(const ExprRef& e, uint64_t v) {
    return e && e->op == ExprOp::Const && e->val == MaskToBits(v, e->bits);
}
static bool isZero(const ExprRef& e)    { return isConstVal(e, 0); }
static bool isOne(const ExprRef& e)     { return isConstVal(e, 1); }
static bool isAllOnes(const ExprRef& e) { return e && e->op == ExprOp::Const && e->val == MaskToBits(~0ull, e->bits); }

static ExprRef rebuild(ExprOp op, uint32_t bits, uint64_t val, std::vector<ExprRef> kids) {
    auto e = std::make_shared<Expr>();
    e->op = op; e->bits = bits; e->val = val; e->kids = std::move(kids);
    return e;
}

// One bottom-up pass: simplify kids, constant-fold, then apply identities.
static ExprRef simplifyOnce(const ExprRef& e) {
    if (!e) return e;
    if (e->op == ExprOp::Const || e->op == ExprOp::Var) return e;

    std::vector<ExprRef> k;
    k.reserve(e->kids.size());
    for (const auto& kid : e->kids) k.push_back(simplifyOnce(kid));
    ExprRef cur = rebuild(e->op, e->bits, e->val, k);

    // Whole-subtree constant folding (true only when no Var/Load remains beneath).
    uint64_t cv = 0;
    if (EvalConst(cur, cv)) return C(cv, e->bits);

    const uint32_t bits = e->bits;
    const ExprRef& a = k.size() > 0 ? k[0] : nullptr;
    const ExprRef& b = k.size() > 1 ? k[1] : nullptr;

    switch (e->op) {
        case ExprOp::Add: if (isZero(a)) return b; if (isZero(b)) return a; break;
        case ExprOp::Sub: if (isZero(b)) return a; if (ExprEqual(a, b)) return C(0, bits); break;
        case ExprOp::Mul:
            if (isZero(a) || isZero(b)) return C(0, bits);
            if (isOne(a)) return b; if (isOne(b)) return a; break;
        case ExprOp::And:
            if (isZero(a) || isZero(b)) return C(0, bits);
            if (isAllOnes(a)) return b; if (isAllOnes(b)) return a;
            if (ExprEqual(a, b)) return a; break;
        case ExprOp::Or:
            if (isZero(a)) return b; if (isZero(b)) return a;
            if (isAllOnes(a) || isAllOnes(b)) return C(~0ull, bits);
            if (ExprEqual(a, b)) return a; break;
        case ExprOp::Xor:
            if (isZero(a)) return b; if (isZero(b)) return a;
            if (ExprEqual(a, b)) return C(0, bits); break;
        case ExprOp::Shl: case ExprOp::LShr: case ExprOp::AShr:
            if (isZero(b)) return a; if (isZero(a)) return C(0, bits); break;
        case ExprOp::Not: if (a && a->op == ExprOp::Not) return a->kids[0]; break;
        case ExprOp::Neg: if (a && a->op == ExprOp::Neg) return a->kids[0]; break;
        case ExprOp::Eq: if (ExprEqual(a, b)) return C(1, 1); break;
        case ExprOp::Ne: if (ExprEqual(a, b)) return C(0, 1); break;
        case ExprOp::Ite: {
            uint64_t cc = 0;
            if (a && EvalConst(a, cc)) return cc ? k[1] : k[2];
            if (k.size() == 3 && ExprEqual(k[1], k[2])) return k[1];
            break;
        }
        default: break;
    }
    return cur;
}

ExprRef Simplify(const ExprRef& e) {
    ExprRef cur = e;
    for (int i = 0; i < 32; ++i) {        // bounded fixpoint
        ExprRef next = simplifyOnce(cur);
        if (ExprEqual(next, cur)) return next;
        cur = next;
    }
    return cur;
}

} // namespace ds
