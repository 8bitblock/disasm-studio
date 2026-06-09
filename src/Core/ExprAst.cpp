//
// ExprAst.cpp — see ExprAst.h. Pure logic, no engine/OS deps.
//
#include "ExprAst.h"

#include <cstdio>

namespace ds {

uint64_t MaskToBits(uint64_t v, uint32_t bits) {
    if (bits >= 64) return v;
    if (bits == 0)  return 0;
    return v & ((1ull << bits) - 1);
}

uint64_t SignExtendTo64(uint64_t v, uint32_t bits) {
    if (bits >= 64 || bits == 0) return v;
    v &= MaskToBits(~0ull, bits);
    const uint64_t sign = 1ull << (bits - 1);
    return (v ^ sign) - sign;   // standard sign-extend trick
}

static ExprRef mk(ExprOp op, uint32_t bits, uint64_t val, std::vector<ExprRef> kids) {
    auto e = std::make_shared<Expr>();
    e->op = op; e->bits = bits; e->val = val; e->kids = std::move(kids);
    return e;
}

static bool isCmp(ExprOp op) {
    switch (op) {
        case ExprOp::Eq: case ExprOp::Ne: case ExprOp::Ult:
        case ExprOp::Ule: case ExprOp::Slt: case ExprOp::Sle: return true;
        default: return false;
    }
}

ExprRef C(uint64_t v, uint32_t bits)            { return mk(ExprOp::Const, bits, MaskToBits(v, bits), {}); }
ExprRef Var(uint64_t id, uint32_t bits)         { return mk(ExprOp::Var, bits, id, {}); }
ExprRef Un(ExprOp op, ExprRef a, uint32_t bits) { return mk(op, bits ? bits : (a ? a->bits : 0), 0, { a }); }
ExprRef Bin(ExprOp op, ExprRef a, ExprRef b, uint32_t bits) {
    const uint32_t w = isCmp(op) ? 1u : (bits ? bits : (a ? a->bits : 0));
    return mk(op, w, 0, { a, b });
}
ExprRef Extract(ExprRef a, uint32_t lowBit, uint32_t bits) { return mk(ExprOp::Extract, bits, lowBit, { a }); }
ExprRef Ext(ExprOp op, ExprRef a, uint32_t bits)           { return mk(op, bits, 0, { a }); }
ExprRef IteE(ExprRef cond, ExprRef a, ExprRef b)           { return mk(ExprOp::Ite, a ? a->bits : 0, 0, { cond, a, b }); }
ExprRef ConcatE(ExprRef hi, ExprRef lo) {
    uint32_t w = (hi ? hi->bits : 0) + (lo ? lo->bits : 0);
    if (w > 64) w = 64;
    return mk(ExprOp::Concat, w, 0, { hi, lo });
}
ExprRef LoadE(ExprRef addr, uint32_t bits) { return mk(ExprOp::Load, bits, 0, { addr }); }

bool EvalConst(const ExprRef& e, uint64_t& out) {
    if (!e) return false;
    const auto& k = e->kids;
    uint64_t a = 0, b = 0, c = 0;
    switch (e->op) {
        case ExprOp::Const: out = e->val; return true;
        case ExprOp::Var: case ExprOp::Load: return false;

        case ExprOp::Not: if (!EvalConst(k[0], a)) return false; out = MaskToBits(~a, e->bits); return true;
        case ExprOp::Neg: if (!EvalConst(k[0], a)) return false; out = MaskToBits(0ull - a, e->bits); return true;

        case ExprOp::Add: case ExprOp::Sub: case ExprOp::Mul:
        case ExprOp::UDiv: case ExprOp::URem:
        case ExprOp::And: case ExprOp::Or: case ExprOp::Xor:
        case ExprOp::Shl: case ExprOp::LShr: case ExprOp::AShr:
        case ExprOp::Eq: case ExprOp::Ne: case ExprOp::Ult:
        case ExprOp::Ule: case ExprOp::Slt: case ExprOp::Sle:
            if (!EvalConst(k[0], a) || !EvalConst(k[1], b)) return false;
            break;

        case ExprOp::Concat:
            if (!EvalConst(k[0], a) || !EvalConst(k[1], b)) return false;
            out = MaskToBits((a << k[1]->bits) | b, e->bits); return true;
        case ExprOp::Extract:
            if (!EvalConst(k[0], a)) return false;
            out = MaskToBits(a >> e->val, e->bits); return true;
        case ExprOp::ZExt:
            if (!EvalConst(k[0], a)) return false;
            out = MaskToBits(a, e->bits); return true;
        case ExprOp::SExt:
            if (!EvalConst(k[0], a)) return false;
            out = MaskToBits(SignExtendTo64(a, k[0]->bits), e->bits); return true;
        case ExprOp::Ite:
            if (!EvalConst(k[0], c)) return false;
            return EvalConst(c ? k[1] : k[2], out);
    }

    const uint32_t w = k[0]->bits;   // operand width for arithmetic ops
    switch (e->op) {
        case ExprOp::Add: out = MaskToBits(a + b, e->bits); return true;
        case ExprOp::Sub: out = MaskToBits(a - b, e->bits); return true;
        case ExprOp::Mul: out = MaskToBits(a * b, e->bits); return true;
        case ExprOp::UDiv: if (b == 0) return false; out = MaskToBits(a / b, e->bits); return true;
        case ExprOp::URem: if (b == 0) return false; out = MaskToBits(a % b, e->bits); return true;
        case ExprOp::And: out = MaskToBits(a & b, e->bits); return true;
        case ExprOp::Or:  out = MaskToBits(a | b, e->bits); return true;
        case ExprOp::Xor: out = MaskToBits(a ^ b, e->bits); return true;
        case ExprOp::Shl:  out = (b >= w) ? 0 : MaskToBits(a << b, e->bits); return true;
        case ExprOp::LShr: out = (b >= w) ? 0 : MaskToBits(MaskToBits(a, w) >> b, e->bits); return true;
        case ExprOp::AShr: {
            const int64_t sa = (int64_t)SignExtendTo64(a, w);
            const uint32_t sh = (b >= 63) ? 63 : (uint32_t)b;
            out = MaskToBits((uint64_t)(sa >> sh), e->bits); return true;
        }
        case ExprOp::Eq:  out = (MaskToBits(a, w) == MaskToBits(b, w)) ? 1 : 0; return true;
        case ExprOp::Ne:  out = (MaskToBits(a, w) != MaskToBits(b, w)) ? 1 : 0; return true;
        case ExprOp::Ult: out = (MaskToBits(a, w) <  MaskToBits(b, w)) ? 1 : 0; return true;
        case ExprOp::Ule: out = (MaskToBits(a, w) <= MaskToBits(b, w)) ? 1 : 0; return true;
        case ExprOp::Slt: out = ((int64_t)SignExtendTo64(a, w) <  (int64_t)SignExtendTo64(b, w)) ? 1 : 0; return true;
        case ExprOp::Sle: out = ((int64_t)SignExtendTo64(a, w) <= (int64_t)SignExtendTo64(b, w)) ? 1 : 0; return true;
        default: return false;
    }
}

bool ExprEqual(const ExprRef& a, const ExprRef& b) {
    if (a == b) return true;            // same shared node (or both null)
    if (!a || !b) return false;
    if (a->op != b->op || a->bits != b->bits || a->val != b->val) return false;
    if (a->kids.size() != b->kids.size()) return false;
    for (size_t i = 0; i < a->kids.size(); ++i)
        if (!ExprEqual(a->kids[i], b->kids[i])) return false;
    return true;
}

static const char* opName(ExprOp op) {
    switch (op) {
        case ExprOp::Not: return "~"; case ExprOp::Neg: return "neg";
        case ExprOp::Add: return "+"; case ExprOp::Sub: return "-"; case ExprOp::Mul: return "*";
        case ExprOp::UDiv: return "udiv"; case ExprOp::URem: return "urem";
        case ExprOp::And: return "&"; case ExprOp::Or: return "|"; case ExprOp::Xor: return "^";
        case ExprOp::Shl: return "<<"; case ExprOp::LShr: return ">>u"; case ExprOp::AShr: return ">>s";
        case ExprOp::Eq: return "=="; case ExprOp::Ne: return "!="; case ExprOp::Ult: return "<u";
        case ExprOp::Ule: return "<=u"; case ExprOp::Slt: return "<s"; case ExprOp::Sle: return "<=s";
        case ExprOp::Concat: return "concat"; case ExprOp::Extract: return "extract";
        case ExprOp::ZExt: return "zext"; case ExprOp::SExt: return "sext"; case ExprOp::Ite: return "ite";
        case ExprOp::Load: return "load"; default: return "?";
    }
}

std::string ExprToString(const ExprRef& e) {
    if (!e) return "<null>";
    char buf[64];
    if (e->op == ExprOp::Const) { std::snprintf(buf, sizeof(buf), "0x%llX:%u", (unsigned long long)e->val, e->bits); return buf; }
    if (e->op == ExprOp::Var)   { std::snprintf(buf, sizeof(buf), "v%llu:%u", (unsigned long long)e->val, e->bits); return buf; }
    std::string s = "("; s += opName(e->op);
    for (const auto& k : e->kids) { s += " "; s += ExprToString(k); }
    s += ")";
    return s;
}

} // namespace ds
