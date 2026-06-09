#pragma once
//
// ExprAst.h
// A small, self-contained bit-vector expression tree — the lingua franca between
// the symbolic engine (SymEngine), the MBA/constant-fold simplifier (Simplify), and
// the constraint solver (SolverBridge) for features F1 (clean-room synthesis) and F3
// (path explorer). Deliberately INDEPENDENT of Triton/Z3 types so the interface and
// every consumer are unit-testable with `cl` and a MockSymEngine — the production
// TritonSymEngine lowers Triton's AST into this representation.
//
// Values are modular bit-vectors of width `bits` in 1..64 (wider widths are outside
// the scoped envelope). Signedness lives in the operator (Slt vs Ult, AShr vs LShr),
// not the node. Nodes are immutable and shared via shared_ptr<const Expr>.
//
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ds {

enum class ExprOp {
    Const,      // literal value (val), width bits
    Var,        // symbolic input variable id = val, width bits
    // unary
    Not, Neg,
    // binary arithmetic / bitwise (modular, width = bits)
    Add, Sub, Mul, UDiv, URem, And, Or, Xor, Shl, LShr, AShr,
    // comparisons -> 1-bit result
    Eq, Ne, Ult, Ule, Slt, Sle,
    // structural
    Concat,     // concat(hi=kids[0], lo=kids[1]); bits = hi.bits + lo.bits
    Extract,    // extract `bits` bits starting at low bit `val` from kids[0]
    ZExt, SExt, // widen kids[0] to `bits` (zero / sign extend)
    Ite,        // kids[0]?kids[1]:kids[2]; kids[0] is 1-bit
    Load,       // symbolic memory load at address kids[0], `bits` wide
};

struct Expr;
using ExprRef = std::shared_ptr<const Expr>;

struct Expr {
    ExprOp               op   = ExprOp::Const;
    uint32_t             bits = 0;   // result width (1..64)
    uint64_t             val  = 0;   // Const value / Var id / Extract low bit
    std::vector<ExprRef> kids;

    bool isConst() const { return op == ExprOp::Const; }
    bool isVar()   const { return op == ExprOp::Var; }
};

// ---- width helpers ----
uint64_t MaskToBits(uint64_t v, uint32_t bits);          // v & ((1<<bits)-1), 64-safe
uint64_t SignExtendTo64(uint64_t v, uint32_t bits);      // treat v as `bits`-wide signed

// ---- builders (Const values are masked to width on construction) ----
ExprRef C(uint64_t v, uint32_t bits);
ExprRef Var(uint64_t id, uint32_t bits);
ExprRef Un(ExprOp op, ExprRef a, uint32_t bits = 0);                 // bits 0 => a->bits
ExprRef Bin(ExprOp op, ExprRef a, ExprRef b, uint32_t bits = 0);     // bits 0 => a->bits (cmp => 1)
ExprRef Extract(ExprRef a, uint32_t lowBit, uint32_t bits);
ExprRef Ext(ExprOp zextOrSext, ExprRef a, uint32_t bits);
ExprRef IteE(ExprRef cond, ExprRef a, ExprRef b);
ExprRef ConcatE(ExprRef hi, ExprRef lo);
ExprRef LoadE(ExprRef addr, uint32_t bits);

// ---- evaluation / comparison / printing ----
// Fold a fully-constant expression (no Var/Load) to its value. False if it contains
// a Var/Load or an undefined op (e.g. divide-by-zero), in which case `out` is unset.
bool EvalConst(const ExprRef& e, uint64_t& out);

// Structural equality: same op/bits/val and structurally-equal kids.
bool ExprEqual(const ExprRef& a, const ExprRef& b);

// Human-readable form for the F1 "reasoning" panel and test diagnostics.
std::string ExprToString(const ExprRef& e);

} // namespace ds
