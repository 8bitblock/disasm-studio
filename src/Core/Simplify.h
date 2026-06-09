#pragma once
//
// Simplify.h
// A SOUND, deterministic simplifier over the ExprAst bit-vector tree — the pure
// first-line MBA/algebraic reducer for F1 clean-room synthesis (the SolverBridge can
// later hand harder residue to Z3). Every rewrite preserves semantics exactly; the
// pass is conservative (never wrong, not necessarily complete), so the F1 N-sample
// I/O-equivalence check remains the correctness backstop. Pure logic, cl-testable.
//
#include "ExprAst.h"

namespace ds {

// Constant-fold every constant subtree and apply universally-valid identities
// (x^x=0, x+0=x, x*0=0, x&x=x, ~~x=x, ite(1,a,b)=a, …) to a bounded fixpoint.
ExprRef Simplify(const ExprRef& e);

} // namespace ds
