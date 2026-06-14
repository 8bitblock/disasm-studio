#pragma once
//
// Cond.h
// A tiny, dependency-free evaluator for conditional-breakpoint expressions.
// Grammar (whitespace optional):
//
//   condition := operand OP operand
//   OP        := == | != | <= | >= | < | > | s< | s<= | s> | s>=
//   operand   := number | register | '[' addr ']'
//   addr      := (register | number) ['+' number | '-' number]
//
// The s-prefixed operators compare as SIGNED 64-bit values (rax s< 0 is true
// when rax holds a negative two's-complement value); the plain forms stay
// unsigned. `-1` literals parse via strtoull wrap-around to 0xFFFF... — exactly
// the bit pattern a signed compare expects.
//
// Registers and memory are resolved through caller-supplied callbacks, so the
// evaluator stays decoupled from Win32 CONTEXT / process memory and is unit
// testable. An empty expression evaluates to true (unconditional breakpoint).
//
#include <cstdint>
#include <functional>
#include <string>

namespace ds {

struct CondContext {
    // Resolve a register name (lowercase, e.g. "rax") to its value.
    // Return false if the name is not a known register.
    std::function<bool(const std::string&, uint64_t&)> reg;
    // Read 8 bytes of debuggee memory at the given address.
    std::function<uint64_t(uint64_t)>                  mem;
};

// Evaluates expr. On a parse error or unknown register, returns `onError`
// (default true, so a malformed condition behaves like an unconditional bp and
// the user notices the stop rather than silently never stopping).
bool EvalCondition(const std::string& expr, const CondContext& ctx, bool onError = true);

// Evaluate a single operand expression (number | register | [base +/- disp])
// using the same callbacks as EvalCondition. Returns false on a parse error or
// unknown register; on success writes the value to `out`. Backs watch expressions.
bool EvalExpression(const std::string& expr, const CondContext& ctx, uint64_t& out);

// ---- Pre-compiled conditions ------------------------------------------------
// A breakpoint's condition is parsed once (when set/changed) into this tiny AST,
// then evaluated repeatedly on each hit without re-parsing the string. The two
// operands and the comparison operator are baked in; an empty / unconditional
// expression compiles to {empty=true}, and an unparseable one to {valid=false}.

enum class CondOp  : uint8_t { Eq, Ne, Lt, Gt, Le, Ge, SLt, SGt, SLe, SGe };  // S* = signed compares (appended; values stable)
enum class CondTerm: uint8_t { Number, Register, Memory }; // a single operand's kind

// A compiled operand: a literal number, a named register, or a memory deref
// [base +/- disp] where base is itself one of {Number, Register}.
struct CondOperand {
    CondTerm    kind = CondTerm::Number;
    uint64_t    number = 0;     // Number: the literal; Memory: base if baseIsReg==false
    std::string reg;            // Register: name; Memory: base register if baseIsReg==true
    bool        baseIsReg = false; // Memory only: whether the base is a register
    int64_t     disp = 0;       // Memory only: signed displacement
};

// A compiled condition. Mirrors the EvalCondition grammar exactly so compiled
// evaluation is bit-for-bit identical to the string path.
struct CondProgram {
    bool        valid = false;  // parsed successfully (a comparison of two operands)
    bool        empty = true;   // the source was blank -> unconditional (always true)
    CondOp      op = CondOp::Eq;
    CondOperand lhs, rhs;
};

// Parse `expr` once into a CondProgram. A blank expr yields {valid=true, empty=true};
// a malformed one yields {valid=false}. Never throws.
CondProgram CompileCondition(const std::string& expr);

// Parse a single-operand `expr` (number | register | [base +/- disp]) into an
// operand. Returns false (and leaves `out` unspecified) on a parse error.
bool CompileExpression(const std::string& expr, CondOperand& out);

// Evaluate a pre-compiled condition. Semantics match EvalCondition exactly:
// an empty program is true; an invalid one or an unknown register returns
// `onError`; otherwise the comparison result.
bool EvalCompiled(const CondProgram& prog, const CondContext& ctx, bool onError = true);

// Evaluate a pre-compiled single operand (backs compiled watch expressions).
// Returns false on an unknown register / missing mem callback.
bool EvalCompiled(const CondOperand& op, const CondContext& ctx, uint64_t& out);

} // namespace ds
