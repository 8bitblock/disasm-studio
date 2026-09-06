#include "Cond.h"

#include <cctype>
#include <cstdlib>

namespace ds {

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static bool parseNumber(const std::string& t, uint64_t& out) {
    if (t.empty()) return false;
    char* end = nullptr;
    // strtoull with base 0 handles 0x.. and decimal.
    unsigned long long v = std::strtoull(t.c_str(), &end, 0);
    if (end == t.c_str() || *end != '\0') return false;
    out = (uint64_t)v;
    return true;
}

// ---- single-operand compile (parse once) ------------------------------------
// Parse a single operand string (number | register | [base +/- disp]) into a
// CondOperand without evaluating it. Shared by both the string-eval path (which
// compiles-then-evaluates) and CompileExpression/CompileCondition, so the grammar
// has exactly one implementation and the two paths can never diverge.
static bool compileOperand(const std::string& tokIn, CondOperand& out) {
    std::string t = trim(tokIn);
    if (t.empty()) return false;

    if (t.front() == '[' && t.back() == ']') {
        std::string inner = trim(t.substr(1, t.size() - 2));
        // Split on a top-level + or - for an optional displacement.
        int64_t disp = 0;
        std::string baseTok = inner;
        size_t op = std::string::npos; char opc = 0;
        for (size_t i = 1; i < inner.size(); ++i)
            if (inner[i] == '+' || inner[i] == '-') { op = i; opc = inner[i]; break; }
        if (op != std::string::npos) {
            baseTok = trim(inner.substr(0, op));
            uint64_t d = 0;
            if (!parseNumber(trim(inner.substr(op + 1)), d)) return false;
            disp = (opc == '-') ? -(int64_t)d : (int64_t)d;
        }
        // The base must itself be a number or register (no nested [ ]).
        CondOperand base;
        baseTok = trim(baseTok);
        std::string lower = baseTok;
        for (char& c : lower) c = (char)std::tolower((unsigned char)c);
        uint64_t num = 0;
        out.kind = CondTerm::Memory;
        out.disp = disp;
        if (parseNumber(baseTok, num)) { out.baseIsReg = false; out.number = num; return true; }
        if (!baseTok.empty() && baseTok.front() != '[') { out.baseIsReg = true; out.reg = lower; return true; }
        return false;
    }

    // Register? (case-insensitive). We can't query reg validity at compile time,
    // so anything that isn't a literal is recorded as a register and validated at
    // eval (matching the string path: an unknown register fails the eval).
    std::string lower = t;
    for (char& c : lower) c = (char)std::tolower((unsigned char)c);
    uint64_t num = 0;
    if (parseNumber(t, num)) { out.kind = CondTerm::Number; out.number = num; return true; }
    out.kind = CondTerm::Register; out.reg = lower; return true;
}

// Evaluate a compiled operand against live register/memory callbacks.
static bool evalCompiledOperand(const CondOperand& o, const CondContext& ctx, uint64_t& out) {
    switch (o.kind) {
        case CondTerm::Number:
            out = o.number; return true;
        case CondTerm::Register: {
            uint64_t rv = 0;
            if (ctx.reg && ctx.reg(o.reg, rv)) { out = rv; return true; }
            return false;   // unknown register
        }
        case CondTerm::Memory: {
            uint64_t base = 0;
            if (o.baseIsReg) {
                if (!ctx.reg || !ctx.reg(o.reg, base)) return false;
            } else {
                base = o.number;
            }
            if (!ctx.mem) return false;
            out = ctx.mem((uint64_t)((int64_t)base + o.disp));
            return true;
        }
    }
    return false;
}

// Evaluate a single operand: number, register, or [addr] memory deref. Compiles
// the token then evaluates it, so it shares the grammar with the compiled path.
static bool evalOperand(const std::string& tokIn, const CondContext& ctx, uint64_t& out) {
    CondOperand o;
    if (!compileOperand(tokIn, o)) return false;
    return evalCompiledOperand(o, ctx, out);
}

// Find the comparison operator in `expr`. Returns its position + fills `op`.
// Earliest occurrence wins; on a same-position tie the longer operator wins
// ("s<=" beats "s<" beats "<"). The signed forms are 's'-prefixed and accepted
// only at a word boundary, so a register name ending in 's' can never donate
// its trailing letter to the operator ("rflags<0" must parse as rflags < 0,
// not "rflag s< 0").
static size_t findCompareOp(const std::string& expr, std::string& op) {
    auto boundaryOk = [&](size_t p) {
        return p == 0 || !(std::isalnum((unsigned char)expr[p - 1]) || expr[p - 1] == '_');
    };
    // First occurrence of `tok`; for the s-prefixed forms, skip non-boundary hits.
    auto findTok = [&](const char* tok, bool guarded) {
        size_t p = expr.find(tok);
        while (guarded && p != std::string::npos && !boundaryOk(p)) p = expr.find(tok, p + 1);
        return p;
    };
    struct Cand { const char* tok; bool guarded; };
    // Longer forms listed first so a same-position tie keeps the longer operator.
    static const Cand cands[] = { {"s<=", true}, {"s>=", true},
                                  {"==", false}, {"!=", false}, {"<=", false}, {">=", false},
                                  {"s<", true},  {"s>", true},
                                  {"<", false},  {">", false} };
    size_t pos = std::string::npos;
    op.clear();
    for (const auto& c : cands) {
        size_t p = findTok(c.tok, c.guarded);
        if (p != std::string::npos && (pos == std::string::npos || p < pos)) { pos = p; op = c.tok; }
    }
    return pos;
}

static bool opFromStr(const std::string& s, CondOp& out) {
    if (s == "==")  { out = CondOp::Eq;  return true; }
    if (s == "!=")  { out = CondOp::Ne;  return true; }
    if (s == "<")   { out = CondOp::Lt;  return true; }
    if (s == ">")   { out = CondOp::Gt;  return true; }
    if (s == "<=")  { out = CondOp::Le;  return true; }
    if (s == ">=")  { out = CondOp::Ge;  return true; }
    if (s == "s<")  { out = CondOp::SLt; return true; }
    if (s == "s>")  { out = CondOp::SGt; return true; }
    if (s == "s<=") { out = CondOp::SLe; return true; }
    if (s == "s>=") { out = CondOp::SGe; return true; }
    return false;
}

static bool applyOp(CondOp op, uint64_t lhs, uint64_t rhs) {
    switch (op) {
        case CondOp::Eq:  return lhs == rhs;
        case CondOp::Ne:  return lhs != rhs;
        case CondOp::Lt:  return lhs <  rhs;
        case CondOp::Gt:  return lhs >  rhs;
        case CondOp::Le:  return lhs <= rhs;
        case CondOp::Ge:  return lhs >= rhs;
        case CondOp::SLt: return (int64_t)lhs <  (int64_t)rhs;
        case CondOp::SGt: return (int64_t)lhs >  (int64_t)rhs;
        case CondOp::SLe: return (int64_t)lhs <= (int64_t)rhs;
        case CondOp::SGe: return (int64_t)lhs >= (int64_t)rhs;
    }
    return false;
}

// ---- compiling ---------------------------------------------------------------

CondProgram CompileCondition(const std::string& exprIn) {
    CondProgram p;
    std::string expr = trim(exprIn);
    if (expr.empty()) { p.valid = true; p.empty = true; return p; } // unconditional
    p.empty = false;

    std::string op;
    size_t pos = findCompareOp(expr, op);
    if (pos == std::string::npos) return p;                 // no operator -> invalid
    if (!opFromStr(op, p.op)) return p;
    if (!compileOperand(expr.substr(0, pos), p.lhs)) return p;
    if (!compileOperand(expr.substr(pos + op.size()), p.rhs)) return p;
    p.valid = true;
    return p;
}

static bool isBreakpointRegister(const std::string& name) {
    return name == "rax" || name == "eax" || name == "rbx" || name == "ebx" ||
           name == "rcx" || name == "ecx" || name == "rdx" || name == "edx" ||
           name == "rsi" || name == "esi" || name == "rdi" || name == "edi" ||
           name == "rbp" || name == "ebp" || name == "rsp" || name == "esp" ||
           name == "rip" || name == "eip" || name == "rflags" || name == "eflags" ||
           name == "r8"  || name == "r9"  || name == "r10" || name == "r11" ||
           name == "r12" || name == "r13" || name == "r14" || name == "r15";
}

static const std::string* unsupportedBreakpointRegister(const CondOperand& operand) {
    if (operand.kind == CondTerm::Register && !isBreakpointRegister(operand.reg))
        return &operand.reg;
    if (operand.kind == CondTerm::Memory && operand.baseIsReg && !isBreakpointRegister(operand.reg))
        return &operand.reg;
    return nullptr;
}

bool ValidateBreakpointCondition(const std::string& expr, std::string* error) {
    if (error) error->clear();
    const CondProgram program = CompileCondition(expr);
    if (!program.valid) {
        if (error) {
            *error = "Expected: <operand> <operator> <operand> (for example, rax == 0). "
                     "Operators are ==, !=, <, <=, >, >= and signed s<, s<=, s>, s>=.";
        }
        return false;
    }
    if (program.empty) return true;

    const std::string* bad = unsupportedBreakpointRegister(program.lhs);
    if (!bad) bad = unsupportedBreakpointRegister(program.rhs);
    if (bad) {
        if (error) {
            *error = "Unknown register '" + *bad +
                     "'. Use an x86/x64 general-purpose register such as rax, eax, rsp, rip, or r8.";
        }
        return false;
    }
    return true;
}

bool CompileExpression(const std::string& expr, CondOperand& out) {
    return compileOperand(expr, out);
}

bool EvalCompiled(const CondProgram& prog, const CondContext& ctx, bool onError) {
    if (prog.empty) return true;        // unconditional
    if (!prog.valid) return onError;    // unparseable -> behave like the string path's error
    uint64_t lhs = 0, rhs = 0;
    if (!evalCompiledOperand(prog.lhs, ctx, lhs)) return onError;
    if (!evalCompiledOperand(prog.rhs, ctx, rhs)) return onError;
    return applyOp(prog.op, lhs, rhs);
}

bool EvalCompiled(const CondOperand& op, const CondContext& ctx, uint64_t& out) {
    return evalCompiledOperand(op, ctx, out);
}

// ---- string-entry points (compile-then-eval) --------------------------------

bool EvalCondition(const std::string& exprIn, const CondContext& ctx, bool onError) {
    return EvalCompiled(CompileCondition(exprIn), ctx, onError);
}

bool EvalExpression(const std::string& expr, const CondContext& ctx, uint64_t& out) {
    return evalOperand(expr, ctx, out);
}

} // namespace ds
