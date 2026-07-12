#include "Decompiler.h"
#include "DataFlow.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ds {
namespace {

// ----------------------------------------------------------- operand lift ---

static std::string trim(const std::string& x) {
    size_t s = x.find_first_not_of(" \t");
    size_t e = x.find_last_not_of(" \t");
    return s == std::string::npos ? std::string() : x.substr(s, e - s + 1);
}

// Turn [mem] into *(mem) so operands read like C.
static std::string cOperand(const std::string& s) {
    std::string o;
    for (char c : s) { if (c == '[') o += "*("; else if (c == ']') o += ')'; else o += c; }
    return o;
}

// Split "a, b" at the first top-level comma (ignoring commas inside []/()).
static bool split2(const std::string& ops, std::string& a, std::string& b) {
    int depth = 0;
    for (size_t i = 0; i < ops.size(); ++i) {
        char c = ops[i];
        if (c == '[' || c == '(') ++depth;
        else if (c == ']' || c == ')') --depth;
        else if (c == ',' && depth == 0) { a = trim(ops.substr(0, i)); b = trim(ops.substr(i + 1)); return true; }
    }
    a = trim(ops);
    return false;
}

// CmpKind / FlagState are shared with the data-flow pass (DataFlow.h): they
// describe what an instruction did to the flags so a following Jcc reads as a
// real condition, and carry the (lhs,rhs) the condition compares.

// Defined further down; forward-declared so liftStmt can render setcc / cmovcc
// (which read the flags a preceding cmp/test set) as real conditions.
static std::string condString(const std::string& mnem, const FlagState& fl, bool negate);

// Defined in the Python section below; forward-declared so the Structurer's
// condition-gloss post-pass can match an `if (...)` condition's parentheses.
static size_t pyMatchParen(const std::string& s, size_t open);

// Lift one instruction to a C-ish statement. Returns "" for instructions that
// produce no statement (nop, leave, the cmp/test that only set flags). Updates
// `fl` when the instruction sets flags a branch may test.
static std::string liftStmt(const Instruction& in, FlagState& fl,
                            const std::function<std::string(uint64_t)>& nameFor) {
    const std::string& m = in.mnemonic;
    std::string a, b;
    bool two = split2(in.operands, a, b);
    std::string A = cOperand(a), B = cOperand(b);

    auto callName = [&](uint64_t t) -> std::string {
        if (nameFor) { std::string n = nameFor(t); if (!n.empty()) return n; }
        char c[32]; std::snprintf(c, sizeof(c), "sub_%llX", (unsigned long long)t); return c;
    };

    // The implicit accumulator:remainder pair for one-operand mul/imul/div/idiv,
    // picked from the operand's width (defaults to the 64-bit rdx:rax pair).
    auto accPair = [&](std::string& lo, std::string& hi) {
        std::string t = a; for (char& c : t) c = (char)std::tolower((unsigned char)c);
        bool re = t.size() > 2 && t[0] == 'r';                         // r8d / r8w / r8b extended forms
        if (t=="eax"||t=="ebx"||t=="ecx"||t=="edx"||t=="esi"||t=="edi"||t=="ebp"||t=="esp"||(re && t.back()=='d'))
            { lo = "eax"; hi = "edx"; }
        else if (t=="ax"||t=="bx"||t=="cx"||t=="dx"||t=="si"||t=="di"||t=="bp"||t=="sp"||(re && t.back()=='w'))
            { lo = "ax"; hi = "dx"; }
        else if (t=="al"||t=="bl"||t=="cl"||t=="dl"||t=="ah"||t=="bh"||t=="ch"||t=="dh"||
                 t=="sil"||t=="dil"||t=="bpl"||t=="spl"||(re && t.back()=='b'))
            { lo = "al"; hi = "ah"; }
        else { lo = "rax"; hi = "rdx"; }
    };

    if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs" ||
        m == "movdqu" || m == "movdqa" || m == "movaps" || m == "movups" || m == "movq" || m == "movd")
        return two ? (A + " = " + B + ";") : std::string();
    if (m == "lea") {
        std::string rhs = cOperand(b);
        if (rhs.size() > 3 && rhs.rfind("*(", 0) == 0 && rhs.back() == ')') rhs = rhs.substr(2, rhs.size() - 3);
        return A + " = &(" + rhs + ");";
    }
    if (m == "add")  { fl = { CmpKind::ArithZero, A, "" }; return A + " += " + B + ";"; }
    if (m == "sub")  { fl = { CmpKind::ArithZero, A, "" }; return A + " -= " + B + ";"; }
    if (m == "and")  { fl = { CmpKind::ArithZero, A, "" }; return A + " &= " + B + ";"; }
    if (m == "or")   { fl = { CmpKind::ArithZero, A, "" }; return A + " |= " + B + ";"; }
    if (m == "xor")  { fl = { CmpKind::ArithZero, A, "" }; return (two && a == b) ? (A + " = 0;") : (A + " ^= " + B + ";"); }
    if (m == "shl" || m == "sal") return A + " <<= " + B + ";";
    if (m == "shr" || m == "sar") return A + " >>= " + B + ";";
    if (m == "rol" || m == "ror") {
        std::string amt = two ? B : "1";   // single-operand form rotates by 1
        return A + " = " + (m == "rol" ? "_rotl(" : "_rotr(") + A + ", " + amt + ");";
    }
    if (m == "imul") {
        // 3-operand: imul dst, src, imm  ->  dst = src * imm;  2-operand: dst *= src.
        std::string s1, s2;
        if (two && split2(b, s1, s2)) return A + " = " + cOperand(s1) + " * " + cOperand(s2) + ";";
        if (two) return A + " *= " + B + ";";
        std::string lo, hi; accPair(lo, hi);                 // 1-operand: rdx:rax = rax * src
        return hi + ":" + lo + " = " + lo + " * " + A + ";";
    }
    if (m == "mul") { std::string lo, hi; accPair(lo, hi); return hi + ":" + lo + " = " + lo + " * " + A + ";"; }
    if (m == "div" || m == "idiv") {                         // rdx:rax / src -> quotient rax, remainder rdx
        std::string lo, hi; accPair(lo, hi);
        return lo + " = " + hi + ":" + lo + " / " + A + "; " + hi + " = " + hi + ":" + lo + " % " + A + ";";
    }
    if (m == "xchg" && two) return "swap(" + A + ", " + B + ");";
    if (m == "bswap")       return A + " = bswap(" + A + ");";
    if (m == "inc")  { fl = { CmpKind::ArithZero, A, "" }; return A + "++;"; }
    if (m == "dec")  { fl = { CmpKind::ArithZero, A, "" }; return A + "--;"; }
    if (m == "neg")  return A + " = -" + A + ";";
    if (m == "not")  return A + " = ~" + A + ";";
    if (m == "push" || m == "pop" || m == "nop" || m == "endbr64" || m == "endbr32" ||
        m == "leave" || m == "hlt" || m == "int3" || m == "cdqe" || m == "cdq" || m == "cqo")
        return std::string();
    if (m == "cmp")  { fl = { CmpKind::Cmp, A, B }; return std::string(); }
    if (m == "test") { fl = (two && a == b) ? FlagState{ CmpKind::TestZero, A, "" } : FlagState{ CmpKind::TestAnd, A, B }; return std::string(); }
    if (m == "call") {
        if (HasBranchTarget(in)) return callName(in.branchTarget) + "();";
        return "(*" + cOperand(in.operands) + ")();";
    }
    // Flag-consuming forms: render against the condition the preceding cmp/test set.
    if (m.size() > 3 && m.rfind("set", 0) == 0)            // setcc:  dst = (condition)
        return A + " = (" + condString("j" + m.substr(3), fl, false) + ");";
    if (m.size() > 4 && two && m.rfind("cmov", 0) == 0)    // cmovcc: if (cond) dst = src
        return "if (" + condString("j" + m.substr(4), fl, false) + ") " + A + " = " + B + ";";
    // Anything not modelled: keep it as an inline-asm comment so nothing is lost.
    if (in.operands.empty()) return "__asm { " + m + " };";
    return "__asm { " + m + " " + in.operands + " };";
}

// Map a Jcc mnemonic to a C comparison operator (and its negation). Returns
// false for branches we don't model as a relational test.
static bool condOp(const std::string& m, const char*& op, const char*& neg) {
    if (m == "je"  || m == "jz")  { op = "=="; neg = "!="; return true; }
    if (m == "jne" || m == "jnz") { op = "!="; neg = "=="; return true; }
    if (m == "jg"  || m == "jnle" || m == "ja"  || m == "jnbe") { op = ">";  neg = "<="; return true; }
    if (m == "jge" || m == "jnl"  || m == "jae" || m == "jnb" || m == "jnc") { op = ">="; neg = "<"; return true; }
    if (m == "jl"  || m == "jnge" || m == "jb"  || m == "jc" || m == "jnae") { op = "<";  neg = ">="; return true; }
    if (m == "jle" || m == "jng"  || m == "jbe" || m == "jna") { op = "<="; neg = ">";  return true; }
    return false;
}

// Render the condition under which block `m`'s conditional branch is TAKEN.
static std::string condString(const std::string& mnem, const FlagState& fl, bool negate) {
    const char* op; const char* neg;
    if (mnem == "js" || mnem == "jns") {
        // SF reflects the sign of the result. After `cmp a,b` that result is (a-b),
        // so js == signed a<b; for test/arith the value tested is the result itself.
        bool sign = (mnem == "js");
        if (negate) sign = !sign;
        std::string lhs = fl.lhs.empty() ? "flags" : fl.lhs;
        if (fl.kind == CmpKind::Cmp)
            return "(int64_t)" + lhs + (sign ? " < " : " >= ") + "(int64_t)" + fl.rhs;
        std::string v = (fl.kind == CmpKind::TestAnd) ? "(" + lhs + " & " + fl.rhs + ")" : lhs;
        return "(int64_t)" + v + (sign ? " < 0" : " >= 0");
    }
    if (!condOp(mnem, op, neg)) {
        // Unmodelled branch (jp, jo, loop, jcxz, ...): expose the raw predicate.
        std::string base = mnem + "_cc";
        return negate ? "!" + base : base;
    }
    const char* o = negate ? neg : op;
    std::string lhs = fl.lhs.empty() ? "flags" : fl.lhs;
    switch (fl.kind) {
        case CmpKind::Cmp:       return lhs + " " + o + " " + fl.rhs;
        case CmpKind::TestZero:  return lhs + " " + o + " 0";
        case CmpKind::TestAnd:   return "(" + lhs + " & " + fl.rhs + ") " + o + " 0";
        case CmpKind::ArithZero: return lhs + " " + o + " 0";
        default:                 return lhs + " " + o + " 0";
    }
}

// ------------------------------------------------------------- dominators ---

// Cooper/Harvey/Kennedy iterative dominators. succ is the forward adjacency;
// returns idom[] (idom[entry]==entry, unreachable nodes == -1).
static std::vector<int> computeIdom(int n, const std::vector<std::vector<int>>& succ, int entry) {
    std::vector<int> order;          // postorder
    std::vector<int> postNum(n, -1);
    std::vector<char> seen(n, 0);
    // Iterative DFS for postorder.
    std::vector<std::pair<int, size_t>> stk;
    stk.push_back({ entry, 0 });
    seen[entry] = 1;
    while (!stk.empty()) {
        auto& [node, i] = stk.back();
        if (i < succ[node].size()) {
            int s = succ[node][i++];
            if (s >= 0 && s < n && !seen[s]) { seen[s] = 1; stk.push_back({ s, 0 }); }
        } else {
            postNum[node] = (int)order.size();
            order.push_back(node);
            stk.pop_back();
        }
    }
    std::vector<int> rpo(order.rbegin(), order.rend());

    std::vector<std::vector<int>> preds(n);
    for (int u = 0; u < n; ++u) for (int v : succ[u]) if (v >= 0 && v < n) preds[v].push_back(u);

    std::vector<int> idom(n, -1);
    idom[entry] = entry;
    auto intersect = [&](int a, int b) {
        // Defensive -1 guards: climbing idom[] normally converges at `entry`, but on
        // an irreducible / exit-less (post-)dominator graph a finger can step to a
        // node whose idom is still unset (-1). Bail to the other operand rather than
        // indexing postNum[-1] (out-of-bounds / UB). idom[] only ever holds reachable
        // nodes, so a finger leaves the reachable set solely by becoming exactly -1,
        // which these checks catch -- no infinite loop is introduced.
        while (a != b) {
            while (a >= 0 && postNum[a] < postNum[b]) a = idom[a];
            if (a < 0) return b;
            while (b >= 0 && postNum[b] < postNum[a]) b = idom[b];
            if (b < 0) return a;
        }
        return a;
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (int b : rpo) {
            if (b == entry) continue;
            int newIdom = -1;
            for (int p : preds[b]) {
                if (postNum[p] == -1) continue;       // unreachable
                if (idom[p] == -1) continue;
                newIdom = (newIdom == -1) ? p : intersect(p, newIdom);
            }
            if (newIdom != -1 && idom[b] != newIdom) { idom[b] = newIdom; changed = true; }
        }
    }
    return idom;
}

// Recover the index expression of a jump-table dispatch (`jmp [base+reg*N]`):
// the register scaled by 8/4/2 is the switch selector. Falls back to a generic
// name when no scaled index is present.
static std::string switchVar(const Instruction& in) {
    const std::string& o = in.operands;
    for (size_t star = o.find('*'); star != std::string::npos; star = o.find('*', star + 1)) {
        if (star + 1 >= o.size()) break;
        char sc = o[star + 1];
        if (sc != '8' && sc != '4' && sc != '2') continue;
        size_t e = star, s = star;
        while (s > 0 && (std::isalnum((unsigned char)o[s - 1]) || o[s - 1] == '_')) --s;
        if (s < e) return o.substr(s, e - s);
    }
    return "switch_index";
}

// ---------------------------------------------------------- the structurer --

struct Term { enum Kind { Return, Uncond, Cond, Fall, External, Switch } kind = Fall; };

struct Structurer {
    const ControlFlowGraph& g;
    const DecompileOptions& opt;

    int N;
    std::unordered_map<uint64_t, int> startToIdx;
    // Lifted body statements per block, each tagged with its source VA: the
    // instruction address in the legacy lift, the block start in the deep
    // data-flow path (whose const-prop/DCE merges statements, so only block
    // granularity survives). Feeds DecompResult::lineVA.
    std::vector<std::vector<std::pair<std::string, uint64_t>>> stmts;
    std::vector<FlagState>  flag;                  // flag state feeding the terminator
    std::vector<std::string> condMnem;             // terminator Jcc mnemonic (cond blocks)
    std::vector<Term::Kind>  term;
    std::vector<int> trueIdx, falseIdx, uncondIdx, fallIdx;   // successor block indices (-1 = none/external)
    std::vector<uint64_t> extTarget;               // external branch VA when a target is out of range
    std::vector<std::vector<int>> caseIdx;         // switch blocks: case target block indices (-1 = external)
    std::vector<std::string>      switchExpr;      // switch blocks: recovered selector expression

    std::vector<std::vector<int>> succ;            // forward adjacency (block indices)
    std::vector<int> idom, ipdom;
    std::vector<char> isHeader;
    std::vector<int>  loopFollow;                  // per header
    std::vector<std::vector<char>> inLoop;         // per header: membership

    std::vector<char> visited;
    std::vector<char> needLabel;
    struct LoopCtx { int header, follow; };
    std::vector<LoopCtx> loopStack;

    // Output is collected as parallel line / source-VA vectors (one entry per
    // emitted line; va 0 = synthetic) and joined into the final text by run().
    std::vector<std::string> lines_;
    std::vector<uint64_t>    lineVAs_;
    bool collecting = false;     // pass 1: discover labels; pass 2: emit
    int  emitted = 0;            // guard against pathological blow-up

    bool           deep_ = false;   // data-flow pass active
    DataFlowResult df_;             // per-block named/propagated statements + flags + decls

    Structurer(const ControlFlowGraph& cfg, const DecompileOptions& o) : g(cfg), opt(o) {
        N = (int)g.blocks.size();
        deep_ = o.deepDataFlow;
        if (deep_) { df_ = AnalyzeDataFlow(cfg, o.nameFor, o.dataRefFor, o.callArgs); if (!df_.ok) deep_ = false; }
        build();
    }

    int idxOf(uint64_t va) const { auto it = startToIdx.find(va); return it == startToIdx.end() ? -1 : it->second; }

    void build() {
        stmts.resize(N); flag.resize(N); condMnem.resize(N); term.resize(N);
        trueIdx.assign(N, -1); falseIdx.assign(N, -1); uncondIdx.assign(N, -1); fallIdx.assign(N, -1);
        extTarget.assign(N, 0); succ.resize(N);
        caseIdx.resize(N); switchExpr.resize(N);
        for (int i = 0; i < N; ++i) startToIdx[g.blocks[i].start] = i;

        for (int i = 0; i < N; ++i) {
            const BasicBlock& b = g.blocks[i];
            if (b.insns.empty()) { term[i] = Term::Fall; continue; }
            const Instruction& last = b.insns.back();
            // Body statements + terminator flag come from the data-flow pass (named,
            // propagated, dead-code-eliminated) when it ran; otherwise fall back to
            // the per-instruction string lift. The terminator (ret/jmp/jcc) is
            // handled by the structuring below in both cases.
            if (deep_) {
                // Data-flow statements have no 1:1 instruction origin (const-prop /
                // DCE rewrote them); tag each with the block start.
                stmts[i].reserve(df_.blockStmts[i].size());
                for (auto& s : df_.blockStmts[i]) stmts[i].emplace_back(s, b.start);
                flag[i]  = df_.termFlag[i];
            } else {
                FlagState fl;
                size_t bodyCount = b.insns.size();
                // A trailing CALL is NOT a terminator, so keep it as a statement.
                bool isTerm = b.isReturn || b.isUncond || (last.isBranch && !last.isCall);
                if (isTerm && bodyCount > 0) --bodyCount;  // exclude terminator
                for (size_t k = 0; k < bodyCount; ++k) {
                    std::string s = liftStmt(b.insns[k], fl, opt.nameFor);
                    if (!s.empty()) stmts[i].emplace_back(std::move(s), b.insns[k].address);
                }
                flag[i] = fl;
            }

            uint64_t fallVA = last.address + last.length;
            int fall = idxOf(fallVA);
            if (b.isSwitch) {
                term[i] = Term::Switch;
                for (uint64_t t : b.caseTargets) caseIdx[i].push_back(idxOf(t));
                switchExpr[i] = switchVar(last);
            } else if (b.isReturn) {
                term[i] = Term::Return;
            } else if (b.isUncond) {
                int t = HasBranchTarget(last) ? idxOf(last.branchTarget) : -1;
                if (t < 0) { term[i] = Term::External; extTarget[i] = last.branchTarget; }
                else       { term[i] = Term::Uncond;   uncondIdx[i] = t; }
            } else if (last.isBranch && !last.isCall) {
                // Conditional jump.
                if (HasBranchTarget(last)) {
                    term[i] = Term::Cond;
                    condMnem[i] = last.mnemonic;
                    trueIdx[i]  = idxOf(last.branchTarget);
                    falseIdx[i] = fall;
                    if (trueIdx[i] < 0) extTarget[i] = last.branchTarget;
                } else {
                    term[i] = Term::External; // unresolved indirect control transfer
                }
            } else {
                // Straight-line (incl. ending in a call): fall through.
                term[i] = Term::Fall; fallIdx[i] = fall;
            }

            // Build forward adjacency for dominator analysis.
            auto add = [&](int t) { if (t >= 0) succ[i].push_back(t); };
            switch (term[i]) {
                case Term::Cond:   add(trueIdx[i]); add(falseIdx[i]); break;
                case Term::Uncond: add(uncondIdx[i]); break;
                case Term::Fall:   add(fallIdx[i]); break;
                case Term::Switch: for (int t : caseIdx[i]) add(t); break;
                default: break;    // Return / External: no in-range successors
            }
        }

        if (N == 0) return;
        idom = computeIdom(N, succ, 0);

        // Post-dominators: dominators on the reversed graph with a virtual exit
        // (index N) linking every return/exit/external block.
        std::vector<std::vector<int>> rsucc(N + 1);
        int exit = N;
        for (int u = 0; u < N; ++u) {
            bool isExit = (term[u] == Term::Return || term[u] == Term::External || succ[u].empty());
            if (isExit) { rsucc[exit].push_back(u); rsucc[u].push_back(exit); }
            for (int v : succ[u]) rsucc[v].push_back(u);   // reverse edge
        }
        std::vector<int> pid = computeIdom(N + 1, rsucc, exit);
        ipdom.assign(N, -1);
        for (int i = 0; i < N; ++i) ipdom[i] = (pid[i] == exit ? -1 : pid[i]);

        detectLoops();
    }

    bool dominates(int a, int b) const {     // does a dominate b?
        if (a < 0 || b < 0) return false;
        int x = b;
        while (true) {
            if (x == a) return true;
            if (idom[x] == x || idom[x] < 0) break;   // reached entry / unreachable
            x = idom[x];
        }
        return false;
    }

    void detectLoops() {
        isHeader.assign(N, 0);
        loopFollow.assign(N, -1);
        inLoop.assign(N, {});
        // Predecessor adjacency depends only on succ[], so build it once here rather
        // than rebuilding it inside the back-edge loop (was O(back-edges * (N+E))).
        std::vector<std::vector<int>> preds(N);
        for (int a = 0; a < N; ++a) for (int s : succ[a]) if (s >= 0 && s < N) preds[s].push_back(a);
        for (int u = 0; u < N; ++u) {
            for (int v : succ[u]) {
                if (v >= 0 && v < N && dominates(v, u)) {   // back-edge u->v: v dominates u
                    // Natural loop for back-edge u->v.
                    isHeader[v] = 1;
                    std::vector<char> body(N, 0);
                    body[v] = 1;
                    std::vector<int> stk; stk.push_back(u);
                    if (!body[u]) { body[u] = 1; }
                    // Walk predecessors of u (in forward graph) back to v.
                    while (!stk.empty()) {
                        int m = stk.back(); stk.pop_back();
                        for (int p : preds[m]) if (!body[p]) { body[p] = 1; stk.push_back(p); }
                    }
                    // Merge with any existing body for this header (multiple latches).
                    if (inLoop[v].empty()) inLoop[v] = body;
                    else for (int i = 0; i < N; ++i) inLoop[v][i] = inLoop[v][i] || body[i];
                }
            }
        }
        // Loop follow: a target of an edge leaving the loop body (smallest addr).
        for (int h = 0; h < N; ++h) {
            if (!isHeader[h]) continue;
            int follow = -1; uint64_t best = ~0ull;
            for (int u = 0; u < N; ++u) {
                if (!inLoop[h][u]) continue;
                for (int v : succ[u]) {
                    if (v < 0 || v >= N || inLoop[h][v]) continue;
                    if (g.blocks[v].start < best) { best = g.blocks[v].start; follow = v; }
                }
            }
            loopFollow[h] = follow;
        }
    }

    // ---- emission ----

    std::string locLabel(int idx) const {
        char b[32]; std::snprintf(b, sizeof(b), "loc_%llX", (unsigned long long)g.blocks[idx].start); return b;
    }
    void line(int depth, const std::string& s, uint64_t va = 0) {
        if (collecting) return;
        std::string l((size_t)depth * 4, ' '); l += s;
        lines_.push_back(std::move(l)); lineVAs_.push_back(va);
    }
    void rawline(const std::string& s, uint64_t va = 0) {
        if (collecting) return;
        lines_.push_back(s); lineVAs_.push_back(va);
    }
    // Source VA for block n's terminator lines (return/goto/if/switch/while):
    // its last instruction, or the block start for an empty block.
    uint64_t termVA(int n) const {
        if (n < 0 || n >= N) return 0;
        return g.blocks[n].insns.empty() ? g.blocks[n].start : g.blocks[n].insns.back().address;
    }

    // A control transfer to block t from inside the current context: returns a
    // full statement (continue/break/goto) or "" meaning "emit t inline here".
    std::string goTo(int t) {
        if (t < 0) return "";
        // Scan the whole loop stack, innermost first. continue/break are C keywords that
        // bind to the INNERMOST loop only, so only loopStack.back() may use them; a
        // transfer to an ENCLOSING loop's header/follow becomes a labelled goto instead
        // of being inlined (inlining would duplicate the outer loop body / swallow its
        // follow into the inner loop).
        for (auto it = loopStack.rbegin(); it != loopStack.rend(); ++it) {
            const bool innermost = (it == loopStack.rbegin());
            if (t == it->header) {
                if (innermost) return "continue;";
                needLabel[t] = 1; return "goto " + locLabel(t) + "; /* continue outer */";
            }
            if (t == it->follow) {
                if (innermost) return "break;";
                needLabel[t] = 1; return "goto " + locLabel(t) + "; /* break outer */";
            }
        }
        if (visited[t]) { needLabel[t] = 1; return "goto " + locLabel(t) + ";"; }
        return "";
    }

    void emitStmts(int n, int depth) { for (auto& s : stmts[n]) line(depth, s.first, s.second); }

    void emitFrom(int n, int stop, int depth) {
        while (n >= 0 && n != stop) {
            if (visited[n]) { needLabel[n] = 1; line(depth, "goto " + locLabel(n) + ";", g.blocks[n].start); return; }
            if (isHeader[n] && (loopStack.empty() || loopStack.back().header != n)) {
                emitLoop(n, depth);
                int f = loopFollow[n];
                if (f == n || f < 0) return;
                n = f;
                continue;
            }
            visited[n] = 1;
            if (++emitted > 100000) { line(depth, "/* output truncated */"); return; }
            if (needLabel[n]) rawline(locLabel(n) + ":", g.blocks[n].start);
            emitStmts(n, depth);
            n = emitTerminator(n, depth);
        }
    }

    // Emit block n's terminator. Returns the next block to continue inline, or -1.
    int emitTerminator(int n, int depth) {
        const uint64_t tva = termVA(n);
        switch (term[n]) {
            case Term::Return:
                if (deep_ && n < (int)df_.retExpr.size() && !df_.retExpr[n].empty()) {
                    // retComment carries "/* = 0x.. */" when the inlined return
                    // expression folded to a constant (display-only suffix).
                    std::string cmt = (n < (int)df_.retComment.size()) ? df_.retComment[n] : std::string();
                    line(depth, "return " + df_.retExpr[n] + ";" + cmt, tva);
                } else
                    line(depth, "return;", tva);
                return -1;
            case Term::External: {
                char b[40]; std::snprintf(b, sizeof(b), "goto loc_%llX; /* tail */", (unsigned long long)extTarget[n]);
                line(depth, b, tva); return -1;
            }
            case Term::Uncond: {
                int t = uncondIdx[n];
                std::string a = goTo(t);
                if (a.empty()) return t;
                if (a == "continue;") return -1;   // natural loop-back; the while `}` re-loops
                line(depth, a, tva); return -1;
            }
            case Term::Switch: {
                // Recovered jump table -> switch/case. Cases are labelled by table
                // index; each body runs to the switch's post-dominator (the join),
                // then breaks. Already-emitted targets become goto/continue/break.
                int join = ipdom[n];
                line(depth, "switch (" + (switchExpr[n].empty() ? std::string("switch_index") : switchExpr[n]) + ") {", tva);
                for (size_t c = 0; c < caseIdx[n].size(); ++c) {
                    char cl[32]; std::snprintf(cl, sizeof(cl), "case %zu:", c);
                    line(depth, cl, tva);
                    int t = caseIdx[n][c];
                    if (t < 0) { line(depth + 1, "break; /* unresolved case */", tva); continue; }
                    std::string a = goTo(t);
                    if (!a.empty()) { line(depth + 1, a, g.blocks[t].start); continue; }
                    // Stop bound for this case body: the post-dominator join when one
                    // exists, else (no reconvergence; join == -1) the NEAREST distinct
                    // sibling-case entry by address. A -1 ("run to exit") stop would let
                    // case 0 swallow every other case and the tail; scanning only forward
                    // (d>c) misses a sibling case that lies at a lower address but a higher
                    // index, so we consider every other case and take the closest one that
                    // sits after this body's entry. emitFrom still terminates naturally at a
                    // return/visited block, so this only matters for fall-through bodies.
                    int stop = join;
                    if (stop < 0) {
                        uint64_t hereVA = g.blocks[t].start, bestVA = ~0ull;
                        for (size_t d = 0; d < caseIdx[n].size(); ++d) {
                            int o = caseIdx[n][d];
                            if (o < 0 || o == t) continue;
                            uint64_t ova = g.blocks[o].start;
                            if (ova > hereVA && ova < bestVA) { bestVA = ova; stop = o; }
                        }
                    }
                    emitFrom(t, stop, depth + 1);
                    line(depth + 1, "break;", tva);
                }
                line(depth, "}", tva);
                return join;
            }
            case Term::Fall: {
                int t = fallIdx[n];
                std::string a = goTo(t);
                if (a.empty()) return t;
                if (a == "continue;") return -1;
                line(depth, a, tva); return -1;
            }
            case Term::Cond: {
                int ct = trueIdx[n], cf = falseIdx[n];
                std::string cond = condString(condMnem[n], flag[n], false);
                // External taken target.
                if (ct < 0) {
                    char tgt[24]; std::snprintf(tgt, sizeof(tgt), "%llX", (unsigned long long)extTarget[n]);
                    line(depth, "if (" + cond + ") goto loc_" + tgt + ";", tva);  // don't truncate an unbounded condition
                    std::string af = goTo(cf);
                    if (af.empty()) return cf;
                    line(depth, af, tva); return -1;
                }
                std::string at = goTo(ct), af = goTo(cf);
                if (!at.empty() && !af.empty()) {                 // both branches exit
                    line(depth, "if (" + cond + ") " + at, tva);
                    line(depth, af, tva);
                    return -1;
                }
                if (!at.empty()) {                                 // taken exits; fall continues inline
                    line(depth, "if (" + cond + ") " + at, tva);
                    return cf;
                }
                if (!af.empty()) {                                 // fallthrough exits; invert
                    line(depth, "if (" + condString(condMnem[n], flag[n], true) + ") " + af, tva);
                    return ct;
                }
                // Structured if / if-else with a post-dominator join.
                int f = ipdom[n];
                if (f < 0 && cf >= 0 && cf != ct) {
                    // No common join before exit (both arms independently reach a return).
                    // Bound the then-arm by the else's entry so it can't overrun and
                    // swallow the else / tail, then continue inline from cf. (-1 as the
                    // stop would never match a real block, so the then would run away.)
                    line(depth, "if (" + cond + ") {", tva);
                    emitFrom(ct, cf, depth + 1);
                    line(depth, "}", tva);
                    return cf;
                }
                bool thenEmpty = (ct == f);
                bool elseEmpty = (cf == f);
                if (thenEmpty && elseEmpty) return f;          // condition has no body
                if (thenEmpty) {                               // invert so the body isn't an empty 'then'
                    line(depth, "if (" + condString(condMnem[n], flag[n], true) + ") {", tva);
                    emitFrom(cf, f, depth + 1);
                    line(depth, "}", tva);
                    return f;
                }
                line(depth, "if (" + cond + ") {", tva);
                emitFrom(ct, f, depth + 1);
                line(depth, "}", tva);
                if (!elseEmpty) {
                    line(depth, "else {", tva);
                    emitFrom(cf, f, depth + 1);
                    line(depth, "}", tva);
                }
                return f;
            }
        }
        return -1;
    }

    void emitLoop(int h, int depth) {
        visited[h] = 1;
        if (needLabel[h]) rawline(locLabel(h) + ":", g.blocks[h].start);
        int follow = loopFollow[h];

        // Pre-tested if the header itself is the 2-way test with one arm leaving
        // the loop, and the header has no side-effecting statements.
        bool pretested = false, bodyIsTrue = false; int bodyEntry = -1;
        if (term[h] == Term::Cond && stmts[h].empty()) {
            int ct = trueIdx[h], cf = falseIdx[h];
            bool ctIn = ct >= 0 && ct < N && inLoop[h][ct];
            bool cfIn = cf >= 0 && cf < N && inLoop[h][cf];
            // The post-loop continuation / break target is the header's OWN exit
            // arm (the side not in the loop), not the loop-wide min-address follow,
            // which in a multi-exit loop can route to a different block and drop cf.
            if (ctIn && !cfIn) { pretested = true; bodyIsTrue = true;  bodyEntry = ct; follow = cf; }
            else if (cfIn && !ctIn) { pretested = true; bodyIsTrue = false; bodyEntry = cf; follow = ct; }
        }

        // Make emitFrom's post-loop continuation (loopFollow[h]) agree with the
        // break target so the header's real exit block isn't swallowed.
        if (pretested) loopFollow[h] = follow;
        loopStack.push_back({ h, follow });
        if (pretested) {
            std::string cond = condString(condMnem[h], flag[h], /*negate=*/!bodyIsTrue);
            line(depth, "while (" + cond + ") {", termVA(h));
            emitFrom(bodyEntry, h, depth + 1);
            line(depth, "}", termVA(h));
        } else {
            line(depth, "while (1) {", g.blocks[h].start);
            emitStmts(h, depth + 1);
            int nxt = emitTerminator(h, depth + 1);
            emitFrom(nxt, h, depth + 1);
            line(depth, "}", g.blocks[h].start);
        }
        loopStack.pop_back();
    }

    // Stage 4: post-pass that turns a `while (COND) { ...; i++; }` whose induction
    // variable `i` (incremented/decremented as the last body statement and tested
    // in COND) into `for (; COND; i++) { ... }`. Purely textual and conservative:
    // any loop that doesn't match the exact shape is left as a while. Operates on
    // the line/VA vectors in place (the rewritten `for` keeps the while header's
    // VA; the hoisted step line's VA entry is erased with it).
    static void reconstructForLoops(std::vector<std::string>& L, std::vector<uint64_t>& V) {
        auto indentOf = [](const std::string& l) { size_t i = 0; while (i < l.size() && (l[i] == ' ' || l[i] == '\t')) ++i; return l.substr(0, i); };
        auto trimd = [](const std::string& l) { size_t a = l.find_first_not_of(" \t"); size_t b = l.find_last_not_of(" \t"); return a == std::string::npos ? std::string() : l.substr(a, b - a + 1); };
        auto isIdent = [](const std::string& s) {
            if (s.empty() || !(std::isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
            for (char c : s) if (!(std::isalnum((unsigned char)c) || c == '_')) return false; return true;
        };
        auto wordIn = [](const std::string& hay, const std::string& w) {
            for (size_t p = hay.find(w); p != std::string::npos; p = hay.find(w, p + 1)) {
                bool lok = p == 0 || !(std::isalnum((unsigned char)hay[p - 1]) || hay[p - 1] == '_');
                size_t e = p + w.size();
                bool rok = e >= hay.size() || !(std::isalnum((unsigned char)hay[e]) || hay[e] == '_');
                if (lok && rok) return true;
            }
            return false;
        };
        // Parse "i++" / "i--" / "i += k" / "i -= k" -> (id, full step text).
        auto parseStep = [&](const std::string& tin, std::string& id, std::string& step) -> bool {
            std::string t = tin;
            if (!t.empty() && t.back() == ';') t.pop_back();
            if (t.size() > 2) {
                std::string suf = t.substr(t.size() - 2);
                if (suf == "++" || suf == "--") { std::string i = t.substr(0, t.size() - 2); if (isIdent(i)) { id = i; step = t; return true; } }
            }
            for (const char* op : { " += ", " -= " }) {
                size_t o = t.find(op);
                if (o != std::string::npos) { std::string i = t.substr(0, o); if (isIdent(i) && t.find(' ', o + 4) == std::string::npos) { id = i; step = t; return true; } }
            }
            return false;
        };
        for (size_t i = 0; i < L.size(); ++i) {
            std::string ind = indentOf(L[i]);
            std::string t = trimd(L[i]);
            if (t.rfind("while (", 0) != 0 || t.size() < 10 || t.substr(t.size() - 3) != ") {") continue;
            std::string cond = t.substr(7, t.size() - 10);  // between "while (" and ") {"
            if (cond == "1") continue;
            // Matching close brace at the same indent.
            size_t j = std::string::npos;
            for (size_t k = i + 1; k < L.size(); ++k)
                if (trimd(L[k]) == "}" && indentOf(L[k]) == ind) { j = k; break; }
            if (j == std::string::npos || j == 0) continue;
            // A `continue` (or a `goto` that bypasses the bottom step) skips the step
            // in a while but a for always runs it - so only convert loops whose body
            // has neither. (break/return exit the loop in both forms, so they're safe.)
            bool unsafeJump = false;
            for (size_t k = i + 1; k < j; ++k) {
                std::string tk = trimd(L[k]);
                if (tk == "continue;" || tk.rfind("goto ", 0) == 0) { unsafeJump = true; break; }
            }
            if (unsafeJump) continue;
            // Last non-blank body line is the candidate step; it must sit at the
            // loop's top level (one indent in), not inside a nested block.
            size_t s = j - 1; while (s > i && trimd(L[s]).empty()) --s;
            if (s <= i || indentOf(L[s]).size() != ind.size() + 4) continue;
            std::string id, step;
            if (!parseStep(trimd(L[s]), id, step)) continue;
            if (!wordIn(cond, id)) continue;
            L[i] = ind + "for (; " + cond + "; " + step + ") {";
            L.erase(L.begin() + s);
            V.erase(V.begin() + s);
        }
    }

    // ---- readability post-passes (Stage 5) -----------------------------------
    // All three operate in place on the parallel line / VA vectors. They never
    // touch the legacy lift (run() gates them behind deep_) and each keeps
    // L.size() == V.size() so the per-line VA invariant holds.

    static std::string ind_of(const std::string& l) { size_t i = 0; while (i < l.size() && (l[i] == ' ' || l[i] == '\t')) ++i; return l.substr(0, i); }
    static std::string trim_(const std::string& l) { size_t a = l.find_first_not_of(" \t"); size_t b = l.find_last_not_of(" \t"); return a == std::string::npos ? std::string() : l.substr(a, b - a + 1); }
    static bool identCh(char c) { return std::isalnum((unsigned char)c) || c == '_'; }
    // Whole-word occurrence count of `w` in `hay`.
    static int wordCount(const std::string& hay, const std::string& w) {
        int n = 0;
        for (size_t p = hay.find(w); p != std::string::npos; p = hay.find(w, p + 1)) {
            bool lok = p == 0 || !identCh(hay[p - 1]);
            size_t e = p + w.size();
            bool rok = e >= hay.size() || !identCh(hay[e]);
            if (lok && rok) ++n;
        }
        return n;
    }
    // Replace every whole-word occurrence of `from` with `to` in `s`.
    static std::string wordReplace(const std::string& s, const std::string& from, const std::string& to) {
        std::string o; o.reserve(s.size());
        for (size_t i = 0; i < s.size();) {
            if (s.compare(i, from.size(), from) == 0) {
                bool lok = i == 0 || !identCh(s[i - 1]);
                size_t e = i + from.size();
                bool rok = e >= s.size() || !identCh(s[e]);
                if (lok && rok) { o += to; i = e; continue; }
            }
            o += s[i++];
        }
        return o;
    }
    // A "vN" temporary (decompiler-minted, safe to rename/fold): 'v' + digits.
    static bool isTempVar(const std::string& id) {
        if (id.size() < 2 || id[0] != 'v') return false;
        for (size_t i = 1; i < id.size(); ++i) if (!std::isdigit((unsigned char)id[i])) return false;
        return true;
    }

    // (A) Rename loop-counter temporaries (the `vN` driven by a reconstructed
    // `for (; COND; vN++/--/+=)` header) to i / j / k. Pure whole-word token
    // rename across every line — line count and VA map are untouched.
    static void prettyNamesPass(std::vector<std::string>& L, std::vector<uint64_t>& V) {
        (void)V;
        std::vector<std::string> counters;   // discovered order -> i, j, k, ...
        auto noteCounter = [&](const std::string& id) {
            if (!isTempVar(id)) return;
            for (auto& c : counters) if (c == id) return;
            counters.push_back(id);
        };
        for (const std::string& l : L) {
            std::string t = trim_(l);
            if (t.rfind("for (; ", 0) != 0) continue;
            size_t semi = t.rfind("; ");                       // step clause start
            if (semi == std::string::npos) continue;
            std::string step = t.substr(semi + 2);             // "vN++) {" / "vN += k) {"
            // identifier at the head of the step
            size_t e = 0; while (e < step.size() && identCh(step[e])) ++e;
            if (e == 0) continue;
            noteCounter(step.substr(0, e));
        }
        if (counters.empty()) return;
        static const char* kNames[] = { "i", "j", "k", "m", "n" };
        for (size_t c = 0; c < counters.size() && c < 5; ++c) {
            const std::string& to = kNames[c];
            // Don't collide with a name already present as a different identifier.
            bool clash = false;
            for (const std::string& l : L) if (wordCount(l, to) && wordCount(l, counters[c]) == 0) { clash = true; break; }
            if (clash) continue;
            for (std::string& l : L) l = wordReplace(l, counters[c], to);
        }
    }

    // (B) Expression folding. Two intra-block, conservative rewrites that each
    // erase one line and its matching VA entry (vectors stay equal length):
    //
    //   B1 coalesce  `vN = E;` + `vN OP= R;`  ->  `vN = (E) OP R;`   (the data-flow
    //                pass emits accumulators as an init + compound-assign chain;
    //                fusing them reads like real C). Only when the two lines are
    //                adjacent (same depth), R does not itself reference vN, and the
    //                init RHS has no side effect (no call).
    //   B2 inline    after B1, a `vN = EXPR;` whose vN is used EXACTLY once more in
    //                the whole function — on the very next statement at the same
    //                depth (a store / if / return / assignment) — folds into that
    //                use, deleting the dead def.
    //
    // Both refuse to cross a call/store-bearing RHS into a position that would
    // change evaluation order, and never touch args (a<N>) or stack locals.
    static void foldTempsPass(std::vector<std::string>& L, std::vector<uint64_t>& V) {
        auto rhsHasCall = [](const std::string& rhs) {
            for (size_t k = 0; k + 1 < rhs.size(); ++k)
                if (rhs[k] == '(' && k > 0 && identCh(rhs[k - 1])) return true;
            return false;
        };
        // Split "lhs OP= rhs;" / "lhs = rhs;" -> (lhs, op-or-empty, rhs) without ';'.
        // op is "" for a plain '=', otherwise the compound operator ("+","<<",...).
        auto parseAssign = [](const std::string& t, std::string& lhs, std::string& op, std::string& rhs) -> bool {
            if (t.empty() || t.back() != ';') return false;
            std::string body = t.substr(0, t.size() - 1);
            // find the assignment '=' that isn't '==', '!=', '<=', '>='.
            for (size_t p = 0; p + 1 < body.size(); ++p) {
                if (body[p] != '=' || body[p + 1] == '=') continue;
                if (p > 0 && (body[p - 1] == '!' || body[p - 1] == '<' || body[p - 1] == '>' || body[p - 1] == '=')) continue;
                // compound op chars sit just before " = "
                size_t ls = p;                       // points at '='
                // require " = " spacing
                if (p == 0 || body[p - 1] != ' ' || p + 1 >= body.size() || body[p + 1] != ' ') {
                    // compound form "lhs OP= rhs": op char immediately precedes '='
                    if (p == 0) return false;
                    // collect the (1-2 char) operator just before '='
                    size_t oe = p; size_t os = p; while (os > 0 && std::string("+-&|^<>*/%").find(body[os - 1]) != std::string::npos) --os;
                    if (os == p) return false;        // not a recognised compound
                    std::string left = body.substr(0, os);
                    while (!left.empty() && left.back() == ' ') left.pop_back();
                    lhs = left; op = body.substr(os, oe - os);
                    std::string r = body.substr(p + 1);
                    size_t rs = r.find_first_not_of(' '); rhs = (rs == std::string::npos) ? "" : r.substr(rs);
                    return !lhs.empty();
                }
                lhs = body.substr(0, ls); while (!lhs.empty() && lhs.back() == ' ') lhs.pop_back();
                op = "";
                std::string r = body.substr(p + 1);
                size_t rs = r.find_first_not_of(' '); rhs = (rs == std::string::npos) ? "" : r.substr(rs);
                return !lhs.empty();
            }
            return false;
        };

        // ---- B1: coalesce init + compound-assign chains ----
        for (size_t i = 0; i + 1 < L.size();) {
            std::string ind = ind_of(L[i]);
            std::string a = trim_(L[i]);
            std::string lhs1, op1, rhs1;
            if (parseAssign(a, lhs1, op1, rhs1) && op1.empty() && isTempVar(lhs1) && !rhsHasCall(rhs1)) {
                size_t j = i + 1; while (j < L.size() && trim_(L[j]).empty()) ++j;
                if (j < L.size() && ind_of(L[j]) == ind) {
                    std::string lhs2, op2, rhs2;
                    if (parseAssign(trim_(L[j]), lhs2, op2, rhs2) && lhs2 == lhs1 && !op2.empty() &&
                        wordCount(rhs2, lhs1) == 0 && !rhsHasCall(rhs2)) {
                        // fuse into "vN = E OP R;" keeping the init line's VA. Wrap E
                        // in parens only when it's a compound expression (operator
                        // precedence safety); a bare identifier / number / *(...) /
                        // mem[...] needs none.
                        auto atomic = [&](const std::string& e) {
                            int depth = 0;
                            for (size_t k = 0; k < e.size(); ++k) {
                                char ch = e[k];
                                if (ch == '(' || ch == '[') ++depth;
                                else if (ch == ')' || ch == ']') --depth;
                                else if (depth == 0 && k > 0 && e[k] == ' ') return false;  // a top-level space = operator
                            }
                            return true;
                        };
                        std::string E = atomic(rhs1) ? rhs1 : ("(" + rhs1 + ")");
                        L[i] = ind + lhs1 + " = " + E + " " + op2 + " " + rhs2 + ";";
                        L.erase(L.begin() + j);
                        V.erase(V.begin() + j);
                        continue;     // re-examine in case of a longer chain
                    }
                }
            }
            ++i;
        }

        // ---- B2: inline a single-use temp into the next statement ----
        for (size_t i = 0; i + 1 < L.size();) {
            std::string ind = ind_of(L[i]);
            std::string a = trim_(L[i]);
            std::string lhs, op, rhs;
            bool advanced = false;
            if (parseAssign(a, lhs, op, rhs) && op.empty() && isTempVar(lhs) && !rhsHasCall(rhs)) {
                size_t j = i + 1; while (j < L.size() && trim_(L[j]).empty()) ++j;
                if (j < L.size() && ind_of(L[j]) == ind) {
                    int total = 0; for (const std::string& l : L) total += wordCount(l, lhs);
                    int onJ = wordCount(L[j], lhs);
                    std::string ut = trim_(L[j]);
                    bool destOk = !ut.empty() && (ut.back() == ';' || ut.back() == '{');
                    if (total == 2 && onJ == 1 && destOk) {
                        L[j] = wordReplace(L[j], lhs, "(" + rhs + ")");
                        L.erase(L.begin() + i);
                        V.erase(V.begin() + i);
                        advanced = true;
                    }
                }
            }
            if (!advanced) ++i;
        }
    }

    // (C) Condition gloss: append a short plain-language `/* ... */` to a simple
    // relational `if (VAR OP IMM) {` (or one-line `if (...) ...;`). Heuristic and
    // purely additive — the condition text is unchanged, line count unchanged.
    static void conditionGlossPass(std::vector<std::string>& L, std::vector<uint64_t>& V) {
        (void)V;
        auto hexOrDec = [](const std::string& s, long long& out) -> bool {
            if (s.empty()) return false;
            char* end = nullptr;
            errno = 0;
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                // Parse hex unsigned (full 64-bit), then only gloss values that fit a
                // signed decimal — a huge mask like 0x8000000000000000 isn't a
                // meaningful "threshold" and would print a wrong-signed number.
                unsigned long long u = std::strtoull(s.c_str(), &end, 16);
                if (end == s.c_str() || *end != '\0' || errno == ERANGE) return false;
                if (u > (unsigned long long)INT64_MAX) return false;
                out = (long long)u; return true;
            }
            long long v = std::strtoll(s.c_str(), &end, 10);
            if (end == s.c_str() || *end != '\0' || errno == ERANGE) return false;
            out = v; return true;
        };
        for (std::string& l : L) {
            if (l.find("/*") != std::string::npos) continue;          // already glossed
            std::string ind = ind_of(l), t = trim_(l);
            // locate "if (" ... ")" condition
            if (t.rfind("if (", 0) != 0) continue;
            size_t close = pyMatchParen(t, 3);
            if (close == std::string::npos) continue;
            std::string cond = t.substr(4, close - 4);
            // Only a single, simple `LHS OP RHS` relational (no &&/||).
            if (cond.find("&&") != std::string::npos || cond.find("||") != std::string::npos) continue;
            struct Op { const char* sym; const char* word; };
            static const Op kOps[] = {
                { " == ", "equals" }, { " != ", "is not" }, { " <= ", "at most" },
                { " >= ", "at least" }, { " < ", "below" }, { " > ", "above" },
            };
            const Op* hit = nullptr; size_t op = std::string::npos;
            for (auto& o : kOps) {
                size_t p = cond.find(o.sym);
                if (p != std::string::npos && (op == std::string::npos || p < op)) { op = p; hit = &o; }
            }
            if (!hit) continue;
            std::string lhs = trim_(cond.substr(0, op));
            std::string rhs = trim_(cond.substr(op + std::strlen(hit->sym)));
            // LHS a plain identifier (var / arg), RHS a small literal -> human gloss.
            bool lhsId = !lhs.empty() && (std::isalpha((unsigned char)lhs[0]) || lhs[0] == '_');
            for (char c : lhs) if (!identCh(c)) { lhsId = false; break; }
            long long rv;
            if (!lhsId || !hexOrDec(rhs, rv)) continue;
            char dec[48]; std::snprintf(dec, sizeof(dec), "%lld", rv);
            std::string gloss = " /* " + lhs + " " + hit->word + " " + dec + " */";
            // Append at end of line (keeps any trailing "{" or one-line body intact).
            l += gloss;
        }
    }

    DecompResult run(uint64_t funcStart) {
        // Header line with a resolved name when available.
        std::string fname;
        if (opt.nameFor) fname = opt.nameFor(funcStart);
        if (fname.empty()) { char b[32]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)funcStart); fname = b; }

        if (N == 0) return { "// nothing decoded at this address\n", { 0 } };

        // Pass 1: discover which blocks need labels (goto targets).
        needLabel.assign(N, 0);
        visited.assign(N, 0);
        loopStack.clear(); collecting = true; emitted = 0; lines_.clear(); lineVAs_.clear();
        emitFrom(0, -1, 1);

        // Pass 2: emit for real with labels in place.
        visited.assign(N, 0);
        loopStack.clear(); collecting = false; emitted = 0; lines_.clear(); lineVAs_.clear();
        // Header: when the data-flow pass detected parameters, list exactly those (the
        // body names them a1..aN, so the header matches the body) — this surfaces the
        // x86 cdecl/stdcall + Win64 register args. Keep guessSignature's inferred return
        // type when it gave one. Otherwise fall back to the inferred "<ret> (args)"
        // signature (name spliced in) or a plain nullary header (legacy path unchanged).
        std::string header;
        if (deep_ && opt.x86 && !df_.args.empty()) {
            std::string ret = "__int64";
            if (!opt.signature.empty()) {
                size_t p = opt.signature.find('(');
                std::string r = (p == std::string::npos) ? opt.signature : opt.signature.substr(0, p);
                while (!r.empty() && r.back() == ' ') r.pop_back();
                if (!r.empty()) ret = r;
            }
            header = ret + " " + fname + "(";
            for (size_t i = 0; i < df_.args.size(); ++i) { if (i) header += ", "; header += df_.args[i]; }
            header += ")";
        } else if (!opt.signature.empty()) {
            header = opt.signature;
            size_t paren = header.find('(');
            if (paren != std::string::npos) header.insert(paren, fname);
            else header += " " + fname + "()";
        } else {
            header = "__int64 " + fname + "()";
        }
        rawline(header);
        rawline("{");
        // Inferred local declarations (data-flow pass): one per assigned non-arg var.
        if (deep_ && !df_.decls.empty()) {
            for (const std::string& d : df_.decls) line(1, d);
            rawline("");
        }
        emitFrom(0, -1, 1);
        rawline("}");
        if (deep_) {
            reconstructForLoops(lines_, lineVAs_);
            // Readability post-passes A -> B -> C (deep path only). Order matters:
            // rename counters first (so folding/gloss see the friendly names), then
            // fold single-use temps, then gloss the surviving conditions.
            if (opt.prettyNames)    prettyNamesPass(lines_, lineVAs_);
            if (opt.foldTemps)      foldTempsPass(lines_, lineVAs_);
            if (opt.conditionGloss) conditionGlossPass(lines_, lineVAs_);
        }

        // Join with '\n' + trailing '\n' — byte-identical to the legacy string
        // builder (every line() / rawline() appended its own '\n').
        DecompResult r;
        for (const std::string& l : lines_) { r.text += l; r.text += '\n'; }
        r.lineVA = std::move(lineVAs_);
        return r;
    }
};

// ----------------------- C -> Python pseudocode (DecompileToPython) ---------
//
// A line-by-line text transform over the structurer's pseudo-C, driven by the
// (machine-generated, hence well-formed) brace/indent shape: "X {" openers turn
// into "X:" headers, "}" closers vanish, statements lose ';' and get operator /
// token rewrites. The C emitter stays byte-identical; only the display differs.

// Find the ')' matching the '(' at s[open] (quote-aware), or npos.
static size_t pyMatchParen(const std::string& s, size_t open) {
    int depth = 0; char quote = 0;
    for (size_t i = open; i < s.size(); ++i) {
        char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') quote = c;
        else if (c == '(') ++depth;
        else if (c == ')') { if (--depth == 0) return i; }
    }
    return std::string::npos;
}

static bool pyIdentChar(char c) { return std::isalnum((unsigned char)c) || c == '_'; }
static bool pyKeyword(const std::string& s);
static std::string pyIdentifier(const std::string& raw, const char* fallback);

static bool pyDottedIdentifier(const std::string& s) {
    if (s.empty()) return false;
    size_t b = 0;
    while (b < s.size()) {
        size_t e = s.find('.', b);
        if (e == std::string::npos) e = s.size();
        std::string part = s.substr(b, e - b);
        if (part.empty() || !(std::isalpha((unsigned char)part[0]) || part[0] == '_') || pyKeyword(part))
            return false;
        for (char c : part) if (!pyIdentChar(c)) return false;
        b = e + 1;
    }
    return true;
}

// nameFor deliberately accepts analyst-authored labels. When one is used as a
// call target, make only the callable token Python-safe; operands and qualified
// import spellings (`kernel32.CreateFileW`) remain otherwise untouched.
static std::string pyCallNames(std::string s) {
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c != '(') continue;

        size_t e = i;
        while (e > 0 && std::isspace((unsigned char)s[e - 1])) --e;
        size_t b = e;
        while (b > 0) {
            char x = s[b - 1];
            if (x == '=' || x == ',' || x == ';' || x == '[' || x == ']' ||
                x == '(' || x == ')' || x == '{' || x == '}') break;
            if (x == '!') {
                size_t pos = b - 1;
                bool left = pos > 0 && pyIdentChar(s[pos - 1]);
                bool right = pos + 1 < s.size() && pyIdentChar(s[pos + 1]);
                if (!left || !right) break;
            }
            if (std::string("+-*/%&|^<>").find(x) != std::string::npos) {
                size_t pos = b - 1;
                bool leftIdent = pos > 0 && pyIdentChar(s[pos - 1]);
                bool rightIdent = pos + 1 < s.size() && pyIdentChar(s[pos + 1]);
                bool arrow = (x == '-' && pos + 1 < s.size() && s[pos + 1] == '>') ||
                             (x == '>' && pos > 0 && s[pos - 1] == '-');
                if (!arrow && (!leftIdent || !rightIdent)) break; // unary/deref or a real operator boundary
                bool spaced = (pos > 0 && std::isspace((unsigned char)s[pos - 1])) ||
                              (pos + 1 < s.size() && std::isspace((unsigned char)s[pos + 1]));
                bool paired = (pos > 0 && ((x == '&' && s[pos - 1] == '&') ||
                                           (x == '|' && s[pos - 1] == '|') ||
                                           (x == '<' && (s[pos - 1] == '<' || s[pos - 1] == '=')) ||
                                           (x == '>' && (s[pos - 1] == '>' || s[pos - 1] == '=')))) ||
                              (pos + 1 < s.size() && ((x == '&' && s[pos + 1] == '&') ||
                                                     (x == '|' && s[pos + 1] == '|') ||
                                                     (x == '<' && (s[pos + 1] == '<' || s[pos + 1] == '=')) ||
                                                     (x == '>' && (s[pos + 1] == '>' || s[pos + 1] == '='))));
                if (spaced || paired) break;
            }
            --b;
        }
        while (b < e && std::isspace((unsigned char)s[b])) ++b;
        if (e <= b) continue;
        if (s.compare(b, 7, "return ") == 0) b += 7;
        while (b < e && std::isspace((unsigned char)s[b])) ++b;
        if (e <= b) continue;

        std::string raw = s.substr(b, e - b);
        std::string normalized;
        normalized.reserve(raw.size());
        for (size_t k = 0; k < raw.size();) {
            if (k + 1 < raw.size() && raw[k] == ':' && raw[k + 1] == ':') {
                normalized += '.'; k += 2;
            } else if (k + 1 < raw.size() && raw[k] == '-' && raw[k + 1] == '>') {
                normalized += '.'; k += 2;
            } else normalized += raw[k++];
        }
        std::string replacement = pyDottedIdentifier(normalized)
            ? normalized : pyIdentifier(normalized, "func");
        if (replacement == raw) continue;
        const size_t gap = i - e;
        s.replace(b, e - b, replacement);
        i = b + replacement.size() + gap;
    }
    return s;
}

// Expression rewrite: *(X) -> mem[X], &(X) -> addr(X), strip C casts, ! -> not,
// && / || -> and / or, " / " -> " // " (integer division), hi:lo -> (hi, lo).
// Quote-aware so string literals inlined by dataRefFor pass through untouched.
static std::string pyExpr(std::string s) {
    s = pyCallNames(std::move(s));
    // A C indirect call spells a callable value as `(*fp)(args)` (or
    // `(**(addr))(args)` for a pointer loaded from memory). Python calls the
    // value directly. Remove exactly the call-site dereference here; the normal
    // memory pass below still turns any remaining `*(addr)` into `mem[addr]`.
    char quote = 0;
    for (size_t i = 0; i + 2 < s.size(); ++i) {
        char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c != '(' || s[i + 1] != '*') continue;
        size_t close = pyMatchParen(s, i);
        if (close != std::string::npos && close + 1 < s.size() && s[close + 1] == '(')
            s.erase(i + 1, 1);   // (*fp)(...) -> (fp)(...)
    }

    // *(X) -> mem[X]. The C lift only ever emits the literal "*(" for a memory
    // dereference (multiplication always has spaces around '*').
    quote = 0;
    for (size_t i = 0; i + 1 < s.size(); ++i) {
        char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c == '*' && s[i + 1] == '(') {
            size_t close = pyMatchParen(s, i + 1);
            if (close == std::string::npos) break;
            s = s.substr(0, i) + "mem[" + s.substr(i + 2, close - (i + 2)) + "]" + s.substr(close + 1);
            // continue scanning forward; inner derefs (now inside mem[...]) still match
        }
    }
    static const char* kCasts[] = {
        // Microsoft-width spellings are emitted by the deep data-flow lift for
        // movzx/movsx, so keep these in sync with DataFlow.cpp.
        "(unsigned __int8)", "(unsigned __int16)", "(unsigned __int32)", "(unsigned __int64)",
        "(signed __int8)",   "(signed __int16)",   "(signed __int32)",   "(signed __int64)",
        "(__int8)", "(__int16)", "(__int32)", "(__int64)",
        "(int64_t)", "(uint64_t)", "(int32_t)", "(uint32_t)", "(int16_t)", "(uint16_t)",
        "(int8_t)", "(uint8_t)", "(unsigned long long)", "(signed long long)", "(long long)",
        "(unsigned int)", "(signed int)", "(int)", "(unsigned)", "(signed)",
        "(const void *)", "(const char *)", "(const wchar_t *)", "(unsigned char *)",
        "(void *)", "(char *)", "(wchar_t *)",
        "(size_t)", "(ssize_t)", "(intptr_t)", "(uintptr_t)",
        "(float)", "(double)", "(bool)", "(char)", "(short)", "(long)",
    };
    std::string o; o.reserve(s.size());
    quote = 0;
    for (size_t i = 0; i < s.size();) {
        char c = s[i];
        if (quote) {
            o += c;
            if (c == '\\' && i + 1 < s.size()) { o += s[i + 1]; i += 2; continue; }
            if (c == quote) quote = 0;
            ++i; continue;
        }
        if (c == '"' || c == '\'') { quote = c; o += c; ++i; continue; }
        // C constants -> Python literals, word-boundary safe (so a variable like
        // `truth` or `null_ptr` is never partially rewritten). Only fires at the
        // start of an identifier run whose previous output char isn't an ident char.
        if ((std::isalpha((unsigned char)c) || c == '_') && (o.empty() || !pyIdentChar(o.back()))) {
            static const std::pair<const char*, const char*> kConst[] = {
                { "true", "True" }, { "false", "False" }, { "nullptr", "None" }, { "NULL", "None" },
            };
            bool did = false;
            for (auto& kv : kConst) {
                size_t n = std::strlen(kv.first);
                if (s.compare(i, n, kv.first) == 0 && (i + n >= s.size() || !pyIdentChar(s[i + n]))) {
                    o += kv.second; i += n; did = true; break;
                }
            }
            if (did) continue;
        }
        if (c == '&' && i + 1 < s.size() && s[i + 1] == '&') {
            while (!o.empty() && std::isspace((unsigned char)o.back())) o.pop_back();
            o += " and "; i += 2;
            while (i < s.size() && std::isspace((unsigned char)s[i])) ++i;
            continue;
        }
        if (c == '|' && i + 1 < s.size() && s[i + 1] == '|') {
            while (!o.empty() && std::isspace((unsigned char)o.back())) o.pop_back();
            o += " or "; i += 2;
            while (i < s.size() && std::isspace((unsigned char)s[i])) ++i;
            continue;
        }
        if (c == '-' && i + 1 < s.size() && s[i + 1] == '>') { o += '.'; i += 2; continue; }
        if (c == ':' && i + 1 < s.size() && s[i + 1] == ':') { o += '.'; i += 2; continue; }
        if (c == '&' && i + 1 < s.size() && s[i + 1] == '(') { o += "addr"; ++i; continue; }   // lea: &(X) -> addr(X)
        if (c == '!' && (i + 1 >= s.size() || s[i + 1] != '=')) { o += "not "; ++i; continue; }
        if (c == '/' && i > 0 && s[i - 1] == ' ' && i + 1 < s.size() && s[i + 1] == ' '
            && (i < 2 || s[i - 2] != '/')) { o += "//"; ++i; continue; }   // " / " -> " // "
        if (c == '(') {   // strip C casts
            bool stripped = false;
            for (const char* cast : kCasts) {
                size_t n = std::strlen(cast);
                if (s.compare(i, n, cast) == 0) { i += n; stripped = true; break; }
            }
            if (stripped) continue;
        }
        if (c == ':' && !o.empty() && pyIdentChar(o.back())
            && i + 1 < s.size() && (std::isalpha((unsigned char)s[i + 1]) || s[i + 1] == '_')) {
            // hi:lo register pair (1-operand mul/div lift) -> a (hi, lo) tuple
            size_t bs = o.size(); while (bs > 0 && pyIdentChar(o[bs - 1])) --bs;
            std::string hi = o.substr(bs);
            size_t j = i + 1; while (j < s.size() && pyIdentChar(s[j])) ++j;
            std::string lo = s.substr(i + 1, j - (i + 1));
            o.resize(bs); o += "(" + hi + ", " + lo + ")";
            i = j; continue;
        }
        o += c; ++i;
    }
    return o;
}

// One C statement (trailing ';' already removed) -> a Python statement.
static std::string pyStmt(const std::string& tin) {
    std::string t = tin;
    if (t.empty()) return "pass";
    // Keep inline assembly opaque. In particular, an instruction spelling can
    // itself contain `; `, which must not be mistaken for the div-lift's pair of
    // top-level C statements below.
    if (t.rfind("__asm { ", 0) == 0 && t.size() > 10 && t.compare(t.size() - 2, 2, " }") == 0) {
        std::string body = t.substr(8, t.size() - 10);
        std::string lit = "'";
        for (char c : body) { if (c == '\\' || c == '\'') lit += '\\'; lit += c; }
        lit += '\'';
        return "asm(" + lit + ")";
    }
    // The 1-operand div lift packs two statements into one line; translate both.
    {   // split on top-level "; "
        int depth = 0; char quote = 0;
        for (size_t i = 0; i + 1 < t.size(); ++i) {
            char c = t[i];
            if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
            if (c == '"' || c == '\'') quote = c;
            else if (c == '(' || c == '[') ++depth;
            else if (c == ')' || c == ']') --depth;
            else if (c == ';' && depth == 0 && t[i + 1] == ' ')
                return pyStmt(t.substr(0, i)) + "; " + pyStmt(t.substr(i + 2));
        }
    }
    if (t == "return")               return "return";
    if (t.rfind("return ", 0) == 0)  return "return " + pyExpr(t.substr(7));
    if (t == "break" || t == "continue" || t.rfind("goto ", 0) == 0) return t;   // goto stays a pseudo-statement
    if (t.rfind("swap(", 0) == 0 && t.back() == ')') {
        std::string inner = t.substr(5, t.size() - 6), a, b;
        if (split2(inner, a, b)) {
            std::string A = pyExpr(a), B = pyExpr(b);
            return A + ", " + B + " = " + B + ", " + A;
        }
    }
    if (t.size() > 2 && t.compare(t.size() - 2, 2, "++") == 0) return pyExpr(t.substr(0, t.size() - 2)) + " += 1";
    if (t.size() > 2 && t.compare(t.size() - 2, 2, "--") == 0) return pyExpr(t.substr(0, t.size() - 2)) + " -= 1";
    return pyExpr(t);
}

static bool pyTypeWord(const std::string& s) {
    static const char* kWords[] = {
        "void", "bool", "char", "short", "int", "long", "float", "double",
        "signed", "unsigned", "const", "volatile", "restrict", "struct", "class", "enum",
        "size_t", "ssize_t", "intptr_t", "uintptr_t",
        "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "__int8", "__int16", "__int32", "__int64",
        "BYTE", "WORD", "DWORD", "QWORD", "BOOL", "WCHAR", "HANDLE", "HWND", "HRESULT",
        "LPVOID", "LPCVOID", "LPSTR", "LPCSTR", "LPWSTR", "LPCWSTR",
    };
    for (const char* w : kWords) if (s == w) return true;
    return false;
}

static bool pyKeyword(const std::string& s) {
    static const char* kWords[] = {
        "False", "None", "True", "and", "as", "assert", "async", "await", "break",
        "class", "continue", "def", "del", "elif", "else", "except", "finally", "for",
        "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or",
        "pass", "raise", "return", "try", "while", "with", "yield",
    };
    for (const char* w : kWords) if (s == w) return true;
    return false;
}

// Symbols can contain module separators, C++ scopes, punctuation, or even spaces
// from a user rename. Preserve the information in a stable Python identifier
// instead of silently taking only the final identifier fragment.
static std::string pyIdentifier(const std::string& raw, const char* fallback) {
    std::string out; out.reserve(raw.size() + 1);
    for (char c : raw) {
        if (std::isalnum((unsigned char)c) || c == '_') out += c;
        else if (out.empty() || out.back() != '_') out += '_';
    }
    if (out.empty()) out = fallback;
    if (std::isdigit((unsigned char)out[0])) out.insert(out.begin(), '_');
    if (pyKeyword(out)) out += '_';
    return out;
}

static bool pyCallingConvention(const std::string& s) {
    static const char* kWords[] = {
        "__cdecl", "__fastcall", "__stdcall", "__thiscall", "__vectorcall",
        "cdecl", "fastcall", "stdcall", "thiscall", "WINAPI", "CALLBACK", "NTAPI",
    };
    for (const char* w : kWords) if (s == w) return true;
    return false;
}

// Return the name portion before a function's opening parenthesis. The emitter
// always puts the return type/calling convention first, but the actual symbol can
// be a user-authored phrase or a qualified C++/module name.
static std::string pyFunctionName(const std::string& prefix) {
    size_t p = 0;
    bool sawType = false;
    bool firstWord = true;
    bool expectTag = false;
    while (p < prefix.size() && std::isspace((unsigned char)prefix[p])) ++p;
    while (p < prefix.size()) {
        while (p < prefix.size() && (std::isspace((unsigned char)prefix[p]) ||
                                     prefix[p] == '*' || prefix[p] == '&')) ++p;
        size_t b = p;
        while (p < prefix.size() && !std::isspace((unsigned char)prefix[p]) &&
               prefix[p] != '*' && prefix[p] != '&') ++p;
        if (b == p) break;
        std::string word = prefix.substr(b, p - b);
        bool suffixType = word.size() > 2 && word.compare(word.size() - 2, 2, "_t") == 0;
        bool upperType = word.size() > 1;
        for (char c : word) if (std::isalpha((unsigned char)c) && !std::isupper((unsigned char)c)) upperType = false;
        bool convention = pyCallingConvention(word);
        bool type = expectTag || pyTypeWord(word) || suffixType || (upperType && !sawType);
        // A user-defined return type (`Widget foo`) is indistinguishable from a
        // bare symbol until there is a following token. Function headers emitted
        // by this decompiler always have a return type, so consume that first word.
        if (firstWord && !type && !convention &&
            prefix.find_first_not_of(" \t*&", p) != std::string::npos)
            type = true;
        if (!type && !convention)
            return trim(prefix.substr(b));
        expectTag = word == "struct" || word == "class" || word == "enum";
        if (type) sawType = true;
        firstWord = false;
    }

    // Unknown/malformed return type: the final token is still a better function
    // name than emitting an empty or invalid `def` line.
    size_t e = prefix.find_last_not_of(" \t*&");
    if (e == std::string::npos) return std::string();
    size_t b = e + 1;
    while (b > 0 && !std::isspace((unsigned char)prefix[b - 1]) &&
           prefix[b - 1] != '*' && prefix[b - 1] != '&') --b;
    return prefix.substr(b, e - b + 1);
}

// Split a C parameter list without treating commas in function-pointer types as
// parameter separators.
static std::vector<std::string> pySplitParams(const std::string& s) {
    std::vector<std::string> out;
    int paren = 0, bracket = 0; char quote = 0; size_t begin = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') quote = c;
        else if (c == '(') ++paren;
        else if (c == ')') --paren;
        else if (c == '[') ++bracket;
        else if (c == ']') --bracket;
        else if (c == ',' && paren == 0 && bracket == 0) {
            out.push_back(trim(s.substr(begin, i - begin)));
            begin = i + 1;
        }
    }
    out.push_back(trim(s.substr(begin)));
    return out;
}

// Extract a usable Python parameter name from a typed C declaration. Unnamed
// parameters get stable a<N> placeholders; a sole `void` means no parameters.
static std::string pyParamName(std::string a, size_t ordinal) {
    a = trim(a);
    if (a.empty() || a == "void") return std::string();
    if (a == "...") return "*args";

    // Function-pointer declarator: `void (*callback)(int, int)` (also accepts
    // calling-convention words between '(' and '*').
    for (size_t star = a.find('*'); star != std::string::npos; star = a.find('*', star + 1)) {
        if (a.rfind('(', star) == std::string::npos) continue;
        size_t b = star + 1; while (b < a.size() && std::isspace((unsigned char)a[b])) ++b;
        if (b >= a.size() || !(std::isalpha((unsigned char)a[b]) || a[b] == '_')) continue;
        size_t e = b + 1; while (e < a.size() && pyIdentChar(a[e])) ++e;
        return a.substr(b, e - b);
    }

    // Drop trailing array extents so `const char *argv[]` ends at `argv`.
    for (;;) {
        size_t e = a.find_last_not_of(" \t");
        if (e == std::string::npos || a[e] != ']') break;
        int depth = 0; size_t b = e;
        for (;;) {
            char c = a[b];
            if (c == ']') ++depth;
            else if (c == '[' && --depth == 0) break;
            if (b == 0) { depth = -1; break; }
            --b;
        }
        if (depth != 0) break;
        a.erase(b);
    }

    // Last identifier is the declarator name. If it is only a C type word, the
    // signature omitted the name (`int`, `char **`) and needs a placeholder.
    for (size_t e = a.size(); e > 0;) {
        while (e > 0 && !pyIdentChar(a[e - 1])) --e;
        size_t b = e; while (b > 0 && pyIdentChar(a[b - 1])) --b;
        if (b == e) break;
        std::string id = a.substr(b, e - b);
        // An identifier before a later '*'/'&' is part of the type, not a name
        // (`Widget *` is an unnamed parameter; `Widget *value` ends at value).
        const bool beforePointer = a.find_first_of("*&", e) != std::string::npos;
        if ((std::isalpha((unsigned char)id[0]) || id[0] == '_') &&
            !pyTypeWord(id) && !beforePointer)
            return id;
        e = b;
    }
    return "a" + std::to_string(ordinal);
}

enum class PyDecl { NotDeclaration, Uninitialized, Initialized };

// Translate a known C local declaration. Uninitialized locals disappear (as
// before); initialized declarations retain their assignment instead of leaking
// invalid `int x = ...` syntax into the Python view.
static PyDecl pyDeclaration(const std::string& t, std::string& statement) {
    if (t.empty() || t.back() != ';') return PyDecl::NotDeclaration;
    size_t wb = 0;
    while (wb < t.size() && std::isspace((unsigned char)t[wb])) ++wb;
    size_t we = wb;
    while (we < t.size() && pyIdentChar(t[we])) ++we;
    if (wb == we) return PyDecl::NotDeclaration;
    std::string first = t.substr(wb, we - wb);
    bool suffixType = first.size() > 2 && first.compare(first.size() - 2, 2, "_t") == 0;
    if (!pyTypeWord(first) && !suffixType) return PyDecl::NotDeclaration;

    // Split comma-separated declarators at top level (`int x = 1, *p = f(a,b)`).
    // The shared type stays on the first segment; pyParamName also accepts the
    // later bare/pointer declarators.
    std::string body = t.substr(0, t.size() - 1);
    std::vector<std::string> decls;
    int paren = 0, bracket = 0, brace = 0; char quote = 0; size_t begin = 0;
    for (size_t i = 0; i <= body.size(); ++i) {
        char c = i < body.size() ? body[i] : ',';
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') quote = c;
        else if (c == '(') ++paren;
        else if (c == ')') --paren;
        else if (c == '[') ++bracket;
        else if (c == ']') --bracket;
        else if (c == '{') ++brace;
        else if (c == '}') --brace;
        else if (c == ',' && paren == 0 && bracket == 0 && brace == 0) {
            decls.push_back(trim(body.substr(begin, i - begin)));
            begin = i + 1;
        }
    }

    bool initialized = false;
    for (const std::string& decl : decls) {
        size_t eq = std::string::npos;
        paren = bracket = brace = 0; quote = 0;
        for (size_t i = 0; i < decl.size(); ++i) {
            char c = decl[i];
            if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
            if (c == '"' || c == '\'') quote = c;
            else if (c == '(') ++paren;
            else if (c == ')') --paren;
            else if (c == '[') ++bracket;
            else if (c == ']') --bracket;
            else if (c == '{') ++brace;
            else if (c == '}') --brace;
            else if (c == '=' && paren == 0 && bracket == 0 && brace == 0) {
                char prev = i ? decl[i - 1] : 0;
                char next = i + 1 < decl.size() ? decl[i + 1] : 0;
                if (next != '=' && std::string("=!<>+-*/%&|^").find(prev) == std::string::npos) {
                    eq = i; break;
                }
            }
        }
        if (eq == std::string::npos) continue; // Python has no declaration-only counterpart

        std::string lhs = trim(decl.substr(0, eq));
        std::string name = pyParamName(lhs, 0);
        if (name.empty() || name == "a0" || name == "*args") continue;
        name = pyIdentifier(name, "local");
        std::string rhs = trim(decl.substr(eq + 1));
        // A simple C aggregate initializer is most legible as a Python list.
        if (rhs.size() >= 2 && rhs.front() == '{' && rhs.back() == '}')
            rhs = "[" + rhs.substr(1, rhs.size() - 2) + "]";
        if (!statement.empty()) statement += "; ";
        statement += name + " = " + pyExpr(rhs);
        initialized = true;
    }
    return initialized ? PyDecl::Initialized : PyDecl::Uninitialized;
}

static bool pyIsLabel(const std::string& t) {
    if (t.size() < 2 || t.back() != ':' || t.rfind("loc_", 0) != 0) return false;
    for (size_t i = 4; i + 1 < t.size(); ++i) if (!std::isxdigit((unsigned char)t[i])) return false;
    return true;
}

// Text before a Python # comment, respecting the quoted string used by asm().
static std::string pyCodePart(const std::string& s) {
    bool sq = false, dq = false;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if ((sq || dq) && c == '\\') { ++i; continue; }
        if (!dq && c == '\'') { sq = !sq; continue; }
        if (!sq && c == '"') { dq = !dq; continue; }
        if (!sq && !dq && c == '#') return trim(s.substr(0, i));
    }
    return trim(s);
}

static size_t pyIndentOf(const std::string& s) {
    size_t n = 0;
    while (n < s.size() && (s[n] == ' ' || s[n] == '\t')) ++n;
    return n;
}

// The C structurer represents an else-if as an `else` containing one nested
// `if`. Collapse only when that if/else chain is the outer else's sole executable
// child, so Python gets the natural `elif` spelling without changing semantics.
static void pyFoldElif(std::vector<std::string>& lines, std::vector<uint64_t>& vas) {
    for (size_t i = 0; i + 1 < lines.size(); ++i) {
        if (trim(lines[i]) != "else:") continue; // keep a commented else untouched
        const size_t outerIndent = pyIndentOf(lines[i]);
        const size_t childIndent = outerIndent + 4;
        const size_t nested = i + 1;
        std::string nestedCode = pyCodePart(lines[nested]);
        if (pyIndentOf(lines[nested]) != childIndent || nestedCode.rfind("if ", 0) != 0 ||
            nestedCode.back() != ':') continue;

        // Find the outer else's end. Blank lines do not carry indentation, while
        // comments do and therefore correctly delimit an outdented suite.
        size_t end = lines.size();
        for (size_t k = nested + 1; k < lines.size(); ++k) {
            if (trim(lines[k]).empty()) continue;
            if (pyIndentOf(lines[k]) <= outerIndent) { end = k; break; }
        }

        bool soleChain = true;
        for (size_t k = nested + 1; k < end; ++k) {
            std::string code = pyCodePart(lines[k]);
            if (code.empty() || pyIndentOf(lines[k]) != childIndent) continue;
            if (code == "else:" || code.rfind("elif ", 0) == 0) continue;
            soleChain = false; break; // a sequential statement also belongs to the outer else
        }
        if (!soleChain) continue;

        // Retain any trailing comment from the nested if header.
        std::string nestedText = trim(lines[nested]);
        lines[i] = std::string(outerIndent, ' ') + "elif " + nestedText.substr(3);
        if (i < vas.size() && nested < vas.size()) vas[i] = vas[nested];
        lines.erase(lines.begin() + nested);
        if (nested < vas.size()) vas.erase(vas.begin() + nested);
        --end;
        for (size_t k = i + 1; k < end; ++k) {
            size_t ind = pyIndentOf(lines[k]);
            if (ind >= childIndent) lines[k].erase(0, 4);
        }
    }
}

// Dropping C declarations/braces and match-ending breaks can expose genuinely
// empty Python suites (an empty spin loop and a break-only switch case are common
// binary shapes). Insert a mapped `pass`; an empty match needs a wildcard case
// because Python's match grammar does not accept a plain statement as its suite.
static void pyEnsureNonEmptySuites(std::vector<std::string>& lines, std::vector<uint64_t>& vas) {
    const size_t n = lines.size();
    std::vector<size_t> nextCode(n + 1, n);
    for (size_t i = n; i-- > 0;)
        nextCode[i] = pyCodePart(lines[i]).empty() ? nextCode[i + 1] : i;

    std::vector<std::string> rebuilt;
    std::vector<uint64_t> rebuiltVA;
    rebuilt.reserve(n + n / 8 + 2);
    rebuiltVA.reserve(rebuilt.capacity());
    for (size_t i = 0; i < lines.size(); ++i) {
        rebuilt.push_back(lines[i]);
        rebuiltVA.push_back(i < vas.size() ? vas[i] : 0);
        std::string code = pyCodePart(lines[i]);
        if (code.empty() || code.back() != ':') continue;   // not a compound-statement header
        size_t ind = pyIndentOf(lines[i]);
        size_t j = nextCode[i + 1];
        if (j < lines.size() && pyIndentOf(lines[j]) > ind) continue;

        const uint64_t va = i < vas.size() ? vas[i] : 0;
        if (code.rfind("match ", 0) == 0) {
            rebuilt.push_back(std::string(ind + 4, ' ') + "case _:");
            rebuiltVA.push_back(va);
            rebuilt.push_back(std::string(ind + 8, ' ') + "pass");
            rebuiltVA.push_back(va);
        } else {
            rebuilt.push_back(std::string(ind + 4, ' ') + "pass");
            rebuiltVA.push_back(va);
        }
    }
    lines.swap(rebuilt);
    vas.swap(rebuiltVA);
}

} // namespace

DecompResult DecompileWithMap(const ControlFlowGraph& g, const DecompileOptions& opt) {
    if (g.blocks.empty()) return { "// no code\n", { 0 } };
    Structurer s(g, opt);
    return s.run(g.funcStart);
}

std::string Decompile(const ControlFlowGraph& g, const DecompileOptions& opt) {
    return DecompileWithMap(g, opt).text;
}

DecompResult DecompileToPython(const DecompResult& c) {
    // Split into lines (DecompResult convention: no entry for the empty segment
    // after the trailing '\n').
    std::vector<std::string> L; std::vector<uint64_t> V;
    for (size_t s = 0, i = 0; i <= c.text.size(); ++i)
        if (i == c.text.size() || c.text[i] == '\n') {
            if (i == c.text.size() && s == i) break;
            L.push_back(c.text.substr(s, i - s));
            s = i + 1;
        }
    V = c.lineVA; V.resize(L.size(), 0);

    DecompResult r;
    std::vector<std::string> out; std::vector<uint64_t> outVA;
    struct Blk { size_t indent; int kind; std::string step; uint64_t stepVA; };   // kind 0=other 1=loop 2=switch
    std::vector<Blk> stack;
    auto switchDepth = [&]() { size_t n = 0; for (const Blk& b : stack) if (b.kind == 2) ++n; return n; };
    auto currentLoop = [&]() -> const Blk* {
        for (auto it = stack.rbegin(); it != stack.rend(); ++it)
            if (it->kind == 1) return &*it;
        return nullptr;
    };
    auto emitAt = [&](size_t indent, const std::string& s, uint64_t va) {
        out.push_back(std::string(indent + 4 * switchDepth(), ' ') + s);
        outVA.push_back(va);
    };

    for (size_t i = 0; i < L.size(); ++i) {
        const std::string& raw = L[i];
        const uint64_t va = V[i];
        size_t ind = 0; while (ind < raw.size() && raw[ind] == ' ') ++ind;
        std::string t = raw.substr(ind);
        while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();

        if (t.empty()) { out.push_back(""); outVA.push_back(va); continue; }

        // Split a trailing /* ... */ into a Python # comment suffix.
        std::string cmt;
        if (t.size() > 4 && t.compare(t.size() - 2, 2, "*/") == 0) {
            size_t cs = t.rfind("/*");
            if (cs != std::string::npos) {
                std::string inner = t.substr(cs + 2, t.size() - cs - 4);
                size_t a = inner.find_first_not_of(' '), b = inner.find_last_not_of(' ');
                if (a != std::string::npos) cmt = "  # " + inner.substr(a, b - a + 1);
                t = t.substr(0, cs);
                while (!t.empty() && t.back() == ' ') t.pop_back();
            }
        }

        if (t.rfind("//", 0) == 0) { emitAt(ind, "#" + t.substr(2), va); continue; }   // comment line
        if (t.empty()) { if (!cmt.empty()) emitAt(ind, cmt.substr(2), va); continue; } // comment-only /* */ line

        if (i == 0) {   // function header: "<ret> name(args)" -> "def name(args):"
            size_t p = t.find('(');
            size_t close = (p == std::string::npos) ? std::string::npos : pyMatchParen(t, p);
            if (p != std::string::npos && close != std::string::npos) {
                std::string rawName = pyFunctionName(t.substr(0, p));
                std::string name = pyIdentifier(rawName, "func");
                // Keep argument names only. Typed signatures can contain arrays,
                // unnamed parameters, or nested commas in a function-pointer type.
                std::string args = t.substr(p + 1, close - p - 1), alist;
                std::vector<std::string> params = pySplitParams(args);
                std::vector<std::string> usedNames;
                for (size_t ai = 0; ai < params.size(); ++ai) {
                    std::string paramName = pyParamName(params[ai], ai + 1);
                    if (paramName.empty()) continue;   // empty list / sole C `void`
                    const bool variadic = paramName == "*args";
                    if (!variadic) paramName = pyIdentifier(paramName, "a");
                    std::string bare = variadic ? paramName.substr(1) : paramName;
                    std::string unique = bare;
                    int suffix = 2;
                    while (std::find(usedNames.begin(), usedNames.end(), unique) != usedNames.end())
                        unique = bare + "_" + std::to_string(suffix++);
                    usedNames.push_back(unique);
                    paramName = variadic ? "*" + unique : unique;
                    if (!alist.empty()) alist += ", ";
                    alist += paramName;
                }
                std::string nameComment;
                if (!rawName.empty() && rawName != name) nameComment = "  # symbol: " + rawName;
                emitAt(ind, "def " + name + "(" + alist + "):" + cmt + nameComment, va);
                continue;
            }
        }

        if (t == "{") { stack.push_back({ ind, 0, "", 0 }); continue; }
        if (t == "}") {
            if (!stack.empty()) {
                Blk b = stack.back(); stack.pop_back();
                if (b.kind == 1 && !b.step.empty()) emitAt(b.indent + 4, b.step, b.stepVA);   // for-loop step
            }
            continue;
        }

        if (t.size() > 2 && t.compare(t.size() - 2, 2, " {") == 0) {   // block opener "X {"
            std::string head = t.substr(0, t.size() - 2);
            while (!head.empty() && head.back() == ' ') head.pop_back();
            if (head == "while (1)") { emitAt(ind, "while True:" + cmt, va); stack.push_back({ ind, 1, "", 0 }); }
            else if (head.rfind("for (; ", 0) == 0 && head.back() == ')') {
                std::string inner = head.substr(7, head.size() - 8);     // "COND; STEP"
                size_t semi = inner.rfind("; ");
                std::string cond = semi == std::string::npos ? inner : inner.substr(0, semi);
                std::string step = semi == std::string::npos ? std::string() : inner.substr(semi + 2);
                emitAt(ind, "while " + pyExpr(cond) + ":" + cmt, va);
                stack.push_back({ ind, 1, step.empty() ? std::string() : pyStmt(step), va });
            }
            else if (head.rfind("while (", 0) == 0 && head.back() == ')') {
                emitAt(ind, "while " + pyExpr(head.substr(7, head.size() - 8)) + ":" + cmt, va);
                stack.push_back({ ind, 1, "", 0 });
            }
            else if (head == "else") { emitAt(ind, "else:" + cmt, va); stack.push_back({ ind, 0, "", 0 }); }
            else if (head.rfind("if (", 0) == 0 && head.back() == ')') {
                emitAt(ind, "if " + pyExpr(head.substr(4, head.size() - 5)) + ":" + cmt, va);
                stack.push_back({ ind, 0, "", 0 });
            }
            else if (head.rfind("switch (", 0) == 0 && head.back() == ')') {
                emitAt(ind, "match " + pyExpr(head.substr(8, head.size() - 9)) + ":" + cmt, va);
                stack.push_back({ ind, 2, "", 0 });   // push AFTER emit: the match line sits outside
            }
            else { emitAt(ind, head + ":" + cmt, va); stack.push_back({ ind, 0, "", 0 }); }
            continue;
        }

        if (pyIsLabel(t)) { emitAt(ind, "# " + t, va); continue; }       // goto target marker
        if (t.rfind("case ", 0) == 0 && t.back() == ':') { emitAt(ind, t + cmt, va); continue; }
        if (t == "default:") { emitAt(ind, "case _:" + cmt, va); continue; }

        if (!t.empty() && t.back() == ';') {                             // plain statement
            std::string declStatement;
            PyDecl decl = pyDeclaration(t, declStatement);
            if (decl == PyDecl::Uninitialized) {
                if (!cmt.empty()) emitAt(ind, cmt.substr(2), va);
                continue;
            }
            if (decl == PyDecl::Initialized) {
                emitAt(ind, declStatement + cmt, va);
                continue;
            }
            std::string stmt = t.substr(0, t.size() - 1);
            while (!stmt.empty() && stmt.back() == ' ') stmt.pop_back();
            if (stmt.rfind("if (", 0) == 0) {                            // one-liner "if (C) S;"
                size_t close = pyMatchParen(stmt, 3);
                if (close != std::string::npos) {
                    std::string cond = stmt.substr(4, close - 4);
                    std::string rest = close + 1 < stmt.size() ? stmt.substr(close + 1) : std::string();
                    size_t rs = rest.find_first_not_of(' ');
                    rest = rs == std::string::npos ? std::string() : rest.substr(rs);
                    if (rest == "continue") {
                        const Blk* loop = currentLoop();
                        if (loop && !loop->step.empty()) {
                            emitAt(ind, "if " + pyExpr(cond) + ":", va);
                            emitAt(ind + 4, loop->step, loop->stepVA);
                            emitAt(ind + 4, "continue" + cmt, va);
                            continue;
                        }
                    }
                    emitAt(ind, "if " + pyExpr(cond) + ": " + pyStmt(rest) + cmt, va);
                    continue;
                }
            }
            if (stmt == "break") {   // match-case needs no break; loop break stays
                bool inSwitch = false;
                for (auto it = stack.rbegin(); it != stack.rend(); ++it)
                    if (it->kind == 1) break; else if (it->kind == 2) { inSwitch = true; break; }
                if (inSwitch) { if (!cmt.empty()) emitAt(ind, "pass" + cmt, va); continue; }
            }
            if (stmt == "continue") {
                const Blk* loop = currentLoop();
                if (loop && !loop->step.empty()) emitAt(ind, loop->step, loop->stepVA);
            }
            emitAt(ind, pyStmt(stmt) + cmt, va);
            continue;
        }

        emitAt(ind, pyExpr(t) + cmt, va);   // anything else: best-effort expression rewrite
    }

    pyFoldElif(out, outVA);
    pyEnsureNonEmptySuites(out, outVA);
    for (const std::string& l : out) { r.text += l; r.text += '\n'; }
    r.lineVA = std::move(outVA);
    return r;
}

} // namespace ds
