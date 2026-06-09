#include "Decompiler.h"
#include "DataFlow.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <string>
#include <unordered_map>
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
        if (in.branchTarget) return callName(in.branchTarget) + "();";
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
    std::vector<std::vector<std::string>> stmts;   // lifted body statements per block
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

    std::string out;
    bool collecting = false;     // pass 1: discover labels; pass 2: emit
    int  emitted = 0;            // guard against pathological blow-up

    bool           deep_ = false;   // data-flow pass active
    DataFlowResult df_;             // per-block named/propagated statements + flags + decls

    Structurer(const ControlFlowGraph& cfg, const DecompileOptions& o) : g(cfg), opt(o) {
        N = (int)g.blocks.size();
        deep_ = o.deepDataFlow;
        if (deep_) { df_ = AnalyzeDataFlow(cfg, o.nameFor, o.dataRefFor); if (!df_.ok) deep_ = false; }
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
                stmts[i] = df_.blockStmts[i];
                flag[i]  = df_.termFlag[i];
            } else {
                FlagState fl;
                size_t bodyCount = b.insns.size();
                // A trailing CALL is NOT a terminator, so keep it as a statement.
                bool isTerm = b.isReturn || b.isUncond || (last.isBranch && !last.isCall);
                if (isTerm && bodyCount > 0) --bodyCount;  // exclude terminator
                for (size_t k = 0; k < bodyCount; ++k) {
                    std::string s = liftStmt(b.insns[k], fl, opt.nameFor);
                    if (!s.empty()) stmts[i].push_back(std::move(s));
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
                int t = idxOf(last.branchTarget);
                if (t < 0) { term[i] = Term::External; extTarget[i] = last.branchTarget; }
                else       { term[i] = Term::Uncond;   uncondIdx[i] = t; }
            } else if (last.isBranch && !last.isCall) {
                // Conditional jump.
                term[i] = Term::Cond;
                condMnem[i] = last.mnemonic;
                trueIdx[i]  = idxOf(last.branchTarget);
                falseIdx[i] = fall;
                if (trueIdx[i] < 0) extTarget[i] = last.branchTarget;
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
    void line(int depth, const std::string& s) { if (!collecting) { out.append((size_t)depth * 4, ' '); out += s; out += '\n'; } }
    void rawline(const std::string& s)         { if (!collecting) { out += s; out += '\n'; } }

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

    void emitStmts(int n, int depth) { for (auto& s : stmts[n]) line(depth, s); }

    void emitFrom(int n, int stop, int depth) {
        while (n >= 0 && n != stop) {
            if (visited[n]) { needLabel[n] = 1; line(depth, "goto " + locLabel(n) + ";"); return; }
            if (isHeader[n] && (loopStack.empty() || loopStack.back().header != n)) {
                emitLoop(n, depth);
                int f = loopFollow[n];
                if (f == n || f < 0) return;
                n = f;
                continue;
            }
            visited[n] = 1;
            if (++emitted > 100000) { line(depth, "/* output truncated */"); return; }
            if (needLabel[n]) rawline(locLabel(n) + ":");
            emitStmts(n, depth);
            n = emitTerminator(n, depth);
        }
    }

    // Emit block n's terminator. Returns the next block to continue inline, or -1.
    int emitTerminator(int n, int depth) {
        switch (term[n]) {
            case Term::Return:
                if (deep_ && n < (int)df_.retExpr.size() && !df_.retExpr[n].empty())
                    line(depth, "return " + df_.retExpr[n] + ";");
                else
                    line(depth, "return;");
                return -1;
            case Term::External: {
                char b[40]; std::snprintf(b, sizeof(b), "goto loc_%llX; /* tail */", (unsigned long long)extTarget[n]);
                line(depth, b); return -1;
            }
            case Term::Uncond: {
                int t = uncondIdx[n];
                std::string a = goTo(t);
                if (a.empty()) return t;
                if (a == "continue;") return -1;   // natural loop-back; the while `}` re-loops
                line(depth, a); return -1;
            }
            case Term::Switch: {
                // Recovered jump table -> switch/case. Cases are labelled by table
                // index; each body runs to the switch's post-dominator (the join),
                // then breaks. Already-emitted targets become goto/continue/break.
                int join = ipdom[n];
                line(depth, "switch (" + (switchExpr[n].empty() ? std::string("switch_index") : switchExpr[n]) + ") {");
                for (size_t c = 0; c < caseIdx[n].size(); ++c) {
                    char cl[32]; std::snprintf(cl, sizeof(cl), "case %zu:", c);
                    line(depth, cl);
                    int t = caseIdx[n][c];
                    if (t < 0) { line(depth + 1, "break; /* unresolved case */"); continue; }
                    std::string a = goTo(t);
                    if (!a.empty()) { line(depth + 1, a); continue; }
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
                    line(depth + 1, "break;");
                }
                line(depth, "}");
                return join;
            }
            case Term::Fall: {
                int t = fallIdx[n];
                std::string a = goTo(t);
                if (a.empty()) return t;
                if (a == "continue;") return -1;
                line(depth, a); return -1;
            }
            case Term::Cond: {
                int ct = trueIdx[n], cf = falseIdx[n];
                std::string cond = condString(condMnem[n], flag[n], false);
                // External taken target.
                if (ct < 0) {
                    char tgt[24]; std::snprintf(tgt, sizeof(tgt), "%llX", (unsigned long long)extTarget[n]);
                    line(depth, "if (" + cond + ") goto loc_" + tgt + ";");  // don't truncate an unbounded condition
                    std::string af = goTo(cf);
                    if (af.empty()) return cf;
                    line(depth, af); return -1;
                }
                std::string at = goTo(ct), af = goTo(cf);
                if (!at.empty() && !af.empty()) {                 // both branches exit
                    line(depth, "if (" + cond + ") " + at);
                    line(depth, af);
                    return -1;
                }
                if (!at.empty()) {                                 // taken exits; fall continues inline
                    line(depth, "if (" + cond + ") " + at);
                    return cf;
                }
                if (!af.empty()) {                                 // fallthrough exits; invert
                    line(depth, "if (" + condString(condMnem[n], flag[n], true) + ") " + af);
                    return ct;
                }
                // Structured if / if-else with a post-dominator join.
                int f = ipdom[n];
                if (f < 0 && cf >= 0 && cf != ct) {
                    // No common join before exit (both arms independently reach a return).
                    // Bound the then-arm by the else's entry so it can't overrun and
                    // swallow the else / tail, then continue inline from cf. (-1 as the
                    // stop would never match a real block, so the then would run away.)
                    line(depth, "if (" + cond + ") {");
                    emitFrom(ct, cf, depth + 1);
                    line(depth, "}");
                    return cf;
                }
                bool thenEmpty = (ct == f);
                bool elseEmpty = (cf == f);
                if (thenEmpty && elseEmpty) return f;          // condition has no body
                if (thenEmpty) {                               // invert so the body isn't an empty 'then'
                    line(depth, "if (" + condString(condMnem[n], flag[n], true) + ") {");
                    emitFrom(cf, f, depth + 1);
                    line(depth, "}");
                    return f;
                }
                line(depth, "if (" + cond + ") {");
                emitFrom(ct, f, depth + 1);
                line(depth, "}");
                if (!elseEmpty) {
                    line(depth, "else {");
                    emitFrom(cf, f, depth + 1);
                    line(depth, "}");
                }
                return f;
            }
        }
        return -1;
    }

    void emitLoop(int h, int depth) {
        visited[h] = 1;
        if (needLabel[h]) rawline(locLabel(h) + ":");
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
            line(depth, "while (" + cond + ") {");
            emitFrom(bodyEntry, h, depth + 1);
            line(depth, "}");
        } else {
            line(depth, "while (1) {");
            emitStmts(h, depth + 1);
            int nxt = emitTerminator(h, depth + 1);
            emitFrom(nxt, h, depth + 1);
            line(depth, "}");
        }
        loopStack.pop_back();
    }

    // Stage 4: post-pass that turns a `while (COND) { ...; i++; }` whose induction
    // variable `i` (incremented/decremented as the last body statement and tested
    // in COND) into `for (; COND; i++) { ... }`. Purely textual and conservative:
    // any loop that doesn't match the exact shape is left as a while.
    static std::string reconstructForLoops(const std::string& in) {
        std::vector<std::string> L;
        for (size_t s = 0, i = 0; i <= in.size(); ++i)
            if (i == in.size() || in[i] == '\n') { L.push_back(in.substr(s, i - s)); s = i + 1; }
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
        }
        std::string out;
        for (size_t i = 0; i < L.size(); ++i) { out += L[i]; if (i + 1 < L.size()) out += '\n'; }
        return out;
    }

    std::string run(uint64_t funcStart) {
        // Header line with a resolved name when available.
        std::string fname;
        if (opt.nameFor) fname = opt.nameFor(funcStart);
        if (fname.empty()) { char b[32]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)funcStart); fname = b; }

        if (N == 0) return "// nothing decoded at this address\n";

        // Pass 1: discover which blocks need labels (goto targets).
        needLabel.assign(N, 0);
        visited.assign(N, 0);
        loopStack.clear(); collecting = true; emitted = 0; out.clear();
        emitFrom(0, -1, 1);

        // Pass 2: emit for real with labels in place.
        visited.assign(N, 0);
        loopStack.clear(); collecting = false; emitted = 0; out.clear();
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
        out += header + "\n{\n";
        // Inferred local declarations (data-flow pass): one per assigned non-arg var.
        if (deep_ && !df_.decls.empty()) {
            for (const std::string& d : df_.decls) { out.append(4, ' '); out += d; out += '\n'; }
            out += "\n";
        }
        emitFrom(0, -1, 1);
        out += "}\n";
        if (deep_) out = reconstructForLoops(out);
        return out;
    }
};

} // namespace

std::string Decompile(const ControlFlowGraph& g, const DecompileOptions& opt) {
    if (g.blocks.empty()) return "// no code\n";
    Structurer s(g, opt);
    return s.run(g.funcStart);
}

} // namespace ds
