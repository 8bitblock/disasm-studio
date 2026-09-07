#include "Decompiler.h"
#include "DataFlow.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
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

static std::string stripOperandSize(const std::string& operand) {
    std::string value = trim(operand);
    std::string lowered = value;
    for (char& c : lowered) c = static_cast<char>(std::tolower((unsigned char)c));
    static const char* prefixes[] = {
        "zmmword ptr ", "ymmword ptr ", "xmmword ptr ", "tbyte ptr ",
        "qword ptr ", "dword ptr ", "word ptr ", "byte ptr ",
    };
    for (const char* prefix : prefixes) {
        const size_t length = std::strlen(prefix);
        if (lowered.compare(0, length, prefix) == 0)
            return trim(value.substr(length));
    }
    return value;
}

static uint16_t textualOperandWidth(const std::string& operand) {
    std::string value = trim(operand);
    for (char& c : value) c = static_cast<char>(std::tolower((unsigned char)c));
    if (value.rfind("qword ptr ", 0) == 0) return 64;
    if (value.rfind("dword ptr ", 0) == 0) return 32;
    if (value.rfind("word ptr ", 0) == 0) return 16;
    if (value.rfind("byte ptr ", 0) == 0) return 8;
    static const char* r8[] = { "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
                                "sil", "dil", "bpl", "spl" };
    static const char* r16[] = { "ax", "bx", "cx", "dx", "si", "di", "bp", "sp" };
    static const char* r32[] = { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" };
    for (const char* reg : r8) if (value == reg) return 8;
    for (const char* reg : r16) if (value == reg) return 16;
    for (const char* reg : r32) if (value == reg) return 32;
    if (value.size() > 2 && value[0] == 'r') {
        if (value.back() == 'b') return 8;
        if (value.back() == 'w') return 16;
        if (value.back() == 'd') return 32;
    }
    return 64;
}

// Turn [mem] into *(mem) so operands read like C. Decoder size qualifiers are
// type metadata, not expression text; leaving `byte ptr` in Python is invalid.
static std::string cOperand(const std::string& s) {
    const std::string value = stripOperandSize(s);
    std::string o;
    for (char c : value) { if (c == '[') o += "*("; else if (c == ']') o += ')'; else o += c; }
    return o;
}

// Canonical dependency key for the integer-register aliases used by the raw
// (non-data-flow) lifter. EAX/AX/AL/AH all name the same mutable storage for
// provenance purposes; keeping their formatted spellings separate can reuse a
// comparison expression after a partial-register write.
static std::string rawRegisterDependency(std::string token) {
    for (char& c : token) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    static const char* aliases[8][5] = {
        {"rax","eax","ax","al","ah"}, {"rcx","ecx","cx","cl","ch"},
        {"rdx","edx","dx","dl","dh"}, {"rbx","ebx","bx","bl","bh"},
        {"rsp","esp","sp","spl",nullptr}, {"rbp","ebp","bp","bpl",nullptr},
        {"rsi","esi","si","sil",nullptr}, {"rdi","edi","di","dil",nullptr}
    };
    for (int reg = 0; reg < 8; ++reg)
        for (int alias = 0; alias < 5 && aliases[reg][alias]; ++alias)
            if (token == aliases[reg][alias]) return "REG:" + std::to_string(reg);
    if (token.size() >= 2 && token[0] == 'r' && std::isdigit(static_cast<unsigned char>(token[1]))) {
        size_t end = 1;
        while (end < token.size() && std::isdigit(static_cast<unsigned char>(token[end]))) ++end;
        const int reg = std::atoi(token.substr(1, end - 1).c_str());
        const std::string suffix = token.substr(end);
        if (reg >= 8 && reg <= 15 && (suffix.empty() || suffix == "d" || suffix == "w" || suffix == "b"))
            return "REG:" + std::to_string(reg);
    }
    return {};
}

static std::vector<std::string> rawOperandDependencies(const std::string& operand) {
    std::vector<std::string> result;
    std::string token;
    auto flush = [&]() {
        if (token.empty()) return;
        std::string dependency = rawRegisterDependency(token);
        if (!dependency.empty() && std::find(result.begin(), result.end(), dependency) == result.end())
            result.push_back(std::move(dependency));
        token.clear();
    };
    for (size_t i = 0; i <= operand.size(); ++i) {
        const char c = i < operand.size() ? operand[i] : ' ';
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') token.push_back(c);
        else flush();
    }
    return result;
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

static uint16_t conditionWidth(const Instruction& instruction) {
    for (const TypedOperand& operand : instruction.typedOperands)
        if (operand.widthBits) return operand.widthBits;
    return 0;
}

// Defined in the Python section below; forward-declared so the Structurer's
// condition-gloss post-pass can match an `if (...)` condition's parentheses.
static size_t pyMatchParen(const std::string& s, size_t open);

// Lift one instruction to a C-ish statement. Returns "" for instructions that
// produce no statement (nop, leave, the cmp/test that only set flags). Updates
// `fl` when the instruction sets flags a branch may test.
static std::string liftStmt(const Instruction& in, FlagState& fl,
                            const std::function<std::string(uint64_t)>& nameFor) {
    // Prefixes carry ordering, repetition, or control-flow semantics that the
    // scalar statement lift does not implement. Preserve the decoded operation
    // in the lightweight path just as the deep data-flow path does.
    if (!in.prefixes.empty() || in.isRepString) {
        fl.clear();
        return "__asm { " + InstructionText(in) + " };";
    }
    const std::string& m = in.mnemonic;
    std::string a, b;
    bool two = split2(in.operands, a, b);
    std::string A = cOperand(a), B = cOperand(b);
    auto flagDependencies = [&]() {
        std::vector<std::string> dependencies;
        auto append = [&](const std::string& operand) {
            for (std::string dependency : rawOperandDependencies(operand))
                if (std::find(dependencies.begin(), dependencies.end(), dependency) == dependencies.end())
                    dependencies.push_back(std::move(dependency));
        };
        append(a); if (two) append(b);
        if (a.find('[') != std::string::npos || b.find('[') != std::string::npos)
            dependencies.push_back("MEM");
        return dependencies;
    };
    auto invalidateDestination = [&](const std::string& destination, bool memory) {
        if (memory) { fl.invalidateDependency("MEM"); return; }
        for (const std::string& dependency : rawOperandDependencies(destination))
            fl.invalidateDependency(dependency);
    };
    auto destinationAliasesSource = [&]() {
        if (!two || a.find('[') != std::string::npos || b.find('[') != std::string::npos)
            return false;
        const std::vector<std::string> left = rawOperandDependencies(a);
        const std::vector<std::string> right = rawOperandDependencies(b);
        return left.size() == 1 && right.size() == 1 && left.front() == right.front();
    };

    auto callName = [&](uint64_t t) -> std::string {
        if (nameFor) { std::string n = nameFor(t); if (!n.empty()) return n; }
        char c[32]; std::snprintf(c, sizeof(c), "sub_%llX", (unsigned long long)t); return c;
    };

    // The implicit accumulator:remainder pair for one-operand mul/imul/div/idiv,
    // picked from the operand's width (defaults to the 64-bit rdx:rax pair).
    auto accumulatorWidth = [&]() -> uint16_t {
        const uint16_t typed = conditionWidth(in);
        if (typed <= 8 && typed) return 8;
        if (typed <= 16 && typed) return 16;
        if (typed <= 32 && typed) return 32;
        if (typed) return 64;

        std::string t = a;
        for (char& c : t) c = (char)std::tolower((unsigned char)c);
        if (t.find("qword ptr") != std::string::npos) return 64;
        if (t.find("dword ptr") != std::string::npos) return 32;
        if (t.find("word ptr")  != std::string::npos) return 16;
        if (t.find("byte ptr")  != std::string::npos) return 8;
        const bool re = t.size() > 2 && t[0] == 'r';
        if (t=="eax"||t=="ebx"||t=="ecx"||t=="edx"||t=="esi"||t=="edi"||
            t=="ebp"||t=="esp"||(re && t.back()=='d')) return 32;
        if (t=="ax"||t=="bx"||t=="cx"||t=="dx"||t=="si"||t=="di"||
            t=="bp"||t=="sp"||(re && t.back()=='w')) return 16;
        if (t=="al"||t=="bl"||t=="cl"||t=="dl"||t=="ah"||t=="bh"||
            t=="ch"||t=="dh"||t=="sil"||t=="dil"||t=="bpl"||t=="spl"||
            (re && t.back()=='b')) return 8;
        return 64;
    };
    auto accPair = [&](std::string& lo, std::string& hi) {
        switch (accumulatorWidth()) {
            case 8:  lo = "al";  hi = "ah";  break;
            case 16: lo = "ax";  hi = "dx";  break;
            case 32: lo = "eax"; hi = "edx"; break;
            default: lo = "rax"; hi = "rdx"; break;
        }
    };

    if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs" ||
        m == "movdqu" || m == "movdqa" || m == "movaps" || m == "movups" || m == "movq" || m == "movd") {
        invalidateDestination(A, a.find('[') != std::string::npos);
        if (!two) return {};
        std::string rhs = B;
        if (m == "movzx" || m == "movsx" || m == "movsxd") {
            uint16_t width = 0;
            if (in.typedOperands.size() > 1) width = in.typedOperands[1].widthBits;
            if (!width) width = m == "movsxd" ? 32 : textualOperandWidth(b);
            width = width <= 8 ? 8 : width <= 16 ? 16 : width <= 32 ? 32 : 64;
            const bool zeroExtend = m == "movzx";
            std::string cast;
            if (zeroExtend) cast = "(unsigned __int" + std::to_string(width) + ")";
            else if (width == 32) cast = "(int)";
            else cast = "(__int" + std::to_string(width) + ")";
            rhs = cast + rhs;
        }
        return A + " = " + rhs + ";";
    }
    if (m == "lea") {
        invalidateDestination(A, false);
        std::string rhs = cOperand(b);
        if (rhs.size() > 3 && rhs.rfind("*(", 0) == 0 && rhs.back() == ')') rhs = rhs.substr(2, rhs.size() - 3);
        return A + " = &(" + rhs + ");";
    }
    if (m == "add")  { fl.clear(); fl.write(destinationAliasesSource() ? static_cast<uint8_t>(kX86FlagZF | kX86FlagSF) : static_cast<uint8_t>(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF), CmpKind::AddResult, A, B, {}, conditionWidth(in), flagDependencies()); return A + " += " + B + ";"; }
    if (m == "sub")  { fl.clear(); fl.write(destinationAliasesSource() ? static_cast<uint8_t>(kX86FlagZF | kX86FlagSF) : static_cast<uint8_t>(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF), CmpKind::SubResult, A, B, {}, conditionWidth(in), flagDependencies()); return A + " -= " + B + ";"; }
    if (m == "and")  { fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::LogicResult, A, B, {}, conditionWidth(in), flagDependencies()); return A + " &= " + B + ";"; }
    if (m == "or")   { fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::LogicResult, A, B, {}, conditionWidth(in), flagDependencies()); return A + " |= " + B + ";"; }
    if (m == "xor")  { fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::LogicResult, A, B, {}, conditionWidth(in), flagDependencies()); return (two && a == b) ? (A + " = 0;") : (A + " ^= " + B + ";"); }
    if (m == "shl" || m == "sal") { fl.clear(); return A + " <<= " + B + ";"; }
    if (m == "shr" || m == "sar") { fl.clear(); return A + " >>= " + B + ";"; }
    if (m == "rol" || m == "ror") {
        fl.clear(); // count-dependent CF/OF are not modeled yet
        std::string amt = two ? B : "1";   // single-operand form rotates by 1
        return A + " = " + (m == "rol" ? "_rotl(" : "_rotr(") + A + ", " + amt + ");";
    }
    if (m == "imul") {
        fl.clear(); // Only CF/OF are defined and need a product-width model.
        // 3-operand: imul dst, src, imm  ->  dst = src * imm;  2-operand: dst *= src.
        std::string s1, s2;
        if (two && split2(b, s1, s2)) return A + " = " + cOperand(s1) + " * " + cOperand(s2) + ";";
        if (two) return A + " *= " + B + ";";
        std::string lo, hi; accPair(lo, hi);                 // 1-operand: rdx:rax = rax * src
        return hi + ":" + lo + " = " + lo + " * " + A + ";";
    }
    if (m == "mul") { fl.clear(); std::string lo, hi; accPair(lo, hi); return hi + ":" + lo + " = " + lo + " * " + A + ";"; }
    if (m == "div" || m == "idiv") {                         // rdx:rax / src -> quotient rax, remainder rdx
        fl.clear();
        std::string lo, hi; accPair(lo, hi);
        const std::string width = std::to_string(accumulatorWidth());
        const std::string kind = m == "idiv" ? "s" : "u";
        char address[24];
        std::snprintf(address, sizeof(address), "%llX", (unsigned long long)in.address);
        const std::string suffix = "_" + std::string(address);
        const std::string highSnapshot = "local_div_hi" + suffix;
        const std::string lowSnapshot = "local_div_lo" + suffix;
        const std::string sourceSnapshot = "local_div_src" + suffix;
        const std::string args = highSnapshot + ", " + lowSnapshot + ", " + sourceSnapshot;
        // Snapshot every input before either architectural output changes. This
        // is essential for DIV AL/AH, whose outputs share AX, and when the
        // divisor aliases an accumulator register.
        return highSnapshot + " = " + hi + "; " + lowSnapshot + " = " + lo + "; " +
               sourceSnapshot + " = " + A + "; " +
               lo + " = " + kind + "div" + width + "(" + args + "); " +
               hi + " = " + kind + "rem" + width + "(" + args + ");";
    }
    if (m == "xchg" && two) { invalidateDestination(A, a.find('[') != std::string::npos); invalidateDestination(B, b.find('[') != std::string::npos); return "swap(" + A + ", " + B + ");"; }
    if (m == "bswap")       { invalidateDestination(A, false); return A + " = bswap(" + A + ");"; }
    if (m == "inc")  { invalidateDestination(A, a.find('[') != std::string::npos); fl.clear(kX86FlagZF | kX86FlagSF | kX86FlagOF | kX86FlagPF); fl.write(kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::IncResult, A, "", {}, conditionWidth(in), flagDependencies()); return A + "++;"; }
    if (m == "dec")  { invalidateDestination(A, a.find('[') != std::string::npos); fl.clear(kX86FlagZF | kX86FlagSF | kX86FlagOF | kX86FlagPF); fl.write(kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::DecResult, A, "", {}, conditionWidth(in), flagDependencies()); return A + "--;"; }
    if (m == "neg")  { fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::NegResult, A, "", {}, conditionWidth(in), flagDependencies()); return A + " = -" + A + ";"; }
    if (m == "not")  { invalidateDestination(A, a.find('[') != std::string::npos); return A + " = ~" + A + ";"; }
    if (m == "nop" || m == "endbr64" || m == "endbr32")
        return std::string();
    if (m == "cmp")  { fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::Cmp, A, B, {}, conditionWidth(in), flagDependencies()); return std::string(); }
    if (m == "test") {
        fl.clear();
        fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF,
                 (two && a == b) ? CmpKind::TestZero : CmpKind::TestAnd,
                 A, (two && a == b) ? std::string() : B, {}, conditionWidth(in), flagDependencies());
        return std::string();
    }
    if (m == "call") {
        fl = {}; // x86 calls do not preserve condition flags
        if (HasBranchTarget(in)) return callName(in.branchTarget) + "();";
        return "(*" + cOperand(in.operands) + ")();";
    }
    // Flag-consuming forms: render against the condition the preceding cmp/test set.
    if (m.size() > 3 && m.rfind("set", 0) == 0) {          // setcc:  dst = (condition)
        const std::string condition = condString("j" + m.substr(3), fl, false);
        invalidateDestination(A, a.find('[') != std::string::npos);
        return A + " = (" + condition + ");";
    }
    if (m.size() > 4 && two && m.rfind("cmov", 0) == 0) {  // cmovcc: if (cond) dst = src
        const std::string condition = condString("j" + m.substr(4), fl, false);
        invalidateDestination(A, a.find('[') != std::string::npos);
        return "if (" + condition + ") " + A + " = " + B + ";";
    }
    // Anything not modelled: keep it as an inline-asm comment so nothing is lost.
    fl = {}; // an unmodelled instruction may have overwritten flag provenance
    if (in.operands.empty()) return "__asm { " + m + " };";
    return "__asm { " + m + " " + in.operands + " };";
}

// Map a Jcc mnemonic to a C comparison operator (and its negation). Returns
// false for branches we don't model as a relational test.
// Render the condition under which block `m`'s conditional branch is TAKEN.
static std::string condString(const std::string& mnem, const FlagState& fl, bool negate) {
    return RenderX86Condition(mnem, fl, negate);
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

struct Term { enum Kind { Return, NoReturnCall, Uncond, Cond, Fall, External, Indirect, Switch } kind = Fall; };

struct Structurer {
    const ControlFlowGraph& g;
    const DecompileOptions& opt;

    int N;
    std::unordered_map<uint64_t, int> startToIdx;
    struct LiftedStatement {
        std::string text;
        uint64_t sourceVA = 0;
        SourceOriginGranularity granularity = SourceOriginGranularity::Synthetic;
    };
    // Propagation and DCE retain/eliminate the instruction origin with each
    // statement. This keeps deep pseudocode navigation exact, including VA 0.
    std::vector<std::vector<LiftedStatement>> stmts;
    std::vector<FlagState>  flag;                  // flag state feeding the terminator
    std::vector<std::string> condMnem;             // terminator Jcc mnemonic (cond blocks)
    std::vector<Term::Kind>  term;
    std::vector<int> trueIdx, falseIdx, uncondIdx, fallIdx;   // successor block indices (-1 = none/external)
    std::vector<uint64_t> extTarget;               // external branch VA when a target is out of range
    std::vector<std::vector<int>> caseIdx;         // switch blocks: case target block indices (-1 = external)
    std::vector<std::vector<int64_t>> caseValue;   // exact switch keys (sparse JVM keys included)
    std::vector<int> switchDefaultIdx;              // default target block, -1 when external/absent
    std::vector<uint64_t> switchDefaultTarget;
    std::vector<char> switchDefaultValid;
    std::vector<std::string>      switchExpr;      // switch blocks: recovered selector expression
    std::vector<std::string>      indirectExpr;    // unresolved indirect branch operand

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
    std::vector<SourceOrigin> lineOrigins_;
    bool collecting = false;     // pass 1: discover labels; pass 2: emit
    int  emitted = 0;            // guard against pathological blow-up

    bool           deep_ = false;   // data-flow pass active
    bool           rawUnsupported_ = false;
    DataFlowResult df_;             // per-block named/propagated statements + flags + decls
    bool           outputTruncated_ = false;

    Structurer(const ControlFlowGraph& cfg, const DecompileOptions& o) : g(cfg), opt(o) {
        N = (int)g.blocks.size();
        const Arch targetArch = o.target.architecture;
        const DecompileABI targetABI = o.target.abi;
        deep_ = o.deepDataFlow && (targetArch == Arch::X86 || targetArch == Arch::X64);
        rawUnsupported_ = targetArch != Arch::X86 && targetArch != Arch::X64;
        if (deep_) {
            df_ = AnalyzeDataFlow(cfg, o.nameFor, o.dataRefFor, o.callArgs,
                                  targetArch, targetABI);
            if (!df_.ok) deep_ = false;
        }
        build();
    }

    int idxOf(uint64_t va) const { auto it = startToIdx.find(va); return it == startToIdx.end() ? -1 : it->second; }

    void build() {
        stmts.resize(N); flag.resize(N); condMnem.resize(N); term.resize(N);
        trueIdx.assign(N, -1); falseIdx.assign(N, -1); uncondIdx.assign(N, -1); fallIdx.assign(N, -1);
        extTarget.assign(N, 0); succ.resize(N);
        caseIdx.resize(N); caseValue.resize(N); switchExpr.resize(N); indirectExpr.resize(N);
        switchDefaultIdx.assign(N, -1); switchDefaultTarget.assign(N, 0); switchDefaultValid.assign(N, 0);
        for (int i = 0; i < N; ++i) startToIdx[g.blocks[i].start] = i;

        for (int i = 0; i < N; ++i) {
            const BasicBlock& b = g.blocks[i];
            if (b.insns.empty()) { term[i] = Term::Fall; continue; }
            const Instruction& transfer = BlockTransferInstruction(b);
            // Body statements + terminator flag come from the data-flow pass (named,
            // propagated, dead-code-eliminated) when it ran; otherwise fall back to
            // the per-instruction string lift. The terminator (ret/jmp/jcc) is
            // handled by the structuring below in both cases.
            if (deep_) {
                stmts[i].reserve(df_.blockStmts[i].size());
                for (const DataFlowStatement& s : df_.blockStmts[i])
                    stmts[i].push_back({s.text, s.sourceValid ? s.sourceVA : b.start,
                                        s.sourceValid ? SourceOriginGranularity::Instruction
                                                      : SourceOriginGranularity::BasicBlock});
                flag[i]  = df_.termFlag[i];
            } else {
                FlagState fl;
                for (size_t k = 0; k < b.insns.size(); ++k) {
                    if (k == b.transferIndex && !b.isNoReturnCall) continue; // retain noreturn call + delay-slot work
                    std::string s = rawUnsupported_
                        ? "__asm { " + InstructionText(b.insns[k]) + " };"
                        : liftStmt(b.insns[k], fl, opt.nameFor);
                    if (!s.empty()) stmts[i].push_back({std::move(s), b.insns[k].address,
                                                        SourceOriginGranularity::Instruction});
                }
                flag[i] = fl;
            }

            uint64_t fallVA = b.end;
            int fall = idxOf(fallVA);
            // The CFG is authoritative about fallthrough. In particular, two
            // noncontiguous input chunks may be numerically adjacent but must not
            // acquire an edge unless the caller supplied an explicit transfer.
            if (fall >= 0 && std::find(b.succ.begin(), b.succ.end(), static_cast<size_t>(fall)) == b.succ.end())
                fall = -1;
            if (b.isSwitch) {
                term[i] = Term::Switch;
                if (!b.switchCases.empty()) {
                    for (const auto& c : b.switchCases) {
                        caseValue[i].push_back(c.value);
                        caseIdx[i].push_back(c.targetValid ? idxOf(c.target) : -1);
                    }
                } else {
                    for (size_t c = 0; c < b.caseTargets.size(); ++c) {
                        caseValue[i].push_back(static_cast<int64_t>(c));
                        caseIdx[i].push_back(idxOf(b.caseTargets[c]));
                    }
                }
                switchDefaultValid[i] = b.switchDefaultTargetValid;
                switchDefaultTarget[i] = b.switchDefaultTarget;
                if (b.switchDefaultTargetValid) switchDefaultIdx[i] = idxOf(b.switchDefaultTarget);
                switchExpr[i] = switchVar(transfer);
            } else if (b.isReturn) {
                term[i] = Term::Return;
            } else if (b.isNoReturnCall) {
                term[i] = Term::NoReturnCall;
            } else if (b.isUncond) {
                uint64_t directTarget = 0;
                if (!TryGetDirectTarget(transfer, directTarget)) {
                    term[i] = Term::Indirect;
                    indirectExpr[i] = cOperand(transfer.operands);
                } else {
                    int t = idxOf(directTarget);
                    if (t < 0) { term[i] = Term::External; extTarget[i] = directTarget; }
                    else       { term[i] = Term::Uncond;   uncondIdx[i] = t; }
                }
            } else if (InstructionEndsBlock(transfer)) {
                // Conditional jump.
                uint64_t directTarget = 0;
                if (TryGetDirectTarget(transfer, directTarget)) {
                    term[i] = Term::Cond;
                    condMnem[i] = transfer.mnemonic;
                    trueIdx[i]  = idxOf(directTarget);
                    falseIdx[i] = fall;
                    if (trueIdx[i] < 0) extTarget[i] = directTarget;
                } else {
                    term[i] = Term::Indirect; // unresolved indirect control transfer
                    indirectExpr[i] = cOperand(transfer.operands);
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
                case Term::Switch:
                    for (int t : caseIdx[i]) add(t);
                    add(switchDefaultIdx[i]);
                    break;
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
            bool isExit = (term[u] == Term::Return || term[u] == Term::NoReturnCall ||
                           term[u] == Term::External || term[u] == Term::Indirect || succ[u].empty());
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
    void line(int depth, const std::string& s) {
        if (collecting) return;
        std::string l((size_t)depth * 4, ' '); l += s;
        lines_.push_back(std::move(l)); lineVAs_.push_back(0);
        lineOrigins_.push_back({ 0, false, SourceOriginGranularity::Synthetic });
    }
    void line(int depth, const std::string& s, uint64_t va,
              SourceOriginGranularity granularity = SourceOriginGranularity::Instruction) {
        if (collecting) return;
        std::string l((size_t)depth * 4, ' '); l += s;
        lines_.push_back(std::move(l)); lineVAs_.push_back(va);
        lineOrigins_.push_back({ va, true, granularity });
    }
    void rawline(const std::string& s) {
        if (collecting) return;
        lines_.push_back(s); lineVAs_.push_back(0);
        lineOrigins_.push_back({ 0, false, SourceOriginGranularity::Synthetic });
    }
    void rawline(const std::string& s, uint64_t va,
                 SourceOriginGranularity granularity = SourceOriginGranularity::Instruction) {
        if (collecting) return;
        lines_.push_back(s); lineVAs_.push_back(va);
        lineOrigins_.push_back({ va, true, granularity });
    }
    // Source VA for block n's terminator lines (return/goto/if/switch/while):
    // its last instruction, or the block start for an empty block.
    uint64_t termVA(int n) const {
        if (n < 0 || n >= N) return 0;
        if (g.blocks[n].insns.empty()) return g.blocks[n].start;
        return BlockTransferInstruction(g.blocks[n]).address;
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

    void emitStmts(int n, int depth) {
        for (const LiftedStatement& s : stmts[n])
            line(depth, s.text, s.sourceVA, s.granularity);
    }

    void emitFrom(int n, int stop, int depth) {
        while (n >= 0 && n != stop) {
            if (visited[n]) { needLabel[n] = 1; line(depth, "goto " + locLabel(n) + ";", g.blocks[n].start,
                                                    SourceOriginGranularity::BasicBlock); return; }
            if (isHeader[n] && (loopStack.empty() || loopStack.back().header != n)) {
                emitLoop(n, depth);
                int f = loopFollow[n];
                if (f == n || f < 0) return;
                n = f;
                continue;
            }
            visited[n] = 1;
            if (++emitted > 100000) {
                outputTruncated_ = true;
                line(depth, "/* output truncated */");
                return;
            }
            if (needLabel[n]) rawline(locLabel(n) + ":", g.blocks[n].start, SourceOriginGranularity::BasicBlock);
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
            case Term::NoReturnCall:
                line(depth, "__builtin_unreachable(); /* noreturn */", tva);
                return -1;
            case Term::External: {
                char b[40]; std::snprintf(b, sizeof(b), "goto loc_%llX; /* tail */", (unsigned long long)extTarget[n]);
                line(depth, b, tva); return -1;
            }
            case Term::Indirect: {
                std::string operand = trim(indirectExpr[n]);
                if (operand.empty()) operand = "unknown_target";
                line(depth, "goto *(" + operand + "); /* unresolved indirect */", tva);
                return -1;
            }
            case Term::Uncond: {
                int t = uncondIdx[n];
                std::string a = goTo(t);
                if (a.empty()) return t;
                if (a == "continue;") return -1;   // natural loop-back; the while `}` re-loops
                line(depth, a, tva); return -1;
            }
            case Term::Switch: {
                // Recovered jump table -> switch/case. Cases retain their decoded
                // key (including sparse/negative JVM keys); each body runs to the switch's post-dominator (the join),
                // then breaks. Already-emitted targets become goto/continue/break.
                int join = ipdom[n];
                line(depth, "switch (" + (switchExpr[n].empty() ? std::string("switch_index") : switchExpr[n]) + ") {", tva);
                for (size_t c = 0; c < caseIdx[n].size(); ++c) {
                    const int64_t value = c < caseValue[n].size() ? caseValue[n][c] : static_cast<int64_t>(c);
                    line(depth, "case " + std::to_string(value) + ":", tva);
                    int t = caseIdx[n][c];
                    if (t < 0) { line(depth + 1, "break; /* unresolved case */", tva); continue; }
                    std::string a = goTo(t);
                    if (!a.empty()) { line(depth + 1, a, g.blocks[t].start, SourceOriginGranularity::BasicBlock); continue; }
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
                if (switchDefaultValid[n]) {
                    line(depth, "default:", tva);
                    const int t = switchDefaultIdx[n];
                    if (t < 0) {
                        char target[32];
                        std::snprintf(target, sizeof(target), "goto loc_%llX; /* external default */",
                                      (unsigned long long)switchDefaultTarget[n]);
                        line(depth + 1, target, tva);
                    } else {
                        std::string a = goTo(t);
                        if (!a.empty()) line(depth + 1, a, g.blocks[t].start, SourceOriginGranularity::BasicBlock);
                        else {
                            emitFrom(t, join, depth + 1);
                            line(depth + 1, "break;", tva);
                        }
                    }
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
                    // Keep both branch arms explicit.  The taken edge leaves the
                    // supplied function, so every in-function fallthrough block is
                    // controlled by the inverse condition and belongs inside the
                    // else arm.  A one-line guard followed by inline fallthrough is
                    // equivalent in C, but loses that relationship in source-oriented
                    // Python because goto_label() is only an explicit flow placeholder.
                    line(depth, "if (" + cond + ") {", tva);
                    line(depth + 1, "goto loc_" + std::string(tgt) + ";", tva);
                    line(depth, "}", tva);
                    if (cf >= 0) {
                        line(depth, "else {", tva);
                        std::string af = goTo(cf);
                        if (af.empty()) emitFrom(cf, -1, depth + 1);
                        else line(depth + 1, af, tva);
                        line(depth, "}", tva);
                    }
                    return -1;
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
        if (needLabel[h]) rawline(locLabel(h) + ":", g.blocks[h].start, SourceOriginGranularity::BasicBlock);
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
            // When the header's taken arm leaves the supplied function, loop
            // recovery consumes that Jcc while choosing the in-loop fallthrough
            // as the body.  Preserve the destination after the reconstructed
            // loop; otherwise a polling/retry loop silently loses its exit edge.
            // `trueIdx < 0` is the validity bit here (VA zero is a valid target).
            if (!bodyIsTrue && trueIdx[h] < 0) {
                char target[24];
                std::snprintf(target, sizeof(target), "%llX",
                              static_cast<unsigned long long>(extTarget[h]));
                line(depth, "goto loc_" + std::string(target) + ";", termVA(h));
            }
        } else {
            line(depth, "while (1) {", g.blocks[h].start, SourceOriginGranularity::BasicBlock);
            emitStmts(h, depth + 1);
            int nxt = emitTerminator(h, depth + 1);
            emitFrom(nxt, h, depth + 1);
            line(depth, "}", g.blocks[h].start, SourceOriginGranularity::BasicBlock);
        }
        loopStack.pop_back();
    }

    // Stage 4: post-pass that turns a `while (COND) { ...; i++; }` whose induction
    // variable `i` (incremented/decremented as the last body statement and tested
    // in COND) into `for (; COND; i++) { ... }`. Purely textual and conservative:
    // any loop that doesn't match the exact shape is left as a while. Operates on
    // the line/VA vectors in place (the rewritten `for` keeps the while header's
    // VA; the hoisted step line's VA entry is erased with it).
    static void reconstructForLoops(std::vector<std::string>& L, std::vector<uint64_t>& V,
                                    std::vector<SourceOrigin>& O) {
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
            O.erase(O.begin() + s);
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
    static void foldTempsPass(std::vector<std::string>& L, std::vector<uint64_t>& V,
                              std::vector<SourceOrigin>& O) {
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
                        O.erase(O.begin() + j);
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
                    auto isDeclaration = [&](const std::string& l) {
                        const std::string t = trim_(l);
                        return (t.rfind("int " + lhs, 0) == 0 ||
                                t.rfind("__int64 " + lhs, 0) == 0 ||
                                t.rfind("void *" + lhs, 0) == 0) && t.back() == ';';
                    };
                    int total = 0;
                    for (size_t k = 0; k < L.size(); ++k)
                        if (k != i && !isDeclaration(L[k])) total += wordCount(L[k], lhs);
                    int onJ = wordCount(L[j], lhs);
                    std::string ut = trim_(L[j]);
                    bool destOk = !ut.empty() && (ut.back() == ';' || ut.back() == '{');
                    if (total == 1 && onJ == 1 && destOk) {
                        L[j] = wordReplace(L[j], lhs, "(" + rhs + ")");
                        L.erase(L.begin() + i);
                        V.erase(V.begin() + i);
                        O.erase(O.begin() + i);
                        // The folded temporary no longer exists; remove its now-
                        // stale declaration as well (and the matching source map).
                        for (size_t d = 0; d < L.size(); ++d) {
                            if (!isDeclaration(L[d])) continue;
                            L.erase(L.begin() + d);
                            V.erase(V.begin() + d);
                            O.erase(O.begin() + d);
                            break;
                        }
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

        if (N == 0) {
            DecompResult empty;
            empty.text = "// nothing decoded at this address\n";
            empty.lineVA = { 0 };
            empty.lineOrigins = { { 0, false } };
            empty.complete = g.complete;
            empty.incompleteReason = g.incompleteReason;
            return empty;
        }

        // Pass 1: discover which blocks need labels (goto targets).
        needLabel.assign(N, 0);
        visited.assign(N, 0);
        loopStack.clear(); collecting = true; emitted = 0; lines_.clear(); lineVAs_.clear(); lineOrigins_.clear();
        emitFrom(0, -1, 1);

        // Pass 2: emit for real with labels in place.
        visited.assign(N, 0);
        loopStack.clear(); collecting = false; emitted = 0; lines_.clear(); lineVAs_.clear(); lineOrigins_.clear();
        // Header: when the data-flow pass detected parameters, list exactly those (the
        // body names them a1..aN, so the header matches the body) — this surfaces the
        // x86 cdecl/stdcall + Win64 register args. Keep guessSignature's inferred return
        // type when it gave one. Otherwise fall back to the inferred "<ret> (args)"
        // signature (name spliced in) or a plain nullary header (legacy path unchanged).
        std::string header;
        if (deep_ && !df_.args.empty()) {
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
            reconstructForLoops(lines_, lineVAs_, lineOrigins_);
            // Readability post-passes A -> B -> C (deep path only). Order matters:
            // rename counters first (so folding/gloss see the friendly names), then
            // fold single-use temps, then gloss the surviving conditions.
            if (opt.prettyNames)    prettyNamesPass(lines_, lineVAs_);
            if (opt.foldTemps)      foldTempsPass(lines_, lineVAs_, lineOrigins_);
            if (opt.conditionGloss) conditionGlossPass(lines_, lineVAs_);
        }

        // Join with '\n' + trailing '\n' — byte-identical to the legacy string
        // builder (every line() / rawline() appended its own '\n').
        DecompResult r;
        for (const std::string& l : lines_) { r.text += l; r.text += '\n'; }
        r.lineVA = std::move(lineVAs_);
        r.lineOrigins = std::move(lineOrigins_);
        r.complete = g.complete && !outputTruncated_;
        r.incompleteReason = g.incompleteReason;
        if (outputTruncated_) {
            if (!r.incompleteReason.empty()) r.incompleteReason += "; ";
            r.incompleteReason += "decompiler output statement budget exhausted";
        }
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
static bool pyTypeWord(const std::string& s);
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

// Remove syntax that is valid on C literals but not on Python literals. Native
// instruction operands commonly retain ULL/i64/f suffixes, and data references
// may be rendered as wide C strings. The value itself is unchanged.
static std::string pyLiteralSyntax(const std::string& s) {
    static const char* kSuffixes[] = {
        "ui64", "i64", "ull", "llu", "ul", "lu", "ll", "u", "l", "f",
    };
    std::string out;
    out.reserve(s.size());
    char quote = 0;
    for (size_t i = 0; i < s.size();) {
        const char c = s[i];
        if (quote) {
            out += c;
            if (c == '\\' && i + 1 < s.size()) {
                out += s[i + 1];
                i += 2;
                continue;
            }
            if (c == quote) quote = 0;
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') {
            quote = c;
            out += c;
            ++i;
            continue;
        }

        // L"...", u8"...", U'...' -> ordinary Python str literals. Python's
        // `u` prefix would be legal, but dropping every C width prefix produces
        // one stable spelling and avoids the invalid `u8`/`L` variants.
        const bool boundary = i == 0 || !pyIdentChar(s[i - 1]);
        size_t prefix = 0;
        if (boundary && i + 2 < s.size() && s[i] == 'u' && s[i + 1] == '8' &&
            (s[i + 2] == '"' || s[i + 2] == '\''))
            prefix = 2;
        else if (boundary && i + 1 < s.size() &&
                 (s[i] == 'L' || s[i] == 'u' || s[i] == 'U') &&
                 (s[i + 1] == '"' || s[i + 1] == '\''))
            prefix = 1;
        if (prefix) {
            i += prefix;
            continue;
        }

        if (std::isdigit((unsigned char)c) && boundary) {
            size_t j = i;
            bool decimalFloat = false;
            if (j + 2 <= s.size() && s[j] == '0' && j + 1 < s.size() &&
                (s[j + 1] == 'x' || s[j + 1] == 'X')) {
                j += 2;
                while (j < s.size() && std::isxdigit((unsigned char)s[j])) ++j;
            } else if (j + 2 <= s.size() && s[j] == '0' && j + 1 < s.size() &&
                       (s[j + 1] == 'b' || s[j + 1] == 'B')) {
                j += 2;
                while (j < s.size() && (s[j] == '0' || s[j] == '1')) ++j;
            } else {
                while (j < s.size() && std::isdigit((unsigned char)s[j])) ++j;
                if (j < s.size() && s[j] == '.') {
                    decimalFloat = true;
                    ++j;
                    while (j < s.size() && std::isdigit((unsigned char)s[j])) ++j;
                }
                if (j < s.size() && (s[j] == 'e' || s[j] == 'E')) {
                    decimalFloat = true;
                    size_t exponent = j++;
                    if (j < s.size() && (s[j] == '+' || s[j] == '-')) ++j;
                    size_t digits = j;
                    while (j < s.size() && std::isdigit((unsigned char)s[j])) ++j;
                    if (digits == j) j = exponent; // malformed exponent: leave it alone
                }
            }

            size_t suffixLen = 0;
            for (const char* suffix : kSuffixes) {
                const size_t n = std::strlen(suffix);
                if (j + n > s.size()) continue;
                bool equal = true;
                for (size_t k = 0; k < n; ++k)
                    if (std::tolower((unsigned char)s[j + k]) != suffix[k]) { equal = false; break; }
                if (equal && (j + n == s.size() || !pyIdentChar(s[j + n]))) {
                    suffixLen = n;
                    break;
                }
            }
            bool legacyOctal = !decimalFloat && j > i + 1 && s[i] == '0';
            for (size_t k = i + 1; legacyOctal && k < j; ++k)
                if (s[k] < '0' || s[k] > '7') legacyOctal = false;
            if (legacyOctal) {
                out += "0o";
                out.append(s, i + 1, j - i - 1);
            } else {
                out.append(s, i, j - i);
            }
            i = j + suffixLen;
            continue;
        }

        out += c;
        ++i;
    }
    return out;
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
            // Include bitwise NOT: ~(value) is a unary expression, while a
            // tilde embedded in an analyst label still needs name sanitation.
            if (std::string("+-*/%&|^<>~").find(x) != std::string::npos) {
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

static bool pyLooksLikeCast(const std::string& inside) {
    bool signal = false;
    bool token = false;
    for (size_t i = 0; i < inside.size();) {
        while (i < inside.size() && std::isspace((unsigned char)inside[i])) ++i;
        if (i == inside.size()) break;
        if (inside[i] == '*' || inside[i] == '&') {
            signal = true;
            ++i;
            continue;
        }
        if (!(std::isalpha((unsigned char)inside[i]) || inside[i] == '_')) return false;
        size_t b = i++;
        while (i < inside.size() && pyIdentChar(inside[i])) ++i;
        std::string word = inside.substr(b, i - b);
        token = true;
        const bool suffixType = word.size() > 2 && word.compare(word.size() - 2, 2, "_t") == 0;
        const bool namedType = std::isupper((unsigned char)word[0]) || word.rfind("__", 0) == 0;
        signal = signal || pyTypeWord(word) || suffixType || namedType;
        if (i + 1 < inside.size() && inside[i] == ':' && inside[i + 1] == ':') {
            signal = true;
            i += 2;
        }
    }
    return token && signal;
}

static bool pyCallableValue(const std::string& raw) {
    const std::string s = trim(raw);
    if (s.empty() || !(std::isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    size_t i = 1;
    while (i < s.size() && pyIdentChar(s[i])) ++i;
    while (i < s.size()) {
        if (s[i] == '.') {
            if (++i >= s.size() || !(std::isalpha((unsigned char)s[i]) || s[i] == '_')) return false;
            while (i < s.size() && pyIdentChar(s[i])) ++i;
            continue;
        }
        if (s[i] == '[') {
            int depth = 1;
            char quote = 0;
            for (++i; i < s.size() && depth; ++i) {
                const char c = s[i];
                if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
                if (c == '"' || c == '\'') quote = c;
                else if (c == '[') ++depth;
                else if (c == ']') --depth;
            }
            if (depth) return false;
            continue;
        }
        return false;
    }
    return true;
}

// `(*fp)(x)` becomes `(fp)(x)` during dereference lowering. Parenthesized
// callables are legal Python, but the native spelling is simply `fp(x)` (and
// likewise `mem[address](x)` for an indirect call through memory).
static std::string pyUnwrapCallableGroups(std::string s) {
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c != '(') continue;
        const size_t close = pyMatchParen(s, i);
        if (close == std::string::npos || close + 1 >= s.size() || s[close + 1] != '(' ||
            !pyCallableValue(s.substr(i + 1, close - i - 1)))
            continue;
        s.erase(close, 1);
        s.erase(i, 1);
        if (i) --i;
    }
    return s;
}

static bool pyNoneTokenAt(const std::string& s, size_t p) {
    return p + 4 <= s.size() && s.compare(p, 4, "None") == 0 &&
           (p == 0 || !pyIdentChar(s[p - 1])) &&
           (p + 4 == s.size() || !pyIdentChar(s[p + 4]));
}

// Equality against a null pointer is identity in source-level Python. Canonical
// spacing also repairs compact C forms such as `p!=NULL` after NULL -> None.
static std::string pyNoneComparisons(std::string s) {
    char quote = 0;
    for (size_t i = 0; i + 1 < s.size(); ++i) {
        const char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        const bool equal = s[i] == '=' && s[i + 1] == '=';
        const bool unequal = s[i] == '!' && s[i + 1] == '=';
        if (!equal && !unequal) continue;

        size_t leftEnd = i;
        while (leftEnd > 0 && std::isspace((unsigned char)s[leftEnd - 1])) --leftEnd;
        const bool leftNone = leftEnd >= 4 && pyNoneTokenAt(s, leftEnd - 4);
        size_t right = i + 2;
        while (right < s.size() && std::isspace((unsigned char)s[right])) ++right;
        const bool rightNone = pyNoneTokenAt(s, right);
        if (!leftNone && !rightNone) continue;

        size_t replaceBegin = i;
        while (replaceBegin > 0 && std::isspace((unsigned char)s[replaceBegin - 1])) --replaceBegin;
        size_t replaceEnd = i + 2;
        while (replaceEnd < s.size() && std::isspace((unsigned char)s[replaceEnd])) ++replaceEnd;
        const std::string replacement = unequal ? " is not " : " is ";
        s.replace(replaceBegin, replaceEnd - replaceBegin, replacement);
        i = replaceBegin + replacement.size() - 1;
    }
    return s;
}

static size_t pyUnaryOperandEnd(const std::string& s, size_t start) {
    while (start < s.size() && std::isspace((unsigned char)s[start])) ++start;
    if (start >= s.size()) return std::string::npos;
    if ((s[start] == '!' && start + 1 < s.size() && s[start + 1] != '=') ||
        s[start] == '~' || s[start] == '+' || s[start] == '-')
        return pyUnaryOperandEnd(s, start + 1);
    if (s[start] == '(') {
        const size_t close = pyMatchParen(s, start);
        return close == std::string::npos ? close : close + 1;
    }
    if (s[start] == '*' && start + 1 < s.size() && s[start + 1] == '(') {
        const size_t close = pyMatchParen(s, start + 1);
        return close == std::string::npos ? close : close + 1;
    }
    if (!(std::isalpha((unsigned char)s[start]) || s[start] == '_' ||
          std::isdigit((unsigned char)s[start])))
        return start + 1;

    size_t end = start + 1;
    while (end < s.size() && (pyIdentChar(s[end]) || s[end] == '.')) ++end;
    for (;;) {
        if (end < s.size() && s[end] == '(') {
            const size_t close = pyMatchParen(s, end);
            if (close == std::string::npos) return close;
            end = close + 1;
            continue;
        }
        if (end < s.size() && s[end] == '[') {
            int depth = 1;
            char quote = 0;
            size_t i = end + 1;
            for (; i < s.size() && depth; ++i) {
                const char c = s[i];
                if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
                if (c == '"' || c == '\'') quote = c;
                else if (c == '[') ++depth;
                else if (c == ']') --depth;
            }
            if (depth) return std::string::npos;
            end = i;
            continue;
        }
        break;
    }
    return end;
}

struct PyIntegerCast {
    const char* spelling;
    const char* intrinsic;
};

// Python integers have unbounded precision, so dropping a native integer cast
// changes both truncation and sign interpretation. Rewrite every fixed-width C
// spelling the lift emits into an explicit pseudo-intrinsic. Work from right to
// left so nested casts retain their original order.
static std::string pyIntegerCasts(std::string s) {
    static constexpr PyIntegerCast kIntegerCasts[] = {
        { "(unsigned __int8)", "u8" },   { "(unsigned __int16)", "u16" },
        { "(unsigned __int32)", "u32" }, { "(unsigned __int64)", "u64" },
        { "(signed __int8)", "s8" },     { "(signed __int16)", "s16" },
        { "(signed __int32)", "s32" },   { "(signed __int64)", "s64" },
        { "(__int8)", "s8" },            { "(__int16)", "s16" },
        { "(__int32)", "s32" },          { "(__int64)", "s64" },
        { "(uint8_t)", "u8" },           { "(uint16_t)", "u16" },
        { "(uint32_t)", "u32" },         { "(uint64_t)", "u64" },
        { "(int8_t)", "s8" },            { "(int16_t)", "s16" },
        { "(int32_t)", "s32" },          { "(int64_t)", "s64" },
        { "(std::uint8_t)", "u8" },      { "(std::uint16_t)", "u16" },
        { "(std::uint32_t)", "u32" },    { "(std::uint64_t)", "u64" },
        { "(std::int8_t)", "s8" },       { "(std::int16_t)", "s16" },
        { "(std::int32_t)", "s32" },     { "(std::int64_t)", "s64" },
        { "(unsigned char)", "u8" },     { "(signed char)", "s8" },
        { "(char)", "s8" },              { "(unsigned short int)", "u16" },
        { "(signed short int)", "s16" }, { "(short int)", "s16" },
        { "(unsigned short)", "u16" },   { "(signed short)", "s16" },
        { "(short)", "s16" },            { "(unsigned int)", "u32" },
        { "(signed int)", "s32" },       { "(int)", "s32" },
        { "(unsigned)", "u32" },         { "(signed)", "s32" },
        { "(unsigned long long int)", "u64" },
        { "(signed long long int)", "s64" }, { "(long long int)", "s64" },
        { "(unsigned long long)", "u64" }, { "(signed long long)", "s64" },
        { "(long long)", "s64" },
        { "(BYTE)", "u8" },              { "(WORD)", "u16" },
        { "(DWORD)", "u32" },            { "(QWORD)", "u64" },
        { "(BOOL)", "s32" },             { "(WCHAR)", "u16" },
        { "(HRESULT)", "s32" },          { "(bool)", "bool" },
    };

    for (size_t pass = 0; pass <= s.size(); ++pass) {
        size_t found = std::string::npos;
        const PyIntegerCast* cast = nullptr;
        char quote = 0;
        for (size_t i = 0; i < s.size(); ++i) {
            const char c = s[i];
            if (quote) {
                if (c == '\\') ++i;
                else if (c == quote) quote = 0;
                continue;
            }
            if (c == '"' || c == '\'') { quote = c; continue; }
            if (c != '(') continue;
            for (const PyIntegerCast& candidate : kIntegerCasts) {
                const size_t n = std::strlen(candidate.spelling);
                if (s.compare(i, n, candidate.spelling) == 0) {
                    found = i;
                    cast = &candidate;
                    break;
                }
            }
        }
        if (!cast) break;

        size_t operand = found + std::strlen(cast->spelling);
        while (operand < s.size() && std::isspace((unsigned char)s[operand])) ++operand;
        const size_t end = pyUnaryOperandEnd(s, operand);
        if (end == std::string::npos || end <= operand) break;
        std::string value = trim(s.substr(operand, end - operand));
        while (value.size() >= 2 && value.front() == '(' &&
               pyMatchParen(value, 0) == value.size() - 1)
            value = trim(value.substr(1, value.size() - 2));
        const std::string replacement = std::string(cast->intrinsic) + "(" + value + ")";
        s.replace(found, end - found, replacement);
    }
    return s;
}

// Python's `not` binds less tightly than comparisons and arithmetic, while C's
// `!` is a unary operator. Parenthesize only when text follows the operand that
// would otherwise change the grouping (`!x == y` -> `(not x) == y`).
static std::string pyProtectLogicalNot(std::string s) {
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c != '!' || (i + 1 < s.size() && s[i + 1] == '=')) continue;
        size_t operand = i + 1;
        while (operand < s.size() && std::isspace((unsigned char)s[operand])) ++operand;
        const size_t end = pyUnaryOperandEnd(s, operand);
        if (end == std::string::npos) continue;
        size_t next = end;
        while (next < s.size() && std::isspace((unsigned char)s[next])) ++next;
        const bool logicalBoundary = next + 1 < s.size() &&
            (s.compare(next, 2, "&&") == 0 || s.compare(next, 2, "||") == 0);
        const bool safe = next == s.size() || logicalBoundary ||
            (next < s.size() && std::string(")],;").find(s[next]) != std::string::npos);
        if (safe) continue;
        const std::string replacement = "(not " + s.substr(operand, end - operand) + ")";
        s.replace(i, end - i, replacement);
        i += replacement.size() - 1;
    }
    return s;
}

// C logical operators produce integer 0/1; Python and/or return an operand.
// Keep their lazy evaluation, but normalize any logical expression used as a
// value. Delimiter frames handle arguments, indices, assignments, and grouped
// arithmetic without recursively parsing arbitrary expression nesting. A direct
// if/while condition needs only truthiness and can keep its shorter spelling.
static std::string pyLogicalValues(const std::string& s, bool topLevelValue) {
    struct Frame { size_t start; bool logical; };
    struct Event { size_t position; bool open; };
    std::vector<Frame> frames{{0, false}};
    std::vector<Event> events;
    auto finish = [&](size_t end) {
        Frame& frame = frames.back();
        if (frame.logical && (topLevelValue || frames.size() > 1)) {
            size_t begin = frame.start;
            while (begin < end && std::isspace((unsigned char)s[begin])) ++begin;
            while (end > begin && std::isspace((unsigned char)s[end - 1])) --end;
            if (begin < end) {
                events.push_back({begin, true});
                events.push_back({end, false});
            }
        }
        frame.logical = false;
    };
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c == '(' || c == '[' || c == '{') {
            frames.push_back({i + 1, false});
            continue;
        }
        if (c == ')' || c == ']' || c == '}') {
            if (frames.size() > 1) {
                finish(i);
                frames.pop_back();
            }
            continue;
        }
        const bool assignment = c == '=' &&
            (i == 0 || std::string("=!<>").find(s[i - 1]) == std::string::npos) &&
            (i + 1 == s.size() || s[i + 1] != '=');
        if (c == ',' || assignment) {
            finish(i);
            frames.back().start = i + 1;
            continue;
        }
        if (std::isalpha((unsigned char)c) || c == '_') {
            size_t end = i + 1;
            while (end < s.size() && pyIdentChar(s[end])) ++end;
            if ((end - i == 3 && s.compare(i, 3, "and") == 0) ||
                (end - i == 2 && s.compare(i, 2, "or") == 0))
                frames.back().logical = true;
            i = end - 1;
        }
    }
    if (frames.size() != 1) return s; // Leave malformed expressions unchanged.
    finish(s.size());
    if (events.empty()) return s;
    std::sort(events.begin(), events.end(), [](const Event& a, const Event& b) {
        if (a.position != b.position) return a.position < b.position;
        return a.open < b.open; // Close a finished value before the next begins.
    });
    std::string out;
    out.reserve(s.size() + events.size() * 6);
    size_t copied = 0;
    for (const Event& event : events) {
        out.append(s, copied, event.position - copied);
        out += event.open ? "int(bool(" : "))";
        copied = event.position;
    }
    out.append(s, copied, s.size() - copied);
    return out;
}

// Expression rewrite: fixed-width integer casts -> sN/uN, *(X) -> mem[X],
// &(X) -> addr(X), strip pointer/display casts, ! -> not, && / || -> and / or,
// hi:lo -> (hi, lo).
// Quote-aware so string literals inlined by dataRefFor pass through untouched.
static std::string pyExpr(std::string s, bool logicalValue = true) {
    s = pyLiteralSyntax(s);
    s = pyCallNames(std::move(s));
    s = pyProtectLogicalNot(std::move(s));
    s = pyIntegerCasts(std::move(s));
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
        "(const void *)", "(const char *)", "(const wchar_t *)", "(unsigned char *)",
        "(void *)", "(char *)", "(wchar_t *)",
        "(size_t)", "(ssize_t)", "(intptr_t)", "(uintptr_t)",
        "(float)", "(double)", "(long)",
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
        if (c == '(') {   // strip C casts
            bool stripped = false;
            for (const char* cast : kCasts) {
                size_t n = std::strlen(cast);
                if (s.compare(i, n, cast) == 0) { i += n; stripped = true; break; }
            }
            if (!stripped) {
                const size_t close = pyMatchParen(s, i);
                size_t next = close == std::string::npos ? close : close + 1;
                while (next != std::string::npos && next < s.size() &&
                       std::isspace((unsigned char)s[next])) ++next;
                const bool spaced = close != std::string::npos && next > close + 1;
                const bool binaryAfterSpace = next < s.size() && spaced &&
                    std::string("+-*/%&|^<>=?").find(s[next]) != std::string::npos;
                // A cast must be followed by an operand. Closing delimiters
                // and separators instead mean this was a grouped value, e.g.
                // helper((MAGIC)) or table[(value_t)]. Uppercase/suffix-based
                // type guesses alone must not erase those expressions.
                const bool operandFollows = next < s.size() &&
                    (pyIdentChar(s[next]) ||
                     std::string("(\"'!~+-*&").find(s[next]) != std::string::npos ||
                     (s[next] == '.' && next + 1 < s.size() &&
                      std::isdigit((unsigned char)s[next + 1])));
                if (close != std::string::npos && operandFollows && !binaryAfterSpace &&
                    pyLooksLikeCast(s.substr(i + 1, close - i - 1))) {
                    i = close + 1;
                    stripped = true;
                }
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
    return pyLogicalValues(pyUnwrapCallableGroups(pyNoneComparisons(std::move(o))),
                           logicalValue);
}

static std::string pyStripOuterParens(std::string s) {
    s = trim(s);
    while (s.size() >= 2 && s.front() == '(' && pyMatchParen(s, 0) == s.size() - 1)
        s = trim(s.substr(1, s.size() - 2));
    return s;
}

static bool pyTopLevelComparison(const std::string& input, std::string& lhs,
                                 std::string& op, std::string& rhs) {
    const std::string s = pyStripOuterParens(input);
    int paren = 0, bracket = 0;
    char quote = 0;
    size_t found = std::string::npos;
    size_t width = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c == '(') { ++paren; continue; }
        if (c == ')') { --paren; continue; }
        if (c == '[') { ++bracket; continue; }
        if (c == ']') { --bracket; continue; }
        if (paren || bracket) continue;
        size_t n = 0;
        if (i + 1 < s.size() &&
            (s.compare(i, 2, "==") == 0 || s.compare(i, 2, "!=") == 0 ||
             s.compare(i, 2, "<=") == 0 || s.compare(i, 2, ">=") == 0))
            n = 2;
        else if (c == '<' || c == '>')
            n = 1;
        if (!n) continue;
        if (found != std::string::npos) return false;
        found = i;
        width = n;
        i += n - 1;
    }
    if (found == std::string::npos) return false;
    lhs = trim(s.substr(0, found));
    op = s.substr(found, width);
    rhs = trim(s.substr(found + width));
    return !lhs.empty() && !rhs.empty();
}

static uint16_t pyNativeRegisterWidth(std::string reg) {
    reg = trim(reg);
    for (char& c : reg) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    static constexpr const char* k8[] = {
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "sil", "dil", "bpl", "spl"
    };
    static constexpr const char* k16[] = {
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp"
    };
    static constexpr const char* k32[] = {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
    };
    static constexpr const char* k64[] = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"
    };
    for (const char* candidate : k8)  if (reg == candidate) return 8;
    for (const char* candidate : k16) if (reg == candidate) return 16;
    for (const char* candidate : k32) if (reg == candidate) return 32;
    for (const char* candidate : k64) if (reg == candidate) return 64;

    if (reg.size() >= 2 && reg[0] == 'r' && std::isdigit(static_cast<unsigned char>(reg[1]))) {
        size_t end = 1;
        while (end < reg.size() && std::isdigit(static_cast<unsigned char>(reg[end]))) ++end;
        const int number = std::atoi(reg.substr(1, end - 1).c_str());
        if (number < 8 || number > 15) return 0;
        const std::string suffix = reg.substr(end);
        if (suffix.empty()) return 64;
        if (suffix == "d") return 32;
        if (suffix == "w") return 16;
        if (suffix == "b") return 8;
    }
    return 0;
}

static bool pyRedundantRegisterWidthCast(const std::string& value, std::string& reg) {
    const std::string candidate = pyStripOuterParens(value);
    static constexpr struct { const char* prefix; uint16_t width; } kCasts[] = {
        { "u8(", 8 }, { "s8(", 8 }, { "u16(", 16 }, { "s16(", 16 },
        { "u32(", 32 }, { "s32(", 32 }, { "u64(", 64 }, { "s64(", 64 },
    };
    for (const auto& cast : kCasts) {
        const size_t prefixLength = std::strlen(cast.prefix);
        if (candidate.size() <= prefixLength || candidate.compare(0, prefixLength, cast.prefix) != 0 ||
            candidate.back() != ')' || pyMatchParen(candidate, prefixLength - 1) != candidate.size() - 1)
            continue;
        const std::string inner = pyStripOuterParens(
            candidate.substr(prefixLength, candidate.size() - prefixLength - 1));
        if (pyNativeRegisterWidth(inner) != cast.width) return false;
        reg = inner;
        return true;
    }
    return false;
}

// Preserve the comparison emitted from native flag provenance, including an
// explicit == 0 / != 0.  Python truthiness is shorter, but it hides the TEST/CMP
// relationship the pseudocode is meant to explain and can make a goto arm look
// less directly connected to its machine-code predicate.  A width conversion
// around the matching architectural register is redundant for equality with
// zero, so `test eax, eax` remains the more direct `eax != 0`.
static std::string pyCondition(const std::string& c) {
    const std::string expr = pyExpr(c, false);
    std::string lhs, op, rhs;
    if (!pyTopLevelComparison(expr, lhs, op, rhs) || (op != "==" && op != "!="))
        return expr;
    if (lhs == "0") std::swap(lhs, rhs);
    if (rhs != "0") return expr;
    std::string reg;
    return pyRedundantRegisterWidthCast(lhs, reg) ? reg + " " + op + " 0" : expr;
}

// LOBYTE/LOWORD/BYTE1 are readable C lvalues, but function-call syntax cannot
// appear on the left side of a Python assignment. Preserve the untouched bits
// of the full register variable and explicitly narrow the replacement value.
static bool pyPartialWrite(const std::string& input, std::string& output) {
    std::string t = trim(input);
    int delta = 0;
    if (t.rfind("++", 0) == 0 || t.rfind("--", 0) == 0) {
        delta = t[0] == '+' ? 1 : -1;
        t = trim(t.substr(2));
    }

    struct PartialSpec {
        const char* macro;
        const char* intrinsic;
        const char* mask;
        unsigned shift;
    };
    static constexpr PartialSpec kPartial[] = {
        { "LOBYTE", "u8",  "0xFF",   0 },
        { "LOWORD", "u16", "0xFFFF", 0 },
        { "BYTE1",  "u8",  "0xFF00", 8 },
    };

    const PartialSpec* spec = nullptr;
    for (const PartialSpec& candidate : kPartial) {
        const size_t n = std::strlen(candidate.macro);
        if (t.compare(0, n, candidate.macro) == 0 && t.size() > n && t[n] == '(') {
            spec = &candidate;
            break;
        }
    }
    if (!spec) return false;

    const size_t open = std::strlen(spec->macro);
    const size_t close = pyMatchParen(t, open);
    if (close == std::string::npos) return false;
    const std::string base = pyExpr(trim(t.substr(open + 1, close - open - 1)));
    if (base.empty()) return false;
    std::string tail = trim(t.substr(close + 1));

    if (!delta && (tail == "++" || tail == "--")) {
        delta = tail[0] == '+' ? 1 : -1;
        tail.clear();
    }

    std::string current = std::string(spec->intrinsic) + "(" + base;
    if (spec->shift) current += " >> " + std::to_string(spec->shift);
    current += ")";

    std::string narrowed;
    if (delta) {
        if (!tail.empty()) return false;
        narrowed = std::string(spec->intrinsic) + "(" + current +
                   (delta > 0 ? " + 1)" : " - 1)");
    } else {
        struct AssignmentOp { const char* spelling; const char* binary; };
        static constexpr AssignmentOp kOps[] = {
            { "<<=", "<<" }, { ">>=", ">>" }, { "+=", "+" }, { "-=", "-" },
            { "*=", "*" },   { "/=", "/" },  { "%=", "%" }, { "&=", "&" },
            { "|=", "|" },   { "^=", "^" },  { "=",  nullptr },
        };
        const AssignmentOp* assignment = nullptr;
        for (const AssignmentOp& candidate : kOps) {
            const size_t n = std::strlen(candidate.spelling);
            if (tail.compare(0, n, candidate.spelling) == 0) {
                assignment = &candidate;
                tail = trim(tail.substr(n));
                break;
            }
        }
        if (!assignment || tail.empty()) return false;
        const std::string rhs = pyExpr(tail);
        if (rhs.empty()) return false;
        narrowed = std::string(spec->intrinsic) + "(";
        if (assignment->binary)
            narrowed += current + " " + assignment->binary + " ";
        narrowed += rhs + ")";
    }

    output = base + " = (" + base + " & ~" + spec->mask + ") | ";
    if (spec->shift)
        output += "(" + narrowed + " << " + std::to_string(spec->shift) + ")";
    else
        output += narrowed;
    return true;
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
    std::string partial;
    if (pyPartialWrite(t, partial)) return partial;
    if (t == "return")               return "return";
    if (t.rfind("return ", 0) == 0)  return "return " + pyExpr(t.substr(7));
    if (t == "break" || t == "continue") return t;
    if (t.rfind("goto ", 0) == 0) {
        std::string target = trim(t.substr(5));
        if (!target.empty() && target[0] == '*') {
            std::string expression = trim(target.substr(1));
            if (expression.size() >= 2 && expression.front() == '(' &&
                pyMatchParen(expression, 0) == expression.size() - 1)
                expression = expression.substr(1, expression.size() - 2);
            return "indirect_jump(" + pyExpr(expression) + ")";
        }
        std::string quoted = "\"";
        for (char c : target) { if (c == '\\' || c == '"') quoted += '\\'; quoted += c; }
        return "goto_label(" + quoted + "\")"; // explicit placeholder for irreducible direct flow
    }
    if (t.rfind("swap(", 0) == 0 && t.back() == ')') {
        std::string inner = t.substr(5, t.size() - 6), a, b;
        if (split2(inner, a, b)) {
            std::string A = pyExpr(a), B = pyExpr(b);
            // Tuple RHS values are captured together, but Python assigns the
            // targets left-to-right. Store through the original address before
            // replacing a register which may participate in that address:
            // xchg rax, [rax] -> mem[rax], rax = rax, mem[rax].
            const bool simpleA = !A.empty() &&
                (std::isalpha((unsigned char)A.front()) || A.front() == '_') &&
                std::all_of(A.begin(), A.end(), pyIdentChar);
            if (simpleA && B.rfind("mem[", 0) == 0 && B.back() == ']')
                return B + ", " + A + " = " + A + ", " + B;
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
    const bool separated = we < t.size() &&
        (std::isspace((unsigned char)t[we]) || t[we] == '*' || t[we] == '&');
    const bool namedType = separated && !first.empty() && std::isupper((unsigned char)first[0]);
    if (!pyTypeWord(first) && !suffixType && !namedType) return PyDecl::NotDeclaration;

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

static std::vector<std::string> pySplitStatements(const std::string& s) {
    std::vector<std::string> out;
    int paren = 0, bracket = 0, brace = 0;
    char quote = 0;
    size_t begin = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        const char c = i < s.size() ? s[i] : ';';
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') quote = c;
        else if (c == '(') ++paren;
        else if (c == ')') --paren;
        else if (c == '[') ++bracket;
        else if (c == ']') --bracket;
        else if (c == '{') ++brace;
        else if (c == '}') --brace;
        else if (c == ';' && paren == 0 && bracket == 0 && brace == 0) {
            std::string part = trim(s.substr(begin, i - begin));
            if (!part.empty()) out.push_back(std::move(part));
            begin = i + 1;
        }
    }
    return out;
}

static bool pySimpleAssignment(const std::string& line, std::string& lhs, std::string& rhs) {
    const std::string s = pyCodePart(line);
    int paren = 0, bracket = 0;
    char quote = 0;
    size_t equal = std::string::npos;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c == '(') { ++paren; continue; }
        if (c == ')') { --paren; continue; }
        if (c == '[') { ++bracket; continue; }
        if (c == ']') { --bracket; continue; }
        if (c != '=' || paren || bracket) continue;
        const char prev = i ? s[i - 1] : 0;
        const char next = i + 1 < s.size() ? s[i + 1] : 0;
        if (next == '=' || std::string("=!<>+-*/%&|^").find(prev) != std::string::npos)
            continue;
        if (equal != std::string::npos) return false;
        equal = i;
    }
    if (equal == std::string::npos) return false;
    lhs = trim(s.substr(0, equal));
    rhs = trim(s.substr(equal + 1));
    if (lhs.empty() || rhs.empty() || !(std::isalpha((unsigned char)lhs[0]) || lhs[0] == '_'))
        return false;
    for (char c : lhs) if (!pyIdentChar(c)) return false;
    return true;
}

static bool pyCodeContainsWord(const std::string& line, const std::string& word) {
    char quote = 0;
    for (size_t i = 0; i < line.size();) {
        const char c = line[i];
        if (quote) {
            if (c == '\\' && i + 1 < line.size()) { i += 2; continue; }
            if (c == quote) quote = 0;
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') { quote = c; ++i; continue; }
        if (c == '/' && i + 1 < line.size() && (line[i + 1] == '/' || line[i + 1] == '*')) break;
        if (i + word.size() <= line.size() && line.compare(i, word.size(), word) == 0 &&
            (i == 0 || !pyIdentChar(line[i - 1])) &&
            (i + word.size() == line.size() || !pyIdentChar(line[i + word.size()])))
            return true;
        ++i;
    }
    return false;
}

static bool pyCodeWritesWord(const std::string& line, const std::string& word) {
    if (!pyCodeContainsWord(line, word)) return false;
    if (line.find("swap(") != std::string::npos) return true;
    for (size_t p = line.find(word); p != std::string::npos; p = line.find(word, p + 1)) {
        if ((p && pyIdentChar(line[p - 1])) ||
            (p + word.size() < line.size() && pyIdentChar(line[p + word.size()])))
            continue;
        size_t left = p;
        while (left > 0 && std::isspace((unsigned char)line[left - 1])) --left;
        if (left >= 2 && (line.compare(left - 2, 2, "++") == 0 ||
                          line.compare(left - 2, 2, "--") == 0))
            return true;
        size_t right = p + word.size();
        while (right < line.size() && std::isspace((unsigned char)line[right])) ++right;
        if (right + 1 < line.size() && (line.compare(right, 2, "++") == 0 ||
                                        line.compare(right, 2, "--") == 0))
            return true;
        if (right < line.size() && line[right] == '=' &&
            (right + 1 == line.size() || line[right + 1] != '='))
            return true;
        if (right + 1 < line.size() && line[right + 1] == '=' &&
            std::string("+-*/%&|^<>").find(line[right]) != std::string::npos)
            return true;
    }
    return false;
}

static bool pyCodeTakesAddressOf(const std::string& line, const std::string& word) {
    for (size_t p = line.find(word); p != std::string::npos; p = line.find(word, p + 1)) {
        if ((p && pyIdentChar(line[p - 1])) ||
            (p + word.size() < line.size() && pyIdentChar(line[p + word.size()])))
            continue;
        size_t marker = p;
        while (marker > 0 && std::isspace((unsigned char)line[marker - 1])) --marker;
        if (marker > 0 && line[marker - 1] == '(') {
            --marker;
            while (marker > 0 && std::isspace((unsigned char)line[marker - 1])) --marker;
        }
        if (marker == 0 || line[marker - 1] != '&') continue;
        size_t before = marker - 1;
        while (before > 0 && std::isspace((unsigned char)line[before - 1])) --before;
        if (before == 0 || std::string("=(,[{!?:+-*/%&|^<>").find(line[before - 1]) != std::string::npos)
            return true;
    }
    return false;
}

static std::string pyCStructurePart(const std::string& line) {
    char quote = 0;
    for (size_t i = 0; i + 1 < line.size(); ++i) {
        const char c = line[i];
        if (quote) { if (c == '\\') ++i; else if (c == quote) quote = 0; continue; }
        if (c == '"' || c == '\'') { quote = c; continue; }
        if (c == '/' && (line[i + 1] == '/' || line[i + 1] == '*'))
            return trim(line.substr(0, i));
    }
    return trim(line);
}

static size_t pyMatchingBlockClose(const std::vector<std::string>& lines, size_t opener) {
    int depth = 0;
    for (size_t i = opener; i < lines.size(); ++i) {
        const std::string t = pyCStructurePart(lines[i]);
        if (t == "{" || (t.size() >= 2 && t.compare(t.size() - 2, 2, " {") == 0)) ++depth;
        if (t == "}" && --depth == 0) return i;
    }
    return std::string::npos;
}

struct PyRangeParts {
    std::string variable;
    std::string stop;
    std::string comparisonCast;
    long long step = 0;
    bool inclusive = false;
};

static bool pyPositiveInteger(const std::string& input, long long& value) {
    const std::string s = pyLiteralSyntax(trim(input));
    if (s.empty()) return false;
    char* end = nullptr;
    errno = 0;
    value = std::strtoll(s.c_str(), &end, 0);
    return end != s.c_str() && *end == '\0' && errno != ERANGE && value > 0;
}

static bool pyParseRangeParts(const std::string& condition, const std::string& stepText,
                              PyRangeParts& out) {
    const std::string step = trim(stepText);
    long long stride = 0;
    std::string variable;
    if (step.size() > 2 && (step.compare(step.size() - 2, 2, "++") == 0 ||
                            step.compare(step.size() - 2, 2, "--") == 0)) {
        variable = trim(step.substr(0, step.size() - 2));
        stride = step.back() == '+' ? 1 : -1;
    } else {
        size_t op = step.find(" += ");
        bool subtract = false;
        if (op == std::string::npos) { op = step.find(" -= "); subtract = true; }
        if (op == std::string::npos) return false;
        variable = trim(step.substr(0, op));
        long long magnitude = 0;
        if (!pyPositiveInteger(step.substr(op + 4), magnitude)) return false;
        stride = subtract ? -magnitude : magnitude;
    }
    if (variable.empty() || !(std::isalpha((unsigned char)variable[0]) || variable[0] == '_')) return false;
    for (char c : variable) if (!pyIdentChar(c)) return false;

    std::string lhs, op, rhs;
    if (!pyTopLevelComparison(pyExpr(condition), lhs, op, rhs)) return false;
    auto stripRedundantParens = [](std::string value) {
        value = trim(value);
        while (value.size() >= 2 && value.front() == '(' &&
               pyMatchParen(value, 0) == value.size() - 1)
            value = trim(value.substr(1, value.size() - 2));
        return value;
    };
    lhs = stripRedundantParens(lhs);
    rhs = stripRedundantParens(rhs);
    auto unwrapFixedCast = [&](const std::string& value, std::string& intrinsic,
                               std::string& inner) {
        const size_t open = value.find('(');
        if (open == std::string::npos || pyMatchParen(value, open) != value.size() - 1)
            return false;
        intrinsic = value.substr(0, open);
        if (intrinsic != "u8" && intrinsic != "u16" && intrinsic != "u32" &&
            intrinsic != "u64" && intrinsic != "s8" && intrinsic != "s16" &&
            intrinsic != "s32" && intrinsic != "s64")
            return false;
        inner = stripRedundantParens(value.substr(open + 1, value.size() - open - 2));
        return !inner.empty();
    };
    std::string lhsCast, rhsCast, lhsInner, rhsInner;
    if (unwrapFixedCast(lhs, lhsCast, lhsInner) &&
        unwrapFixedCast(rhs, rhsCast, rhsInner) && lhsCast == rhsCast) {
        // Keep the cast contract until the start, bound, and terminal step have
        // been proved in range. Otherwise range() would silently erase native
        // signedness or make a wrapping loop appear finite.
        out.comparisonCast = lhsCast;
        lhs = lhsInner;
        rhs = rhsInner;
    }
    if (rhs == variable) {
        std::swap(lhs, rhs);
        if (op == "<") op = ">";
        else if (op == ">") op = "<";
        else if (op == "<=") op = ">=";
        else if (op == ">=") op = "<=";
    }
    if (lhs != variable) return false;
    if (stride > 0 && op != "<" && op != "<=") return false;
    if (stride < 0 && op != ">" && op != ">=") return false;
    out.variable = variable;
    out.stop = rhs;
    out.step = stride;
    out.inclusive = op == "<=" || op == ">=";
    return true;
}

static std::string pyAdjustedRangeStop(const std::string& stop, int delta) {
    char* end = nullptr;
    errno = 0;
    const long long value = std::strtoll(stop.c_str(), &end, 0);
    if (end != stop.c_str() && *end == '\0' && errno != ERANGE &&
        !((delta > 0 && value == LLONG_MAX) || (delta < 0 && value == LLONG_MIN)))
        return std::to_string(value + delta);

    bool atomic = !stop.empty() && (std::isalnum((unsigned char)stop[0]) || stop[0] == '_');
    for (char c : stop) if (!(pyIdentChar(c) || c == '.')) { atomic = false; break; }
    const std::string base = atomic ? stop : "(" + stop + ")";
    return base + (delta > 0 ? " + 1" : " - 1");
}

static bool pyRangeSemanticsSafe(const std::vector<std::string>& lines, size_t opener,
                                 const PyRangeParts& range, const std::string& start,
                                 size_t& close) {
    if (!range.comparisonCast.empty()) {
        auto integer = [](const std::string& input, long long& value) {
            std::string text = pyLiteralSyntax(trim(input));
            while (text.size() >= 2 && text.front() == '(' &&
                   pyMatchParen(text, 0) == text.size() - 1)
                text = trim(text.substr(1, text.size() - 2));
            // pyLiteralSyntax spells C octal in Python's 0o form.
            const size_t prefix = !text.empty() && (text[0] == '-' || text[0] == '+') ? 1 : 0;
            if (text.compare(prefix, 2, "0o") == 0) text.erase(prefix + 1, 1);
            char* end = nullptr;
            errno = 0;
            value = std::strtoll(text.c_str(), &end, 0);
            return end != text.c_str() && *end == '\0' && errno != ERANGE;
        };
        long long first = 0, stop = 0;
        if (!integer(start, first) || !integer(range.stop, stop)) return false;
        const bool isSigned = range.comparisonCast[0] == 's';
        const unsigned bits = static_cast<unsigned>(std::strtoul(range.comparisonCast.c_str() + 1,
                                                               nullptr, 10));
        const long long minimum = !isSigned ? 0 : bits == 64 ? LLONG_MIN : -(1LL << (bits - 1));
        // Values beyond LLONG_MAX are intentionally unproved, including u64
        // bounds; retaining while is preferable to lossy range reconstruction.
        const long long maximum = bits == 64 ? LLONG_MAX :
            (1LL << (isSigned ? bits - 1 : bits)) - 1;
        if (first < minimum || first > maximum || stop < minimum || stop > maximum)
            return false;
        const bool enters = range.step > 0 ?
            (range.inclusive ? first <= stop : first < stop) :
            (range.inclusive ? first >= stop : first > stop);
        if (enters) {
            // Account for the step executed after the last body iteration. A
            // strict bound permits one less unit of overshoot than an inclusive
            // bound. These conservative limits avoid any signed host overflow.
            const long long magnitude = range.step > 0 ? range.step : -range.step;
            const long long overshoot = magnitude - (range.inclusive ? 0 : 1);
            if (range.step > 0 ? stop > maximum - overshoot : stop < minimum + overshoot)
                return false;
        }
    }
    close = pyMatchingBlockClose(lines, opener);
    if (close == std::string::npos) return false;
    for (size_t i = opener + 1; i < close; ++i) {
        if (pyCodeWritesWord(lines[i], range.variable) ||
            pyCodeTakesAddressOf(lines[i], range.variable) ||
            pyCodeContainsWord(lines[i], "goto"))
            return false;
    }

    // range() snapshots its stop once. Reject call/subscript bounds and any
    // simple bound variable that the loop body writes.
    if (range.stop.find('(') != std::string::npos || range.stop.find('[') != std::string::npos)
        return false;
    for (size_t p = 0; p < range.stop.size();) {
        if (!(std::isalpha((unsigned char)range.stop[p]) || range.stop[p] == '_')) { ++p; continue; }
        size_t e = p + 1;
        while (e < range.stop.size() && pyIdentChar(range.stop[e])) ++e;
        const std::string name = range.stop.substr(p, e - p);
        for (size_t i = opener + 1; i < close; ++i)
            if (pyCodeWritesWord(lines[i], name) || pyCodeTakesAddressOf(lines[i], name)) return false;
        p = e;
    }
    for (size_t i = close + 1; i < lines.size(); ++i)
        if (pyCodeContainsWord(lines[i], range.variable)) return false;
    return true;
}

static std::string pyRangeCall(const std::string& start, const PyRangeParts& range) {
    std::string stop = range.stop;
    if (range.inclusive) stop = pyAdjustedRangeStop(stop, range.step > 0 ? 1 : -1);
    if (range.step == 1 && start == "0") return "range(" + stop + ")";
    std::string call = "range(" + start + ", " + stop;
    if (range.step != 1) call += ", " + std::to_string(range.step);
    return call + ")";
}

// The C structurer represents an else-if as an `else` containing one nested
// `if`. Collapse only when that if/else chain is the outer else's sole executable
// child, so Python gets the natural `elif` spelling without changing semantics.
static void pyFoldElif(std::vector<std::string>& lines, std::vector<uint64_t>& vas,
                       std::vector<SourceOrigin>& origins) {
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
        if (i < origins.size() && nested < origins.size()) origins[i] = origins[nested];
        lines.erase(lines.begin() + nested);
        if (nested < vas.size()) vas.erase(vas.begin() + nested);
        if (nested < origins.size()) origins.erase(origins.begin() + nested);
        --end;
        for (size_t k = i + 1; k < end; ++k) {
            size_t ind = pyIndentOf(lines[k]);
            if (ind >= childIndent) lines[k].erase(0, 4);
        }
    }
}

// Consecutive C case labels share one body. Python match has no fallthrough, so
// represent that exact shape as an OR-pattern instead of inventing an empty first
// case (`case 0 | 1:` is the source-level Python equivalent).
static void pyMergeEmptyCases(std::vector<std::string>& lines, std::vector<uint64_t>& vas,
                              std::vector<SourceOrigin>& origins) {
    auto pattern = [](const std::string& line, std::string& value) {
        const std::string code = pyCodePart(line);
        if (trim(line) != code || code.rfind("case ", 0) != 0 || code.back() != ':') return false;
        value = trim(code.substr(5, code.size() - 6));
        return !value.empty() && value != "_";
    };
    for (size_t i = 0; i + 1 < lines.size();) {
        size_t next = i + 1;
        while (next < lines.size() && trim(lines[next]).empty()) ++next;
        std::string first, second;
        if (next == lines.size() || !pattern(lines[i], first) || !pattern(lines[next], second) ||
            pyIndentOf(lines[i]) != pyIndentOf(lines[next])) {
            ++i;
            continue;
        }
        lines[i] = std::string(pyIndentOf(lines[i]), ' ') + "case " + first + " | " + second + ":";
        lines.erase(lines.begin() + next);
        if (next < vas.size()) vas.erase(vas.begin() + next);
        if (next < origins.size()) origins.erase(origins.begin() + next);
    }
}

// Dropping C declarations/braces and match-ending breaks can expose genuinely
// empty Python suites (an empty spin loop and a break-only switch case are common
// binary shapes). Insert a mapped `pass`; an empty match needs a wildcard case
// because Python's match grammar does not accept a plain statement as its suite.
static void pyEnsureNonEmptySuites(std::vector<std::string>& lines, std::vector<uint64_t>& vas,
                                   std::vector<SourceOrigin>& origins) {
    const size_t n = lines.size();
    std::vector<size_t> nextCode(n + 1, n);
    for (size_t i = n; i-- > 0;)
        nextCode[i] = pyCodePart(lines[i]).empty() ? nextCode[i + 1] : i;

    std::vector<std::string> rebuilt;
    std::vector<uint64_t> rebuiltVA;
    std::vector<SourceOrigin> rebuiltOrigins;
    rebuilt.reserve(n + n / 8 + 2);
    rebuiltVA.reserve(rebuilt.capacity());
    rebuiltOrigins.reserve(rebuilt.capacity());
    for (size_t i = 0; i < lines.size(); ++i) {
        rebuilt.push_back(lines[i]);
        rebuiltVA.push_back(i < vas.size() ? vas[i] : 0);
        rebuiltOrigins.push_back(i < origins.size() ? origins[i] : SourceOrigin{});
        std::string code = pyCodePart(lines[i]);
        if (code.empty() || code.back() != ':') continue;   // not a compound-statement header
        size_t ind = pyIndentOf(lines[i]);
        size_t j = nextCode[i + 1];
        if (j < lines.size() && pyIndentOf(lines[j]) > ind) continue;

        const uint64_t va = i < vas.size() ? vas[i] : 0;
        if (code.rfind("match ", 0) == 0) {
            rebuilt.push_back(std::string(ind + 4, ' ') + "case _:");
            rebuiltVA.push_back(va);
            rebuiltOrigins.push_back(SourceOrigin{});
            rebuilt.push_back(std::string(ind + 8, ' ') + "pass");
            rebuiltVA.push_back(va);
            rebuiltOrigins.push_back(SourceOrigin{});
        } else {
            rebuilt.push_back(std::string(ind + 4, ' ') + "pass");
            rebuiltVA.push_back(va);
            rebuiltOrigins.push_back(SourceOrigin{});
        }
    }
    lines.swap(rebuilt);
    vas.swap(rebuiltVA);
    origins.swap(rebuiltOrigins);
}

} // namespace

static DecompileDiagnosticKind diagnosticKindForReason(std::string_view reason) {
    if (reason.find("budget") != std::string_view::npos)
        return DecompileDiagnosticKind::InstructionLimit;
    if (reason.find("decoder") != std::string_view::npos ||
        reason.find("decode") != std::string_view::npos)
        return DecompileDiagnosticKind::DecodeFailure;
    if (reason.find("chunk") != std::string_view::npos ||
        reason.find("supplied") != std::string_view::npos ||
        reason.find("target") != std::string_view::npos)
        return DecompileDiagnosticKind::MissingChunk;
    if (reason.find("clamp") != std::string_view::npos ||
        reason.find("address range") != std::string_view::npos)
        return DecompileDiagnosticKind::ClippedInput;
    return DecompileDiagnosticKind::Other;
}

static void ensureCompletenessDiagnostic(DecompResult& result) {
    if (!result.complete && result.diagnostics.empty()) {
        const std::string message = result.incompleteReason.empty()
                                  ? "decompilation input was incomplete"
                                  : result.incompleteReason;
        result.diagnostics.push_back({diagnosticKindForReason(message), message});
    }
}

DecompResult DecompileWithMap(const ControlFlowGraph& g, const DecompileOptions& opt) {
    if (g.blocks.empty()) {
        DecompResult r;
        r.text = "// no code\n";
        r.lineVA = { 0 };
        r.lineOrigins = { { 0, false } };
        r.complete = g.complete;
        r.incompleteReason = g.incompleteReason;
        ensureCompletenessDiagnostic(r);
        return r;
    }
    Structurer s(g, opt);
    DecompResult result = s.run(g.funcStart);
    ensureCompletenessDiagnostic(result);
    return result;
}

DecompResult DecompileWithMap(const std::vector<CFGCodeChunk>& chunks,
                              IDisassembler& dis,
                              const DecompileOptions& opt,
                              size_t maxInsns,
                              const JumpTableResolver& resolveTable,
                              const NoreturnCallResolver& isNoreturnCall,
                              const DirectTargetResolver& resolveDirectTarget) {
    return DecompileWithMap(BuildCFG(chunks, dis, maxInsns, resolveTable,
                                     isNoreturnCall, resolveDirectTarget), opt);
}

std::string Decompile(const ControlFlowGraph& g, const DecompileOptions& opt) {
    return DecompileWithMap(g, opt).text;
}

std::string Decompile(const std::vector<CFGCodeChunk>& chunks,
                      IDisassembler& dis,
                      const DecompileOptions& opt,
                      size_t maxInsns,
                      const JumpTableResolver& resolveTable,
                      const NoreturnCallResolver& isNoreturnCall,
                      const DirectTargetResolver& resolveDirectTarget) {
    return DecompileWithMap(chunks, dis, opt, maxInsns, resolveTable,
                            isNoreturnCall, resolveDirectTarget).text;
}

DecompResult DecompileToPython(const DecompResult& c) {
    // Split into lines (DecompResult convention: no entry for the empty segment
    // after the trailing '\n').
    std::vector<std::string> L; std::vector<uint64_t> V; std::vector<SourceOrigin> O;
    for (size_t s = 0, i = 0; i <= c.text.size(); ++i)
        if (i == c.text.size() || c.text[i] == '\n') {
            if (i == c.text.size() && s == i) break;
            L.push_back(c.text.substr(s, i - s));
            s = i + 1;
        }
    V = c.lineVA; V.resize(L.size(), 0);
    O = c.lineOrigins;
    if (O.size() != L.size()) {
        O.assign(L.size(), {});
        for (size_t i = 0; i < L.size(); ++i)
            O[i] = { V[i], V[i] != 0,
                     V[i] != 0 ? SourceOriginGranularity::Instruction
                               : SourceOriginGranularity::Synthetic };
    }

    DecompResult r;
    std::vector<std::string> out; std::vector<uint64_t> outVA; std::vector<SourceOrigin> outOrigins;
    struct Blk { size_t indent; int kind; std::string step; uint64_t stepVA; SourceOrigin stepOrigin; }; // kind 0=other 1=loop 2=switch
    std::vector<Blk> stack;
    SourceOrigin activeOrigin;
    bool sawHeaderCandidate = false;
    auto switchDepth = [&]() { size_t n = 0; for (const Blk& b : stack) if (b.kind == 2) ++n; return n; };
    auto currentLoop = [&]() -> const Blk* {
        for (auto it = stack.rbegin(); it != stack.rend(); ++it)
            if (it->kind == 1) return &*it;
        return nullptr;
    };
    auto emitAt = [&](size_t indent, const std::string& s, uint64_t va) {
        out.push_back(std::string(indent + 4 * switchDepth(), ' ') + s);
        outVA.push_back(va);
        outOrigins.push_back(activeOrigin);
    };
    auto emitStatementsAt = [&](size_t indent, const std::string& statements,
                                const std::string& comment, uint64_t va) {
        std::vector<std::string> parts = pySplitStatements(statements);
        if (parts.empty()) {
            if (!comment.empty()) emitAt(indent, comment.substr(2), va);
            return;
        }
        for (size_t part = 0; part < parts.size(); ++part)
            emitAt(indent, parts[part] + (part + 1 == parts.size() ? comment : std::string()), va);
    };

    for (size_t i = 0; i < L.size(); ++i) {
        const std::string& raw = L[i];
        const uint64_t va = V[i];
        activeOrigin = O[i];
        size_t ind = 0; while (ind < raw.size() && raw[ind] == ' ') ++ind;
        std::string t = raw.substr(ind);
        while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();

        if (t.empty()) { out.push_back(""); outVA.push_back(va); outOrigins.push_back(activeOrigin); continue; }

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

        if (!sawHeaderCandidate) { // first non-comment line is the function header candidate
            sawHeaderCandidate = true;
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

        if (t == "{") { stack.push_back({ ind, 0, "", 0, {} }); continue; }
        if (t == "}") {
            if (!stack.empty()) {
                Blk b = stack.back(); stack.pop_back();
                if (b.kind == 1 && !b.step.empty()) {
                    SourceOrigin saved = activeOrigin; activeOrigin = b.stepOrigin;
                    emitAt(b.indent + 4, b.step, b.stepVA); activeOrigin = saved;
                }   // for-loop step
            }
            continue;
        }

        if (t.size() > 2 && t.compare(t.size() - 2, 2, " {") == 0) {   // block opener "X {"
            std::string head = t.substr(0, t.size() - 2);
            while (!head.empty() && head.back() == ' ') head.pop_back();
            if (head == "while (1)") { emitAt(ind, "while True:" + cmt, va); stack.push_back({ ind, 1, "", 0, {} }); }
            else if (head.rfind("for (; ", 0) == 0 && head.back() == ')') {
                std::string inner = head.substr(7, head.size() - 8);     // "COND; STEP"
                size_t semi = inner.rfind("; ");
                std::string cond = semi == std::string::npos ? inner : inner.substr(0, semi);
                std::string step = semi == std::string::npos ? std::string() : inner.substr(semi + 2);
                PyRangeParts range;
                size_t close = std::string::npos;
                size_t init = out.size();
                while (init > 0 && trim(out[init - 1]).empty()) --init;
                if (init > 0) --init; else init = std::string::npos;
                std::string initVar, start;
                const size_t renderedIndent = ind + 4 * switchDepth();
                const bool rangeReady = !step.empty() && pyParseRangeParts(cond, step, range) &&
                    init != std::string::npos && pyIndentOf(out[init]) == renderedIndent &&
                    trim(out[init]) == pyCodePart(out[init]) &&
                    pySimpleAssignment(out[init], initVar, start) && initVar == range.variable &&
                    pyRangeSemanticsSafe(L, i, range, start, close);
                if (rangeReady) {
                    const std::string initText = trim(out[init]);
                    const uint64_t initVA = init < outVA.size() ? outVA[init] : 0;
                    const SourceOrigin initOrigin = init < outOrigins.size() ? outOrigins[init] : SourceOrigin{};
                    out.erase(out.begin() + init);
                    if (init < outVA.size()) outVA.erase(outVA.begin() + init);
                    if (init < outOrigins.size()) outOrigins.erase(outOrigins.begin() + init);
                    // range() absorbs the initializer syntactically, but its
                    // instruction is still independently navigable in the source
                    // map. Retain it as a mapped source-oriented comment.
                    const SourceOrigin headerOrigin = activeOrigin;
                    activeOrigin = initOrigin;
                    emitAt(ind, "# init: " + initText, initVA);
                    activeOrigin = headerOrigin;
                    emitAt(ind, "for " + range.variable + " in " + pyRangeCall(start, range) + ":" + cmt, va);
                    stack.push_back({ ind, 1, "", 0, {} });
                } else {
                    emitAt(ind, "while " + pyCondition(cond) + ":" + cmt, va);
                    stack.push_back({ ind, 1, step.empty() ? std::string() : pyStmt(step), va, activeOrigin });
                }
            }
            else if (head.rfind("while (", 0) == 0 && head.back() == ')') {
                emitAt(ind, "while " + pyCondition(head.substr(7, head.size() - 8)) + ":" + cmt, va);
                stack.push_back({ ind, 1, "", 0, {} });
            }
            else if (head == "else") { emitAt(ind, "else:" + cmt, va); stack.push_back({ ind, 0, "", 0, {} }); }
            else if (head.rfind("if (", 0) == 0 && head.back() == ')') {
                emitAt(ind, "if " + pyCondition(head.substr(4, head.size() - 5)) + ":" + cmt, va);
                stack.push_back({ ind, 0, "", 0, {} });
            }
            else if (head.rfind("switch (", 0) == 0 && head.back() == ')') {
                emitAt(ind, "match " + pyExpr(head.substr(8, head.size() - 9)) + ":" + cmt, va);
                stack.push_back({ ind, 2, "", 0, {} });   // push AFTER emit: the match line sits outside
            }
            else { emitAt(ind, head + ":" + cmt, va); stack.push_back({ ind, 0, "", 0, {} }); }
            continue;
        }

        if (pyIsLabel(t)) { emitAt(ind, "# " + t, va); continue; }       // goto target marker
        if (t.rfind("case ", 0) == 0 && t.back() == ':') {
            emitAt(ind, "case " + pyExpr(t.substr(5, t.size() - 6)) + ":" + cmt, va);
            continue;
        }
        if (t == "default:") { emitAt(ind, "case _:" + cmt, va); continue; }

        if (!t.empty() && t.back() == ';') {                             // plain statement
            std::string declStatement;
            PyDecl decl = pyDeclaration(t, declStatement);
            if (decl == PyDecl::Uninitialized) {
                if (!cmt.empty()) emitAt(ind, cmt.substr(2), va);
                continue;
            }
            if (decl == PyDecl::Initialized) {
                emitStatementsAt(ind, declStatement, cmt, va);
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
                            emitAt(ind, "if " + pyCondition(cond) + ":", va);
                            const SourceOrigin saved = activeOrigin;
                            activeOrigin = loop->stepOrigin;
                            emitAt(ind + 4, loop->step, loop->stepVA);
                            activeOrigin = saved;
                            emitAt(ind + 4, "continue" + cmt, va);
                            continue;
                        }
                    }
                    emitAt(ind, "if " + pyCondition(cond) + ":", va);
                    emitStatementsAt(ind + 4, pyStmt(rest), cmt, va);
                    continue;
                }
            }
            if (stmt == "break") {   // match-case needs no break; loop break stays
                bool inSwitch = false;
                for (auto it = stack.rbegin(); it != stack.rend(); ++it)
                    if (it->kind == 1) break; else if (it->kind == 2) { inSwitch = true; break; }
                if (inSwitch) {
                    if (!cmt.empty()) emitAt(ind, "pass" + cmt, va);
                    else {
                        size_t previous = out.size();
                        while (previous > 0 && pyCodePart(out[previous - 1]).empty()) --previous;
                        if (previous > 0) {
                            const size_t header = previous - 1;
                            const std::string code = pyCodePart(out[header]);
                            if (code.rfind("case ", 0) == 0 && code.back() == ':' &&
                                pyIndentOf(out[header]) + 4 == ind + 4 * switchDepth()) {
                                // This empty arm exits the switch. Keep an
                                // explicit synthetic body before label merging
                                // can confuse it with source fallthrough.
                                activeOrigin = {};
                                emitAt(ind, "pass", outVA[header]);
                            }
                        }
                    }
                    continue;
                }
            }
            if (stmt == "continue") {
                const Blk* loop = currentLoop();
                if (loop && !loop->step.empty()) {
                    const SourceOrigin saved = activeOrigin;
                    activeOrigin = loop->stepOrigin;
                    emitAt(ind, loop->step, loop->stepVA);
                    activeOrigin = saved;
                }
            }
            emitStatementsAt(ind, pyStmt(stmt), cmt, va);
            continue;
        }

        emitAt(ind, pyExpr(t) + cmt, va);   // anything else: best-effort expression rewrite
    }

    pyMergeEmptyCases(out, outVA, outOrigins);
    pyFoldElif(out, outVA, outOrigins);
    pyEnsureNonEmptySuites(out, outVA, outOrigins);
    for (const std::string& l : out) { r.text += l; r.text += '\n'; }
    r.lineVA = std::move(outVA);
    r.lineOrigins = std::move(outOrigins);
    r.complete = c.complete;
    r.incompleteReason = c.incompleteReason;
    r.diagnostics = c.diagnostics;
    return r;
}

} // namespace ds
