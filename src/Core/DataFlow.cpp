#include "DataFlow.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ds {
namespace {

// ------------------------------------------------------------------ utils ---

std::string trim(const std::string& x) {
    size_t s = x.find_first_not_of(" \t");
    size_t e = x.find_last_not_of(" \t");
    return s == std::string::npos ? std::string() : x.substr(s, e - s + 1);
}
std::string lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}
// Split "a, b" at the first top-level comma (ignoring commas inside []/()).
bool split2(const std::string& ops, std::string& a, std::string& b) {
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

// ------------------------------------------------------------- registers ---
// Canonical 64-bit register index 0..15 (x86 encoding order), -1 = untracked
// (rip / xmm / segment / unknown). Sub-registers alias the same canonical id.
enum { RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7 };

struct RegInfo { int canon = -1; int width = 8; bool high8 = false; };

const std::unordered_map<std::string, RegInfo>& regTable() {
    static const std::unordered_map<std::string, RegInfo> t = [] {
        std::unordered_map<std::string, RegInfo> m;
        const char* r64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                               "r8","r9","r10","r11","r12","r13","r14","r15"};
        const char* r32[8]  = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
        const char* r16[8]  = {"ax","cx","dx","bx","sp","bp","si","di"};
        const char* r8l[8]  = {"al","cl","dl","bl","spl","bpl","sil","dil"};
        const char* r8h[4]  = {"ah","ch","dh","bh"};
        for (int i = 0; i < 16; ++i) m[r64[i]] = { i, 8, false };
        for (int i = 0; i < 8;  ++i) { m[r32[i]] = { i, 4, false }; m[r16[i]] = { i, 2, false }; m[r8l[i]] = { i, 1, false }; }
        for (int i = 0; i < 4;  ++i) m[r8h[i]] = { i, 1, true };
        for (int i = 8; i < 16; ++i) {
            std::string b = "r" + std::to_string(i);
            m[b + "d"] = { i, 4, false }; m[b + "w"] = { i, 2, false }; m[b + "b"] = { i, 1, false };
        }
        return m;
    }();
    return t;
}
bool lookupReg(const std::string& tok, RegInfo& out) {
    auto& t = regTable();
    auto it = t.find(lower(tok));
    if (it == t.end()) return false;
    out = it->second; return true;
}

// --------------------------------------------------------------- operands ---

enum class OK { None, Reg, Imm, Mem, Sym };
struct Mem {
    bool baseReg = false; int baseCanon = -1;
    bool hasIndex = false; int idxCanon = -1; int scale = 1;
    long long disp = 0; bool ripRel = false; bool dispOnly = false;
    int width = 8; std::string raw;
};
struct Operand {
    OK kind = OK::None;
    RegInfo reg;
    long long imm = 0;
    Mem mem;
    std::string sym;     // symbol / unparsed token
    std::string raw;     // original text
    bool parsed = false;
};

bool parseImm(const std::string& s, long long& out) {
    std::string t = trim(s);
    if (t.empty()) return false;
    bool neg = false; size_t i = 0;
    if (t[0] == '+' || t[0] == '-') { neg = (t[0] == '-'); i = 1; }
    char* end = nullptr;
    unsigned long long v = std::strtoull(t.c_str() + i, &end, 0);
    if (end == t.c_str() + i || *end != '\0') return false;
    out = neg ? -(long long)v : (long long)v;
    return true;
}

bool parseMem(const std::string& inside, Mem& m) {
    // Tokenize on top-level + / - keeping the sign with each term.
    std::string s = trim(inside);
    m.baseReg = m.hasIndex = m.ripRel = false; m.disp = 0; m.scale = 1; m.baseCanon = m.idxCanon = -1;
    bool sawReg = false, sawDisp = false;
    size_t i = 0; int sign = 1;
    auto eat = [&](size_t from, size_t to) {
        std::string term = trim(s.substr(from, to - from));
        if (term.empty()) return;
        // reg*scale ?
        size_t star = term.find('*');
        if (star != std::string::npos) {
            std::string r = trim(term.substr(0, star));
            std::string sc = trim(term.substr(star + 1));
            RegInfo ri; long long scv = 1;
            if (lookupReg(r, ri) && parseImm(sc, scv)) { m.hasIndex = true; m.idxCanon = ri.canon; m.scale = (int)scv; sawReg = true; return; }
        }
        RegInfo ri;
        if (lookupReg(term, ri)) {
            if (lower(term) == "rip") { m.ripRel = true; sawReg = true; return; }
            if (!m.baseReg) { m.baseReg = true; m.baseCanon = ri.canon; }
            else { m.hasIndex = true; m.idxCanon = ri.canon; }
            sawReg = true; return;
        }
        long long v = 0;
        if (parseImm(term, v)) { m.disp += sign * v; sawDisp = true; return; }
        // Unrecognized term -> bail (handled by caller via return value).
        m.raw = "?";
    };
    size_t start = 0;
    for (i = 0; i < s.size(); ++i) {
        if (s[i] == '+' || s[i] == '-') {
            eat(start, i);
            sign = (s[i] == '-') ? -1 : 1;
            start = i + 1;
        }
    }
    eat(start, s.size());
    if (m.raw == "?") return false;
    m.dispOnly = (!m.baseReg && !m.hasIndex && !m.ripRel && sawDisp);
    (void)sawReg;
    return true;
}

bool parseOperand(const std::string& in, Operand& out) {
    out = Operand{};
    out.raw = trim(in);
    std::string s = out.raw;
    if (s.empty()) return false;
    // Strip a leading size keyword and segment override.
    static const struct { const char* kw; int w; } sizes[] = {
        {"byte ptr",1},{"word ptr",2},{"dword ptr",4},{"qword ptr",8},{"xmmword ptr",16},{"ptr",0} };
    int memWidth = 0;
    std::string ls = lower(s);
    for (const auto& sz : sizes) {
        size_t kl = std::string(sz.kw).size();
        if (ls.rfind(sz.kw, 0) == 0) { memWidth = sz.w; s = trim(s.substr(kl)); ls = lower(s); break; }
    }
    if (ls.rfind("fs:", 0) == 0 || ls.rfind("gs:", 0) == 0) { s = s.substr(3); ls = lower(s); }

    if (!s.empty() && s.front() == '[' && s.back() == ']') {
        Mem m; m.width = memWidth ? memWidth : 8;
        if (!parseMem(s.substr(1, s.size() - 2), m)) { out.kind = OK::Sym; out.sym = out.raw; return false; }
        out.kind = OK::Mem; out.mem = m; out.parsed = true; return true;
    }
    RegInfo ri;
    if (lookupReg(s, ri)) { out.kind = OK::Reg; out.reg = ri; out.parsed = true; return true; }
    long long v;
    if (parseImm(s, v)) { out.kind = OK::Imm; out.imm = v; out.parsed = true; return true; }
    out.kind = OK::Sym; out.sym = s; out.parsed = true; return true;   // symbol / label / fn name
}

std::string immText(long long v) {
    char b[32];
    if (v < 0)        std::snprintf(b, sizeof(b), "-0x%llX", (unsigned long long)(-v));
    else if (v < 16)  std::snprintf(b, sizeof(b), "%lld", v);
    else              std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v);
    return b;
}

// The assignment target for a (possibly partial) register write. A 32-bit write
// zeroes the upper 32 bits, so it's a full def; an 8/16-bit write only touches
// the low byte/word, rendered LOBYTE/LOWORD/BYTE1 so the high bits aren't lost.
std::string lhsFor(const std::string& nm, int width, bool high8) {
    if (width >= 4) return nm;
    if (high8)      return "BYTE1(" + nm + ")";
    return width == 2 ? "LOWORD(" + nm + ")" : "LOBYTE(" + nm + ")";
}

// ---- tiny constant-expression evaluator (folded-constant comments) ----------
// When inter-block const-prop inlines only constants into an assignment's RHS
// (e.g. "v1 = (0x1000 + 0x234);"), the human still has to do the arithmetic.
// This evaluates such an expression so the emitter can append "/* = 0x1234 */".
// Strictly numeric: any identifier, cast, deref, comparison, or string makes it
// bail (no comment). `lits` counts numeric literals so a bare constant (or a
// parenthesized one) never gets a redundant comment.
struct ConstEval {
    const char* p; const char* e; bool ok = true; int lits = 0;
    explicit ConstEval(const std::string& s) : p(s.c_str()), e(s.c_str() + s.size()) {}
    void ws() { while (p < e && *p == ' ') ++p; }
    bool eat(char c) { ws(); if (p < e && *p == c) { ++p; return true; } return false; }
    bool peek2(const char* two) { ws(); return p + 1 < e && p[0] == two[0] && p[1] == two[1]; }
    long long prim() {
        ws();
        if (eat('(')) { long long v = expr(); if (!eat(')')) ok = false; return v; }
        if (p < e && (std::isdigit((unsigned char)*p))) {
            char* endp = nullptr;
            long long v = (long long)std::strtoull(p, &endp, 0);   // 0x-aware
            if (endp == p) { ok = false; return 0; }
            p = endp; ++lits;
            return v;
        }
        ok = false; return 0;
    }
    long long unary() {
        ws();
        if (eat('-')) return -unary();
        if (eat('~')) return ~unary();
        return prim();
    }
    long long mul() {
        long long v = unary();
        for (;;) {
            ws();
            if (p < e && *p == '*' && (p + 1 >= e || p[1] != '(')) { ++p; v *= unary(); }   // "*(" is a deref
            else if (p < e && *p == '/') { ++p; long long r = unary(); if (!r) { ok = false; return 0; } v /= r; }
            else if (p < e && *p == '%') { ++p; long long r = unary(); if (!r) { ok = false; return 0; } v %= r; }
            else return v;
        }
    }
    long long add() {
        long long v = mul();
        for (;;) {
            ws();
            if (p < e && *p == '+') { ++p; v += mul(); }
            else if (p < e && *p == '-') { ++p; v -= mul(); }
            else return v;
        }
    }
    long long shift() {
        long long v = add();
        for (;;) {
            if (peek2("<<")) { p += 2; long long r = add(); if (r < 0 || r > 63) { ok = false; return 0; } v = (long long)((unsigned long long)v << r); }
            else if (peek2(">>")) { p += 2; long long r = add(); if (r < 0 || r > 63) { ok = false; return 0; } v = (long long)((unsigned long long)v >> r); }
            else return v;
        }
    }
    long long band() { long long v = shift(); while (ok) { ws(); if (p < e && *p == '&' && (p + 1 >= e || p[1] != '&')) { ++p; v &= shift(); } else break; } return v; }
    long long bxor() { long long v = band();  while (ok) { ws(); if (p < e && *p == '^') { ++p; v ^= band(); } else break; } return v; }
    long long expr() { long long v = bxor();  while (ok) { ws(); if (p < e && *p == '|' && (p + 1 >= e || p[1] != '|')) { ++p; v |= bxor(); } else break; } return v; }
};

// Evaluate `s` as a pure constant expression. True only when the WHOLE string
// parses and at least two literals took part (folding actually happened).
static bool tryFoldConst(const std::string& s, long long& out) {
    if (s.empty() || s.size() > 128) return false;
    ConstEval ev(s);
    long long v = ev.expr();
    ev.ws();
    if (!ev.ok || ev.p != ev.e || ev.lits < 2) return false;
    out = v;
    return true;
}

// ----------------------------------------------------------- the analyzer ---

struct Val { std::string expr; std::set<std::string> reads; std::set<std::string> deps; };

struct Stmt {
    std::string dst;                 // variable defined ("" if none)
    std::string text;                // rendered statement
    std::vector<std::string> reads;  // variable names read
    bool side = false;               // store/call: never DCE'd (but a dead call-dst is stripped)
    std::string callRhs;             // for a call: RHS without "dst = " (to strip a dead result)
};

struct Analyzer {
    const ControlFlowGraph& g;
    const std::function<std::string(uint64_t)>& nameFor;
    const std::function<std::string(uint64_t)>& dataRefFor;
    bool callArgs_;                                       // recover/inline call arguments
    bool is32_ = false;                                   // 32-bit (x86) calling convention
    int N;

    // A pending pushed value (32-bit cdecl/stdcall arg marshalling). Collected
    // since the last call / frame manipulation, consumed (reversed: last push =
    // first arg) at the next call. `reads` keeps the def alive through DCE.
    struct PushArg { std::string text; std::set<std::string> reads; };
    std::vector<PushArg> pendingPush_;

    std::unordered_map<std::string, std::string> name_;   // loc id -> variable name
    std::unordered_map<std::string, std::string> argName_; // reg loc -> a1..a4
    std::unordered_map<std::string, int>  width_;          // var name -> max access width
    std::unordered_set<std::string>       ptr_;            // var names that are pointers
    std::unordered_set<std::string>       assigned_;       // var names ever defined (declared as locals)
    std::vector<std::string>              order_;          // local declaration order
    int vCounter_ = 1, localCounter_ = 0;
    int argCount_ = 0;                                     // number of detected parameters (a1..aN)

    std::vector<std::vector<Stmt>> blockStmts_;
    std::vector<FlagState>         termFlag_;

    // Return-value recovery: the inlined rax expression captured at the end of each
    // return block (if rax still had a propagated value there).
    std::vector<bool>                  retHasInline_;
    std::vector<std::string>           retInline_;
    std::vector<std::set<std::string>> retInlineReads_;
    std::vector<std::string>           retExpr_;     // final per-block "return <expr>" text
    std::vector<std::set<std::string>> retReads_;    // vars a return reads (liveness seed)

    Analyzer(const ControlFlowGraph& cfg, const std::function<std::string(uint64_t)>& nf,
             const std::function<std::string(uint64_t)>& dr, bool callArgs)
        : g(cfg), nameFor(nf), dataRefFor(dr), callArgs_(callArgs), N((int)cfg.blocks.size()) {}

    // Resolve a constant data address to a display token (quoted string / import /
    // global name), or "" if not meaningful.
    std::string dref(uint64_t addr) { return (dataRefFor && addr) ? dataRefFor(addr) : std::string(); }

    static std::string regLoc(int canon)  { return "r" + std::to_string(canon); }
    // Tracked stack slot: [rbp/rsp +/- disp] with no index. loc id "k:<base>:<disp>".
    static bool stackLoc(const Mem& m, std::string& loc) {
        if (m.hasIndex || m.ripRel || !m.baseReg) return false;
        if (m.baseCanon != RBP && m.baseCanon != RSP) return false;
        loc = "k:" + std::to_string(m.baseCanon) + ":" + std::to_string(m.disp);
        return true;
    }

    std::string nameOf(const std::string& loc) {
        auto it = name_.find(loc);
        if (it != name_.end()) return it->second;
        std::string nm;
        auto a = argName_.find(loc);
        if (a != argName_.end())      nm = a->second;
        else if (!loc.empty() && loc[0] == 'r') nm = "v" + std::to_string(vCounter_++);
        else                          nm = "local_" + std::to_string(localCounter_++);
        name_[loc] = nm;
        return nm;
    }
    bool isArg(const std::string& loc) const { return argName_.count(loc) != 0; }

    void noteWidth(const std::string& nm, int w) { int& cur = width_[nm]; if (w > cur) cur = w; }
    void markAssigned(const std::string& nm) {
        if (assigned_.insert(nm).second && !nm.empty() && nm[0] != 'a') order_.push_back(nm);
    }

    // Does this mnemonic write its first operand, and does it also read it?
    static void classifyDst(const std::string& m, bool& writesA, bool& readsA) {
        writesA = readsA = false;
        if (m == "mov" || m == "lea" || m == "movzx" || m == "movsx" || m == "movsxd" ||
            m == "movabs" || m == "movq" || m == "movd" || m == "pop" || m == "setcc") { writesA = true; return; }
        if (m.rfind("set", 0) == 0) { writesA = true; return; }
        if (m == "add" || m == "sub" || m == "and" || m == "or" || m == "xor" || m == "shl" ||
            m == "shr" || m == "sar" || m == "sal" || m == "inc" || m == "dec" || m == "neg" ||
            m == "not" || m == "imul" || m.rfind("cmov", 0) == 0) { writesA = true; readsA = true; return; }
        if (m == "cmp" || m == "test" || m == "push") { readsA = true; return; }
    }

    // Heuristically classify the function as 32-bit (x86) vs 64-bit (x64) from the
    // operands seen. Any genuine 64-bit register (rax.., r8..r15, rip) settles it as
    // 64-bit. For 32-bit we key specifically on a 32-bit STACK/BASE pointer (esp/ebp):
    // a 64-bit function commonly does 32-bit data math on eax/ecx, so a bare e-register
    // must NOT force the 32-bit model (that would lose Win64 register-arg detection) —
    // only the frame pointer's width reliably distinguishes the ABI.
    bool looksLike32() const {
        bool saw64 = false, saw32Frame = false;
        const std::unordered_map<std::string, RegInfo>& t = regTable();
        auto scanTok = [&](const std::string& tok) {
            std::string lt = lower(trim(tok));
            if (lt == "rip") { saw64 = true; return; }
            auto it = t.find(lt);
            if (it == t.end()) return;
            if (it->second.width == 8) saw64 = true;                  // any 64-bit register
            else if (it->second.width == 4 && (it->second.canon == RSP || it->second.canon == RBP))
                saw32Frame = true;                                    // esp / ebp -> 32-bit frame
        };
        // Walk operand tokens (splitting on the separators that can frame a register).
        for (const BasicBlock& blk : g.blocks)
            for (const Instruction& in : blk.insns) {
                const std::string& o = in.operands;
                std::string cur;
                for (size_t i = 0; i <= o.size(); ++i) {
                    char c = (i < o.size()) ? o[i] : ',';
                    if (std::isalnum((unsigned char)c) || c == '_') cur += c;
                    else { if (!cur.empty()) scanTok(cur); cur.clear(); }
                }
                if (saw64) return false;   // a single 64-bit operand settles it
            }
        return saw32Frame && !saw64;
    }

    // ---- per-function argument detection (read-before-write at entry) ----
    // Scans the prologue linearly across blocks until the first ret (mirroring
    // guessSignature in the UI) so the arg count matches the emitted header. Picks
    // the calling convention from the bitness: Win64 passes a1..a4 in rcx/rdx/r8/r9,
    // while 32-bit cdecl/stdcall pass arguments on the stack ([ebp+8+4k] with a frame
    // pointer, or [esp+4+4k] without) — both detected as read-before-write slots.
    void detectArgs() {
        if (N == 0) return;
        if (is32_) { detectArgsX86(); return; }

        const int win64[4] = { RCX, RDX, 8, 9 };
        std::unordered_set<int> written;
        bool isArg[16] = { false };
        auto useReg = [&](int canon) {
            if (canon < 0 || written.count(canon)) return;
            for (int k = 0; k < 4; ++k) if (canon == win64[k]) isArg[canon] = true;
        };
        bool done = false;
        for (const BasicBlock& blk : g.blocks) {
            for (const Instruction& in : blk.insns) {
                const std::string m = lower(in.mnemonic);
                std::string a, b; bool two = split2(in.operands, a, b);
                Operand da, sb;
                bool okA = parseOperand(a, da);
                bool writesA = false, readsA = false;
                classifyDst(m, writesA, readsA);
                // `xor x,x` / `sub x,x` zero the register - they don't read an argument.
                bool selfZero = two && a == b && (m == "xor" || m == "sub");
                // Registers inside memory operands are always reads (address computation).
                if (okA && da.kind == OK::Mem) { if (da.mem.baseReg) useReg(da.mem.baseCanon); if (da.mem.hasIndex) useReg(da.mem.idxCanon); }
                if (okA && da.kind == OK::Reg && readsA && !selfZero) useReg(da.reg.canon);
                if (two && parseOperand(b, sb)) {
                    if (sb.kind == OK::Reg) useReg(sb.reg.canon);
                    if (sb.kind == OK::Mem) { if (sb.mem.baseReg) useReg(sb.mem.baseCanon); if (sb.mem.hasIndex) useReg(sb.mem.idxCanon); }
                }
                if (okA && da.kind == OK::Reg && writesA) written.insert(da.reg.canon);
                if (in.isRet) { done = true; break; }
            }
            if (done) break;
        }
        // Win64 args are contiguous a1..aN: if a later reg is an arg, name the earlier ones too.
        int maxArg = 0;
        for (int k = 0; k < 4; ++k) if (isArg[win64[k]]) maxArg = k + 1;
        int n = 0;
        for (int k = 0; k < maxArg; ++k) argName_[regLoc(win64[k])] = "a" + std::to_string(++n);
        argCount_ = n;
    }

    // 32-bit cdecl/stdcall argument detection. Incoming arguments live on the stack
    // above the return address: with a frame pointer they are [ebp + 8 + 4*k]; without
    // one they are [esp + 4 + 4*k]. We collect the positive stack slots that are READ
    // before being WRITTEN (true incoming parameters, not locals which sit at negative
    // offsets), and name them a1..aN in ascending-offset order. Tracking esp/ebp as a
    // copied frame base is out of scope; we key off the literal base register, which
    // covers the overwhelmingly common `mov ebp,esp` and leaf `[esp+N]` forms.
    void detectArgsX86() {
        std::set<long long> ebpArgs, espArgs;       // positive arg displacements
        std::set<std::string> writtenSlot;          // stack slots already written
        bool done = false;
        for (const BasicBlock& blk : g.blocks) {
            for (const Instruction& in : blk.insns) {
                const std::string m = lower(in.mnemonic);
                std::string a, b; bool two = split2(in.operands, a, b);
                Operand da, sb;
                bool okA = parseOperand(a, da);
                bool okB = two && parseOperand(b, sb);
                bool writesA = false, readsA = false;
                classifyDst(m, writesA, readsA);

                // Is `op` a frame-relative [ebp/esp + disp] slot? Returns base canon + disp.
                auto frameSlot = [&](const Operand& op, int& base, long long& disp) -> bool {
                    if (op.kind != OK::Mem || op.mem.hasIndex || op.mem.ripRel || !op.mem.baseReg) return false;
                    if (op.mem.baseCanon != RBP && op.mem.baseCanon != RSP) return false;
                    base = op.mem.baseCanon; disp = op.mem.disp; return true;
                };
                auto slotId = [&](int base, long long disp) {
                    return "k:" + std::to_string(base) + ":" + std::to_string(disp);
                };
                // Record a positive incoming-arg slot the first time it's read (and not
                // yet written). ebp frame: disp >= 8; esp frame: disp >= 4.
                auto noteRead = [&](const Operand& op) {
                    int base; long long disp;
                    if (!frameSlot(op, base, disp)) return;
                    if (writtenSlot.count(slotId(base, disp))) return;
                    long long minDisp = (base == RBP) ? 8 : 4;
                    if (disp < minDisp) return;            // negative/low: a local, not a param
                    (base == RBP ? ebpArgs : espArgs).insert(disp);
                };
                auto noteWrite = [&](const Operand& op) {
                    int base; long long disp;
                    if (frameSlot(op, base, disp)) writtenSlot.insert(slotId(base, disp));
                };

                // Source operand is always a read.
                if (okB) noteRead(sb);
                // Destination: a read for read-modify-write or compare/test/push; also a
                // read when it is the second source of a store-less compare.
                if (okA) {
                    if (da.kind == OK::Mem) {
                        if (readsA || !writesA) noteRead(da);   // mem dst that is read (cmp/test/add..)
                        if (writesA) noteWrite(da);
                    } else if (da.kind == OK::Reg && readsA) {
                        // a register read can't be a stack arg; nothing to do.
                    }
                }
                if (in.isRet) { done = true; break; }
            }
            if (done) break;
        }
        // Choose the frame model that actually carried args (prefer ebp when present).
        const std::set<long long>& args = !ebpArgs.empty() ? ebpArgs : espArgs;
        int base = !ebpArgs.empty() ? RBP : RSP;
        int n = 0;
        for (long long disp : args)                  // ascending offset == argument order
            argName_["k:" + std::to_string(base) + ":" + std::to_string(disp)] = "a" + std::to_string(++n);
        argCount_ = n;
    }

    // ---- operand value rendering (with intra-block propagation) ----
    struct Env { std::unordered_map<std::string, Val> v; };

    // Render a tracked location (reg or stack slot) as a value expression.
    std::string renderLoc(Env& e, const std::string& loc, std::set<std::string>& reads, std::set<std::string>& deps) {
        auto it = e.v.find(loc);
        if (it != e.v.end()) {
            reads.insert(it->second.reads.begin(), it->second.reads.end());
            deps.insert(it->second.deps.begin(), it->second.deps.end());
            return it->second.expr;
        }
        std::string nm = nameOf(loc);
        reads.insert(nm); deps.insert(loc);
        return nm;
    }

    // Render an operand as an r-value. Sets isMemLoad if it dereferences untracked memory.
    std::string renderRValue(Env& e, const Operand& op, std::set<std::string>& reads,
                             std::set<std::string>& deps, bool& isMemLoad) {
        isMemLoad = false;
        switch (op.kind) {
            case OK::Imm: return immText(op.imm);
            case OK::Sym: return op.sym;
            case OK::Reg:
                if (op.reg.canon < 0) { reads.insert(op.raw); return op.raw; }   // untracked reg (xmm/rip)
                noteWidth(nameOf(regLoc(op.reg.canon)), op.reg.width);
                return renderLoc(e, regLoc(op.reg.canon), reads, deps);
            case OK::Mem: {
                std::string sloc;
                if (stackLoc(op.mem, sloc)) { noteWidth(nameOf(sloc), op.mem.width); return renderLoc(e, sloc, reads, deps); }
                if (op.mem.dispOnly) {   // [const]: a named global / import slot reads as that name
                    std::string tok = dref((uint64_t)op.mem.disp);
                    if (!tok.empty() && tok.front() != '"') return tok;
                }
                isMemLoad = true; deps.insert("MEM");
                return "*(" + renderAddr(e, op.mem, reads, deps) + ")";
            }
            default: return op.raw;
        }
    }

    // Render a memory address expression (base + index*scale + disp), pointer-tagging base.
    std::string renderAddr(Env& e, const Mem& m, std::set<std::string>& reads, std::set<std::string>& deps) {
        std::string s; bool first = true;
        auto add = [&](const std::string& t, bool sub) {
            if (first) { s = (sub ? "-" + t : t); first = false; }
            else       { s += (sub ? " - " : " + ") + t; }
        };
        if (m.ripRel)  add("rip", false);
        if (m.baseReg) {
            std::string nm = nameOf(regLoc(m.baseCanon));
            ptr_.insert(nm);                               // used as a pointer base
            add(renderLoc(e, regLoc(m.baseCanon), reads, deps), false);
        }
        if (m.hasIndex) {
            std::string idx = renderLoc(e, regLoc(m.idxCanon), reads, deps);
            add(m.scale > 1 ? (idx + " * " + std::to_string(m.scale)) : idx, false);
        }
        if (m.disp || first) add(immText(m.disp < 0 ? -m.disp : m.disp), m.disp < 0);
        return s;
    }

    // Recover the argument list passed to a call at the current program point and
    // render it as the inside of "callee(...)". Heuristic, no callee prototypes:
    //   x86 (cdecl/stdcall): the values pushed since the last call/frame setup, in
    //     call order (cdecl/stdcall push right-to-left, so the last push is arg1).
    //   Win64: the propagated values still live in the integer arg registers
    //     rcx, rdx, r8, r9 — a CONTIGUOUS run from rcx (stop at the first one with
    //     no tracked value, so a stale higher register can't fabricate a gap arg).
    // Volatile registers are cleared after every call, so a value in an arg
    // register here was set since the last call (or must-reach from predecessors)
    // — strong evidence it is being passed. Each argument's reads are unioned into
    // `reads` so the value (incl. a string literal) survives DCE and folds in.
    std::string renderCallArgs(Env& e, std::set<std::string>& reads) {
        if (!callArgs_) return "";
        std::vector<std::string> argv;
        if (is32_) {
            for (auto it = pendingPush_.rbegin(); it != pendingPush_.rend() && argv.size() < 8; ++it) {
                argv.push_back(it->text);
                reads.insert(it->reads.begin(), it->reads.end());
            }
        } else {
            const int win64[4] = { RCX, RDX, 8, 9 };
            for (int k = 0; k < 4; ++k) {
                auto it = e.v.find(regLoc(win64[k]));
                if (it == e.v.end() || it->second.expr.empty()) break;   // contiguity from rcx
                argv.push_back(it->second.expr);
                reads.insert(it->second.reads.begin(), it->second.reads.end());
            }
        }
        std::string s;
        for (size_t i = 0; i < argv.size(); ++i) { if (i) s += ", "; s += argv[i]; }
        return s;
    }

    // Invalidate cached values when something they depend on changes.
    void killDep(Env& e, const std::string& dep) {
        for (auto it = e.v.begin(); it != e.v.end();) {
            if (it->second.deps.count(dep)) it = e.v.erase(it); else ++it;
        }
    }
    void killMemory(Env& e) { killDep(e, "MEM"); }
    // A write through a computed pointer (or a call) may alias a tracked stack
    // slot, so conservatively drop all cached stack-slot values.
    void killStackSlots(Env& e) {
        for (auto it = e.v.begin(); it != e.v.end();)
            if (it->first.rfind("k:", 0) == 0) it = e.v.erase(it); else ++it;
    }

    // ---- lift one block ----
    // `inEnv` seeds the block with constant/copy values that reach it from its
    // predecessors (inter-block propagation; empty for the legacy intra-block lift).
    // In `dry` mode no statements are recorded (the lift is used purely as the
    // data-flow transfer function during the reaching-definitions fixpoint) and the
    // resulting exit environment is written to *outEnv; name/width/ptr bookkeeping is
    // idempotent so it is safe to run in either mode.
    void liftBlock(int bi, const Env& inEnv = {}, bool dry = false, Env* outEnv = nullptr) {
        const BasicBlock& b = g.blocks[bi];
        std::vector<Stmt> scratch;
        std::vector<Stmt>& out = dry ? scratch : blockStmts_[bi];
        if (!dry) out.clear();
        Env e = inEnv;
        FlagState fl;
        pendingPush_.clear();   // x86 pushed-arg accumulator is per-block

        size_t count = b.insns.size();
        if (!b.insns.empty()) {
            const Instruction& last = b.insns.back();
            bool isTerm = b.isReturn || b.isUncond || (last.isBranch && !last.isCall);
            if (isTerm) --count;
        }

        for (size_t k = 0; k < count; ++k) {
            const Instruction& in = b.insns[k];
            const std::string m = lower(in.mnemonic);
            std::string aTok, bTok; bool two = split2(in.operands, aTok, bTok);
            Operand da, sb;
            bool okA = parseOperand(aTok, da);
            bool okB = two ? parseOperand(bTok, sb) : false;

            // Destination location id (tracked reg or stack slot), if any.
            auto dstLoc = [&](const Operand& d, std::string& loc, int& width) -> bool {
                if (d.kind == OK::Reg && d.reg.canon >= 0) { loc = regLoc(d.reg.canon); width = d.reg.width; return true; }
                if (d.kind == OK::Mem) { std::string s; if (stackLoc(d.mem, s)) { loc = s; width = d.mem.width; return true; } }
                return false;
            };

            std::set<std::string> reads, deps; bool ml = false;
            // Whether the destination register is a high-8 sub-register (ah/bh/ch/dh).
            bool dHigh8 = okA && da.kind == OK::Reg && da.reg.high8;

            auto emitDef = [&](const std::string& loc, int width, bool high8, const std::string& rhsExpr,
                               std::set<std::string>& rd, std::set<std::string>& dp) {
                std::string nm = nameOf(loc);
                noteWidth(nm, width); markAssigned(nm);
                killDep(e, loc);                          // invalidate anything depending on this loc
                if (width >= 4) {                         // full (32-bit zero-extends) def: propagatable
                    Stmt s; s.dst = nm; s.text = nm + " = " + rhsExpr + ";";
                    // Const-prop folded the RHS down to pure arithmetic on
                    // constants: spell out the result ("/* = 0x1234 */") so the
                    // reader doesn't have to. Display-only — the propagated
                    // value (Val.expr below) stays the uncommented expression.
                    if (long long cv = 0; tryFoldConst(rhsExpr, cv))
                        s.text += " /* = " + immText(cv) + " */";
                    s.reads.assign(rd.begin(), rd.end());
                    out.push_back(std::move(s));
                    Val v; v.expr = rhsExpr; v.reads = rd; v.deps = dp; e.v[loc] = std::move(v);
                } else {                                  // 8/16-bit partial write: read-modify-write
                    Stmt s; s.dst = nm; s.text = lhsFor(nm, width, high8) + " = " + rhsExpr + ";";
                    s.reads.assign(rd.begin(), rd.end()); s.reads.push_back(nm);   // upper bits of nm survive
                    out.push_back(std::move(s));
                    e.v.erase(loc);                       // don't inline a partial value as the full register
                }
            };
            auto emitStore = [&](const Operand& d, const std::string& rhsExpr, std::set<std::string>& rd) {
                std::string addr = renderAddr(e, d.mem, rd, deps);
                Stmt s; s.side = true; s.text = "*(" + addr + ") = " + rhsExpr + ";";
                s.reads.assign(rd.begin(), rd.end());
                out.push_back(std::move(s));
                killMemory(e); killStackSlots(e);          // may alias a tracked stack slot
            };
            auto emitRaw = [&](const std::string& text) {
                Stmt s; s.side = true; s.text = text; out.push_back(std::move(s));
            };

            // Unparseable operands -> fall back to a faithful asm comment (never lose it).
            if ((two && (!okA || !okB)) || (!two && !okA && !in.operands.empty())) {
                emitRaw(in.operands.empty() ? ("__asm { " + m + " };")
                                            : ("__asm { " + m + " " + in.operands + " };"));
                e.v.clear();   // be conservative after an unmodeled op
                continue;
            }

            // --- x86 call-arg marshalling (32-bit) ---
            // A write to esp/ebp ends a pushed-argument group: the prologue's
            // `mov ebp,esp` / `sub esp,N`, or the post-call `add esp,N` cleanup. So
            // the next call only sees the pushes that follow this point.
            if (is32_ && callArgs_ && okA && da.kind == OK::Reg &&
                (da.reg.canon == RSP || da.reg.canon == RBP)) {
                bool w = false, rmw = false; classifyDst(m, w, rmw);
                if (w) pendingPush_.clear();
            }
            // A pushed value is a candidate cdecl/stdcall argument: render it now and
            // queue it for the next call (the stack itself stays unmodeled, so push
            // still emits no statement — it's just remembered).
            if (m == "push") {
                if (is32_ && callArgs_ && okA) {
                    std::set<std::string> rd, dp; bool ml2 = false;
                    std::string val;
                    if (da.kind == OK::Imm && (uint64_t)da.imm > 0x1000) val = dref((uint64_t)da.imm);  // string/global
                    if (val.empty()) val = renderRValue(e, da, rd, dp, ml2);
                    pendingPush_.push_back({ val, rd });
                }
                continue;
            }

            // --- mnemonic dispatch ---
            if (m == "nop" || m == "endbr64" || m == "endbr32" || m == "leave" || m == "hlt" ||
                m == "int3" || m == "cdqe" || m == "cdq" || m == "cqo" || m == "pop")
                continue;   // no statement (pop: stack not modeled, mirrors the legacy lift)

            if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs" ||
                m == "movq" || m == "movd") {
                if (!two) continue;
                std::string rhs;
                if (sb.kind == OK::Imm && (uint64_t)sb.imm > 0x1000) rhs = dref((uint64_t)sb.imm); // string/global address
                if (rhs.empty()) rhs = renderRValue(e, sb, reads, deps, ml);
                // movzx/movsx make the source width explicit so a later read isn't wrong.
                if (m == "movzx" || m == "movsx" || m == "movsxd") {
                    int sw = sb.kind == OK::Reg ? sb.reg.width : (sb.kind == OK::Mem ? sb.mem.width : 4);
                    bool uns = (m == "movzx");
                    const char* cast = nullptr;
                    if      (sw == 1) cast = uns ? "(unsigned __int8)"  : "(__int8)";
                    else if (sw == 2) cast = uns ? "(unsigned __int16)" : "(__int16)";
                    else if (sw == 4 && !uns) cast = "(int)";
                    if (cast) rhs = cast + rhs;
                }
                std::string loc; int w;
                if (dstLoc(da, loc, w)) emitDef(loc, w, dHigh8, rhs, reads, deps);
                else if (da.kind == OK::Mem) emitStore(da, rhs, reads);
                continue;
            }
            if (m == "lea") {
                if (!two || sb.kind != OK::Mem) continue;
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); ptr_.insert(nm);
                    // lea of a constant address -> resolve to a string/symbol token.
                    std::string tok = sb.mem.dispOnly ? dref((uint64_t)sb.mem.disp) : std::string();
                    if (!tok.empty()) { std::set<std::string> rd, dp; emitDef(loc, w, false, tok, rd, dp); }
                    else { std::string addr = renderAddr(e, sb.mem, reads, deps); emitDef(loc, w, false, "(" + addr + ")", reads, deps); }
                }
                continue;
            }
            // Arithmetic / logic: compound assignment, sets flags for a following Jcc.
            auto compound = [&](const char* op) {
                if (!two) return;
                // Polish: `x += -k` -> `x -= k`; `x -= -k` -> `x += k`.
                const char* useOp = op;
                Operand src = sb;
                if (src.kind == OK::Imm && src.imm < 0 && (op[0] == '+' || op[0] == '-') && op[1] == '\0') {
                    useOp = (op[0] == '+') ? "-" : "+";
                    src.imm = -src.imm;
                }
                std::string rhs = renderRValue(e, src, reads, deps, ml);
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); noteWidth(nm, w); markAssigned(nm);
                    Stmt s; s.dst = nm; s.text = lhsFor(nm, w, dHigh8) + " " + useOp + "= " + rhs + ";";
                    s.reads.assign(reads.begin(), reads.end()); s.reads.push_back(nm);
                    out.push_back(std::move(s));
                    killDep(e, loc); e.v.erase(loc);             // value is now non-trivial; stop inlining it
                    fl = { CmpKind::ArithZero, nm, "" };
                } else if (da.kind == OK::Mem) {
                    std::set<std::string> rd = reads;
                    std::string lhs = renderRValue(e, da, rd, deps, ml);
                    Stmt s; s.side = true; s.text = lhs + " " + op + "= " + rhs + ";";
                    s.reads.assign(rd.begin(), rd.end()); out.push_back(std::move(s));
                    killMemory(e); killStackSlots(e);
                }
            };
            if (m == "add") { compound("+"); continue; }
            if (m == "sub") { compound("-"); continue; }
            if (m == "and") { compound("&"); continue; }
            if (m == "or")  { compound("|"); continue; }
            if (m == "shl" || m == "sal") { compound("<<"); continue; }
            if (m == "shr" || m == "sar") { compound(">>"); continue; }
            if (m == "xor") {
                if (two && aTok == bTok) {   // xor x,x -> x = 0 (constant; enables propagation)
                    std::string loc; int w;
                    if (dstLoc(da, loc, w)) { std::set<std::string> rd, dp; emitDef(loc, w, dHigh8, "0", rd, dp); fl = { CmpKind::ArithZero, nameOf(loc), "" }; }
                    continue;
                }
                compound("^"); continue;
            }
            if (m == "inc" || m == "dec") {
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); noteWidth(nm, w); markAssigned(nm);
                    Stmt s; s.dst = nm; s.text = lhsFor(nm, w, dHigh8) + (m == "inc" ? "++;" : "--;"); s.reads.push_back(nm);
                    out.push_back(std::move(s)); killDep(e, loc); e.v.erase(loc);
                    fl = { CmpKind::ArithZero, nm, "" };
                }
                continue;
            }
            if (m == "neg" || m == "not") {
                std::string loc; int w;
                if (dstLoc(da, loc, w)) { std::string cur = renderLoc(e, loc, reads, deps);
                    emitDef(loc, w, dHigh8, std::string(m == "neg" ? "-" : "~") + "(" + cur + ")", reads, deps); }
                continue;
            }
            if (m == "imul" && two) {
                std::string rhs = renderRValue(e, sb, reads, deps, ml);
                std::string loc; int w;
                if (dstLoc(da, loc, w)) { std::string cur = renderLoc(e, loc, reads, deps);
                    std::set<std::string> rd = reads; emitDef(loc, w, dHigh8, cur + " * " + rhs, rd, deps); }
                continue;
            }
            // One-operand mul/imul/div/idiv use the implicit rdx:rax accumulator pair.
            if ((m == "mul" || m == "imul" || m == "div" || m == "idiv") && !two && okA) {
                int w = da.kind == OK::Reg ? da.reg.width : (da.kind == OK::Mem ? da.mem.width : 8);
                int dw = w < 4 ? 4 : w;                                      // accumulator is the full reg
                std::string loLoc = regLoc(RAX), hiLoc = regLoc(RDX);
                std::string opnd = renderRValue(e, da, reads, deps, ml);     // multiplier / divisor
                std::string loVal = renderLoc(e, loLoc, reads, deps);        // current rax
                if (m == "mul" || m == "imul") {
                    // rdx:rax = rax * opnd; we render the low half (the common use).
                    std::set<std::string> rd = reads; emitDef(loLoc, dw, false, loVal + " * " + opnd, rd, deps);
                    killDep(e, hiLoc); e.v.erase(hiLoc);                     // high half clobbered, not modeled
                } else {
                    // quotient -> rax, remainder -> rdx (both read the original rax).
                    std::set<std::string> rd = reads;
                    emitDef(hiLoc, dw, false, loVal + " % " + opnd, rd, deps);   // remainder first (rax unchanged)
                    std::set<std::string> rd2 = reads;
                    emitDef(loLoc, dw, false, loVal + " / " + opnd, rd2, deps);  // then quotient overwrites rax
                }
                continue;
            }
            if (m == "cmp") {
                std::string A = renderRValue(e, da, reads, deps, ml);
                std::set<std::string> rb; bool ml2 = false;
                std::string B = two ? renderRValue(e, sb, rb, deps, ml2) : "0";
                fl = { CmpKind::Cmp, A, B };
                continue;
            }
            if (m == "test") {
                std::string A = renderRValue(e, da, reads, deps, ml);
                if (two && aTok == bTok) fl = { CmpKind::TestZero, A, "" };
                else { std::set<std::string> rb; bool ml2 = false; std::string B = two ? renderRValue(e, sb, rb, deps, ml2) : "0"; fl = { CmpKind::TestAnd, A, B }; }
                continue;
            }
            if (m == "call") {
                // Recover the call's arguments BEFORE clobbering the volatile arg
                // registers below (rcx/rdx/r8/r9 hold the Win64 integer args here).
                std::string args = renderCallArgs(e, reads);
                std::string callee;
                if (in.branchTarget) { std::string nm = nameFor ? nameFor(in.branchTarget) : std::string();
                    if (nm.empty()) { char c[24]; std::snprintf(c, sizeof(c), "sub_%llX", (unsigned long long)in.branchTarget); nm = c; }
                    callee = nm; }
                else {
                    // Indirect call: resolve `call [iat]` to the import name when known.
                    std::string tok = (da.kind == OK::Mem && da.mem.dispOnly) ? dref((uint64_t)da.mem.disp) : std::string();
                    if (!tok.empty() && tok.front() != '"') callee = tok;
                    else { std::set<std::string> rd; bool ml2 = false; callee = "(*" + renderRValue(e, da, rd, deps, ml2) + ")"; reads.insert(rd.begin(), rd.end()); }
                }
                std::string callExpr = callee + "(" + args + ")";
                // A call returns in rax (Win64) and clobbers the volatile registers.
                std::string raxNm = nameOf(regLoc(RAX)); markAssigned(raxNm); noteWidth(raxNm, 8);
                Stmt s; s.side = true; s.dst = raxNm; s.callRhs = callExpr; s.text = raxNm + " = " + callExpr + ";";
                s.reads.assign(reads.begin(), reads.end());
                out.push_back(std::move(s));
                const int vol[] = { RAX, RCX, RDX, 8, 9, 10, 11 };
                for (int r : vol) { e.v.erase(regLoc(r)); killDep(e, regLoc(r)); }
                killMemory(e); killStackSlots(e);   // callee may write through a passed &local
                pendingPush_.clear();               // consumed: the next call starts a fresh group
                continue;
            }
            if (m.size() > 3 && m.rfind("set", 0) == 0) {        // setcc (8-bit dst)
                std::string loc; int w;
                if (dstLoc(da, loc, w)) emitDef(loc, 1, dHigh8, "(" + condText("j" + m.substr(3), fl, false) + ")", reads, deps);
                continue;
            }
            if (m.size() > 4 && two && m.rfind("cmov", 0) == 0) { // cmovcc
                std::string rhs = renderRValue(e, sb, reads, deps, ml);
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); markAssigned(nm); noteWidth(nm, w);
                    Stmt s; s.dst = nm; s.text = "if (" + condText("j" + m.substr(4), fl, false) + ") " + nm + " = " + rhs + ";";
                    s.reads.assign(reads.begin(), reads.end());
                    out.push_back(std::move(s)); killDep(e, loc); e.v.erase(loc);
                }
                continue;
            }
            // Anything unmodeled: keep as an inline-asm comment so nothing is lost.
            emitRaw(in.operands.empty() ? ("__asm { " + m + " };") : ("__asm { " + m + " " + in.operands + " };"));
            e.v.clear();
        }
        termFlag_[bi] = fl;
        // For a return block, remember rax's propagated value (the return value). Reset
        // first so a prior (dry-run) lift with a different entry env can't leave a stale
        // inline value when the final lift no longer has one.
        if (g.blocks[bi].isReturn) {
            retHasInline_[bi] = false; retInline_[bi].clear(); retInlineReads_[bi].clear();
            auto it = e.v.find(regLoc(RAX));
            if (it != e.v.end()) { retHasInline_[bi] = true; retInline_[bi] = it->second.expr; retInlineReads_[bi] = it->second.reads; }
        }
        if (outEnv) *outEnv = std::move(e);
    }

    // A value is safe to carry across a basic-block boundary only if it is a pure
    // constant or a copy of a register/argument (no memory load): two predecessors
    // could observe different memory for the same address expression, so MEM-tagged
    // values are never propagated inter-block.
    static bool crossBlockSafe(const Val& v) { return v.deps.find("MEM") == v.deps.end(); }

    // Meet of predecessor exit environments at a block entry: keep a location only
    // when EVERY predecessor agrees on a byte-identical, boundary-safe value for it.
    // Any disagreement (e.g. a value redefined on one path, or a loop back-edge that
    // mutates it) drops the location, which conservatively falls back to its variable
    // name — exactly the must-reach lattice a constant/copy propagation needs.
    Env meetPreds(const std::vector<int>& preds, const std::vector<Env>& outEnv) const {
        Env e;
        if (preds.empty()) return e;
        const Env& first = outEnv[preds[0]];
        for (const auto& kv : first.v) {
            if (!crossBlockSafe(kv.second)) continue;
            bool all = true;
            for (size_t p = 1; p < preds.size(); ++p) {
                auto it = outEnv[preds[p]].v.find(kv.first);
                if (it == outEnv[preds[p]].v.end() || it->second.expr != kv.second.expr) { all = false; break; }
            }
            if (all) e.v[kv.first] = kv.second;
        }
        return e;
    }

    // Local C-condition renderer for setcc / cmovcc (mirrors Decompiler's condString).
    static bool condOp(const std::string& m, const char*& op, const char*& neg) {
        if (m == "je"  || m == "jz")  { op = "=="; neg = "!="; return true; }
        if (m == "jne" || m == "jnz") { op = "!="; neg = "=="; return true; }
        if (m == "jg"  || m == "jnle" || m == "ja"  || m == "jnbe") { op = ">";  neg = "<="; return true; }
        if (m == "jge" || m == "jnl"  || m == "jae" || m == "jnb" || m == "jnc") { op = ">="; neg = "<"; return true; }
        if (m == "jl"  || m == "jnge" || m == "jb"  || m == "jc" || m == "jnae") { op = "<";  neg = ">="; return true; }
        if (m == "jle" || m == "jng"  || m == "jbe" || m == "jna") { op = "<="; neg = ">";  return true; }
        return false;
    }
    static std::string condText(const std::string& mnem, const FlagState& fl, bool negate) {
        const char* op; const char* neg;
        if (!condOp(mnem, op, neg)) { std::string base = mnem + "_cc"; return negate ? "!" + base : base; }
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

    // ---- global live-variable analysis + dead-assignment elimination ----
    void eliminateDead() {
        std::vector<std::set<std::string>> gen(N), kill(N), liveIn(N), liveOut(N);
        for (int i = 0; i < N; ++i) {
            std::set<std::string> defined;
            for (const Stmt& s : blockStmts_[i]) {
                for (const std::string& r : s.reads) if (!defined.count(r)) gen[i].insert(r);
                if (!s.dst.empty()) { defined.insert(s.dst); kill[i].insert(s.dst); }
            }
        }
        bool changed = true;
        while (changed) {
            changed = false;
            for (int i = N - 1; i >= 0; --i) {
                std::set<std::string> out;
                for (size_t s : g.blocks[i].succ) if (s < (size_t)N) out.insert(liveIn[s].begin(), liveIn[s].end());
                if (g.blocks[i].isReturn) out.insert(retReads_[i].begin(), retReads_[i].end());
                std::set<std::string> in = gen[i];
                for (const std::string& v : out) if (!kill[i].count(v)) in.insert(v);
                if (out != liveOut[i] || in != liveIn[i]) { liveOut[i] = std::move(out); liveIn[i] = std::move(in); changed = true; }
            }
        }
        for (int i = 0; i < N; ++i) {
            std::set<std::string> live = liveOut[i];
            std::vector<Stmt>& v = blockStmts_[i];
            for (int k = (int)v.size() - 1; k >= 0; --k) {
                Stmt& s = v[k];
                bool dstLive = s.dst.empty() ? true : live.count(s.dst) != 0;
                if (!s.side && !s.dst.empty() && !dstLive) { v.erase(v.begin() + k); continue; }   // dead assignment
                if (s.side && !s.dst.empty() && !dstLive && !s.callRhs.empty()) {                    // dead call result
                    s.text = s.callRhs + ";"; s.dst.clear();
                }
                if (!s.dst.empty()) live.erase(s.dst);
                for (const std::string& r : s.reads) live.insert(r);
            }
        }
    }

    DataFlowResult run() {
        DataFlowResult r;
        if (N == 0) return r;
        blockStmts_.assign(N, {});
        termFlag_.assign(N, {});
        retHasInline_.assign(N, false); retInline_.assign(N, {}); retInlineReads_.assign(N, {});
        retExpr_.assign(N, {}); retReads_.assign(N, {});
        r.retComment.assign(N, {});
        is32_ = looksLike32();   // settle the ABI once (arg detection + call-arg recovery)
        detectArgs();

        // ---- inter-block reaching-definitions (sparse constant/copy propagation) ----
        // A constant/copy defined in one block and used in a successor should render
        // folded (e.g. `mov rax,5` then a later block's `mov rbx,rax` -> `rbx = 5`).
        // We run the per-block lift as a data-flow transfer function: starting from a
        // baseline (empty-inEnv) lift to allocate names, then iterate `inEnv = meet of
        // predecessors' outEnv` to a fixpoint. The final lift below is seeded with the
        // converged inEnv so values fold across boundaries; the meet (must-reach with
        // identical expr) keeps this sound through joins and loop back-edges.
        std::vector<std::vector<int>> preds(N);
        for (int u = 0; u < N; ++u)
            for (size_t s : g.blocks[u].succ) if (s < (size_t)N) preds[s].push_back(u);

        std::vector<Env> inEnv(N), outEnv(N);
        // Baseline (legacy) transfer: empty inEnv -> seeds names + initial outEnv.
        for (int i = 0; i < N; ++i) liftBlock(i, Env{}, /*dry=*/true, &outEnv[i]);
        // Fixpoint: refine entry envs from predecessor exit envs, re-running the
        // transfer until nothing changes. The meet only narrows (must-reach), so this
        // converges quickly (≈ loop-nesting depth); the cap bounds worst-case cost on
        // pathologically large CFGs while still reaching a fixpoint in practice.
        const int kMaxIters = N < 12 ? N + 4 : 16;
        for (int iter = 0; iter < kMaxIters; ++iter) {
            bool changed = false;
            for (int i = 1; i < N; ++i) {            // block 0 (entry) keeps empty inEnv
                Env m = meetPreds(preds[i], outEnv);
                if (m.v.size() != inEnv[i].v.size()) { inEnv[i] = std::move(m); changed = true; }
                else {
                    bool diff = false;
                    for (const auto& kv : m.v) { auto it = inEnv[i].v.find(kv.first);
                        if (it == inEnv[i].v.end() || it->second.expr != kv.second.expr) { diff = true; break; } }
                    if (diff) { inEnv[i] = std::move(m); changed = true; }
                }
            }
            if (!changed && iter > 0) break;
            for (int i = 0; i < N; ++i) liftBlock(i, inEnv[i], /*dry=*/true, &outEnv[i]);
        }
        // Final lift with the converged entry environments (records statements).
        for (int i = 0; i < N; ++i) liftBlock(i, inEnv[i], /*dry=*/false, nullptr);

        // Recover return values: a function returns in rax (Win64). If rax is ever
        // assigned, each return reports rax's value (inlined when known, else its
        // variable name); otherwise it's a bare `return;`.
        std::string raxNm = name_.count(regLoc(RAX)) ? name_[regLoc(RAX)] : "";
        bool raxAssigned = false;
        if (!raxNm.empty())
            for (const auto& blk : blockStmts_) { for (const Stmt& s : blk) if (s.dst == raxNm) { raxAssigned = true; break; } if (raxAssigned) break; }
        if (raxAssigned)
            for (int i = 0; i < N; ++i) {
                if (!g.blocks[i].isReturn) continue;
                if (retHasInline_[i]) { retExpr_[i] = retInline_[i]; retReads_[i] = retInlineReads_[i]; }
                else                  { retExpr_[i] = raxNm; retReads_[i] = { raxNm }; }
                // The inlined return expression folded to pure constant math:
                // spell out the value as a trailing comment (display-only).
                if (long long cv = 0; tryFoldConst(retExpr_[i], cv))
                    r.retComment[i] = " /* = " + immText(cv) + " */";
            }

        eliminateDead();

        // Declare every local/temp that survives DCE, in first-appearance order.
        // Arguments (a*) live in the header; untracked names (xmm*, etc.) are skipped.
        auto declarable = [](const std::string& nm) {
            if (nm.rfind("local_", 0) == 0) return true;
            return nm.size() >= 2 && nm[0] == 'v' && std::isdigit((unsigned char)nm[1]) != 0;
        };
        std::set<std::string> seen;
        for (int i = 0; i < N; ++i)
            for (const Stmt& s : blockStmts_[i]) {
                auto consider = [&](const std::string& nm) {
                    if (!declarable(nm) || !seen.insert(nm).second) return;
                    std::string type = ptr_.count(nm) ? "void *" : (width_[nm] && width_[nm] <= 4 ? "int " : "__int64 ");
                    r.decls.push_back(type + nm + ";");
                };
                if (!s.dst.empty()) consider(s.dst);
                for (const std::string& rd : s.reads) consider(rd);
            }
        r.blockStmts.assign(N, {});
        for (int i = 0; i < N; ++i) {
            for (Stmt& s : blockStmts_[i]) r.blockStmts[i].push_back(std::move(s.text));
            r.termFlag.push_back(termFlag_[i]);
        }
        r.retExpr = std::move(retExpr_);
        for (int k = 1; k <= argCount_; ++k) r.args.push_back("a" + std::to_string(k));  // header parameter list
        r.ok = true;
        return r;
    }
};

} // namespace

DataFlowResult AnalyzeDataFlow(const ControlFlowGraph& g,
                               const std::function<std::string(uint64_t)>& nameFor,
                               const std::function<std::string(uint64_t)>& dataRefFor,
                               bool recoverCallArgs) {
    if (g.blocks.empty()) return {};
    Analyzer a(g, nameFor, dataRefFor, recoverCallArgs);
    return a.run();
}

} // namespace ds
