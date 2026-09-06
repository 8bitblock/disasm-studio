#include "DataFlow.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ds {

namespace {

enum class X86Cond { E, NE, A, AE, B, BE, G, GE, L, LE, S, NS, O, NO, P, NP, Unknown };

X86Cond decodeCond(const std::string& m) {
    if (m == "je" || m == "jz") return X86Cond::E;
    if (m == "jne" || m == "jnz") return X86Cond::NE;
    if (m == "ja" || m == "jnbe") return X86Cond::A;
    if (m == "jae" || m == "jnb" || m == "jnc") return X86Cond::AE;
    if (m == "jb" || m == "jc" || m == "jnae") return X86Cond::B;
    if (m == "jbe" || m == "jna") return X86Cond::BE;
    if (m == "jg" || m == "jnle") return X86Cond::G;
    if (m == "jge" || m == "jnl") return X86Cond::GE;
    if (m == "jl" || m == "jnge") return X86Cond::L;
    if (m == "jle" || m == "jng") return X86Cond::LE;
    if (m == "js") return X86Cond::S;
    if (m == "jns") return X86Cond::NS;
    if (m == "jo") return X86Cond::O;
    if (m == "jno") return X86Cond::NO;
    if (m == "jp" || m == "jpe") return X86Cond::P;
    if (m == "jnp" || m == "jpo") return X86Cond::NP;
    return X86Cond::Unknown;
}

X86Cond invertCond(X86Cond c) {
    switch (c) {
        case X86Cond::E: return X86Cond::NE; case X86Cond::NE: return X86Cond::E;
        case X86Cond::A: return X86Cond::BE; case X86Cond::BE: return X86Cond::A;
        case X86Cond::AE: return X86Cond::B; case X86Cond::B: return X86Cond::AE;
        case X86Cond::G: return X86Cond::LE; case X86Cond::LE: return X86Cond::G;
        case X86Cond::GE: return X86Cond::L; case X86Cond::L: return X86Cond::GE;
        case X86Cond::S: return X86Cond::NS; case X86Cond::NS: return X86Cond::S;
        case X86Cond::O: return X86Cond::NO; case X86Cond::NO: return X86Cond::O;
        case X86Cond::P: return X86Cond::NP; case X86Cond::NP: return X86Cond::P;
        default: return X86Cond::Unknown;
    }
}

uint16_t flagWidth(const FlagProvenance& p) {
    return !p.widthBits ? 64 : p.widthBits <= 8 ? 8 : p.widthBits <= 16 ? 16 :
           p.widthBits <= 32 ? 32 : 64;
}

bool wholeParenthesized(const std::string& value) {
    if (value.size() < 2 || value.front() != '(' || value.back() != ')') return false;
    int depth = 0;
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '(') ++depth;
        else if (value[i] == ')' && (--depth == 0)) return i + 1 == value.size();
        if (depth < 0) return false;
    }
    return false;
}

std::string flagCast(bool isSigned, uint16_t width, const std::string& value) {
    std::string operand = value;
    while (wholeParenthesized(operand)) operand = operand.substr(1, operand.size() - 2);
    return "(" + std::string(isSigned ? "int" : "uint") + std::to_string(width) +
           "_t)(" + operand + ")";
}

std::string signMask(uint16_t width) {
    if (width == 64) return "0x8000000000000000ULL";
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llXU",
                  static_cast<unsigned long long>(uint64_t{1} << (width - 1)));
    return text;
}

std::string resultValue(const FlagProvenance& p, uint16_t width) {
    if (p.kind == CmpKind::Cmp)
        return flagCast(false, width, flagCast(false, width, p.lhs) + " - " +
                                    flagCast(false, width, p.rhs));
    if (p.kind == CmpKind::TestAnd)
        return flagCast(false, width, flagCast(false, width, p.lhs) + " & " +
                                      flagCast(false, width, p.rhs));
    return flagCast(false, width, p.lhs);
}

std::string flagExpression(X86Flag flag, const FlagProvenance& p) {
    if (!p.valid) return {};
    const uint16_t width = flagWidth(p);
    const std::string uResult = flagCast(false, width, p.lhs);
    const std::string uRhs = flagCast(false, width, p.rhs);
    const std::string result = resultValue(p, width);
    switch (flag) {
        case X86Flag::Zero:
            if (p.kind == CmpKind::Cmp) return uResult + " == " + uRhs;
            return result + " == 0";
        case X86Flag::Sign:
            return flagCast(true, width, result) + " < 0";
        case X86Flag::Carry:
            switch (p.kind) {
                case CmpKind::Cmp:
                    return flagCast(false, width, p.lhs) + " < " + uRhs;
                case CmpKind::TestZero: case CmpKind::TestAnd: case CmpKind::LogicResult:
                    return "false"; // TEST/AND/OR/XOR clear CF.
                case CmpKind::AddResult:
                    // With result and either addend, carry is result < addend.
                    return uResult + " < " + uRhs;
                case CmpKind::SubResult: {
                    // Reconstruct the old destination modulo the operation width.
                    const std::string old = flagCast(false, width, uResult + " + " + uRhs);
                    return old + " < " + uRhs;
                }
                case CmpKind::NegResult:
                    return uResult + " != 0";
                default: return {};
            }
        case X86Flag::Overflow:
            switch (p.kind) {
                case CmpKind::TestZero: case CmpKind::TestAnd: case CmpKind::LogicResult:
                    return "false"; // TEST/AND/OR/XOR clear OF.
                case CmpKind::IncResult:
                case CmpKind::NegResult:
                    return uResult + " == " + signMask(width);
                case CmpKind::DecResult: {
                    const uint64_t maxSigned = width == 64 ? 0x7FFFFFFFFFFFFFFFull :
                        ((uint64_t{1} << (width - 1)) - 1);
                    char text[24]; std::snprintf(text, sizeof(text), width == 64 ? "0x%llXULL" : "0x%llXU",
                                                static_cast<unsigned long long>(maxSigned));
                    return uResult + " == " + text;
                }
                case CmpKind::AddResult: {
                    const std::string old = flagCast(false, width, uResult + " - " + uRhs);
                    return "((~(" + old + " ^ " + uRhs + ") & (" + old + " ^ " + uResult +
                           ") & " + signMask(width) + ") != 0)";
                }
                case CmpKind::Cmp: {
                    const std::string left = flagCast(false, width, p.lhs);
                    const std::string value = flagCast(false, width, left + " - " + uRhs);
                    return "(((" + left + " ^ " + uRhs + ") & (" + left + " ^ " + value +
                           ") & " + signMask(width) + ") != 0)";
                }
                case CmpKind::SubResult: {
                    const std::string old = flagCast(false, width, uResult + " + " + uRhs);
                    return "(((" + old + " ^ " + uRhs + ") & (" + old + " ^ " + uResult +
                           ") & " + signMask(width) + ") != 0)";
                }
                default: return {};
            }
        case X86Flag::Parity:
            return {}; // No invented parity helper: expose jp_cc/jnp_cc instead.
        default:
            return {};
    }
}

bool sameCmpOrigin(const FlagState& state, uint8_t needed,
                   const FlagProvenance*& origin) {
    origin = nullptr;
    for (uint8_t index = 0; index < static_cast<uint8_t>(X86Flag::Count); ++index) {
        if (!(needed & static_cast<uint8_t>(1u << index))) continue;
        const X86Flag flag = static_cast<X86Flag>(index);
        const FlagProvenance& p = state.get(flag);
        if (!p.valid || p.kind != CmpKind::Cmp) return false;
        if (!origin) origin = &p;
        else if (!origin->sameOrigin(p)) return false;
    }
    return origin != nullptr;
}

} // namespace

std::string RenderX86Condition(const std::string& mnemonic, const FlagState& state, bool negate) {
    const std::string fallback = negate ? "!" + mnemonic + "_cc" : mnemonic + "_cc";
    X86Cond cond = decodeCond(mnemonic);
    if (cond == X86Cond::Unknown) return fallback;
    if (negate) cond = invertCond(cond);

    // Preserve the compact, readable relation when all required flags came
    // from one CMP. The cast encodes the Jcc's signedness and exact width.
    const FlagProvenance* cmp = nullptr;
    uint8_t needed = 0;
    switch (cond) {
        case X86Cond::E: case X86Cond::NE: needed = kX86FlagZF; break;
        case X86Cond::A: case X86Cond::BE: needed = kX86FlagCF | kX86FlagZF; break;
        case X86Cond::AE: case X86Cond::B: needed = kX86FlagCF; break;
        case X86Cond::G: case X86Cond::LE: needed = kX86FlagZF | kX86FlagSF | kX86FlagOF; break;
        case X86Cond::GE: case X86Cond::L: needed = kX86FlagSF | kX86FlagOF; break;
        case X86Cond::S: case X86Cond::NS: needed = kX86FlagSF; break;
        case X86Cond::O: case X86Cond::NO: needed = kX86FlagOF; break;
        case X86Cond::P: case X86Cond::NP: needed = kX86FlagPF; break;
        default: break;
    }
    if (cond == X86Cond::E || cond == X86Cond::NE) {
        const FlagProvenance& zero = state.get(X86Flag::Zero);
        if (zero.valid) {
            if (zero.kind == CmpKind::Cmp)
                return flagCast(false, flagWidth(zero), zero.lhs) +
                       (cond == X86Cond::E ? " == " : " != ") +
                       flagCast(false, flagWidth(zero), zero.rhs);
            return resultValue(zero, flagWidth(zero)) +
                   (cond == X86Cond::E ? " == 0" : " != 0");
        }
    }
    if (sameCmpOrigin(state, needed, cmp)) {
        const char* op = nullptr;
        bool unsignedRelation = false, signedRelation = false;
        switch (cond) {
            case X86Cond::E: op = "=="; break; case X86Cond::NE: op = "!="; break;
            case X86Cond::A: op = ">"; unsignedRelation = true; break;
            case X86Cond::AE: op = ">="; unsignedRelation = true; break;
            case X86Cond::B: op = "<"; unsignedRelation = true; break;
            case X86Cond::BE: op = "<="; unsignedRelation = true; break;
            case X86Cond::G: op = ">"; signedRelation = true; break;
            case X86Cond::GE: op = ">="; signedRelation = true; break;
            case X86Cond::L: op = "<"; signedRelation = true; break;
            case X86Cond::LE: op = "<="; signedRelation = true; break;
            default: break; // JS/JO/JP are individual flag tests, not comparisons.
        }
        if (op) {
            if (unsignedRelation)
                return flagCast(false, flagWidth(*cmp), cmp->lhs) + " " + op + " " +
                       flagCast(false, flagWidth(*cmp), cmp->rhs);
            if (signedRelation)
                return flagCast(true, flagWidth(*cmp), cmp->lhs) + " " + op + " " +
                       flagCast(true, flagWidth(*cmp), cmp->rhs);
            return flagCast(false, flagWidth(*cmp), cmp->lhs) + " " + op + " " +
                   flagCast(false, flagWidth(*cmp), cmp->rhs);
        }
    }

    auto expression = [&](X86Flag flag) { return flagExpression(flag, state.get(flag)); };
    std::string cf = expression(X86Flag::Carry), zf = expression(X86Flag::Zero);
    std::string sf = expression(X86Flag::Sign), of = expression(X86Flag::Overflow);
    std::string pf = expression(X86Flag::Parity);
    switch (cond) {
        case X86Cond::E:  return zf.empty() ? fallback : "(" + zf + ")";
        case X86Cond::NE: return zf.empty() ? fallback : "!(" + zf + ")";
        case X86Cond::A:  return cf.empty() || zf.empty() ? fallback : "!(" + cf + ") && !(" + zf + ")";
        case X86Cond::AE: return cf.empty() ? fallback : "!(" + cf + ")";
        case X86Cond::B:  return cf.empty() ? fallback : "(" + cf + ")";
        case X86Cond::BE: return cf.empty() || zf.empty() ? fallback : "(" + cf + ") || (" + zf + ")";
        case X86Cond::G:  return zf.empty() || sf.empty() || of.empty() ? fallback :
                                "!(" + zf + ") && ((" + sf + ") == (" + of + "))";
        case X86Cond::GE: return sf.empty() || of.empty() ? fallback : "(" + sf + ") == (" + of + ")";
        case X86Cond::L:  return sf.empty() || of.empty() ? fallback : "(" + sf + ") != (" + of + ")";
        case X86Cond::LE: return zf.empty() || sf.empty() || of.empty() ? fallback :
                                "(" + zf + ") || ((" + sf + ") != (" + of + "))";
        case X86Cond::S:  return sf.empty() ? fallback : "(" + sf + ")";
        case X86Cond::NS: return sf.empty() ? fallback : "!(" + sf + ")";
        case X86Cond::O:  return of.empty() ? fallback : "(" + of + ")";
        case X86Cond::NO: return of.empty() ? fallback : "!(" + of + ")";
        case X86Cond::P:  return pf.empty() ? fallback : "(" + pf + ")";
        case X86Cond::NP: return pf.empty() ? fallback : "!(" + pf + ")";
        default: return fallback;
    }
}

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
struct BitPattern {
    uint64_t bits = 0;
    uint16_t widthBits = 64;
    bool signedInterpretation = false;
};

uint16_t normalizedBitWidth(uint16_t width) {
    if (!width || width > 64) return 64;
    return width;
}
uint64_t bitMask(uint16_t width) {
    width = normalizedBitWidth(width);
    return width == 64 ? (std::numeric_limits<uint64_t>::max)()
                       : ((uint64_t{1} << width) - 1);
}
BitPattern makeBits(uint64_t bits, uint16_t width = 64, bool signedValue = false) {
    BitPattern value;
    value.widthBits = normalizedBitWidth(width);
    value.bits = bits & bitMask(value.widthBits);
    value.signedInterpretation = signedValue;
    return value;
}
bool bitPatternNegative(const BitPattern& value) {
    const uint16_t width = normalizedBitWidth(value.widthBits);
    return value.signedInterpretation &&
           (value.bits & (uint64_t{1} << (width - 1))) != 0;
}
uint64_t bitPatternMagnitude(const BitPattern& value) {
    return ((~value.bits) + 1u) & bitMask(value.widthBits);
}

struct Mem {
    bool baseReg = false; int baseCanon = -1;
    bool hasIndex = false; int idxCanon = -1; int scale = 1;
    long long disp = 0; bool ripRel = false; bool dispOnly = false;
    int width = 8; std::string raw;
};
struct Operand {
    OK kind = OK::None;
    OperandAccess access = OperandAccess::None;
    RegInfo reg;
    BitPattern imm;
    Mem mem;
    std::string sym;     // symbol / unparsed token
    std::string raw;     // original text
    bool parsed = false;
};

bool parseSigned64(const std::string& s, int64_t& out) {
    std::string t = trim(s);
    if (t.empty()) return false;
    bool neg = false; size_t i = 0;
    if (t[0] == '+' || t[0] == '-') { neg = (t[0] == '-'); i = 1; }
    if (i == t.size()) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(t.c_str() + i, &end, 0);
    if (errno == ERANGE || end == t.c_str() + i || *end != '\0') return false;
    const uint64_t maxPositive = static_cast<uint64_t>((std::numeric_limits<int64_t>::max)());
    const uint64_t maxNegativeMagnitude = maxPositive + 1u;
    if ((!neg && v > maxPositive) || (neg && v > maxNegativeMagnitude)) return false;
    if (!neg) out = static_cast<int64_t>(v);
    else if (v == maxNegativeMagnitude) out = (std::numeric_limits<int64_t>::min)();
    else out = -static_cast<int64_t>(v);
    return true;
}

bool parseImm(const std::string& s, BitPattern& out) {
    std::string t = trim(s);
    if (t.empty()) return false;
    bool neg = false; size_t i = 0;
    if (t[0] == '+' || t[0] == '-') { neg = t[0] == '-'; i = 1; }
    if (i == t.size()) return false;
    char* end = nullptr;
    errno = 0;
    const uint64_t magnitude = std::strtoull(t.c_str() + i, &end, 0);
    if (errno == ERANGE || end == t.c_str() + i || *end != '\0') return false;
    out = makeBits(neg ? uint64_t{0} - magnitude : magnitude, 64, neg);
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
            RegInfo ri; int64_t scv = 1;
            if (lookupReg(r, ri) && parseSigned64(sc, scv) && scv > 0 && scv <= 8) {
                m.hasIndex = true; m.idxCanon = ri.canon; m.scale = static_cast<int>(scv);
                sawReg = true; return;
            }
        }
        RegInfo ri;
        if (lower(term) == "rip") { m.ripRel = true; sawReg = true; return; }
        if (lookupReg(term, ri)) {
            if (!m.baseReg) { m.baseReg = true; m.baseCanon = ri.canon; }
            else { m.hasIndex = true; m.idxCanon = ri.canon; }
            sawReg = true; return;
        }
        int64_t v = 0;
        if (parseSigned64(term, v)) {
            if (sign < 0) {
                if (v == (std::numeric_limits<int64_t>::min)()) { m.raw = "?"; return; }
                v = -v;
            }
            if ((v > 0 && m.disp > (std::numeric_limits<int64_t>::max)() - v) ||
                (v < 0 && m.disp < (std::numeric_limits<int64_t>::min)() - v)) {
                m.raw = "?"; return;
            }
            m.disp += v; sawDisp = true; return;
        }
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
    BitPattern v;
    if (parseImm(s, v)) { out.kind = OK::Imm; out.imm = v; out.parsed = true; return true; }
    out.kind = OK::Sym; out.sym = s; out.parsed = true; return true;   // symbol / label / fn name
}

bool operandFromTyped(const TypedOperand& typed, Operand& out) {
    out = Operand{};
    out.access = typed.access;
    out.parsed = true;
    switch (typed.kind) {
        case OperandKind::Register: {
            out.raw = lower(typed.registerName);
            RegInfo reg;
            if (!lookupReg(out.raw, reg)) {
                // SIMD/control registers are intentionally outside the symbolic
                // register model. Keep the exact decoder spelling, but do not
                // pretend it aliases a general-purpose register.
                out.kind = OK::Sym;
                out.sym = out.raw;
                return true;
            }
            if (typed.widthBits) reg.width = std::max<int>(1, typed.widthBits / 8);
            out.kind = OK::Reg;
            out.reg = reg;
            return true;
        }
        case OperandKind::Immediate:
        case OperandKind::Pointer:
            out.kind = OK::Imm;
            out.imm = makeBits(typed.immediate, typed.widthBits, typed.immediateSigned);
            return true;
        case OperandKind::Memory: {
            Mem memory;
            memory.width = typed.widthBits ? std::max<int>(1, typed.widthBits / 8) : 8;
            memory.disp = typed.displacement;
            memory.dispOnly = typed.displacementValid;
            const std::string base = lower(typed.baseRegister);
            const std::string index = lower(typed.indexRegister);
            if (base == "rip" || base == "eip") {
                memory.ripRel = true;
                memory.dispOnly = false;
            } else if (!base.empty()) {
                RegInfo reg;
                if (!lookupReg(base, reg)) return false;
                memory.baseReg = true;
                memory.baseCanon = reg.canon;
                memory.dispOnly = false;
            }
            if (!index.empty()) {
                RegInfo reg;
                if (!lookupReg(index, reg)) return false;
                memory.hasIndex = true;
                memory.idxCanon = reg.canon;
                memory.scale = typed.scale > 0 ? typed.scale : 1;
                memory.dispOnly = false;
            }
            out.kind = OK::Mem;
            out.mem = std::move(memory);
            return true;
        }
        default:
            return false;
    }
}

std::vector<std::string> splitOperands(const std::string& operands) {
    std::vector<std::string> result;
    int depth = 0;
    size_t begin = 0;
    for (size_t i = 0; i <= operands.size(); ++i) {
        const char c = i < operands.size() ? operands[i] : ',';
        if (c == '[' || c == '(') ++depth;
        else if (c == ']' || c == ')') --depth;
        else if (c == ',' && depth == 0) {
            const std::string token = trim(operands.substr(begin, i - begin));
            if (!token.empty()) result.push_back(token);
            begin = i + 1;
        }
    }
    return result;
}

// Production decoders provide typedOperands; never reparse their formatted
// operand string. Text parsing remains only for deliberately minimal test and
// compatibility decoders that expose no typed model at all.
bool decodeOperands(const Instruction& instruction, std::vector<Operand>& out) {
    out.clear();
    if (!instruction.typedOperands.empty()) {
        out.reserve(instruction.typedOperands.size());
        for (const TypedOperand& typed : instruction.typedOperands) {
            Operand operand;
            if (!operandFromTyped(typed, operand)) return false;
            out.push_back(std::move(operand));
        }
        return !out.empty();
    }
    const std::vector<std::string> tokens = splitOperands(instruction.operands);
    out.reserve(tokens.size());
    for (const std::string& token : tokens) {
        Operand operand;
        if (!parseOperand(token, operand)) return false;
        out.push_back(std::move(operand));
    }
    return !out.empty();
}

uint16_t operandWidthBits(const Operand& operand) {
    if (operand.kind == OK::Reg) return static_cast<uint16_t>(operand.reg.width * 8);
    if (operand.kind == OK::Mem) return static_cast<uint16_t>(operand.mem.width * 8);
    if (operand.kind == OK::Imm) return operand.imm.widthBits;
    return 0;
}

bool sameOperand(const Operand& a, const Operand& b) {
    if (a.kind != b.kind) return false;
    if (a.kind == OK::Reg)
        return a.reg.canon == b.reg.canon && a.reg.width == b.reg.width &&
               a.reg.high8 == b.reg.high8;
    if (a.kind == OK::Imm)
        return a.imm.bits == b.imm.bits && a.imm.widthBits == b.imm.widthBits;
    if (a.kind == OK::Mem)
        return a.mem.baseReg == b.mem.baseReg && a.mem.baseCanon == b.mem.baseCanon &&
               a.mem.hasIndex == b.mem.hasIndex && a.mem.idxCanon == b.mem.idxCanon &&
               a.mem.scale == b.mem.scale && a.mem.disp == b.mem.disp &&
               a.mem.ripRel == b.mem.ripRel;
    return a.raw == b.raw && a.sym == b.sym;
}

std::string immText(const BitPattern& value) {
    char b[32];
    if (bitPatternNegative(value))
        std::snprintf(b, sizeof(b), "-0x%llX",
                      static_cast<unsigned long long>(bitPatternMagnitude(value)));
    else if (value.bits < 16)
        std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(value.bits));
    else
        std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(value.bits));
    return b;
}
std::string signedMagnitudeText(int64_t value) {
    const uint64_t magnitude = value < 0
        ? uint64_t(-(value + 1)) + 1u : static_cast<uint64_t>(value);
    return immText(makeBits(magnitude, 64, false));
}
std::string addressText(uint64_t value) {
    if (!value) return "0";
    char b[32]; std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)value); return b;
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
    uint16_t widthBits = 64;
    uint64_t mask = (std::numeric_limits<uint64_t>::max)();
    explicit ConstEval(const std::string& s, uint16_t width)
        : p(s.c_str()), e(s.c_str() + s.size()),
          widthBits(normalizedBitWidth(width)), mask(bitMask(widthBits)) {}
    void ws() { while (p < e && *p == ' ') ++p; }
    bool eat(char c) { ws(); if (p < e && *p == c) { ++p; return true; } return false; }
    bool peek2(const char* two) { ws(); return p + 1 < e && p[0] == two[0] && p[1] == two[1]; }
    uint64_t prim() {
        ws();
        if (eat('(')) { uint64_t v = expr(); if (!eat(')')) ok = false; return v; }
        if (p < e && (std::isdigit((unsigned char)*p))) {
            char* endp = nullptr;
            errno = 0;
            const uint64_t v = std::strtoull(p, &endp, 0);   // 0x-aware
            if (errno == ERANGE || endp == p || v > mask) { ok = false; return 0; }
            p = endp; ++lits;
            return v;
        }
        ok = false; return 0;
    }
    uint64_t unary() {
        ws();
        if (eat('-')) return (uint64_t{0} - unary()) & mask;
        if (eat('~')) return (~unary()) & mask;
        return prim();
    }
    uint64_t mul() {
        uint64_t v = unary();
        for (;;) {
            ws();
            if (p < e && *p == '*' && (p + 1 >= e || p[1] != '(')) {
                ++p; const uint64_t r = unary();
                if (!ok || (r && v > mask / r)) { ok = false; return 0; }
                v *= r;
            }
            else if (p < e && *p == '/') { ++p; uint64_t r = unary(); if (!r) { ok = false; return 0; } v /= r; }
            else if (p < e && *p == '%') { ++p; uint64_t r = unary(); if (!r) { ok = false; return 0; } v %= r; }
            else return v;
        }
    }
    uint64_t add() {
        uint64_t v = mul();
        for (;;) {
            ws();
            if (p < e && *p == '+') {
                ++p; const uint64_t r = mul();
                if (!ok || v > mask - r) { ok = false; return 0; }
                v += r;
            }
            else if (p < e && *p == '-') {
                ++p; const uint64_t r = mul();
                if (!ok || v < r) { ok = false; return 0; }
                v -= r;
            }
            else return v;
        }
    }
    uint64_t shift() {
        uint64_t v = add();
        for (;;) {
            if (peek2("<<")) {
                p += 2; const uint64_t r = add();
                if (r >= widthBits || (r && v > (mask >> r))) { ok = false; return 0; }
                v = (v << r) & mask;
            }
            else if (peek2(">>")) {
                p += 2; const uint64_t r = add();
                if (r >= widthBits) { ok = false; return 0; }
                v >>= r;
            }
            else return v;
        }
    }
    uint64_t band() { uint64_t v = shift(); while (ok) { ws(); if (p < e && *p == '&' && (p + 1 >= e || p[1] != '&')) { ++p; v &= shift(); } else break; } return v & mask; }
    uint64_t bxor() { uint64_t v = band();  while (ok) { ws(); if (p < e && *p == '^') { ++p; v ^= band(); } else break; } return v & mask; }
    uint64_t expr() { uint64_t v = bxor();  while (ok) { ws(); if (p < e && *p == '|' && (p + 1 >= e || p[1] != '|')) { ++p; v |= bxor(); } else break; } return v & mask; }
};

// Evaluate `s` as a pure constant expression. True only when the WHOLE string
// parses and at least two literals took part (folding actually happened).
static bool tryFoldConst(const std::string& s, uint16_t widthBits, BitPattern& out) {
    if (s.empty() || s.size() > 128) return false;
    ConstEval ev(s, widthBits);
    const uint64_t v = ev.expr();
    ev.ws();
    if (!ev.ok || ev.p != ev.e || ev.lits < 2) return false;
    out = makeBits(v, widthBits, false);
    return true;
}

// ----------------------------------------------------------- the analyzer ---

struct Val {
    std::string expr;
    std::set<std::string> reads;
    std::set<std::string> deps;
    uint16_t widthBits = 0; // width at which the expression was produced
};

struct Stmt {
    std::string dst;                 // variable defined ("" if none)
    std::string text;                // rendered statement
    std::vector<std::string> reads;  // variable names read
    bool side = false;               // store/call: never DCE'd (but a dead call-dst is stripped)
    std::string callRhs;             // for a call: RHS without "dst = " (to strip a dead result)
    uint64_t sourceVA = 0;
    bool sourceValid = false;
};

struct Analyzer {
    const ControlFlowGraph& g;
    const std::function<std::string(uint64_t)>& nameFor;
    const std::function<std::string(uint64_t)>& dataRefFor;
    bool callArgs_;                                       // recover/inline call arguments
    Arch targetArch_ = Arch::X64;
    DecompileABI targetABI_ = DecompileABI::Auto;
    bool exactArch_ = false;
    bool is32_ = false;                                   // 32-bit (x86) calling convention
    const Instruction* currentInstruction_ = nullptr;
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
    std::vector<uint16_t>              retInlineWidth_;
    std::vector<std::string>           retExpr_;     // final per-block "return <expr>" text
    std::vector<std::set<std::string>> retReads_;    // vars a return reads (liveness seed)

    Analyzer(const ControlFlowGraph& cfg, const std::function<std::string(uint64_t)>& nf,
             const std::function<std::string(uint64_t)>& dr, bool callArgs, Arch targetArch,
             DecompileABI targetABI)
        : g(cfg), nameFor(nf), dataRefFor(dr),
          callArgs_(callArgs && targetABI != DecompileABI::Unknown),
          targetArch_(targetArch), targetABI_(targetABI),
          exactArch_(true), N((int)cfg.blocks.size()) {}
    Analyzer(const ControlFlowGraph& cfg, const std::function<std::string(uint64_t)>& nf,
             const std::function<std::string(uint64_t)>& dr, bool callArgs)
        : g(cfg), nameFor(nf), dataRefFor(dr), callArgs_(callArgs), N((int)cfg.blocks.size()) {}

    // Resolve a constant data address to a display token (quoted string / import /
    // global name), or "" if not meaningful.
    static bool safeDataRefIdentifier(const std::string& text) {
        if (text.empty()) return false;
        static const std::set<std::string> reserved = {
            "False", "None", "True", "and", "as", "assert", "async", "await",
            "break", "class", "continue", "def", "del", "elif", "else", "except",
            "finally", "for", "from", "global", "if", "import", "in", "is",
            "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
            "while", "with", "yield"
        };
        size_t i = 0;
        while (i < text.size()) {
            if (!(std::isalpha((unsigned char)text[i]) || text[i] == '_')) return false;
            const size_t begin = i++;
            while (i < text.size() && (std::isalnum((unsigned char)text[i]) || text[i] == '_')) ++i;
            if (reserved.count(text.substr(begin, i - begin))) return false;
            if (i == text.size()) return true;
            if (text[i] == '.') { ++i; continue; }
            if (i + 1 < text.size() && text[i] == ':' && text[i + 1] == ':') { i += 2; continue; }
            return false;
        }
        return false;
    }

    static bool hexDigit(unsigned char c) {
        return std::isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    // Accept only one complete double-quoted literal. The callback is analyst-
    // facing and therefore untrusted: matching first/last quotes alone would let
    // `"x"; injected(); "y"` escape into the generated expression. Restrict
    // escapes to the C/Python intersection and reject raw controls or trailing
    // expression text.
    static bool safeQuotedDataRefLiteral(const std::string& text) {
        if (text.size() < 2 || text.front() != '"' || text.back() != '"') return false;
        const size_t end = text.size() - 1;
        for (size_t i = 1; i < end;) {
            const unsigned char c = static_cast<unsigned char>(text[i++]);
            if (c == '"' || c < 0x20 || c == 0x7F) return false;
            if (c != '\\') continue;
            if (i >= end) return false;
            const unsigned char escape = static_cast<unsigned char>(text[i++]);
            if (std::strchr("\\\"'abfnrtv", escape)) continue;
            if (escape >= '0' && escape <= '7') {
                for (int digits = 1; digits < 3 && i < end && text[i] >= '0' && text[i] <= '7'; ++digits)
                    ++i;
                continue;
            }
            size_t digits = 0;
            if (escape == 'x') digits = 2;
            else if (escape == 'u') digits = 4;
            else if (escape == 'U') digits = 8;
            else return false;
            if (i + digits > end) return false;
            for (size_t d = 0; d < digits; ++d)
                if (!hexDigit(static_cast<unsigned char>(text[i + d]))) return false;
            if (escape == 'u' || escape == 'U') {
                uint32_t codePoint = 0;
                for (size_t d = 0; d < digits; ++d) {
                    const unsigned char h = static_cast<unsigned char>(text[i + d]);
                    codePoint = (codePoint << 4) | (h <= '9' ? h - '0' :
                                h <= 'F' ? h - 'A' + 10 : h - 'a' + 10);
                }
                if (codePoint > 0x10FFFF || (codePoint >= 0xD800 && codePoint <= 0xDFFF))
                    return false;
            }
            i += digits;
            // Python consumes exactly two hex digits after \x while C consumes
            // an unbounded run; reject an ambiguous following hex digit.
            if (escape == 'x' && i < end && hexDigit(static_cast<unsigned char>(text[i])))
                return false;
        }
        return true;
    }

    static std::string quotedDataRef(const std::string& text) {
        std::string quoted = "\"";
        char hex[5];
        for (unsigned char c : text) {
            if (c == '\\' || c == '"') { quoted += '\\'; quoted += static_cast<char>(c); }
            else if (c == '\n') quoted += "\\n";
            else if (c == '\r') quoted += "\\r";
            else if (c == '\t') quoted += "\\t";
            else if (c < 0x20 || c == 0x7F) {
                std::snprintf(hex, sizeof(hex), "\\x%02X", static_cast<unsigned>(c));
                quoted += hex;
            } else quoted += static_cast<char>(c);
        }
        quoted += '"';
        return quoted;
    }

    std::string dref(uint64_t addr) {
        std::string token = dataRefFor ? dataRefFor(addr) : std::string();
        if (token.empty() || safeQuotedDataRefLiteral(token) ||
            safeDataRefIdentifier(token))
            return token;
        // Analyst/user symbols may contain spaces, dashes, punctuation, or a
        // Python keyword. Preserve their exact identity without injecting them
        // as executable expression text.
        return "symbol_ref(" + quotedDataRef(token) + ")";
    }

    static bool addSigned(uint64_t base, int64_t displacement, uint64_t& result) {
        if (displacement >= 0) {
            const uint64_t d = static_cast<uint64_t>(displacement);
            if (base > (std::numeric_limits<uint64_t>::max)() - d) return false;
            result = base + d; return true;
        }
        const uint64_t d = uint64_t(-(displacement + 1)) + 1;
        if (base < d) return false;
        result = base - d; return true;
    }

    // Resolve a memory operand to an absolute data address without using zero
    // as an invalid sentinel. Prefer the parsed RIP form, then decoder-provided
    // typed metadata, then a plain displacement-only address.
    bool constantAddress(const Operand& op, uint64_t& address) const {
        if (op.kind != OK::Mem) return false;
        if (op.mem.ripRel && currentInstruction_) {
            uint64_t next = currentInstruction_->address;
            if (next > (std::numeric_limits<uint64_t>::max)() - currentInstruction_->length) return false;
            next += currentInstruction_->length;
            return addSigned(next, op.mem.disp, address);
        }
        if (currentInstruction_) {
            const TypedOperand* onlyMemory = nullptr;
            for (const TypedOperand& typed : currentInstruction_->typedOperands) {
                if (typed.kind != OperandKind::Memory) continue;
                if (onlyMemory) { onlyMemory = nullptr; break; }
                onlyMemory = &typed;
            }
            if (onlyMemory && onlyMemory->displacementValid) {
                const bool pcRelative = onlyMemory->pcRelative || lower(onlyMemory->baseRegister) == "rip";
                if (pcRelative) {
                    uint64_t next = currentInstruction_->address;
                    if (next > (std::numeric_limits<uint64_t>::max)() - currentInstruction_->length) return false;
                    next += currentInstruction_->length;
                    return addSigned(next, onlyMemory->displacement, address);
                }
                if (onlyMemory->baseRegister.empty() && onlyMemory->indexRegister.empty()) {
                    address = static_cast<uint64_t>(onlyMemory->displacement);
                    return true;
                }
            }
        }
        if (op.mem.dispOnly) { address = static_cast<uint64_t>(op.mem.disp); return true; }
        return false;
    }

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

    void appendStatement(std::vector<Stmt>& statements, Stmt statement) const {
        if (currentInstruction_) {
            statement.sourceVA = currentInstruction_->address;
            statement.sourceValid = true;
        }
        statements.push_back(std::move(statement));
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
        if (exactArch_ && targetABI_ == DecompileABI::Unknown) return;
        if (is32_) { detectArgsX86(); return; }

        const int win64[4] = { RCX, RDX, 8, 9 };
        const int sysv64[6] = { RDI, RSI, RDX, RCX, 8, 9 };
        const int* argRegs = targetABI_ == DecompileABI::SysV64 ? sysv64 : win64;
        const int argRegCount = targetABI_ == DecompileABI::SysV64 ? 6 : 4;
        std::unordered_set<int> written;
        bool isArg[16] = { false };
        auto useReg = [&](int canon) {
            if (canon < 0 || written.count(canon)) return;
            for (int k = 0; k < argRegCount; ++k) if (canon == argRegs[k]) isArg[canon] = true;
        };
        bool done = false;
        for (const BasicBlock& blk : g.blocks) {
            for (const Instruction& in : blk.insns) {
                const std::string m = lower(in.mnemonic);
                std::vector<Operand> operands;
                const bool decoded = decodeOperands(in, operands);
                const bool two = decoded && operands.size() >= 2;
                const bool threeImul = m == "imul" && operands.size() >= 3;
                Operand da, sb;
                const bool okA = decoded && !operands.empty() && (da = operands[0], true);
                const bool okB = two && (sb = operands[1], true);
                bool writesA = false, readsA = false;
                classifyDst(m, writesA, readsA);
                if (threeImul) readsA = false; // dst = src * imm does not read dst
                // `xor x,x` / `sub x,x` zero the register - they don't read an argument.
                bool selfZero = okB && sameOperand(da, sb) && (m == "xor" || m == "sub");
                // Registers inside memory operands are always reads (address computation).
                if (okA && da.kind == OK::Mem) { if (da.mem.baseReg) useReg(da.mem.baseCanon); if (da.mem.hasIndex) useReg(da.mem.idxCanon); }
                if (okA && da.kind == OK::Reg && readsA && !selfZero) useReg(da.reg.canon);
                if (okB) {
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
        for (int k = 0; k < argRegCount; ++k) if (isArg[argRegs[k]]) maxArg = k + 1;
        int n = 0;
        for (int k = 0; k < maxArg; ++k) argName_[regLoc(argRegs[k])] = "a" + std::to_string(++n);
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
                std::vector<Operand> operands;
                const bool decoded = decodeOperands(in, operands);
                const bool two = decoded && operands.size() >= 2;
                const bool threeImul = m == "imul" && operands.size() >= 3;
                Operand da, sb;
                const bool okA = decoded && !operands.empty() && (da = operands[0], true);
                const bool okB = two && (sb = operands[1], true);
                bool writesA = false, readsA = false;
                classifyDst(m, writesA, readsA);
                if (threeImul) readsA = false;

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
                uint64_t address = 0;
                if (constantAddress(op, address)) { // absolute/RIP-relative global or import slot
                    std::string tok = dref(address);
                    if (!tok.empty() && tok.front() != '"') return tok;
                    if (tok.empty()) {
                        isMemLoad = true; deps.insert("MEM");
                        return "*(" + addressText(address) + ")";
                    }
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
        if (m.disp || first) add(signedMagnitudeText(m.disp), m.disp < 0);
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
            const int sysv64[6] = { RDI, RSI, RDX, RCX, 8, 9 };
            const int* argRegs = targetABI_ == DecompileABI::SysV64 ? sysv64 : win64;
            const int argRegCount = targetABI_ == DecompileABI::SysV64 ? 6 : 4;
            for (int k = 0; k < argRegCount; ++k) {
                auto it = e.v.find(regLoc(argRegs[k]));
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

        for (size_t k = 0; k < b.insns.size(); ++k) {
            // Calls explicitly classified as noreturn are both the block transfer
            // and an observable operation. Keep the call statement, then let the
            // structurer emit the no-fallthrough terminator.
            if (k == b.transferIndex && !b.isNoReturnCall) continue; // delay slots still execute
            const Instruction& in = b.insns[k];
            currentInstruction_ = &in;
            const std::string m = lower(in.mnemonic);
            std::vector<Operand> operands;
            const bool operandsDecoded = decodeOperands(in, operands);
            const bool two = operandsDecoded && operands.size() >= 2;
            const bool threeImul = m == "imul" && operandsDecoded && operands.size() >= 3;
            Operand da, sb, third;
            const bool okA = operandsDecoded && !operands.empty() && (da = operands[0], true);
            const bool okB = two && (sb = operands[1], true);
            const bool okThird = threeImul && (third = operands[2], true);

            // Destination location id (tracked reg or stack slot), if any.
            auto dstLoc = [&](const Operand& d, std::string& loc, int& width) -> bool {
                if (d.kind == OK::Reg && d.reg.canon >= 0) { loc = regLoc(d.reg.canon); width = d.reg.width; return true; }
                if (d.kind == OK::Mem) { std::string s; if (stackLoc(d.mem, s)) { loc = s; width = d.mem.width; return true; } }
                return false;
            };

            std::set<std::string> reads, deps; bool ml = false;
            // Whether the destination register is a high-8 sub-register (ah/bh/ch/dh).
            bool dHigh8 = okA && da.kind == OK::Reg && da.reg.high8;
            auto flagOperandValue = [](const Operand& operand, std::string value) {
                // Canonical register storage names the whole register. AH/BH/CH/DH
                // must select bits 8..15 before the flag-width cast is applied.
                if (operand.kind == OK::Reg && operand.reg.high8)
                    return "(" + value + " >> 8)";
                return value;
            };

            auto emitDef = [&](const std::string& loc, int width, bool high8, const std::string& rhsExpr,
                               std::set<std::string>& rd, std::set<std::string>& dp) {
                std::string nm = nameOf(loc);
                noteWidth(nm, width); markAssigned(nm);
                fl.invalidateDependency(loc);              // preserved flags may print this old value
                killDep(e, loc);                          // invalidate anything depending on this loc
                if (width >= 4) {                         // full (32-bit zero-extends) def: propagatable
                    Stmt s; s.dst = nm; s.text = nm + " = " + rhsExpr + ";";
                    // Const-prop folded the RHS down to pure arithmetic on
                    // constants: spell out the result ("/* = 0x1234 */") so the
                    // reader doesn't have to. Display-only — the propagated
                    // value (Val.expr below) stays the uncommented expression.
                    if (BitPattern cv; tryFoldConst(rhsExpr, static_cast<uint16_t>(width * 8), cv))
                        s.text += " /* = " + immText(cv) + " */";
                    s.reads.assign(rd.begin(), rd.end());
                    appendStatement(out, std::move(s));
                    // A printed assignment has already changed this storage.
                    // Reusing an expression that still names its old value
                    // would apply the operation again (a1 = ~a1; return ~a1).
                    // Constants and expressions rooted in other locations can
                    // still propagate; a self-dependent value must be read
                    // back through the destination's current variable name.
                    if (dp.count(loc) || rd.count(nm)) {
                        // Keep the location present for call-argument recovery;
                        // its value now refers to the completed assignment.
                        Val v; v.expr = nm; v.reads = { nm }; v.deps = { loc };
                        v.widthBits = static_cast<uint16_t>(width * 8);
                        e.v[loc] = std::move(v);
                    } else {
                        Val v; v.expr = rhsExpr; v.reads = rd; v.deps = dp;
                        v.widthBits = static_cast<uint16_t>(width * 8);
                        e.v[loc] = std::move(v);
                    }
                } else {                                  // 8/16-bit partial write: read-modify-write
                    Stmt s; s.dst = nm; s.text = lhsFor(nm, width, high8) + " = " + rhsExpr + ";";
                    s.reads.assign(rd.begin(), rd.end()); s.reads.push_back(nm);   // upper bits of nm survive
                    appendStatement(out, std::move(s));
                    e.v.erase(loc);                       // don't inline a partial value as the full register
                }
            };
            auto emitStore = [&](const Operand& d, const std::string& rhsExpr, std::set<std::string>& rd) {
                std::string addr = renderAddr(e, d.mem, rd, deps);
                Stmt s; s.side = true; s.text = "*(" + addr + ") = " + rhsExpr + ";";
                s.reads.assign(rd.begin(), rd.end());
                appendStatement(out, std::move(s));
                // An untracked pointer may alias a global or a modeled stack
                // slot. Without alias proof no prior printable flag expression
                // is safe, even though the physical EFLAGS bits are preserved.
                fl.clear();
                killMemory(e); killStackSlots(e);          // may alias a tracked stack slot
            };
            auto emitRaw = [&](const std::string& text) {
                Stmt s; s.side = true; s.text = text; appendStatement(out, std::move(s));
            };
            auto emitRawReads = [&](const std::string& text,
                                    const std::set<std::string>& trackedReads) {
                Stmt s; s.side = true; s.text = text;
                s.reads.assign(trackedReads.begin(), trackedReads.end());
                appendStatement(out, std::move(s));
            };

            // An unmodelled instruction invalidates only the outputs reported by
            // the decoder. When a legacy decoder reports no semantics at all we
            // retain the old fail-closed behavior and discard the whole cache.
            auto invalidateUnmodelled = [&]() {
                bool reportedOutput = false;
                for (const TypedOperand& typed : in.typedOperands) {
                    if (!OperandWrites(typed.access)) continue;
                    reportedOutput = true;
                    Operand output;
                    if (!operandFromTyped(typed, output)) continue;
                    if (output.kind == OK::Reg && output.reg.canon >= 0) {
                        const std::string loc = regLoc(output.reg.canon);
                        fl.invalidateDependency(loc);
                        killDep(e, loc); e.v.erase(loc);
                    } else if (output.kind == OK::Mem) {
                        std::string loc;
                        if (stackLoc(output.mem, loc)) { fl.invalidateDependency(loc); killDep(e, loc); e.v.erase(loc); }
                        else { fl.clear(); killMemory(e); killStackSlots(e); }
                    }
                }
                for (const std::string& written : in.registersWritten) {
                    RegInfo reg;
                    if (!lookupReg(written, reg) || reg.canon < 0) continue;
                    reportedOutput = true;
                    const std::string loc = regLoc(reg.canon);
                    fl.invalidateDependency(loc);
                    killDep(e, loc); e.v.erase(loc);
                }
                if (!reportedOutput && in.typedOperands.empty() && in.registersWritten.empty())
                    e.v.clear();
                if (in.flagsWritten || (in.typedOperands.empty() && in.registersWritten.empty()))
                    fl = {};
            };

            // Unparseable operands -> fall back to a faithful asm comment (never lose it).
            const bool hasEncodedOperands = !in.typedOperands.empty() || !in.operands.empty();
            if ((hasEncodedOperands && !operandsDecoded) ||
                (two && (!okA || !okB || (threeImul && !okThird)))) {
                emitRaw(in.operands.empty() ? ("__asm { " + m + " };")
                                            : ("__asm { " + m + " " + in.operands + " };"));
                invalidateUnmodelled();
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
                    if (da.kind == OK::Imm) val = dref(da.imm.bits);  // string/global, including VA zero
                    if (val.empty()) val = renderRValue(e, da, rd, dp, ml2);
                    pendingPush_.push_back({ val, rd });
                }
                // Argument recovery is additive metadata, not permission to erase
                // the real stack mutation from the pseudocode.
                emitRaw(in.operands.empty() ? "__asm { push };" : "__asm { push " + in.operands + " };" );
                fl.invalidateDependency(regLoc(RSP));
                fl.invalidateDependency("MEM");
                fl.invalidateDependencyPrefix("k:");
                killDep(e, regLoc(RSP)); e.v.erase(regLoc(RSP)); killStackSlots(e);
                continue;
            }

            // --- mnemonic dispatch ---
            if (m == "nop" || m == "endbr64" || m == "endbr32") continue;
            if (m == "pop" || m == "leave" || m == "hlt" || m == "int3" ||
                m == "cdqe" || m == "cdq" || m == "cqo") {
                std::set<std::string> mutationReads, mutationDeps;
                if (m == "cdqe" || m == "cdq" || m == "cqo") {
                    const std::string source = renderLoc(e, regLoc(RAX), mutationReads,
                                                         mutationDeps);
                    const std::string target = m == "cdqe" ? regLoc(RAX) : regLoc(RDX);
                    const int width = m == "cdq" ? 4 : 8;
                    const std::string expression = m == "cdqe"
                        ? "(int64_t)(int32_t)(" + source + ")"
                        : m == "cdq" ? "(int32_t)(" + source + ") >> 31"
                                     : "(int64_t)(" + source + ") >> 63";
                    emitDef(target, width, false, expression, mutationReads, mutationDeps);
                    continue;
                }
                if (m == "pop") (void)renderLoc(e, regLoc(RSP), mutationReads, mutationDeps);
                if (m == "leave") (void)renderLoc(e, regLoc(RBP), mutationReads, mutationDeps);
                emitRawReads(in.operands.empty() ? ("__asm { " + m + " };")
                                                 : ("__asm { " + m + " " + in.operands + " };"),
                             mutationReads);
                if (m == "leave") {
                    fl.invalidateDependency(regLoc(RSP)); fl.invalidateDependency(regLoc(RBP));
                    fl.invalidateDependency("MEM");
                    fl.invalidateDependencyPrefix("k:");
                    e.v.erase(regLoc(RSP)); e.v.erase(regLoc(RBP)); killStackSlots(e); pendingPush_.clear();
                } else if (m == "pop" && okA) {
                    std::string loc; int w = 0;
                    if (dstLoc(da, loc, w)) { fl.invalidateDependency(loc); killDep(e, loc); e.v.erase(loc); }
                    fl.invalidateDependency(regLoc(RSP)); fl.invalidateDependency("MEM");
                    fl.invalidateDependencyPrefix("k:");
                    killDep(e, regLoc(RSP)); e.v.erase(regLoc(RSP)); killStackSlots(e);
                }
                continue;
            }

            if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs" ||
                m == "movq" || m == "movd") {
                if (!two) { emitRaw("__asm { " + m + " " + in.operands + " };"); invalidateUnmodelled(); continue; }
                std::string rhs;
                if (sb.kind == OK::Imm) rhs = dref(sb.imm.bits); // string/global address, including VA zero
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
                else { emitRaw("__asm { " + m + " " + in.operands + " };"); invalidateUnmodelled(); }
                continue;
            }
            if (m == "lea") {
                if (!two || sb.kind != OK::Mem) { emitRaw("__asm { lea " + in.operands + " };"); invalidateUnmodelled(); continue; }
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); ptr_.insert(nm);
                    // lea of a constant address -> resolve to a string/symbol token.
                    uint64_t address = 0;
                    std::string tok = constantAddress(sb, address) ? dref(address) : std::string();
                    if (!tok.empty()) { std::set<std::string> rd, dp; emitDef(loc, w, false, tok, rd, dp); }
                    else if (constantAddress(sb, address)) {
                        std::set<std::string> rd, dp; emitDef(loc, w, false, addressText(address), rd, dp);
                    }
                    else { std::string addr = renderAddr(e, sb.mem, reads, deps); emitDef(loc, w, false, "(" + addr + ")", reads, deps); }
                } else { emitRaw("__asm { lea " + in.operands + " };"); invalidateUnmodelled(); }
                continue;
            }
            // Arithmetic / logic: compound assignment, sets flags for a following Jcc.
            auto compound = [&](const char* op, CmpKind flagKind) {
                if (!two) {
                    emitRaw("__asm { " + m + (in.operands.empty() ? std::string() : " " + in.operands) + " };");
                    invalidateUnmodelled(); return;
                }
                // Polish: `x += -k` -> `x -= k`; `x -= -k` -> `x += k`.
                const char* useOp = op;
                Operand src = sb;
                const std::string semanticRhs = renderRValue(e, sb, reads, deps, ml);
                if (src.kind == OK::Imm && bitPatternNegative(src.imm) &&
                    (op[0] == '+' || op[0] == '-') && op[1] == '\0') {
                    useOp = (op[0] == '+') ? "-" : "+";
                    src.imm = makeBits(bitPatternMagnitude(src.imm), src.imm.widthBits, false);
                }
                std::string rhs = (useOp == op) ? semanticRhs : renderRValue(e, src, reads, deps, ml);
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); noteWidth(nm, w); markAssigned(nm);
                    fl.invalidateDependency(loc);
                    Stmt s; s.dst = nm; s.text = lhsFor(nm, w, dHigh8) + " " + useOp + "= " + rhs + ";";
                    s.reads.assign(reads.begin(), reads.end()); s.reads.push_back(nm);
                    appendStatement(out, std::move(s));
                    killDep(e, loc); e.v.erase(loc);             // value is now non-trivial; stop inlining it
                    fl.clear();
                    if (flagKind != CmpKind::None) {
                        std::vector<std::string> flagReads(reads.begin(), reads.end());
                        flagReads.push_back(nm);
                        std::vector<std::string> flagDeps(deps.begin(), deps.end());
                        flagDeps.push_back(loc);
                        const bool aliasedArithmetic =
                            (flagKind == CmpKind::AddResult || flagKind == CmpKind::SubResult) &&
                            sameOperand(da, sb);
                        const uint8_t modeled = aliasedArithmetic
                            ? static_cast<uint8_t>(kX86FlagZF | kX86FlagSF)
                            : static_cast<uint8_t>(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF);
                        fl.write(modeled,
                                 flagKind, nm, semanticRhs, flagReads,
                                 static_cast<uint16_t>(w * 8), flagDeps);
                    }
                } else if (da.kind == OK::Mem) {
                    std::set<std::string> rd = reads;
                    std::string lhs = renderRValue(e, da, rd, deps, ml);
                    Stmt s; s.side = true; s.text = lhs + " " + op + "= " + rhs + ";";
                    s.reads.assign(rd.begin(), rd.end()); appendStatement(out, std::move(s));
                    killMemory(e); killStackSlots(e);
                    fl.clear();
                    if (flagKind != CmpKind::None)
                        fl.write(((flagKind == CmpKind::AddResult || flagKind == CmpKind::SubResult) &&
                                  sameOperand(da, sb))
                                     ? static_cast<uint8_t>(kX86FlagZF | kX86FlagSF)
                                     : static_cast<uint8_t>(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF),
                                 flagKind, lhs, semanticRhs,
                                 std::vector<std::string>(rd.begin(), rd.end()),
                                 operandWidthBits(da),
                                 std::vector<std::string>(deps.begin(), deps.end()));
                } else {
                    emitRaw("__asm { " + m + " " + in.operands + " };"); invalidateUnmodelled();
                }
            };
            if (m == "add") { compound("+", CmpKind::AddResult); continue; }
            if (m == "sub") { compound("-", CmpKind::SubResult); continue; }
            if (m == "and") { compound("&", CmpKind::LogicResult); continue; }
            if (m == "or")  { compound("|", CmpKind::LogicResult); continue; }
            if (m == "shl" || m == "sal" || m == "shr" || m == "sar") {
                const uint16_t bits = operandWidthBits(da);
                std::string loc; int w = 0;
                const bool tracked = dstLoc(da, loc, w);
                if (!two || (bits != 8 && bits != 16 && bits != 32 && bits != 64) ||
                    (!tracked && da.kind != OK::Mem)) {
                    emitRaw("__asm { " + m + " " + in.operands + " };");
                    invalidateUnmodelled(); continue;
                }
                // Intel SDM Vol. 2B, SAL/SAR/SHL/SHR: byte/word/dword
                // operands use a five-bit count; qwords use six bits. A zero
                // masked count preserves flags, including an encoded 32/64.
                const uint64_t countMask = bits == 64 ? 63 : 31;
                const bool countKnown = sb.kind == OK::Imm;
                const uint64_t maskedCount = countKnown ? sb.imm.bits & countMask : 0;
                const bool unchanged = countKnown && maskedCount == 0;
                if (unchanged && (da.kind != OK::Reg || bits != 32 || is32_)) {
                    // Keep memory access visible, but there is no memory
                    // mutation or flag writer when the count is zero.
                    if (da.kind == OK::Mem)
                        emitRaw("__asm { " + m + " " + in.operands + " };");
                    continue;
                }

                std::string value = flagOperandValue(da, renderRValue(e, da, reads, deps, ml));
                std::string count = countKnown ? std::to_string(maskedCount) :
                    "((" + renderRValue(e, sb, reads, deps, ml) + ") & " +
                    std::to_string(countMask) + ")";
                // Canonical variables can be wider than the operand. Select
                // the native input width before sign extension (SAR) or zero
                // extension (SHR/SHL), then calculate in 64 bits. All masked
                // counts are below 64, so even byte/word shifts past their
                // width avoid C's promoted-int overflow/overshift hazards.
                const bool arithmetic = m == "sar";
                std::string input = flagCast(arithmetic, bits, value);
                if (bits < 64) input = flagCast(arithmetic, 64, input);
                const std::string expression = unchanged
                    ? flagCast(false, bits, value)
                    : flagCast(false, bits, input +
                        (m == "shl" || m == "sal" ? " << " : " >> ") + count);
                if (tracked) emitDef(loc, w, dHigh8, expression, reads, deps);
                else emitStore(da, expression, reads);

                // Nonzero/unknown counts need independent CF/OF modeling;
                // do not reuse a previous CMP as this shift's branch condition.
                // At zero, keep all still-printable provenance. The x64 EAX
                // write still zero-extends RAX, so emitDef may invalidate a
                // prior flag expression that depended on its old upper bits.
                if (!unchanged) fl.clear();
                continue;
            }
            if (m == "xor") {
                if (two && sameOperand(da, sb)) {   // xor x,x -> x = 0 (constant; enables propagation)
                    std::string loc; int w;
                    if (dstLoc(da, loc, w)) { std::set<std::string> rd, dp; emitDef(loc, w, dHigh8, "0", rd, dp); const std::string nm = nameOf(loc); fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::LogicResult, nm, "", { nm }, static_cast<uint16_t>(w * 8), { loc }); }
                    else { emitRaw("__asm { xor " + in.operands + " };"); invalidateUnmodelled(); }
                    continue;
                }
                compound("^", CmpKind::LogicResult); continue;
            }
            if (m == "inc" || m == "dec") {
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); noteWidth(nm, w); markAssigned(nm);
                    fl.invalidateDependency(loc);
                    Stmt s; s.dst = nm; s.text = lhsFor(nm, w, dHigh8) + (m == "inc" ? "++;" : "--;"); s.reads.push_back(nm);
                    appendStatement(out, std::move(s)); killDep(e, loc); e.v.erase(loc);
                    // INC/DEC deliberately preserve CF; the other tracked flags
                    // come from the increment/decrement result.
                    fl.clear(kX86FlagZF | kX86FlagSF | kX86FlagOF | kX86FlagPF);
                    fl.write(kX86FlagZF | kX86FlagSF | kX86FlagOF,
                             m == "inc" ? CmpKind::IncResult : CmpKind::DecResult,
                             nm, "", { nm }, static_cast<uint16_t>(w * 8), { loc });
                } else { emitRaw("__asm { " + m + " " + in.operands + " };"); invalidateUnmodelled(); }
                continue;
            }
            if (m == "neg" || m == "not") {
                std::string loc; int w;
                if (dstLoc(da, loc, w)) { std::string cur = renderLoc(e, loc, reads, deps);
                    emitDef(loc, w, dHigh8, std::string(m == "neg" ? "-" : "~") + "(" + cur + ")", reads, deps);
                    if (m == "neg") { const std::string nm = nameOf(loc); fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::NegResult, nm, "", { nm }, static_cast<uint16_t>(w * 8), { loc }); }
                } else { emitRaw("__asm { " + m + " " + in.operands + " };"); invalidateUnmodelled(); }
                continue;
            }
            if (m == "imul" && threeImul) {
                std::string lhs = renderRValue(e, sb, reads, deps, ml);
                std::set<std::string> thirdReads, thirdDeps; bool thirdLoad = false;
                std::string rhs = renderRValue(e, third, thirdReads, thirdDeps, thirdLoad);
                reads.insert(thirdReads.begin(), thirdReads.end());
                deps.insert(thirdDeps.begin(), thirdDeps.end());
                std::string loc; int w;
                if (dstLoc(da, loc, w)) emitDef(loc, w, dHigh8, lhs + " * " + rhs, reads, deps);
                else { emitRaw("__asm { imul " + in.operands + " };"); invalidateUnmodelled(); }
                fl = {}; // IMUL does not define the relational Z/S flag provenance we model.
                continue;
            }
            if (m == "imul" && two) {
                std::string rhs = renderRValue(e, sb, reads, deps, ml);
                std::string loc; int w;
                if (dstLoc(da, loc, w)) { std::string cur = renderLoc(e, loc, reads, deps);
                    std::set<std::string> rd = reads; emitDef(loc, w, dHigh8, cur + " * " + rhs, rd, deps); }
                else { emitRaw("__asm { imul " + in.operands + " };"); invalidateUnmodelled(); }
                fl = {};
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
                    // Native division consumes the full high:low dividend. Keep
                    // signedness and source width explicit: Python's / and //
                    // model neither IDIV truncation nor the implicit high half.
                    const int bits = w <= 1 ? 8 : w <= 2 ? 16 : w <= 4 ? 32 : 64;
                    const std::string kind = m == "idiv" ? "s" : "u";
                    if (da.kind == OK::Reg && da.reg.canon >= 0) {
                        if (bits == 8)
                            opnd = std::string(da.reg.high8 ? "BYTE1(" : "LOBYTE(") + opnd + ")";
                        else if (bits == 16)
                            opnd = "LOWORD(" + opnd + ")";
                    }
                    bool sharedByteAccumulator = false;
                    std::string hiVal;
                    if (bits == 8) {
                        // DIV/IDIV r/m8 consumes AX and writes AL (quotient) and
                        // AH (remainder); RDX is not part of this form.
                        hiVal = "BYTE1(" + loVal + ")";
                        loVal = "LOBYTE(" + loVal + ")";
                        hiLoc = loLoc;
                        sharedByteAccumulator = true;
                    } else {
                        hiVal = renderLoc(e, hiLoc, reads, deps);
                        if (bits == 16) {
                            // The word form consumes DX:AX and writes the low
                            // words only, preserving both registers' upper bits.
                            hiVal = "LOWORD(" + hiVal + ")";
                            loVal = "LOWORD(" + loVal + ")";
                        }
                    }
                    char address[24];
                    std::snprintf(address, sizeof(address), "%llX",
                                  static_cast<unsigned long long>(in.address));
                    auto snapshotInput = [&](const char* suffix, const std::string& value) {
                        const std::string temporary = "local_div_" + std::string(suffix) + "_" + address;
                        noteWidth(temporary, bits / 8);
                        markAssigned(temporary);
                        Stmt snapshot;
                        snapshot.dst = temporary;
                        snapshot.text = temporary + " = " + value + ";";
                        snapshot.reads.assign(reads.begin(), reads.end());
                        appendStatement(out, std::move(snapshot));
                        return temporary;
                    };
                    // All three inputs are pre-state snapshots. Besides the
                    // high/low output alias, the divisor itself may be AL/AX/EAX/RAX.
                    const std::string highSnapshot = snapshotInput("hi", hiVal);
                    const std::string lowSnapshot = snapshotInput("lo", loVal);
                    const std::string sourceSnapshot = snapshotInput("src", opnd);
                    const std::string args = highSnapshot + ", " + lowSnapshot + ", " + sourceSnapshot;
                    std::set<std::string> rd = reads;
                    rd.insert(highSnapshot); rd.insert(lowSnapshot); rd.insert(sourceSnapshot);
                    emitDef(hiLoc, bits < 32 ? bits / 8 : dw, sharedByteAccumulator,
                            kind + "rem" + std::to_string(bits) + "(" + args + ")", rd, deps);
                    if (!out.empty()) out.back().side = true; // one indivisible native DIV/IDIV result pair
                    std::set<std::string> rd2 = reads;
                    rd2.insert(highSnapshot); rd2.insert(lowSnapshot); rd2.insert(sourceSnapshot);
                    emitDef(loLoc, bits < 32 ? bits / 8 : dw, false,
                            kind + "div" + std::to_string(bits) + "(" + args + ")", rd2, deps);
                    if (!out.empty()) out.back().side = true;
                }
                fl = {};
                continue;
            }
            if (m == "cmp") {
                std::string A = flagOperandValue(da, renderRValue(e, da, reads, deps, ml));
                std::set<std::string> rb; bool ml2 = false;
                std::string B = two ? flagOperandValue(sb, renderRValue(e, sb, rb, deps, ml2)) : "0";
                reads.insert(rb.begin(), rb.end());
                fl.clear();
                fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF,
                         CmpKind::Cmp, A, B,
                         std::vector<std::string>(reads.begin(), reads.end()),
                         operandWidthBits(da),
                         std::vector<std::string>(deps.begin(), deps.end()));
                continue;
            }
            if (m == "test") {
                std::string A = flagOperandValue(da, renderRValue(e, da, reads, deps, ml));
                if (two && sameOperand(da, sb)) { fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::TestZero, A, "", std::vector<std::string>(reads.begin(), reads.end()), operandWidthBits(da), std::vector<std::string>(deps.begin(), deps.end())); }
                else { std::set<std::string> rb; bool ml2 = false; std::string B = two ? flagOperandValue(sb, renderRValue(e, sb, rb, deps, ml2)) : "0";
                    reads.insert(rb.begin(), rb.end());
                    fl.clear(); fl.write(kX86FlagCF | kX86FlagZF | kX86FlagSF | kX86FlagOF, CmpKind::TestAnd, A, B, std::vector<std::string>(reads.begin(), reads.end()), operandWidthBits(da), std::vector<std::string>(deps.begin(), deps.end())); }
                continue;
            }
            if (m == "call") {
                // Recover the call's arguments BEFORE clobbering the volatile arg
                // registers below (rcx/rdx/r8/r9 hold the Win64 integer args here).
                std::string args = renderCallArgs(e, reads);
                std::string callee;
                if (HasBranchTarget(in)) { std::string nm = nameFor ? nameFor(in.branchTarget) : std::string();
                    if (nm.empty()) { char c[24]; std::snprintf(c, sizeof(c), "sub_%llX", (unsigned long long)in.branchTarget); nm = c; }
                    callee = nm; }
                else {
                    // Indirect call: resolve `call [iat]` to the import name when known.
                    uint64_t address = 0;
                    std::string tok = constantAddress(da, address) ? dref(address) : std::string();
                    if (!tok.empty() && tok.front() != '"') callee = tok;
                    else { std::set<std::string> rd; bool ml2 = false; callee = "(*" + renderRValue(e, da, rd, deps, ml2) + ")"; reads.insert(rd.begin(), rd.end()); }
                }
                std::string callExpr = callee + "(" + args + ")";
                // A call returns in eax for x86 and rax for x64. This width feeds
                // declaration inference even when the result cannot be folded.
                const int returnBytes = is32_ ? 4 : 8;
                std::string raxNm = nameOf(regLoc(RAX)); markAssigned(raxNm); noteWidth(raxNm, returnBytes);
                Stmt s; s.side = true; s.dst = raxNm; s.callRhs = callExpr; s.text = raxNm + " = " + callExpr + ";";
                s.reads.assign(reads.begin(), reads.end());
                appendStatement(out, std::move(s));
                const int winVol[] = { RAX, RCX, RDX, 8, 9, 10, 11 };
                const int sysvVol[] = { RAX, RCX, RDX, RSI, RDI, 8, 9, 10, 11 };
                if (targetABI_ == DecompileABI::Unknown) {
                    for (int reg = 0; reg < 16; ++reg) { e.v.erase(regLoc(reg)); killDep(e, regLoc(reg)); }
                } else {
                    const int* vol = targetABI_ == DecompileABI::SysV64 ? sysvVol : winVol;
                    const size_t volCount = targetABI_ == DecompileABI::SysV64
                        ? sizeof(sysvVol) / sizeof(sysvVol[0]) : sizeof(winVol) / sizeof(winVol[0]);
                    for (size_t vr = 0; vr < volCount; ++vr) {
                        const int reg = vol[vr]; e.v.erase(regLoc(reg)); killDep(e, regLoc(reg));
                    }
                }
                killMemory(e); killStackSlots(e);   // callee may write through a passed &local
                pendingPush_.clear();               // consumed: the next call starts a fresh group
                fl = {};                            // calls clobber x86 condition flags
                continue;
            }
            if (m.size() > 3 && m.rfind("set", 0) == 0) {        // setcc (8-bit dst)
                std::string loc; int w;
                const std::vector<std::string> flagReads = fl.allReads();
                reads.insert(flagReads.begin(), flagReads.end());
                if (dstLoc(da, loc, w)) emitDef(loc, 1, dHigh8, "(" + RenderX86Condition("j" + m.substr(3), fl, false) + ")", reads, deps);
                else { emitRaw("__asm { " + m + " " + in.operands + " };"); invalidateUnmodelled(); }
                continue;
            }
            if (m.size() > 4 && two && m.rfind("cmov", 0) == 0) { // cmovcc
                std::string rhs = renderRValue(e, sb, reads, deps, ml);
                const std::vector<std::string> flagReads = fl.allReads();
                reads.insert(flagReads.begin(), flagReads.end());
                std::string loc; int w;
                if (dstLoc(da, loc, w)) {
                    std::string nm = nameOf(loc); markAssigned(nm); noteWidth(nm, w);
                    const std::string condition = RenderX86Condition("j" + m.substr(4), fl, false);
                    Stmt s; s.dst = nm; s.text = "if (" + condition + ") " + nm + " = " + rhs + ";";
                    s.reads.assign(reads.begin(), reads.end());
                    appendStatement(out, std::move(s)); fl.invalidateDependency(loc); killDep(e, loc); e.v.erase(loc);
                } else { emitRaw("__asm { " + m + " " + in.operands + " };"); invalidateUnmodelled(); }
                continue;
            }
            // Anything unmodeled: keep as an inline-asm comment so nothing is lost.
            emitRaw(in.operands.empty() ? ("__asm { " + m + " };") : ("__asm { " + m + " " + in.operands + " };"));
            invalidateUnmodelled();
        }
        termFlag_[bi] = fl;
        // For a return block, remember rax's propagated value (the return value). Reset
        // first so a prior (dry-run) lift with a different entry env can't leave a stale
        // inline value when the final lift no longer has one.
        if (g.blocks[bi].isReturn) {
            retHasInline_[bi] = false; retInline_[bi].clear(); retInlineReads_[bi].clear();
            retInlineWidth_[bi] = 0;
            auto it = e.v.find(regLoc(RAX));
            if (it != e.v.end()) {
                retHasInline_[bi] = true;
                retInline_[bi] = it->second.expr;
                retInlineReads_[bi] = it->second.reads;
                retInlineWidth_[bi] = it->second.widthBits;
            }
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
                if (it == outEnv[preds[p]].v.end() || it->second.expr != kv.second.expr ||
                    it->second.widthBits != kv.second.widthBits) { all = false; break; }
            }
            if (all) e.v[kv.first] = kv.second;
        }
        return e;
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
            // A terminator consumes the cmp/test operands even though the flag-
            // setting instruction itself emits no statement. Seed those reads so
            // DCE cannot delete the reaching definitions that make the condition.
            for (const std::string& r : termFlag_[i].allReads())
                if (!defined.count(r)) gen[i].insert(r);
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
            const std::vector<std::string> flagReads = termFlag_[i].allReads();
            live.insert(flagReads.begin(), flagReads.end());
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
        retInlineWidth_.assign(N, 0);
        retExpr_.assign(N, {}); retReads_.assign(N, {});
        r.retComment.assign(N, {});
        is32_ = exactArch_ ? targetArch_ == Arch::X86 : looksLike32();
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
                        if (it == inEnv[i].v.end() || it->second.expr != kv.second.expr ||
                            it->second.widthBits != kv.second.widthBits) { diff = true; break; } }
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
                const uint16_t returnWidth = retHasInline_[i] && retInlineWidth_[i]
                    ? retInlineWidth_[i] : static_cast<uint16_t>(is32_ ? 32 : 64);
                if (BitPattern cv; tryFoldConst(retExpr_[i], returnWidth, cv))
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
            for (Stmt& s : blockStmts_[i])
                r.blockStmts[i].push_back({std::move(s.text), s.sourceVA, s.sourceValid});
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

DataFlowResult AnalyzeDataFlow(const ControlFlowGraph& g,
                               const std::function<std::string(uint64_t)>& nameFor,
                               const std::function<std::string(uint64_t)>& dataRefFor,
                               bool recoverCallArgs,
                               Arch targetArch,
                               DecompileABI targetABI) {
    if (g.blocks.empty() || (targetArch != Arch::X86 && targetArch != Arch::X64)) return {};
    if (targetArch == Arch::X86 && targetABI != DecompileABI::Auto && targetABI != DecompileABI::Unknown &&
        targetABI != DecompileABI::X86Cdecl && targetABI != DecompileABI::X86Stdcall) return {};
    if (targetArch == Arch::X64 && targetABI != DecompileABI::Auto && targetABI != DecompileABI::Unknown &&
        targetABI != DecompileABI::Win64 && targetABI != DecompileABI::SysV64) return {};
    Analyzer a(g, nameFor, dataRefFor, recoverCallArgs, targetArch, targetABI);
    return a.run();
}

} // namespace ds
