#include "BinaryViewTab.h"
#include "../Core/FunctionAnalyzer.h"
#include "../Core/FunctionNamer.h"
#include "../Core/CFG.h"
#include "../Core/Cond.h"
#include "../Core/Decompiler.h"
#include "../Core/AnalysisService.h"
#include "../Core/Report.h"
#include "../Core/ProcessManager.h"
#include "../Core/SynthesisJob.h"   // F1 synthesize a region
#include "../Core/PatchCompiler.h"  // F2 compile editor source -> bytes
#include "../Core/PatchPlacer.h"    // F2 cave-finder + detour placement
#include "../Disasm/Assembler.h"
#include "DataRef.h"
#include "../Ui/Fonts.h"
#include "../Ui/Theme.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <unordered_set>

namespace ds {

static bool hasBreakpoint(const std::unordered_set<uint64_t>& bps, uint64_t a) {
    return bps.count(a) != 0;
}

static bool hasBreakpoint(const DbgSnapshot& snap, uint64_t a) {
    return std::find_if(snap.breakpoints.begin(), snap.breakpoints.end(),
                        [a](const SwBreakpointInfo& bp) { return bp.address == a; }) != snap.breakpoints.end();
}

// Turn a space-separated hex byte string ("48 89 5C") into a C initializer
// ("{ 0x48, 0x89, 0x5C }") for pasting shellcode / patch bytes into source.
static std::string bytesToCArray(const std::string& hexBytes) {
    std::string out;
    for (size_t i = 0; i < hexBytes.size();) {
        if (hexBytes[i] == ' ') { ++i; continue; }
        if (i + 1 >= hexBytes.size()) break;
        if (!out.empty()) out += ", ";
        out += "0x"; out += hexBytes[i]; out += hexBytes[i + 1];
        i += 2;
    }
    return "{ " + out + " }";
}

// Pull a code window for the cursor: returns pointer + size into the image.
// If vaStart is 0, it is initialized to the first code section / entry point.
static const uint8_t* codeWindow(AppContext& ctx, uint64_t& vaStart, size_t& size) {
    if (!ctx.binary.loaded()) return nullptr;
    if (vaStart == 0) {
        if (const Section* s = ctx.binary.firstCodeSection())
            vaStart = ctx.binary.imageBase() + s->virtualAddress;
        else
            vaStart = ctx.binary.imageBase() + ctx.binary.entryPoint();
    }
    size_t avail = 0;
    const uint8_t* p = ctx.binary.ptrFromVA(vaStart, avail);
    size = std::min<size_t>(avail, 4096);
    return p;
}

// ---------- Live disassembly helpers ----------

// Register name (incl. 32/16/8-bit aliases) -> the full 64-bit field it lives in.
struct RegAlias { const char* name; uint64_t Registers::* field; };
static const RegAlias kRegAliases[] = {
    {"rax",&Registers::rax},{"eax",&Registers::rax},{"ax",&Registers::rax},{"al",&Registers::rax},{"ah",&Registers::rax},
    {"rbx",&Registers::rbx},{"ebx",&Registers::rbx},{"bx",&Registers::rbx},{"bl",&Registers::rbx},{"bh",&Registers::rbx},
    {"rcx",&Registers::rcx},{"ecx",&Registers::rcx},{"cx",&Registers::rcx},{"cl",&Registers::rcx},{"ch",&Registers::rcx},
    {"rdx",&Registers::rdx},{"edx",&Registers::rdx},{"dx",&Registers::rdx},{"dl",&Registers::rdx},{"dh",&Registers::rdx},
    {"rsi",&Registers::rsi},{"esi",&Registers::rsi},{"si",&Registers::rsi},{"sil",&Registers::rsi},
    {"rdi",&Registers::rdi},{"edi",&Registers::rdi},{"di",&Registers::rdi},{"dil",&Registers::rdi},
    {"rbp",&Registers::rbp},{"ebp",&Registers::rbp},{"bp",&Registers::rbp},{"bpl",&Registers::rbp},
    {"rsp",&Registers::rsp},{"esp",&Registers::rsp},{"sp",&Registers::rsp},{"spl",&Registers::rsp},
    {"r8", &Registers::r8 },{"r8d",&Registers::r8 },{"r8w",&Registers::r8 },{"r8b",&Registers::r8 },
    {"r9", &Registers::r9 },{"r9d",&Registers::r9 },{"r9w",&Registers::r9 },{"r9b",&Registers::r9 },
    {"r10",&Registers::r10},{"r10d",&Registers::r10},{"r10w",&Registers::r10},{"r10b",&Registers::r10},
    {"r11",&Registers::r11},{"r11d",&Registers::r11},{"r11w",&Registers::r11},{"r11b",&Registers::r11},
    {"r12",&Registers::r12},{"r12d",&Registers::r12},{"r12w",&Registers::r12},{"r12b",&Registers::r12},
    {"r13",&Registers::r13},{"r13d",&Registers::r13},{"r13w",&Registers::r13},{"r13b",&Registers::r13},
    {"r14",&Registers::r14},{"r14d",&Registers::r14},{"r14w",&Registers::r14},{"r14b",&Registers::r14},
    {"r15",&Registers::r15},{"r15d",&Registers::r15},{"r15w",&Registers::r15},{"r15b",&Registers::r15},
    {"rip",&Registers::rip},{"eip",&Registers::rip},
};

static bool lookupReg(const Registers& r, const std::string& lname, uint64_t& v) {
    for (const auto& a : kRegAliases)
        if (lname == a.name) { v = r.*a.field; return true; }
    return false;
}

static std::string resolveString(const uint8_t* buf, size_t n);   // defined below; used by regHints

// Build "rax=0x.. rbx=0x.." for every register referenced by the operand text,
// in first-seen order. Used to annotate the instruction sitting at RIP. When `dbg`
// is given (paused), a register that points to a string also shows it inline, so the
// value a register carries is readable right on the current instruction.
static std::string regHints(const Instruction& in, const Registers& r, Debugger* dbg = nullptr) {
    std::string out;
    std::vector<std::string> seen;
    const std::string& s = in.operands;
    for (size_t i = 0; i < s.size();) {
        if (!std::isalpha((unsigned char)s[i])) { ++i; continue; }
        size_t j = i + 1;
        while (j < s.size() && std::isalnum((unsigned char)s[j])) ++j;
        std::string tok = s.substr(i, j - i);
        for (char& ch : tok) ch = (char)std::tolower((unsigned char)ch);
        uint64_t v = 0;
        if (lookupReg(r, tok, v) && std::find(seen.begin(), seen.end(), tok) == seen.end()) {
            seen.push_back(tok);
            char b[48];
            std::snprintf(b, sizeof(b), "%s%s=0x%llX", out.empty() ? "" : "  ",
                          tok.c_str(), (unsigned long long)v);
            out += b;
            if (dbg && v >= 0x1000) {   // does this register point to a string?
                uint8_t tmp[64]; size_t g = dbg->readMemory(v, tmp, sizeof(tmp));
                std::string str = resolveString(tmp, g);
                if (!str.empty()) { out += " \""; out += str.substr(0, 24); out += "\""; }
            }
        }
        i = j;
    }
    return out;
}

// Evaluate a conditional branch against the live flags so the paused RIP row can say
// whether it will branch or fall through. x86/x64 only (the Win32 debugger never
// targets other arches). Returns: -1 = not a recognized conditional branch;
// 0 = condition false (falls through); 1 = condition true (will jump).
static int evalCondBranch(const std::string& mnem, uint64_t rflags, const Registers& r, bool is32) {
    const bool CF = (rflags >> 0)  & 1ull, PF = (rflags >> 2)  & 1ull;
    const bool ZF = (rflags >> 6)  & 1ull, SF = (rflags >> 7)  & 1ull;
    const bool OF = (rflags >> 11) & 1ull;
    auto B = [](bool b) { return b ? 1 : 0; };
    std::string m = mnem;                                  // normalize case (engine-agnostic)
    for (char& c : m) c = (char)std::tolower((unsigned char)c);
    if (m == "jo")                          return B(OF);
    if (m == "jno")                         return B(!OF);
    if (m == "js")                          return B(SF);
    if (m == "jns")                         return B(!SF);
    if (m == "je"  || m == "jz")            return B(ZF);
    if (m == "jne" || m == "jnz")           return B(!ZF);
    if (m == "jb"  || m == "jc"  || m == "jnae") return B(CF);
    if (m == "jae" || m == "jnc" || m == "jnb")  return B(!CF);
    if (m == "jbe" || m == "jna")           return B(CF || ZF);
    if (m == "ja"  || m == "jnbe")          return B(!CF && !ZF);
    if (m == "jl"  || m == "jnge")          return B(SF != OF);
    if (m == "jge" || m == "jnl")           return B(SF == OF);
    if (m == "jle" || m == "jng")           return B(ZF || (SF != OF));
    if (m == "jg"  || m == "jnle")          return B(!ZF && (SF == OF));
    if (m == "jp"  || m == "jpe")           return B(PF);
    if (m == "jnp" || m == "jpo")           return B(!PF);
    if (m == "jcxz")                        return B((r.rcx & 0xFFFFull) == 0);
    if (m == "jecxz")                       return B((r.rcx & 0xFFFFFFFFull) == 0);
    if (m == "jrcxz")                       return B((is32 ? (r.rcx & 0xFFFFFFFFull) : r.rcx) == 0);
    return -1;
}

// Begin the listing a few instructions BEFORE rip so the current line isn't
// pinned to the very top. x86 is variable-length, so we align by trial: decode
// forward from rip-lookback and accept the earliest start whose stream lands
// exactly on rip (that yields the most leading context).
// True instruction boundaries self-synchronize on x86, but a trial start that
// merely happens to land on `target` can begin mid-instruction and render a few
// garbage "context" rows above it. So prefer a KNOWN boundary first: when an
// analyzed function start `anchor` sits within the lookback window and decoding
// from it lands exactly on target, it is a guaranteed-correct start. Only if no
// such anchor exists do we fall back to the earliest trial offset.
static bool decodeReaches(IDisassembler& dis, const uint8_t* p, size_t avail,
                          uint64_t from, uint64_t target) {
    uint64_t a = from; size_t idx = 0;
    for (int guard = 0; a < target && idx < avail && guard < 256; ++guard) {
        Instruction one;
        if (!dis.decodeOne(p + idx, avail - idx, a, one) || one.length == 0) return false;
        a += one.length; idx += one.length;
    }
    return a == target;
}

static uint64_t alignWindowStart(Debugger& dbg, IDisassembler& dis, uint64_t rip, int lookback,
                                 uint64_t anchor = 0) {
    if (lookback <= 0 || rip <= (uint64_t)lookback) return rip;
    uint64_t base = rip - (uint64_t)lookback;
    std::vector<uint8_t> pre((size_t)lookback + 16);
    size_t got = dbg.readMemoryMasked(base, pre.data(), pre.size());   // mask our 0xCC bps so alignment decodes real insns
    if (got < (size_t)lookback) return rip;
    // Anchor to a known function-start boundary inside the window when it cleanly
    // reaches rip (no garbage leading rows).
    if (anchor && anchor <= rip && rip - anchor <= (uint64_t)lookback) {
        size_t off = (size_t)(anchor - base);
        if (off < got && decodeReaches(dis, pre.data() + off, got - off, anchor, rip)) return anchor;
    }
    for (int off = 0; off < lookback; ++off) {
        uint64_t a = base + (uint64_t)off;
        size_t   idx = (size_t)off;
        for (int guard = 0; a < rip && idx < got && guard < 256; ++guard) {
            Instruction one;
            if (!dis.decodeOne(pre.data() + idx, got - idx, a, one) || one.length == 0) break;
            a += one.length; idx += one.length;
        }
        if (a == rip) return base + (uint64_t)off;   // earliest aligned = most context
    }
    return rip;
}

// Same trial-alignment as alignWindowStart but reading from a loaded BinaryFile,
// so the static Assembly view can show context above a navigated address.
static uint64_t alignBinaryStart(BinaryFile& bin, IDisassembler& dis, uint64_t target, int lookback,
                                 uint64_t anchor = 0) {
    if (lookback <= 0 || target <= (uint64_t)lookback) return target;
    uint64_t base = target - (uint64_t)lookback;
    size_t avail = 0;
    const uint8_t* p = bin.ptrFromVA(base, avail);
    if (!p || avail < (size_t)lookback) return target;
    if (anchor && anchor <= target && target - anchor <= (uint64_t)lookback) {
        size_t off = (size_t)(anchor - base);
        if (off < avail && decodeReaches(dis, p + off, avail - off, anchor, target)) return anchor;
    }
    for (int off = 0; off < lookback; ++off) {
        uint64_t a = base + (uint64_t)off; size_t idx = (size_t)off;
        for (int guard = 0; a < target && idx < avail && guard < 256; ++guard) {
            Instruction one;
            if (!dis.decodeOne(p + idx, avail - idx, a, one) || one.length == 0) break;
            a += one.length; idx += one.length;
        }
        if (a == target) return base + (uint64_t)off;
    }
    return target;
}

// ---------- Naive pseudocode generation (live view) ----------

// Turn an operand's [mem] into *(mem) so the output reads like C.
static std::string cOperand(const std::string& s) {
    std::string o;
    for (char c : s) { if (c == '[') o += "*("; else if (c == ']') o += ')'; else o += c; }
    return o;
}

// Split "a, b" at the first top-level comma (ignoring commas inside [] or ()).
static bool split2(const std::string& ops, std::string& a, std::string& b) {
    int depth = 0;
    for (size_t i = 0; i < ops.size(); ++i) {
        char c = ops[i];
        if (c == '[' || c == '(') ++depth;
        else if (c == ']' || c == ')') --depth;
        else if (c == ',' && depth == 0) {
            auto trim = [](std::string x) {
                size_t s = x.find_first_not_of(" \t"); size_t e = x.find_last_not_of(" \t");
                return s == std::string::npos ? std::string() : x.substr(s, e - s + 1);
            };
            a = trim(ops.substr(0, i)); b = trim(ops.substr(i + 1));
            return true;
        }
    }
    return false;
}

// Translate one instruction to a pseudo-C line. cmpA/cmpB carry the previous
// compare's operands so a following Jcc renders a real condition. Returns "" for
// instructions that produce no statement (nop, the cmp/test that only set flags).
static std::string pseudoLine(const Instruction& in, std::string& cmpA, std::string& cmpB) {
    const std::string& m = in.mnemonic;
    std::string a, b;
    bool two = split2(in.operands, a, b);
    std::string A = cOperand(a), B = cOperand(b);
    char tbuf[32];
    auto target = [&]() -> std::string {
        if (in.branchTarget) { std::snprintf(tbuf, sizeof(tbuf), "loc_%llX", (unsigned long long)in.branchTarget); return tbuf; }
        return cOperand(in.operands);
    };
    auto cond = [&](const char* op) -> std::string {
        std::string lhs = cmpA.empty() ? "flags" : cmpA;
        std::string rhs = cmpB.empty() ? "0" : cmpB;
        char buf[320];
        std::snprintf(buf, sizeof(buf), "if (%s %s %s) goto %s;", lhs.c_str(), op, rhs.c_str(), target().c_str());
        return buf;
    };

    if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs" || m == "movdqu" || m == "movaps")
        return two ? A + " = " + B + ";" : (m + " " + in.operands + ";");
    if (m == "lea") {
        std::string rhs = cOperand(b);
        if (rhs.size() > 3 && rhs.rfind("*(", 0) == 0 && rhs.back() == ')') rhs = rhs.substr(2, rhs.size() - 3);
        return A + " = " + rhs + ";";
    }
    if (m == "add")  return A + " += " + B + ";";
    if (m == "sub")  return A + " -= " + B + ";";
    if (m == "and")  return A + " &= " + B + ";";
    if (m == "or")   return A + " |= " + B + ";";
    if (m == "xor")  return (two && a == b) ? (A + " = 0;") : (A + " ^= " + B + ";");
    if (m == "shl" || m == "sal") return A + " <<= " + B + ";";
    if (m == "shr" || m == "sar") return A + " >>= " + B + ";";
    if (m == "imul" && two)       return A + " *= " + B + ";";
    if (m == "inc")  return A + "++;";
    if (m == "dec")  return A + "--;";
    if (m == "neg")  return A + " = -" + A + ";";
    if (m == "not")  return A + " = ~" + A + ";";
    if (m == "push") return "push(" + cOperand(in.operands) + ");";
    if (m == "pop")  return cOperand(in.operands) + " = pop();";
    if (m == "call") {
        if (in.branchTarget) { char c[40]; std::snprintf(c, sizeof(c), "sub_%llX();", (unsigned long long)in.branchTarget); return c; }
        return "(*" + cOperand(in.operands) + ")();";
    }
    if (m == "ret" || m == "retn" || m == "retf") return "return;";
    if (m == "leave") return std::string();
    if (m == "nop" || m == "endbr64" || m == "endbr32") return std::string();
    if (m == "cmp")  { cmpA = A; cmpB = B; return std::string(); }
    if (m == "test") { if (two && a == b) { cmpA = A; cmpB = "0"; } else { cmpA = A; cmpB = B; } return std::string(); }
    if (m == "jmp")  return "goto " + target() + ";";
    if (m == "je"  || m == "jz")               return cond("==");
    if (m == "jne" || m == "jnz")              return cond("!=");
    if (m == "jg"  || m == "jnle" || m == "ja"  || m == "jnbe") return cond(">");
    if (m == "jge" || m == "jnl"  || m == "jae" || m == "jnb" || m == "jnc") return cond(">=");
    if (m == "jl"  || m == "jnge" || m == "jb"  || m == "jc" || m == "jnae") return cond("<");
    if (m == "jle" || m == "jng"  || m == "jbe" || m == "jna")  return cond("<=");
    if (m == "js")  return "if (sign) goto " + target() + ";";
    if (m == "jns") return "if (!sign) goto " + target() + ";";
    // Anything else: keep the raw instruction as an inline-asm comment.
    return "/* " + m + " " + in.operands + " */";
}

// Build a pseudo-C function body from a decoded run starting at `start`.
static std::string buildPseudo(const std::vector<Instruction>& insns, uint64_t start) {
    if (insns.empty()) return "// nothing decoded at this address";
    // Estimate the function end: stop just after a ret once we've passed every
    // forward branch target seen so far (so we don't cut a function mid-way).
    uint64_t maxFwd = start;
    size_t end = insns.size();
    for (size_t i = 0; i < insns.size(); ++i) {
        const auto& in = insns[i];
        if (in.isBranch && !in.isCall && in.branchTarget > in.address)
            maxFwd = std::max(maxFwd, in.branchTarget);
        if (in.isRet && in.address >= maxFwd) { end = i + 1; break; }
        if (i >= 1200) { end = i + 1; break; }
    }
    uint64_t endAddr = insns[end - 1].address + insns[end - 1].length;
    std::unordered_map<uint64_t, bool> labels;
    for (size_t i = 0; i < end; ++i) {
        const auto& in = insns[i];
        if (in.isBranch && in.branchTarget >= start && in.branchTarget < endAddr)
            labels[in.branchTarget] = true;
    }
    std::string out;
    char hdr[64];
    std::snprintf(hdr, sizeof(hdr), "sub_%llX()\n{\n", (unsigned long long)start);
    out += hdr;
    std::string cmpA, cmpB;
    for (size_t i = 0; i < end; ++i) {
        const auto& in = insns[i];
        if (labels.count(in.address)) {
            char lbl[40]; std::snprintf(lbl, sizeof(lbl), "\nloc_%llX:\n", (unsigned long long)in.address);
            out += lbl;
        }
        std::string line = pseudoLine(in, cmpA, cmpB);
        if (!line.empty()) { out += "    "; out += line; out += '\n'; }
    }
    out += "}\n";
    return out;
}

// Scan the debuggee's committed, readable memory for a pattern. kind:
// 0=ASCII 1=UTF-16LE 2=hex bytes 3=u64 value. Capped for responsiveness.
static std::vector<uint64_t> liveMemorySearch(Debugger& dbg, const char* query, int kind, std::string& status) {
    std::vector<uint64_t> hits;
    std::vector<uint8_t> pat;
    std::string q = query ? query : "";
    if (kind == 0) { for (char c : q) pat.push_back((uint8_t)c); }
    else if (kind == 1) { for (char c : q) { pat.push_back((uint8_t)c); pat.push_back(0); } }
    else if (kind == 2) {
        for (size_t i = 0; i < q.size();) {
            if (std::isspace((unsigned char)q[i])) { ++i; continue; }
            // Require a full two-hex-digit byte; a lone trailing nibble ("4") is malformed, not 0x04.
            if (i + 1 >= q.size() || !std::isxdigit((unsigned char)q[i]) || !std::isxdigit((unsigned char)q[i + 1])) break;
            char b[3] = { q[i], q[i + 1], 0 }; unsigned v = 0;
            std::sscanf(b, "%x", &v); pat.push_back((uint8_t)v); i += 2;
        }
    } else {
        unsigned long long v = 0;
        if (std::sscanf(q.c_str(), "0x%llx", &v) == 1 || std::sscanf(q.c_str(), "%llx", &v) == 1)
            for (int k = 0; k < 8; ++k) pat.push_back((uint8_t)(v >> (k * 8)));
    }
    if (pat.empty()) { status = "Enter something to search for."; return hits; }

    const size_t kCapBytes = 256u * 1024u * 1024u, kCapHits = 2000;
    size_t scanned = 0;
    std::vector<uint8_t> buf;
    for (const auto& rg : dbg.regions()) {
        if (!rg.read || rg.state != 0x1000 /*MEM_COMMIT*/ || rg.size == 0) continue;
        size_t sz = (size_t)rg.size;
        if (scanned + sz > kCapBytes) sz = kCapBytes - scanned;
        buf.resize(sz);
        size_t got = dbg.readMemory(rg.base, buf.data(), sz);
        for (size_t i = 0; got >= pat.size() && i + pat.size() <= got; ++i) {
            if (buf[i] != pat[0]) continue;
            bool hit = true;
            for (size_t j = 1; j < pat.size(); ++j) if (buf[i + j] != pat[j]) { hit = false; break; }
            if (hit) { hits.push_back(rg.base + i); if (hits.size() >= kCapHits) { status = "stopped at 2000 hits"; return hits; } }
        }
        scanned += sz;
        if (scanned >= kCapBytes) { status = "stopped at 256 MB scanned"; break; }
    }
    if (status.empty() || hits.size()) { char s[48]; std::snprintf(s, sizeof(s), "%zu hit(s)", hits.size()); status = s; }
    return hits;
}

// ---------- String comments + cross-references ----------

// The data address an instruction references (RIP-relative or an absolute memory
// immediate), used for inline string comments and xref matching. 0 = none.
// Definition lives in DataRef.h so it can be unit-tested in isolation.

// If `buf` begins with a printable ASCII or UTF-16LE run (>= 3 chars), return it.
static std::string resolveString(const uint8_t* buf, size_t n) {
    size_t a = 0;
    while (a < n && buf[a] >= 32 && buf[a] < 127) ++a;
    if (a >= 3 && (a == n || buf[a] == 0)) return std::string((const char*)buf, a);
    size_t u = 0;
    while (u * 2 + 1 < n && buf[u * 2] >= 32 && buf[u * 2] < 127 && buf[u * 2 + 1] == 0) ++u;
    if (u >= 3) { std::string s; s.reserve(u); for (size_t k = 0; k < u; ++k) s += (char)buf[k * 2]; return s; }
    return std::string();
}

// A slow 0..1 pulse (~2s period) for flashing the focused line.
// A concise plain-language / C-ish gloss of what one instruction does, shown
// inline in the listing (same place as string comments). Returns "" when the
// mnemonic is self-explanatory or unmodelled (so the line stays uncluttered).
static std::string instrGloss(const Instruction& in) {
    const std::string& m = in.mnemonic;
    std::string a, b;
    bool two = split2(in.operands, a, b);
    // split2 only fills a/b when there's a comma; for a single operand use it all.
    std::string A = two ? cOperand(a) : cOperand(in.operands);
    std::string B = two ? cOperand(b) : std::string();

    if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs") return two ? A + " = " + B : std::string();
    if (m == "lea") { std::string r = cOperand(b); if (r.size() > 3 && r.rfind("*(", 0) == 0 && r.back() == ')') r = r.substr(2, r.size() - 3); return A + " = &" + r; }
    if (m == "xchg" && two) return "swap " + A + ", " + B;
    if (m == "add")  return (a == "rsp" || a == "esp") ? "free " + b + " of stack" : A + " += " + B;
    if (m == "sub")  return (a == "rsp" || a == "esp") ? "alloc " + b + " of stack" : A + " -= " + B;
    if (m == "and")  return A + " &= " + B;
    if (m == "or")   return A + " |= " + B;
    if (m == "xor")  return (two && a == b) ? A + " = 0" : A + " ^= " + B;
    if (m == "shl" || m == "sal") return A + " <<= " + B;
    if (m == "shr" || m == "sar") return A + " >>= " + B;
    if (m == "imul" && two) return A + " *= " + B;
    if (m == "inc")  return A + "++";
    if (m == "dec")  return A + "--";
    if (m == "neg")  return A + " = -" + A;
    if (m == "not")  return A + " = ~" + A;
    if (m == "cmp")  return "compare " + A + ", " + B;
    if (m == "test") return (two && a == b) ? "is " + A + " zero?" : "test " + A + " & " + B;
    if (m == "push") return "push " + cOperand(in.operands);
    if (m == "pop")  return cOperand(in.operands) + " = pop()";
    if (m == "ret" || m == "retn" || m == "retf") return "return";
    if (m == "leave") return "tear down stack frame";
    struct JC { const char* mn; const char* desc; };
    static const JC jcs[] = {
        {"je","if =="},{"jz","if zero"},{"jne","if !="},{"jnz","if not zero"},
        {"jg","if > (signed)"},{"jnle","if > (signed)"},{"jge","if >= (signed)"},{"jnl","if >= (signed)"},
        {"jl","if < (signed)"},{"jnge","if < (signed)"},{"jle","if <= (signed)"},{"jng","if <= (signed)"},
        {"ja","if > (unsigned)"},{"jnbe","if > (unsigned)"},{"jae","if >= (unsigned)"},{"jnb","if >= (unsigned)"},
        {"jb","if < (unsigned)"},{"jnae","if < (unsigned)"},{"jbe","if <= (unsigned)"},{"jna","if <= (unsigned)"},
        {"js","if negative"},{"jns","if not negative"},{"jo","if overflow"},{"jno","if no overflow"},
        {"jc","if carry"},{"jnc","if no carry"},{"jp","if parity"},{"jnp","if no parity"},
        {"jcxz","if cx == 0"},{"jecxz","if ecx == 0"},{"jrcxz","if rcx == 0"},{"loop","decrement rcx, loop while != 0"},
    };
    for (const auto& j : jcs) if (m == j.mn) return std::string(j.desc) + " -> jump";
    if (m.rfind("rep", 0) == 0 || m == "movs" || m == "movsb" || m == "movsd" || m == "movsq" ||
        m == "stos" || m == "stosb" || m == "stosd" || m == "lods" || m == "scas" || m == "cmps")
        return "string/block operation";
    if (m == "syscall" || m == "sysenter") return "kernel system call";
    return std::string();   // call / jmp handled by the target name; nop/etc. omitted
}

// One-line purpose for common imported APIs (matched on the function name with
// any A/W/Ex suffix or Nt/Zw prefix ignored). "" when unknown.
static std::string apiPurpose(const std::string& dllDotFunc) {
    std::string fn = dllDotFunc;
    size_t dot = fn.find('.');
    if (dot != std::string::npos) fn = fn.substr(dot + 1);
    for (char& c : fn) c = (char)std::tolower((unsigned char)c);
    auto has = [&](const char* k) { return fn.find(k) != std::string::npos; };
    if (has("createfile"))        return "open / create a file or device";
    if (has("readfile"))          return "read from a file/handle";
    if (has("writefile"))         return "write to a file/handle";
    if (has("createprocess") || has("winexec") || has("shellexecute")) return "spawn a process";
    if (has("virtualalloc"))      return "allocate memory (often RWX)";
    if (has("virtualprotect"))    return "change memory protection";
    if (has("writeprocessmemory"))return "write another process's memory";
    if (has("readprocessmemory")) return "read another process's memory";
    if (has("createremotethread") || has("ntcreatethreadex")) return "start a thread in another process";
    if (has("queueuserapc"))      return "queue an APC (injection)";
    if (has("loadlibrary"))       return "load a DLL at runtime";
    if (has("getprocaddress"))    return "resolve an export by name";
    if (has("getmodulehandle"))   return "get a loaded module base";
    if (has("isdebuggerpresent") || has("checkremotedebugger")) return "anti-debug check";
    if (has("ntqueryinformationprocess")) return "query process info (often anti-debug)";
    if (has("setwindowshookex"))  return "install a hook (injection)";
    if (has("regsetvalue") || has("regcreatekey")) return "write the registry (persistence?)";
    if (has("regopenkey") || has("regqueryvalue")) return "read the registry";
    if (has("createservice"))     return "install a service (persistence)";
    if (has("wsastartup") || has("socket") || has("connect") || has("send") || has("recv")) return "network socket I/O";
    if (has("internetopen") || has("internetconnect") || has("httpsendrequest") || has("winhttp") || has("urldownload")) return "HTTP / internet I/O";
    if (has("crypt") || has("bcrypt"))   return "cryptography";
    if (has("messagebox"))        return "show a message box";
    if (has("exitprocess") || has("terminateprocess")) return "terminate the process";
    if (has("getprocessheap") || has("heapalloc")) return "heap allocation";
    if (has("sleep"))             return "delay execution";
    if (has("getticktount") || has("gettickcount") || has("queryperformancecounter")) return "read a timer (timing/anti-debug)";
    if (has("createmutex"))       return "create a mutex (single-instance?)";
    return std::string();
}

static float slowPulse() { return 0.5f + 0.5f * std::sin((float)ImGui::GetTime() * 3.0f); }

// Short module name for symbols ("C:\\...\\kernel32.dll" -> "kernel32").
static std::string modShortName(const std::string& name) {
    size_t s = name.find_last_of("/\\");
    std::string b = (s == std::string::npos) ? name : name.substr(s + 1);
    size_t d = b.find_last_of('.');
    if (d != std::string::npos) b = b.substr(0, d);
    return b;
}

// Parse a live module's PE export table into (va, name) pairs (best-effort, reads debuggee memory).
static void parseExports(Debugger& dbg, uint64_t base,
                         std::vector<std::pair<uint64_t, std::string>>& out) {
    uint8_t dos[0x40];
    if (dbg.readMemory(base, dos, sizeof(dos)) != sizeof(dos) || dos[0] != 'M' || dos[1] != 'Z') return;
    uint32_t e_lfanew = 0; std::memcpy(&e_lfanew, dos + 0x3C, 4);
    if (e_lfanew > 0x1000) return;
    uint8_t pe[0x1A];
    if (dbg.readMemory(base + e_lfanew, pe, sizeof(pe)) != sizeof(pe) || pe[0] != 'P' || pe[1] != 'E') return;
    uint16_t magic = 0; std::memcpy(&magic, pe + 24, 2);            // optional header magic
    bool plus = (magic == 0x20B);
    uint32_t ddOff = e_lfanew + 24 + (plus ? 112u : 96u);          // DataDirectory[0] = export table
    uint8_t dd[8];
    if (dbg.readMemory(base + ddOff, dd, 8) != 8) return;
    uint32_t expRVA = 0, expSize = 0;
    std::memcpy(&expRVA, dd, 4); std::memcpy(&expSize, dd + 4, 4);
    if (!expRVA) return;
    uint8_t ed[40];
    if (dbg.readMemory(base + expRVA, ed, sizeof(ed)) != sizeof(ed)) return;
    uint32_t numFuncs = 0, numNames = 0, addrFuncs = 0, addrNames = 0, addrOrd = 0;
    std::memcpy(&numFuncs, ed + 20, 4); std::memcpy(&numNames, ed + 24, 4);
    std::memcpy(&addrFuncs, ed + 28, 4); std::memcpy(&addrNames, ed + 32, 4); std::memcpy(&addrOrd, ed + 36, 4);
    if (numNames == 0 || numNames > 100000 || numFuncs == 0 || numFuncs > 200000) return;
    std::vector<uint32_t> nameRVAs(numNames), eat(numFuncs);
    std::vector<uint16_t> ords(numNames);
    if (dbg.readMemory(base + addrNames, nameRVAs.data(), numNames * 4) != numNames * 4) return;
    if (dbg.readMemory(base + addrOrd,   ords.data(),     numNames * 2) != numNames * 2) return;
    if (dbg.readMemory(base + addrFuncs,  eat.data(),      numFuncs * 4) != numFuncs * 4) return;
    out.reserve(numNames);
    for (uint32_t i = 0; i < numNames; ++i) {
        uint16_t o = ords[i];
        if (o >= numFuncs) continue;
        uint32_t funcRVA = eat[o];
        if (funcRVA == 0 || (funcRVA >= expRVA && funcRVA < expRVA + expSize)) continue;  // 0 / forwarder
        char nm[128] = {0};
        if (!dbg.readMemory(base + nameRVAs[i], nm, sizeof(nm) - 1)) continue;
        nm[sizeof(nm) - 1] = 0;
        if (nm[0]) out.emplace_back(base + (uint64_t)funcRVA, std::string(nm));
    }
}

void BinaryViewTab::renderWelcome(AppContext& ctx) {
    const float  scale = theme::UiScale();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const float  heroW = 560.0f * scale;
    const float  offX  = (avail.x - heroW) * 0.5f > 0 ? (avail.x - heroW) * 0.5f : 0.0f;
    auto center = [&](float w) { ImGui::SetCursorPosX(offX + (heroW - w) * 0.5f); };

    // Push the hero down so it sits in the upper third, not jammed to the top.
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + avail.y * 0.10f);

    // Big accent title (font temporarily scaled up — no extra font asset needed).
    ImGui::PushFont(ui::gUiFont ? ui::gUiFont : ImGui::GetFont());
    ImGui::SetWindowFontScale(2.1f);
    const char* title = "DisasmStudio";
    center(ImGui::CalcTextSize(title).x);
    ImGui::TextColored(theme::col::accent(), "%s", title);
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopFont();

    const char* sub = "A fast, GPU-accelerated disassembler & debugger workbench";
    center(ImGui::CalcTextSize(sub).x);
    ImGui::TextDisabled("%s", sub);

    ImGui::Dummy(ImVec2(0, 18 * scale));

    // Primary action: a wide accent button.
    const float btnW = 240.0f * scale, btnH = 38.0f * scale;
    const ImVec4 acc = theme::col::accent();
    ImGui::PushStyleColor(ImGuiCol_Button,        acc);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(acc.x * 1.15f, acc.y * 1.15f, acc.z * 1.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(acc.x * 0.85f, acc.y * 0.85f, acc.z * 0.85f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(1, 1, 1, 1));
    center(btnW);
    if (ImGui::Button("Open Binary...", ImVec2(btnW, btnH))) ctx.openBinaryDialog();
    ImGui::PopStyleColor(4);

    const char* hint = "or press Ctrl+O   \xc2\xb7   File > Open as Raw... for shellcode / firmware";
    center(ImGui::CalcTextSize(hint).x);
    ImGui::TextDisabled("%s", hint);

    // Recent targets, pulled from the same recents index the Projects tab uses.
    std::vector<RecentEntry> recents = LoadRecents();
    if (!recents.empty()) {
        ImGui::Dummy(ImVec2(0, 22 * scale));
        const int rows = (int)std::min<size_t>(recents.size(), 7);
        const float listH = ImGui::GetFrameHeight()
                          + rows * ImGui::GetTextLineHeightWithSpacing()
                          + 18.0f * scale;
        ImGui::SetCursorPosX(offX);
        ImGui::BeginChild("welc_recents", ImVec2(heroW, listH), ImGuiChildFlags_Borders);
        ImGui::SeparatorText("Recent");
        for (int i = 0; i < rows; ++i) {
            const RecentEntry& r = recents[i];
            ImGui::PushID(i);
            const std::string& label = r.name.empty() ? r.path : r.name;
            if (ImGui::Selectable(label.c_str()) && !r.path.empty()) {
                ctx.loadBinaryPath(r.path);
                ctx.requestedTab = "Binary View";
            }
            if (ImGui::IsItemHovered() && !r.path.empty()) ImGui::SetTooltip("%s", r.path.c_str());
            if (!r.arch.empty()) {                         // right-aligned arch tag
                ImGui::SameLine(heroW - ImGui::CalcTextSize(r.arch.c_str()).x - 24.0f * scale);
                ImGui::TextDisabled("%s", r.arch.c_str());
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
}

// Assembly view dispatcher: a full-program listing (default) or a window around
// the cursor. The full listing is the "see the entire app as asm" mode.
void BinaryViewTab::renderAssembly(AppContext& ctx) {
    if (!ctx.binary.loaded() || !ctx.disasm) {
        ImGui::TextDisabled("Load a binary to disassemble (File > Open Binary).");
        return;
    }
    // Launch-and-debug the loaded binary straight from the static view (breaks at
    // the entry point). Only shown when there's nothing attached yet.
    if (!ctx.debug.snapshot().attached()) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.42f, 0.24f, 1.0f));
        bool run = ImGui::SmallButton("> Run");
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Launch this binary under the debugger and break at its entry point");
        if (run) {
            std::string err;
            if (ctx.debug.launchAndAttach(ctx.binary.path(), err)) { runErr_.clear(); ctx.openLiveAssemblyView(); }
            else runErr_ = "Launch failed: " + err;
        }
        if (!runErr_.empty()) { ImGui::SameLine(); ImGui::TextColored(theme::col::bad(), "%s", runErr_.c_str()); }
        ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();
    }
    ImGui::Checkbox("Full program", &asmFullProgram_);
    ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();
    if (ImGui::SmallButton("Rebuild listing")) listBuilt_ = false;

    // Rebuild the cached listing when the image, analyzed functions, strings,
    // engine, or arch change. (strings feed the data-section rows, so a late
    // async string scan must re-trigger the build.) The worker adopts the same
    // signature (listingSig) when it delivers a prebuilt listing, so this guard
    // doesn't redundantly re-sweep on the UI thread after a background build.
    uint64_t sig = listingSig(ctx);
    if (!listBuilt_ || sig != listSig_) { buildFullListing(ctx); listSig_ = sig; lastAsmScroll_ = 0; }

    ImGui::SameLine();
    ImGui::TextDisabled("%d instruction(s), %d function(s)%s", listInsnCount_, (int)functions_.size(),
                        listInsnCount_ >= 800000 ? "  (capped)" : "");
    ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();
    ImGui::Checkbox("Explain", &showHints_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Inline plain-language note of what each instruction does");
    ImGui::SameLine();
    ImGui::Checkbox("Str", &showStringComments_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Inline string / imported-API comments");
    ImGui::SameLine();
    ImGui::Checkbox("Arrows", &showJumpArrows_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Branch arrows in the flow gutter");
    ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();
    if (ImGui::SmallButton("Prev")) stepAsmCursor(-1);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous instruction (K)");
    ImGui::SameLine();
    if (ImGui::SmallButton("Next")) stepAsmCursor(1);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next instruction (J)");
    ImGui::Separator();

    if (asmFullProgram_) renderAssemblyFull(ctx);
    else                 renderAssemblyWindow(ctx);
}

// Cache key for the full-program listing. Shared by the UI-thread lazy build and
// the background-worker adopt path so the two agree on when listRows_ is current.
uint64_t BinaryViewTab::listingSig(AppContext& ctx) const {
    return (ctx.binary.loaded() ? ctx.binary.contentHash() : 0)
         ^ ((uint64_t)functions_.size() << 1)
         ^ ((uint64_t)strings_.size() << 20)
         ^ ((uint64_t)ctx.arch << 40)
         ^ ((uint64_t)(ctx.disasm ? ctx.disasm->engine() : Engine::Zydis) << 44);
}

// Linear-sweep every executable section once and cache a row index (instruction
// addresses + function-divider markers). Re-decoded per visible row at render
// time, so memory stays small even for large images. String literals from the
// non-executable (data) sections are also indexed as rows so the listing can
// scroll to a clicked string. Sections are walked in ascending VA order, so the
// row vector stays globally sorted by address (the nav scroll binary-searches it).
// This UI-thread build is the fallback; on load/patch the worker builds the same
// rows off-thread (BuildListingRows) and render() adopts them.
void BinaryViewTab::buildFullListing(AppContext& ctx) {
    listRows_.clear();
    listInsnCount_ = 0;
    listBuilt_ = true;
    if (!ctx.binary.loaded() || !ctx.disasm) return;

    std::unordered_set<uint64_t> funcStarts;
    for (const auto& f : functions_) funcStarts.insert(f.address);

    // Strings sorted by address, consumed per data section below (ascending).
    std::vector<int> strOrder(strings_.size());
    for (int i = 0; i < (int)strings_.size(); ++i) strOrder[i] = i;
    std::sort(strOrder.begin(), strOrder.end(),
              [&](int a, int b) { return strings_[a].address < strings_[b].address; });

    // Walk sections in VA order so listRows_ stays sorted by address.
    std::vector<const Section*> secs;
    for (const auto& s : ctx.binary.sections()) secs.push_back(&s);
    std::sort(secs.begin(), secs.end(),
              [](const Section* a, const Section* b) { return a->virtualAddress < b->virtualAddress; });

    const int kCap = 800000;   // safety cap to keep huge images responsive
    for (const Section* sp : secs) {
        const Section& s = *sp;
        uint64_t va = ctx.binary.imageBase() + s.virtualAddress;
        if (s.executable) {
            size_t avail = 0;
            const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
            if (!p) continue;
            size_t limit = s.rawSize ? std::min<size_t>(avail, (size_t)s.rawSize) : avail;
            size_t off = 0;
            while (off < limit && listInsnCount_ < kCap) {
                uint64_t a = va + off;
                if (funcStarts.count(a)) listRows_.push_back({ a, true });   // divider
                Instruction in;
                bool ok = ctx.disasm->decodeOne(p + off, limit - off, a, in) && in.length;
                listRows_.push_back({ a, false });
                ++listInsnCount_;
                off += ok ? in.length : 1;
            }
            if (listInsnCount_ >= kCap) break;
        } else {
            // Data section: emit a row per known string literal inside its VA span,
            // so navigating to a string lands on a real, visible row.
            uint64_t span    = std::max<uint64_t>(s.virtualSize, s.rawSize);
            uint64_t secEnd  = va + span;
            for (int oi : strOrder) {
                uint64_t sa = strings_[oi].address;
                if (sa < va)     continue;
                if (sa >= secEnd) continue;
                listRows_.push_back({ sa, false, true, oi });
            }
        }
    }
}

void BinaryViewTab::renderAsmFuncHeader(AppContext& ctx, uint64_t addr) {
    ImGui::TableNextRow();
    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(theme::col::accent().x, theme::col::accent().y, theme::col::accent().z, 0.18f)));
    std::string nm = symbolFor(ctx, addr);
    if (nm.empty() || nm.find("+0x") != std::string::npos) { char b[28]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)addr); nm = b; }
    ImGui::TableSetColumnIndex(2); ImGui::TextColored(theme::col::muted(), "0x%llX", (unsigned long long)addr);
    ImGui::TableSetColumnIndex(4); ImGui::TextColored(theme::col::accent(), "%s:", nm.c_str());
}

// Select every instruction address in [a, b] (inclusive) using the cached listing
// order; backs Shift+click range selection in the full listing.
void BinaryViewTab::selectRange(uint64_t a, uint64_t b) {
    if (a > b) { uint64_t t = a; a = b; b = t; }
    selVAs_.clear();
    for (const auto& r : listRows_) {        // listRows_ is sorted ascending by addr
        if (r.divider) continue;
        if (r.addr < a) continue;
        if (r.addr > b) break;
        selVAs_.insert(r.addr);
    }
    if (selVAs_.empty()) { selVAs_.insert(a); selVAs_.insert(b); }
}

// Batch actions over the current multi-line selection (selVAs_), shown at the top
// of an instruction's right-click menu when that row is part of the selection.
void BinaryViewTab::asmSelectionMenu(AppContext& ctx, const DbgSnapshot& snap) {
    std::vector<uint64_t> sel(selVAs_.begin(), selVAs_.end());
    std::sort(sel.begin(), sel.end());
    if (sel.empty()) return;
    const uint64_t lo = sel.front(), hi = sel.back();

    auto decodeAt = [&](uint64_t va, Instruction& out) -> bool {
        size_t avail = 0; const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
        return p && ctx.disasm && ctx.disasm->decodeOne(p, avail, va, out) && out.length;
    };

    ImGui::TextDisabled("Selection: %d line(s)  0x%llX-0x%llX",
                        (int)sel.size(), (unsigned long long)lo, (unsigned long long)hi);
    if (ImGui::MenuItem("Create signature from selection -> Sig Scanner")) {
        ctx.pendingSignature = buildSignature(ctx, lo, hi, false, false);
        ctx.pendingSignatureLive = false;        // built from the file image -> file scan
        ctx.requestedTab = "Sig Scanner";
    }
    if (ImGui::MenuItem("Create signature (wildcard calls/jumps)##sel")) {   // ##sel: unique ID vs per-line item
        ctx.pendingSignature = buildSignature(ctx, lo, hi, false, true);
        ctx.pendingSignatureLive = false;        // built from the file image -> file scan
        ctx.requestedTab = "Sig Scanner";
    }
    if (ImGui::MenuItem("Copy bytes##sel")) {                                 // ##sel: unique ID vs per-line item
        std::string bytes;
        for (uint64_t va : sel) { Instruction in2; if (decodeAt(va, in2)) { if (!bytes.empty()) bytes += ' '; bytes += in2.bytes; } }
        ImGui::SetClipboardText(bytes.c_str());
    }
    if (ImGui::MenuItem("Copy as C array##sel")) {
        std::string bytes;
        for (uint64_t va : sel) { Instruction in2; if (decodeAt(va, in2)) { if (!bytes.empty()) bytes += ' '; bytes += in2.bytes; } }
        ImGui::SetClipboardText(bytesToCArray(bytes).c_str());
    }
    if (ImGui::MenuItem("Copy instructions")) {
        std::string text;
        for (uint64_t va : sel) {
            Instruction in2;
            if (decodeAt(va, in2)) { text += in2.mnemonic; if (!in2.operands.empty()) { text += ' '; text += in2.operands; } text += '\n'; }
        }
        ImGui::SetClipboardText(text.c_str());
    }
    if (ImGui::MenuItem("NOP out selection")) {
        for (uint64_t va : sel) { Instruction in2; if (decodeAt(va, in2)) applyPatchBytes(ctx, va, std::vector<uint8_t>(in2.length, 0x90), in2.length, false); }
    }
    if (ImGui::MenuItem("Assemble over selection (region patch)...")) {
        // Patch the whole [lo, end-of-hi] span at once: prefill the assembler with
        // the current instructions and let applyPatchBytes handle the byte length
        // (it NOP-pads a short encoding up to the original span).
        Instruction hiIn; uint32_t span = 0;
        if (decodeAt(hi, hiIn)) span = (uint32_t)((hi + hiIn.length) - lo);
        std::string txt;
        for (uint64_t va : sel) { Instruction in2; if (decodeAt(va, in2)) { if (!txt.empty()) txt += "; "; txt += in2.mnemonic; if (!in2.operands.empty()) { txt += ' '; txt += in2.operands; } } }
        patchVA_ = lo; patchLen_ = span; patchMode_ = 1;
        std::snprintf(patchAsmText_, sizeof(patchAsmText_), "%s", txt.c_str());
        patchHex_[0] = 0; patchAsm_.clear(); patchStatus_.clear();
        openPatchPopup_ = true;
    }
    if (ImGui::MenuItem("Add breakpoints on selection")) {
        for (uint64_t va : sel) if (breakpoints_.insert(va).second && snap.attached()) ctx.debug.addBreakpoint(va);
    }
    if (ImGui::MenuItem("Bookmark selection")) {
        for (uint64_t va : sel) bookmarks_.push_back({ va, "bookmark" });
    }
    ImGui::Separator();
    {   // span end = end of the last selected instruction
        Instruction hiIn; uint64_t end = hi;
        if (decodeAt(hi, hiIn)) end = hi + hiIn.length;
        if (ImGui::MenuItem("Synthesize equivalent (F1)..."))  runSynthesis(ctx, lo, end);
        if (ImGui::MenuItem("Hot-patch this selection (F2)...")) openHotPatch(ctx, lo, (uint32_t)(end - lo));
        if (ImGui::MenuItem("Explore paths from here (F3)..."))  runPathExplore(ctx, lo);
    }
    if (ImGui::MenuItem("Clear selection")) { selVAs_.clear(); selAnchorVA_ = 0; }
}

// Batch actions over the live multi-line selection. Mirrors asmSelectionMenu, but
// decodes from the debuggee's memory (readMemory) instead of the file image, so it
// works on relocated / runtime-only code and lets the byte range drive a live scan.
void BinaryViewTab::liveSelectionMenu(AppContext& ctx, const DbgSnapshot& snap) {
    std::vector<uint64_t> sel(selVAs_.begin(), selVAs_.end());
    std::sort(sel.begin(), sel.end());
    if (sel.empty()) return;
    const uint64_t lo = sel.front(), hi = sel.back();

    auto decodeAt = [&](uint64_t va, Instruction& out) -> bool {
        // Mask our 0xCC breakpoints and decode with the debuggee-bitness decoder: this
        // drives NOP-out (in2.length sizes the patch) and signature creation, so a stray
        // int3 or an x64-decoded WOW64 target would otherwise patch/scan the wrong bytes.
        uint8_t mem[16]; size_t got = ctx.debug.readMemoryMasked(va, mem, sizeof(mem));
        IDisassembler* d = liveDecoder(ctx, snap.is32);
        return got && d && d->decodeOne(mem, got, va, out) && out.length;
    };

    ImGui::TextDisabled("Selection: %d line(s)  0x%llX-0x%llX",
                        (int)sel.size(), (unsigned long long)lo, (unsigned long long)hi);
    if (ImGui::MenuItem("Scan selected bytes in process memory")) {
        // buildSignature(live=true) reads the bytes from the debuggee; wildcard=false
        // keeps it a literal hex string the hex search parser can consume.
        std::string sig = buildSignature(ctx, lo, hi, true, false);
        liveFindKind_ = 2;                                  // hex bytes
        std::snprintf(liveFind_, sizeof(liveFind_), "%s", sig.c_str());
        liveFindHits_ = liveMemorySearch(ctx.debug, sig.c_str(), 2, liveFindStatus_);
        openFindPopup_ = true;                              // surface results in the Live Search panel
    }
    if (ImGui::MenuItem("Create signature from selection -> Sig Scanner")) {
        ctx.pendingSignature = buildSignature(ctx, lo, hi, true, false);
        ctx.pendingSignatureLive = true;         // built from debuggee memory -> live scan
        ctx.requestedTab = "Sig Scanner";
    }
    if (ImGui::MenuItem("Create signature (wildcard calls/jumps)##livesel")) {
        ctx.pendingSignature = buildSignature(ctx, lo, hi, true, true);
        ctx.pendingSignatureLive = true;         // built from debuggee memory -> live scan
        ctx.requestedTab = "Sig Scanner";
    }
    if (ImGui::MenuItem("Copy bytes##livesel")) {
        std::string bytes;
        for (uint64_t va : sel) { Instruction in2; if (decodeAt(va, in2)) { if (!bytes.empty()) bytes += ' '; bytes += in2.bytes; } }
        ImGui::SetClipboardText(bytes.c_str());
    }
    if (ImGui::MenuItem("Copy as C array##livesel")) {
        std::string bytes;
        for (uint64_t va : sel) { Instruction in2; if (decodeAt(va, in2)) { if (!bytes.empty()) bytes += ' '; bytes += in2.bytes; } }
        ImGui::SetClipboardText(bytesToCArray(bytes).c_str());
    }
    if (ImGui::MenuItem("Copy instructions##livesel")) {
        std::string text;
        for (uint64_t va : sel) {
            Instruction in2;
            if (decodeAt(va, in2)) { text += in2.mnemonic; if (!in2.operands.empty()) { text += ' '; text += in2.operands; } text += '\n'; }
        }
        ImGui::SetClipboardText(text.c_str());
    }
    if (ImGui::MenuItem("NOP out selection##livesel")) {
        for (uint64_t va : sel) { Instruction in2; if (decodeAt(va, in2)) applyPatchBytes(ctx, va, std::vector<uint8_t>(in2.length, 0x90), in2.length, false); }
    }
    if (ImGui::MenuItem("Add breakpoints on selection##livesel")) {
        for (uint64_t va : sel) if (breakpoints_.insert(va).second && snap.attached()) ctx.debug.addBreakpoint(va);
    }
    if (ImGui::MenuItem("Bookmark selection##livesel")) {
        // Bookmarks persist as FILE VAs; translate each runtime address back.
        for (uint64_t va : sel) bookmarks_.push_back({ liveVAtoFile(ctx, va), "bookmark" });
    }
    if (ImGui::MenuItem("Clear selection##livesel")) { selVAs_.clear(); selAnchorVA_ = 0; }
}

// Shared single-instruction copy actions, used by BOTH the static and live per-row
// context menus so they can't drift or double up against the selection menu.
void BinaryViewTab::emitInstrCopyMenu(const Instruction& in) {
    if (ImGui::MenuItem("Copy bytes")) ImGui::SetClipboardText(in.bytes.c_str());
    if (ImGui::MenuItem("Copy as C array")) ImGui::SetClipboardText(bytesToCArray(in.bytes).c_str());
    if (ImGui::MenuItem("Copy instruction")) { std::string t = in.mnemonic + " " + in.operands; ImGui::SetClipboardText(t.c_str()); }
}

// Render one instruction row (columns 0-4: bp, flow gutter, address, bytes,
// instruction) in the static listing. Shared by the windowed and full-program views.
void BinaryViewTab::renderAsmRow(AppContext& ctx, const Instruction& in, const DbgSnapshot& snap,
                                 const std::string& hoverTok, std::string& nextHoverTok, bool autoScrollHere) {
    ImGui::TableNextRow();
    ImGui::PushID((void*)(uintptr_t)in.address);

    bool rowAtRip = snap.attached() && snap.regs.rip == in.address;
    bool rowSel   = in.address == cursorVA_ && !rowAtRip;
    bool rowMulti = selVAs_.size() > 1 && !rowAtRip && !rowSel && selVAs_.count(in.address);
    if (rowAtRip) { float p = slowPulse(); ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.16f, 0.42f, 0.21f, 0.40f + 0.38f * p))); }
    else if (rowSel) { float p = slowPulse(); ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.20f, 0.32f, 0.54f, 0.30f + 0.34f * p))); }
    else if (rowMulti) { ImVec4 sc = theme::col::selection(); ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(sc.x, sc.y, sc.z, 0.26f))); }

    ImGui::TableSetColumnIndex(0);
    bool bp = hasBreakpoint(breakpoints_, in.address);
    if (ImGui::Selectable(bp ? "*" : " ", false, ImGuiSelectableFlags_None, ImVec2(0, 0))) {
        if (bp) { breakpoints_.erase(in.address); if (snap.attached()) ctx.debug.removeBreakpoint(in.address); }
        else    { breakpoints_.insert(in.address); if (snap.attached()) ctx.debug.addBreakpoint(in.address); }
    }

    // col 1: flow gutter — record this row's center Y (+ lane/address X once) so
    // drawAsmArrows() can paint branch arrows over the listing after EndTable.
    ImGui::TableSetColumnIndex(1);
    if (!asmGotLaneX_) { asmLaneX_ = ImGui::GetCursorScreenPos().x; asmGotLaneX_ = true; }
    ImGui::Dummy(ImVec2(1.0f, ImGui::GetTextLineHeight()));
    asmFlow_.push_back({ in.address, in.branchTarget,
                         in.isBranch && !in.isCall && in.branchTarget != 0,
                         (ImGui::GetItemRectMin().y + ImGui::GetItemRectMax().y) * 0.5f });

    ImGui::TableSetColumnIndex(2);
    if (!asmGotAddrX_) { asmAddrX_ = ImGui::GetCursorScreenPos().x; asmGotAddrX_ = true; }
    bool hwbp = std::any_of(snap.hwBreakpoints.begin(), snap.hwBreakpoints.end(),
                            [&](const HwBreakpointInfo& h) { return h.address == in.address; });
    char addrLbl[40]; std::snprintf(addrLbl, sizeof(addrLbl), "%s0x%llX", rowAtRip ? "> " : "  ", (unsigned long long)in.address);
    if (rowAtRip)  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.9f, 0.4f, 1));
    else if (hwbp) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.6f, 0.95f, 1));
    else           ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
    if (ImGui::Selectable(addrLbl, false)) {
        ImGuiIO& io = ImGui::GetIO();
        if (io.KeyShift && selAnchorVA_) {
            selectRange(selAnchorVA_, in.address);                 // extend range from the anchor
        } else if (io.KeyCtrl) {
            if (selVAs_.count(in.address)) selVAs_.erase(in.address); else selVAs_.insert(in.address);
            selAnchorVA_ = in.address;
        } else {
            selVAs_.clear(); selVAs_.insert(in.address); selAnchorVA_ = in.address;
        }
        cursorVA_ = in.address;
    }
    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && in.branchTarget) navigateTo(in.branchTarget);
    ImGui::PopStyleColor();
    if (autoScrollHere && in.address == cursorVA_ && cursorVA_ != lastAsmScroll_) { ImGui::SetScrollHereY(0.4f); lastAsmScroll_ = cursorVA_; }
    if (ImGui::BeginPopupContextItem("ictx")) {
        const bool inSel = selVAs_.size() > 1 && selVAs_.count(in.address);
        if (inSel) {   // batch actions on the selection (copy/signature/NOP come from here, not per-row)
            asmSelectionMenu(ctx, snap);
            ImGui::Separator();
        }
        ImGui::BeginDisabled(!snap.attached());
        if (ImGui::MenuItem("Run to cursor")) ctx.debug.runToCursor(in.address);
        ImGui::Separator();
        {   // Hardware breakpoint (DR0-DR3): execute, or data write / read-write.
            HwKind curKind = HwKind::Execute; bool hasHw = false;
            for (const auto& h : snap.hwBreakpoints) if (h.address == in.address) { curKind = h.kind; hasHw = true; break; }
            if (ImGui::BeginMenu("Hardware breakpoint (DR)")) {
                if (ImGui::MenuItem("Execute", nullptr, hasHw && curKind == HwKind::Execute)) {
                    ctx.debug.removeHardwareBreakpoint(in.address);
                    if (!(hasHw && curKind == HwKind::Execute)) ctx.debug.addHardwareBreakpoint(in.address, HwKind::Execute, 1);
                }
                ImGui::Separator();
                ImGui::TextDisabled("data length"); ImGui::SameLine();
                ImGui::RadioButton("1", &hwSizeSel_, 1); ImGui::SameLine();
                ImGui::RadioButton("2", &hwSizeSel_, 2); ImGui::SameLine();
                ImGui::RadioButton("4", &hwSizeSel_, 4); ImGui::SameLine();
                ImGui::RadioButton("8", &hwSizeSel_, 8);
                if (ImGui::MenuItem("Break on write", nullptr, hasHw && curKind == HwKind::Write)) {
                    ctx.debug.removeHardwareBreakpoint(in.address);
                    ctx.debug.addHardwareBreakpoint(in.address, HwKind::Write, (uint8_t)hwSizeSel_);
                }
                if (ImGui::MenuItem("Break on read/write", nullptr, hasHw && curKind == HwKind::ReadWrite)) {
                    ctx.debug.removeHardwareBreakpoint(in.address);
                    ctx.debug.addHardwareBreakpoint(in.address, HwKind::ReadWrite, (uint8_t)hwSizeSel_);
                }
                if (hasHw && ImGui::MenuItem("Remove")) ctx.debug.removeHardwareBreakpoint(in.address);
                ImGui::EndMenu();
            }
        }
        ImGui::EndDisabled();
        bool swbp = hasBreakpoint(breakpoints_, in.address);
        if (ImGui::MenuItem("Toggle software breakpoint", nullptr, swbp)) {
            if (swbp) { breakpoints_.erase(in.address); if (snap.attached()) ctx.debug.removeBreakpoint(in.address); }
            else      { breakpoints_.insert(in.address); if (snap.attached()) ctx.debug.addBreakpoint(in.address); }
        }
        if (ImGui::MenuItem("Set breakpoint condition...")) {
            annPopupVA_ = in.address;
            auto it = condBuf_.find(in.address);
            std::snprintf(condPopupBuf_, sizeof(condPopupBuf_), "%s", it != condBuf_.end() ? it->second.c_str() : "");
            openCondPopup_ = true;
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Copy address")) { char c[24]; std::snprintf(c, sizeof(c), "0x%llX", (unsigned long long)in.address); ImGui::SetClipboardText(c); }
        if (!inSel) emitInstrCopyMenu(in);   // selection menu already offers these when multi-selecting
        if (in.branchTarget && ImGui::MenuItem("Follow target")) navigateTo(in.branchTarget);
        if (ImGui::MenuItem("Find references to this address")) startXrefSearch(ctx, in.address);
        if (uint64_t ref = instrDataRef(in)) if (ImGui::MenuItem("Find references to operand target")) startXrefSearch(ctx, ref);
        if (in.mnemonic == "jmp" && in.operands.find('[') != std::string::npos) {
            if (ImGui::MenuItem("Resolve jump table -> targets")) {
                xrefHits_ = resolveJumpTable(ctx, in);
                xrefTarget_ = in.address;
                char s[56]; std::snprintf(s, sizeof(s), "%zu jump-table target(s)", xrefHits_.size()); xrefStatus_ = s;
                openXrefPopup_ = true;
            }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Rename symbol...")) { annPopupVA_ = in.address; std::string n = annName(ctx, in.address); std::snprintf(renameBuf_, sizeof(renameBuf_), "%s", n.c_str()); openRenamePopup_ = true; }
        if (ImGui::MenuItem("Set comment...")) { annPopupVA_ = in.address; auto cit = comments_.find(in.address); std::snprintf(commentBuf_, sizeof(commentBuf_), "%s", cit != comments_.end() ? cit->second.c_str() : ""); openCommentPopup_ = true; }
        if (ImGui::MenuItem("Patch...")) { patchVA_ = in.address; patchLen_ = in.length; patchMode_ = 1; std::snprintf(patchHex_, sizeof(patchHex_), "%s", in.bytes.c_str()); std::snprintf(patchAsmText_, sizeof(patchAsmText_), "%s %s", in.mnemonic.c_str(), in.operands.c_str()); patchAsm_.clear(); patchStatus_.clear(); openPatchPopup_ = true; }
        if (!inSel && ImGui::MenuItem("NOP out instruction") && in.length)
            applyPatchBytes(ctx, in.address, std::vector<uint8_t>(in.length, 0x90), in.length, false);
        if (uint64_t pk = patchKeyFor(ctx, in.address); std::any_of(ctx.project.patches.begin(), ctx.project.patches.end(),
                        [&](const PjPatch& x) { return x.address == pk; }))
            if (ImGui::MenuItem("Revert patch here")) revertPatchAt(ctx, in.address);
        if (!inSel) {
            if (ImGui::MenuItem("Create signature -> Sig Scanner")) {
                ctx.pendingSignature = buildSignature(ctx, in.address, in.address, false, false);
                ctx.pendingSignatureLive = false;
                ctx.requestedTab = "Sig Scanner";
            }
            if (ImGui::MenuItem("Create signature (wildcard calls/jumps)")) {
                ctx.pendingSignature = buildSignature(ctx, in.address, in.address, false, true);
                ctx.pendingSignatureLive = false;
                ctx.requestedTab = "Sig Scanner";
            }
        }
        ImGui::Separator();
        if (selAnchorVA_ && selAnchorVA_ != in.address && ImGui::MenuItem("Select from anchor to here"))
            { selectRange(selAnchorVA_, in.address); cursorVA_ = in.address; }
        if (ImGui::MenuItem(selVAs_.count(in.address) ? "Remove line from selection" : "Add line to selection")) {
            if (selVAs_.count(in.address)) selVAs_.erase(in.address);
            else { selVAs_.insert(in.address); if (!selAnchorVA_) selAnchorVA_ = in.address; }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Add bookmark here")) bookmarks_.push_back({ in.address, "bookmark" });
        if (ImGui::MenuItem("Define function here")) {
            if (std::find_if(functions_.begin(), functions_.end(), [&](const Func& f){ return f.address == in.address; }) == functions_.end()) {
                char nm[28]; std::snprintf(nm, sizeof(nm), "sub_%llX", (unsigned long long)in.address);
                functions_.push_back({ in.address, nm, 0 });
                listBuilt_ = false;       // refresh function dividers in the listing
                funcIndexDirty_ = true;   // keep the sorted lookup index in sync
                ++liveGen_;               // invalidate the cached live decode (divider set)
            }
        }
        ImGui::EndPopup();
    }

    ImGui::TableSetColumnIndex(3);
    ImGui::TextDisabled("%s", in.bytes.c_str());

    ImGui::TableSetColumnIndex(4);
    ImVec4 mcol = in.isCall ? ImVec4(0.55f, 0.8f, 1.0f, 1) : in.isBranch ? ImVec4(0.95f, 0.75f, 0.4f, 1) : ImVec4(0.9f, 0.9f, 0.9f, 1);
    {
        ImVec2 cp = ImGui::GetCursorScreenPos();
        if (!hoverTok.empty() && in.mnemonic == hoverTok)
            ImGui::GetWindowDrawList()->AddRectFilled(cp, ImVec2(cp.x + ImGui::CalcTextSize(in.mnemonic.c_str()).x, cp.y + ImGui::GetTextLineHeight()), IM_COL32(95, 120, 175, 150), 2.0f);
        ImGui::TextColored(mcol, "%-7s", in.mnemonic.c_str());
        if (ImGui::IsItemHovered()) nextHoverTok = in.mnemonic;
    }
    ImGui::SameLine(0, 0);
    renderHoverTokens(in.operands.c_str(), ImGui::GetColorU32(ImVec4(0.9f, 0.9f, 0.9f, 1.0f)), hoverTok, nextHoverTok);
    if (in.branchTarget) {
        ImGui::SameLine(); ImGui::TextDisabled("  ; 0x%llX", (unsigned long long)in.branchTarget);
        if (ImGui::IsItemClicked()) navigateTo(in.branchTarget);       // click the target to follow
        if (showNames_) {
            std::string nm = symbolFor(ctx, in.branchTarget);
            if (!nm.empty()) {
                ImGui::SameLine(0, 6); ImGui::TextColored(theme::col::call(), "%s", nm.c_str());
                if (ImGui::IsItemClicked()) navigateTo(in.branchTarget);
            }
        }
    }
    bool dataComment = false;
    if (showStringComments_) {
        uint64_t ref = instrDataRef(in);
        if (!ref) ref = instrImmRef(in);   // also catch `mov reg, offset str` / `push offset str`
        if (ref) {
            if (auto it = importMap_.find(ref); it != importMap_.end()) {       // call/jmp through the IAT
                std::string txt = it->second;
                std::string purpose = apiPurpose(it->second);
                if (!purpose.empty()) txt += "  (" + purpose + ")";
                ImGui::SameLine(); ImGui::TextColored(theme::col::call(), "  ; %s", txt.c_str());
                dataComment = true;
            } else {
                size_t av = 0; const uint8_t* pp = ctx.binary.ptrFromVA(ref, av);
                if (pp) { std::string s = resolveString(pp, std::min(av, (size_t)80));
                          if (!s.empty()) { ImGui::SameLine(); ImGui::TextColored(ImVec4(0.80f, 0.72f, 0.45f, 1.0f), "  ; \"%.50s\"", s.c_str()); dataComment = true; } }
            }
        }
    }
    // Inline "what it does" gloss, unless a string/API comment already explains it.
    if (showHints_ && !dataComment) {
        std::string g = instrGloss(in);
        if (!g.empty()) { ImGui::SameLine(); ImGui::TextColored(ImVec4(0.52f, 0.58f, 0.68f, 1.0f), "  ; %s", g.c_str()); }
    }
    if (auto cit = comments_.find(in.address); cit != comments_.end() && !cit->second.empty()) {
        ImGui::SameLine(); ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "  ; %s", cit->second.c_str());
    }
    {   // anti-analysis / timing / privileged instruction flag
        const std::string& m = in.mnemonic;
        bool susp = m == "rdtsc" || m == "rdtscp" || m == "cpuid" || m == "sysenter" ||
                    m == "sidt"  || m == "sgdt"   || m == "sldt"  || m == "smsw" || m == "in" || m == "out";
        if (!susp && m == "int" && in.operands.find("2d") != std::string::npos) susp = true; // int 0x2d
        if (susp) { ImGui::SameLine(); ImGui::TextColored(ImVec4(0.95f, 0.5f, 0.4f, 1.0f), "  ; anti-analysis?"); }
    }
    ImGui::PopID();
}

// The entire program as assembly, with function dividers, clipper-rendered.
// Small "Pop out" / "Dock" toggle drawn at the top of a poppable panel. Flips the
// panel's popped-out flag (the render() layout then either keeps it inline or renders
// it as a standalone, viewport-backed window).
static void panelPopToggle(bool* poppedOut, const char* id) {
    ImGui::PushID(id);
    if (ImGui::SmallButton(*poppedOut ? "Dock" : "Pop out")) *poppedOut = !*poppedOut;
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip(*poppedOut ? "Dock this panel back into the main window"
                                     : "Open this panel in its own window");
    ImGui::PopID();
}

// Inline analysis-progress widget (phase label + bar [+ Cancel]) shared by the Binary
// View hot spots. Mirrors the status-bar version in App::renderStatusBar.
static void drawAnalysisProgress(AppContext& ctx, bool withCancel) {
    ProgressSnapshot pr = ctx.analysis.progress();
    char lbl[64];
    if (pr.modulesTotal > 0)
        std::snprintf(lbl, sizeof(lbl), "Modules %u/%u", pr.modulesDone, pr.modulesTotal);
    else {
        const char* ph = pr.phase == AnalysisPhase::Strings   ? "Scanning strings"
                       : pr.phase == AnalysisPhase::Functions ? "Discovering functions"
                       : pr.phase == AnalysisPhase::Listing   ? "Building listing"
                       : pr.phase == AnalysisPhase::Xref      ? "Building xrefs"
                       : "Analyzing";
        std::snprintf(lbl, sizeof(lbl), "%s", ph);
    }
    ImGui::TextColored(theme::col::accent(), "%s", lbl);
    ImGui::SameLine();
    float frac = (pr.modulesTotal > 0) ? (float)pr.modulesDone / (float)pr.modulesTotal
               : (pr.total > 0 ? (float)pr.current / (float)pr.total : -1.0f);
    float w = 160.0f * theme::UiScale();
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, theme::col::accent());
    if (frac >= 0.0f) ImGui::ProgressBar(frac, ImVec2(w, 0.0f));
    else { float t = (float)ImGui::GetTime(); ImGui::ProgressBar(t - (float)(long long)t, ImVec2(w, 0.0f), ""); }
    ImGui::PopStyleColor();
    if (withCancel) { ImGui::SameLine(); if (ImGui::SmallButton("Cancel")) ctx.analysis.cancelPending(); }
}

void BinaryViewTab::renderAssemblyFull(AppContext& ctx) {
    DbgSnapshot snap = ctx.debug.snapshot();
    if (listRows_.empty()) {
        if (ctx.analysis.bulkPending()) drawAnalysisProgress(ctx, true);
        else ImGui::TextDisabled("No executable code found (try Functions > Analyze, or a different arch).");
        return;
    }

    // Reset the per-frame branch-arrow geometry sink (filled inside renderAsmRow).
    asmFlow_.clear(); asmGotLaneX_ = asmGotAddrX_ = false;
    ImVec2 tableMin = ImGui::GetCursorScreenPos();
    ImVec2 tableAvail = ImGui::GetContentRegionAvail();

    // Decoded visible-row cache validity: drop it when the image (load bumps the
    // content hash, a patch bumps liveGen_), the arch, or the engine changes, so a
    // stale decode can never render. (See decodeCache_ in the header.)
    uint64_t dcKey = (ctx.binary.loaded() ? ctx.binary.contentHash() : 0)
                   ^ (liveGen_ * 0x9E3779B97F4A7C15ull)
                   ^ ((uint64_t)ctx.arch << 40)
                   ^ ((uint64_t)(ctx.disasm ? ctx.disasm->engine() : Engine::Zydis) << 44);
    if (dcKey != decodeCacheKey_) { decodeCache_.clear(); decodeCacheKey_ = dcKey; }

    ui::PushMono();
    if (ImGui::BeginTable("asm_full", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("bp", ImGuiTableColumnFlags_WidthFixed, 22);
        ImGui::TableSetupColumn("flow", ImGuiTableColumnFlags_WidthFixed, 36);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        // Jump to the cursor's row when navigation moved it (goto, xref, etc.).
        int scrollToRow = -1;
        if (cursorVA_ && cursorVA_ != lastAsmScroll_) {
            size_t lo = 0, hi = listRows_.size();
            while (lo < hi) { size_t mid = (lo + hi) / 2; if (listRows_[mid].addr < cursorVA_) lo = mid + 1; else hi = mid; }
            bool exact = lo < listRows_.size() && listRows_[lo].addr == cursorVA_;
            // A data address that has no listing row and lies outside every
            // executable section (e.g. a non-string data xref target) can't be
            // shown in the code listing — route it to the Hex view, which renders
            // starting at cursorVA_. Known strings are exact row hits, so this only
            // affects arbitrary data addresses.
            bool inExec = false;
            if (!exact) {
                for (const auto& s : ctx.binary.sections())
                    if (s.executable) {
                        uint64_t sv = ctx.binary.imageBase() + s.virtualAddress;
                        uint64_t sp = std::max<uint64_t>(s.virtualSize, s.rawSize);
                        if (cursorVA_ >= sv && cursorVA_ < sv + sp) { inExec = true; break; }
                    }
            }
            lastAsmScroll_ = cursorVA_;   // don't retrigger (incl. the Hex bounce) for this address
            if (!exact && !inExec && !listRows_.empty()) {
                mainView_ = 2;            // show the data byte/text in the Hex view
            } else {
                scrollToRow = (int)lo;
                if (scrollToRow >= (int)listRows_.size()) scrollToRow = (int)listRows_.size() - 1;
            }
        }

        const std::string hoverTok = hoverToken_;
        std::string nextHoverTok;

        ImGuiListClipper clipper;
        clipper.Begin((int)listRows_.size(), ImGui::GetTextLineHeightWithSpacing());
        if (scrollToRow >= 0) clipper.IncludeItemByIndex(scrollToRow);
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const ListRow& row = listRows_[(size_t)i];
                if (row.divider) {
                    renderAsmFuncHeader(ctx, row.addr);
                } else if (row.strData && row.strIdx >= 0 && row.strIdx < (int)strings_.size()) {
                    // A string literal from a data section: a plain, clickable row
                    // (address + the quoted text) so the listing can scroll here.
                    const Strng& st = strings_[(size_t)row.strIdx];
                    ImGui::TableNextRow();
                    ImGui::PushID((void*)(uintptr_t)row.addr);
                    if (row.addr == cursorVA_) {
                        ImVec4 sc = theme::col::selection();
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(sc.x, sc.y, sc.z, 0.30f)));
                    }
                    ImGui::TableSetColumnIndex(2);
                    char addrLbl[40]; std::snprintf(addrLbl, sizeof(addrLbl), "  0x%llX", (unsigned long long)row.addr);
                    if (ImGui::Selectable(addrLbl, false, ImGuiSelectableFlags_SpanAllColumns)) navigateTo(row.addr);
                    ImGui::TableSetColumnIndex(4);
                    ImGui::TextColored(ImVec4(0.80f, 0.72f, 0.45f, 1.0f), st.wide ? "L\"%s\"" : "\"%s\"", st.text.c_str());
                    ImGui::PopID();
                } else {
                    // Decode once per address and memoize: a fast scroll otherwise
                    // re-decodes the same visible rows every frame.
                    auto dit = decodeCache_.find(row.addr);
                    if (dit == decodeCache_.end()) {
                        Instruction in;
                        size_t avail = 0;
                        const uint8_t* p = ctx.binary.ptrFromVA(row.addr, avail);
                        if (!(p && ctx.disasm->decodeOne(p, avail, row.addr, in) && in.length)) {
                            in = Instruction{}; in.address = row.addr; in.length = 1;
                            uint8_t b = (p && avail) ? p[0] : 0;
                            char hb[8]; std::snprintf(hb, sizeof(hb), "%02X", b); in.bytes = hb;
                            in.mnemonic = "db";
                            char ob[8]; std::snprintf(ob, sizeof(ob), "0x%02X", b); in.operands = ob;
                        }
                        if (decodeCache_.size() >= 4096) decodeCache_.clear();   // bounded; re-warms
                        dit = decodeCache_.emplace(row.addr, std::move(in)).first;
                    }
                    renderAsmRow(ctx, dit->second, snap, hoverTok, nextHoverTok, /*autoScrollHere=*/false);
                }
                // Fire the navigation scroll for whichever row kind matched (incl.
                // a function-divider or a string row), now that it has been drawn.
                if (i == scrollToRow) ImGui::SetScrollHereY(0.4f);
            }
        }
        clipper.End();
        hoverToken_ = nextHoverTok;
        ImGui::EndTable();
    }
    ui::PopMono();
    if (showJumpArrows_) drawAsmArrows(tableMin.x, tableMin.y, tableMin.x + tableAvail.x, tableMin.y + tableAvail.y);
}

void BinaryViewTab::renderAssemblyWindow(AppContext& ctx) {
    if (!ctx.binary.loaded() || !ctx.disasm) {
        ImGui::TextDisabled("Load a binary to disassemble (File > Open Binary).");
        return;
    }
    uint64_t va = cursorVA_;
    size_t size = 0;
    const uint8_t* p = codeWindow(ctx, va, size);
    if (cursorVA_ == 0) cursorVA_ = va;
    if (!p) { ImGui::TextDisabled("Cursor address is not mapped to file data."); return; }

    // Back up so the focused line isn't pinned to the top (show a screenful above it).
    // Anchor the window to the nearest analyzed function start within the lookback
    // so context rows above the cursor decode from a real boundary, not a guess.
    uint64_t fanchor = 0;
    for (const auto& f : functions_)
        if (f.address <= cursorVA_ && cursorVA_ - f.address <= 192 && f.address > fanchor) fanchor = f.address;
    uint64_t winStart = alignBinaryStart(ctx.binary, *ctx.disasm, cursorVA_, 192, fanchor);
    size_t avail2 = 0;
    const uint8_t* wp = ctx.binary.ptrFromVA(winStart, avail2);
    if (!wp) { wp = p; winStart = va; avail2 = size; }

    DbgSnapshot snap = ctx.debug.snapshot();
    auto insns = ctx.disasm->disassemble(wp, std::min<size_t>(avail2, 4096), winStart, 256);

    // Function starts (call targets + analyzed functions) -> "sub_X" dividers.
    std::unordered_set<uint64_t> funcSet;
    for (const auto& in : insns) if (in.isCall && in.branchTarget) funcSet.insert(in.branchTarget);
    for (const auto& f : functions_) funcSet.insert(f.address);

    // Reset the per-frame branch-arrow geometry sink (filled inside renderAsmRow).
    asmFlow_.clear(); asmGotLaneX_ = asmGotAddrX_ = false;
    ImVec2 tableMin = ImGui::GetCursorScreenPos();
    ImVec2 tableAvail = ImGui::GetContentRegionAvail();

    ui::PushMono();
    if (ImGui::BeginTable("asm", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("bp", ImGuiTableColumnFlags_WidthFixed, 22);
        ImGui::TableSetupColumn("flow", ImGuiTableColumnFlags_WidthFixed, 36);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        // Same shared row renderer as the full listing, so the windowed view gets
        // the full right-click menu, multi-select, hints, string comments, and the
        // branch arrows for free (no bespoke duplication).
        const std::string hoverTok = hoverToken_;
        std::string nextHoverTok;
        bool firstRow = true;
        for (auto& in : insns) {
            if (!firstRow && funcSet.count(in.address)) renderAsmFuncHeader(ctx, in.address);
            firstRow = false;
            renderAsmRow(ctx, in, snap, hoverTok, nextHoverTok, /*autoScrollHere=*/true);
        }
        hoverToken_ = nextHoverTok;
        ImGui::EndTable();
    }
    ui::PopMono();
    if (showJumpArrows_) drawAsmArrows(tableMin.x, tableMin.y, tableMin.x + tableAvail.x, tableMin.y + tableAvail.y);
}

// Branch arrows for the static listings, painted in the flow gutter over the
// table after EndTable. Mirrors the live view's arrow renderer but reads the
// per-row geometry collected in asmFlow_ (visible rows only, so a target that
// scrolled off-screen gets a short up/down stub). clipX0/clipX1 bound the gutter
// horizontally; the vertical clip is derived from the visible rows so arrows
// never paint over the frozen column header.
void BinaryViewTab::drawAsmArrows(float x0, float y0, float x1, float y1) {
    if (asmFlow_.empty() || !asmGotLaneX_ || !asmGotAddrX_) return;

    float firstY = 1e30f, lastY = -1e30f;
    std::unordered_map<uint64_t, float> yOf;
    yOf.reserve(asmFlow_.size() * 2);
    for (const auto& r : asmFlow_) { firstY = std::min(firstY, r.y); lastY = std::max(lastY, r.y); yOf[r.addr] = r.y; }

    // Clip to the table's BODY rect (below the frozen header), not to firstY/lastY:
    // the clipper can force-render an off-screen navigation target, which would
    // otherwise blow the vertical bounds out for one frame.
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    dl->PushClipRect(ImVec2(x0, y0 + ImGui::GetFrameHeight()), ImVec2(x1, y1), true);
    const float laneBase = asmLaneX_ + 3.0f;
    const float xTip     = asmAddrX_ - 4.0f;

    struct Arr { float y0, y1; bool toWin, up; ImU32 col; };
    std::vector<Arr> arrs;
    arrs.reserve(asmFlow_.size());
    for (const auto& r : asmFlow_) {
        if (!r.branch) continue;
        bool active = (r.addr == cursorVA_) || (r.target == cursorVA_);
        ImU32 col = active              ? IM_COL32(120, 220, 120, 235)
                  : (r.target < r.addr) ? IM_COL32(220, 170,  90, 210)    // backward
                                        : IM_COL32(110, 170, 230, 210);   // forward
        Arr a; a.col = col; a.y0 = r.y;
        auto it = yOf.find(r.target);
        if (it != yOf.end()) { a.toWin = true; a.up = false; a.y1 = it->second; }
        else { a.toWin = false; a.up = r.target < r.addr; a.y1 = a.up ? firstY - 8.0f : lastY + 8.0f; }
        arrs.push_back(a);
    }
    std::sort(arrs.begin(), arrs.end(),
              [](const Arr& a, const Arr& b) { return std::min(a.y0, a.y1) < std::min(b.y0, b.y1); });
    std::vector<float> laneBot;
    for (const Arr& a : arrs) {
        float top = std::min(a.y0, a.y1), bot = std::max(a.y0, a.y1);
        int lane = -1;
        for (int L = 0; L < (int)laneBot.size(); ++L) if (laneBot[L] < top - 2.0f) { lane = L; break; }
        if (lane < 0) { lane = (int)laneBot.size(); laneBot.push_back(bot); }
        else laneBot[lane] = bot;
        float xb = laneBase + (lane > 7 ? 7 : lane) * 4.0f;   // gutter is 36px: 3px base + up to 7 lanes * 4px
        dl->AddLine(ImVec2(xTip, a.y0), ImVec2(xb, a.y0), a.col, 1.6f);
        dl->AddLine(ImVec2(xb, a.y0), ImVec2(xb, a.y1), a.col, 1.6f);
        if (a.toWin) {
            dl->AddLine(ImVec2(xb, a.y1), ImVec2(xTip, a.y1), a.col, 1.6f);
            dl->AddTriangleFilled(ImVec2(xTip - 5, a.y1 - 4), ImVec2(xTip - 5, a.y1 + 4), ImVec2(xTip + 1, a.y1), a.col);
        } else if (a.up) {
            dl->AddTriangleFilled(ImVec2(xb - 4, a.y1 + 6), ImVec2(xb + 4, a.y1 + 6), ImVec2(xb, a.y1), a.col);
        } else {
            dl->AddTriangleFilled(ImVec2(xb - 4, a.y1 - 6), ImVec2(xb + 4, a.y1 - 6), ImVec2(xb, a.y1), a.col);
        }
    }
    dl->PopClipRect();
}

// Move the cursor +/- N instructions through the cached full listing, skipping
// the function-divider marker rows (which share an address with the first
// instruction of the function). Backs J/K and the Prev/Next buttons.
void BinaryViewTab::stepAsmCursor(int delta) {
    if (listRows_.empty() || delta == 0 || !cursorVA_) return;
    // Anchor on the instruction CONTAINING the cursor (largest instruction addr
    // <= cursorVA_): with a ceil anchor a forward step from a non-aligned cursor
    // would overshoot by one (the ceil row is already the "next" instruction).
    size_t lo = 0, hi = listRows_.size();
    while (lo < hi) { size_t mid = (lo + hi) / 2; if (listRows_[mid].addr <= cursorVA_) lo = mid + 1; else hi = mid; }
    long idx = (long)lo - 1;                                                  // floor row (addr <= cursorVA_)
    while (idx >= 0 && listRows_[(size_t)idx].divider) --idx;                 // back over dividers to the instruction
    if (idx < 0) { idx = 0; while (idx < (long)listRows_.size() && listRows_[(size_t)idx].divider) ++idx; }
    if (idx >= (long)listRows_.size()) idx = (long)listRows_.size() - 1;
    int dir = delta < 0 ? -1 : 1, n = delta < 0 ? -delta : delta;
    for (int s = 0; s < n;) {
        long j = idx + dir;
        if (j < 0 || j >= (long)listRows_.size()) break;
        idx = j;
        if (!listRows_[(size_t)idx].divider) ++s;   // count only instruction landings
    }
    if (idx >= 0 && idx < (long)listRows_.size() && !listRows_[(size_t)idx].divider) {
        cursorVA_      = listRows_[(size_t)idx].addr;
        lastAsmScroll_ = 0;   // trigger the SetScrollHereY re-centering next frame
    }
}

// Restore a recorded patch's original bytes (live process + in-memory image) and
// drop the patch entry. Mirrors the Patches-tab revert; deliberately does NOT
// route through applyPatchBytes (which would re-capture the reverted bytes as a
// new patch's "original" and corrupt the undo chain).
// Canonical file-VA key for a patch. Mirrors applyPatchBytes: only translate when
// `va` (a live runtime VA) doesn't resolve in the file image but its translation
// does, so a static-view file VA is left untouched.
uint64_t BinaryViewTab::patchKeyFor(AppContext& ctx, uint64_t va) {
    if (ctx.debug.snapshot().attached()) {
        size_t a0 = 0;
        if (!ctx.binary.ptrFromVA(va, a0)) {
            uint64_t t = liveVAtoFile(ctx, va);
            size_t a1 = 0;
            if (t != va && ctx.binary.ptrFromVA(t, a1)) return t;
        }
    }
    return va;
}

void BinaryViewTab::revertPatchAt(AppContext& ctx, uint64_t va) {
    uint64_t fileVA = patchKeyFor(ctx, va);   // patches are keyed by file VA
    auto& V = ctx.project.patches;
    auto it = std::find_if(V.begin(), V.end(), [&](const PjPatch& x) { return x.address == fileVA; });
    if (it == V.end()) return;
    if (!it->orig.empty()) {
        // Live write needs the runtime VA; the image write + record use the file VA.
        if (ctx.debug.snapshot().attached())
            ctx.debug.writeMemory(fileVAtoLive(ctx, fileVA), it->orig.data(), it->orig.size());
        ctx.binary.writeImage(fileVA, it->orig.data(), it->orig.size());
    }
    V.erase(it);
    // As in applyPatchBytes: no synchronous UI listing sweep — the worker rebuilds
    // off-thread via functionsDirty_, and visible rows re-decode the restored bytes.
    pseudoVA_ = 0; decompVA_ = 0; functionsDirty_ = true;
    ++liveGen_;   // a live byte changed: invalidate the cached live decode
}

// Run the static function analysis (entry point + exports + prologue scan +
// recursive call-following) and publish the results into the side-panel list.
// Shared by the "Analyze" buttons and the auto-analysis on binary load.
void BinaryViewTab::analyzeFunctions(AppContext& ctx) {
    if (!ctx.binary.loaded() || !ctx.disasm) return;
    FunctionAnalyzer fa;
    auto found = fa.analyze(ctx.binary, *ctx.disasm);
    functions_.clear();
    functions_.reserve(found.size());
    for (auto& f : found) functions_.push_back({ f.address, f.name, f.size, false });
    fnSummary_ = fa.lastSummary();
    funcIndexDirty_ = true;   // function set changed: rebuild the sorted lookup index
    guessFunctionNames(ctx);  // give anonymous sub_ functions meaningful guessed names
    ++liveGen_;               // ...and invalidate the cached live decode (divider set)
}

// Heuristically name the anonymous (sub_<addr>) functions so the listing,
// decompiler and call sites read in plain language: a function that calls
// CreateFileW + ReadFile becomes "read_file", a one-jmp stub to an import
// becomes "j_<API>", the entry point becomes "start", and so on. Guesses are
// written into Func::name (so they flow through symbolFor everywhere) and flagged
// so the side panel can colour them; they are recomputed each analyze and never
// persisted (user renames still win and are saved separately). See FunctionNamer.
void BinaryViewTab::guessFunctionNames(AppContext& ctx) {
    guessReason_.clear();
    for (auto& f : functions_) f.guessed = false;
    if (!guessNames_ || !ctx.binary.loaded() || !ctx.disasm || functions_.empty()) return;

    std::vector<NamerInput> in;
    in.reserve(functions_.size());
    for (auto& f : functions_) in.push_back({ f.address, f.size, false, f.name });

    // Imports: an IAT-slot / import-target VA -> "dll.func". Restricted to the
    // import map so the guesser never recurses into the sub_ names we're replacing.
    auto importNameFor = [this](uint64_t va) -> std::string {
        auto it = importMap_.find(va);
        return it != importMap_.end() ? it->second : std::string();
    };
    // A printable string literal at a data address (strings_ is sorted by address).
    auto stringRefFor = [this](uint64_t va) -> std::string {
        if (strings_.empty()) return std::string();
        auto it = std::lower_bound(strings_.begin(), strings_.end(), va,
                                   [](const Strng& s, uint64_t a) { return s.address < a; });
        return (it != strings_.end() && it->address == va) ? it->text : std::string();
    };

    uint64_t entryVA = ctx.binary.entryPoint() ? ctx.binary.imageBase() + ctx.binary.entryPoint() : 0;
    FunctionNamer namer;
    auto guesses = namer.name(ctx.binary, *ctx.disasm, in, entryVA, importNameFor, stringRefFor);

    int n = 0;
    for (size_t i = 0; i < functions_.size() && i < guesses.size(); ++i) {
        if (!guesses[i].guessed) continue;
        functions_[i].name    = guesses[i].name;
        functions_[i].guessed = true;
        guessReason_[functions_[i].address] = guesses[i].reason;
        ++n;
    }
    if (n) {
        char extra[48]; std::snprintf(extra, sizeof(extra), "  (+%d named by heuristics)", n);
        fnSummary_ += extra;
    }
    funcIndexDirty_ = true;
    symCache_.clear();   // resolved names changed: drop the cache so they take effect
}

// Function containing `addr` (greatest function start <= addr), by binary search
// over a lazily-built sorted index. Replaces the per-frame linear scans of
// functions_ in symbolFor / the status bar / the live views. Returns nullptr when
// there is no function at or before the address.
const BinaryViewTab::Func* BinaryViewTab::funcContaining(uint64_t addr) {
    if (functions_.empty()) return nullptr;
    if (funcIndexDirty_) {
        funcIndex_.clear();
        funcIndex_.reserve(functions_.size());
        for (int i = 0; i < (int)functions_.size(); ++i) funcIndex_.push_back({ functions_[i].address, i });
        std::sort(funcIndex_.begin(), funcIndex_.end());
        funcIndexDirty_ = false;
    }
    // upper_bound on the address key -> first start strictly greater than addr; the
    // element before it is the greatest start <= addr.
    auto it = std::upper_bound(funcIndex_.begin(), funcIndex_.end(),
                               std::make_pair(addr, 0),
                               [](const std::pair<uint64_t,int>& a, const std::pair<uint64_t,int>& b) {
                                   return a.first < b.first;
                               });
    if (it == funcIndex_.begin()) return nullptr;
    --it;
    return &functions_[it->second];
}

// Extract printable strings: ASCII/UTF-8 runs and UTF-16LE runs (>= 4 chars).
// File mode maps offsets through offsetToVA so they line up with the disassembly;
// Live mode (stringsLive_) walks the attached process's committed memory and uses
// the region base + offset directly. Usage is cross-referenced via "Find references".
void BinaryViewTab::scanStrings(AppContext& ctx) {
    if (stringsLive_) {
        // LIVE: scan the attached process's module images OFF the render thread (reading
        // hundreds of MB via ReadProcessMemory would otherwise freeze the UI). We pick
        // the module ranges here (main module first, so module strings keep a STABLE
        // address across rescans) and hand them + a memory-reader to LiveScanService.
        DbgSnapshot snap = ctx.debug.snapshot();
        strings_.clear(); stringsScanned_ = false; stringsScanning_ = false;
        if (!snap.attached()) return;
        ProcessManager pm;
        std::vector<ModuleInfo> mods = pm.modules(snap.pid);
        const uint64_t mainBase = liveMainBase(ctx);
        std::stable_sort(mods.begin(), mods.end(), [&](const ModuleInfo& a, const ModuleInfo& b) {
            if ((a.base == mainBase) != (b.base == mainBase)) return a.base == mainBase;   // main module first
            return a.base < b.base;
        });
        std::vector<LiveRange> ranges;
        ranges.reserve(mods.size());
        for (const auto& m : mods) if (m.size) ranges.push_back({ m.base, (uint64_t)m.size });
        MemReader reader = [dbg = &ctx.debug](uint64_t va, void* out, size_t n) { return dbg->readMemoryMasked(va, out, n); };
        stringsScanning_ = true;
        stringsToken_ = ctx.livescan.requestStrings(std::move(ranges), std::move(reader), ctx.livescan.epoch());
        return;
    }
    // FILE: the image is already in memory, so scan synchronously via the shared pure
    // scanner (the same one the background worker runs on load).
    strings_.clear();
    stringsScanned_ = true;
    stringsScanning_ = false;
    if (!ctx.binary.loaded()) return;
    std::vector<StrResult> r = ScanStringsImage(ctx.binary);
    strings_.reserve(r.size());
    for (auto& s : r) strings_.push_back({ s.address, s.text, s.wide });
}

// Called once after a new binary is loaded. Lands the cursor on the entry point
// (real code, with context above it) instead of the raw first byte of the code
// section, clears state tied to the previous binary, and runs a first analysis
// so functions / names / references are ready immediately.
void BinaryViewTab::onBinaryLoaded(AppContext& ctx) {
    if (!ctx.binary.loaded()) return;
    uint64_t entry = ctx.binary.entryPoint()
                   ? ctx.binary.imageBase() + ctx.binary.entryPoint()
                   : 0;
    if (!entry) {   // DLLs/raw blobs may have no entry point: fall back to first code section
        if (const Section* s = ctx.binary.firstCodeSection())
            entry = ctx.binary.imageBase() + s->virtualAddress;
    }
    cursorVA_      = entry;
    lastAsmScroll_ = 0;          // force the Assembly view to re-center on the new cursor
    navHist_.clear(); navPos_ = -1;
    strings_.clear(); stringsScanned_ = false; stringsLive_ = false;   // strings/symbols belonged to the old image
    stringsScanning_ = false; xrefScanning_ = false;                   // drop in-flight live scans for the old image
    stringsToken_ = 0; xrefToken_ = 0;                                 // ignore any of their late results (tokens are >= 1)
    functions_.clear(); funcIndexDirty_ = true; guessReason_.clear(); fnSummary_.clear();
    algos_.clear(); algosScanned_ = false; algoSel_ = -1;   // algorithm matches belonged to the old image
    symCache_.clear();
    decompVA_ = 0; decompText_.clear();
    listBuilt_ = false;          // full-program listing belongs to the old image
    // IAT->"dll.func" map (cheap, read on the UI thread by symbolFor/dataRefToken).
    importMap_.clear();
    for (const auto& im : ctx.binary.imports()) importMap_[im.iatVA] = im.dll + "." + im.name;
    loadProjectState(ctx);       // restore saved comments/renames/bookmarks/breakpoints/notes/cursor
    // Re-apply saved patches to the in-memory image so the disassembly shows them
    // across sessions. The content hash was already cached from the pristine file
    // (above), so these writes don't change the project's sidecar key. Do this BEFORE
    // kicking off the background analysis so functions/strings reflect the patched bytes.
    for (const auto& pp : ctx.project.patches)
        if (!pp.bytes.empty()) ctx.binary.writeImage(pp.address, pp.bytes.data(), pp.bytes.size());
    // If this is a live module already analyzed by "analyze all modules", restore its
    // cached results instantly instead of re-scanning. (Files always re-analyze.)
    if (ctx.binary.isMappedImage()) {
        if (LoadedModule* am = ctx.modules.active();
            am && am->base == ctx.binary.imageBase() && am->analyzed()) {
            restoreFromModuleCache(ctx, *am);
            return;
        }
    }
    // Run string extraction + function discovery + heuristic naming + the full-program
    // listing index + the whole-program xref index on the background worker pool;
    // render() swaps the results in atomically as each pass finishes (incremental
    // delivery: strings/functions appear first, the heavier listing/xref follow). The
    // live string scan stays on the UI thread.
    uint64_t e = ctx.analysis.bumpEpoch();
    ctx.analysis.requestBulk(&ctx.binary, ctx.engine, ctx.arch,
                             K_Funcs | K_Strings | K_Listing | K_Xref | K_Intent, guessNames_, e);
}

// Restore a registry module's cached analysis (from "analyze all modules") into the
// tab's live state, so switching to an already-analyzed module is instant (no re-scan).
void BinaryViewTab::restoreFromModuleCache(AppContext& ctx, LoadedModule& m) {
    functions_.clear(); guessReason_.clear();
    functions_.reserve(m.cache.functions.size());
    for (auto& f : m.cache.functions) {
        functions_.push_back({ f.address, f.name, f.size, f.guessed });
        if (f.guessed && !f.reason.empty()) guessReason_[f.address] = f.reason;
    }
    fnSummary_      = m.cache.summary;
    funcIndexDirty_ = true;
    symCache_.clear();
    strings_.clear();
    strings_.reserve(m.cache.strings.size());
    for (auto& s : m.cache.strings) strings_.push_back({ s.address, s.text, s.wide });
    stringsScanned_ = true;
    if (m.cache.listingValid) {
        listRows_.clear();
        listRows_.reserve(m.cache.listRows.size());
        for (auto& r : m.cache.listRows) listRows_.push_back({ r.addr, r.divider, r.strData, r.strIdx });
        listInsnCount_ = m.cache.listInsnCount;
        listBuilt_     = true;
        listSig_       = listingSig(ctx);
    } else {
        listRows_.clear(); listInsnCount_ = 0; listBuilt_ = false;
    }
    if (m.cache.xref) { xrefIndex_ = *m.cache.xref; xrefIndexSig_ = xrefSig(ctx); }
    ++liveGen_;
}

// Pull persisted analysis (ctx.project, populated on load) into the tab's live
// editing state. Runs once per freshly-opened binary.
void BinaryViewTab::loadProjectState(AppContext& ctx) {
    const ProjectState& p = ctx.project;
    comments_ = p.comments;
    names_    = p.names;
    algoLabels_ = p.algorithmLabels;   // user-confirmed algorithm labels (evidence overlay)
    bookmarks_.clear();
    for (const auto& b : p.bookmarks) bookmarks_.push_back({ b.address, b.label });
    breakpoints_.clear();
    breakpoints_.insert(p.breakpoints.begin(), p.breakpoints.end());
    condBuf_.clear();
    for (const auto& kv : p.bpConditions) condBuf_[kv.first] = kv.second;
    std::snprintf(notes_, sizeof(notes_), "%s", p.notes.c_str());
    watches_ = p.watches;
    if (p.lastCursor) cursorVA_ = p.lastCursor;

    // If we're already attached, arm any saved breakpoints now.
    if (ctx.debug.snapshot().attached())
        for (uint64_t a : breakpoints_)
            if (!ctx.debug.hasBreakpoint(a)) {
                auto it = condBuf_.find(a);
                ctx.debug.addBreakpoint(a, it != condBuf_.end() ? it->second : std::string());
            }
    symCache_.clear();
    decompVA_ = 0;
    projectLoaded_ = true;
    projectDirty_  = false;   // freshly loaded: tab state matches ctx.project
}

// Mirror the tab's live editing state back into ctx.project so the App can flush
// it to the sidecar on close / exit. Cheap (annotation maps are user-sized).
void BinaryViewTab::saveProjectState(AppContext& ctx) {
    // Only mirror back once we've actually pulled this image's saved state in,
    // so an end-of-frame sync can never clobber freshly-loaded annotations.
    if (!ctx.binary.loaded() || !projectLoaded_) return;
    ProjectState& p = ctx.project;
    // Small / user-sized state: cheap to mirror every frame, so it is always current
    // for the App's flush on close/switch/exit (no dirty tracking needed).
    p.bookmarks.clear();
    for (const auto& b : bookmarks_) p.bookmarks.push_back({ b.address, b.label });
    p.breakpoints.assign(breakpoints_.begin(), breakpoints_.end());
    p.bpConditions.clear();
    for (const auto& kv : condBuf_) if (!kv.second.empty()) p.bpConditions[kv.first] = kv.second;
    p.notes = notes_;
    p.watches = watches_;
    if (cursorVA_) p.lastCursor = cursorVA_;
    // The comment / name maps can hold thousands of entries on a heavily-annotated
    // binary; deep-copying them every frame was the real cost. Only mirror them when
    // an edit actually changed them (set by the comment/rename popups + clears).
    if (projectDirty_) {
        p.comments = comments_;
        p.names    = names_;
        p.algorithmLabels = algoLabels_;
        projectDirty_ = false;
    }
    // (ctx.project.patches is written directly by the patch popup.)
}

std::string BinaryViewTab::annName(AppContext& /*ctx*/, uint64_t addr) {
    auto it = names_.find(addr);
    return (it != names_.end()) ? it->second : std::string();
}

void BinaryViewTab::navigateTo(uint64_t va) {
    if (!va) return;
    const bool live = (mainView_ == 4);   // live view cursors are runtime VAs
    // Push onto history unless we're already sitting on this exact (address, view).
    if (navPos_ < 0 || navHist_.empty() || navHist_[navPos_].va != va || navHist_[navPos_].live != live) {
        if (navPos_ >= 0 && navPos_ + 1 < (int)navHist_.size())
            navHist_.erase(navHist_.begin() + navPos_ + 1, navHist_.end());  // drop forward branch
        navHist_.push_back({ va, live });
        navPos_ = (int)navHist_.size() - 1;
    }
    cursorVA_      = va;
    lastAsmScroll_ = 0;       // re-center the static full-program listing
    followLiveRip_ = false;
}
// Restore the history entry at navPos_, switching the view to the space (live vs
// static) that entry belongs to so a runtime VA never lands in a file-VA view.
void BinaryViewTab::navBack() {
    if (navPos_ <= 0) return;
    --navPos_;
    const NavEntry& e = navHist_[navPos_];
    if (e.live) mainView_ = 4;                 // runtime entry -> live view
    else if (mainView_ == 4) mainView_ = 0;    // leaving live for a file entry -> static Assembly
    cursorVA_ = e.va; lastAsmScroll_ = 0; lastScrolledRip_ = 0; followLiveRip_ = false;
}
void BinaryViewTab::navForward() {
    if (navPos_ < 0 || navPos_ + 1 >= (int)navHist_.size()) return;
    ++navPos_;
    const NavEntry& e = navHist_[navPos_];
    if (e.live) mainView_ = 4;
    else if (mainView_ == 4) mainView_ = 0;
    cursorVA_ = e.va; lastAsmScroll_ = 0; lastScrolledRip_ = 0; followLiveRip_ = false;
}
void BinaryViewTab::gotoStatic(AppContext& ctx, uint64_t fileVA) {
    if (mainView_ == 4) liveNavigate(fileVAtoLive(ctx, fileVA));   // live view: shift to the runtime VA
    else navigateTo(fileVA);
}
void BinaryViewTab::liveNavigate(uint64_t va) { navigateTo(va); }

void BinaryViewTab::toggleBreakpoint(AppContext& ctx, uint64_t va) {
    if (!va) return;
    if (hasBreakpoint(breakpoints_, va)) {
        breakpoints_.erase(va);
        if (ctx.debug.snapshot().attached()) ctx.debug.removeBreakpoint(va);
    } else {
        breakpoints_.insert(va);
        if (ctx.debug.snapshot().attached()) ctx.debug.addBreakpoint(va);
    }
}

void BinaryViewTab::renderHoverTokens(const char* s, unsigned int col, const std::string& hl, std::string& nextHover) {
    if (!s || !s[0]) return;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 hlCol = IM_COL32(95, 120, 175, 150);
    bool first = true;
    for (size_t i = 0; s[i];) {
        bool word = std::isalnum((unsigned char)s[i]) || s[i] == '_';
        size_t j = i + 1;
        if (word) while (s[j] && (std::isalnum((unsigned char)s[j]) || s[j] == '_')) ++j;
        else      while (s[j] && !(std::isalnum((unsigned char)s[j]) || s[j] == '_')) ++j;
        std::string tok(s + i, j - i);
        if (!first) ImGui::SameLine(0, 0);
        first = false;
        ImVec2 cp = ImGui::GetCursorScreenPos();
        if (word && !hl.empty() && tok == hl) {
            ImVec2 ts = ImGui::CalcTextSize(tok.c_str());
            dl->AddRectFilled(cp, ImVec2(cp.x + ts.x, cp.y + ts.y), hlCol, 2.0f);
        }
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextUnformatted(tok.c_str());
        ImGui::PopStyleColor();
        if (word && ImGui::IsItemHovered()) nextHover = tok;
        i = j;
    }
}

void BinaryViewTab::renderLiveAssembly(AppContext& ctx) {
    DbgSnapshot snap = ctx.debug.snapshot();
    if (!snap.attached()) {
        ImGui::TextDisabled("Attach a process in the Communications tab to view live assembly.");
        return;
    }
    if (snap.state == DbgState::Terminated) {
        ImGui::TextColored(theme::col::bad(), "The debugged process has terminated.");
        return;
    }
    if (!ctx.disasm) {
        ImGui::TextDisabled("No disassembler is available.");
        return;
    }

    const bool     running = snap.state == DbgState::Running;
    const bool     paused  = snap.state == DbgState::Paused;
    const uint64_t rip     = snap.regs.rip;

    // (register-delta tracking for value highlighting now lives in render() so it stays
    //  current regardless of which view/tab is active when the user steps.)

    // Small colored toolbar button: hover tint + optional tooltip + disabled state.
    auto cbtn = [](const char* label, ImVec4 base, bool enabled, const char* tip) -> bool {
        if (!enabled) ImGui::BeginDisabled();
        ImVec4 hov(base.x * 1.3f, base.y * 1.3f, base.z * 1.3f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, base);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, base);
        bool r = ImGui::SmallButton(label);
        ImGui::PopStyleColor(3);
        if (!enabled) ImGui::EndDisabled();
        if (tip && tip[0] && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("%s", tip);
        return r;
    };
    const ImVec4 cGreen(0.18f, 0.42f, 0.24f, 1.0f);
    const ImVec4 cBlue (0.18f, 0.30f, 0.48f, 1.0f);

    // ---- Header row 1: live state pill + execution controls ----
    ImVec4 stcol = running ? theme::col::good() : paused ? theme::col::warn() : theme::col::muted();
    const char* sttext = running ? "RUNNING" : paused ? "PAUSED" : "ATTACHED";
    {
        ImVec2 dp = ImGui::GetCursorScreenPos();
        float  lh = ImGui::GetTextLineHeight();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(dp.x + 5.0f, dp.y + lh * 0.5f),
                                                    5.0f, ImGui::GetColorU32(stcol));
        ImGui::Dummy(ImVec2(14.0f, lh));
    }
    ImGui::SameLine(); ImGui::TextColored(stcol, "%s", sttext);
    ImGui::SameLine(); ImGui::TextDisabled("PID %u  TID %u", snap.pid, snap.tid);
    ImGui::SameLine(); ImGui::TextDisabled("|");
    ImGui::SameLine();
    if (cbtn(running ? "Pause" : "Continue", running ? cBlue : cGreen, true,
             running ? "Break into the process (F5)" : "Resume execution (F5)")) {
        if (running) ctx.debug.pause(); else ctx.debug.cont();
    }
    ImGui::SameLine(); if (cbtn("Into", cBlue, paused, "Step Into (F11)"))        ctx.debug.stepInto();
    ImGui::SameLine(); if (cbtn("Over", cBlue, paused, "Step Over (F10)"))        ctx.debug.stepOver();
    ImGui::SameLine(); if (cbtn("Out",  cBlue, paused, "Step Out (Shift+F11)"))   ctx.debug.stepOut();

    // ---- Header row 2: navigation + search + view mode + display toggles ----
    bool canBack = navPos_ > 0;
    bool canFwd  = navPos_ >= 0 && navPos_ + 1 < (int)navHist_.size();
    if (cbtn("<", cBlue, canBack, "Back")) navBack();
    ImGui::SameLine();
    if (cbtn(">", cBlue, canFwd, "Forward")) navForward();
    ImGui::SameLine();
    ImGui::Checkbox("Follow RIP", &followLiveRip_);
    ImGui::SameLine();
    ImGui::BeginDisabled(rip == 0);
    if (ImGui::SmallButton("Sync")) { followLiveRip_ = true; cursorVA_ = rip; lastScrolledRip_ = 0; }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("Jump to and follow RIP");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    if (ImGui::InputTextWithHint("##livegoto", "goto 0x...", gotoBuf_, sizeof(gotoBuf_),
                                 ImGuiInputTextFlags_EnterReturnsTrue)) {
        unsigned long long a = 0;
        if (std::sscanf(gotoBuf_, "%llx", &a) == 1 || std::sscanf(gotoBuf_, "0x%llx", &a) == 1)
            liveNavigate((uint64_t)a);
    }
    ImGui::SameLine(); ImGui::TextDisabled("|");
    ImGui::SameLine(); if (cbtn("Search", cBlue, true, "Search live memory (Ctrl+F)")) openFindPopup_ = true;
    ImGui::SameLine(); ImGui::TextDisabled("|");
    ImGui::SameLine(); ImGui::RadioButton("Disasm", &liveMode_, 0);
    ImGui::SameLine(); ImGui::RadioButton("Pseudo", &liveMode_, 1);
    ImGui::SameLine(); ImGui::TextDisabled("|");
    ImGui::SameLine(); ImGui::Checkbox("Regs",   &showRegBox_);
    ImGui::SameLine(); ImGui::Checkbox("Arrows", &showJumpArrows_);
    ImGui::SameLine(); ImGui::Checkbox("Hints",  &showRegHints_);
    ImGui::SameLine(); ImGui::Checkbox("Str",    &showStringComments_);
    ImGui::SameLine(); ImGui::Checkbox("Names",  &showNames_);
    if (running) { ImGui::SameLine(); ImGui::TextDisabled("(last captured)"); }
    if (!ImGui::GetIO().WantTextInput && ImGui::GetIO().KeyCtrl && !ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F))
        openFindPopup_ = true;

    ImGui::Separator();

    // ---- Resolve the focus address, then lay out: main view | register box ----
    if (followLiveRip_ && rip) cursorVA_ = rip;
    uint64_t base = cursorVA_ ? cursorVA_ : rip;
    if (base == 0) {
        ImGui::TextDisabled("Waiting for the first debug event. Press Pause if the process is running.");
        renderLiveSearchPopup(ctx);
        return;
    }

    const float boxW = 252.0f;
    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImGui::BeginChild("livemain", ImVec2(showRegBox_ ? avail.x - boxW - 8.0f : 0.0f, 0), ImGuiChildFlags_None);
    if (liveMode_ == 1) renderLivePseudocode(ctx, snap, base);
    else                renderLiveListing(ctx, snap, base);
    ImGui::EndChild();

    if (showRegBox_) {
        ImGui::SameLine();
        ImGui::BeginChild("liveregbox", ImVec2(boxW, 0), ImGuiChildFlags_Borders);
        renderRegisterBox(ctx, snap);
        ImGui::EndChild();
    }

    renderLiveSearchPopup(ctx);
}

void BinaryViewTab::renderLiveListing(AppContext& ctx, DbgSnapshot& snap, uint64_t base) {
    const uint64_t rip = snap.regs.rip;
    // Back up the window so the focus (RIP when following, or the navigated cursor)
    // isn't pinned to the very top - you can see the code above it too. Anchor to
    // the nearest analyzed function start (translated to the runtime base for ASLR)
    // so the leading context decodes from a real instruction boundary.
    uint64_t lanchor = 0;
    if (const Func* nf = funcContaining(liveVAtoFile(ctx, base))) {
        uint64_t fl = fileVAtoLive(ctx, nf->address);   // nearest analyzed start, runtime base
        if (fl <= base && base - fl <= 128) lanchor = fl;
    }
    IDisassembler* dis = liveDecoder(ctx, snap.is32);   // match the debuggee's bitness (x86 for WOW64)
    uint64_t start = alignWindowStart(ctx.debug, *dis, base, 128, lanchor);

    // The live decode is cached. Re-reading process memory and re-disassembling 256
    // instructions (plus rebuilding the address index and function-divider set) on
    // every frame churned the heap, and the working set climbed steadily while
    // attached. Rebuild only when the window start, RIP (catches stepping and
    // self-modifying code), a live write/patch/re-analyze (liveGen_), the function
    // set, or the target process changes.
    uint64_t liveSig = start ^ (rip * 0x9E3779B97F4A7C15ull)
                     ^ ((uint64_t)liveGen_ << 1) ^ ((uint64_t)functions_.size() << 17)
                     ^ ((uint64_t)symPid_ << 33);
    if (liveSig != liveCacheSig_ || liveCacheStart_ != start || liveInsns_.empty()) {
        if (liveBuf_.size() < 4096) liveBuf_.resize(4096);   // reused scratch; never realloc'd per frame
        size_t got = ctx.debug.readMemoryMasked(start, liveBuf_.data(), 4096);   // mask our 0xCC bps -> real instructions
        if (!got) {
            ImGui::TextColored(theme::col::bad(), "Could not read process memory at 0x%llX.", (unsigned long long)start);
            return;   // leave the previous cache intact rather than poisoning it with an empty decode
        }
        liveInsns_ = dis->disassemble(liveBuf_.data(), got, start, 256);

        liveIdxOf_.clear();
        liveIdxOf_.reserve(liveInsns_.size() * 2);
        for (int i = 0; i < (int)liveInsns_.size(); ++i) liveIdxOf_[liveInsns_[i].address] = i;

        // Function starts: in-window call targets + analyzed functions + the containing
        // module's exports -> a "sub_X" divider is printed before each one.
        liveFuncSet_.clear();
        for (const auto& in : liveInsns_) if (in.isCall && in.branchTarget) liveFuncSet_.insert(in.branchTarget);
        for (const auto& f : functions_) liveFuncSet_.insert(fileVAtoLive(ctx, f.address));   // file-base -> runtime base (ASLR)
        if (symAttached_) {
            if (liveModulesPid_ != symPid_ || liveModules_.empty()) {
                ProcessManager pm; liveModules_ = pm.modules(symPid_); liveModulesPid_ = symPid_;
            }
            for (const auto& m : liveModules_)
                if (start >= m.base && start < m.base + m.size) {
                    auto it = modExports_.find(m.base);
                    if (it == modExports_.end()) {
                        std::vector<std::pair<uint64_t, std::string>> ex;
                        parseExports(ctx.debug, m.base, ex);
                        std::sort(ex.begin(), ex.end());
                        it = modExports_.emplace(m.base, std::move(ex)).first;
                    }
                    for (const auto& e : it->second) liveFuncSet_.insert(e.first);
                    break;
                }
        }
        liveCacheStart_ = start; liveCacheSig_ = liveSig;
    }
    if (liveInsns_.empty()) {
        ImGui::TextDisabled("No instructions decoded at 0x%llX.", (unsigned long long)start);
        return;
    }

    // Alias the cached members so the render loop below reads unchanged.
    auto& insns   = liveInsns_;
    auto& idxOf   = liveIdxOf_;
    auto& funcSet = liveFuncSet_;

    std::vector<float> rowY(insns.size(), -1.0f);
    float laneX0 = 0.0f, addrX = 0.0f;
    bool  gotLaneX = false, gotAddrX = false;

    ui::PushMono();
    ImVec2 tableMin   = ImGui::GetCursorScreenPos();
    ImVec2 tableAvail = ImGui::GetContentRegionAvail();
    if (ImGui::BeginTable("live_asm", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("bp",      ImGuiTableColumnFlags_WidthFixed, 22);
        ImGui::TableSetupColumn("flow",    ImGuiTableColumnFlags_WidthFixed, 36);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Bytes",   ImGuiTableColumnFlags_WidthFixed, 188);
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        // Divider row printed before a function's first instruction.
        auto emitFuncHeader = [&](uint64_t addr) {
            ImGui::TableNextRow();
            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(theme::col::accent().x, theme::col::accent().y, theme::col::accent().z, 0.18f)));
            std::string nm = symbolFor(ctx, addr);
            if (nm.empty() || nm.find("+0x") != std::string::npos) { char b[28]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)addr); nm = b; }
            ImGui::TableSetColumnIndex(2); ImGui::TextColored(theme::col::muted(), "0x%llX", (unsigned long long)addr);
            ImGui::TableSetColumnIndex(4); ImGui::TextColored(theme::col::accent(), "%s:", nm.c_str());
        };

        const std::string hoverTok = hoverToken_;   // highlight matches of last frame's hovered token
        std::string nextHoverTok;
        float lh = ImGui::GetTextLineHeight();
        for (int i = 0; i < (int)insns.size(); ++i) {
            const auto& in = insns[i];
            if (i > 0 && funcSet.count(in.address)) emitFuncHeader(in.address);
            ImGui::TableNextRow();
            ImGui::PushID((void*)(uintptr_t)in.address);

            bool rowAtRip = rip == in.address;
            bool rowSel   = in.address == cursorVA_ && !rowAtRip;
            bool rowMulti = selVAs_.size() > 1 && !rowAtRip && !rowSel && selVAs_.count(in.address);
            if (rowAtRip) {
                float p = slowPulse();   // slow green flash on the current instruction
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.16f, 0.42f, 0.21f, 0.40f + 0.38f * p)));
            } else if (rowSel) {
                float p = slowPulse();   // slow blue flash on the focused line
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.20f, 0.32f, 0.54f, 0.30f + 0.34f * p)));
            } else if (rowMulti) {       // muted highlight for a multi-line selection
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.20f, 0.28f, 0.42f, 0.45f)));
            }

            // col 0: breakpoint gutter (merged: snapshot OR pending/local list, so it updates instantly)
            ImGui::TableSetColumnIndex(0);
            bool bp = hasBreakpoint(snap, in.address) || hasBreakpoint(breakpoints_, in.address);
            ImGui::PushStyleColor(ImGuiCol_Text, theme::col::bad());
            if (ImGui::Selectable(bp ? "*" : " ", false, ImGuiSelectableFlags_None, ImVec2(0, 0))) {
                if (bp) {
                    ctx.debug.removeBreakpoint(in.address);
                    breakpoints_.erase(in.address);
                } else {
                    ctx.debug.addBreakpoint(in.address);
                    breakpoints_.insert(in.address);
                }
            }
            ImGui::PopStyleColor();

            // col 1: flow gutter (arrows are drawn after the table)
            ImGui::TableSetColumnIndex(1);
            if (!gotLaneX) { laneX0 = ImGui::GetCursorScreenPos().x; gotLaneX = true; }
            ImGui::Dummy(ImVec2(1.0f, lh));
            rowY[i] = (ImGui::GetItemRectMin().y + ImGui::GetItemRectMax().y) * 0.5f;

            // col 2: address
            ImGui::TableSetColumnIndex(2);
            if (!gotAddrX) { addrX = ImGui::GetCursorScreenPos().x; gotAddrX = true; }
            bool hwbp = std::any_of(snap.hwBreakpoints.begin(), snap.hwBreakpoints.end(),
                                    [&](const HwBreakpointInfo& h) { return h.address == in.address; });
            char addrLbl[48];
            std::snprintf(addrLbl, sizeof(addrLbl), "%s0x%llX",
                          rowAtRip ? "> " : "  ", (unsigned long long)in.address);
            ImVec4 acol = rowAtRip ? theme::col::good()
                        : hwbp     ? ImVec4(0.95f, 0.6f, 0.95f, 1.0f)
                                   : ImGui::GetStyleColorVec4(ImGuiCol_Text);
            ImGui::PushStyleColor(ImGuiCol_Text, acol);
            if (ImGui::Selectable(addrLbl, false)) {
                ImGuiIO& io = ImGui::GetIO();
                if (io.KeyShift && selAnchorVA_) {           // range from the anchor over the live insns
                    uint64_t a = selAnchorVA_, b = in.address; if (a > b) { uint64_t t = a; a = b; b = t; }
                    selVAs_.clear();
                    for (const auto& q : insns) if (q.address >= a && q.address <= b) selVAs_.insert(q.address);
                } else if (io.KeyCtrl) {                      // toggle this line in/out of the selection
                    if (selVAs_.count(in.address)) selVAs_.erase(in.address); else selVAs_.insert(in.address);
                    selAnchorVA_ = in.address;
                } else {                                      // plain click: single select + new anchor
                    selVAs_.clear(); selVAs_.insert(in.address); selAnchorVA_ = in.address;
                }
                cursorVA_ = in.address; followLiveRip_ = false;
            }
            ImGui::PopStyleColor();
            if (in.address == base && base != lastScrolledRip_) {
                ImGui::SetScrollHereY(0.4f);   // center the focus line (RIP or navigated cursor)
                lastScrolledRip_ = base;
            }
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && in.branchTarget)
                liveNavigate(in.branchTarget);
            if (ImGui::BeginPopupContextItem("live_ictx")) {
                const bool inSel = selVAs_.size() > 1 && selVAs_.count(in.address);
                if (inSel) { liveSelectionMenu(ctx, snap); ImGui::Separator(); }
                if (ImGui::MenuItem("Run to cursor")) ctx.debug.runToCursor(in.address);
                if (in.branchTarget && ImGui::MenuItem("Follow target")) liveNavigate(in.branchTarget);
                ImGui::Separator();
                bool swbp = hasBreakpoint(snap, in.address) || hasBreakpoint(breakpoints_, in.address);
                if (ImGui::MenuItem("Software breakpoint", nullptr, swbp)) {
                    if (swbp) { ctx.debug.removeBreakpoint(in.address);
                                breakpoints_.erase(in.address); }
                    else { ctx.debug.addBreakpoint(in.address);
                           breakpoints_.insert(in.address); }
                }
                if (ImGui::MenuItem("Set breakpoint condition...")) {
                    annPopupVA_ = in.address;
                    auto it = condBuf_.find(in.address);
                    std::snprintf(condPopupBuf_, sizeof(condPopupBuf_), "%s", it != condBuf_.end() ? it->second.c_str() : "");
                    openCondPopup_ = true;
                }
                {   // Hardware breakpoint (DR0-DR3): execute, or data write / read-write.
                    HwKind curKind = HwKind::Execute; bool hasHw = false;
                    for (const auto& h : snap.hwBreakpoints) if (h.address == in.address) { curKind = h.kind; hasHw = true; break; }
                    if (ImGui::BeginMenu("Hardware breakpoint (DR)")) {
                        if (ImGui::MenuItem("Execute", nullptr, hasHw && curKind == HwKind::Execute)) {
                            ctx.debug.removeHardwareBreakpoint(in.address);
                            if (!(hasHw && curKind == HwKind::Execute)) ctx.debug.addHardwareBreakpoint(in.address, HwKind::Execute, 1);
                        }
                        ImGui::Separator();
                        ImGui::TextDisabled("data length"); ImGui::SameLine();
                        ImGui::RadioButton("1", &hwSizeSel_, 1); ImGui::SameLine();
                        ImGui::RadioButton("2", &hwSizeSel_, 2); ImGui::SameLine();
                        ImGui::RadioButton("4", &hwSizeSel_, 4); ImGui::SameLine();
                        ImGui::RadioButton("8", &hwSizeSel_, 8);
                        if (ImGui::MenuItem("Break on write", nullptr, hasHw && curKind == HwKind::Write)) {
                            ctx.debug.removeHardwareBreakpoint(in.address);
                            ctx.debug.addHardwareBreakpoint(in.address, HwKind::Write, (uint8_t)hwSizeSel_);
                        }
                        if (ImGui::MenuItem("Break on read/write", nullptr, hasHw && curKind == HwKind::ReadWrite)) {
                            ctx.debug.removeHardwareBreakpoint(in.address);
                            ctx.debug.addHardwareBreakpoint(in.address, HwKind::ReadWrite, (uint8_t)hwSizeSel_);
                        }
                        if (hasHw && ImGui::MenuItem("Remove")) ctx.debug.removeHardwareBreakpoint(in.address);
                        ImGui::EndMenu();
                    }
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Patch (asm / bytes)...")) {
                    patchVA_ = in.address; patchLen_ = in.length;
                    std::snprintf(patchHex_, sizeof(patchHex_), "%s", in.bytes.c_str());
                    std::snprintf(patchAsmText_, sizeof(patchAsmText_), "%s %s", in.mnemonic.c_str(), in.operands.c_str());
                    patchAsm_.clear(); patchStatus_.clear(); openPatchPopup_ = true;
                }
                if (ImGui::MenuItem("NOP instruction")) {
                    // Route through applyPatchBytes so the patch is recorded (revertable
                    // via Save Binary As / Patches tab), the in-memory image is updated,
                    // and BOTH the pseudocode and decompiler caches are invalidated -
                    // matching the static listing's NOP behavior.
                    uint32_t len = in.length ? in.length : 1;
                    applyPatchBytes(ctx, in.address, std::vector<uint8_t>(len, 0x90), len, false);
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Copy address")) {
                    char cb[32]; std::snprintf(cb, sizeof(cb), "0x%llX", (unsigned long long)in.address);
                    ImGui::SetClipboardText(cb);
                }
                if (!inSel) emitInstrCopyMenu(in);   // selection menu already offers these when multi-selecting
                ImGui::Separator();
                if (ImGui::MenuItem("Find references to this address")) startXrefSearch(ctx, in.address);
                if (uint64_t ref = instrDataRef(in))
                    if (ImGui::MenuItem("Find references to operand target")) startXrefSearch(ctx, ref);
                ImGui::Separator();
                // Annotations persist under the FILE va; translate from the runtime
                // address so renames/comments line up with the static view under ASLR.
                uint64_t annVA = liveVAtoFile(ctx, in.address);
                if (ImGui::MenuItem("Rename symbol...")) {
                    annPopupVA_ = annVA;
                    std::string n = annName(ctx, annVA);
                    std::snprintf(renameBuf_, sizeof(renameBuf_), "%s", n.c_str());
                    openRenamePopup_ = true;
                }
                if (ImGui::MenuItem("Set comment...")) {
                    annPopupVA_ = annVA;
                    auto cit = comments_.find(annVA);
                    std::snprintf(commentBuf_, sizeof(commentBuf_), "%s", cit != comments_.end() ? cit->second.c_str() : "");
                    openCommentPopup_ = true;
                }
                ImGui::Separator();
                // annVA is the FILE va (liveVAtoFile above); bookmarks persist as file VAs, so
                // a live-view bookmark lines up with the static listing and survives ASLR.
                if (ImGui::MenuItem("Add bookmark here")) bookmarks_.push_back({ annVA, "bookmark" });
                ImGui::EndPopup();
            }

            // col 3: raw bytes
            ImGui::TableSetColumnIndex(3);
            ImGui::TextDisabled("%s", in.bytes.c_str());

            // col 4: mnemonic + operands (+ clickable target, + reg hints on the RIP row)
            ImGui::TableSetColumnIndex(4);
            ImVec4 mcol = in.isCall   ? theme::col::call()
                        : in.isBranch ? theme::col::branch()
                                      : ImVec4(0.90f, 0.90f, 0.90f, 1.0f);
            {   // mnemonic (one hover-highlightable token)
                ImVec2 cp = ImGui::GetCursorScreenPos();
                if (!hoverTok.empty() && in.mnemonic == hoverTok)
                    ImGui::GetWindowDrawList()->AddRectFilled(cp,
                        ImVec2(cp.x + ImGui::CalcTextSize(in.mnemonic.c_str()).x, cp.y + ImGui::GetTextLineHeight()),
                        IM_COL32(95, 120, 175, 150), 2.0f);
                ImGui::TextColored(mcol, "%-7s", in.mnemonic.c_str());
                if (ImGui::IsItemHovered()) nextHoverTok = in.mnemonic;
            }
            ImGui::SameLine(0, 0);
            renderHoverTokens(in.operands.c_str(), ImGui::GetColorU32(ImVec4(0.90f, 0.90f, 0.90f, 1.0f)), hoverTok, nextHoverTok);
            if (in.branchTarget) {
                ImGui::SameLine();
                ImGui::TextColored(theme::col::muted(), "; 0x%llX", (unsigned long long)in.branchTarget);
                if (ImGui::IsItemHovered()) {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) liveNavigate(in.branchTarget);
                }
                if (showNames_) {
                    std::string nm = symbolFor(ctx, in.branchTarget);
                    if (!nm.empty()) { ImGui::SameLine(0, 6); ImGui::TextColored(theme::col::call(), "%s", nm.c_str()); }
                }
            }
            if (showRegHints_ && rowAtRip) {
                std::string hint = regHints(in, snap.regs, &ctx.debug);
                if (!hint.empty()) {
                    ImGui::SameLine();
                    ImGui::TextColored(theme::col::accent(), "  ; %s", hint.c_str());
                }
            }
            // At the paused instruction: if it's a conditional branch, say whether the
            // current flags make it jump or fall through (x86/x64; -1 = not conditional).
            if (rowAtRip && snap.state == DbgState::Paused && in.isBranch && !in.isCall && !in.isRet) {
                int t = evalCondBranch(in.mnemonic, snap.regs.rflags, snap.regs, snap.is32);
                if (t == 1) {
                    ImGui::SameLine(); ImGui::TextColored(theme::col::good(), "  -> will jump");
                } else if (t == 0) {
                    ImGui::SameLine(); ImGui::TextColored(theme::col::muted(), "  -> falls through");
                }
            }
            // x64dbg-style inline string/data comment for a referenced address.
            // Memoized per stop (liveStopKey): the live listing renders ~256 rows with
            // no clipper, so resolving this every frame meant 1-2 debuggee readMemory()s
            // per data-referencing row, every frame, while paused.
            if (showStringComments_) {
                uint64_t ref = instrDataRef(in);
                if (!ref) ref = instrImmRef(in);   // also catch `mov reg, offset str` / `push offset str`
                if (ref) {
                    uint64_t sk = liveStopKey(snap);
                    if (sk != strCmtCacheKey_) { strCmtCache_.clear(); strCmtCacheKey_ = sk; }
                    auto it = strCmtCache_.find(ref);
                    if (it == strCmtCache_.end()) {
                        std::string cmt;
                        uint8_t tmp[80]; size_t g = ctx.debug.readMemory(ref, tmp, sizeof(tmp));
                        std::string s = resolveString(tmp, g);
                        if (!s.empty()) {
                            char b[80]; std::snprintf(b, sizeof(b), "  ; \"%.50s\"", s.c_str());
                            cmt = b;
                        } else if (g >= (size_t)(snap.is32 ? 4 : 8)) {
                            // The slot may hold a char* (e.g. mov reg,[rip+x]); follow one
                            // level and show the pointed-to string if there is one. Honour the
                            // target pointer width so a 32-bit (WOW64) target doesn't drag
                            // adjacent bytes into the high dword and follow a bogus address.
                            uint64_t p = 0; std::memcpy(&p, tmp, snap.is32 ? 4 : 8);
                            if (p >= 0x10000) {
                                uint8_t tmp2[80]; size_t g2 = ctx.debug.readMemory(p, tmp2, sizeof(tmp2));
                                std::string s2 = resolveString(tmp2, g2);
                                if (!s2.empty()) { char b[80]; std::snprintf(b, sizeof(b), "  ; -> \"%.50s\"", s2.c_str()); cmt = b; }
                            }
                        }
                        it = strCmtCache_.emplace(ref, std::move(cmt)).first;
                    }
                    if (!it->second.empty()) {
                        ImGui::SameLine();
                        ImGui::TextColored(ImVec4(0.80f, 0.72f, 0.45f, 1.0f), "%s", it->second.c_str());
                    }
                }
            }
            // User comment (persisted in the project), mirroring the static listing
            // so annotations carry over between the static and live views. Keyed by
            // the file VA, so translate from the runtime address under ASLR.
            if (auto cit = comments_.find(liveVAtoFile(ctx, in.address)); cit != comments_.end() && !cit->second.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "  ; %s", cit->second.c_str());
            }
            ImGui::PopID();
        }
        hoverToken_ = nextHoverTok;   // remember for next frame's highlight
        ImGui::EndTable();
    }
    ui::PopMono();

    // ---- Branch arrows in the flow gutter (drawn over the listing) ----
    if (showJumpArrows_ && gotLaneX && gotAddrX) {
        ImVec2 clipMin = tableMin;
        ImVec2 clipMax = ImVec2(tableMin.x + tableAvail.x, tableMin.y + tableAvail.y);
        float firstY = clipMax.y, lastY = clipMin.y;
        for (float y : rowY) if (y >= 0) { firstY = std::min(firstY, y); lastY = std::max(lastY, y); }

        ImDrawList* dl = ImGui::GetForegroundDrawList();
        dl->PushClipRect(clipMin, clipMax, true);
        const float laneBase = laneX0 + 3.0f;
        const float xTip     = addrX - 4.0f;

        struct Arr { float y0, y1; bool toWin, up; ImU32 col; };
        std::vector<Arr> arrs;
        arrs.reserve(insns.size());
        for (int i = 0; i < (int)insns.size(); ++i) {
            const auto& in = insns[i];
            if (!in.isBranch || in.isCall || !in.branchTarget || rowY[i] < 0) continue;
            auto it = idxOf.find(in.branchTarget);
            bool active = (in.address == rip) || (it != idxOf.end() && insns[it->second].address == rip);
            ImU32 col = active                         ? IM_COL32(120, 220, 120, 235)
                      : (in.branchTarget < in.address) ? IM_COL32(220, 170,  90, 210)   // backward
                                                       : IM_COL32(110, 170, 230, 210);  // forward
            Arr a; a.col = col; a.y0 = rowY[i];
            if (it != idxOf.end() && rowY[it->second] >= 0) {
                a.toWin = true; a.up = false; a.y1 = rowY[it->second];
            } else {
                a.toWin = false; a.up = in.branchTarget < start;
                a.y1 = a.up ? firstY - 8.0f : lastY + 8.0f;
            }
            arrs.push_back(a);
        }
        std::sort(arrs.begin(), arrs.end(),
                  [](const Arr& a, const Arr& b) { return std::min(a.y0, a.y1) < std::min(b.y0, b.y1); });
        std::vector<float> laneBot;
        for (const Arr& a : arrs) {
            float top = std::min(a.y0, a.y1), bot = std::max(a.y0, a.y1);
            int lane = -1;
            for (int L = 0; L < (int)laneBot.size(); ++L) if (laneBot[L] < top - 2.0f) { lane = L; break; }
            if (lane < 0) { lane = (int)laneBot.size(); laneBot.push_back(bot); }
            else laneBot[lane] = bot;
            float xb = laneBase + (lane > 7 ? 7 : lane) * 4.0f;   // gutter is 36px: 3px base + up to 7 lanes * 4px
            dl->AddLine(ImVec2(xTip, a.y0), ImVec2(xb, a.y0), a.col, 1.6f);
            dl->AddLine(ImVec2(xb, a.y0), ImVec2(xb, a.y1), a.col, 1.6f);
            if (a.toWin) {
                dl->AddLine(ImVec2(xb, a.y1), ImVec2(xTip, a.y1), a.col, 1.6f);
                dl->AddTriangleFilled(ImVec2(xTip - 5, a.y1 - 4), ImVec2(xTip - 5, a.y1 + 4),
                                      ImVec2(xTip + 1, a.y1), a.col);
            } else if (a.up) {
                dl->AddTriangleFilled(ImVec2(xb - 4, a.y1 + 6), ImVec2(xb + 4, a.y1 + 6), ImVec2(xb, a.y1), a.col);
            } else {
                dl->AddTriangleFilled(ImVec2(xb - 4, a.y1 - 6), ImVec2(xb + 4, a.y1 - 6), ImVec2(xb, a.y1), a.col);
            }
        }
        dl->PopClipRect();
    }

    // Follow jumps from the keyboard: Enter follows the selected instruction's
    // branch/call target; Backspace walks the navigation history back.
    if (!ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter)) {
            auto it = idxOf.find(cursorVA_);
            if (it != idxOf.end() && insns[it->second].branchTarget) liveNavigate(insns[it->second].branchTarget);
        }
        if (ImGui::IsKeyPressed(ImGuiKey_Backspace)) navBack();
    }
}

// Per-stop memo key shared by the live-view caches: a hash of the whole register
// snapshot + the live-edit generation + run state. A step, a re-stop (even at the
// same RIP, e.g. a breakpoint in a loop), or any register/memory edit changes it.
uint64_t BinaryViewTab::liveStopKey(const DbgSnapshot& snap) const {
    const Registers& rr = snap.regs;
    uint64_t key = 1469598103934665603ull;
    auto mix = [&key](uint64_t x) { key = (key ^ x) * 1099511628211ull; };
    mix(rr.rip); mix(rr.rsp); mix(rr.rbp); mix(rr.rflags);
    mix(rr.rax); mix(rr.rbx); mix(rr.rcx); mix(rr.rdx); mix(rr.rsi); mix(rr.rdi);
    mix(rr.r8);  mix(rr.r9);  mix(rr.r10); mix(rr.r11);
    mix(rr.r12); mix(rr.r13); mix(rr.r14); mix(rr.r15);
    mix((uint64_t)liveGen_); mix((uint64_t)snap.state);
    return key;
}

std::string BinaryViewTab::describePointer(AppContext& ctx, const DbgSnapshot& snap, uint64_t v) {
    if (v < 0x1000) return std::string();                 // null / small immediates aren't pointers

    // Memoize per stop. This runs for every register and stack slot, every frame, while
    // paused - and the symbol path (symbolFor) can hit DbgHelp/PDB loads. While the
    // debuggee is paused the inputs are frozen, so cache by a hash of the whole register
    // snapshot + the live-edit generation: a step, a re-stop (even at the same RIP, e.g. a
    // breakpoint in a loop), or any register/memory edit changes the key and clears it,
    // but repeated render frames at the same stop are O(1) lookups. Negatives are cached
    // too (most values aren't pointers), so non-pointer rows cost one map probe per frame.
    uint64_t key = liveStopKey(snap);
    if (key != ptrDescCacheKey_) { ptrDescCache_.clear(); ptrDescCacheKey_ = key; }
    if (auto it = ptrDescCache_.find(v); it != ptrDescCache_.end()) return it->second;

    std::string result;
    const int memW = snap.is32 ? 4 : 8;                   // honour target pointer width
    uint8_t buf[80];
    size_t g = ctx.debug.readMemory(v, buf, sizeof(buf));
    // 1) Does it point straight at a readable string?
    if (g) {
        std::string s = resolveString(buf, g);
        if (!s.empty()) { if (s.size() > 40) s.resize(40); result = "\"" + s + "\""; }
    }
    // 2) Does it point at a known function/import/export?
    if (result.empty()) {
        std::string sym = symbolFor(ctx, liveVAtoFile(ctx, v));
        if (!sym.empty()) result = sym;
    }
    // 3) One pointer-hop (a char**): follow and show the pointed-to string if any.
    if (result.empty() && (size_t)g >= (size_t)memW) {
        uint64_t p = 0; std::memcpy(&p, buf, memW);
        if (p >= 0x1000) {
            uint8_t buf2[80];
            size_t g2 = ctx.debug.readMemory(p, buf2, sizeof(buf2));
            if (g2) {
                std::string s2 = resolveString(buf2, g2);
                if (!s2.empty()) { if (s2.size() > 40) s2.resize(40); result = "-> \"" + s2 + "\""; }
            }
        }
    }
    ptrDescCache_[v] = result;
    return result;
}

void BinaryViewTab::renderRegisterBox(AppContext& ctx, DbgSnapshot& snap) {
    const Registers& r = snap.regs;
    const bool is32 = snap.is32;   // 32-bit (WOW64) target: e* names, 4-byte stack
    const bool paused = snap.state == DbgState::Paused;   // memory previews only meaningful while paused
    auto chg = [&](uint64_t Registers::* f) { return haveTwoStops_ && (r.*f != regsAtPrevStop_.*f); };
    const ImVec4 valCol(0.86f, 0.88f, 0.92f, 1.0f);

    ImGui::TextColored(theme::col::accent(), "Registers");
    ImGui::SameLine(); ImGui::TextDisabled("TID %u%s", snap.tid, is32 ? "  (32-bit)" : "");
    ImGui::Separator();

    ui::PushMono();
    // Left-click a register/stack value to follow it; right-click to copy.
    auto copyVal = [](uint64_t v, bool prefix) {
        char b[24]; std::snprintf(b, sizeof(b), prefix ? "0x%llX" : "%016llX", (unsigned long long)v);
        ImGui::SetClipboardText(b);
    };
    auto row = [&](const char* n, uint64_t Registers::* f) {
        uint64_t v = r.*f;
        if (is32) v &= 0xFFFFFFFFull;   // WOW64 regs are zero-extended already; mask anyway for parity with describePointer/display
        ImGui::PushID(n);
        ImGui::TextColored(theme::col::muted(), "%-3s", n);
        ImGui::SameLine(0, 6);
        if (is32) ImGui::TextColored(chg(f) ? theme::col::warn() : valCol, "%08llX", (unsigned long long)(v & 0xFFFFFFFFull));
        else      ImGui::TextColored(chg(f) ? theme::col::warn() : valCol, "%016llX", (unsigned long long)v);
        if (ImGui::IsItemHovered()) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))  liveNavigate(v);
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) ImGui::OpenPopup("rmenu");
        }
        if (ImGui::BeginPopup("rmenu")) {
            if (ImGui::MenuItem("Follow in disassembly")) liveNavigate(v);
            if (ImGui::MenuItem("Copy value"))    copyVal(v, false);
            if (ImGui::MenuItem("Copy 0x value")) copyVal(v, true);
            ImGui::EndPopup();
        }
        if (paused) {   // annotate what the register points at (string / symbol)
            std::string desc = describePointer(ctx, snap, v);
            if (!desc.empty()) { ImGui::SameLine(0, 8); ImGui::TextColored(theme::col::muted(), "%.48s", desc.c_str()); }
        }
        ImGui::PopID();
    };
    if (is32) {
        row("EAX", &Registers::rax); row("EBX", &Registers::rbx);
        row("ECX", &Registers::rcx); row("EDX", &Registers::rdx);
        row("ESI", &Registers::rsi); row("EDI", &Registers::rdi);
        row("EBP", &Registers::rbp); row("ESP", &Registers::rsp);
        ImGui::Separator();
        row("EIP", &Registers::rip);
    } else {
        row("RAX", &Registers::rax); row("RBX", &Registers::rbx);
        row("RCX", &Registers::rcx); row("RDX", &Registers::rdx);
        row("RSI", &Registers::rsi); row("RDI", &Registers::rdi);
        row("RBP", &Registers::rbp); row("RSP", &Registers::rsp);
        row("R8",  &Registers::r8);  row("R9",  &Registers::r9);
        row("R10", &Registers::r10); row("R11", &Registers::r11);
        row("R12", &Registers::r12); row("R13", &Registers::r13);
        row("R14", &Registers::r14); row("R15", &Registers::r15);
        ImGui::Separator();
        row("RIP", &Registers::rip);
    }
    ImGui::TextColored(theme::col::muted(), "RFL"); ImGui::SameLine(0, 6);
    ImGui::TextColored(chg(&Registers::rflags) ? theme::col::warn() : valCol, "%08llX",
                       (unsigned long long)(r.rflags & 0xFFFFFFFFull));
    ui::PopMono();

    auto flag = [&](const char* n, int bit) {
        bool on = (r.rflags >> bit) & 1ull;
        ImGui::TextColored(on ? theme::col::good() : theme::col::muted(), "%s", n);
        ImGui::SameLine(0, 6);
    };
    flag("ZF", 6); flag("CF", 0); flag("SF", 7); flag("OF", 11); ImGui::NewLine();
    flag("PF", 2); flag("AF", 4); flag("DF", 10); ImGui::NewLine();

    ImGui::Separator();
    ImGui::TextColored(theme::col::muted(), is32 ? "Stack (ESP)" : "Stack (RSP)");
    ui::PushMono();
    const int slot = is32 ? 4 : 8;
    for (int i = 0; i < 12; ++i) {
        uint64_t addr = r.rsp + (uint64_t)i * slot, val = 0;
        size_t g = ctx.debug.readMemory(addr, &val, slot);
        ImGui::PushID(i);
        if (g == (size_t)slot) {
            if (is32) ImGui::Text("%04llX %08llX", (unsigned long long)(addr & 0xFFFF), (unsigned long long)(val & 0xFFFFFFFFull));
            else      ImGui::Text("%04llX %016llX", (unsigned long long)(addr & 0xFFFF), (unsigned long long)val);
            if (ImGui::IsItemHovered()) {
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))  liveNavigate(val);
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) ImGui::OpenPopup("smenu");
            }
            if (ImGui::BeginPopup("smenu")) {
                if (ImGui::MenuItem("Follow value"))   liveNavigate(val);
                if (ImGui::MenuItem("Copy value"))     copyVal(val, true);
                if (ImGui::MenuItem("Copy address"))   copyVal(addr, true);
                ImGui::EndPopup();
            }
            if (paused) {   // annotate what the stack slot points at (string / symbol)
                std::string desc = describePointer(ctx, snap, val);
                if (!desc.empty()) { ImGui::SameLine(0, 8); ImGui::TextColored(theme::col::muted(), "%.40s", desc.c_str()); }
            }
        } else {
            ImGui::TextDisabled("%04llX  ????", (unsigned long long)(addr & 0xFFFF));
        }
        ImGui::PopID();
    }
    ui::PopMono();
}

void BinaryViewTab::renderLivePseudocode(AppContext& ctx, DbgSnapshot& snap, uint64_t start) {
    // Scope to the function enclosing `start`. Analyzed function bounds are file-base
    // VAs, so translate them to the runtime base (ASLR) to pick the right function and
    // decompile exactly it - not an open-ended window that runs into the next function.
    uint64_t fnStartLive = start;
    uint32_t fnSize = 0;
    // The file<->live base delta is constant, so file-space ordering matches live
    // ordering: query the index in file space, then translate the result back.
    const Func* best = funcContaining(liveVAtoFile(ctx, start));
    if (best && start - fileVAtoLive(ctx, best->address) < 0x4000) {
        fnStartLive = fileVAtoLive(ctx, best->address);
        fnSize      = best->size;
    }

    ImGui::TextColored(theme::col::accent(), "Pseudocode");
    ImGui::SameLine();
    {
        std::string nm = symbolFor(ctx, fnStartLive);
        if (nm.empty()) { char b[28]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)fnStartLive); nm = b; }
        ImGui::TextDisabled("%s", nm.c_str());
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) pseudoVA_ = 0;
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy") && !pseudoText_.empty()) ImGui::SetClipboardText(pseudoText_.c_str());
    ImGui::Separator();

    if (pseudoVA_ != fnStartLive || pseudoText_.empty()) {
        size_t win = fnSize ? (size_t)std::min<uint32_t>(fnSize + 16u, 16384u) : 4096u;
        std::vector<uint8_t> buf(win);
        size_t got = ctx.debug.readMemoryMasked(fnStartLive, buf.data(), buf.size());   // mask 0xCC bps -> real code
        if (!got) {
            ImGui::TextColored(theme::col::bad(), "Could not read memory at 0x%llX.", (unsigned long long)fnStartLive);
            return;
        }
        buf.resize(got);
        // Same structured pipeline as the static decompiler view: CFG -> dominator
        // structuring -> readable pseudo-C with named call targets. Decode with the
        // debuggee-bitness decoder so a 32-bit (WOW64) target isn't read as x64.
        auto jt = [this, &ctx](const Instruction& in) { return resolveJumpTable(ctx, in); };
        ControlFlowGraph g = BuildCFG(buf.data(), got, fnStartLive, *liveDecoder(ctx, snap.is32), 2000, jt);
        DecompileOptions opt;
        opt.nameFor    = [this, &ctx](uint64_t a) -> std::string { return symbolFor(ctx, a); };
        opt.dataRefFor = [this, &ctx](uint64_t a) -> std::string { return dataRefToken(ctx, a, /*live=*/true); };
        opt.signature  = guessSignature(ctx, liveVAtoFile(ctx, fnStartLive), fnSize);
        pseudoText_    = Decompile(g, opt);
        pseudoVA_     = fnStartLive;
    }

    ui::PushMono();
    ImGui::BeginChild("pseudo", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(pseudoText_.c_str());
    ImGui::EndChild();
    ui::PopMono();
    (void)snap;
}

void BinaryViewTab::renderLiveSearchPopup(AppContext& ctx) {
    if (openFindPopup_) { ImGui::OpenPopup("Live Search"); openFindPopup_ = false; }
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(540, 440), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Live Search", nullptr, ImGuiWindowFlags_None)) return;

    ImGui::TextDisabled("Search the debuggee's committed memory.");
    ImGui::RadioButton("ASCII",  &liveFindKind_, 0); ImGui::SameLine();
    ImGui::RadioButton("UTF-16", &liveFindKind_, 1); ImGui::SameLine();
    ImGui::RadioButton("Hex",    &liveFindKind_, 2); ImGui::SameLine();
    ImGui::RadioButton("u64",    &liveFindKind_, 3);
    ImGui::SetNextItemWidth(-80);
    bool go = ImGui::InputTextWithHint("##q", "text  /  DE AD BE EF  /  0x1400", liveFind_, sizeof(liveFind_),
                                       ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Find") || go) {
        liveFindStatus_.clear();
        DbgSnapshot s = ctx.debug.snapshot();
        if (s.attached()) liveFindHits_ = liveMemorySearch(ctx.debug, liveFind_, liveFindKind_, liveFindStatus_);
        else liveFindStatus_ = "Not attached.";
    }
    if (!liveFindStatus_.empty()) ImGui::TextDisabled("%s", liveFindStatus_.c_str());

    ImGui::BeginChild("hits", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), ImGuiChildFlags_Borders);
    ui::PushMono();
    for (uint64_t a : liveFindHits_) {
        ImGui::PushID((void*)(uintptr_t)a);
        char lbl[40]; std::snprintf(lbl, sizeof(lbl), "0x%llX", (unsigned long long)a);
        if (ImGui::Selectable(lbl)) liveNavigate(a);
        if (ImGui::IsItemHovered()) {
            unsigned char prev[48] = {0};
            size_t g = ctx.debug.readMemory(a, prev, sizeof(prev) - 1);
            char txt[64]; size_t o = 0;
            for (size_t i = 0; i < g && o < sizeof(txt) - 1; ++i)
                txt[o++] = (prev[i] >= 32 && prev[i] < 127) ? (char)prev[i] : '.';
            txt[o] = 0;
            ImGui::SetTooltip("%s", txt);
        }
        if (ImGui::BeginPopupContextItem("hitmenu")) {
            if (ImGui::MenuItem("Follow")) liveNavigate(a);
            if (ImGui::MenuItem("Copy address")) {
                char cb[24]; std::snprintf(cb, sizeof(cb), "0x%llX", (unsigned long long)a);
                ImGui::SetClipboardText(cb);
            }
            ImGui::EndPopup();
        }
        ImGui::PopID();
    }
    ui::PopMono();
    ImGui::EndChild();

    ImGui::TextDisabled("Click to follow; right-click to copy.");
    ImGui::SameLine(ImGui::GetWindowWidth() - 90);
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// Build a byte-pattern signature ("48 8B ?? ..") covering the instruction(s) in
// [lo, hi]. With `wildcard`, the rel8/rel32 displacement of a call/jmp/jcc is
// masked to ?? so the signature survives recompilation/relocation. `live` reads
// the attached debuggee's memory instead of the on-disk image.
std::string BinaryViewTab::buildSignature(AppContext& ctx, uint64_t lo, uint64_t hi,
                                          bool live, bool wildcard) {
    // Live signatures use the debuggee-bitness decoder and a 0xCC-masked read; the
    // static path uses the file engine. ctx.disasm may be null when attached with no
    // file loaded, so don't require it in live mode.
    IDisassembler* dis = live ? liveDecoder(ctx, ctx.debug.snapshot().is32) : ctx.disasm.get();
    if (!dis) return "";
    std::string out;
    uint64_t a = lo;
    for (int guard = 0; a <= hi && guard < 512; ++guard) {
        uint8_t mem[16] = {0};
        size_t got = 0;
        if (live) {
            got = ctx.debug.readMemoryMasked(a, mem, sizeof(mem));
        } else {
            size_t avail = 0; const uint8_t* p = ctx.binary.ptrFromVA(a, avail);
            if (p) { got = std::min<size_t>(avail, sizeof(mem)); std::memcpy(mem, p, got); }
        }
        if (!got) break;
        Instruction in;
        if (!dis->decodeOne(mem, got, a, in) || !in.length) break;
        uint32_t len = in.length > sizeof(mem) ? (uint32_t)sizeof(mem) : in.length;

        // Bytes [wcStart, wcStart+wcCount) are masked when wildcarding a branch. The
        // "displacement lives in the trailing rel8/rel16/rel32 bytes" rule is an x86/x64
        // encoding fact; other arches (ARM/ARM64/MIPS/PPC/RISC-V) encode the branch offset
        // as a bitfield inside a fixed-width word, so masking trailing bytes there would
        // wildcard the wrong bits. Gate on x86/x64 (the live decoder is always x86/x64);
        // off-x86 we emit a literal signature, matching the non-wildcard menu item.
        uint32_t wcStart = len, wcCount = 0;
        if (wildcard && (live || ArchIsX86(ctx.arch)) &&
            (in.isCall || in.isBranch) && in.branchTarget) {
            // Walk past legacy prefixes to the opcode byte; a 0x66 operand-size prefix
            // shrinks a direct near branch's displacement from rel32 to rel16.
            uint32_t oi = 0; bool has66 = false;
            while (oi < len) {
                uint8_t b = mem[oi];
                if (b == 0x66) { has66 = true; ++oi; }
                else if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                         b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                         b == 0x64 || b == 0x65) { ++oi; }     // addr-size / lock / rep / segment
                else break;
            }
            uint8_t  op      = (oi < len) ? mem[oi] : 0;
            bool     nearRel = (op == 0xE8 || op == 0xE9) ||                                   // direct call/jmp rel
                               (op == 0x0F && oi + 1 < len && (mem[oi + 1] & 0xF0) == 0x80);   // jcc rel near
            uint32_t rel     = nearRel ? (has66 ? 2u : 4u)      // direct near branch: rel16 vs rel32
                                       : (len >= 5 ? 4u : 1u);  // else length heuristic (FF /2,/4 disp32; rel8)
            if (rel < len) { wcStart = len - rel; wcCount = rel; }
        }
        for (uint32_t i = 0; i < len; ++i) {
            if (!out.empty()) out.push_back(' ');
            if (i >= wcStart && i < wcStart + wcCount) out += "??";
            else { char hb[4]; std::snprintf(hb, sizeof(hb), "%02X", mem[i]); out += hb; }
        }
        a += in.length;
    }
    return out;
}

// Apply `bytes` at `va`: optionally NOP-pad a short encoding up to origLen, record
// the patch so "File > Save Binary As..." can splice it on disk, and write it
// straight into the debuggee when attached. Shared by the Patch popup and the
// one-click "NOP out instruction" menu item.
void BinaryViewTab::applyPatchBytes(AppContext& ctx, uint64_t va,
                                    std::vector<uint8_t> bytes, uint32_t origLen, bool padNop) {
    if (bytes.empty()) return;
    if (padNop && origLen && bytes.size() < origLen)
        bytes.resize(origLen, 0x90);   // fill the tail of the original instruction with NOPs

    const bool attached = ctx.debug.snapshot().attached();
    auto& V = ctx.project.patches;

    // The on-disk image write + persisted patch record key off the FILE VA, but a
    // patch initiated from the live listing carries a runtime VA (ASLR-relocated).
    // The live process read/write conversely always wants the runtime VA, derived
    // back from the file VA so it's correct whether the patch came from the live or
    // the static listing.
    uint64_t fileVA = patchKeyFor(ctx, va);
    uint64_t liveVA = attached ? fileVAtoLive(ctx, fileVA) : va;

    // Capture the bytes being overwritten so the patch reverts *exactly*. Reuse a
    // prior patch's captured original (re-patching the same address must not store
    // the earlier patch as the "original"). For a fresh capture, read what is
    // actually being overwritten: live process memory when attached (the file image
    // can differ at run time - relocations / self-modification - or may not map this
    // VA at all, which previously left orig empty so revert did nothing), else the
    // on-disk image.
    std::vector<uint8_t> orig;
    if (auto prev = std::find_if(V.begin(), V.end(),
                                 [&](const PjPatch& x){ return x.address == fileVA; }); prev != V.end())
        orig = prev->orig;
    if (orig.size() < bytes.size()) {
        std::vector<uint8_t> cur;
        if (attached) {
            cur.resize(bytes.size());
            cur.resize(ctx.debug.readMemory(liveVA, cur.data(), cur.size()));   // keep only what was read
        }
        if (cur.size() < bytes.size()) {                                    // not attached / short read
            size_t oavail = 0; const uint8_t* op = ctx.binary.ptrFromVA(fileVA, oavail);
            if (op) { size_t n = std::min(oavail, bytes.size()); cur.assign(op, op + n); }
        }
        for (size_t i = orig.size(); i < cur.size(); ++i) orig.push_back(cur[i]);   // append only the new tail
    }

    PjPatch pp; pp.address = fileVA; pp.bytes = bytes; pp.orig = std::move(orig);
    V.erase(std::remove_if(V.begin(), V.end(),
                           [&](const PjPatch& x) { return x.address == fileVA; }), V.end());
    V.push_back(std::move(pp));

    // Also write straight into the debuggee when attached.
    if (attached) {
        size_t w = ctx.debug.writeMemory(liveVA, bytes.data(), bytes.size());
        patchStatus_ = (w == bytes.size()) ? "Live-patched + recorded for Save Binary As."
                                           : "Recorded; live write failed (no write access?).";
    } else {
        patchStatus_ = "Recorded. Use File > Save Binary As... to write a patched copy.";
    }
    // Reflect the patch in the in-memory image so the static disassembly shows it
    // (the live view already reads the patched process memory).
    ctx.binary.writeImage(fileVA, bytes.data(), bytes.size());
    // Don't force a synchronous UI-thread listing re-sweep here: the visible rows
    // re-decode the patched image bytes immediately, and functionsDirty_ kicks the
    // worker to rebuild the row index off-thread (so a patch never freezes the UI).
    pseudoVA_ = 0; decompVA_ = 0;   // invalidate pseudocode / decompiler caches
    functionsDirty_ = true;         // boundaries may have changed: re-analyze + rebuild listing on the worker
    ++liveGen_;                     // a live byte changed: invalidate the cached live decode
}

void BinaryViewTab::renderPatchPopup(AppContext& ctx) {
    if (openPatchPopup_) { ImGui::OpenPopup("Patch"); openPatchPopup_ = false; }
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(480, 0), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Patch", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    // Patch a LIVE target at its own bitness (the file engine/arch would assemble/preview
    // x64 bytes into a 32-bit WOW64 process, or vice versa); the static path uses the file.
    DbgSnapshot    snap     = ctx.debug.snapshot();
    const bool     live     = snap.attached();
    const bool     is32     = snap.is32;
    const Arch     liveArch = is32 ? Arch::X86 : Arch::X64;
    IDisassembler* pdis     = live ? liveDecoder(ctx, snap.is32) : ctx.disasm.get();

    ImGui::Text("Address 0x%llX", (unsigned long long)patchVA_);
    ImGui::SameLine(); ImGui::TextDisabled("(%u-byte original span)", patchLen_);
    ImGui::RadioButton("Assembly", &patchMode_, 1); ImGui::SameLine();
    ImGui::RadioButton("Hex bytes", &patchMode_, 0);

    std::vector<uint8_t> bytes;       // the bytes that Apply will write
    std::string          err;

    if (patchMode_ == 1) {
        // Assemble typed instructions with Keystone.
        ImGui::TextDisabled(is32 ? "e.g.  mov eax, 1   |   jmp 0x%llX   |   nop ; nop"
                                 : "e.g.  mov rax, 1   |   jmp 0x%llX   |   nop ; nop", (unsigned long long)patchVA_);
        ui::PushMono();
        ImGui::SetNextItemWidth(440);
        ImGui::InputText("##asm", patchAsmText_, sizeof(patchAsmText_));
        ui::PopMono();
        if (patchAsmText_[0]) {
            AsmResult r = Assemble(live ? liveArch : ctx.arch, patchAsmText_, patchVA_);
            if (r.ok) {
                bytes = r.bytes;
                std::string hx;
                for (uint8_t bb : bytes) { char t[4]; std::snprintf(t, sizeof(t), "%02X ", bb); hx += t; }
                ImGui::TextColored(theme::col::muted(), "Encodes to %zu byte(s):", bytes.size());
                ui::PushMono(); ImGui::TextWrapped("%s", hx.c_str()); ui::PopMono();
            } else {
                err = r.error;
                ImGui::TextColored(theme::col::bad(), "assembler: %s", err.c_str());
            }
        }
    } else {
        // Raw hex bytes, with a disassembly preview.
        ImGui::TextDisabled("Edit raw bytes; Apply records the patch (and writes it live if attached).");
        ui::PushMono();
        ImGui::SetNextItemWidth(440);
        ImGui::InputText("##hex", patchHex_, sizeof(patchHex_));
        ui::PopMono();
        for (size_t i = 0; patchHex_[i];) {
            if (std::isspace((unsigned char)patchHex_[i])) { ++i; continue; }
            // Require a full byte; a lone trailing nibble would silently become a wrong patch byte.
            if (!std::isxdigit((unsigned char)patchHex_[i]) || !std::isxdigit((unsigned char)patchHex_[i + 1])) break;
            char b[3] = { patchHex_[i], patchHex_[i + 1], 0 };
            unsigned v = 0; std::sscanf(b, "%x", &v);
            bytes.push_back((uint8_t)v); i += 2;
        }
        patchAsm_.clear();
        if (pdis && !bytes.empty()) {
            auto pv = pdis->disassemble(bytes.data(), bytes.size(), patchVA_, 8);
            for (auto& in : pv) { patchAsm_ += in.mnemonic; patchAsm_ += ' '; patchAsm_ += in.operands; patchAsm_ += '\n'; }
        }
        ImGui::TextColored(theme::col::muted(), "Preview:");
        ui::PushMono(); ImGui::TextUnformatted(patchAsm_.empty() ? "(no valid bytes)" : patchAsm_.c_str()); ui::PopMono();
        if (ImGui::SmallButton("NOP fill") && patchLen_) {
            std::string s; for (uint32_t i = 0; i < patchLen_; ++i) { if (i) s += ' '; s += "90"; }
            std::snprintf(patchHex_, sizeof(patchHex_), "%s", s.c_str());
        }
        ImGui::SameLine(); ImGui::TextDisabled("fill original %u byte(s) with 0x90", patchLen_);
    }

    if (!bytes.empty() && patchLen_ && bytes.size() != patchLen_)
        ImGui::TextColored(theme::col::warn(), "%zu bytes != original %u (%s)",
                           bytes.size(), patchLen_,
                           bytes.size() < patchLen_ ? "shorter: NOP-pad the rest of the span"
                                                    : "longer: overwrites the following bytes");

    ImGui::Separator();
    ImGui::Checkbox("Pad short encodings with NOP", &patchPadNop_);
    ImGui::BeginDisabled(bytes.empty());
    if (ImGui::Button("Apply")) applyPatchBytes(ctx, patchVA_, bytes, patchLen_, patchPadNop_);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!patchLen_);
    if (ImGui::Button("NOP out"))   // replace the whole original instruction with 0x90s
        applyPatchBytes(ctx, patchVA_, std::vector<uint8_t>(patchLen_, 0x90), patchLen_, false);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Copy bytes") && !bytes.empty()) {
        std::string hx; for (uint8_t bb : bytes) { char t[4]; std::snprintf(t, sizeof(t), "%02X ", bb); hx += t; }
        ImGui::SetClipboardText(hx.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    if (!patchStatus_.empty()) { ImGui::SameLine(); ImGui::TextColored(theme::col::accent(), "%s", patchStatus_.c_str()); }
    ImGui::EndPopup();
}

void BinaryViewTab::renderCommentPopup(AppContext& /*ctx*/) {
    if (openCommentPopup_) { ImGui::OpenPopup("Set Comment"); openCommentPopup_ = false; }
    ImVec2 c = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(c, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(480, 0), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Set Comment", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::Text("Comment at 0x%llX", (unsigned long long)annPopupVA_);
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(460);
    bool enter = ImGui::InputText("##cmt", commentBuf_, sizeof(commentBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::Separator();
    if (ImGui::Button("Save", ImVec2(110, 0)) || enter) {
        if (commentBuf_[0]) comments_[annPopupVA_] = commentBuf_;
        else                comments_.erase(annPopupVA_);
        projectDirty_ = true;
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Remove", ImVec2(110, 0))) { comments_.erase(annPopupVA_); projectDirty_ = true; ImGui::CloseCurrentPopup(); }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void BinaryViewTab::renderRenamePopup(AppContext& ctx) {
    if (openRenamePopup_) { ImGui::OpenPopup("Rename Symbol"); openRenamePopup_ = false; }
    ImVec2 c = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(c, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(420, 0), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Rename Symbol", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::Text("Name for 0x%llX", (unsigned long long)annPopupVA_);
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(400);
    bool enter = ImGui::InputText("##rn", renameBuf_, sizeof(renameBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::Separator();
    auto commit = [&]() {
        if (renameBuf_[0]) names_[annPopupVA_] = renameBuf_;
        else               names_.erase(annPopupVA_);
        projectDirty_ = true;
        symCache_.clear();         // resolved names changed
        decompVA_ = 0;             // pseudocode references names
        ImGui::CloseCurrentPopup();
    };
    if (ImGui::Button("Save", ImVec2(110, 0)) || enter) commit();
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(110, 0))) { names_.erase(annPopupVA_); projectDirty_ = true; symCache_.clear(); decompVA_ = 0; ImGui::CloseCurrentPopup(); }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110, 0))) ImGui::CloseCurrentPopup();
    (void)ctx;
    ImGui::EndPopup();
}

void BinaryViewTab::renderCondPopup(AppContext& ctx) {
    if (openCondPopup_) { ImGui::OpenPopup("Breakpoint Condition"); openCondPopup_ = false; }
    ImVec2 c = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(c, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(460, 0), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Breakpoint Condition", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::Text("Stop at 0x%llX only when:", (unsigned long long)annPopupVA_);
    ImGui::TextDisabled("e.g.  rax == 0   |   [rsp+8] > 0x10   |   rcx != rdx     (empty = unconditional)");
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(440);
    bool enter = ImGui::InputText("##cond", condPopupBuf_, sizeof(condPopupBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::Separator();
    auto commit = [&]() {
        if (condPopupBuf_[0]) condBuf_[annPopupVA_] = condPopupBuf_;
        else                  condBuf_.erase(annPopupVA_);
        // Ensure a software breakpoint exists so the condition has something to gate.
        breakpoints_.insert(annPopupVA_);
        if (ctx.debug.snapshot().attached()) {
            if (!ctx.debug.hasBreakpoint(annPopupVA_)) ctx.debug.addBreakpoint(annPopupVA_, condPopupBuf_);
            else                                       ctx.debug.setBreakpointCondition(annPopupVA_, condPopupBuf_);
        }
        ImGui::CloseCurrentPopup();
    };
    if (ImGui::Button("Save", ImVec2(110, 0)) || enter) commit();
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(110, 0))) {
        condBuf_.erase(annPopupVA_);
        if (ctx.debug.snapshot().attached()) ctx.debug.setBreakpointCondition(annPopupVA_, "");
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

uint64_t BinaryViewTab::liveMainBase(AppContext& ctx) {
    if (!symAttached_) return 0;
    if (liveMainBase_ && liveMainBasePid_ == symPid_) return liveMainBase_;
    if (liveModulesPid_ != symPid_ || liveModules_.empty()) {   // mirror symbolFor's cache invalidation
        ProcessManager pm; liveModules_ = pm.modules(symPid_); liveModulesPid_ = symPid_;
        modExports_.clear(); symCache_.clear(); symbols_.reset();
    }
    const std::string want = modShortName(ctx.binary.path());
    const ModuleInfo* main = nullptr;
    for (const auto& m : liveModules_) {                 // prefer a name match with the loaded file
        std::string mn = modShortName(m.name.empty() ? m.path : m.name);
        bool eq = mn.size() == want.size();
        for (size_t i = 0; eq && i < mn.size(); ++i) eq = std::tolower((unsigned char)mn[i]) == std::tolower((unsigned char)want[i]);
        if (eq) { main = &m; break; }
    }
    if (!main)                                           // fallback: the lowest-base module (typically the exe)
        for (const auto& m : liveModules_)
            if (!main || m.base < main->base) main = &m;
    liveMainBase_    = main ? main->base : 0;
    liveMainBasePid_ = symPid_;
    return liveMainBase_;
}

// Pick (and cache) a decoder whose bitness matches the live debuggee. The Win32
// debugger only ever drives x86/x64 targets, so this is X86 (WOW64) or X64; for
// any other case it falls back to the static engine.
IDisassembler* BinaryViewTab::liveDecoder(AppContext& ctx, bool is32) {
    Arch want = is32 ? Arch::X86 : Arch::X64;
    if (!liveDisasm_ || liveDisasmArch_ != (int)want) {
        liveDisasm_     = MakeDisassembler(ctx.engine, want);
        liveDisasmArch_ = (int)want;
    }
    return liveDisasm_ ? liveDisasm_.get() : ctx.disasm.get();
}

uint64_t BinaryViewTab::fileVAtoLive(AppContext& ctx, uint64_t fileVA) {
    uint64_t rb = liveMainBase(ctx);
    if (!rb || !ctx.binary.loaded()) return fileVA;
    return fileVA + (rb - ctx.binary.imageBase());      // unsigned wrap is consistent both ways
}

uint64_t BinaryViewTab::liveVAtoFile(AppContext& ctx, uint64_t liveVA) {
    uint64_t rb = liveMainBase(ctx);
    if (!rb || !ctx.binary.loaded()) return liveVA;
    return liveVA - (rb - ctx.binary.imageBase());
}

std::string BinaryViewTab::symbolFor(AppContext& ctx, uint64_t addr) {
    if (!addr) return std::string();

    // A user rename for this exact address wins over every other resolver.
    if (auto it = names_.find(addr); it != names_.end() && !it->second.empty())
        return it->second;
    // An IAT slot resolves to its imported API name.
    if (auto it = importMap_.find(addr); it != importMap_.end())
        return it->second;

    // Drop the cache + DbgHelp session when the target changes (attach <-> static).
    if (symAttached_ != symSessionLive_) {
        symSessionLive_ = symAttached_;
        symCache_.clear(); symbols_.reset();
    }
    auto cached = symCache_.find(addr);
    if (cached != symCache_.end()) return cached->second;

    std::string result;

    if (symAttached_) {
        if (liveModulesPid_ != symPid_ || liveModules_.empty()) {
            ProcessManager pm; liveModules_ = pm.modules(symPid_); liveModulesPid_ = symPid_;
            modExports_.clear(); symCache_.clear(); symbols_.reset();
        }
        const ModuleInfo* mod = nullptr;
        for (const auto& m : liveModules_)
            if (addr >= m.base && addr < m.base + m.size) { mod = &m; break; }
        if (mod) {
            std::string mn = modShortName(mod->name);
            // 1) DbgHelp: rich PDB names where available (else export names).
            symbols_.useLive(ctx.debug.processHandle());
            symbols_.ensureModule(mod->base, mod->size, mod->path);
            std::string nm; uint64_t disp = 0;
            if (symbols_.resolve(addr, nm, disp)) {
                char buf[256];
                if (disp == 0)          std::snprintf(buf, sizeof(buf), "%s.%s", mn.c_str(), nm.c_str());
                else if (disp < 0x4000) std::snprintf(buf, sizeof(buf), "%s.%s+0x%llX", mn.c_str(), nm.c_str(), (unsigned long long)disp);
                else                    std::snprintf(buf, sizeof(buf), "%s+0x%llX", mn.c_str(), (unsigned long long)(addr - mod->base));
                result = buf;
            }
            // 2) Our own export-table parser (covers cases DbgHelp didn't load).
            if (result.empty()) {
                auto it = modExports_.find(mod->base);
                if (it == modExports_.end()) {
                    std::vector<std::pair<uint64_t, std::string>> ex;
                    parseExports(ctx.debug, mod->base, ex);
                    std::sort(ex.begin(), ex.end());
                    it = modExports_.emplace(mod->base, std::move(ex)).first;
                }
                const auto& ex = it->second;
                if (!ex.empty()) {
                    size_t lo = 0, hi = ex.size();
                    while (lo < hi) { size_t mid = (lo + hi) / 2; if (ex[mid].first <= addr) lo = mid + 1; else hi = mid; }
                    if (lo > 0) {
                        const auto& e = ex[lo - 1];
                        uint64_t off = addr - e.first;
                        if (off < 0x4000) {
                            char buf[256];
                            if (off == 0) std::snprintf(buf, sizeof(buf), "%s.%s", mn.c_str(), e.second.c_str());
                            else          std::snprintf(buf, sizeof(buf), "%s.%s+0x%llX", mn.c_str(), e.second.c_str(), (unsigned long long)off);
                            result = buf;
                        }
                    }
                }
            }
            // 3) module + offset.
            if (result.empty()) {
                char buf[112]; std::snprintf(buf, sizeof(buf), "%s+0x%llX", mn.c_str(), (unsigned long long)(addr - mod->base));
                result = buf;
            }
        }
    } else if (ctx.binary.loaded()) {
        // 1) DbgHelp on the binary file (loads its PDB if one sits next to it).
        symbols_.useBinary(ctx.binary.path(), ctx.binary.imageBase());
        std::string nm; uint64_t disp = 0;
        if (symbols_.resolve(addr, nm, disp)) {
            char buf[256];
            if (disp == 0) std::snprintf(buf, sizeof(buf), "%s", nm.c_str());
            else           std::snprintf(buf, sizeof(buf), "%s+0x%llX", nm.c_str(), (unsigned long long)disp);
            result = buf;
        }
        // 2) Analyzed functions fallback (run Analyze to populate).
        if (result.empty() && !functions_.empty()) {
            const Func* best = funcContaining(addr);   // greatest start <= addr (exact match included)
            if (best && addr - best->address < 0x1000) {
                uint64_t off = addr - best->address;
                if (off == 0) result = best->name;
                else { char buf[256]; std::snprintf(buf, sizeof(buf), "%s+0x%llX", best->name.c_str(), (unsigned long long)off); result = buf; }
            }
        }
    }

    // Bound the per-session cache: a long live session resolving many distinct
    // addresses would otherwise grow it without limit. A hard reset is cheap and
    // matches the existing clear-on-context-change behavior above.
    if (symCache_.size() > 100000) symCache_.clear();
    symCache_[addr] = result;
    return result;
}

void BinaryViewTab::computeCallStack(AppContext& ctx, const DbgSnapshot& snap) {
    const Registers& r = snap.regs;
    uint64_t sig = r.rip ^ (r.rsp << 1) ^ ((uint64_t)snap.tid << 7) ^ (uint64_t)snap.state
                 ^ ((uint64_t)snap.frames.size() << 13);
    if (sig == callStackSig_) return;            // recompute only when the stop changes
    callStackSig_ = sig;
    callStack_.clear();
    if (!snap.attached() || snap.state != DbgState::Paused) return;

    // Prefer the debugger's real StackWalk64 unwind (proper .pdata-driven unwinding
    // of the remote debuggee). The heuristic RSP/RBP scan below is the fallback only
    // when the unwind produced nothing (e.g. a thread we couldn't walk).
    if (!snap.frames.empty()) {
        callStackReal_ = true;
        for (const auto& fr : snap.frames) {
            // Re-resolve the name through our own namer (heuristic guesses, user
            // renames, analyzed functions) for parity with the listing; fall back to
            // the debugger's best-effort DbgHelp name when we have nothing better.
            std::string nm = symbolFor(ctx, fr.pc);
            if (nm.empty()) nm = fr.name;
            callStack_.push_back({ fr.pc, fr.frameSp, nm });
        }
        return;
    }
    callStackReal_ = false;

    const int slot = snap.is32 ? 4 : 8;                  // 32-bit (WOW64): 4-byte stack slots / return addrs
    IDisassembler* dec = liveDecoder(ctx, snap.is32);    // decode return sites at the debuggee's bitness
    if (!dec) return;

    auto regions = ctx.debug.regions();
    auto isExec = [&](uint64_t a) {
        for (const auto& rg : regions)
            if (rg.exec && rg.state == 0x1000 && a >= rg.base && a < rg.base + rg.size) return true;
        return false;
    };

    // Frame 0: the current instruction.
    callStack_.push_back({ r.rip, r.rsp, symbolFor(ctx, r.rip) });

    // Walk up the stack: a qword that lands just past a `call` is a return address.
    const size_t kMaxQ = 2048, kMaxFrames = 64;
    std::vector<uint8_t> stk((size_t)kMaxQ * slot);
    size_t got = ctx.debug.readMemory(r.rsp, stk.data(), stk.size());
    size_t nq = got / slot;
    for (size_t i = 0; i < nq && callStack_.size() < kMaxFrames; ++i) {
        uint64_t val = 0; std::memcpy(&val, stk.data() + i * slot, slot);   // 4/8-byte slot, zero-extended
        if (val < 0x10000 || !isExec(val)) continue;
        uint8_t pre[16];
        if (ctx.debug.readMemory(val - 16, pre, sizeof(pre)) != sizeof(pre)) continue;
        bool isRet = false;
        for (int len = 2; len <= 7 && !isRet; ++len) {     // a call ending exactly at val?
            Instruction one;
            if (dec->decodeOne(pre + (16 - len), (size_t)len, val - (uint64_t)len, one)
                && one.length == (uint32_t)len && one.isCall)
                isRet = true;
        }
        if (isRet) callStack_.push_back({ val, r.rsp + (uint64_t)i * slot, symbolFor(ctx, val) });
    }
}

void BinaryViewTab::renderCallStack(AppContext& ctx) {
    DbgSnapshot snap = ctx.debug.snapshot();
    if (!snap.attached())                  { ImGui::TextDisabled("Attach a process to view the call stack."); return; }
    if (snap.state != DbgState::Paused)    { ImGui::TextDisabled("Pause the process to walk the stack."); return; }

    computeCallStack(ctx, snap);
    ImGui::TextDisabled("%s for TID %u  -  %d frame(s)",
                        callStackReal_ ? "StackWalk64 unwind" : "Heuristic walk",
                        snap.tid, (int)callStack_.size());
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) callStackSig_ = 0;

    ui::PushMono();
    if (ImGui::BeginTable("callstack", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed, 28);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Function");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)callStack_.size(); ++i) {
            const auto& f = callStack_[i];
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0); ImGui::TextDisabled("%d", i);
            ImGui::TableSetColumnIndex(1);
            char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)f.pc);
            if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) { cursorVA_ = f.pc; followLiveRip_ = false; }
            if (ImGui::BeginPopupContextItem("csm")) {
                if (ImGui::MenuItem("Go to")) { cursorVA_ = f.pc; followLiveRip_ = false; }
                if (ImGui::MenuItem("Copy address")) { char c[24]; std::snprintf(c, sizeof(c), "0x%llX", (unsigned long long)f.pc); ImGui::SetClipboardText(c); }
                if (ImGui::MenuItem("Copy function") && !f.name.empty()) ImGui::SetClipboardText(f.name.c_str());
                ImGui::EndPopup();
            }
            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(i == 0 ? theme::col::good() : theme::col::accent(), "%s", f.name.empty() ? "?" : f.name.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ui::PopMono();
    ImGui::TextDisabled(callStackReal_
        ? "Click a frame to jump there. Frame 0 = current; frames from a real .pdata unwind."
        : "Click a frame to jump there. Frame 0 = current; deeper frames are best-effort.");
}

// Annotated live stack dump: qwords from RSP with [rsp+0xNN] offsets, each value
// resolved to a symbol (return addresses, function/global pointers) or the string
// it points to, and a "follow" jump. Frame boundaries from the call-stack walk and
// the RBP slot are highlighted. Pause-only (reads the debuggee's memory).
void BinaryViewTab::renderStackTab(AppContext& ctx) {
    DbgSnapshot snap = ctx.debug.snapshot();
    if (!snap.attached())               { ImGui::TextDisabled("Attach a process to inspect the stack."); return; }
    if (snap.state != DbgState::Paused) { ImGui::TextDisabled("Pause the process to inspect the stack."); return; }

    const Registers& r = snap.regs;
    const bool is32 = snap.is32;        // 32-bit (WOW64): 4-byte slots, esp+ offsets
    const int  slot = is32 ? 4 : 8;
    computeCallStack(ctx, snap);   // cached per stop; gives frame SPs to flag below

    ImGui::TextDisabled("TID %u   %s 0x%llX   %s 0x%llX", snap.tid,
                        is32 ? "ESP" : "RSP", (unsigned long long)r.rsp,
                        is32 ? "EBP" : "RBP", (unsigned long long)r.rbp);
    ImGui::SameLine(); ImGui::SetNextItemWidth(140);
    ImGui::SliderInt("rows", &stackRows_, 8, 128);
    ImGui::Separator();

    ui::PushMono();
    if (ImGui::BeginTable("stacktbl", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Offset",  ImGuiTableColumnFlags_WidthFixed, 96);
        ImGui::TableSetupColumn("Value",   ImGuiTableColumnFlags_WidthFixed, 156);
        ImGui::TableSetupColumn("Resolves to");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (int i = 0; i < stackRows_; ++i) {
            uint64_t addr = r.rsp + (uint64_t)i * slot;
            uint64_t val = 0;
            size_t got = ctx.debug.readMemory(addr, &val, slot);
            ImGui::TableNextRow();
            ImGui::PushID(i);

            bool isRbp   = (r.rbp && addr == r.rbp);
            bool isFrame = false;
            for (const auto& f : callStack_) if (f.frameSp && f.frameSp == addr) { isFrame = true; break; }
            if (isRbp)        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.30f, 0.26f, 0.12f, 0.55f)));
            else if (isFrame) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.16f, 0.24f, 0.36f, 0.45f)));

            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(theme::col::muted(), "0x%llX", (unsigned long long)addr);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%s+0x%X%s", is32 ? "esp" : "rsp", (unsigned)(i * slot), isRbp ? (is32 ? " ebp" : " rbp") : "");

            ImGui::TableSetColumnIndex(2);
            if (got != (size_t)slot) { ImGui::TextDisabled(is32 ? "????????" : "????????????????"); ImGui::PopID(); continue; }
            if (is32) ImGui::Text("0x%08llX", (unsigned long long)(val & 0xFFFFFFFFull));
            else      ImGui::Text("0x%016llX", (unsigned long long)val);

            ImGui::TableSetColumnIndex(3);
            // Prefer a resolved symbol (return addresses + named pointers); fall back
            // to the string the value points to. A bare "module+0xNN" is just noise.
            std::string note;
            std::string sym = symbolFor(ctx, val);
            bool bareModOff = (sym.find('.') == std::string::npos) && (sym.find("+0x") != std::string::npos);
            if (!sym.empty() && !bareModOff) note = sym;
            if (note.empty()) {
                uint8_t tmp[64]; size_t g = ctx.debug.readMemory(val, tmp, sizeof(tmp));
                std::string s = resolveString(tmp, g);
                if (!s.empty()) note = "\"" + (s.size() > 48 ? s.substr(0, 48) + "..." : s) + "\"";
            }
            if (val >= 0x10000) {
                if (ImGui::SmallButton("follow")) liveNavigate(val);
                if (!note.empty()) { ImGui::SameLine(); ImGui::TextColored(theme::col::accent(), "%s", note.c_str()); }
            } else if (!note.empty()) {
                ImGui::TextColored(theme::col::accent(), "%s", note.c_str());
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ui::PopMono();
    ImGui::TextDisabled("Yellow = RBP slot; blue = a call frame. 'follow' jumps the live view to that value.");
}

void BinaryViewTab::buildSymbolIndex(AppContext& ctx) {
    uint64_t sig = symAttached_ ? ((uint64_t)symPid_ | 0x100000000ull)
                                : (uint64_t)(ctx.binary.loaded() ? functions_.size() + 1 : 0);
    if (sig == symbolIndexSig_ && !symbolIndex_.empty()) return;
    symbolIndexSig_ = sig;
    symbolIndex_.clear();
    gotoFilterLast_.clear(); gotoMatches_.clear();

    if (symAttached_) {
        if (liveModulesPid_ != symPid_ || liveModules_.empty()) {
            ProcessManager pm; liveModules_ = pm.modules(symPid_); liveModulesPid_ = symPid_;
        }
        for (const auto& m : liveModules_) {
            auto it = modExports_.find(m.base);
            if (it == modExports_.end()) {
                std::vector<std::pair<uint64_t, std::string>> ex;
                parseExports(ctx.debug, m.base, ex);
                std::sort(ex.begin(), ex.end());
                it = modExports_.emplace(m.base, std::move(ex)).first;
            }
            std::string mn = modShortName(m.name);
            for (const auto& e : it->second) symbolIndex_.push_back({ e.first, mn + "." + e.second });
            if (symbolIndex_.size() > 120000) break;
        }
    } else if (ctx.binary.loaded()) {
        for (const auto& f : functions_) symbolIndex_.push_back({ f.address, f.name });
    }
}

uint64_t BinaryViewTab::lookupSymbol(AppContext& ctx, const char* name) {
    if (!name || !name[0]) return 0;
    buildSymbolIndex(ctx);
    std::string q = name;
    for (char& c : q) c = (char)std::tolower((unsigned char)c);
    uint64_t sub = 0;
    for (const auto& s : symbolIndex_) {
        std::string n = s.second;
        for (char& c : n) c = (char)std::tolower((unsigned char)c);
        if (n == q) return s.first;                            // exact "module.name"
        size_t dot = n.find('.');
        if (dot != std::string::npos && n.compare(dot + 1, std::string::npos, q) == 0) return s.first;  // bare name
        if (!sub && n.find(q) != std::string::npos) sub = s.first;  // first substring match
    }
    if (sub) return sub;
    // Fallback: ask DbgHelp to resolve the name against the PDB / export table
    // (covers symbols that never made it into our in-tab index). In the static
    // case bind the file session on demand; live sessions are already bound.
    if (!symAttached_ && ctx.binary.loaded())
        symbols_.useBinary(ctx.binary.path(), ctx.binary.imageBase());
    uint64_t va = 0;
    if (symbols_.addressOf(name, va)) return va;
    return 0;
}

void BinaryViewTab::renderGotoPopup(AppContext& ctx) {
    if (openGotoPopup_) {
        ImGui::OpenPopup("Goto Symbol");
        openGotoPopup_ = false;
        buildSymbolIndex(ctx);
        gotoNameBuf_[0] = 0; gotoFilterLast_ = "\x01";   // force a refilter on open
    }
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(580, 470), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Goto Symbol", nullptr, ImGuiWindowFlags_None)) return;

    ImGui::TextDisabled("%zu symbol(s).  Type a name (or 0xADDRESS).", symbolIndex_.size());
    ImGui::SameLine();
    if (ImGui::SmallButton("Rebuild")) { symbolIndexSig_ = ~0ull; buildSymbolIndex(ctx); gotoFilterLast_ = "\x01"; }

    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-1);
    bool enter = ImGui::InputTextWithHint("##gname", "filter symbols...", gotoNameBuf_, sizeof(gotoNameBuf_),
                                          ImGuiInputTextFlags_EnterReturnsTrue);

    if (gotoFilterLast_ != gotoNameBuf_) {                 // re-filter only when text changed
        gotoFilterLast_ = gotoNameBuf_;
        gotoMatches_.clear();
        std::string q = gotoNameBuf_;
        for (char& c : q) c = (char)std::tolower((unsigned char)c);
        for (int i = 0; i < (int)symbolIndex_.size() && (int)gotoMatches_.size() < 500; ++i) {
            if (q.empty()) { gotoMatches_.push_back(i); continue; }
            std::string n = symbolIndex_[i].second;
            for (char& c : n) c = (char)std::tolower((unsigned char)c);
            if (n.find(q) != std::string::npos) gotoMatches_.push_back(i);
        }
    }

    auto go = [&](uint64_t a) { navigateTo(a); ImGui::CloseCurrentPopup(); };
    if (enter) {
        unsigned long long a = 0;
        bool hexPref = gotoNameBuf_[0] == '0' && (gotoNameBuf_[1] == 'x' || gotoNameBuf_[1] == 'X');
        if (hexPref && std::sscanf(gotoNameBuf_ + 2, "%llx", &a) == 1)  go((uint64_t)a);
        else if (!gotoMatches_.empty())                                 go(symbolIndex_[gotoMatches_[0]].first);
        else if (std::sscanf(gotoNameBuf_, "%llx", &a) == 1)            go((uint64_t)a);
        else if (uint64_t s = lookupSymbol(ctx, gotoNameBuf_))          go(s);  // DbgHelp PDB/export fallback
    }

    ImGui::BeginChild("glist", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), ImGuiChildFlags_Borders);
    ui::PushMono();
    for (int idx : gotoMatches_) {
        const auto& s = symbolIndex_[idx];
        ImGui::PushID(idx);
        char lbl[320]; std::snprintf(lbl, sizeof(lbl), "0x%llX  %s", (unsigned long long)s.first, s.second.c_str());
        if (ImGui::Selectable(lbl)) go(s.first);
        ImGui::PopID();
    }
    if (gotoMatches_.empty())
        ImGui::TextDisabled(symbolIndex_.empty() ? "No symbols. Attach a process, or Analyze a loaded binary." : "No match.");
    ui::PopMono();
    ImGui::EndChild();

    ImGui::TextDisabled("Enter = first match / address.   Esc / Close to dismiss.");
    ImGui::SameLine(ImGui::GetWindowWidth() - 90);
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void BinaryViewTab::startTextSearch(AppContext& ctx) {
    textHits_.clear(); textStatus_.clear(); openTextPopup_ = true;
    textHitsLive_ = ctx.debug.snapshot().attached();   // attached -> hits are runtime VAs
    if (!textSearch_[0]) { textStatus_ = "Enter text to search.";      return; }

    std::string q = textSearch_;
    const bool ci = !textCaseSensitive_;
    if (ci) for (char& c : q) c = (char)std::tolower((unsigned char)c);

    const size_t kHitCap = 4000;
    char line[192];
    DbgSnapshot snap = ctx.debug.snapshot();
    // Debuggee-bitness engine when attached (the x64 engine on a 32-bit WOW64 target
    // decodes to garbage and matches nothing); works with no file loaded too.
    IDisassembler* dis = snap.attached() ? liveDecoder(ctx, snap.is32) : ctx.disasm.get();
    if (!dis) { textStatus_ = "No disassembler available."; return; }
    auto scan = [&](const uint8_t* data, size_t size, uint64_t base) -> bool {
        Instruction in;
        for (size_t off = 0; off < size;) {
            uint64_t a = base + off;
            if (!dis->decodeOne(data + off, size - off, a, in) || in.length == 0) { ++off; continue; }
            std::snprintf(line, sizeof(line), "%s %s", in.mnemonic.c_str(), in.operands.c_str());
            if (ci) for (char* c = line; *c; ++c) *c = (char)std::tolower((unsigned char)*c);
            if (std::strstr(line, q.c_str())) {
                textHits_.push_back(a);
                if (textHits_.size() >= kHitCap) return false;
            }
            off += in.length;
        }
        return true;
    };

    if (snap.attached()) {
        std::vector<uint8_t> buf; size_t scanned = 0; const size_t kBytesCap = 64u * 1024 * 1024;
        for (const auto& rg : ctx.debug.regions()) {
            if (!rg.exec || rg.state != 0x1000 || rg.size == 0) continue;
            size_t sz = (size_t)rg.size; if (scanned + sz > kBytesCap) sz = kBytesCap - scanned;
            buf.resize(sz);
            size_t got = ctx.debug.readMemoryMasked(rg.base, buf.data(), sz);
            if (got && !scan(buf.data(), got, rg.base)) break;
            scanned += sz; if (scanned >= kBytesCap) break;
        }
    } else if (ctx.binary.loaded()) {
        for (const auto& s : ctx.binary.sections()) {
            if (!s.executable) continue;
            size_t avail = 0; uint64_t va = ctx.binary.imageBase() + s.virtualAddress;
            const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
            if (p && avail && !scan(p, avail, va)) break;
        }
    } else { textStatus_ = "Attach a process or load a binary first."; return; }

    char st[64]; std::snprintf(st, sizeof(st), "%zu match(es)", textHits_.size());
    textStatus_ = st;
}

void BinaryViewTab::renderTextSearchPopup(AppContext& ctx) {
    if (openTextPopup_) { ImGui::OpenPopup("Code Text Search"); openTextPopup_ = false; }
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(640, 470), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Code Text Search", nullptr, ImGuiWindowFlags_None)) return;

    ImGui::TextDisabled("Search the disassembly text (mnemonic + operands) across executable code.");
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-190);
    bool go = ImGui::InputTextWithHint("##tq", "syscall  |  xor eax, eax  |  rip+0x  |  call qword",
                                       textSearch_, sizeof(textSearch_), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine(); ImGui::Checkbox("Case", &textCaseSensitive_);
    ImGui::SameLine(); if (ImGui::Button("Find") || go) startTextSearch(ctx);
    if (!textStatus_.empty()) ImGui::TextDisabled("%s", textStatus_.c_str());

    DbgSnapshot snap = ctx.debug.snapshot();
    ImGui::BeginChild("tlist", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), ImGuiChildFlags_Borders);
    ui::PushMono();
    for (uint64_t a : textHits_) {
        ImGui::PushID((void*)(uintptr_t)a);
        uint8_t mem[16]; size_t got = 0;
        if (snap.attached()) got = ctx.debug.readMemoryMasked(a, mem, sizeof(mem));   // mask 0xCC so the label isn't int3
        else if (ctx.binary.loaded()) {
            size_t av = 0; const uint8_t* p = ctx.binary.ptrFromVA(a, av);
            if (p) { got = std::min(av, sizeof(mem)); std::memcpy(mem, p, got); }
        }
        std::string txt; Instruction one;
        IDisassembler* pdis = snap.attached() ? liveDecoder(ctx, snap.is32) : ctx.disasm.get();   // debuggee bitness for the label
        if (got && pdis && pdis->decodeOne(mem, got, a, one)) txt = one.mnemonic + " " + one.operands;
        char lbl[220]; std::snprintf(lbl, sizeof(lbl), "0x%llX  %s", (unsigned long long)a, txt.c_str());
        // Hits are runtime VAs when the search ran against the debuggee -> show them in
        // the live view; otherwise they're file VAs for the static view. Both record history.
        if (ImGui::Selectable(lbl)) { if (textHitsLive_) { mainView_ = 4; liveNavigate(a); } else navigateTo(a); }
        if (ImGui::BeginPopupContextItem("tm")) {
            if (ImGui::MenuItem("Go to")) { if (textHitsLive_) { mainView_ = 4; liveNavigate(a); } else navigateTo(a); }
            if (ImGui::MenuItem("Copy address")) { char c[24]; std::snprintf(c, sizeof(c), "0x%llX", (unsigned long long)a); ImGui::SetClipboardText(c); }
            ImGui::EndPopup();
        }
        ImGui::PopID();
    }
    if (textHits_.empty() && !textStatus_.empty()) ImGui::TextDisabled("No matches.");
    ui::PopMono();
    ImGui::EndChild();

    ImGui::TextDisabled("Click a result to jump there.");
    ImGui::SameLine(ImGui::GetWindowWidth() - 90);
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// instrRefsAddr(in, target) now lives in DataRef.h (shared with the Core live-xref
// sweep FindRefsInBuffer); included via "DataRef.h" at the top of this file.

void BinaryViewTab::startXrefSearch(AppContext& ctx, uint64_t target) {
    xrefTarget_ = target;
    xrefHits_.clear();
    xrefStatus_.clear();
    xrefScanning_ = false;
    openXrefPopup_ = true;
    DbgSnapshot snap = ctx.debug.snapshot();
    xrefHitsLive_ = snap.attached();                   // attached -> hits are runtime VAs

    const size_t kHitCap = 3000;
    if (snap.attached()) {
        // ATTACHED: sweep the debuggee's executable committed memory OFF the render
        // thread (up to 64 MB of ReadProcessMemory + decode would otherwise stall the
        // UI). Collect the exec ranges here; LiveScanService decodes them with a
        // debuggee-bitness decoder (the file engine mis-decodes a 32-bit WOW64 target).
        std::vector<LiveRange> ranges;
        size_t scanned = 0; const size_t kBytesCap = 64u * 1024 * 1024;
        for (const auto& rg : ctx.debug.regions()) {
            if (!rg.exec || rg.state != 0x1000 /*MEM_COMMIT*/ || rg.size == 0) continue;
            size_t sz = (size_t)rg.size; if (scanned + sz > kBytesCap) sz = kBytesCap - scanned;
            ranges.push_back({ rg.base, (uint64_t)sz });
            scanned += sz; if (scanned >= kBytesCap) break;
        }
        Engine e = ctx.disasm ? ctx.disasm->engine() : Engine::Zydis;
        Arch   a = snap.is32 ? Arch::X86 : Arch::X64;
        MemReader reader = [dbg = &ctx.debug](uint64_t va, void* out, size_t n) { return dbg->readMemoryMasked(va, out, n); };
        xrefScanning_ = true;
        xrefStatus_   = "scanning...";
        xrefToken_    = ctx.livescan.requestXref(std::move(ranges), target, e, a, std::move(reader),
                                                 ctx.livescan.epoch(), kHitCap);
        return;
    }
    // FILE: synchronous decode-sweep of the on-disk image (fast, in-memory).
    if (!ctx.binary.loaded()) { xrefStatus_ = "Attach a process or load a binary first."; return; }
    IDisassembler* dis = ctx.disasm.get();
    if (!dis) { xrefStatus_ = "No disassembler available."; return; }
    for (const auto& s : ctx.binary.sections()) {
        if (!s.executable) continue;
        size_t avail = 0;
        uint64_t va = ctx.binary.imageBase() + s.virtualAddress;
        const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
        if (p && avail && !FindRefsInBuffer(p, avail, va, target, *dis, xrefHits_, kHitCap)) break;
    }
    char st[64];
    std::snprintf(st, sizeof(st), "%zu reference(s)", xrefHits_.size());
    xrefStatus_ = st;
}

// "Analyze all modules": read every not-yet-analyzed module's image from the live
// process on the LiveScanService pool (so the UI never blocks on ReadProcessMemory),
// then — as each image arrives (see the ReadImage drain in render) — hand it to the
// analysis pool. Results land in each module's registry cache for instant switching.
void BinaryViewTab::analyzeAllModules(AppContext& ctx) {
    DbgSnapshot snap = ctx.debug.snapshot();
    if (!snap.attached()) return;
    if (liveModulesPid_ != snap.pid || liveModules_.empty()) {
        ProcessManager pm; liveModules_ = pm.modules(snap.pid); liveModulesPid_ = snap.pid;
    }
    for (auto& mi : liveModules_) ctx.modules.addOrUpdate(mi.name, mi.base, mi.size, mi.path);

    const uint64_t activeBase = ctx.modules.active() ? ctx.modules.active()->base : 0;
    MemReader reader = [dbg = &ctx.debug](uint64_t va, void* out, size_t n) { return dbg->readMemoryMasked(va, out, n); };
    uint64_t e = ctx.livescan.epoch();

    // Count first so the progress bar shows N/total, then enqueue the reads.
    std::vector<const ModuleInfo*> todo;
    for (auto& mi : liveModules_) {
        LoadedModule* m = ctx.modules.byBase(mi.base);
        if (!m || m->analyzed() || m->analyzing) continue;       // already done / in flight
        if (mi.base == activeBase) continue;                     // the active module is analyzed in ctx.binary
        if (!mi.size || mi.size > 128ull * 1024 * 1024) continue; // skip pathological sizes
        m->analyzing = true;
        todo.push_back(&mi);
    }
    if (todo.empty()) return;
    ctx.livescan.beginBatch((uint32_t)todo.size());
    for (const ModuleInfo* mi : todo)
        ctx.livescan.requestReadImage(mi->base, mi->size, mi->base, reader, e);   // moduleBase = base
}

void BinaryViewTab::renderXrefPopup(AppContext& ctx) {
    if (openXrefPopup_) { ImGui::OpenPopup("References"); openXrefPopup_ = false; }
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(640, 460), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("References", nullptr, ImGuiWindowFlags_None)) return;

    ImGui::Text("References to 0x%llX", (unsigned long long)xrefTarget_);
    if (!xrefStatus_.empty()) { ImGui::SameLine(); ImGui::TextDisabled("- %s", xrefStatus_.c_str()); }

    DbgSnapshot snap = ctx.debug.snapshot();
    ImGui::BeginChild("xref", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), ImGuiChildFlags_Borders);
    ui::PushMono();
    for (uint64_t a : xrefHits_) {
        ImGui::PushID((void*)(uintptr_t)a);
        uint8_t mem[16]; size_t got = 0;
        if (snap.attached()) got = ctx.debug.readMemoryMasked(a, mem, sizeof(mem));   // mask 0xCC so the label isn't int3
        else if (ctx.binary.loaded()) {
            size_t av = 0; const uint8_t* p = ctx.binary.ptrFromVA(a, av);
            if (p) { got = std::min(av, sizeof(mem)); std::memcpy(mem, p, got); }
        }
        std::string line;
        Instruction one;
        IDisassembler* pdis = snap.attached() ? liveDecoder(ctx, snap.is32) : ctx.disasm.get();   // debuggee bitness for the label
        if (got && pdis && pdis->decodeOne(mem, got, a, one))
            line = one.mnemonic + " " + one.operands;
        std::string sym = symbolFor(ctx, a);
        char lbl[280];
        if (!sym.empty())
            std::snprintf(lbl, sizeof(lbl), "0x%llX  %-26.26s  in %s", (unsigned long long)a, line.c_str(), sym.c_str());
        else
            std::snprintf(lbl, sizeof(lbl), "0x%llX  %s", (unsigned long long)a, line.c_str());
        if (ImGui::Selectable(lbl)) { if (xrefHitsLive_) { mainView_ = 4; liveNavigate(a); } else navigateTo(a); }
        if (ImGui::BeginPopupContextItem("xm")) {
            if (ImGui::MenuItem("Go to")) { if (xrefHitsLive_) { mainView_ = 4; liveNavigate(a); } else navigateTo(a); }
            if (ImGui::MenuItem("Copy address")) {
                char c[24]; std::snprintf(c, sizeof(c), "0x%llX", (unsigned long long)a); ImGui::SetClipboardText(c);
            }
            ImGui::EndPopup();
        }
        ImGui::PopID();
    }
    if (xrefScanning_) {
        ImGui::TextDisabled("Scanning process memory...");
        ImGui::SameLine();
        LiveProgress lp = ctx.livescan.progress();
        float frac = lp.total > 0 ? (float)lp.current / (float)lp.total : -1.0f;
        if (frac >= 0.0f) ImGui::ProgressBar(frac, ImVec2(160.0f * theme::UiScale(), 0.0f));
        else { float t = (float)ImGui::GetTime(); ImGui::ProgressBar(t - (float)(long long)t, ImVec2(160.0f * theme::UiScale(), 0.0f), ""); }
    } else if (xrefHits_.empty()) {
        ImGui::TextDisabled("No references found in scanned code.");
    }
    ui::PopMono();
    ImGui::EndChild();

    ImGui::TextDisabled("Click a reference to jump to it.");
    ImGui::SameLine(ImGui::GetWindowWidth() - 90);
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// Content signature the whole-program xref index is cached by (image hash + patch
// count + arch + engine + function count) so it only rebuilds when the code or
// analysis actually changes. Shared by buildXrefIndex and the background-result
// pickup, which adopts the worker's index and stamps this same signature.
uint64_t BinaryViewTab::xrefSig(AppContext& ctx) {
    return (ctx.binary.loaded() ? ctx.binary.contentHash() : 0)
         ^ ((uint64_t)ctx.project.patches.size() << 8)
         ^ ((uint64_t)functions_.size() << 1)
         ^ ((uint64_t)ctx.arch << 40)
         ^ ((uint64_t)(ctx.disasm ? ctx.disasm->engine() : Engine::Zydis) << 44);
}

// (Re)build the whole-program xref index from the on-disk image (UI-thread fallback
// when the worker's prebuilt index isn't current).
void BinaryViewTab::buildXrefIndex(AppContext& ctx) {
    uint64_t sig = xrefSig(ctx);
    if (sig == xrefIndexSig_ && !xrefIndex_.empty()) return;
    xrefIndex_.clear();
    xrefIndexSig_ = sig;
    if (!ctx.binary.loaded() || !ctx.disasm) return;
    for (const auto& s : ctx.binary.sections()) {
        if (!s.executable) continue;
        size_t avail = 0;
        uint64_t va = ctx.binary.imageBase() + s.virtualAddress;
        const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
        if (p && avail) BuildXrefInto(xrefIndex_, p, avail, va, *ctx.disasm);
    }
    FinalizeXrefIndex(xrefIndex_);
}

// True when the whole-program xref index matches the current image; otherwise kick
// an off-thread K_Xref build (coalesced at the current epoch so it doesn't supersede
// in-flight funcs/listing) and return false so the tab shows progress instead of
// sweeping all code on the UI thread.
bool BinaryViewTab::ensureXrefReady(AppContext& ctx) {
    uint64_t sig = xrefSig(ctx);
    if (sig == xrefIndexSig_ && !xrefIndex_.empty()) return true;
    if (xrefRequestedSig_ != sig && ctx.binary.loaded() && ctx.disasm) {
        ctx.analysis.requestBulk(&ctx.binary, ctx.engine, ctx.arch, K_Xref, guessNames_, ctx.analysis.epoch());
        xrefRequestedSig_ = sig;
    }
    return false;
}

// "Xrefs" lower sub-tab: instant "who references this?" for the cursor address and
// its enclosing function, from the precomputed index (no per-query code sweep).
void BinaryViewTab::renderXrefsTab(AppContext& ctx) {
    if (!ctx.binary.loaded()) { ImGui::TextDisabled("Load a binary to see cross-references."); return; }
    if (!ensureXrefReady(ctx)) {
        ImGui::TextDisabled("Building cross-reference index\xE2\x80\xA6");
        drawAnalysisProgress(ctx, false);
        return;
    }

    // The index is keyed in file space; translate a live-view cursor back to it.
    uint64_t cur     = (mainView_ == 4) ? liveVAtoFile(ctx, cursorVA_) : cursorVA_;
    const Func* fn   = funcContaining(cur);
    uint64_t fnStart = (fn && cur - fn->address < 0x100000) ? fn->address : 0;

    ImGui::TextDisabled("%zu reference edge(s) indexed.", xrefIndex_.edgeCount());
    ImGui::SameLine();
    // Rebuild: drop the cached signature so ensureXrefReady re-requests off-thread.
    if (ImGui::SmallButton("Rebuild")) { xrefIndexSig_ = ~0ull; xrefRequestedSig_ = ~0ull; }
    ImGui::SameLine();
    ImGui::TextDisabled("|  cursor 0x%llX", (unsigned long long)cur);
    ImGui::Separator();

    // Render one referencing source: decode it from the file image for a label, with
    // its enclosing symbol, and navigate on click (runtime VA in the live view).
    auto sourceRow = [&](uint64_t a) {
        ImGui::PushID((void*)(uintptr_t)(a ^ 0xD1B54A33u));
        uint8_t mem[16]; size_t got = 0;
        size_t av = 0; const uint8_t* p = ctx.binary.ptrFromVA(a, av);
        if (p) { got = std::min(av, sizeof(mem)); std::memcpy(mem, p, got); }
        std::string line; Instruction one;
        if (got && ctx.disasm && ctx.disasm->decodeOne(mem, got, a, one))
            line = one.mnemonic + " " + one.operands;
        std::string sym = symbolFor(ctx, a);
        char lbl[300];
        if (!sym.empty())
            std::snprintf(lbl, sizeof(lbl), "0x%llX  %-26.26s  in %s", (unsigned long long)a, line.c_str(), sym.c_str());
        else
            std::snprintf(lbl, sizeof(lbl), "0x%llX  %s", (unsigned long long)a, line.c_str());
        if (ImGui::Selectable(lbl)) {
            if (mainView_ == 4) liveNavigate(fileVAtoLive(ctx, a));
            else                navigateTo(a);
        }
        if (ImGui::BeginPopupContextItem("xtm")) {
            if (ImGui::MenuItem("Copy address")) { char c[24]; std::snprintf(c, sizeof(c), "0x%llX", (unsigned long long)a); ImGui::SetClipboardText(c); }
            ImGui::EndPopup();
        }
        ImGui::PopID();
    };

    auto section = [&](const char* title, uint64_t target) {
        std::string sym = target ? symbolFor(ctx, target) : std::string();
        if (target) ImGui::TextColored(theme::col::accent(), "%s to 0x%llX%s%s%s", title,
                        (unsigned long long)target, sym.empty() ? "" : "  (", sym.c_str(), sym.empty() ? "" : ")");
        else        { ImGui::TextDisabled("%s: no address at cursor", title); return; }
        const std::vector<uint64_t>* src = xrefIndex_.sources(target);
        if (!src || src->empty()) { ImGui::TextDisabled("   no references found"); return; }
        ImGui::TextDisabled("   %zu reference(s):", src->size());
        ui::PushMono();
        ImGuiListClipper clip;
        clip.Begin((int)src->size());
        while (clip.Step())
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) sourceRow((*src)[i]);
        ui::PopMono();
    };

    ImGui::BeginChild("xrefs", ImVec2(0, 0), ImGuiChildFlags_None);
    section("References", cur);
    if (fnStart && fnStart != cur) {
        ImGui::Dummy(ImVec2(0, 6)); ImGui::Separator();
        section("References to enclosing function", fnStart);
    }
    ImGui::EndChild();
}

// Structured pseudo-C for one function, mirroring the static Pseudocode view's
// pipeline (CFG -> dominator structuring -> named call targets). Used by the
// analysis export; the on-screen view keeps its own cached path.
std::string BinaryViewTab::decompileFunctionText(AppContext& ctx, uint64_t fnStart, uint32_t fnSize) {
    if (!ctx.binary.loaded() || !ctx.disasm) return std::string();
    size_t avail = 0;
    const uint8_t* p = ctx.binary.ptrFromVA(fnStart, avail);
    if (!p) return std::string();
    size_t win = fnSize ? std::min<size_t>(avail, std::min<uint32_t>(fnSize + 16u, 16384u))
                        : std::min<size_t>(avail, 4096);
    auto jt = [this, &ctx](const Instruction& in) { return resolveJumpTable(ctx, in); };
    ControlFlowGraph g = BuildCFG(p, win, fnStart, *ctx.disasm, 2000, jt);
    DecompileOptions opt;
    opt.nameFor    = [this, &ctx](uint64_t a) -> std::string { return symbolFor(ctx, a); };
    opt.dataRefFor = [this, &ctx](uint64_t a) -> std::string { return dataRefToken(ctx, a, /*live=*/false); };
    opt.x86        = ArchIsX86(ctx.arch);   // gate the arg-header to x86/x64 (avoid spurious args on other arches)
    opt.signature  = guessSignature(ctx, fnStart, fnSize);
    return Decompile(g, opt);
}

// File > Export Analysis: gather annotations + decompiled named functions and write
// a Markdown / HTML report via the App's save dialog.
void BinaryViewTab::exportAnalysis(AppContext& ctx) {
    if (!ctx.binary.loaded()) { exportStatus_ = "Load a binary first."; openExportPopup_ = true; return; }

    ReportInput in;
    {   // title = binary file name
        const std::string& path = ctx.binary.path();
        size_t s = path.find_last_of("/\\");
        in.title = (s == std::string::npos) ? path : path.substr(s + 1);
    }
    { char h[20]; std::snprintf(h, sizeof(h), "%016llX", (unsigned long long)ctx.binary.contentHash()); in.hashHex = h; }
    in.arch          = ctx.project.arch;
    in.engine        = ctx.project.engine;
    in.functionCount = (int)functions_.size();
    in.stringCount   = (int)strings_.size();

    for (const auto& kv : names_)    in.renames.push_back({ kv.first, kv.second });
    for (const auto& kv : comments_) in.comments.push_back({ kv.first, kv.second });
    std::sort(in.renames.begin(),  in.renames.end());
    std::sort(in.comments.begin(), in.comments.end());
    for (const auto& b : bookmarks_) in.bookmarks.push_back({ b.address, b.label });
    std::sort(in.bookmarks.begin(), in.bookmarks.end());
    in.notes = notes_;

    // Decompile the analyst's named functions (cap keeps a large rename set fast).
    const size_t kFnCap = 300;
    size_t skipped = 0;
    for (const auto& f : functions_) {
        auto nm = names_.find(f.address);
        if (nm == names_.end()) continue;                       // only user-named functions
        if (in.functions.size() >= kFnCap) { ++skipped; continue; }
        ReportFunction rf;
        rf.address    = f.address;
        rf.name       = nm->second;
        rf.signature  = guessSignature(ctx, f.address, f.size);
        rf.pseudocode = decompileFunctionText(ctx, f.address, f.size);
        in.functions.push_back(std::move(rf));
    }

    std::string md   = RenderReportMarkdown(in);
    std::string html = RenderReportHtml(in);

    std::string base = in.title;
    if (size_t dot = base.find_last_of('.'); dot != std::string::npos) base = base.substr(0, dot);

    std::string msg;
    bool ok = ctx.exportAnalysisFile(base, md, html, msg);
    if (msg.empty()) return;   // dialog cancelled -> no popup
    if (ok && skipped) msg += "  (" + std::to_string(skipped) + " named function(s) beyond the cap were omitted)";
    exportStatus_ = msg;
    openExportPopup_ = true;
}

void BinaryViewTab::renderPseudocode(AppContext& ctx) {
    panelPopToggle(&pseudoPoppedOut_, "pseudo"); ImGui::SameLine();
    ImGui::TextDisabled("Decompiler view (structured pseudo-C).");
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) decompVA_ = 0;
    ImGui::SameLine();
    ImGui::TextDisabled("if/else + while recovery via dominator analysis; goto fallback for irreducible flow.");
    ImGui::Separator();
    if (!ctx.binary.loaded() || !ctx.disasm) { ImGui::TextDisabled("No binary loaded."); return; }

    // Decompile the function enclosing the cursor (so we structure a whole fn,
    // not just the window under the cursor). Cached until the function changes.
    uint64_t fnStart = cursorVA_;
    uint32_t fnSize  = 0;
    const Func* best = funcContaining(cursorVA_);
    if (best && cursorVA_ - best->address < 0x4000) { fnStart = best->address; fnSize = best->size; }

    if (fnStart != decompVA_ || decompText_.empty()) {
        decompVA_ = fnStart;
        size_t avail = 0;
        const uint8_t* p = ctx.binary.ptrFromVA(fnStart, avail);
        if (!p) {
            decompText_ = "// cursor address is not mapped to file data\n";
        } else {
            size_t win = fnSize ? std::min<size_t>(avail, std::min<uint32_t>(fnSize + 16u, 16384u))
                                : std::min<size_t>(avail, 4096);
            auto jt = [this, &ctx](const Instruction& in) { return resolveJumpTable(ctx, in); };
            ControlFlowGraph g = BuildCFG(p, win, fnStart, *ctx.disasm, 2000, jt);
            DecompileOptions opt;
            opt.nameFor    = [this, &ctx](uint64_t a) -> std::string { return symbolFor(ctx, a); };
            opt.dataRefFor = [this, &ctx](uint64_t a) -> std::string { return dataRefToken(ctx, a, /*live=*/false); };
            // Feed the inferred signature into the emitted header (name spliced in).
            opt.x86       = ArchIsX86(ctx.arch);   // gate the arg-header to x86/x64
            opt.signature = guessSignature(ctx, fnStart, fnSize);
            decompText_ = Decompile(g, opt);
            if (!opt.signature.empty())
                decompText_ = "// signature is heuristic (no full type recovery)\n" + decompText_;
        }
    }

    ui::PushMono();
    // Read-only multiline so the user can select / copy the output.
    ImGui::InputTextMultiline("##decomp", decompText_.data(), decompText_.size() + 1,
                              ImVec2(-1, -1), ImGuiInputTextFlags_ReadOnly);
    ui::PopMono();
}

void BinaryViewTab::renderHex(AppContext& ctx) {
    if (!ctx.binary.loaded()) { ImGui::TextDisabled("No binary loaded."); return; }
    uint64_t va = cursorVA_;
    size_t avail = 0;
    const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
    if (!p) { p = ctx.binary.bytes().data(); avail = ctx.binary.bytes().size(); va = ctx.binary.imageBase(); }
    size_t rows = std::min<size_t>(avail / 16 + 1, 64);
    ImGui::BeginChild("hex", ImVec2(0, 0), ImGuiChildFlags_Borders);
    ui::PushMono();
    for (size_t r = 0; r < rows; ++r) {
        char line[160]; int o = 0;
        o += std::snprintf(line + o, sizeof(line) - o, "%012llX  ", (unsigned long long)(va + r * 16));
        for (size_t c = 0; c < 16; ++c) {
            size_t idx = r * 16 + c;
            if (idx < avail) o += std::snprintf(line + o, sizeof(line) - o, "%02X ", p[idx]);
            else             o += std::snprintf(line + o, sizeof(line) - o, "   ");
        }
        o += std::snprintf(line + o, sizeof(line) - o, " ");
        for (size_t c = 0; c < 16; ++c) {
            size_t idx = r * 16 + c;
            char ch = (idx < avail && std::isprint(p[idx])) ? (char)p[idx] : '.';
            if (idx < avail) o += std::snprintf(line + o, sizeof(line) - o, "%c", ch);
        }
        ImGui::TextUnformatted(line);
    }
    ui::PopMono();
    ImGui::EndChild();
}

// Build call edges between discovered functions (cached). Each function is
// swept once; direct CALLs whose target is another function become edges.
void BinaryViewTab::buildCallGraph(AppContext& ctx) {
    uint64_t sig = (ctx.binary.loaded() ? ctx.binary.contentHash() : 0) ^ ((uint64_t)functions_.size() << 1);
    if (sig == callGraphSig_) return;
    callGraphSig_ = sig;
    callees_.clear(); callers_.clear();
    if (!ctx.binary.loaded() || !ctx.disasm) return;
    std::unordered_set<uint64_t> fset;
    for (auto& f : functions_) fset.insert(f.address);
    for (auto& f : functions_) {
        size_t avail = 0;
        const uint8_t* p = ctx.binary.ptrFromVA(f.address, avail);
        if (!p) continue;
        size_t win = f.size ? std::min<size_t>(avail, f.size) : std::min<size_t>(avail, 4096);
        auto& outv = callees_[f.address];
        size_t off = 0; int guard = 0;
        while (off < win && guard++ < 50000) {
            Instruction in;
            if (!ctx.disasm->decodeOne(p + off, win - off, f.address + off, in) || !in.length) { ++off; continue; }
            if (in.isCall && in.branchTarget && fset.count(in.branchTarget) &&
                std::find(outv.begin(), outv.end(), in.branchTarget) == outv.end()) {
                outv.push_back(in.branchTarget);
                callers_[in.branchTarget].push_back(f.address);
            }
            off += in.length;
        }
    }
}

// True when the cached call graph matches the current image; otherwise kick an
// off-thread K_CallGraph build (coalesced at the current epoch) and return false so
// the tab shows progress instead of sweeping every function body on the UI thread.
bool BinaryViewTab::ensureCallGraphReady(AppContext& ctx) {
    uint64_t sig = (ctx.binary.loaded() ? ctx.binary.contentHash() : 0) ^ ((uint64_t)functions_.size() << 1);
    if (sig == callGraphSig_) return true;
    if (callGraphRequestedSig_ != sig && ctx.binary.loaded() && ctx.disasm) {
        ctx.analysis.requestBulk(&ctx.binary, ctx.engine, ctx.arch, K_CallGraph, guessNames_, ctx.analysis.epoch());
        callGraphRequestedSig_ = sig;
    }
    return false;
}

void BinaryViewTab::renderCallGraph(AppContext& ctx) {
    if (!ctx.binary.loaded() || !ctx.disasm) { ImGui::TextDisabled("Load a binary to view the call graph."); return; }
    if (!ensureCallGraphReady(ctx)) {
        ImGui::TextDisabled("Building call graph\xE2\x80\xA6");
        drawAnalysisProgress(ctx, false);
        return;
    }

    uint64_t fn = cursorVA_;
    const Func* best = funcContaining(cursorVA_);
    if (best) fn = best->address;

    auto nameOf = [&](uint64_t a) {
        std::string s = symbolFor(ctx, a);
        if (s.empty()) { char b[28]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)a); s = b; }
        return s;
    };

    ImGui::TextDisabled("Call graph around the current function. Click a node to navigate.");
    ImGui::Text("Center: %s  (0x%llX)", nameOf(fn).c_str(), (unsigned long long)fn);
    ImGui::Separator();

    ImGui::Columns(3, "cg", true);
    ImGui::TextDisabled("Callers (callers of this fn)"); ImGui::NextColumn();
    ImGui::TextDisabled("This function");                ImGui::NextColumn();
    ImGui::TextDisabled("Callees (called by this fn)");  ImGui::NextColumn();
    ImGui::Separator();

    ui::PushMono();
    auto cit = callers_.find(fn);
    if (cit == callers_.end() || cit->second.empty()) ImGui::TextDisabled("(none found)");
    else for (uint64_t a : cit->second) { ImGui::PushID((void*)(uintptr_t)a); if (ImGui::Selectable(nameOf(a).c_str())) gotoStatic(ctx, a); ImGui::PopID(); }
    ImGui::NextColumn();

    ImGui::TextColored(theme::col::accent(), "%s", nameOf(fn).c_str());
    ImGui::NextColumn();

    auto eit = callees_.find(fn);
    if (eit == callees_.end() || eit->second.empty()) ImGui::TextDisabled("(none found)");
    else for (uint64_t a : eit->second) { ImGui::PushID((void*)(uintptr_t)(a ^ 0x55)); if (ImGui::Selectable(nameOf(a).c_str())) gotoStatic(ctx, a); ImGui::PopID(); }
    ImGui::NextColumn();
    ui::PopMono();

    ImGui::Columns(1);
}

// Best-effort calling-convention signature guess (x86-family only). Scans the
// prologue for argument registers read before being written, and whether a
// value is moved into rax/eax (return). Heuristic - clearly labelled as such.
std::string BinaryViewTab::guessSignature(AppContext& ctx, uint64_t fnStart, uint32_t fnSize) {
    if (!ctx.binary.loaded() || !ctx.disasm) return "";
    if (!(ctx.arch == Arch::X64 || ctx.arch == Arch::X86)) return "";
    size_t avail = 0;
    const uint8_t* p = ctx.binary.ptrFromVA(fnStart, avail);
    if (!p) return "";
    size_t win = fnSize ? std::min<size_t>(avail, fnSize) : std::min<size_t>(avail, 512);

    const char* win64[4] = { "rcx", "rdx", "r8", "r9" };
    const char* sysv[6]  = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };
    int win64Args = 0, sysvArgs = 0;
    std::unordered_set<std::string> written;
    bool setsRax = false;
    size_t off = 0; int n = 0;
    while (off < win && n < 80) {
        Instruction in;
        if (!ctx.disasm->decodeOne(p + off, win - off, fnStart + off, in) || !in.length) { ++off; continue; }
        size_t comma = in.operands.find(',');
        std::string dst = comma == std::string::npos ? in.operands : in.operands.substr(0, comma);
        std::string src = comma == std::string::npos ? std::string() : in.operands.substr(comma + 1);
        for (int i = 0; i < 4; ++i) if (!written.count(win64[i]) && src.find(win64[i]) != std::string::npos) win64Args = std::max(win64Args, i + 1);
        for (int i = 0; i < 6; ++i) if (!written.count(sysv[i])  && src.find(sysv[i])  != std::string::npos) sysvArgs  = std::max(sysvArgs,  i + 1);
        auto markIf = [&](const char* full, const char* alias) { if (dst.find(full) != std::string::npos || dst.find(alias) != std::string::npos) written.insert(full); };
        markIf("rcx","ecx"); markIf("rdx","edx"); markIf("r8","r8d"); markIf("r9","r9d"); markIf("rdi","edi"); markIf("rsi","esi");
        if ((in.mnemonic == "mov" || in.mnemonic == "lea" || in.mnemonic == "add" || in.mnemonic == "or" ||
             in.mnemonic == "xor" || in.mnemonic == "and" || in.mnemonic == "sub") &&
            (dst.find("rax") != std::string::npos || dst.find("eax") != std::string::npos)) setsRax = true;
        off += in.length; ++n;
        if (in.isRet) break;
    }
    int args = std::max(win64Args, sysvArgs);
    std::string sig = setsRax ? "__int64 " : "void ";
    sig += "(";
    for (int i = 0; i < args; ++i) { if (i) sig += ", "; sig += "a" + std::to_string(i + 1); }
    sig += ")";
    return sig;
}

std::string BinaryViewTab::dataRefToken(AppContext& ctx, uint64_t va, bool live) {
    if (!va) return "";
    // IAT slot / imported API. importMap_ is keyed by file VA, so translate when live.
    uint64_t fileVA = live ? liveVAtoFile(ctx, va) : va;
    if (auto it = importMap_.find(fileVA); it != importMap_.end()) return it->second;
    // A user rename or known symbol/global for this exact address.
    if (auto it = names_.find(fileVA); it != names_.end() && !it->second.empty()) return it->second;
    // A printable C string at the address -> a quoted, escaped, truncated literal.
    std::string s;
    if (live) {
        uint8_t buf[128];
        size_t got = ctx.debug.readMemory(va, buf, sizeof(buf));
        if (got >= 4) s = resolveString(buf, got);
    } else {
        size_t av = 0; const uint8_t* p = ctx.binary.ptrFromVA(va, av);
        if (p) s = resolveString(p, std::min(av, (size_t)128));
    }
    if (s.size() >= 3) {
        std::string q = "\"";
        for (char c : s) {
            if (q.size() > 48) { q += "..."; break; }
            if (c == '"' || c == '\\') q += '\\';
            if (c == '\n') { q += "\\n"; continue; }
            if (c == '\t') { q += "\\t"; continue; }
            if (c == '\r') { q += "\\r"; continue; }
            q += c;
        }
        q += "\"";
        return q;
    }
    return "";
}

// Resolve a `jmp [reg*scale + table]` switch jump table: read pointer-sized
// entries from the table until one falls outside the mapped image.
std::vector<uint64_t> BinaryViewTab::resolveJumpTable(AppContext& ctx, const Instruction& in) {
    std::vector<uint64_t> out;
    if (in.mnemonic != "jmp" || in.operands.find('[') == std::string::npos) return out;
    const std::string& o = in.operands;
    bool s8 = o.find("*8") != std::string::npos, s4 = o.find("*4") != std::string::npos;
    if (!s8 && !s4) return out;
    uint64_t tableVA = 0;
    for (size_t i = 0; i + 1 < o.size(); ++i)
        if (o[i] == '0' && (o[i + 1] == 'x' || o[i + 1] == 'X')) {
            unsigned long long v = 0; if (std::sscanf(o.c_str() + i, "0x%llx", &v) == 1 && (uint64_t)v > tableVA) tableVA = (uint64_t)v;
        }
    if (tableVA < 0x1000) return out;
    int esz = s8 ? 8 : 4;
    for (int k = 0; k < 1024; ++k) {
        size_t av = 0;
        const uint8_t* p = ctx.binary.ptrFromVA(tableVA + (uint64_t)k * esz, av);
        if (!p || av < (size_t)esz) break;
        uint64_t t = 0; std::memcpy(&t, p, (size_t)esz);
        size_t ta = 0;
        if (!ctx.binary.ptrFromVA(t, ta)) break;   // entry not a mapped address -> end of table
        out.push_back(t);
    }
    return out;
}

void BinaryViewTab::renderGraph(AppContext& ctx) {
    panelPopToggle(&graphPoppedOut_, "cfg"); ImGui::SameLine();
    if (!ctx.binary.loaded() || !ctx.disasm) {
        ImGui::TextDisabled("Load a binary to view the control-flow graph.");
        return;
    }
    uint64_t va = cursorVA_;
    size_t size = 0;
    const uint8_t* p = codeWindow(ctx, va, size);
    if (cursorVA_ == 0) cursorVA_ = va;
    if (!p) { ImGui::TextDisabled("Cursor address is not mapped to code."); return; }

    // Build the CFG for the function at the cursor -- cached. BuildCFG decodes up to
    // 1500 instructions and runs dominator/loop analysis; rebuild only when the root
    // VA, the decoder, or the actual code-window bytes change (so a patch/reload still
    // refreshes) instead of rebuilding the whole graph every frame.
    const size_t win = std::min<size_t>(size, 8192);
    uint64_t cfgSig = 1469598103934665603ull;
    auto cfgMix = [&cfgSig](uint64_t x) { cfgSig = (cfgSig ^ x) * 1099511628211ull; };
    cfgMix(va); cfgMix(win); cfgMix((uint64_t)(uintptr_t)ctx.disasm.get());
    for (size_t i = 0; i < win; ++i) cfgSig = (cfgSig ^ p[i]) * 1099511628211ull;
    if (cfgSig != cfgCacheSig_) {
        auto jt = [this, &ctx](const Instruction& in) { return resolveJumpTable(ctx, in); };
        cfgCache_ = BuildCFG(p, win, va, *ctx.disasm, 1500, jt);
        cfgCacheSig_ = cfgSig;
    }
    const ControlFlowGraph& g = cfgCache_;

    // Title: resolved function name + stats.
    std::string fn = showNames_ ? symbolFor(ctx, va) : std::string();
    if (fn.empty() || fn.find("+0x") != std::string::npos) { char b[32]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)va); fn = b; }
    ImGui::TextColored(theme::col::accent(), "%s", fn.c_str());
    ImGui::SameLine(); ImGui::TextDisabled("@ 0x%llX  -  %d block(s)", (unsigned long long)va, (int)g.blocks.size());
    ImGui::SameLine();
    if (ImGui::SmallButton("Reset layout")) cfgDrag_.clear();
    ImGui::SameLine(); ImGui::TextDisabled("(drag empty space to pan; drag a block to move it; double-click a block to re-root)");

    auto swatch = [](ImU32 c, const char* label) {
        ImVec2 p0 = ImGui::GetCursorScreenPos();
        float h = ImGui::GetTextLineHeight();
        ImGui::GetWindowDrawList()->AddRectFilled(p0, ImVec2(p0.x + h * 1.7f, p0.y + h), c, 3.0f);
        ImGui::Dummy(ImVec2(h * 1.7f + 5, h)); ImGui::SameLine(0, 5);
        ImGui::TextUnformatted(label); ImGui::SameLine(0, 14);
    };
    swatch(IM_COL32(90, 200, 110, 235),  "taken");
    swatch(IM_COL32(150, 160, 175, 205), "fallthrough");
    swatch(IM_COL32(110, 165, 230, 225), "jump");
    swatch(IM_COL32(120, 230, 120, 255), "current (RIP)");
    ImGui::NewLine();

    DbgSnapshot snap = ctx.debug.snapshot();
    const float lineH = ImGui::GetTextLineHeightWithSpacing();
    const float pad   = 9.0f;
    const float hdrH  = lineH + 6.0f;
    const float vGap  = 50.0f;
    const float colW  = 400.0f;

    // Format an instruction line: short +offset, mnemonic, operands, then the
    // resolved call/jump target name and any referenced string (x64dbg-style).
    auto fmtInsn = [&](const Instruction& in) -> std::string {
        char head[20];
        uint64_t off = in.address - va;
        if (off < 0x1000000) std::snprintf(head, sizeof(head), "+%llX", (unsigned long long)off);
        else                 std::snprintf(head, sizeof(head), "%llX", (unsigned long long)(in.address & 0xFFFFFFFF));
        char line[224];
        std::snprintf(line, sizeof(line), "%-7s %-6s %s", head, in.mnemonic.c_str(), in.operands.c_str());
        std::string r = line;
        if (showNames_ && in.branchTarget && (in.isCall || in.isBranch)) {
            std::string nm = symbolFor(ctx, in.branchTarget);
            if (!nm.empty()) { r += "  -> "; r += nm; }
        }
        if (showStringComments_) {
            uint64_t ref = instrDataRef(in);
            if (!ref) ref = instrImmRef(in);   // also catch `mov reg, offset str` / `push offset str`
            if (ref) {
                size_t av = 0; const uint8_t* sp = ctx.binary.ptrFromVA(ref, av);
                if (sp) {
                    std::string s = resolveString(sp, std::min<size_t>(av, 64));
                    if (!s.empty()) { r += "  ; \""; r += s.substr(0, 38); r += "\""; }
                }
            }
        }
        return r;
    };

    ui::PushMono();
    std::vector<ImVec2> sz(g.blocks.size()), pos(g.blocks.size());
    std::vector<int>    col(g.blocks.size(), 0);
    for (size_t i = 0; i < g.blocks.size(); ++i) {
        const auto& b = g.blocks[i];
        float maxw = ImGui::CalcTextSize("loc_0000000000  (fallthrough)").x;
        for (const auto& in : b.insns) maxw = std::max(maxw, ImGui::CalcTextSize(fmtInsn(in).c_str()).x);
        sz[i] = ImVec2(maxw + pad * 2, hdrH + b.insns.size() * lineH + pad);
    }
    for (size_t i = 0; i < g.blocks.size(); ++i)
        for (size_t s = 0; s < g.blocks[i].succ.size(); ++s) {
            size_t t = g.blocks[i].succ[s];
            if (t < g.blocks.size() && t > i) col[t] = std::max(col[t], col[i] + (s == 0 && g.blocks[i].succ.size() > 1 ? 1 : 0));
        }

    ImGui::BeginChild("cfg_canvas", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    ImVec2 origin = ImGui::GetCursorScreenPos();
    float y = origin.y + 12.0f;
    for (size_t i = 0; i < g.blocks.size(); ++i) {
        pos[i] = ImVec2(origin.x + 24.0f + col[i] * colW, y);
        y += sz[i].y + vGap;
    }
    // Apply stored per-block drag offsets.
    for (size_t i = 0; i < g.blocks.size(); ++i) {
        auto it = cfgDrag_.find(g.blocks[i].start);
        if (it != cfgDrag_.end()) { pos[i].x += it->second.first; pos[i].y += it->second.second; }
    }

    // Interaction: click a block to focus it, drag a block to move it, drag empty space to pan.
    ImGuiIO& gio = ImGui::GetIO();
    bool blockActive = false;
    for (size_t i = 0; i < g.blocks.size(); ++i) {
        ImGui::SetCursorScreenPos(pos[i]);
        ImGui::PushID((void*)(uintptr_t)g.blocks[i].start);
        ImGui::InvisibleButton("blk", sz[i]);
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) cursorVA_ = g.blocks[i].start;
        if (ImGui::IsItemActive()) {
            blockActive = true;
            if (ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
                auto& o = cfgDrag_[g.blocks[i].start];
                o.first  += gio.MouseDelta.x; o.second += gio.MouseDelta.y;
                pos[i].x += gio.MouseDelta.x; pos[i].y += gio.MouseDelta.y;
                ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
            }
        }
        ImGui::PopID();
    }
    if (!blockActive && ImGui::IsWindowHovered() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        ImGui::SetScrollX(ImGui::GetScrollX() - gio.MouseDelta.x);
        ImGui::SetScrollY(ImGui::GetScrollY() - gio.MouseDelta.y);
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    }

    // Content extent (includes drag offsets) for the scroll area.
    float maxX = 0, maxY = 0;
    for (size_t i = 0; i < g.blocks.size(); ++i) {
        maxX = std::max(maxX, pos[i].x + sz[i].x);
        maxY = std::max(maxY, pos[i].y + sz[i].y);
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float pulse = slowPulse();

    // Edges (under boxes) with a soft shadow.
    for (size_t i = 0; i < g.blocks.size(); ++i) {
        const auto& b = g.blocks[i];
        ImVec2 from = ImVec2(pos[i].x + sz[i].x * 0.5f, pos[i].y + sz[i].y);
        for (size_t s = 0; s < b.succ.size(); ++s) {
            size_t t = b.succ[s];
            if (t >= pos.size()) continue;
            ImVec2 to = ImVec2(pos[t].x + sz[t].x * 0.5f, pos[t].y);
            ImU32 colr = (b.succ.size() > 1 && s == 0) ? IM_COL32(90, 200, 110, 235)
                       : (b.succ.size() > 1)           ? IM_COL32(150, 160, 175, 205)
                                                       : IM_COL32(110, 165, 230, 225);
            float midY = (from.y + to.y) * 0.5f;
            dl->AddBezierCubic(from, ImVec2(from.x, midY), ImVec2(to.x, midY), to, IM_COL32(0, 0, 0, 80), 4.5f);
            dl->AddBezierCubic(from, ImVec2(from.x, midY), ImVec2(to.x, midY), to, colr, 2.3f);
            dl->AddCircleFilled(from, 2.6f, colr);
            dl->AddTriangleFilled(ImVec2(to.x - 5, to.y - 9), ImVec2(to.x + 5, to.y - 9), ImVec2(to.x, to.y), colr);
        }
    }

    // Boxes.
    for (size_t i = 0; i < g.blocks.size(); ++i) {
        const auto& b = g.blocks[i];
        ImVec2 a = pos[i], c = ImVec2(pos[i].x + sz[i].x, pos[i].y + sz[i].y);
        bool hasRip = snap.attached() && snap.regs.rip >= b.start && snap.regs.rip < b.end;
        bool isCur  = cursorVA_ >= b.start && cursorVA_ < b.end;

        dl->AddRectFilled(ImVec2(a.x + 3, a.y + 4), ImVec2(c.x + 3, c.y + 4), IM_COL32(0, 0, 0, 70), 7.0f);      // shadow
        dl->AddRectFilled(a, c, b.isReturn ? IM_COL32(44, 29, 33, 250) : IM_COL32(25, 29, 37, 250), 7.0f);       // body
        ImU32 hcol = b.isReturn ? IM_COL32(118, 56, 56, 255) : (i == 0) ? IM_COL32(44, 86, 60, 255) : IM_COL32(43, 53, 71, 255);
        dl->AddRectFilled(a, ImVec2(c.x, a.y + hdrH), hcol, 7.0f, ImDrawFlags_RoundCornersTop);                  // header strip

        if (hasRip)
            dl->AddRect(ImVec2(a.x - 2, a.y - 2), ImVec2(c.x + 2, c.y + 2),
                        IM_COL32(90, 230, 90, (int)(55 + 90 * pulse)), 9.0f, 0, 3.0f);                           // RIP glow
        ImU32 border = hasRip ? IM_COL32(95, (int)(180 + 60 * pulse), 95, 255)
                     : isCur  ? IM_COL32(95, 150, 225, 255)
                     : b.isReturn ? IM_COL32(190, 95, 95, 235) : IM_COL32(70, 84, 104, 235);
        dl->AddRect(a, c, border, 7.0f, 0, (hasRip || isCur) ? 2.6f : 1.4f);

        char hdr[64];
        std::snprintf(hdr, sizeof(hdr), "loc_%llX%s", (unsigned long long)b.start,
                      i == 0 ? "  (entry)" : b.isReturn ? "  (return)" : "");
        dl->AddText(ImVec2(a.x + pad, a.y + 4), IM_COL32(235, 226, 182, 255), hdr);

        float ty = a.y + hdrH + 2.0f;
        for (const auto& in : b.insns) {
            bool atRip = snap.attached() && snap.regs.rip == in.address;
            if (atRip)
                dl->AddRectFilled(ImVec2(a.x + 2, ty - 1), ImVec2(c.x - 2, ty + lineH - 3),
                                  IM_COL32(40, 90, 45, (int)(110 + 80 * pulse)), 3.0f);
            ImU32 tc = atRip ? IM_COL32(160, 248, 160, 255)
                     : in.isCall ? IM_COL32(150, 205, 255, 255)
                     : in.isBranch ? IM_COL32(245, 205, 125, 255) : IM_COL32(224, 227, 232, 255);
            dl->AddText(ImVec2(a.x + pad, ty), tc, fmtInsn(in).c_str());
            ty += lineH;
        }
    }

    ImGui::SetCursorScreenPos(origin);   // reset (block drag handles moved the cursor)
    ImGui::Dummy(ImVec2(maxX - origin.x + 50.0f, maxY - origin.y + 24.0f));
    ui::PopMono();
    ImGui::EndChild();
}

void BinaryViewTab::runByteSearch(AppContext& ctx) {
    searchHits_.clear();
    if (!byteSearch_[0]) return;
    if (byteSearchLive_) {                 // scan the attached process instead of the file
        if (!ctx.debug.snapshot().attached()) return;
        std::string st;
        searchHits_ = liveMemorySearch(ctx.debug, byteSearch_, 2 /*hex bytes*/, st);
        return;
    }
    if (!ctx.binary.loaded()) return;
    // Parse hex bytes (spaces optional), no wildcards for this quick search.
    std::vector<uint8_t> pat;
    std::string s = byteSearch_;
    for (size_t i = 0; i < s.size();) {
        if (std::isspace((unsigned char)s[i])) { ++i; continue; }
        // Require a full two-hex-digit byte; a lone trailing nibble is malformed.
        if (i + 1 >= s.size() || !std::isxdigit((unsigned char)s[i]) || !std::isxdigit((unsigned char)s[i + 1])) break;
        char b[3] = { s[i], s[i + 1], 0 }; unsigned v = 0;
        std::sscanf(b, "%x", &v);
        pat.push_back((uint8_t)v); i += 2;
    }
    if (pat.empty()) return;
    const auto& d = ctx.binary.bytes();
    for (size_t i = 0; i + pat.size() <= d.size(); ++i) {
        bool hit = true;
        for (size_t j = 0; j < pat.size(); ++j) if (d[i+j] != pat[j]) { hit = false; break; }
        if (hit) { uint64_t va; if (ctx.binary.offsetToVA(i, va)) searchHits_.push_back(va); if (searchHits_.size() > 1024) break; }
    }
}

void BinaryViewTab::renderSidePanel(AppContext& ctx) {
    panelPopToggle(&sidePoppedOut_, "side");
    ImGui::SeparatorText("Byte Pattern Search");
    ImGui::SetNextItemWidth(-60);
    ImGui::InputTextWithHint("##bsearch", "DE AD BE EF", byteSearch_, sizeof(byteSearch_));
    ImGui::SameLine();
    if (ImGui::Button("Find")) runByteSearch(ctx);
    if (ImGui::Checkbox("Live (process memory)", &byteSearchLive_)) searchHits_.clear();
    if (byteSearchLive_ && !ctx.debug.snapshot().attached())
        ImGui::TextDisabled("Attach to a process to search its memory.");
    if (!searchHits_.empty()) {
        ImGui::Text("%d hit(s)", (int)searchHits_.size());
        ImGui::BeginChild("shits", ImVec2(0, 90), ImGuiChildFlags_Borders);
        for (auto a : searchHits_) {
            char lbl[32]; std::snprintf(lbl, sizeof(lbl), "0x%llX", (unsigned long long)a);
            // Live hits are runtime VAs -> live view; file hits -> static view. Both record history.
            if (ImGui::Selectable(lbl)) { if (byteSearchLive_) { mainView_ = 4; liveNavigate(a); } else navigateTo(a); }
        }
        ImGui::EndChild();
    }

    if (ImGui::BeginTabBar("side")) {
        if (ImGui::BeginTabItem("Bookmarks")) {
            // Bookmarks persist as FILE VAs; in the live view translate the runtime cursor back.
            if (ImGui::SmallButton("+ here") && ctx.binary.loaded())
                bookmarks_.push_back({ mainView_ == 4 ? liveVAtoFile(ctx, cursorVA_) : cursorVA_, "bookmark" });
            ImGui::SameLine(); ImGui::TextDisabled("(persists with the project)");
            int removeAt = -1;
            for (int i = 0; i < (int)bookmarks_.size(); ++i) {
                auto& b = bookmarks_[i];
                ImGui::PushID(i);
                char lbl[96]; std::snprintf(lbl, sizeof(lbl), "0x%llX %s",
                    (unsigned long long)b.address, b.label.c_str());
                if (ImGui::Selectable(lbl)) gotoStatic(ctx, b.address);
                if (ImGui::BeginPopupContextItem("bmctx")) {
                    if (ImGui::MenuItem("Go to")) gotoStatic(ctx, b.address);
                    ImGui::SetNextItemWidth(180);
                    char nameTmp[64]; std::snprintf(nameTmp, sizeof(nameTmp), "%s", b.label.c_str());
                    if (ImGui::InputText("label", nameTmp, sizeof(nameTmp), ImGuiInputTextFlags_EnterReturnsTrue)) b.label = nameTmp;
                    if (ImGui::MenuItem("Remove")) removeAt = i;
                    ImGui::EndPopup();
                }
                ImGui::PopID();
            }
            if (removeAt >= 0) bookmarks_.erase(bookmarks_.begin() + removeAt);
            if (bookmarks_.empty()) ImGui::TextDisabled("No bookmarks.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Functions")) {
            ImGui::BeginDisabled(!ctx.binary.loaded() || !ctx.disasm);
            if (ImGui::SmallButton("Analyze")) analyzeFunctions(ctx);
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Checkbox("Guess", &guessNames_)) analyzeFunctions(ctx);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Heuristically name unknown functions\n(read_file, net_send, j_CreateFileW, start, ...)");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##fnf", "filter...", fnFilter_, sizeof(fnFilter_));
            if (!fnSummary_.empty()) ImGui::TextDisabled("%s", fnSummary_.c_str());

            if (functions_.empty()) {
                ImGui::TextDisabled("Code sections:");
                for (const auto& s : ctx.binary.sections()) {
                    if (!s.executable) continue;
                    char lbl[96]; std::snprintf(lbl, sizeof(lbl), "%-8s  0x%llX",
                        s.name.c_str(), (unsigned long long)(ctx.binary.imageBase() + s.virtualAddress));
                    if (ImGui::Selectable(lbl)) gotoStatic(ctx, ctx.binary.imageBase() + s.virtualAddress);
                }
            } else {
                ImGui::BeginChild("fnlist", ImVec2(0, 0), ImGuiChildFlags_Borders);
                ui::PushMono();   // monospace so the 0x... address column lines up
                // Filter into an index list, then clipper-render only visible rows.
                fnVisible_.clear();
                for (int i = 0; i < (int)functions_.size(); ++i) {
                    if (fnFilter_[0]) {
                        const Func& f = functions_[i];
                        std::string dn = annName(ctx, f.address);
                        const std::string& nm = dn.empty() ? f.name : dn;
                        if (nm.find(fnFilter_) == std::string::npos && f.name.find(fnFilter_) == std::string::npos) continue;
                    }
                    fnVisible_.push_back(i);
                }
                ImGuiListClipper fnClip;
                fnClip.Begin((int)fnVisible_.size());
                while (fnClip.Step())
                    for (int row = fnClip.DisplayStart; row < fnClip.DisplayEnd; ++row) {
                        const Func& f = functions_[fnVisible_[row]];
                        std::string dn = annName(ctx, f.address);
                        const std::string& nm = dn.empty() ? f.name : dn;
                        char lbl[160]; std::snprintf(lbl, sizeof(lbl), "0x%llX  %s",
                            (unsigned long long)f.address, nm.c_str());
                        ImGui::PushID(fnVisible_[row]);
                        // A heuristic guess (no user rename overriding) is tinted amber
                        // with its basis as a tooltip, so it reads as best-effort.
                        const bool guessShown = f.guessed && dn.empty();
                        if (guessShown) ImGui::PushStyleColor(ImGuiCol_Text, theme::col::warn());
                        if (ImGui::Selectable(lbl)) gotoStatic(ctx, f.address);
                        if (guessShown) ImGui::PopStyleColor();
                        if (guessShown && ImGui::IsItemHovered()) {
                            auto rit = guessReason_.find(f.address);
                            ImGui::SetTooltip("guessed name - %s",
                                rit != guessReason_.end() ? rit->second.c_str() : "heuristic");
                        }
                        ImGui::PopID();
                    }
                ui::PopMono();
                ImGui::EndChild();
            }
            if (!ctx.binary.loaded()) ImGui::TextDisabled("No binary loaded.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Strings")) {
            DbgSnapshot ssnap = ctx.debug.snapshot();
            // Discoverability: the first time we're attached to a new process, flip to
            // Live and scan once automatically so live strings "just work" without the
            // user having to find the Live toggle.
            if (ssnap.attached() && ssnap.pid && stringsAutoPid_ != ssnap.pid) {
                stringsAutoPid_ = ssnap.pid;
                stringsLive_    = true;
                scanStrings(ctx);
            }
            bool canScan = stringsLive_ ? ssnap.attached() : ctx.binary.loaded();
            ImGui::BeginDisabled(!canScan);
            if (ImGui::SmallButton("Scan")) scanStrings(ctx);
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Checkbox("Live", &stringsLive_)) {
                strings_.clear(); stringsScanned_ = false;
                // Re-scan immediately on toggle when we can, so the list never looks empty.
                if (stringsLive_ ? ssnap.attached() : ctx.binary.loaded()) scanStrings(ctx);
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Scan the attached process's memory instead of the file on disk.");
            ImGui::SameLine(); ImGui::TextDisabled("%d (ASCII/UTF-8 + UTF-16)", (int)strings_.size());
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##strf", "filter...", strFilter_, sizeof(strFilter_));

            // Fixed-width columns so addresses, type, and text line up (the old
            // single-label render was ragged because hex addresses vary in width).
            ImGui::BeginChild("strs", ImVec2(0, 0), ImGuiChildFlags_Borders);
            ui::PushMono();
            if (ImGui::BeginTable("strtbl", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV)) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("T",       ImGuiTableColumnFlags_WidthFixed, 22);
                ImGui::TableSetupColumn("String");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                strVisible_.clear();
                for (int i = 0; i < (int)strings_.size(); ++i)
                    if (!strFilter_[0] || strings_[i].text.find(strFilter_) != std::string::npos) strVisible_.push_back(i);
                ImGuiListClipper strClip;
                strClip.Begin((int)strVisible_.size());
                while (strClip.Step())
                    for (int row = strClip.DisplayStart; row < strClip.DisplayEnd; ++row) {
                    auto& s = strings_[strVisible_[row]];
                    ImGui::TableNextRow();
                    ImGui::PushID((void*)(uintptr_t)s.address);
                    ImGui::TableSetColumnIndex(0);
                    char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)s.address);
                    if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) { if (stringsLive_) { mainView_ = 4; liveNavigate(s.address); } else navigateTo(s.address); }
                    if (ImGui::BeginPopupContextItem("sm")) {
                        if (ImGui::MenuItem("Go to"))                       { if (stringsLive_) { mainView_ = 4; liveNavigate(s.address); } else navigateTo(s.address); }
                        if (ImGui::MenuItem("Find references (where used)")) startXrefSearch(ctx, s.address);
                        if (ImGui::MenuItem("Copy address")) {
                            char c[24]; std::snprintf(c, sizeof(c), "0x%llX", (unsigned long long)s.address); ImGui::SetClipboardText(c);
                        }
                        if (ImGui::MenuItem("Copy string")) ImGui::SetClipboardText(s.text.c_str());
                        ImGui::EndPopup();
                    }
                    ImGui::TableSetColumnIndex(1); ImGui::TextDisabled(s.wide ? "L" : "A");
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(s.text.c_str());
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ui::PopMono();
            if (stringsScanning_) {                 // a live scan is running off-thread
                ImGui::TextDisabled("Scanning process memory...");
                ImGui::SameLine();
                LiveProgress lp = ctx.livescan.progress();
                float frac = lp.total > 0 ? (float)lp.current / (float)lp.total : -1.0f;
                float w = 140.0f * theme::UiScale();
                if (frac >= 0.0f) ImGui::ProgressBar(frac, ImVec2(w, 0.0f));
                else { float t = (float)ImGui::GetTime(); ImGui::ProgressBar(t - (float)(long long)t, ImVec2(w, 0.0f), ""); }
            } else if (stringsScanned_ && strings_.empty()) {
                ImGui::TextDisabled(stringsLive_ ? "No strings found in process memory." : "No strings found.");
            } else if (!stringsScanned_) {
                if (stringsLive_ && !ssnap.attached()) ImGui::TextDisabled("Attach to a process, then Scan.");
                else ImGui::TextDisabled("Press Scan to extract strings.");
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

// ---- F1/F2/F3 advanced features --------------------------------------------
// Run synchronously on demand (matching the decompiler's lazy-synchronous model);
// the AnalysisService worker path is a documented follow-up. With the stub engine
// (engines feature off) F1/F3 report "engine unavailable"; F2's asm tier works now.

static Arch archOf(AppContext& ctx) { return ctx.binary.is64Bit() ? Arch::X64 : Arch::X86; }

void BinaryViewTab::runSynthesis(AppContext& ctx, uint64_t lo, uint64_t end) {
    if (!ctx.binary.loaded() || end <= lo) return;
    // Off the render thread via the AnalysisService worker (K_Synthesis); the result is
    // adopted in the bulk-drain loop. Current epoch so a load/patch supersedes it.
    synthHave_ = false; synthPending_ = true; synthFocus_ = true;
    ctx.analysis.requestBulk(&ctx.binary, ctx.engine, ctx.arch, K_Synthesis, guessNames_,
                             ctx.analysis.epoch(), 0, lo, end);
}

void BinaryViewTab::renderSynthesisTab(AppContext& ctx) {
    ImGuiTabItemFlags f = synthFocus_ ? ImGuiTabItemFlags_SetSelected : 0;
    synthFocus_ = false;
    if (!ImGui::BeginTabItem("Synthesis", nullptr, f)) return;
    if (synthPending_) {
        ImGui::TextDisabled("Synthesizing region\xE2\x80\xA6 (running on the analysis worker)");
        ImGui::EndTabItem();
        return;
    }
    if (!synthHave_) {
        ImGui::TextDisabled("Select a loop-free region, right-click \xE2\x86\x92 \"Synthesize equivalent (F1)\".");
        ImGui::TextDisabled("F1 simplifies MBA / opaque-predicate / junk into clean code, verified by");
        ImGui::TextDisabled("N random input/output samples (a best-effort badge, not a formal proof).");
        ImGui::EndTabItem();
        return;
    }
    const SynthResult& r = synth_;
    ImGui::Text("Region 0x%llX  (%u bytes)", (unsigned long long)r.regionStart, r.regionSize);
    if (!r.inEnvelope) {
        ImGui::TextColored(theme::col::bad(), "Out of envelope: %s", r.rejectedReason.c_str());
    } else if (!r.rejectedReason.empty()) {
        ImGui::TextColored(theme::col::warn(), "%s", r.rejectedReason.c_str());
        ImGui::TextDisabled("Enable the 'engines' vcpkg feature + DS_HAVE_SYMENGINE for real symbolic execution.");
    } else {
        ImGui::TextColored(theme::col::warn(), "confidence %.1f%%  (%u/%u samples)%s",
                           r.confidence * 100.0, r.samplesPassed, r.samplesTotal,
                           r.z3Equivalent ? "   [solver-equivalent]" : "");
        ui::PushMono();
        ImGui::TextUnformatted(r.cleanedPseudoC.c_str());
        ui::PopMono();
        if (ImGui::SmallButton("Save to project")) {
            ctx.project.syntheses.push_back(PjSynthesis{
                r.regionStart, r.regionSize, r.cleanedPseudoC,
                r.samplesPassed, r.samplesTotal, r.z3Equivalent, r.reasoning });
            projectDirty_ = true;
        }
    }
    if (!r.reasoning.empty()) ImGui::TextDisabled("%s", r.reasoning.c_str());
    ImGui::EndTabItem();
}

void BinaryViewTab::openHotPatch(AppContext& ctx, uint64_t siteVA, uint32_t origLen) {
    (void)ctx;
    hotSiteVA_ = siteVA; hotOrigLen_ = origLen; hotFocus_ = true; hotStatus_.clear();
}

void BinaryViewTab::applyHotPatch(AppContext& ctx) {
    const PatchLang lang = hotLang_ == 1 ? PatchLang::C : hotLang_ == 2 ? PatchLang::Python : PatchLang::Asm;
    PatchCtx pc; pc.arch = archOf(ctx); pc.siteVA = hotSiteVA_;
    CompileResult cr = CompilePatch(lang, hotEditor_, pc);
    if (!cr.ok) { hotStatus_ = std::string("compile: ") + cr.diagnostics; return; }

    // Gather executable regions to scan for code caves.
    std::vector<ExecRegion> regions;
    for (const auto& s : ctx.binary.sections()) {
        if (!s.executable) continue;
        const uint64_t va = ctx.binary.imageBase() + s.virtualAddress;
        size_t avail = 0; const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
        if (p) regions.push_back({ va, p, (size_t)std::min<uint64_t>(avail, s.virtualSize) });
    }
    PlaceInput pin;
    pin.siteVA  = hotSiteVA_;
    pin.origLen = hotOrigLen_;
    pin.newBody = cr.bytes;
    pin.caves   = FindCodeCaves(regions, cr.bytes.size() + kDetourJmpLen);
    PlaceResult pr = PlacePatch(pin);
    if (pr.status == PlaceStatus::Refused || pr.status == PlaceStatus::NeedsAlloc) {
        hotStatus_ = std::string("place: ") + pr.reason; return;
    }
    for (const auto& w : pr.writes) applyPatchBytes(ctx, w.va, w.bytes, (uint32_t)w.origLen, false);
    ctx.project.hotPatches.push_back(PjHotPatch{ hotSiteVA_, PatchLangName(lang), std::string(hotEditor_) });
    projectDirty_ = true;
    if (pr.status == PlaceStatus::InSpan) {
        hotStatus_ = "patched in-span (" + std::to_string(cr.bytes.size()) + " bytes)";
    } else {
        char b[64];
        std::snprintf(b, sizeof(b), "patched via detour @ 0x%llX", (unsigned long long)pr.caveVA);
        hotStatus_ = b;
    }
}

void BinaryViewTab::renderHotPatchTab(AppContext& ctx) {
    ImGuiTabItemFlags f = hotFocus_ ? ImGuiTabItemFlags_SetSelected : 0;
    hotFocus_ = false;
    if (!ImGui::BeginTabItem("Hot-Patch", nullptr, f)) return;
    if (hotSiteVA_ == 0) {
        ImGui::TextDisabled("Right-click a selection \xE2\x86\x92 \"Hot-patch this selection (F2)\".");
        ImGui::TextDisabled("Write a replacement; it is compiled and injected (in-span or via a code-cave detour).");
    } else {
        ImGui::Text("Site 0x%llX   span %u bytes", (unsigned long long)hotSiteVA_, hotOrigLen_);
        ImGui::RadioButton("Asm", &hotLang_, 0); ImGui::SameLine();
        ImGui::RadioButton("C", &hotLang_, 1);   ImGui::SameLine();
        ImGui::RadioButton("Python", &hotLang_, 2);
        ui::PushMono();
        ImGui::InputTextMultiline("##hotsrc", hotEditor_, sizeof(hotEditor_),
                                  ImVec2(-1.0f, 160.0f * theme::UiScale()));
        ui::PopMono();
        if (ImGui::Button("Compile & Patch")) applyHotPatch(ctx);
        if (!hotStatus_.empty()) { ImGui::SameLine(); ImGui::TextWrapped("%s", hotStatus_.c_str()); }
        ImGui::TextDisabled("Asm works now (Keystone). C/Python need the libtcc / python build (DS_HAVE_LIBTCC / DS_HAVE_PYTHON).");
    }
    ImGui::EndTabItem();
}

void BinaryViewTab::runPathExplore(AppContext& ctx, uint64_t rootVA) {
    if (!ctx.binary.loaded() || rootVA == 0) return;
    // STATIC structural exploration off the render thread (K_PathExplore): builds a CFG
    // look-ahead tree from the file image. Richer symbolic tags + input solving arrive
    // with the engines build; the live-debugger concolic explore is the own-thread follow-up.
    pathHave_ = false; pathPending_ = true; pathFocus_ = true; pathStatus_.clear();
    ctx.analysis.requestBulk(&ctx.binary, ctx.engine, ctx.arch, K_PathExplore, guessNames_,
                             ctx.analysis.epoch(), 0, rootVA, rootVA + 1);
}

void BinaryViewTab::renderPathExplorerTab(AppContext& ctx) {
    ImGuiTabItemFlags f = pathFocus_ ? ImGuiTabItemFlags_SetSelected : 0;
    pathFocus_ = false;
    if (!ImGui::BeginTabItem("Path Explorer", nullptr, f)) return;
    if (pathPending_) {
        ImGui::TextDisabled("Exploring paths\xE2\x80\xA6 (building the CFG look-ahead tree)");
        ImGui::EndTabItem();
        return;
    }
    if (!pathHave_) {
        ImGui::TextDisabled("Right-click a region \xE2\x86\x92 \"Explore paths from here (F3)\" for a CFG look-ahead tree.");
        ImGui::TextDisabled("Structural now; symbolic tags (overflow) + input solving arrive with the engines build.");
        if (!pathStatus_.empty()) ImGui::TextWrapped("%s", pathStatus_.c_str());
        ImGui::EndTabItem();
        return;
    }
    // Render the path tree (when an engine-backed explorer populated it).
    std::function<void(int)> drawNode = [&](int idx) {
        if (idx < 0 || idx >= (int)pathTree_.nodes.size()) return;
        const PathNode& n = pathTree_.nodes[idx];
        ImVec4 col = theme::col::muted();
        switch (n.tag) {
            case PathTag::IntOverflow: col = theme::col::bad();  break;
            case PathTag::HiddenCode:  col = theme::col::warn(); break;
            case PathTag::Escaped:     col = theme::col::muted();break;
            case PathTag::Safe:        col = theme::col::good(); break;
        }
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        const bool open = ImGui::TreeNodeEx((void*)(intptr_t)idx, ImGuiTreeNodeFlags_DefaultOpen,
                                            "0x%llX  [%s]", (unsigned long long)n.blockVA, PathTagName(n.tag));
        ImGui::PopStyleColor();
        if (ImGui::IsItemClicked()) ctx.gotoAddress(n.blockVA);
        if (open) { for (int c : n.children) drawNode(c); ImGui::TreePop(); }
    };
    if (!pathTree_.nodes.empty()) drawNode(0);
    if (pathTree_.truncated) ImGui::TextDisabled("(tree truncated at the depth/node budget)");
    ImGui::EndTabItem();
}

void BinaryViewTab::renderLowerTabs(AppContext& ctx) {
    panelPopToggle(&lowerPoppedOut_, "lower");
    if (ImGui::BeginTabBar("lower")) {
        renderSynthesisTab(ctx);
        renderHotPatchTab(ctx);
        renderPathExplorerTab(ctx);
        if (ImGui::BeginTabItem("Breakpoints")) {
            DbgSnapshot snap = ctx.debug.snapshot();
            ImGui::SeparatorText("Software (0xCC)");
            if (snap.attached()) {
                if (snap.breakpoints.empty()) ImGui::TextDisabled("None. Click the gutter or right-click an address.");
                ImGui::TextDisabled("Condition examples:  rax == 0x10   |   rcx > 100   |   [rsp+8] != 0");
                for (size_t i = 0; i < snap.breakpoints.size(); ++i) {
                    const auto& bp = snap.breakpoints[i];
                    ImGui::PushID((int)i);
                    ImGui::Text("0x%llX", (unsigned long long)bp.address);
                    ImGui::SameLine();
                    if (ImGui::SmallButton("remove")) {
                        ctx.debug.removeBreakpoint(bp.address);
                        breakpoints_.erase(bp.address);
                        condBuf_.erase(bp.address);
                    }
                    ImGui::SameLine();
                    auto& buf = condBuf_[bp.address];
                    if (buf.empty() && !bp.condition.empty()) buf = bp.condition;
                    char tmp[160]; std::snprintf(tmp, sizeof(tmp), "%s", buf.c_str());
                    ImGui::SetNextItemWidth(260);
                    if (ImGui::InputTextWithHint("##cond", "condition (optional)", tmp, sizeof(tmp),
                                                 ImGuiInputTextFlags_EnterReturnsTrue)) {
                        buf = tmp;
                        ctx.debug.setBreakpointCondition(bp.address, buf);
                    }
                    ImGui::PopID();
                }
                // Locally-added breakpoints the debug thread hasn't armed yet (they
                // arm on the next debug event) - surface them immediately as pending.
                for (uint64_t a : breakpoints_) {
                    if (hasBreakpoint(snap, a)) continue;
                    ImGui::PushID((void*)(uintptr_t)(a ^ 0x9e3779b9u));
                    ImGui::TextColored(theme::col::warn(), "0x%llX", (unsigned long long)a);
                    ImGui::SameLine(); ImGui::TextDisabled("(pending)");
                    ImGui::SameLine();
                    if (ImGui::SmallButton("remove")) {
                        ctx.debug.removeBreakpoint(a);
                        breakpoints_.erase(a);
                        ImGui::PopID(); break;
                    }
                    ImGui::PopID();
                }
            } else {
                if (breakpoints_.empty()) ImGui::TextDisabled("None. Click the left gutter in the assembly view.");
                uint64_t removeBp = 0;
                for (uint64_t a : breakpoints_) {
                    ImGui::PushID((void*)(uintptr_t)(a ^ 0x9e3779b9u));
                    ImGui::Text("0x%llX", (unsigned long long)a);
                    ImGui::SameLine();
                    if (ImGui::SmallButton("remove")) removeBp = a;
                    ImGui::PopID();
                }
                if (removeBp) breakpoints_.erase(removeBp);
                ImGui::TextDisabled("Attach a process to set breakpoint conditions.");
            }
            ImGui::SeparatorText("Hardware (DR0-DR3)");
            if (snap.hwBreakpoints.empty()) ImGui::TextDisabled("None. Right-click an address in the assembly view (max 4).");
            for (size_t i = 0; i < snap.hwBreakpoints.size(); ++i) {
                const HwBreakpointInfo& hb = snap.hwBreakpoints[i];
                const char* kn = hb.kind == HwKind::Execute ? "exec" : hb.kind == HwKind::Write ? "write" : "rdwr";
                ImGui::PushID(1000 + (int)i);
                ImGui::Text("DR%zu  0x%llX  %s/%u", i, (unsigned long long)hb.address, kn, hb.size);
                ImGui::SameLine();
                if (ImGui::SmallButton("remove")) ctx.debug.removeHardwareBreakpoint(hb.address);
                ImGui::PopID();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Registers")) {
            DbgSnapshot snap = ctx.debug.snapshot();
            if (!snap.attached()) {
                ImGui::TextDisabled("Attach a process to view registers and stack.");
            } else {
                const Registers& r = snap.regs;
                const bool paused = snap.state == DbgState::Paused;
                const bool is32 = snap.is32;          // 32-bit (WOW64): e* names, 4-byte stack slots
                const int  slot = is32 ? 4 : 8;
                if (!paused) { regEditIdx_ = -1; stackEditAddr_ = 0; }   // can't edit a running target
                struct RegRow { const char* disp; const char* low; uint64_t Registers::* f; };
                const RegRow kRows[] = {
                    {"RIP","rip",&Registers::rip}, {"RSP","rsp",&Registers::rsp}, {"RBP","rbp",&Registers::rbp}, {"RFL","rflags",&Registers::rflags},
                    {"RAX","rax",&Registers::rax}, {"RBX","rbx",&Registers::rbx}, {"RCX","rcx",&Registers::rcx}, {"RDX","rdx",&Registers::rdx},
                    {"RSI","rsi",&Registers::rsi}, {"RDI","rdi",&Registers::rdi},
                    {"R8 ","r8",&Registers::r8}, {"R9 ","r9",&Registers::r9}, {"R10","r10",&Registers::r10}, {"R11","r11",&Registers::r11},
                    {"R12","r12",&Registers::r12}, {"R13","r13",&Registers::r13}, {"R14","r14",&Registers::r14}, {"R15","r15",&Registers::r15},
                };
                ui::PushMono();
                ImGui::BeginChild("regs", ImVec2(360, 0), ImGuiChildFlags_Borders);
                if (paused) ImGui::TextDisabled("double-click a value to edit");
                else        ImGui::TextDisabled("(read-only while running)");
                const int nRows = is32 ? 10 : (int)(sizeof(kRows) / sizeof(kRows[0]));   // hide r8-r15 for 32-bit
                for (int i = 0; i < nRows; ++i) {
                    if (i == 4) ImGui::Separator();
                    ImGui::PushID(i);
                    uint64_t v = r.*(kRows[i].f);
                    if (is32) v &= 0xFFFFFFFFull;
                    char dn[8]; std::snprintf(dn, sizeof(dn), "%s", kRows[i].disp);
                    if (is32 && dn[0] == 'R') dn[0] = 'E';                               // RIP->EIP, RAX->EAX, ...
                    if (regEditIdx_ == i) {
                        ImGui::Text("%-4s", dn); ImGui::SameLine();
                        ImGui::SetNextItemWidth(150);
                        if (regEditFocus_) { ImGui::SetKeyboardFocusHere(); regEditFocus_ = false; }
                        bool commit = ImGui::InputText("##re", regEditBuf_, sizeof(regEditBuf_),
                                          ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
                        if (commit) {
                            unsigned long long nv = 0;
                            if (std::sscanf(regEditBuf_, "%llx", &nv) == 1) { ctx.debug.setRegister(kRows[i].low, (uint64_t)nv); ++liveGen_; }
                            regEditIdx_ = -1;
                        } else if (ImGui::IsItemDeactivated()) regEditIdx_ = -1;   // click away / Esc cancels
                    } else {
                        char lbl[40];
                        std::snprintf(lbl, sizeof(lbl), is32 ? "%-4s 0x%08llX" : "%-4s 0x%016llX", dn, (unsigned long long)v);
                        ImGui::Selectable(lbl, false);
                        if (paused && ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                            regEditIdx_ = i; regEditFocus_ = true;
                            std::snprintf(regEditBuf_, sizeof(regEditBuf_), "%llX", (unsigned long long)v);
                        }
                        if (paused && std::strcmp(kRows[i].low, "rflags") != 0) {   // what does it point at?
                            std::string desc = describePointer(ctx, snap, v);
                            if (!desc.empty()) { ImGui::SameLine(0, 8); ImGui::TextColored(theme::col::muted(), "%.40s", desc.c_str()); }
                        }
                    }
                    ImGui::PopID();
                }
                ImGui::Separator();   // decode RFL into individual condition flags (matches the side panel)
                {
                    auto flag = [&](const char* n, int bit) {
                        bool on = (r.rflags >> bit) & 1ull;
                        ImGui::TextColored(on ? theme::col::good() : theme::col::muted(), "%s", n);
                        ImGui::SameLine(0, 6);
                    };
                    flag("ZF", 6); flag("CF", 0); flag("SF", 7); flag("OF", 11); ImGui::NewLine();
                    flag("PF", 2); flag("AF", 4); flag("DF", 10); ImGui::NewLine();
                }
                ImGui::EndChild();

                ImGui::SameLine();
                ImGui::BeginChild("stack", ImVec2(0, 0), ImGuiChildFlags_Borders);
                ImGui::TextDisabled(is32 ? "Stack (ESP):" : "Stack (RSP):");
                for (int i = 0; i < 24; ++i) {
                    uint64_t addr = r.rsp + (uint64_t)i * slot;
                    uint64_t val = 0;
                    size_t got = ctx.debug.readMemory(addr, &val, slot);
                    ImGui::PushID(i);
                    if (stackEditAddr_ == addr && addr != 0) {
                        ImGui::Text("0x%llX:", (unsigned long long)addr); ImGui::SameLine();
                        ImGui::SetNextItemWidth(150);
                        if (stackEditFocus_) { ImGui::SetKeyboardFocusHere(); stackEditFocus_ = false; }
                        bool commit = ImGui::InputText("##se", stackEditBuf_, sizeof(stackEditBuf_),
                                          ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
                        if (commit) {
                            unsigned long long nv = 0;
                            if (std::sscanf(stackEditBuf_, "%llx", &nv) == 1) { uint64_t w = (uint64_t)nv; ctx.debug.writeMemory(addr, &w, slot); ++liveGen_; }
                            stackEditAddr_ = 0;
                        } else if (ImGui::IsItemDeactivated()) stackEditAddr_ = 0;
                    } else if (got == (size_t)slot) {
                        char lbl[64]; std::snprintf(lbl, sizeof(lbl), is32 ? "0x%llX:  0x%08llX" : "0x%llX:  0x%016llX",
                                                    (unsigned long long)addr, (unsigned long long)val);
                        ImGui::Selectable(lbl, false);
                        if (paused && ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                            stackEditAddr_ = addr; stackEditFocus_ = true;
                            std::snprintf(stackEditBuf_, sizeof(stackEditBuf_), "%llX", (unsigned long long)val);
                        }
                        if (paused) {   // what does this stack slot point at?
                            std::string desc = describePointer(ctx, snap, val);
                            if (!desc.empty()) { ImGui::SameLine(0, 8); ImGui::TextColored(theme::col::muted(), "%.40s", desc.c_str()); }
                        }
                    } else {
                        ImGui::TextDisabled("0x%llX:  ????", (unsigned long long)addr);
                    }
                    ImGui::PopID();
                }
                ImGui::EndChild();
                ui::PopMono();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Watch")) {
            DbgSnapshot snap = ctx.debug.snapshot();
            ImGui::SetNextItemWidth(-90);
            bool add = ImGui::InputTextWithHint("##watchadd", "expression  e.g.  rax   [rsp+8]   0x140001000",
                                                watchEntry_, sizeof(watchEntry_), ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::SameLine();
            if ((ImGui::Button("Add") || add) && watchEntry_[0]) { watches_.push_back(watchEntry_); watchEntry_[0] = 0; }

            const bool paused = snap.attached() && snap.state == DbgState::Paused;
            if (!paused) ImGui::TextDisabled("Values evaluate while the debuggee is paused.");

            // Resolve registers off the current snapshot + memory off the debuggee,
            // reusing the conditional-breakpoint expression evaluator (Cond.h).
            Registers regs = snap.regs;
            CondContext cc;
            cc.reg = [&regs](const std::string& n, uint64_t& o) -> bool {
                if      (n=="rax") o=regs.rax; else if (n=="rbx") o=regs.rbx; else if (n=="rcx") o=regs.rcx;
                else if (n=="rdx") o=regs.rdx; else if (n=="rsi") o=regs.rsi; else if (n=="rdi") o=regs.rdi;
                else if (n=="rbp") o=regs.rbp; else if (n=="rsp") o=regs.rsp; else if (n=="rip") o=regs.rip;
                else if (n=="rflags") o=regs.rflags;
                else if (n=="r8")  o=regs.r8;  else if (n=="r9")  o=regs.r9;  else if (n=="r10") o=regs.r10;
                else if (n=="r11") o=regs.r11; else if (n=="r12") o=regs.r12; else if (n=="r13") o=regs.r13;
                else if (n=="r14") o=regs.r14; else if (n=="r15") o=regs.r15;
                else return false;
                return true;
            };
            const int memW = snap.is32 ? 4 : 8;   // pointer-width read (don't pull adjacent bytes on a 32-bit target)
            cc.mem = [&ctx, memW](uint64_t a) -> uint64_t { uint64_t v = 0; ctx.debug.readMemory(a, &v, memW); return v; };

            int removeAt = -1;
            ui::PushMono();
            if (ImGui::BeginTable("watches", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Expression", ImGuiTableColumnFlags_WidthFixed, 200);
                ImGui::TableSetupColumn("Hex",        ImGuiTableColumnFlags_WidthFixed, 170);
                ImGui::TableSetupColumn("Signed",     ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("");
                ImGui::TableHeadersRow();
                for (int i = 0; i < (int)watches_.size(); ++i) {
                    ImGui::TableNextRow(); ImGui::PushID(i);
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(watches_[i].c_str());
                    uint64_t v = 0; bool ok = paused && EvalExpression(watches_[i], cc, v);
                    ImGui::TableSetColumnIndex(1);
                    if (ok) ImGui::Text("0x%016llX", (unsigned long long)v); else ImGui::TextDisabled(paused ? "?" : "-");
                    ImGui::TableSetColumnIndex(2);
                    if (ok) ImGui::Text("%lld", (long long)(int64_t)v); else ImGui::TextDisabled("-");
                    ImGui::TableSetColumnIndex(3);
                    if (ImGui::SmallButton("remove")) removeAt = i;
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ui::PopMono();
            if (removeAt >= 0) watches_.erase(watches_.begin() + removeAt);
            if (watches_.empty()) ImGui::TextDisabled("Add expressions (registers, [mem], constants) to watch them each stop.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Threads")) {
            DbgSnapshot snap = ctx.debug.snapshot();
            if (!snap.attached()) {
                ImGui::TextDisabled("Attach a process to list threads.");
            } else {
                ImGui::Text("%d thread(s)  -  active: %u", (int)snap.threads.size(), snap.activeTid);
                if (ImGui::BeginTable("threads", 3,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 80);
                    ImGui::TableSetupColumn("RIP", ImGuiTableColumnFlags_WidthFixed, 170);
                    ImGui::TableSetupColumn("");
                    ImGui::TableHeadersRow();
                    for (auto& t : snap.threads) {
                        ImGui::TableNextRow();
                        ImGui::PushID((int)t.tid);
                        bool active = t.tid == snap.activeTid;
                        ImGui::TableSetColumnIndex(0);
                        if (ImGui::Selectable(active ? "*" : " ", active, ImGuiSelectableFlags_SpanAllColumns))
                            ctx.debug.setActiveThread(t.tid);
                        ImGui::SameLine(); ImGui::Text("%u", t.tid);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("0x%llX", (unsigned long long)t.rip);
                        if (t.suspended) { ImGui::SameLine(); ImGui::TextColored(theme::col::warn(), "[frozen]"); }
                        ImGui::TableSetColumnIndex(2);
                        // t.rip is a runtime VA: follow it in the live view (records history).
                        if (ImGui::SmallButton("follow")) { ctx.debug.setActiveThread(t.tid); mainView_ = 4; liveNavigate(t.rip); }
                        ImGui::SameLine();
                        if (t.suspended) { if (ImGui::SmallButton("thaw"))   ctx.debug.resumeThread(t.tid); }
                        else             { if (ImGui::SmallButton("freeze")) ctx.debug.suspendThread(t.tid); }
                        ImGui::PopID();
                    }
                    ImGui::EndTable();
                }
                ImGui::TextDisabled("Select a thread to point the register/stack views at it; freeze to hold it across continues.");
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Call Stack")) {
            renderCallStack(ctx);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Stack")) {
            renderStackTab(ctx);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Functions")) {
            DbgSnapshot snap = ctx.debug.snapshot();
            ImGui::BeginDisabled(!ctx.binary.loaded() || !ctx.disasm);
            if (ImGui::SmallButton("Analyze binary")) analyzeFunctions(ctx);
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::SetNextItemWidth(200);
            ImGui::InputTextWithHint("##ffilter", "filter by name...", funcTabFilter_, sizeof(funcTabFilter_));
            ImGui::SameLine();
            ImGui::TextDisabled("%d function(s)%s%s", (int)functions_.size(),
                                fnSummary_.empty() ? "" : "  -  ", fnSummary_.c_str());

            const bool haveModules = snap.attached();
            float listH = haveModules ? ImGui::GetContentRegionAvail().y * 0.58f : 0.0f;
            ImGui::BeginChild("fnlist2", ImVec2(0, listH), ImGuiChildFlags_Borders);
            ui::PushMono();
            if (functions_.empty())
                ImGui::TextDisabled("Press \"Analyze binary\" to discover functions (entry, exports, call targets, prologues).");
            if (ImGui::BeginTable("fns", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Size",    ImGuiTableColumnFlags_WidthFixed, 64);
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                // Pre-filter into a dense index list so a clipper can skip off-screen
                // rows; annName() (a map probe + alloc) then runs only for visible rows
                // (this table iterated every function with a per-row probe each frame).
                std::vector<int> vis; vis.reserve(functions_.size());
                for (int i = 0; i < (int)functions_.size(); ++i) {
                    if (!funcTabFilter_[0]) { vis.push_back(i); continue; }
                    const auto& f = functions_[(size_t)i];
                    std::string dn = annName(ctx, f.address);
                    const std::string& nm = dn.empty() ? f.name : dn;
                    if (nm.find(funcTabFilter_) != std::string::npos || f.name.find(funcTabFilter_) != std::string::npos)
                        vis.push_back(i);
                }
                ImGuiListClipper clip;
                clip.Begin((int)vis.size());
                while (clip.Step())
                    for (int vi = clip.DisplayStart; vi < clip.DisplayEnd; ++vi) {
                        auto& f = functions_[(size_t)vis[(size_t)vi]];
                        std::string dn = annName(ctx, f.address);
                        const std::string& nm = dn.empty() ? f.name : dn;
                        ImGui::TableNextRow(); ImGui::PushID((void*)(uintptr_t)f.address);   // full-width id
                        ImGui::TableSetColumnIndex(0);
                        char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)f.address);
                        if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) gotoStatic(ctx, f.address);
                        if (ImGui::BeginPopupContextItem("fnm")) {
                            if (ImGui::MenuItem("Go to"))         gotoStatic(ctx, f.address);
                            if (ImGui::MenuItem("Rename...")) {
                                annPopupVA_ = f.address;
                                std::snprintf(renameBuf_, sizeof(renameBuf_), "%s", dn.c_str());
                                openRenamePopup_ = true;
                            }
                            if (ImGui::MenuItem("Copy address"))  ImGui::SetClipboardText(al);
                            if (ImGui::MenuItem("Copy name"))     ImGui::SetClipboardText(nm.c_str());
                            ImGui::EndPopup();
                        }
                        ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%u", f.size);
                        ImGui::TableSetColumnIndex(2);
                        if (!dn.empty())            ImGui::TextColored(theme::col::accent(), "%s", nm.c_str()); // user rename
                        else if (f.guessed) {                                                                   // heuristic guess
                            ImGui::TextColored(theme::col::warn(), "%s", f.name.c_str());
                            if (ImGui::IsItemHovered()) {
                                auto rit = guessReason_.find(f.address);
                                ImGui::SetTooltip("guessed name - %s",
                                    rit != guessReason_.end() ? rit->second.c_str() : "heuristic");
                            }
                        }
                        else                        ImGui::TextUnformatted(f.name.c_str());                     // plain sub_
                        ImGui::PopID();
                    }
                ImGui::EndTable();
            }
            ui::PopMono();
            ImGui::EndChild();

            if (haveModules) {
                ImGui::SeparatorText("Modules (debuggee)");
                if (ImGui::SmallButton("Refresh modules") || liveModulesPid_ != snap.pid) {
                    ProcessManager pm;
                    liveModules_    = pm.modules(snap.pid);
                    liveModulesPid_ = snap.pid;
                    for (auto& mi : liveModules_) ctx.modules.addOrUpdate(mi.name, mi.base, mi.size, mi.path);
                }
                ImGui::SameLine();
                // Analyze every module in the background (read images off-thread, then
                // fan out across the analysis pool). Disabled while a batch is running.
                ImGui::BeginDisabled(ctx.livescan.batchTotal() > 0);
                if (ImGui::SmallButton("Analyze all modules")) analyzeAllModules(ctx);
                ImGui::EndDisabled();
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                    ImGui::SetTooltip("Read every module's image from the process and analyze it in the background\n(results cached per module; switching is then instant)");
                ImGui::SameLine();
                ImGui::TextDisabled("%d module(s)  -  double-click to load into the disassembler", (int)liveModules_.size());
                ImGui::BeginChild("modlist", ImVec2(0, 0), ImGuiChildFlags_Borders);
                ui::PushMono();
                if (ImGui::BeginTable("mods", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 150);
                    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80);
                    ImGui::TableSetupColumn("Name");
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableHeadersRow();
                    LoadedModule* activeMod = ctx.modules.active();
                    uint64_t activeBase = activeMod ? activeMod->base : 0;
                    for (auto& m : liveModules_) {
                        ImGui::TableNextRow(); ImGui::PushID((void*)(uintptr_t)m.base);   // full-width id (no 32-bit truncation)
                        const bool isActive = (m.base == activeBase);
                        if (isActive)   // tint the row of the module currently loaded in the disassembler
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                ImGui::GetColorU32(ImVec4(theme::col::accent().x, theme::col::accent().y, theme::col::accent().z, 0.18f)));
                        ImGui::TableSetColumnIndex(0);
                        char bl[24]; std::snprintf(bl, sizeof(bl), "0x%llX", (unsigned long long)m.base);
                        // Single click -> view it live; double click -> load it into the
                        // disassembler (read its mapped image + full static analysis).
                        if (ImGui::Selectable(bl, isActive, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                            if (ImGui::IsMouseDoubleClicked(0)) { ctx.loadLiveModule(m.base, m.size, m.name); mainView_ = 0; }
                            else { mainView_ = 4; liveNavigate(m.base); }
                        }
                        if (ImGui::BeginPopupContextItem("modm")) {
                            if (ImGui::MenuItem("Open in disassembler")) { ctx.loadLiveModule(m.base, m.size, m.name); mainView_ = 0; }
                            if (ImGui::MenuItem("Go to base (live)")) { mainView_ = 4; liveNavigate(m.base); }
                            if (ImGui::MenuItem("Copy base")) ImGui::SetClipboardText(bl);
                            if (ImGui::MenuItem("Copy name")) ImGui::SetClipboardText(m.name.c_str());
                            if (ImGui::MenuItem("Copy path")) ImGui::SetClipboardText(m.path.c_str());
                            ImGui::EndPopup();
                        }
                        ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%lluK", (unsigned long long)(m.size / 1024));
                        ImGui::TableSetColumnIndex(2);
                        LoadedModule* rm = ctx.modules.byBase(m.base);
                        if (isActive)                       ImGui::TextColored(theme::col::accent(), "%s  (loaded)", m.name.c_str());
                        else if (rm && rm->analyzing)       ImGui::Text("%s  (analyzing...)", m.name.c_str());
                        else if (rm && rm->analyzed())      ImGui::TextColored(theme::col::good(), "%s  (analyzed)", m.name.c_str());
                        else                                ImGui::TextUnformatted(m.name.c_str());
                        ImGui::PopID();
                    }
                    ImGui::EndTable();
                }
                ui::PopMono();
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Xrefs")) {
            renderXrefsTab(ctx);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Notes")) {
            ImGui::InputTextMultiline("##notes", notes_, sizeof(notes_), ImVec2(-1, -1));
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Results")) {
            ImGui::Text("Byte search: %d hit(s)", (int)searchHits_.size());
            if (searchHits_.empty()) {
                ImGui::TextDisabled("Run a byte search (side panel) to collect hits here.");
            } else {
                ImGui::BeginChild("resultsHits", ImVec2(0, 0), ImGuiChildFlags_Borders);
                for (auto a : searchHits_) {
                    char lbl[32]; std::snprintf(lbl, sizeof(lbl), "0x%llX", (unsigned long long)a);
                    if (ImGui::Selectable(lbl)) { if (byteSearchLive_) { mainView_ = 4; liveNavigate(a); } else navigateTo(a); }
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Patches")) {
            auto& V = ctx.project.patches;
            ImGui::TextDisabled("Accumulated byte patches. File > Save Binary As... writes a patched copy.");
            if (V.empty()) ImGui::TextDisabled("No patches yet. Right-click an instruction > Patch...");
            uint64_t revertVA = 0; bool doRevert = false;
            ui::PushMono();
            if (ImGui::BeginTable("patches", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Patched", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("");
                ImGui::TableHeadersRow();
                auto hex = [](const std::vector<uint8_t>& b) { std::string s; for (size_t i = 0; i < b.size(); ++i) { char t[4]; std::snprintf(t, sizeof(t), i ? " %02X" : "%02X", b[i]); s += t; } return s; };
                for (int i = 0; i < (int)V.size(); ++i) {
                    ImGui::TableNextRow(); ImGui::PushID(i);
                    ImGui::TableSetColumnIndex(0);
                    char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)V[i].address);
                    if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) gotoStatic(ctx, V[i].address);
                    ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", hex(V[i].orig).c_str());
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(hex(V[i].bytes).c_str());
                    ImGui::TableSetColumnIndex(3);
                    // Defer the actual revert until after the table loop so V isn't
                    // mutated mid-iteration; revertPatchAt() does the byte restore
                    // (live + image), the erase, and every cache invalidation.
                    if (ImGui::SmallButton("revert")) { revertVA = V[i].address; doRevert = true; }
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ui::PopMono();
            if (doRevert) revertPatchAt(ctx, revertVA);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Imports")) {
            const auto& imps   = ctx.binary.imports();
            const auto& relocs = ctx.binary.relocations();
            ImGui::TextDisabled("%d import(s)  |  %d base relocation(s)%s", (int)imps.size(), (int)relocs.size(),
                                imps.empty() ? "  (PE import table only)" : "");
            ImGui::SameLine(); ImGui::SetNextItemWidth(240);
            ImGui::InputTextWithHint("##impf", "filter dll / function...", importFilter_, sizeof(importFilter_));
            ImGui::BeginChild("implist", ImVec2(0, 0), ImGuiChildFlags_Borders);
            ui::PushMono();
            if (ImGui::BeginTable("imps", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("IAT VA", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Function");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                impVisible_.clear();
                for (int i = 0; i < (int)imps.size(); ++i)
                    if (!importFilter_[0] || imps[i].dll.find(importFilter_) != std::string::npos
                                          || imps[i].name.find(importFilter_) != std::string::npos) impVisible_.push_back(i);
                ImGuiListClipper impClip;
                impClip.Begin((int)impVisible_.size());
                while (impClip.Step())
                    for (int row = impClip.DisplayStart; row < impClip.DisplayEnd; ++row) {
                    const auto& im = imps[impVisible_[row]];
                    ImGui::TableNextRow(); ImGui::PushID((void*)(uintptr_t)im.iatVA);   // full-width id
                    ImGui::TableSetColumnIndex(0);
                    char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)im.iatVA);
                    if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) gotoStatic(ctx, im.iatVA);
                    if (ImGui::BeginPopupContextItem("imctx")) {
                        if (ImGui::MenuItem("Find call sites (xref to IAT)")) startXrefSearch(ctx, im.iatVA);
                        if (ImGui::MenuItem("Copy name")) { std::string s = im.dll + "." + im.name; ImGui::SetClipboardText(s.c_str()); }
                        ImGui::EndPopup();
                    }
                    ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", im.dll.c_str());
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(im.name.c_str());
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ui::PopMono();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Algorithms")) {
            ImGui::TextDisabled("%d algorithm match(es)", (int)algos_.size());
            if (!algosScanned_ && ctx.analysis.bulkPending()) { ImGui::SameLine(); ImGui::TextDisabled(" - analyzing..."); }
            ImGui::SameLine(); ImGui::TextDisabled("(?)");
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Evidence-only: constants/alphabets found and where they are referenced -\n"
                                  "NOT proof the code executes. Statically-linked but unused crypto also appears here.");
            ImGui::SameLine(); ImGui::SetNextItemWidth(200);
            ImGui::InputTextWithHint("##algof", "filter name / category...", algoFilter_, sizeof(algoFilter_));

            if (algos_.empty()) {
                ImGui::TextDisabled("No known algorithm constants or Base64 alphabets detected.");
            } else {
                // Left: match list.
                ImGui::BeginChild("algolist", ImVec2(ImGui::GetContentRegionAvail().x * 0.46f, 0), ImGuiChildFlags_Borders);
                ui::PushMono();
                if (ImGui::BeginTable("algos", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupColumn("Algorithm");
                    ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 80);
                    ImGui::TableSetupColumn("Conf", ImGuiTableColumnFlags_WidthFixed, 44);
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableHeadersRow();
                    for (int i = 0; i < (int)algos_.size(); ++i) {
                        const AlgoMatch& m = algos_[i];
                        if (algoFilter_[0] && m.name.find(algoFilter_) == std::string::npos
                                           && m.category.find(algoFilter_) == std::string::npos) continue;
                        auto lbl = algoLabels_.find(m.address);
                        bool confirmed = (lbl != algoLabels_.end());
                        ImGui::TableNextRow(); ImGui::PushID(i);
                        ImGui::TableSetColumnIndex(0);
                        if (confirmed) ImGui::PushStyleColor(ImGuiCol_Text, theme::col::accent());
                        if (ImGui::Selectable(confirmed ? lbl->second.c_str() : m.name.c_str(),
                                              algoSel_ == i, ImGuiSelectableFlags_SpanAllColumns))
                            algoSel_ = i;
                        if (confirmed) ImGui::PopStyleColor();
                        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) gotoStatic(ctx, m.address);
                        ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", m.category.c_str());
                        ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%.2f", m.confidence);
                        ImGui::PopID();
                    }
                    ImGui::EndTable();
                }
                ui::PopMono();
                ImGui::EndChild();

                ImGui::SameLine();
                // Right: detail of the selected match + the functions that reference it.
                ImGui::BeginChild("algodetail", ImVec2(0, 0), ImGuiChildFlags_Borders);
                if (algoSel_ >= 0 && algoSel_ < (int)algos_.size()) {
                    const AlgoMatch& m = algos_[algoSel_];
                    auto lbl = algoLabels_.find(m.address);
                    bool confirmed = (lbl != algoLabels_.end());
                    ImGui::TextColored(theme::col::accent(), "%s", confirmed ? lbl->second.c_str() : m.name.c_str());
                    ImGui::SameLine(); ImGui::TextDisabled("(%s, conf %.2f)", m.category.c_str(), m.confidence);
                    if (!confirmed) { if (ImGui::SmallButton("Confirm label")) { algoLabels_[m.address] = m.name; projectDirty_ = true; } }
                    else            { if (ImGui::SmallButton("Clear label"))   { algoLabels_.erase(m.address); projectDirty_ = true; } }
                    ImGui::SameLine(); if (ImGui::SmallButton("Copy name")) ImGui::SetClipboardText(m.name.c_str());

                    if (!m.section.empty()) ImGui::Text("Section: %s", m.section.c_str());
                    char ab[24]; std::snprintf(ab, sizeof(ab), "0x%llX", (unsigned long long)m.address);
                    ImGui::Text("Address: %s", ab);
                    ImGui::SameLine(); if (ImGui::SmallButton("Go to data")) gotoStatic(ctx, m.address);
                    if ((int)m.dataVAs.size() > 1) { ImGui::SameLine(); ImGui::TextDisabled("(%d hits)", (int)m.dataVAs.size()); }
                    if (!m.detail.empty()) ImGui::TextWrapped("%s", m.detail.c_str());
                    if (!m.alphabet.empty()) {
                        ui::PushMono(); ImGui::TextWrapped("%s", m.alphabet.c_str()); ui::PopMono();
                        if (!m.substitutionNote.empty()) ImGui::TextDisabled("%s", m.substitutionNote.c_str());
                    }
                    ImGui::Separator();
                    ImGui::TextDisabled("Referenced by %d function(s):", (int)m.referencedBy.size());
                    ImGui::BeginChild("algorefs", ImVec2(0, 0));
                    ui::PushMono();
                    if (m.referencedBy.empty()) ImGui::TextDisabled("(no resolved references in this image)");
                    for (const auto& x : m.referencedBy) {
                        char rl[80];
                        if (x.funcAddress) std::snprintf(rl, sizeof(rl), "0x%llX  %s", (unsigned long long)x.funcAddress, x.funcName.c_str());
                        else               std::snprintf(rl, sizeof(rl), "ref @ 0x%llX  (function unresolved)", (unsigned long long)x.refInsn);
                        ImGui::PushID((void*)(uintptr_t)x.refInsn);
                        if (ImGui::Selectable(rl)) gotoStatic(ctx, x.funcAddress ? x.funcAddress : x.refInsn);
                        ImGui::PopID();
                    }
                    ui::PopMono();
                    ImGui::EndChild();
                } else {
                    ImGui::TextDisabled("Select a match to see its constants and the functions that reference it.");
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Hotkeys")) {
            ImGui::SeparatorText("Debugger");
            ImGui::BulletText("F5            Continue / Pause");
            ImGui::BulletText("F10           Step Over");
            ImGui::BulletText("F11           Step Into");
            ImGui::BulletText("Shift+F11     Step Out");
            ImGui::BulletText("Ctrl+O        Open Binary");
            ImGui::SeparatorText("Navigation (any view)");
            ImGui::BulletText("Alt+Left / Alt+Right    Back / Forward  (also mouse back/fwd buttons, and the < > toolbar)");
            ImGui::BulletText("Double-click address    Follow the branch / call target");
            ImGui::BulletText("Click  ; 0xADDR         Follow the target");
            ImGui::BulletText("Ctrl+G                  Goto symbol picker        Ctrl+Shift+F   Search disassembly text");
            ImGui::SeparatorText("Actions on the cursor instruction (Assembly view)");
            ImGui::BulletText("J / K  Next / previous instruction  (Shift = x16)   Prev/Next buttons in the header");
            ImGui::BulletText("Enter  Follow target        ;  Add / edit comment        P  Patch this instruction");
            ImGui::BulletText("N      Rename symbol        B  Toggle breakpoint        X  Find references (xrefs)");
            ImGui::BulletText("Right-click  Follow, copy address/bytes/instruction/C-array, breakpoints, rename,");
            ImGui::BulletText("             comment, patch, revert patch, add bookmark, define function, jump table");
            ImGui::BulletText("Shift+click / Ctrl+click an address to multi-select, then right-click for batch");
            ImGui::BulletText("actions: region patch (assemble over selection), NOP, signature, copy, breakpoints");
            ImGui::BulletText("Arrows  Branch arrows in the flow gutter (header toggle); orange=back blue=fwd");
            ImGui::SeparatorText("Live Assembly view");
            ImGui::BulletText("Ctrl+F            Search live process memory");
            ImGui::BulletText("Enter             Follow the selected jump / call target");
            ImGui::BulletText("Backspace / <     Navigate back   ( > = forward )");
            ImGui::BulletText("Disasm / Pseudo   Switch listing vs naive pseudocode");
            ImGui::BulletText("Click gutter      Toggle software breakpoint (updates instantly)");
            ImGui::BulletText("Double-click row  Follow the branch / call target");
            ImGui::BulletText("Click ; 0x...     Follow the branch / call target");
            ImGui::BulletText("Right-click       Run-to-cursor, breakpoints, Patch, NOP, copy, Find references");
            ImGui::BulletText("Find references    Every call/jmp/lea/mov that targets an address");
            ImGui::BulletText("; \"...\" comments   Inline strings for referenced data (header toggle: Str)");
            ImGui::BulletText("Click a register  Follow its value;  right-click = copy");
            ImGui::BulletText("Sync              Jump to RIP and re-enable Follow");
            ImGui::TextDisabled("Strings panel: right-click a string -> Find references (where used).");
            ImGui::TextDisabled("Functions sub-tab lists analyzed functions + debuggee modules.");
            ImGui::TextDisabled("Regs box (top-right), Arrows, Hints, Str toggle in the view's header.");
            ImGui::SeparatorText("Live debugging (lower sub-tabs, while paused)");
            ImGui::BulletText("Registers   Double-click a register or stack qword to edit it (writes the debuggee)");
            ImGui::BulletText("Watch       Pin expressions (rax, [rsp+8], 0x...) - evaluated each stop, persisted");
            ImGui::BulletText("Threads     freeze / thaw holds a thread across continues (auto-thawed on detach)");
            ImGui::BulletText("Right-click an instruction -> Set breakpoint condition... (e.g. rax == 0)");
            ImGui::BulletText("Right-click -> Hardware breakpoint (DR): execute, or break on write / read-write");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    (void)ctx;
}

void BinaryViewTab::render(AppContext& ctx) {
    DbgSnapshot snap = ctx.debug.snapshot();
    symAttached_ = snap.attached();        // cached for symbolFor() this frame
    symPid_      = snap.pid;

    // Track register deltas between consecutive stops so the register box can tint
    // changed values. Done here (not inside the live view) so it stays current no
    // matter which view/tab is active when the user steps.
    if (snap.state == DbgState::Paused && snap.regs.rip != 0 && snap.regs.rip != lastStopRip_) {
        regsAtPrevStop_ = regsAtLastStop_;
        regsAtLastStop_ = snap.regs;
        haveTwoStops_   = (lastStopRip_ != 0);
        lastStopRip_    = snap.regs.rip;
    }

    // Detach edge: release the per-session live caches once, so a debug session's
    // resolved-name cache, export tables, module list, and the live decode scratch
    // don't linger (or accumulate across re-attaches) after we drop the process.
    if (!symAttached_ && wasAttached_) {
        symCache_.clear(); symbols_.reset();
        modExports_.clear();
        liveModules_.clear(); liveModulesPid_ = 0;
        liveInsns_.clear(); liveIdxOf_.clear(); liveFuncSet_.clear();
        liveBuf_.clear(); liveBuf_.shrink_to_fit();
        liveCacheSig_ = ~0ull; liveCacheStart_ = 0; ++liveGen_;
        // Drop in-flight live scans (their debuggee reader is about to be invalid) and
        // forget the module registry built from this (now-dead) session. Drain BOTH
        // pools first: the analysis pool may be mid-read of a module image owned by the
        // registry (an "analyze all modules" batch), so it must be idle before clear()
        // frees those images.
        ctx.livescan.cancelPending();
        ctx.analysis.cancelAndWaitIdle();
        stringsScanning_ = false; xrefScanning_ = false;
        ctx.modules.clear();
    }
    // Attach edge: pull in the whole app. Seed the module registry from the live module
    // list and, when no file is already loaded, auto-open the process's main module so
    // its code is analyzed and browsable immediately ("load the entire app on attach").
    if (symAttached_ && !wasAttached_) {
        ProcessManager pm;
        liveModules_    = pm.modules(snap.pid);
        liveModulesPid_ = snap.pid;
        for (auto& mi : liveModules_) ctx.modules.addOrUpdate(mi.name, mi.base, mi.size, mi.path);
        if (!liveModules_.empty()) {
            const ModuleInfo& main = liveModules_.front();   // Toolhelp lists the main EXE first
            if (LoadedModule* mm = ctx.modules.byBase(main.base)) mm->isMain = true;
            if (!ctx.binary.loaded() && ctx.loadLiveModule(main.base, main.size, main.name))
                mainView_ = 0;   // show the static assembly of the just-loaded main module
        }
    }
    wasAttached_ = symAttached_;

    if (ctx.requestedLiveAssembly) {
        mainView_ = 4;
        followLiveRip_ = true;
        if (snap.regs.rip) cursorVA_ = snap.regs.rip;
        ctx.requestedLiveAssembly = false;
    }

    if (ctx.requestedExportAnalysis) {
        ctx.requestedExportAnalysis = false;
        exportAnalysis(ctx);
    }

    // A freshly loaded binary: re-home to the entry point and auto-analyze so the
    // view opens on real code with functions/names/references already populated.
    if (ctx.binaryJustLoaded) {
        ctx.binaryJustLoaded = false;
        onBinaryLoaded(ctx);
    }

    // A patch may have changed instruction boundaries: re-run function analysis on the
    // background worker (coalesced via the dirty flag) so the decompiler / CFG use
    // current bounds. Bumping the epoch supersedes any in-flight job, and because the
    // patch's writeImage() already ran on this thread, the worker sees the patched bytes.
    // Only the immediately-visible passes run here (functions + strings + the listing
    // index, which needs the strings for its data-section rows). The heavier whole-
    // program xref index and the algorithm scan are deferred: the Xrefs tab rebuilds
    // its index lazily (ensureXrefReady) and the algorithm matches stay until the next
    // full load — so a patch doesn't pay for indexes the user may not look at.
    if (functionsDirty_ && ctx.binary.loaded()) {
        functionsDirty_ = false;
        uint64_t e = ctx.analysis.bumpEpoch();
        ctx.analysis.requestBulk(&ctx.binary, ctx.engine, ctx.arch,
                                 K_Funcs | K_Strings | K_Listing, guessNames_, e);
    }

    // Swap in any finished background analysis atomically (between ImGui calls, so no
    // clipper ever walks a half-updated list). The pool delivers ONE result per pass,
    // so drain them all this frame. Results superseded by a newer load or patch carry a
    // stale epoch and are dropped; results tagged with a module base belong to the
    // multi-module browser (handled there) and are skipped here.
    {
        AnalysisResult ar;
        while (ctx.analysis.tryTakeBulk(ar)) {
            if (ar.epoch != ctx.analysis.epoch()) continue;   // superseded: drop
            if (ar.moduleBase != 0) {
                // "Analyze all modules" result: cache it on the registry module (not the
                // active tab). Switching to that module later restores from this cache.
                if (LoadedModule* m = ctx.modules.byBase(ar.moduleBase)) {
                    if (ar.stringsValid) { m->cache.strings = std::move(ar.strings); m->cache.stringsValid = true; }
                    if (ar.funcsValid)   { m->cache.functions = std::move(ar.functions); m->cache.summary = std::move(ar.summary); m->cache.funcsValid = true; }
                    if (ar.listingValid) { m->cache.listRows = std::move(ar.listRows); m->cache.listInsnCount = ar.listInsnCount; m->cache.listingValid = true; }
                    if (ar.xref)         { m->cache.xref = ar.xref; }
                    // xref is the last of the four passes, so its arrival means done.
                    if (ar.xref || !(ar.kinds & K_Xref)) m->analyzing = false;
                }
                continue;
            }
            if (ar.stringsValid) {
                strings_.clear();
                strings_.reserve(ar.strings.size());
                for (auto& s : ar.strings) strings_.push_back({ s.address, s.text, s.wide });
                stringsScanned_ = true;
            }
            if (ar.funcsValid) {
                functions_.clear();
                functions_.reserve(ar.functions.size());
                guessReason_.clear();
                for (auto& f : ar.functions) {
                    functions_.push_back({ f.address, f.name, f.size, f.guessed });
                    if (f.guessed && !f.reason.empty()) guessReason_[f.address] = f.reason;
                }
                fnSummary_      = ar.summary;
                funcIndexDirty_ = true;     // function set changed: rebuild the sorted lookup
                symCache_.clear();          // resolved names changed: drop the cache
                ++liveGen_;                 // invalidate the live decode's divider set
                if (ar.kinds & K_Listing) {
                    // The worker is (re)building the full listing too — don't sweep on
                    // the UI thread. Drop the stale rows so the view shows progress until
                    // the K_Listing result lands (and mark built + stamp the signature so
                    // the guard doesn't sweep during the gap before the listing arrives).
                    listRows_.clear(); listInsnCount_ = 0; listBuilt_ = true;
                    listSig_ = listingSig(ctx);
                } else {
                    listBuilt_ = false;     // no worker listing: rebuild lazily on the UI thread
                }
            }
            if (ar.listingValid) {
                // Adopt the worker's prebuilt full-program listing (no UI-thread sweep).
                // It carries the data-section string rows too, so stamping listSig_ keeps
                // the guard from re-sweeping (which would otherwise rebuild on the UI).
                listRows_.clear();
                listRows_.reserve(ar.listRows.size());
                for (const auto& r : ar.listRows) listRows_.push_back({ r.addr, r.divider, r.strData, r.strIdx });
                listInsnCount_ = ar.listInsnCount;
                listBuilt_     = true;
                listSig_       = listingSig(ctx);
            }
            if (ar.xref) {
                // Adopt the worker's prebuilt whole-program xref index; stamp the
                // signature buildXrefIndex() uses so it won't redundantly re-sweep.
                xrefIndex_    = std::move(*ar.xref);
                xrefIndexSig_ = xrefSig(ctx);
            }
            if (ar.algosValid) {
                // Adopt the background algorithm-recognition results (Algorithms sub-tab).
                algos_        = std::move(ar.algos);
                algosScanned_ = true;
            }
            if (ar.callGraphValid) {
                // Fold the worker's call edges into the callers_/callees_ adjacency maps
                // and stamp the signature so renderCallGraph won't re-sweep on the UI.
                callees_.clear(); callers_.clear();
                for (const auto& e : ar.callEdges) {
                    callees_[e.from].push_back(e.to);
                    callers_[e.to].push_back(e.from);
                }
                callGraphSig_ = (ctx.binary.loaded() ? ctx.binary.contentHash() : 0) ^ ((uint64_t)functions_.size() << 1);
            }
            if (ar.synthValid) {            // F1 clean-room synthesis result
                synth_ = std::move(ar.synth);
                synthHave_ = true; synthPending_ = false; synthFocus_ = true;
            }
            if (ar.pathValid) {             // F3 static path-exploration result
                pathTree_ = std::move(ar.pathTree);
                pathHave_ = !pathTree_.nodes.empty();
                pathPending_ = false; pathFocus_ = true;
                if (!pathHave_) pathStatus_ = "No reachable paths (region did not decode to a CFG).";
            }
        }
    }

    // Drain LiveScanService (debuggee-memory) results: the off-thread live string scan,
    // the attached xref sweep, and "analyze all modules" image reads.
    {
        LiveScanResult lr;
        while (ctx.livescan.tryTake(lr)) {
            if (lr.epoch != ctx.livescan.epoch()) continue;   // superseded by detach/reload
            if (lr.kind == LiveKind::Strings) {
                if (lr.token != stringsToken_) continue;       // not the latest request
                strings_.clear();
                strings_.reserve(lr.strings.size());
                for (auto& s : lr.strings) strings_.push_back({ s.address, s.text, s.wide });
                stringsScanned_ = true; stringsScanning_ = false;
            } else if (lr.kind == LiveKind::Xref) {
                if (lr.token != xrefToken_) continue;
                xrefHits_ = std::move(lr.hits);
                xrefScanning_ = false;
                char st[80];
                std::snprintf(st, sizeof(st), "%zu reference(s)%s",
                              xrefHits_.size(), lr.truncated ? " (capped)" : "");
                xrefStatus_ = st;
            } else if (lr.kind == LiveKind::ReadImage) {
                // "Analyze all modules": load the just-read image into its registry slot
                // and hand the BinaryFile to the analysis pool (tagged by module base).
                if (LoadedModule* m = ctx.modules.byBase(lr.moduleBase)) {
                    if (!lr.image.empty() && m->bin.loadFromMemory(std::move(lr.image), m->base, m->name)) {
                        m->imageLoaded = true;
                        m->arch = m->bin.machine();
                        ctx.analyzeModule(*m, guessNames_);
                    } else {
                        m->analyzing = false;   // unreadable image: give up on this one
                    }
                }
            }
        }
    }

    // A cross-tab "view this address" request (Tech caps, Sig results, ...).
    // Gated on the flag, not the address, so a legitimate request to VA 0 isn't dropped.
    if (ctx.hasGotoRequest) {
        uint64_t g  = ctx.requestedGotoVA;
        bool     gl = ctx.requestedGotoLive;
        ctx.hasGotoRequest = false;
        ctx.requestedGotoVA = 0;
        ctx.requestedGotoLive = false;
        if (gl) {                                // runtime VA (e.g. a live Sig hit): show it in the
            mainView_ = 4;                       // live view; never translate a runtime VA into the
            liveNavigate(g);                     // file-VA static listing (mainView_=4 first so the
        } else {                                 // NavEntry records as live, keeping back/forward right)
            if (mainView_ == 4) mainView_ = 0;   // leave the live view to show the static address
            navigateTo(g);
        }
    }

    // Welcome / empty state when no binary is loaded.
    if (!ctx.binary.loaded() && !snap.attached()) {
        renderWelcome(ctx);
        return;
    }
    if (!ctx.binary.loaded() && mainView_ != 4)
        mainView_ = 4;

    // Top control row: goto + view switch.
    ImGui::SetNextItemWidth(170);
    if (ImGui::InputTextWithHint("##goto", "0x... or name", gotoBuf_, sizeof(gotoBuf_),
                                 ImGuiInputTextFlags_EnterReturnsTrue)) {
        unsigned long long a = 0;
        bool looksHex = gotoBuf_[0] != 0;
        for (const char* s = gotoBuf_ + ((gotoBuf_[0] == '0' && (gotoBuf_[1] == 'x' || gotoBuf_[1] == 'X')) ? 2 : 0); *s; ++s)
            if (!std::isxdigit((unsigned char)*s)) { looksHex = false; break; }
        if (looksHex && std::sscanf(gotoBuf_, "%llx", &a) == 1)        navigateTo((uint64_t)a);
        else if (uint64_t sym = lookupSymbol(ctx, gotoBuf_))           navigateTo(sym);
    }
    ImGui::SameLine();
    {   // Back / Forward history.
        bool canBack = navPos_ > 0;
        bool canFwd  = navPos_ >= 0 && navPos_ + 1 < (int)navHist_.size();
        ImGui::BeginDisabled(!canBack);
        if (ImGui::Button("<")) navBack();
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("Back (Alt+Left / mouse back)");
        ImGui::SameLine(0, 2);
        ImGui::BeginDisabled(!canFwd);
        if (ImGui::Button(">")) navForward();
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("Forward (Alt+Right / mouse forward)");
    }
    ImGui::SameLine();
    if (ImGui::Button("Goto sym")) openGotoPopup_ = true;
    ImGui::SameLine();
    if (ImGui::Button("Find text")) openTextPopup_ = true;
    ImGui::SameLine();
    ImGui::BeginDisabled(!ctx.binary.loaded());
    ImGui::RadioButton("Assembly", &mainView_, 0); ImGui::SameLine();
    ImGui::RadioButton("Pseudocode", &mainView_, 1); ImGui::SameLine();
    ImGui::RadioButton("Hex", &mainView_, 2); ImGui::SameLine();
    ImGui::RadioButton("Graph (CFG)", &mainView_, 3); ImGui::SameLine();
    ImGui::RadioButton("Call Graph", &mainView_, 5);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!snap.attached());
    ImGui::RadioButton("Live Assembly", &mainView_, 4);
    ImGui::EndDisabled();
    if (ctx.analysis.bulkPending()) {
        ImGui::SameLine(); ImGui::TextDisabled("  ");
        ImGui::SameLine();
        drawAnalysisProgress(ctx, true);
    }
    ImGui::Separator();

    // Layout: main view (left) | side panel (right), lower tabs underneath. A panel
    // that has been popped out (its own window, rendered after this block) is skipped
    // here so the remaining panels reflow to fill the freed space.
    const float sideW  = 320.0f;
    const float lowerH = 200.0f;
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float mainW = sidePoppedOut_  ? avail.x : (avail.x - sideW - 8);
    float mainH = lowerPoppedOut_ ? avail.y : (avail.y - lowerH - 8);

    ImGui::BeginChild("mainview", ImVec2(mainW, mainH), ImGuiChildFlags_Borders);
    // selVAs_ is shared by the static and live listings (file-base vs runtime VAs),
    // so drop the selection when crossing between them to avoid ghost highlights.
    if ((mainView_ == 0 || mainView_ == 4) && mainView_ != selView_) {
        if (selView_ == 0 || selView_ == 4) { selVAs_.clear(); selAnchorVA_ = 0; }
        selView_ = mainView_;
    }
    switch (mainView_) {
        case 0: renderAssembly(ctx);   break;
        case 1: if (pseudoPoppedOut_) { ImGui::TextDisabled("Pseudocode is open in a separate window.");
                                        if (ImGui::SmallButton("Dock back")) pseudoPoppedOut_ = false; }
                else renderPseudocode(ctx); break;
        case 2: renderHex(ctx);        break;
        case 3: if (graphPoppedOut_)  { ImGui::TextDisabled("Graph is open in a separate window.");
                                        if (ImGui::SmallButton("Dock back")) graphPoppedOut_ = false; }
                else renderGraph(ctx); break;
        case 4: renderLiveAssembly(ctx); break;
        case 5: renderCallGraph(ctx);  break;
    }
    ImGui::EndChild();

    if (!sidePoppedOut_) {
        ImGui::SameLine();
        ImGui::BeginChild("sidepanel", ImVec2(sideW, mainH), ImGuiChildFlags_Borders);
        renderSidePanel(ctx);
        ImGui::EndChild();
    }

    if (!lowerPoppedOut_) {
        ImGui::BeginChild("lowertabs", ImVec2(0, 0), ImGuiChildFlags_Borders);
        renderLowerTabs(ctx);
        ImGui::EndChild();
    }

    // Popped-out panels render as standalone windows (their own OS window when
    // viewports are enabled). Closing the window (the title-bar X) docks it back.
    const float ds = theme::UiScale();
    if (sidePoppedOut_) {
        ImGui::SetNextWindowSize(ImVec2(360 * ds, 640 * ds), ImGuiCond_FirstUseEver);
        bool open = true;
        if (ImGui::Begin("Side Panel - DisasmStudio", &open)) renderSidePanel(ctx);
        ImGui::End();
        if (!open) sidePoppedOut_ = false;
    }
    if (lowerPoppedOut_) {
        ImGui::SetNextWindowSize(ImVec2(900 * ds, 320 * ds), ImGuiCond_FirstUseEver);
        bool open = true;
        if (ImGui::Begin("Debug Panels - DisasmStudio", &open)) renderLowerTabs(ctx);
        ImGui::End();
        if (!open) lowerPoppedOut_ = false;
    }
    if (graphPoppedOut_) {
        ImGui::SetNextWindowSize(ImVec2(900 * ds, 720 * ds), ImGuiCond_FirstUseEver);
        bool open = true;
        if (ImGui::Begin("Control-Flow Graph - DisasmStudio", &open)) renderGraph(ctx);
        ImGui::End();
        if (!open) graphPoppedOut_ = false;
    }
    if (pseudoPoppedOut_) {
        ImGui::SetNextWindowSize(ImVec2(820 * ds, 720 * ds), ImGuiCond_FirstUseEver);
        bool open = true;
        if (ImGui::Begin("Pseudocode - DisasmStudio", &open)) renderPseudocode(ctx);
        ImGui::End();
        if (!open) pseudoPoppedOut_ = false;
    }

    // Ctrl+G = symbol picker, Ctrl+Shift+F = disassembly text search (when not typing).
    ImGuiIO& kio = ImGui::GetIO();
    if (!kio.WantTextInput && kio.KeyCtrl) {
        if (ImGui::IsKeyPressed(ImGuiKey_G)) openGotoPopup_ = true;
        if (kio.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F)) openTextPopup_ = true;
    }
    // History navigation: mouse back/forward buttons + Alt+Left/Right (any view).
    if (!kio.WantTextInput) {
        if (ImGui::IsMouseClicked(3) || (kio.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow)))  navBack();
        if (ImGui::IsMouseClicked(4) || (kio.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow))) navForward();
    }
    // Per-instruction shortcuts on the assembly views (operate on the cursor row).
    if (!kio.WantTextInput && !kio.KeyCtrl && !kio.KeyAlt && cursorVA_ && ctx.binary.loaded() &&
        (mainView_ == 0 || mainView_ == 4)) {
        // Comments/renames are keyed in FILE space (persisted to the sidecar); in the
        // live view the cursor is a runtime VA, so translate it back. (B/X intentionally
        // stay in the cursor's own space: breakpoints are runtime, xref search matches
        // whichever space it sweeps.)
        uint64_t annVA = (mainView_ == 4) ? liveVAtoFile(ctx, cursorVA_) : cursorVA_;
        if (ImGui::IsKeyPressed(ImGuiKey_Semicolon)) {                       // ; = comment
            annPopupVA_ = annVA;
            auto it = comments_.find(annVA);
            std::snprintf(commentBuf_, sizeof(commentBuf_), "%s", it != comments_.end() ? it->second.c_str() : "");
            openCommentPopup_ = true;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_N)) {                               // N = rename
            annPopupVA_ = annVA;
            std::string n = annName(ctx, annVA);
            std::snprintf(renameBuf_, sizeof(renameBuf_), "%s", n.c_str());
            openRenamePopup_ = true;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_B)) toggleBreakpoint(ctx, cursorVA_);   // B = breakpoint
        if (ImGui::IsKeyPressed(ImGuiKey_X)) startXrefSearch(ctx, cursorVA_);    // X = xrefs
        // Static-view cursor stepping + patch. J/K (vim-style) are used instead of
        // the arrow keys because ImGui keyboard-nav owns the arrows when focus is in
        // the listing; letter keys deliver reliably (like ;,N,B,X above). Shift = x16.
        if (mainView_ == 0 && !listRows_.empty()) {
            int mult = kio.KeyShift ? 16 : 1;
            if (ImGui::IsKeyPressed(ImGuiKey_J)) stepAsmCursor(mult);            // J = next instruction
            if (ImGui::IsKeyPressed(ImGuiKey_K)) stepAsmCursor(-mult);           // K = previous instruction
        }
        if (mainView_ == 0 && ImGui::IsKeyPressed(ImGuiKey_P)) {                 // P = patch cursor instruction
            size_t avail = 0; const uint8_t* p = ctx.binary.ptrFromVA(cursorVA_, avail);
            Instruction in;
            if (p && ctx.disasm && ctx.disasm->decodeOne(p, avail, cursorVA_, in) && in.length) {
                patchVA_ = cursorVA_; patchLen_ = in.length; patchMode_ = 1;
                std::snprintf(patchHex_, sizeof(patchHex_), "%s", in.bytes.c_str());
                std::snprintf(patchAsmText_, sizeof(patchAsmText_), "%s %s", in.mnemonic.c_str(), in.operands.c_str());
                patchAsm_.clear(); patchStatus_.clear(); openPatchPopup_ = true;
            }
        }
        // Enter = follow the target of the cursor instruction (static view; the
        // live view has its own Enter handler against debuggee memory).
        if (mainView_ == 0 && (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter))) {
            size_t avail = 0; const uint8_t* p = ctx.binary.ptrFromVA(cursorVA_, avail);
            Instruction in;
            if (p && ctx.disasm && ctx.disasm->decodeOne(p, avail, cursorVA_, in) && in.branchTarget)
                navigateTo(in.branchTarget);
        }
    }

    // Popups usable from any view.
    renderXrefPopup(ctx);
    renderGotoPopup(ctx);
    renderTextSearchPopup(ctx);
    renderPatchPopup(ctx);       // usable from the static Assembly view too now
    renderCommentPopup(ctx);
    renderRenamePopup(ctx);
    renderCondPopup(ctx);

    if (openExportPopup_) { ImGui::OpenPopup("Export Analysis"); openExportPopup_ = false; }
    if (ImGui::BeginPopupModal("Export Analysis", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("%s", exportStatus_.c_str());
        ImGui::Separator();
        if (ImGui::Button("OK", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // Keep ctx.project in sync so the App can flush analysis on close / exit.
    saveProjectState(ctx);

    // Mirror the cursor (+ enclosing function name) for the status bar. Match the
    // decompiler's enclosing-function rule: greatest function start <= cursor,
    // within 0x4000; prefer a user rename, else the symbol resolver.
    ctx.cursorVA   = cursorVA_;
    // Runtime cursor for Run to Cursor: the live view already works in runtime VAs;
    // the static views hold file VAs, so translate them for the attached process
    // (fileVAtoLive is a no-op when not attached / base unknown).
    ctx.runtimeCursorVA = (mainView_ == 4) ? cursorVA_ : fileVAtoLive(ctx, cursorVA_);
    ctx.hasCursor  = cursorVA_ != 0 && ctx.binary.loaded();
    ctx.cursorFuncName.clear();
    if (ctx.hasCursor) {
        const Func* best = funcContaining(cursorVA_);
        if (best && cursorVA_ - best->address < 0x4000) {
            std::string dn = annName(ctx, best->address);
            ctx.cursorFuncName = dn.empty() ? best->name : dn;
        } else {
            ctx.cursorFuncName = symbolFor(ctx, cursorVA_);
        }
    }
}

} // namespace ds
