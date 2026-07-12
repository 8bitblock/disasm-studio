//
// FuncAnnotate.cpp
// Heuristic per-function annotation engine. See FuncAnnotate.h for the contract.
// Everything works off the Instruction TEXT (mnemonic/operand strings) the same
// way DataFlow.cpp does, so it stays engine-agnostic and sandbox-testable.
//
#include "FuncAnnotate.h"
#include "ApiInfo.h"
#include "../Tabs/DataRef.h"   // instrDataRef / instrImmRef: pure operand parses

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ds {

const char* NoteKindName(NoteKind k) {
    switch (k) {
        case NoteKind::Prologue:     return "prologue";
        case NoteKind::Epilogue:     return "epilogue";
        case NoteKind::Branch:       return "branch";
        case NoteKind::Loop:         return "loop";
        case NoteKind::Switch:       return "switch";
        case NoteKind::Call:         return "call";
        case NoteKind::IndirectCall: return "indirect call";
        case NoteKind::VirtualCall:  return "virtual call";
        case NoteKind::Vtable:       return "vtable";
        case NoteKind::RetUse:       return "result use";
        case NoteKind::Pattern:      return "pattern";
    }
    return "?";
}

namespace {

std::string toLower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Canonical 64-bit register family for any x86/x64 GP register name ("" = not a GP reg).
std::string canonReg(const std::string& tokIn) {
    std::string t = toLower(tokIn);
    static const std::unordered_map<std::string, const char*> kMap = {
        {"rax","rax"},{"eax","rax"},{"ax","rax"},{"al","rax"},{"ah","rax"},
        {"rbx","rbx"},{"ebx","rbx"},{"bx","rbx"},{"bl","rbx"},{"bh","rbx"},
        {"rcx","rcx"},{"ecx","rcx"},{"cx","rcx"},{"cl","rcx"},{"ch","rcx"},
        {"rdx","rdx"},{"edx","rdx"},{"dx","rdx"},{"dl","rdx"},{"dh","rdx"},
        {"rsi","rsi"},{"esi","rsi"},{"si","rsi"},{"sil","rsi"},
        {"rdi","rdi"},{"edi","rdi"},{"di","rdi"},{"dil","rdi"},
        {"rbp","rbp"},{"ebp","rbp"},{"bp","rbp"},{"bpl","rbp"},
        {"rsp","rsp"},{"esp","rsp"},{"sp","rsp"},{"spl","rsp"},
        {"rip","rip"},{"eip","rip"},
    };
    auto it = kMap.find(t);
    if (it != kMap.end()) return it->second;
    // r8..r15 + d/w/b suffix
    if (t.size() >= 2 && t[0] == 'r' && std::isdigit((unsigned char)t[1])) {
        size_t e = t.size();
        if (t.back() == 'd' || t.back() == 'w' || t.back() == 'b') --e;
        if (e >= 2) {
            bool dig = true;
            for (size_t i = 1; i < e; ++i) if (!std::isdigit((unsigned char)t[i])) { dig = false; break; }
            if (dig) {
                int n = std::atoi(t.substr(1, e - 1).c_str());
                if (n >= 8 && n <= 15) return t.substr(0, e);
            }
        }
    }
    return std::string();
}

// The 32-bit-or-64-bit display name of a family for the current bitness.
std::string regDisplay(const std::string& fam, bool x64) {
    if (x64 || fam.empty()) return fam;
    if (fam[0] == 'r' && !std::isdigit((unsigned char)fam[1])) return "e" + fam.substr(1);
    return fam;   // r8.. don't exist on x86-32, leave as-is
}

bool parseImm(const std::string& tokIn, int64_t& out) {
    std::string t = tokIn;
    while (!t.empty() && t.front() == ' ') t.erase(t.begin());
    while (!t.empty() && t.back() == ' ') t.pop_back();
    bool neg = false;
    if (!t.empty() && (t[0] == '-' || t[0] == '+')) { neg = (t[0] == '-'); t.erase(t.begin()); }
    if (t.empty()) return false;
    unsigned long long v = 0;
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        for (size_t i = 2; i < t.size(); ++i) if (!std::isxdigit((unsigned char)t[i])) return false;
        if (std::sscanf(t.c_str(), "%llx", &v) != 1) return false;
    } else {
        for (char c : t) if (!std::isdigit((unsigned char)c)) return false;
        if (std::sscanf(t.c_str(), "%llu", &v) != 1) return false;
    }
    out = neg ? -(int64_t)v : (int64_t)v;
    return true;
}

// Top-level comma split of an operand string (x86 brackets never contain commas).
std::vector<std::string> splitOps(const std::string& ops) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= ops.size(); ++i) {
        if (i == ops.size() || ops[i] == ',') {
            std::string t = ops.substr(start, i - start);
            while (!t.empty() && t.front() == ' ') t.erase(t.begin());
            while (!t.empty() && t.back() == ' ') t.pop_back();
            if (!t.empty()) out.push_back(t);
            start = i + 1;
        }
    }
    return out;
}

// Parsed "[base + index*scale + disp]" memory operand.
struct MemOp {
    bool        ok = false;
    std::string base, index;   // canonical families ("" = none)
    int         scale = 1;
    int64_t     disp = 0;
    bool        hasDisp = false;
};

MemOp parseMem(const std::string& op) {
    MemOp m;
    size_t lb = op.find('[');
    if (lb == std::string::npos) return m;
    size_t rb = op.find(']', lb);
    std::string inner = op.substr(lb + 1, (rb == std::string::npos ? op.size() : rb) - lb - 1);
    // Strip a segment prefix ("fs:...").
    if (inner.size() > 3 && inner[2] == ':') inner = inner.substr(3);
    // Tokenize on +/-, keeping the sign.
    size_t i = 0; int sign = 1;
    while (i < inner.size()) {
        while (i < inner.size() && inner[i] == ' ') ++i;
        size_t j = i;
        while (j < inner.size() && inner[j] != '+' && inner[j] != '-') ++j;
        std::string term = inner.substr(i, j - i);
        while (!term.empty() && term.back() == ' ') term.pop_back();
        if (!term.empty()) {
            size_t star = term.find('*');
            if (star != std::string::npos) {                     // index*scale (either order)
                std::string a = term.substr(0, star), b = term.substr(star + 1);
                while (!a.empty() && a.back() == ' ') a.pop_back();
                while (!b.empty() && b.front() == ' ') b.erase(b.begin());
                std::string ra = canonReg(a), rb2 = canonReg(b);
                int64_t sc = 0;
                if (!ra.empty() && parseImm(b, sc))      { m.index = ra; m.scale = (int)sc; }
                else if (!rb2.empty() && parseImm(a, sc)){ m.index = rb2; m.scale = (int)sc; }
            } else {
                std::string r = canonReg(term);
                int64_t v = 0;
                if (!r.empty()) {
                    if (m.base.empty()) m.base = r; else if (m.index.empty()) m.index = r;
                } else if (parseImm(term, v)) {
                    m.disp += sign * v; m.hasDisp = true;
                }
            }
        }
        if (j < inner.size()) sign = (inner[j] == '-') ? -1 : 1;
        i = j + 1;
    }
    m.ok = true;
    return m;
}

// All canonical register families appearing anywhere in a text fragment.
void regsInText(const std::string& s, std::vector<std::string>& out) {
    size_t i = 0;
    while (i < s.size()) {
        if (std::isalnum((unsigned char)s[i])) {
            size_t j = i;
            while (j < s.size() && std::isalnum((unsigned char)s[j])) ++j;
            std::string fam = canonReg(s.substr(i, j - i));
            if (!fam.empty() && fam != "rip") out.push_back(fam);
            i = j;
        } else ++i;
    }
}

// Per-instruction register reads/writes (canonical families, heuristic).
struct RW {
    std::vector<std::string> reads, writes;
    bool zeroIdiom = false;       // xor r,r / sub r,r: writes without reading
};

bool isWriteFirstOp(const std::string& m) {
    return m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs" ||
           m == "lea" || m == "pop" || m.rfind("set", 0) == 0 || m.rfind("cmov", 0) == 0 ||
           m == "bswap";
}
bool isRmwFirstOp(const std::string& m) {
    return m == "add" || m == "sub" || m == "adc" || m == "sbb" || m == "and" || m == "or" ||
           m == "xor" || m == "shl" || m == "sal" || m == "shr" || m == "sar" || m == "rol" ||
           m == "ror" || m == "inc" || m == "dec" || m == "neg" || m == "not" || m == "imul" ||
           m == "xadd" || m == "btc" || m == "bts" || m == "btr";
}

RW classifyRW(const Instruction& in) {
    RW rw;
    const std::string& m = in.mnemonic;
    std::vector<std::string> ops = splitOps(in.operands);
    auto addReads = [&](const std::string& text) { regsInText(text, rw.reads); };

    if (m == "call") {
        // Volatile registers clobbered by the callee (we don't model callee reads).
        rw.writes = { "rax", "rcx", "rdx", "r8", "r9", "r10", "r11" };
        for (const auto& o : ops) addReads(o);   // computed-target registers are read
        return rw;
    }
    if (m == "push" || m == "cmp" || m == "test" || m == "ret" || m.rfind("j", 0) == 0) {
        for (const auto& o : ops) addReads(o);
        return rw;
    }
    if (m == "pop" && !ops.empty()) {
        std::string r = canonReg(ops[0]);
        if (!r.empty()) rw.writes.push_back(r); else addReads(ops[0]);
        return rw;
    }
    if (m == "xchg" && ops.size() == 2) {
        for (const auto& o : ops) { addReads(o); std::string r = canonReg(o); if (!r.empty()) rw.writes.push_back(r); }
        return rw;
    }
    if (m == "mul" || m == "div" || m == "idiv" || (m == "imul" && ops.size() == 1)) {
        for (const auto& o : ops) addReads(o);
        rw.reads.push_back("rax"); rw.writes.push_back("rax"); rw.writes.push_back("rdx");
        return rw;
    }
    if (ops.empty()) return rw;

    bool dstIsMem = ops[0].find('[') != std::string::npos;
    std::string dstReg = dstIsMem ? std::string() : canonReg(ops[0]);
    // Registers used inside a memory destination are reads (address computation).
    if (dstIsMem) addReads(ops[0]);
    for (size_t i = 1; i < ops.size(); ++i) addReads(ops[i]);

    if (!dstReg.empty()) {
        bool zero = (m == "xor" || m == "sub") && ops.size() == 2 && canonReg(ops[1]) == dstReg;
        if (zero) { rw.writes.push_back(dstReg); rw.zeroIdiom = true; return rw; }
        if (isWriteFirstOp(m))      { rw.writes.push_back(dstReg); }
        else if (isRmwFirstOp(m))   { rw.reads.push_back(dstReg); rw.writes.push_back(dstReg); }
        else                        { rw.reads.push_back(dstReg); }   // unknown: assume read
    }
    return rw;
}

// Does this instruction WRITE its first-operand memory? (mirrors instrDataAccess)
bool writesMemFirstOp(const Instruction& in) {
    const std::string& m = in.mnemonic;
    std::vector<std::string> ops = splitOps(in.operands);
    if (ops.empty() || ops[0].find('[') == std::string::npos) return false;
    if (m == "cmp" || m == "test" || m == "push" || m == "call" || m == "jmp" || m == "lea") return false;
    if (ops.size() == 1)
        return m == "pop" || m == "inc" || m == "dec" || m == "neg" || m == "not" || m.rfind("set", 0) == 0;
    return true;
}

const char* jccExprOp(const std::string& m, bool& isSigned, bool& isUnsigned) {
    isSigned = isUnsigned = false;
    if (m == "je"  || m == "jz")  return "==";
    if (m == "jne" || m == "jnz") return "!=";
    if (m == "jg"  || m == "jnle"){ isSigned = true;   return ">";  }
    if (m == "jge" || m == "jnl") { isSigned = true;   return ">="; }
    if (m == "jl"  || m == "jnge"){ isSigned = true;   return "<";  }
    if (m == "jle" || m == "jng") { isSigned = true;   return "<="; }
    if (m == "ja"  || m == "jnbe"){ isUnsigned = true; return ">";  }
    if (m == "jae" || m == "jnb") { isUnsigned = true; return ">="; }
    if (m == "jb"  || m == "jnae"){ isUnsigned = true; return "<";  }
    if (m == "jbe" || m == "jna") { isUnsigned = true; return "<="; }
    if (m == "js")  return "s";     // sign set / clear handled specially
    if (m == "jns") return "ns";
    return nullptr;
}

bool isCondJump(const Instruction& in) {
    return in.isBranch && !in.isCall && !in.isRet && HasBranchTarget(in) &&
           in.mnemonic != "jmp" && in.mnemonic[0] == 'j';
}

bool isFlagSetter(const std::string& m) {
    return m == "cmp" || m == "test" || m == "add" || m == "sub" || m == "and" || m == "or" ||
           m == "xor" || m == "inc" || m == "dec" || m == "neg" || m == "shl" || m == "shr" ||
           m == "sar" || m == "sal" || m == "imul" || m == "adc" || m == "sbb" || m == "bt";
}

bool nameLooksLikeCompare(const std::string& nm) {
    std::string n = toLower(nm);
    return n.find("strcmp") != std::string::npos || n.find("stricmp") != std::string::npos ||
           n.find("memcmp") != std::string::npos || n.find("wcscmp") != std::string::npos ||
           n.find("lstrcmp") != std::string::npos || n.find("comparestring") != std::string::npos ||
           n.find("strncmp") != std::string::npos || n.find("cmpi") != std::string::npos;
}

std::string vaHex(uint64_t va) {
    char b[24]; std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)va);
    return b;
}

// One flat, address-ordered view over the CFG with block boundaries kept.
struct FlatInsn {
    const Instruction* in;
    int block;        // owning block index
    int idxInBlock;
};

} // namespace

FuncAnnotations AnnotateFunction(const ControlFlowGraph& g, const AnnotateOptions& opt) {
    FuncAnnotations out;
    if (g.blocks.empty()) return out;
    const bool x64 = opt.x64;

    auto nameFor   = [&](uint64_t va) { return opt.nameFor ? opt.nameFor(va) : std::string(); };
    auto stringFor = [&](uint64_t va) { return opt.stringFor ? opt.stringFor(va) : std::string(); };

    // Block order by start address (BuildCFG emits them sorted, but don't rely on it).
    std::vector<int> order(g.blocks.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = (int)i;
    std::sort(order.begin(), order.end(),
              [&](int a, int b) { return g.blocks[a].start < g.blocks[b].start; });

    std::vector<FlatInsn> flat;
    for (int bi : order)
        for (size_t k = 0; k < g.blocks[bi].insns.size(); ++k)
            flat.push_back({ &g.blocks[bi].insns[k], bi, (int)k });
    if (flat.empty()) return out;

    auto note = [&](uint64_t va, NoteKind kind, std::string text, std::string evidence, float conf) {
        FnNote n; n.va = va; n.kind = kind; n.text = std::move(text);
        n.evidence = std::move(evidence); n.confidence = conf;
        out.notes.push_back(std::move(n));
    };

    // The display name a call resolves to: relative target, or the IAT slot it
    // reads through ("call [rip+x]"), or "" for register-indirect.
    auto callName = [&](const Instruction& in) -> std::string {
        if (HasBranchTarget(in)) {
            std::string n = nameFor(in.branchTarget);
            return n.empty() ? ("sub_" + vaHex(in.branchTarget).substr(2)) : n;
        }
        if (uint64_t slot = instrDataRef(in)) {
            std::string n = nameFor(slot);
            if (!n.empty()) return n;
        }
        return std::string();
    };

    // ---- 1) Prologue / epilogue / frame ------------------------------------
    {
        const BasicBlock& entry = g.blocks[order[0]];
        static const std::set<std::string> kCalleeSaved64 = { "rbx","rsi","rdi","rbp","r12","r13","r14","r15" };
        size_t scan = std::min<size_t>(entry.insns.size(), 12);
        bool sawPushBp = false;
        for (size_t k = 0; k < scan; ++k) {
            const Instruction& in = entry.insns[k];
            const std::string& m = in.mnemonic;
            std::vector<std::string> ops = splitOps(in.operands);
            if (m == "push" && ops.size() == 1) {
                std::string r = canonReg(ops[0]);
                if (r == "rbp") {
                    sawPushBp = true;
                    note(in.address, NoteKind::Prologue, "prologue: save caller's frame pointer",
                         "push " + regDisplay("rbp", x64) + " at function entry", 0.9f);
                } else if (kCalleeSaved64.count(r)) {
                    note(in.address, NoteKind::Prologue, "prologue: save callee-saved " + regDisplay(r, x64),
                         "push of a callee-saved register near function entry", 0.8f);
                }
            } else if (m == "mov" && ops.size() == 2 && canonReg(ops[0]) == "rbp" && canonReg(ops[1]) == "rsp") {
                out.hasFramePointer = true;
                note(in.address, NoteKind::Prologue, "prologue: establish frame pointer",
                     std::string("mov ") + regDisplay("rbp", x64) + ", " + regDisplay("rsp", x64) +
                     (sawPushBp ? " after push — canonical frame setup" : ""), 0.9f);
            } else if (m == "sub" && ops.size() == 2 && canonReg(ops[0]) == "rsp") {
                int64_t n = 0;
                if (parseImm(ops[1], n) && n > 0) {
                    out.frameBytes = (uint32_t)n;
                    note(in.address, NoteKind::Prologue,
                         "prologue: reserve " + vaHex((uint64_t)n) + " bytes of stack frame (locals/spill)",
                         "sub " + regDisplay("rsp", x64) + ", " + vaHex((uint64_t)n) + " near function entry", 0.9f);
                }
            }
        }
        // Epilogues: look just before each ret.
        for (int bi : order) {
            const BasicBlock& b = g.blocks[bi];
            if (!b.isReturn || b.insns.empty()) continue;
            for (size_t k = b.insns.size() >= 4 ? b.insns.size() - 4 : 0; k + 1 < b.insns.size(); ++k) {
                const Instruction& in = b.insns[k];
                std::vector<std::string> ops = splitOps(in.operands);
                if (in.mnemonic == "leave")
                    note(in.address, NoteKind::Epilogue, "epilogue: tear down frame (mov rsp,rbp; pop rbp)",
                         "leave immediately before ret", 0.9f);
                else if (in.mnemonic == "add" && ops.size() == 2 && canonReg(ops[0]) == "rsp")
                    note(in.address, NoteKind::Epilogue, "epilogue: release stack frame",
                         "add " + regDisplay("rsp", x64) + " just before ret", 0.85f);
                else if (in.mnemonic == "pop" && ops.size() == 1 && canonReg(ops[0]) == "rbp")
                    note(in.address, NoteKind::Epilogue, "epilogue: restore caller's frame pointer",
                         "pop " + regDisplay("rbp", x64) + " just before ret", 0.85f);
            }
        }
    }

    // ---- 2) Register lifetimes + read-before-write argument evidence -------
    struct Life { uint64_t first = 0, last = 0; int reads = 0, writes = 0; bool writtenFirst = false; };
    std::map<std::string, Life> life;
    std::set<std::string> writtenEver;
    struct ArgEvidence { uint64_t va = 0; bool asBase = false; };
    std::map<std::string, ArgEvidence> regArgEvidence;   // arg-reg family -> first pre-write read
    std::map<std::string, std::set<int64_t>> fieldOffsets; // reg used as struct base -> field disps

    static const char* kArgRegs64[] = { "rcx", "rdx", "r8", "r9" };
    for (const FlatInsn& f : flat) {
        const Instruction& in = *f.in;
        RW rw = classifyRW(in);
        for (const std::string& r : rw.reads) {
            if (r == "rsp") continue;
            Life& L = life[r];
            if (!L.first) { L.first = in.address; L.writtenFirst = false; }
            L.last = in.address; ++L.reads;
            if (!writtenEver.count(r)) {
                bool isArgReg = false;
                if (x64) { for (const char* a : kArgRegs64) if (r == a) isArgReg = true; }
                else     { isArgReg = (r == "rcx" || r == "rdx"); }   // ecx/edx: thiscall/fastcall hints
                if (isArgReg && !regArgEvidence.count(r)) {
                    MemOp mo = parseMem(in.operands);
                    regArgEvidence[r] = { in.address, mo.ok && (mo.base == r || mo.index == r) };
                }
            }
            // Struct/this-pointer field access: [reg + smallDisp]
            MemOp mo = parseMem(in.operands);
            if (mo.ok && mo.base == r && r != "rbp" && r != "rsp" && mo.hasDisp && mo.disp >= 0 && mo.disp < 0x1000)
                fieldOffsets[r].insert(mo.disp);
        }
        for (const std::string& r : rw.writes) {
            if (r == "rsp") continue;
            Life& L = life[r];
            if (!L.first) { L.first = in.address; L.writtenFirst = true; }
            L.last = in.address; ++L.writes;
            writtenEver.insert(r);
        }
    }
    for (auto& [r, L] : life) {
        RegLifetime rl; rl.reg = r; rl.firstVA = L.first; rl.lastVA = L.last;
        rl.reads = L.reads; rl.writes = L.writes;
        out.regs.push_back(std::move(rl));
    }
    std::sort(out.regs.begin(), out.regs.end(),
              [](const RegLifetime& a, const RegLifetime& b) { return a.firstVA < b.firstVA; });

    // ---- 3) Stack frame slots (locals + stack args) -------------------------
    {
        std::map<std::pair<std::string, int64_t>, StackSlot> slots;
        for (const FlatInsn& f : flat) {
            const Instruction& in = *f.in;
            MemOp mo = parseMem(in.operands);
            if (!mo.ok || mo.base.empty()) continue;
            bool viaBp = mo.base == "rbp", viaSp = mo.base == "rsp";
            if (!viaBp && !viaSp) continue;
            if (in.mnemonic == "lea" && splitOps(in.operands).size() == 2) {
                // lea of a frame slot = address taken; still record the slot.
            }
            bool isArg = false; bool isLocal = false;
            if (viaBp) {
                if (mo.disp < 0) isLocal = true;
                else if (mo.disp >= (x64 ? 0x10 : 8)) isArg = true;
            } else if (viaSp) {
                if (mo.disp >= 0 && out.frameBytes && (uint64_t)mo.disp < out.frameBytes) isLocal = true;
                else if (out.frameBytes && (uint64_t)mo.disp >= out.frameBytes + (x64 ? 8u : 4u)) isArg = true;
                else if (!out.frameBytes) continue;   // no frame info: rsp offsets are ambiguous
            }
            if (!isArg && !isLocal) continue;
            auto key = std::make_pair(regDisplay(mo.base, x64), mo.disp);
            StackSlot& s = slots[key];
            if (s.name.empty()) {
                s.base = key.first; s.offset = mo.disp; s.isArg = isArg;
                char nm[32];
                if (isArg) {
                    int64_t argBase = viaBp ? (x64 ? 0x10 : 8) : (int64_t)out.frameBytes + (x64 ? 8 : 4);
                    std::snprintf(nm, sizeof(nm), "arg_%llX", (unsigned long long)(mo.disp - argBase));
                } else {
                    std::snprintf(nm, sizeof(nm), viaBp ? "var_%llX" : "var_s%llX",
                                  (unsigned long long)(viaBp ? -mo.disp : mo.disp));
                }
                s.name = nm;
            }
            if (writesMemFirstOp(in)) ++s.writes; else ++s.reads;
        }
        for (auto& [k, s] : slots) out.stack.push_back(std::move(s));
        std::sort(out.stack.begin(), out.stack.end(), [](const StackSlot& a, const StackSlot& b) {
            if (a.isArg != b.isArg) return !a.isArg;
            return a.offset < b.offset;
        });
    }

    // ---- 4) Calling convention + arguments ----------------------------------
    {
        int stackArgs = 0;
        for (const StackSlot& s : out.stack) if (s.isArg) ++stackArgs;
        if (x64) {
            // Count the contiguous run of arg registers with pre-write reads.
            int nreg = 0;
            for (const char* a : kArgRegs64) { if (regArgEvidence.count(a)) ++nreg; else break; }
            int loose = (int)regArgEvidence.size();   // non-contiguous reads still count as evidence
            if (loose > nreg) nreg = loose;
            if (nreg > 0 || stackArgs > 0) {
                out.convention = "Microsoft x64 (rcx, rdx, r8, r9)";
                out.convConfidence = 0.65f;
                std::string ev;
                for (auto& [r, e] : regArgEvidence) {
                    ev += ev.empty() ? "reads " : ", ";
                    ev += r + " at " + vaHex(e.va) + " before writing it";
                }
                if (stackArgs) ev += (ev.empty() ? "accesses " : "; plus ") +
                                     std::to_string(stackArgs) + " stack slot(s) above the return address";
                out.convEvidence = ev + " (register-usage heuristic; arg forwarding through calls not modelled)";
            } else {
                out.convention = "Microsoft x64 (assumed; no argument use observed)";
                out.convConfidence = 0.3f;
                out.convEvidence = "no argument register or stack-arg reads seen before they are overwritten";
            }
            int argn = 1;
            for (const char* a : kArgRegs64) {
                auto it = regArgEvidence.find(a);
                if (it == regArgEvidence.end()) { ++argn; continue; }
                std::string line = "arg" + std::to_string(argn) + " in " + a;
                auto fo = fieldOffsets.find(a);
                if (fo != fieldOffsets.end() && !fo->second.empty()) {
                    line += " — used as object/struct pointer (fields";
                    int shown = 0;
                    for (int64_t d : fo->second) { if (shown++ == 4) { line += ", ..."; break; } line += " +" + vaHex((uint64_t)d); }
                    line += ")";
                } else if (it->second.asBase) {
                    line += " — used as a pointer (memory base)";
                } else {
                    line += " — read at " + vaHex(it->second.va);
                }
                out.args.push_back(line);
                ++argn;
            }
            for (const StackSlot& s : out.stack)
                if (s.isArg) out.args.push_back("stack arg " + s.name + " at [" + s.base +
                                                (s.offset >= 0 ? "+" : "") + vaHex((uint64_t)s.offset) + "]");
        } else {
            // x86-32: ret imm is strong; ecx-before-write + field use suggests thiscall.
            uint32_t retImm = 0;
            for (int bi : order) {
                const BasicBlock& b = g.blocks[bi];
                if (!b.isReturn || b.insns.empty()) continue;
                const Instruction& r = b.insns.back();
                if (r.isRet && !r.operands.empty()) { int64_t v = 0; if (parseImm(r.operands, v) && v > 0) retImm = (uint32_t)v; }
            }
            bool ecxThis = regArgEvidence.count("rcx") &&
                           fieldOffsets.count("rcx") && !fieldOffsets["rcx"].empty();
            if (retImm) {
                out.convention = ecxThis ? "thiscall? (this in ecx, ret " + vaHex(retImm) + ")"
                                         : "stdcall (ret " + vaHex(retImm) + ")";
                out.convConfidence = ecxThis ? 0.6f : 0.85f;
                out.convEvidence = "ret " + vaHex(retImm) + " pops " + std::to_string(retImm / 4) +
                                   " stack argument(s) — callee-cleaned" +
                                   (ecxThis ? "; ecx read before write and used for field access" : "");
            } else if (ecxThis) {
                out.convention = "thiscall/fastcall? (ecx used before write)";
                out.convConfidence = 0.5f;
                out.convEvidence = "ecx read before any write and dereferenced with field offsets";
            } else if (stackArgs > 0) {
                out.convention = "cdecl (caller-cleaned stack args)";
                out.convConfidence = 0.5f;
                out.convEvidence = std::to_string(stackArgs) + " [ebp+N] argument slot(s) read; plain ret (caller cleans)";
            } else {
                out.convention = "cdecl (assumed; no argument use observed)";
                out.convConfidence = 0.3f;
                out.convEvidence = "no stack-argument reads seen";
            }
            if (ecxThis) {
                std::string line = "this in ecx — fields";
                int shown = 0;
                for (int64_t d : fieldOffsets["rcx"]) { if (shown++ == 4) { line += ", ..."; break; } line += " +" + vaHex((uint64_t)d); }
                out.args.push_back(line);
            }
            for (const StackSlot& s : out.stack)
                if (s.isArg) out.args.push_back(s.name + " at [ebp+" + vaHex((uint64_t)s.offset) + "]");
        }
    }

    // ---- 5) Loops (back edges by address order) -----------------------------
    struct LoopInfo { int header, latch; uint64_t lo, hi; };
    std::vector<LoopInfo> loops;
    std::unordered_set<uint64_t> loopTermVAs;   // latch terminators that got a loop note
    for (int bi : order) {
        const BasicBlock& b = g.blocks[bi];
        if (b.insns.empty()) continue;
        for (size_t s : b.succ) {
            if (s >= g.blocks.size()) continue;
            const BasicBlock& h = g.blocks[s];
            if (h.start > b.start || h.insns.empty()) continue;   // forward edge
            // Back edge b -> h. Treat [h.start, b.end) as the loop body (approximate).
            loops.push_back({ (int)s, bi, h.start, b.end });
            const Instruction& term = b.insns.back();
            // The latch terminator's condition text is composed in the branch pass
            // below, which checks this set to phrase it as a loop condition.
            if (isCondJump(term)) loopTermVAs.insert(term.address);
            note(h.insns.front().address, NoteKind::Loop,
                 "loop start (back edge from " + vaHex(term.address) + ")",
                 "block at " + vaHex(h.start) + " is re-entered from " + vaHex(b.start) +
                 " (address-order back edge; natural-loop approximation)", 0.7f);
        }
    }

    // ---- 6) Branch meaning + return-value-use + calls -----------------------
    for (int bi : order) {
        const BasicBlock& b = g.blocks[bi];
        if (b.insns.empty()) continue;

        // Switch dispatch.
        if (b.isSwitch) {
            const Instruction& term = b.insns.back();
            note(term.address, NoteKind::Switch,
                 "switch via jump table — " + std::to_string(b.caseTargets.size()) + " case(s)",
                 "indirect jmp resolved to a jump table with " + std::to_string(b.caseTargets.size()) +
                 " in-bounds targets", 0.9f);
        }

        for (size_t k = 0; k < b.insns.size(); ++k) {
            const Instruction& in = b.insns[k];

            // ---- calls ----
            if (in.isCall) {
                std::string nm = callName(in);
                bool indirect = nm.empty() && !HasBranchTarget(in);
                // Argument sniffing: scan backwards for the most recent writes to arg
                // regs (x64) / pushes (x86) since the previous call/branch.
                std::vector<std::string> argTexts;
                if (x64) {
                    std::map<std::string, std::string> argVal;
                    size_t back = 0;
                    for (size_t j = k; j-- > 0 && back < 14; ++back) {
                        const Instruction& p = b.insns[j];
                        if (p.isCall || (p.isBranch && !p.isCall)) break;
                        std::vector<std::string> ops = splitOps(p.operands);
                        if (ops.empty()) continue;
                        std::string dst = canonReg(ops[0]);
                        bool isArgR = dst == "rcx" || dst == "rdx" || dst == "r8" || dst == "r9";
                        if (!isArgR || argVal.count(dst)) continue;
                        std::string val;
                        if ((p.mnemonic == "xor" || p.mnemonic == "sub") && ops.size() == 2 && canonReg(ops[1]) == dst) val = "0";
                        else if (p.mnemonic == "lea" || p.mnemonic.rfind("mov", 0) == 0) {
                            uint64_t ref = instrDataRef(p); if (!ref) ref = instrImmRef(p);
                            if (ref) {
                                std::string s = stringFor(ref);
                                if (!s.empty()) val = "\"" + s.substr(0, 40) + "\"";
                                else { std::string n2 = nameFor(ref); val = n2.empty() ? ("&" + vaHex(ref)) : ("&" + n2); }
                            } else if (ops.size() == 2) {
                                int64_t imm = 0;
                                if (parseImm(ops[1], imm)) val = vaHex((uint64_t)imm);
                                else val = ops[1].substr(0, 24);
                            }
                        }
                        if (!val.empty()) argVal[dst] = val;
                    }
                    for (const char* a : kArgRegs64) {
                        auto it = argVal.find(a);
                        if (it != argVal.end())
                            argTexts.push_back(std::string(a) + "=" + it->second);
                    }
                } else {
                    // x86: pushes between the previous call/branch and this call, last push = arg1.
                    std::vector<std::string> pushes;
                    for (size_t j = k; j-- > 0 && pushes.size() < 6;) {
                        const Instruction& p = b.insns[j];
                        if (p.isCall || (p.isBranch && !p.isCall)) break;
                        if (p.mnemonic == "push") {
                            std::string val;
                            uint64_t ref = instrImmRef(p);
                            if (ref) {
                                std::string s = stringFor(ref);
                                val = !s.empty() ? "\"" + s.substr(0, 40) + "\"" : "&" + vaHex(ref);
                            } else val = p.operands.substr(0, 24);
                            pushes.push_back(val);
                        }
                    }
                    for (size_t j = 0; j < pushes.size(); ++j)
                        argTexts.push_back("arg" + std::to_string(j + 1) + "=" + pushes[j]);
                }

                if (indirect) {
                    // Virtual-call pattern: dispatch reg loaded from [obj] shortly before.
                    MemOp cm = parseMem(in.operands);
                    std::string dispReg = !cm.ok ? canonReg(in.operands) : cm.base;
                    bool isVirtual = false; std::string objReg; int64_t slot = cm.ok ? cm.disp : 0;
                    if (!dispReg.empty()) {
                        for (size_t j = k; j-- > 0 && k - j <= 6;) {
                            const Instruction& p = b.insns[j];
                            std::vector<std::string> ops = splitOps(p.operands);
                            if (ops.size() == 2 && p.mnemonic == "mov" && canonReg(ops[0]) == dispReg) {
                                MemOp lm = parseMem(ops[1]);
                                if (lm.ok && !lm.base.empty() && (!lm.hasDisp || lm.disp == 0) &&
                                    lm.base != "rbp" && lm.base != "rsp") {
                                    isVirtual = true; objReg = lm.base;
                                }
                                break;
                            }
                            if (p.isCall) break;
                        }
                    }
                    if (isVirtual) {
                        std::string txt = "likely virtual call: vtable from [" + regDisplay(objReg, x64) +
                                          "], slot +" + vaHex((uint64_t)slot);
                        if (objReg == "rcx") txt += " (this in " + regDisplay("rcx", x64) + ")";
                        note(in.address, NoteKind::VirtualCall, txt,
                             "mov " + dispReg + ", [" + objReg + "] followed by call through " + dispReg +
                             " — classic vtable dispatch shape (heuristic)", 0.55f);
                    } else {
                        note(in.address, NoteKind::IndirectCall,
                             "indirect call through " + in.operands + " — target decided at runtime",
                             "no static target; register/computed-memory call", 0.8f);
                    }
                } else if (!nm.empty()) {
                    std::string purpose = ApiPurpose(nm);
                    std::string txt;
                    if (!purpose.empty()) txt = purpose;
                    if (!argTexts.empty()) {
                        if (!txt.empty()) txt += " — ";
                        txt += "args: ";
                        for (size_t j = 0; j < argTexts.size(); ++j) { if (j) txt += ", "; txt += argTexts[j]; }
                    }
                    if (!txt.empty())
                        note(in.address, NoteKind::Call, txt,
                             "call to " + nm + (argTexts.empty() ? "" :
                             "; argument registers/pushes traced back within this block (best-effort)"),
                             argTexts.empty() ? 0.75f : 0.6f);
                }

                // Return-value use: scan forward for a read of rax before a write.
                {
                    int seen = 0; bool decided = false;
                    auto scanInsn = [&](const Instruction& q) -> bool {   // true = stop
                        RW rw = classifyRW(q);
                        bool reads = false, writes = false;
                        for (auto& r : rw.reads) if (r == "rax") reads = true;
                        for (auto& r : rw.writes) if (r == "rax") writes = true;
                        if (reads && !rw.zeroIdiom) {
                            std::string how = (q.mnemonic == "cmp" || q.mnemonic == "test")
                                              ? "checked at " + vaHex(q.address)
                                              : "used at " + vaHex(q.address);
                            note(in.address, NoteKind::RetUse, "return value is " + how,
                                 q.mnemonic + " " + q.operands + " reads " + regDisplay("rax", x64) +
                                 " before anything overwrites it", 0.7f);
                            decided = true; return true;
                        }
                        if (writes) {
                            note(in.address, NoteKind::RetUse, "return value not used (overwritten at " +
                                 vaHex(q.address) + ")",
                                 q.mnemonic + " " + q.operands + " overwrites " + regDisplay("rax", x64) +
                                 " before any read (window-limited check)", 0.5f);
                            decided = true; return true;
                        }
                        return false;
                    };
                    for (size_t j = k + 1; j < b.insns.size() && seen < 8 && !decided; ++j, ++seen)
                        if (scanInsn(b.insns[j])) break;
                    if (!decided && seen < 8) {
                        // Follow the unique fallthrough successor a short distance.
                        for (size_t s : b.succ) {
                            if (s >= g.blocks.size()) continue;
                            const BasicBlock& nb = g.blocks[s];
                            if (nb.start != b.end) continue;   // only the fallthrough
                            for (size_t j = 0; j < nb.insns.size() && seen < 8 && !decided; ++j, ++seen)
                                if (scanInsn(nb.insns[j])) break;
                            break;
                        }
                    }
                }
            }

            // ---- conditional branch meaning ----
            if (isCondJump(in) && k == b.insns.size() - 1) {
                // Find the flag setter scanning backwards in this block.
                const Instruction* fs = nullptr;
                for (size_t j = k; j-- > 0;) {
                    if (isFlagSetter(b.insns[j].mnemonic)) { fs = &b.insns[j]; break; }
                    if (b.insns[j].isCall) break;   // a call clobbers flags
                }
                bool sgn = false, uns = false;
                const char* op = jccExprOp(in.mnemonic, sgn, uns);
                std::string cond, ev;
                if (fs && op) {
                    std::vector<std::string> fo = splitOps(fs->operands);
                    std::string A = fo.size() > 0 ? fo[0] : "";
                    std::string Bp = fo.size() > 1 ? fo[1] : "";
                    if (fs->mnemonic == "test" && fo.size() == 2 && A == Bp) {
                        if (!std::strcmp(op, "==")) cond = A + " == 0";
                        else if (!std::strcmp(op, "!=")) cond = A + " != 0";
                        else if (!std::strcmp(op, "s"))  cond = A + " < 0";
                        else if (!std::strcmp(op, "ns")) cond = A + " >= 0";
                        else cond = A + " " + op + " 0";
                    } else if (fs->mnemonic == "test") {
                        cond = "(" + A + " & " + Bp + ") " + (std::strcmp(op, "==") ? "!= 0" : "== 0");
                    } else if (fs->mnemonic == "cmp") {
                        if (!std::strcmp(op, "s"))      cond = A + " - " + Bp + " < 0";
                        else if (!std::strcmp(op, "ns")) cond = A + " - " + Bp + " >= 0";
                        else cond = A + " " + op + " " + Bp + (sgn ? " (signed)" : uns ? " (unsigned)" : "");
                    } else {   // arithmetic set the flags
                        cond = "result of `" + fs->mnemonic + " " + fs->operands + "` " +
                               (std::strcmp(op, "==") == 0 ? "is zero" :
                                std::strcmp(op, "!=") == 0 ? "is non-zero" :
                                std::string("compares ") + op + " 0");
                    }
                    ev = "flags set by `" + fs->mnemonic + " " + fs->operands + "` at " + vaHex(fs->address);

                    // Did the compared value come from the previous call's return?
                    std::vector<std::string> fsRegs; regsInText(fs->operands, fsRegs);
                    bool usesRax = std::find(fsRegs.begin(), fsRegs.end(), "rax") != fsRegs.end();
                    std::string callerNote, calleeNm;
                    if (usesRax) {
                        for (size_t j = k; j-- > 0;) {
                            const Instruction& p = b.insns[j];
                            if (p.address >= fs->address) continue;
                            RW rw = classifyRW(p);
                            bool wrAx = false;
                            for (auto& r : rw.writes) if (r == "rax") wrAx = true;
                            if (p.isCall) { calleeNm = callName(p); if (calleeNm.empty()) calleeNm = "the previous call"; break; }
                            if (wrAx) break;
                        }
                    }
                    std::string txt;
                    if (!calleeNm.empty() && nameLooksLikeCompare(calleeNm)) {
                        bool jumpOnNonZero = !std::strcmp(op, "!=");
                        bool jumpOnZero    = !std::strcmp(op, "==");
                        if (jumpOnNonZero)
                            txt = "jumps to " + vaHex(in.branchTarget) + " if " + calleeNm +
                                  " result is non-zero (strings/memory differ)";
                        else if (jumpOnZero)
                            txt = "jumps to " + vaHex(in.branchTarget) + " if " + calleeNm +
                                  " result is zero (contents equal)";
                        if (!txt.empty()) ev += "; " + calleeNm + " returns 0 on equality";
                    }
                    if (txt.empty()) {
                        txt = "jumps to " + vaHex(in.branchTarget) + " if " + cond;
                        if (!calleeNm.empty()) {
                            txt += " — return value of " + calleeNm + " controls this branch";
                            ev += "; value comes from " + calleeNm;
                        }
                    }
                    if (loopTermVAs.count(in.address)) {
                        txt = "loop: continues while " + cond +
                              (in.branchTarget <= in.address ? "" : " (exit branch)");
                        note(in.address, NoteKind::Loop, txt, ev + "; backward branch closes a loop", 0.7f);
                    } else {
                        note(in.address, NoteKind::Branch, txt, ev, 0.75f);
                    }
                } else if (loopTermVAs.count(in.address)) {
                    note(in.address, NoteKind::Loop,
                         "loop back edge to " + vaHex(in.branchTarget),
                         "backward conditional branch (flag source not identified)", 0.6f);
                }
            }

            // ---- vtable pointer store: lea reg, [code]; ... mov [obj], reg ----
            if (opt.looksLikeVtable && in.mnemonic == "mov") {
                std::vector<std::string> ops = splitOps(in.operands);
                if (ops.size() == 2 && ops[0].find('[') != std::string::npos) {
                    uint64_t cand = 0;
                    std::string src = canonReg(ops[1]);
                    if (!src.empty()) {
                        for (size_t j = k; j-- > 0 && k - j <= 6;) {
                            const Instruction& p = b.insns[j];
                            std::vector<std::string> po = splitOps(p.operands);
                            if (po.size() == 2 && canonReg(po[0]) == src) {
                                if (p.mnemonic == "lea" || p.mnemonic == "mov") {
                                    uint64_t r = instrDataRef(p); if (!r) r = instrImmRef(p);
                                    cand = r;
                                }
                                break;
                            }
                        }
                    } else {
                        int64_t imm = 0;
                        if (parseImm(ops[1], imm) && imm > 0x1000) cand = (uint64_t)imm;
                    }
                    MemOp dm = parseMem(ops[0]);
                    if (cand && dm.ok && !dm.base.empty() && dm.base != "rbp" && dm.base != "rsp" &&
                        (!dm.hasDisp || dm.disp == 0) && opt.looksLikeVtable(cand)) {
                        note(in.address, NoteKind::Vtable,
                             "stores vtable pointer " + vaHex(cand) + " into [" + regDisplay(dm.base, x64) +
                             "] — object construction?",
                             vaHex(cand) + " holds consecutive code pointers (vtable shape) and is written to "
                             "offset 0 of an object pointer", 0.6f);
                    }
                }
            }
        }
    }

    // ---- 7) Loop-body pattern scans -----------------------------------------
    for (const LoopInfo& L : loops) {
        int xorMem = 0, xorImm = 0, memWrite = 0, memRead = 0, idxStep = 0, mix = 0, accAdd = 0, byteCmp = 0;
        std::vector<uint64_t> ev;
        int insnCount = 0;
        for (int bi : order) {
            const BasicBlock& b = g.blocks[bi];
            if (b.start < L.lo || b.start >= L.hi) continue;
            for (const Instruction& in : b.insns) {
                ++insnCount;
                const std::string& m = in.mnemonic;
                std::vector<std::string> ops = splitOps(in.operands);
                bool hasMem = in.operands.find('[') != std::string::npos;
                if (m == "xor" && ops.size() == 2) {
                    if (hasMem) { ++xorMem; ev.push_back(in.address); }
                    else {
                        int64_t imm = 0;
                        if (canonReg(ops[1]).empty() && parseImm(ops[1], imm) && imm != 0) { ++xorImm; ev.push_back(in.address); }
                    }
                }
                if (hasMem && writesMemFirstOp(in)) ++memWrite;
                if (hasMem && !writesMemFirstOp(in) && m != "lea" && m != "cmp") ++memRead;
                if (m == "inc" || (m == "add" && ops.size() == 2 && [&]{ int64_t v; return parseImm(ops[1], v) && v >= 1 && v <= 8; }()))
                    ++idxStep;
                if (m == "lea" && ops.size() == 2) {
                    MemOp lm = parseMem(ops[1]);
                    if (lm.ok && lm.base == canonReg(ops[0]) && lm.hasDisp && lm.disp >= 1 && lm.disp <= 8) ++idxStep;
                }
                if (m == "rol" || m == "ror" || m == "shl" || m == "shr" || m == "sar" || m == "imul") { ++mix; ev.push_back(in.address); }
                if ((m == "add" || m == "adc") && hasMem && ops.size() == 2 && ops[1].find('[') != std::string::npos)
                    { ++accAdd; ev.push_back(in.address); }
                if ((m == "add" || m == "adc") && ops.size() == 2 && !canonReg(ops[1]).empty()) ++accAdd;
                if (m == "cmp" && toLower(in.operands).find("byte") != std::string::npos && hasMem)
                    { ++byteCmp; ev.push_back(in.address); }
                if (in.isRepString) { ++memRead; ++memWrite; }
            }
        }
        auto evStr = [&](const char* what) {
            std::string s = std::string(what) + " inside loop " + vaHex(L.lo) + "-" + vaHex(L.hi) + ":";
            int shown = 0;
            for (uint64_t a : ev) { if (shown++ == 6) { s += " ..."; break; } s += " " + vaHex(a); }
            return s;
        };
        uint64_t hdrVA = 0;
        for (int bi : order) if (g.blocks[bi].start == L.lo && !g.blocks[bi].insns.empty()) { hdrVA = g.blocks[bi].insns.front().address; break; }
        if ((xorMem >= 1 && idxStep >= 1) || (xorImm >= 1 && memRead >= 1 && memWrite >= 1 && idxStep >= 1)) {
            float conf = 0.5f + (xorMem && memWrite ? 0.15f : 0.0f);
            note(hdrVA, NoteKind::Pattern, "XOR decode/encode loop?",
                 evStr("xor over advancing memory"), conf);
        } else if (mix >= 1 && (xorMem + xorImm + accAdd) >= 1 && memRead >= 1 && idxStep >= 1) {
            note(hdrVA, NoteKind::Pattern, "checksum/hash-like loop?",
                 evStr("shift/rotate/multiply mixed with accumulation over memory"), 0.5f);
        } else if (byteCmp >= 1 && idxStep >= 1) {
            note(hdrVA, NoteKind::Pattern, "byte-compare loop (string/memory comparison?)",
                 evStr("byte-wide compares over advancing memory"), 0.5f);
        }
        (void)insnCount;
    }

    // ---- 8) Function-level API-set patterns ----------------------------------
    {
        struct ApiHit { std::string name; uint64_t va; };
        std::vector<ApiHit> calls;
        bool hasRdtsc = false; uint64_t rdtscVA = 0;
        for (const FlatInsn& f : flat) {
            const Instruction& in = *f.in;
            if (in.isCall) {
                std::string nm = callName(in);
                if (!nm.empty()) calls.push_back({ toLower(nm), in.address });
            }
            if (in.mnemonic == "rdtsc" || in.mnemonic == "rdtscp") { hasRdtsc = true; rdtscVA = in.address; }
        }
        auto findCalls = [&](std::initializer_list<const char*> keys, std::vector<const ApiHit*>& hits) {
            for (const ApiHit& c : calls)
                for (const char* k : keys)
                    if (c.name.find(k) != std::string::npos) { hits.push_back(&c); break; }
        };
        auto emitApiPattern = [&](const char* text, std::initializer_list<const char*> keys, float conf) {
            std::vector<const ApiHit*> hits;
            findCalls(keys, hits);
            if (hits.empty()) return;
            std::string ev = "calls:";
            int shown = 0;
            for (const ApiHit* h : hits) { if (shown++ == 5) { ev += " ..."; break; } ev += " " + h->name + "@" + vaHex(h->va); }
            note(0, NoteKind::Pattern, text, ev, conf);
        };
        emitApiPattern("reads user input", { "readconsole", "scanf", "fgets", "getchar", "_getch",
                       "getwindowtext", "getdlgitemtext", "readline", "istream" }, 0.65f);
        emitApiPattern("polls keyboard/mouse state (input handler?)",
                       { "getasynckeystate", "getkeystate", "getkeyboardstate", "getcursorpos" }, 0.6f);
        emitApiPattern("performs string/memory comparison",
                       { "strcmp", "strncmp", "stricmp", "memcmp", "wcscmp", "lstrcmp", "comparestring" }, 0.7f);
        emitApiPattern("opens/reads files", { "createfile", "fopen", "_wfopen", "openfile", "fread" }, 0.6f);
        emitApiPattern("network I/O", { "wsastartup", "socket", "connect", "recv", "internetopen",
                       "winhttp", "urldownload", "httpsendrequest" }, 0.65f);
        emitApiPattern("reads timers (frame pacing / timing / anti-debug?)",
                       { "gettickcount", "queryperformancecounter", "timegettime" }, 0.55f);
        emitApiPattern("registers a callback/handler",
                       { "setwindowshookex", "registerclass", "settimer", "createthread", "atexit",
                         "signal", "setunhandledexceptionfilter", "setconsolectrlhandler" }, 0.6f);
        emitApiPattern("Windows message pump (UI/render/update loop candidate?)",
                       { "peekmessage", "getmessage", "dispatchmessage" }, !loops.empty() ? 0.6f : 0.45f);
        if (hasRdtsc)
            note(0, NoteKind::Pattern, "reads the CPU timestamp counter (timing/anti-debug?)",
                 "rdtsc at " + vaHex(rdtscVA), 0.6f);
        // Config/save file loading: file API + a referenced path-looking string.
        {
            std::vector<const ApiHit*> fileHits;
            findCalls({ "createfile", "fopen", "_wfopen" }, fileHits);
            if (!fileHits.empty() && opt.stringFor) {
                static const char* kExt[] = { ".ini", ".cfg", ".json", ".xml", ".dat", ".sav", ".bin",
                                              ".txt", ".db", ".cfg", ".conf", ".properties", ".yml" };
                for (const FlatInsn& f : flat) {
                    uint64_t ref = instrDataRef(*f.in); if (!ref) ref = instrImmRef(*f.in);
                    if (!ref) continue;
                    std::string s = toLower(stringFor(ref));
                    if (s.empty()) continue;
                    for (const char* e : kExt) {
                        if (s.size() > std::strlen(e) && s.rfind(e) == s.size() - std::strlen(e)) {
                            note(0, NoteKind::Pattern, "loads config/data file \"" + stringFor(ref) + "\"?",
                                 "file-open API called in this function and \"" + stringFor(ref) +
                                 "\" is referenced at " + vaHex(f.in->address), 0.55f);
                            e = nullptr; break;
                        }
                    }
                    if (out.notes.size() > 400) break;   // sanity cap
                }
            }
        }
    }

    // ---- 9) Summary + ordering ------------------------------------------------
    {
        std::sort(out.notes.begin(), out.notes.end(),
                  [](const FnNote& a, const FnNote& b) {
                      if (a.va != b.va) return a.va < b.va;
                      return (int)a.kind < (int)b.kind;
                  });
        int nLocals = 0, nArgsStack = 0, nCalls = 0, nPatterns = 0;
        for (const StackSlot& s : out.stack) (s.isArg ? nArgsStack : nLocals)++;
        for (const FnNote& n : out.notes) {
            if (n.kind == NoteKind::Call || n.kind == NoteKind::IndirectCall || n.kind == NoteKind::VirtualCall) ++nCalls;
            if (n.kind == NoteKind::Pattern) ++nPatterns;
        }
        std::string s = out.convention.empty() ? "" : out.convention;
        size_t paren = s.find(" (assumed");
        if (paren != std::string::npos) s = s.substr(0, paren) + "?";
        if (!out.args.empty()) s += (s.empty() ? "" : " · ") + std::to_string(out.args.size()) + " arg(s)";
        if (out.frameBytes)   s += (s.empty() ? "" : " · ") + ("frame " + vaHex(out.frameBytes));
        if (nLocals)          s += (s.empty() ? "" : " · ") + std::to_string(nLocals) + " local(s)";
        if (!loops.empty())   s += (s.empty() ? "" : " · ") + std::to_string(loops.size()) + " loop(s)";
        for (const FnNote& n : out.notes)
            if (n.kind == NoteKind::Pattern && n.va == 0 && s.size() < 140) { s += " · " + n.text; break; }
        out.summary = s;
    }
    return out;
}

} // namespace ds
