//
// Synthesis.cpp — see Synthesis.h. Pure-Core F1 pipeline.
//
#include "Synthesis.h"
#include "Simplify.h"

#include <cctype>
#include <random>
#include <unordered_map>

namespace ds {

// ---- small register-file name access (sub-registers map to their 64-bit parent) ----
static uint64_t* RegPtr(RegFile& r, const std::string& nameRaw) {
    std::string n; n.reserve(nameRaw.size());
    for (char c : nameRaw) n.push_back((char)std::tolower((unsigned char)c));
    // Normalize common sub-register names to their 64-bit parent (the call site
    // masks the returned storage to the output width, so the parent value is correct).
    static const struct { const char* sub; const char* parent; } aliases[] = {
        {"eax","rax"},{"ax","rax"},{"al","rax"},   {"ebx","rbx"},{"bx","rbx"},{"bl","rbx"},
        {"ecx","rcx"},{"cx","rcx"},{"cl","rcx"},   {"edx","rdx"},{"dx","rdx"},{"dl","rdx"},
        {"esi","rsi"},{"si","rsi"},{"sil","rsi"},  {"edi","rdi"},{"di","rdi"},{"dil","rdi"},
        {"ebp","rbp"},{"bp","rbp"},{"bpl","rbp"},  {"esp","rsp"},{"sp","rsp"},{"spl","rsp"},
        {"r8d","r8"},{"r8w","r8"},{"r8b","r8"},     {"r9d","r9"},{"r9w","r9"},{"r9b","r9"},
        {"r10d","r10"},{"r10w","r10"},{"r10b","r10"},{"r11d","r11"},{"r11w","r11"},{"r11b","r11"},
        {"r12d","r12"},{"r12w","r12"},{"r12b","r12"},{"r13d","r13"},{"r13w","r13"},{"r13b","r13"},
        {"r14d","r14"},{"r14w","r14"},{"r14b","r14"},{"r15d","r15"},{"r15w","r15"},{"r15b","r15"},
        {"eip","rip"},{"eflags","rflags"},
    };
    for (auto& a : aliases) if (n == a.sub) { n = a.parent; break; }
    static const struct { const char* nm; size_t off; } tbl[] = {
        {"rax", offsetof(RegFile,rax)},{"rbx", offsetof(RegFile,rbx)},{"rcx", offsetof(RegFile,rcx)},
        {"rdx", offsetof(RegFile,rdx)},{"rsi", offsetof(RegFile,rsi)},{"rdi", offsetof(RegFile,rdi)},
        {"rbp", offsetof(RegFile,rbp)},{"rsp", offsetof(RegFile,rsp)},{"r8", offsetof(RegFile,r8)},
        {"r9", offsetof(RegFile,r9)},{"r10", offsetof(RegFile,r10)},{"r11", offsetof(RegFile,r11)},
        {"r12", offsetof(RegFile,r12)},{"r13", offsetof(RegFile,r13)},{"r14", offsetof(RegFile,r14)},
        {"r15", offsetof(RegFile,r15)},{"rip", offsetof(RegFile,rip)},{"rflags", offsetof(RegFile,rflags)},
    };
    for (auto& e : tbl) if (n == e.nm) return (uint64_t*)((char*)&r + e.off);
    return nullptr;
}

static uint64_t RegGet(const RegFile& r, const std::string& name) {
    uint64_t* p = RegPtr(const_cast<RegFile&>(r), name);
    return p ? *p : 0;
}

// Write a `bytes`-wide little-endian value into whichever MemBlock contains `addr`.
static void MemWrite(std::vector<MemBlock>& mem, uint64_t addr, uint32_t bytes, uint64_t val) {
    for (auto& b : mem) {
        if (addr >= b.base && addr + bytes <= b.base + b.bytes.size()) {
            for (uint32_t i = 0; i < bytes; ++i)
                b.bytes[addr - b.base + i] = (uint8_t)((val >> (8 * i)) & 0xFF);
            return;
        }
    }
}

// Apply a per-sample assignment (varId -> value) onto a copy of the seed.
static void ApplyInputs(SeedSource& seed, const std::vector<SymbolicInput>& inputs,
                        const std::unordered_map<uint64_t, uint64_t>& assign) {
    for (const auto& in : inputs) {
        auto it = assign.find(in.varId);
        if (it == assign.end()) continue;
        const uint64_t v = it->second;
        if (in.kind == SymbolicInput::Reg) {
            if (uint64_t* p = RegPtr(seed.regs, in.regName)) *p = v;
        } else {
            MemWrite(seed.mem, in.addr, in.bytes, v);
        }
    }
}

// Substitute Var nodes with constants from `assign`, then evaluate.
static ExprRef SubstVars(const ExprRef& e, const std::unordered_map<uint64_t, uint64_t>& assign) {
    if (!e) return e;
    if (e->op == ExprOp::Var) {
        auto it = assign.find(e->val);
        if (it != assign.end()) return C(it->second, e->bits);
        return e;
    }
    if (e->kids.empty()) return e;
    std::vector<ExprRef> k; k.reserve(e->kids.size());
    for (const auto& c : e->kids) k.push_back(SubstVars(c, assign));
    auto m = std::make_shared<Expr>(); m->op = e->op; m->bits = e->bits; m->val = e->val; m->kids = std::move(k);
    return m;
}

EnvelopeReport CheckEnvelope(const std::vector<Instruction>& insns, uint64_t lo, uint64_t hi) {
    EnvelopeReport r;
    for (const auto& in : insns) {
        if (in.address < lo || in.address >= hi) continue;
        if (in.isCall)       { r.reason = "region contains a CALL (out of envelope)"; return r; }
        if (in.isRepString)  { r.reason = "region contains a REP-string loop";        return r; }
        std::string m; for (char c : in.mnemonic) m.push_back((char)std::tolower((unsigned char)c));
        if (m == "syscall" || m == "sysenter" || (m.size() >= 3 && m.substr(0,3) == "int"))
            { r.reason = "region contains a syscall/int (out of envelope)"; return r; }
        if (in.isBranch && in.branchTarget != 0) {
            const uint64_t t = in.branchTarget;
            if (t <= in.address && t >= lo) { r.reason = "region contains a loop (back-edge)"; return r; }
            if (t < lo || t >= hi)          { r.reason = "branch leaves the region";          return r; }
        }
    }
    r.inEnvelope = true;
    return r;
}

SynthResult Synthesize(const std::vector<Instruction>& insns, uint64_t lo, uint64_t hi,
                       const std::vector<SymbolicInput>& inputs, const SeedSource& seed,
                       ISymEngine& eng, ISolver& solver, const SynthesisOptions& opt) {
    SynthResult res;
    res.regionStart = lo;
    res.regionSize  = (uint32_t)(hi - lo);

    EnvelopeReport env = CheckEnvelope(insns, lo, hi);
    if (!env.inEnvelope) { res.rejectedReason = env.reason; return res; }
    res.inEnvelope = true;

    SymOptions so; so.useZ3 = opt.useZ3;
    SymOutputs outs;
    SymStatus st = eng.symbolizeRegion(seed, lo, hi, inputs, so, outs);
    if (st != SymStatus::Ok || outs.outputs.empty()) {
        res.rejectedReason = "symbolic execution produced no usable output";
        res.reasoning = "engine status was not Ok / no outputs";
        return res;
    }

    // Simplify every output; keep the original (pre-simplify) for the optional Z3 check.
    std::vector<ExprRef> origExprs;
    for (const auto& v : outs.outputs) {
        origExprs.push_back(v.expr);
        res.outputs.push_back(SymValue{ v.loc, solver.simplify(v.expr) });
    }

    const std::string& primaryLoc = res.outputs[0].loc;
    const ExprRef&      primary    = res.outputs[0].expr;

    // ---- N-sample blackbox I/O equivalence ----
    std::mt19937_64 rng(opt.seed);
    uint32_t passed = 0;
    const uint32_t total = opt.samples;
    for (uint32_t s = 0; s < total; ++s) {
        std::unordered_map<uint64_t, uint64_t> assign;
        for (const auto& in : inputs) {
            const uint32_t bits = (in.bytes == 0 || in.bytes >= 8) ? 64u : in.bytes * 8u;
            assign[in.varId] = MaskToBits(rng(), bits);
        }
        SeedSource sd = seed;
        ApplyInputs(sd, inputs, assign);

        ConcreteState cs;
        SymStatus cst = eng.runConcrete(sd, lo, hi, so, cs);

        uint64_t pred = 0;
        bool okPred = EvalConst(SubstVars(primary, assign), pred);

        if (cst == SymStatus::Ok && okPred) {
            const uint32_t w = primary ? primary->bits : 64;
            const uint64_t actual = MaskToBits(RegGet(cs.regs, primaryLoc), w);
            if (MaskToBits(pred, w) == actual) ++passed;
        }
    }
    res.samplesPassed = passed;
    res.samplesTotal  = total;
    res.confidence    = total ? (double)passed / (double)total : 0.0;

    // Optional solver equivalence: orig != simplified is UNSAT  =>  equivalent.
    if (opt.useZ3 && primary) {
        ExprRef diff = Bin(ExprOp::Ne, origExprs[0], primary, 1);
        res.z3Equivalent = (solver.isSat(diff) == 0);
    }

    res.cleanedPseudoC = primaryLoc + " = " + ExprToString(primary) + ";";
    char note[160];
    std::snprintf(note, sizeof(note),
                  "simplified %zu output(s); I/O-equivalent on %u/%u random samples (%.1f%%)%s",
                  res.outputs.size(), passed, total, res.confidence * 100.0,
                  res.z3Equivalent ? "; solver-equivalent" : "");
    res.reasoning = note;
    return res;
}

} // namespace ds
