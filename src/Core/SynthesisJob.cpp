//
// SynthesisJob.cpp — see SynthesisJob.h.
//
#include "SynthesisJob.h"
#include "SymEngine.h"
#include "BinaryFile.h"

#include <algorithm>
#include <string>

namespace ds {

SynthResult SynthesizeJob(const BinaryFile& bin, IDisassembler& dis, Arch arch,
                          uint64_t lo, uint64_t hi, const SynthesisOptions& opt) {
    SynthResult res;
    res.regionStart = lo;
    res.regionSize  = (hi > lo) ? (uint32_t)(hi - lo) : 0;

    if (hi <= lo) { res.rejectedReason = "empty region"; return res; }
    if (!ArchIsX86_32Or64(arch)) {
        res.rejectedReason = std::string("synthesis is x86/x64-only; unsupported architecture: ") +
                             ArchName(arch);
        return res;
    }

    size_t avail = 0;
    const uint8_t* p = bin.ptrFromVA(lo, avail);
    if (!p || avail == 0) { res.rejectedReason = "region is not backed by mapped bytes"; return res; }

    const size_t span = std::min(avail, (size_t)(hi - lo));

    // Decode the region into a linear instruction list.
    std::vector<Instruction> insns;
    uint64_t va = lo;
    size_t   off = 0;
    while (va < hi && off < span) {
        Instruction in;
        if (!dis.decodeOne(p + off, span - off, va, in) || in.length == 0) break;
        insns.push_back(in);
        va  += in.length;
        off += in.length;
    }
    if (insns.empty()) { res.rejectedReason = "region did not decode to any instruction"; return res; }

    // Seed the engine with the region bytes and mark the inferred arg registers symbolic.
    SeedSource seed;
    seed.arch = arch;
    MemBlock blk;
    blk.base  = lo;
    blk.bytes.assign(p, p + span);
    blk.perms = P_R | P_X;
    seed.mem.push_back(std::move(blk));

    // Also seed every readable section so RIP-relative loads into .rdata/.data/etc.
    // resolve to concrete bytes instead of faulting on unmapped memory. Section blocks
    // may overlap the code block above; that's fine — reads just resolve either way.
    for (const Section& sec : bin.sections()) {
        const uint64_t secVA = bin.imageBase() + sec.virtualAddress;
        size_t secAvail = 0;
        const uint8_t* sp = bin.ptrFromVA(secVA, secAvail);
        if (!sp || secAvail == 0) continue;
        MemBlock sb;
        sb.base  = secVA;
        sb.bytes.assign(sp, sp + secAvail);
        sb.perms = sec.executable ? (P_R | P_X) : P_R;
        seed.mem.push_back(std::move(sb));
    }

    // Seed a stack so stack-local reads/writes land in mapped, writable memory.
    seed.regs.rsp = 0x7FFFFFFF0000ull;        // sane 16-byte-aligned base
    {
        MemBlock stk;
        stk.base = seed.regs.rsp - 0x4000;
        stk.bytes.assign(0x8000, 0);          // [rsp-0x4000, rsp+0x4000) zero-filled
        stk.perms = P_R | P_W;
        seed.mem.push_back(std::move(stk));
    }

    std::vector<SymbolicInput> inputs;
    if (arch == Arch::X64) {                       // Win64 integer arg registers
        static const char* kArgs[] = { "rcx", "rdx", "r8", "r9" };
        for (uint64_t i = 0; i < 4; ++i)
            inputs.push_back({ SymbolicInput::Reg, kArgs[i], 0, 8, i, std::string("arg") + std::to_string(i) });
    }
    // (x86 stack-arg detection is a documented follow-up; the region still runs with no
    //  symbolic inputs, which the verifier reports as low confidence rather than wrong.)

    auto eng    = MakeSymEngine(arch);
    auto solver = MakeSolver();
    return Synthesize(insns, lo, hi, inputs, seed, *eng, *solver, opt);
}

} // namespace ds
