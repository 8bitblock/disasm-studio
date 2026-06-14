#include "CapstoneDisassembler.h"

#include <capstone/capstone.h>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace ds {

// A REP/REPE/REPNE-prefixed x86 string op (movs/stos/cmps/scas/lods/ins/outs)
// must be treated as one unit when stepping over / out, not single-stepped per
// iteration. Mirrors the Zydis backend's isRepString. Capstone reports the
// legacy group-1 prefix in cs_x86.prefix[0] (and, depending on version, may also
// fold it into the mnemonic text), so we check both and require a string-op base
// mnemonic to avoid flagging SSE instructions that carry a mandatory 0xF2/0xF3.
static bool isRepStringInsn(const cs_insn* insn) {
    if (!insn->detail) return false;
    const cs_x86& x = insn->detail->x86;
    bool hasRep = (x.prefix[0] == X86_PREFIX_REP || x.prefix[0] == X86_PREFIX_REPNE);
    std::string m = insn->mnemonic;
    for (char& c : m) c = (char)std::tolower((unsigned char)c);
    if (!hasRep && (m.rfind("rep", 0) == 0)) hasRep = true;   // e.g. "rep movsb"
    if (!hasRep) return false;
    size_t sp = m.find_last_of(' ');
    std::string base = (sp == std::string::npos) ? m : m.substr(sp + 1);
    static const char* kStr[] = { "movs", "stos", "cmps", "scas", "lods", "ins", "outs" };
    for (const char* s : kStr) if (base.rfind(s, 0) == 0) return true;
    return false;
}

// Extract the first immediate operand of a branch/call as its target. Capstone
// resolves relative branches to absolute addresses for every architecture, so
// reading the IMM operand from the arch-specific detail union yields the same
// branchTarget the Zydis backend produces for x86 - now for ARM/ARM64/MIPS/PPC/
// RISC-V too, which is what CFG, xref, call-graph and goto navigation rely on.
static uint64_t branchTargetFor(const cs_insn* insn, Arch arch) {
    const cs_detail* d = insn->detail;
    if (!d) return 0;
    switch (arch) {
        case Arch::X86: case Arch::X64: {
            const cs_x86& a = d->x86;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == X86_OP_IMM) return (uint64_t)a.operands[i].imm;
            break;
        }
        case Arch::ARM64: {
            const cs_arm64& a = d->arm64;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == ARM64_OP_IMM) return (uint64_t)a.operands[i].imm;
            break;
        }
        case Arch::ARM: {
            const cs_arm& a = d->arm;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == ARM_OP_IMM) return (uint64_t)(uint32_t)a.operands[i].imm;
            break;
        }
        case Arch::MIPS: case Arch::MIPS64: {
            const cs_mips& a = d->mips;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == MIPS_OP_IMM) return (uint64_t)a.operands[i].imm;
            break;
        }
        case Arch::PPC: case Arch::PPC64: {
            const cs_ppc& a = d->ppc;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == PPC_OP_IMM) return (uint64_t)a.operands[i].imm;
            break;
        }
        case Arch::RISCV32: case Arch::RISCV64: {
            const cs_riscv& a = d->riscv;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == RISCV_OP_IMM) return (uint64_t)a.operands[i].imm;
            break;
        }
        case Arch::JVM: break;   // never decoded by Capstone (JvmDisassembler backend)
    }
    return 0;
}

static void appendHexBytes(std::string& out, const uint8_t* p, uint32_t n) {
    char tmp[4];
    for (uint32_t i = 0; i < n; ++i) {
        std::snprintf(tmp, sizeof(tmp), "%02X", p[i]);
        if (i) out.push_back(' ');
        out += tmp;
    }
}

CapstoneDisassembler::CapstoneDisassembler(Arch arch) : arch_(arch) { open(); }
CapstoneDisassembler::~CapstoneDisassembler() { close(); }

bool CapstoneDisassembler::open() {
    cs_arch a = CS_ARCH_X86;
    cs_mode m = CS_MODE_64;
    switch (arch_) {
        case Arch::X86:     a = CS_ARCH_X86;   m = CS_MODE_32;   break;
        case Arch::X64:     a = CS_ARCH_X86;   m = CS_MODE_64;   break;
        case Arch::ARM:     a = CS_ARCH_ARM;   m = CS_MODE_ARM;           break;
        case Arch::ARM64:   a = CS_ARCH_ARM64; m = CS_MODE_LITTLE_ENDIAN; break;
        case Arch::MIPS:    a = CS_ARCH_MIPS;  m = CS_MODE_MIPS32; break;
        case Arch::MIPS64:  a = CS_ARCH_MIPS;  m = CS_MODE_MIPS64; break;
        // Every image this tool can load is little-endian (the ELF loader requires
        // ei_data==1, the Mach-O loader requires the LE magic, PE is LE), so decode PPC
        // little-endian to match. Big-endian was hardcoded and mis-decoded every
        // loadable PPC binary (notably ppc64le ELF). (CS_MODE_LITTLE_ENDIAN == 0.)
        case Arch::PPC:     a = CS_ARCH_PPC;   m = (cs_mode)(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN); break;
        case Arch::PPC64:   a = CS_ARCH_PPC;   m = (cs_mode)(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN); break;
        case Arch::RISCV32: a = CS_ARCH_RISCV; m = CS_MODE_RISCV32; break;
        case Arch::RISCV64: a = CS_ARCH_RISCV; m = CS_MODE_RISCV64; break;
        case Arch::JVM:     ok_ = false; return false;   // routed to JvmDisassembler by the factory
    }
    csh h;
    if (cs_open(a, m, &h) != CS_ERR_OK) { ok_ = false; return false; }
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    // One reusable instruction buffer for cs_disasm_iter (avoids a per-instruction
    // malloc/free in the decode loops).
    cs_insn* scratch = cs_malloc(h);
    if (!scratch) { cs_close(&h); ok_ = false; return false; }
    handle_  = static_cast<uintptr_t>(h);
    scratch_ = scratch;
    ok_      = true;
    return true;
}

void CapstoneDisassembler::close() {
    if (ok_) {
        if (scratch_) { cs_free(static_cast<cs_insn*>(scratch_), 1); scratch_ = nullptr; }
        csh h = static_cast<csh>(handle_);
        cs_close(&h);
        ok_ = false;
    }
}

// Populate a UI Instruction from a decoded Capstone instruction. The static
// target of a relative branch/call is read from the immediate operand (Capstone
// resolves it to an absolute address) for every architecture, matching the Zydis
// backend so the CFG and function analyzer behave the same under either engine.
static void fillInstruction(const cs_insn* insn, Arch arch, Instruction& out) {
    out = Instruction{};
    out.address  = insn->address;
    out.length   = insn->size;
    appendHexBytes(out.bytes, insn->bytes, insn->size);
    out.mnemonic = insn->mnemonic;
    out.operands = insn->op_str;
    if (!insn->detail) return;

    for (int i = 0; i < insn->detail->groups_count; ++i) {
        uint8_t g = insn->detail->groups[i];
        if (g == CS_GRP_CALL) { out.isCall = true; out.isBranch = true; }
        if (g == CS_GRP_RET)  out.isRet = true; // returns from a call frame (step-over/out)
        if (g == CS_GRP_JUMP || g == CS_GRP_RET || g == CS_GRP_BRANCH_RELATIVE)
            out.isBranch = true;
    }

    // Capstone's generic CS_GRP_RET does not fire for several non-x86 returns (MIPS
    // `jr $ra`, PPC `blr`, ARM `bx lr` / `pop {pc}`, RISC-V `ret` / `jr ra`). Detect
    // them by mnemonic so CFG block boundaries and step-out classification are correct
    // under Capstone for every architecture.
    if (!out.isRet && arch != Arch::X86 && arch != Arch::X64) {
        std::string mn = insn->mnemonic; for (char& c : mn) c = (char)std::tolower((unsigned char)c);
        std::string op = insn->op_str;   for (char& c : op) c = (char)std::tolower((unsigned char)c);
        bool ret = false;
        switch (arch) {
            case Arch::ARM: case Arch::ARM64:
                ret = (mn == "ret") || (mn == "bx" && op == "lr") ||
                      ((mn == "pop" || mn.rfind("ldm", 0) == 0) && op.find("pc") != std::string::npos) ||
                      ((mn == "mov" || mn == "mov.w") && op.rfind("pc", 0) == 0 && op.find("lr") != std::string::npos);
                break;
            case Arch::MIPS: case Arch::MIPS64:
                ret = (mn == "jr" && (op == "$ra" || op == "ra"));
                break;
            case Arch::PPC: case Arch::PPC64:
                ret = (mn == "blr" || mn == "blrl" || mn == "bclr");
                break;
            case Arch::RISCV32: case Arch::RISCV64:
                ret = (mn == "ret") || (mn == "jr" && op == "ra") ||
                      (mn == "jalr" && op.find("zero") != std::string::npos && op.find("ra") != std::string::npos);
                break;
            default: break;
        }
        if (ret) { out.isRet = true; out.isBranch = true; }
    }

    if (out.isBranch || out.isCall)
        out.branchTarget = branchTargetFor(insn, arch);

    if (arch == Arch::X86 || arch == Arch::X64)
        out.isRepString = isRepStringInsn(insn);
}

bool CapstoneDisassembler::decodeOne(const uint8_t* data, size_t size,
                                     uint64_t va, Instruction& out) {
    if (!ok_ || !scratch_) return false;
    csh      h    = static_cast<csh>(handle_);
    cs_insn* insn = static_cast<cs_insn*>(scratch_);
    const uint8_t* code = data;
    size_t   left = size;
    uint64_t addr = va;
    if (!cs_disasm_iter(h, &code, &left, &addr, insn)) return false;
    fillInstruction(insn, arch_, out);
    return true;
}

std::vector<Instruction> CapstoneDisassembler::disassemble(const uint8_t* data, size_t size,
                                                          uint64_t va, size_t maxInstructions) {
    std::vector<Instruction> result;
    if (!ok_ || !scratch_) return result;
    csh      h    = static_cast<csh>(handle_);
    cs_insn* insn = static_cast<cs_insn*>(scratch_);

    const uint8_t* code = data;
    size_t   left = size;
    uint64_t addr = va;
    while (left > 0) {
        const uint8_t* at   = code; // decode position (unchanged by iter on failure)
        uint64_t       atVa = addr;
        if (cs_disasm_iter(h, &code, &left, &addr, insn)) {
            Instruction in;
            fillInstruction(insn, arch_, in);
            result.push_back(std::move(in));
        } else {
            // Emit a 1-byte "db" pseudo-op and resync so the stream never stalls.
            Instruction in;
            in.address  = atVa;
            in.length   = 1;
            appendHexBytes(in.bytes, at, 1);
            in.mnemonic = "db";
            char b[8]; std::snprintf(b, sizeof(b), "0x%02X", *at);
            in.operands = b;
            result.push_back(std::move(in));
            code = at + 1; --left; ++addr;
        }
        if (maxInstructions && result.size() >= maxInstructions) break;
    }
    return result;
}

} // namespace ds
