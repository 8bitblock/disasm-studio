#include "CapstoneDisassembler.h"
#include "../Core/AddressSpan.h"

#include <capstone/capstone.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <limits>
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

static bool prefixForToken(std::string_view token, InstructionPrefix& prefix) {
    if (token == "lock")     prefix = InstructionPrefix::Lock;
    else if (token == "rep") prefix = InstructionPrefix::Rep;
    else if (token == "repe" || token == "repz")
        prefix = InstructionPrefix::Repe;
    else if (token == "repne" || token == "repnz")
        prefix = InstructionPrefix::Repne;
    else if (token == "bnd")      prefix = InstructionPrefix::Bnd;
    else if (token == "xacquire") prefix = InstructionPrefix::XAcquire;
    else if (token == "xrelease") prefix = InstructionPrefix::XRelease;
    else if (token == "notrack")  prefix = InstructionPrefix::NoTrack;
    else return false;
    return true;
}

// Capstone represents semantic prefixes as leading mnemonic tokens on x86.
// Normalize those tokens into metadata while retaining a prefix-free mnemonic.
static void normalizeMnemonicPrefixes(Instruction& out) {
    for (;;) {
        const size_t first = out.mnemonic.find_first_not_of(' ');
        if (first == std::string::npos) { out.mnemonic.clear(); return; }
        const size_t end = out.mnemonic.find(' ', first);
        const std::string_view token(out.mnemonic.data() + first,
                                     (end == std::string::npos ? out.mnemonic.size() : end) - first);
        InstructionPrefix prefix{};
        if (!prefixForToken(token, prefix)) {
            if (first) out.mnemonic.erase(0, first);
            return;
        }
        out.prefixes.push_back(prefix);
        if (end == std::string::npos) { out.mnemonic.clear(); return; }
        out.mnemonic.erase(0, out.mnemonic.find_first_not_of(' ', end));
    }
}

static std::string normalizedRegisterName(csh handle, unsigned reg) {
    if (!reg) return {};
    const char* raw = cs_reg_name(handle, reg);
    if (!raw || !*raw) return {};
    std::string name(raw);
    if (!name.empty() && name.front() == '$') name.erase(name.begin());
    for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return name;
}

static void addRegister(std::vector<std::string>& registers, std::string name) {
    if (name.empty() || std::find(registers.begin(), registers.end(), name) != registers.end()) return;
    registers.push_back(std::move(name));
}

static OperandAccess capstoneAccess(uint8_t access) {
    const bool read = (access & CS_AC_READ) != 0;
    const bool write = (access & CS_AC_WRITE) != 0;
    return read && write ? OperandAccess::ReadWrite
         : read          ? OperandAccess::Read
         : write         ? OperandAccess::Write
                         : OperandAccess::None;
}

static OperandAccess registerAccess(const Instruction& out, const std::string& name) {
    const bool read = std::find(out.registersRead.begin(), out.registersRead.end(), name) !=
                      out.registersRead.end();
    const bool write = std::find(out.registersWritten.begin(), out.registersWritten.end(), name) !=
                       out.registersWritten.end();
    return read && write ? OperandAccess::ReadWrite
         : read          ? OperandAccess::Read
         : write         ? OperandAccess::Write
                         : OperandAccess::None;
}

static void fillRegisterSets(csh handle, const cs_insn* insn, Instruction& out) {
    cs_regs read{}, written{};
    uint8_t readCount = 0, writtenCount = 0;
    if (cs_regs_access(handle, insn, read, &readCount, written, &writtenCount) != CS_ERR_OK)
        return;
    for (uint8_t i = 0; i < readCount; ++i)
        addRegister(out.registersRead, normalizedRegisterName(handle, read[i]));
    for (uint8_t i = 0; i < writtenCount; ++i)
        addRegister(out.registersWritten, normalizedRegisterName(handle, written[i]));
    std::sort(out.registersRead.begin(), out.registersRead.end());
    std::sort(out.registersWritten.begin(), out.registersWritten.end());
}

static void fillX86Flags(const cs_x86& x86, Instruction& out) {
    const uint64_t f = x86.eflags;
    auto read = [&](uint64_t mask, SemanticFlag flag) {
        if (f & mask) out.flagsRead |= SemanticFlagBit(flag);
    };
    auto written = [&](uint64_t mask, SemanticFlag flag) {
        if (f & mask) out.flagsWritten |= SemanticFlagBit(flag);
    };
    read(X86_EFLAGS_TEST_CF, SemanticFlag::Carry);
    read(X86_EFLAGS_TEST_PF, SemanticFlag::Parity);
    read(X86_EFLAGS_TEST_AF, SemanticFlag::AuxCarry);
    read(X86_EFLAGS_TEST_ZF, SemanticFlag::Zero);
    read(X86_EFLAGS_TEST_SF, SemanticFlag::Sign);
    read(X86_EFLAGS_TEST_TF, SemanticFlag::Trap);
    read(X86_EFLAGS_TEST_IF, SemanticFlag::Interrupt);
    read(X86_EFLAGS_TEST_DF, SemanticFlag::Direction);
    read(X86_EFLAGS_TEST_OF, SemanticFlag::Overflow);
    written(X86_EFLAGS_MODIFY_CF | X86_EFLAGS_SET_CF | X86_EFLAGS_RESET_CF |
            X86_EFLAGS_UNDEFINED_CF, SemanticFlag::Carry);
    written(X86_EFLAGS_MODIFY_PF | X86_EFLAGS_SET_PF | X86_EFLAGS_RESET_PF |
            X86_EFLAGS_UNDEFINED_PF, SemanticFlag::Parity);
    written(X86_EFLAGS_MODIFY_AF | X86_EFLAGS_SET_AF | X86_EFLAGS_RESET_AF |
            X86_EFLAGS_UNDEFINED_AF, SemanticFlag::AuxCarry);
    written(X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_SET_ZF | X86_EFLAGS_RESET_ZF |
            X86_EFLAGS_UNDEFINED_ZF, SemanticFlag::Zero);
    written(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_SET_SF | X86_EFLAGS_RESET_SF |
            X86_EFLAGS_UNDEFINED_SF, SemanticFlag::Sign);
    written(X86_EFLAGS_MODIFY_TF | X86_EFLAGS_RESET_TF, SemanticFlag::Trap);
    written(X86_EFLAGS_MODIFY_IF | X86_EFLAGS_SET_IF | X86_EFLAGS_RESET_IF,
            SemanticFlag::Interrupt);
    written(X86_EFLAGS_MODIFY_DF | X86_EFLAGS_SET_DF | X86_EFLAGS_RESET_DF,
            SemanticFlag::Direction);
    written(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_SET_OF | X86_EFLAGS_RESET_OF |
            X86_EFLAGS_UNDEFINED_OF, SemanticFlag::Overflow);
}

// Extract a direct branch/call target. Capstone resolves immediates to absolute
// addresses for every architecture; x86 is recomputed from its encoded signed
// displacement so modular next-IP arithmetic cannot wrap across UINT64_MAX.
// The result feeds CFG, xrefs, call graph, and goto navigation.
static int branchTargetOperandIndex(const cs_insn* insn, Arch arch) {
    if (!insn->detail) return -1;
    int result = -1;
    switch (arch) {
        case Arch::X86_16: case Arch::X86: case Arch::X64: {
            const cs_x86& a = insn->detail->x86;
            unsigned count = 0;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == X86_OP_IMM) { result = i; ++count; }
            return count == 1 ? result : -1;
        }
        case Arch::ARM: case Arch::THUMB: {
            const cs_arm& a = insn->detail->arm;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == ARM_OP_IMM) result = i;
            return result;
        }
        case Arch::ARM64: {
            const cs_arm64& a = insn->detail->arm64;
            // TBZ/TBNZ contain both a bit number and a target.  The branch
            // target is the final immediate, as it is for B/BL/CBZ/CBNZ.
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == ARM64_OP_IMM) result = i;
            return result;
        }
        case Arch::MIPS: case Arch::MIPS64: {
            const cs_mips& a = insn->detail->mips;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == MIPS_OP_IMM) result = i;
            return result;
        }
        case Arch::PPC: case Arch::PPC64: {
            const cs_ppc& a = insn->detail->ppc;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == PPC_OP_IMM) result = i;
            return result;
        }
        case Arch::RISCV32: case Arch::RISCV64: {
            const cs_riscv& a = insn->detail->riscv;
            for (uint8_t i = 0; i < a.op_count; ++i)
                if (a.operands[i].type == RISCV_OP_IMM) result = i;
            return result;
        }
        case Arch::JVM: return -1;
        case Arch::GML: return -1;
    }
    return -1;
}

static bool branchTargetFor(const cs_insn* insn, Arch arch, uint64_t& target) {
    const cs_detail* d = insn->detail;
    if (!d) return false;
    auto crossesUint64Boundary = [&](uint64_t candidate) {
        // Every direct displacement in the supported ISAs is at most 32 bits.
        // A result jumping between the bottom and top 4-GiB bands therefore
        // came from modular arithmetic, not a representable flat-VA target.
        constexpr uint64_t kMaxEncodedReach =
            static_cast<uint64_t>((std::numeric_limits<uint32_t>::max)()) + 16;
        constexpr uint64_t kMax = (std::numeric_limits<uint64_t>::max)();
        return (insn->address > kMax - kMaxEncodedReach && candidate < kMaxEncodedReach) ||
               (insn->address < kMaxEncodedReach && candidate > kMax - kMaxEncodedReach);
    };
    switch (arch) {
        case Arch::X86_16: case Arch::X86: case Arch::X64: {
            const cs_x86& a = d->x86;
            const int targetIndex = branchTargetOperandIndex(insn, arch);
            if (targetIndex < 0) break;
            const cs_x86_op* immediate = &a.operands[targetIndex];

            // Normal direct x86 calls/jumps encode a signed PC-relative
            // immediate. Recompute it with checked flat-address arithmetic;
            // Capstone otherwise applies uint64_t modular addition at the top.
            const uint8_t width = a.encoding.imm_size;
            const uint8_t offset = a.encoding.imm_offset;
            if ((width == 1 || width == 2 || width == 4) &&
                offset <= insn->size && width <= insn->size - offset) {
                uint32_t raw = 0;
                for (uint8_t i = 0; i < width; ++i)
                    raw |= static_cast<uint32_t>(insn->bytes[offset + i]) << (i * 8);
                int64_t displacement = 0;
                if (width == 1) displacement = static_cast<int8_t>(raw);
                else if (width == 2) displacement = static_cast<int16_t>(raw);
                else displacement = static_cast<int32_t>(raw);
                if (arch == Arch::X86_16 && width <= 2) {
                    const uint16_t nextIp = static_cast<uint16_t>(
                        static_cast<uint16_t>(insn->address) + insn->size);
                    const uint16_t targetIp = static_cast<uint16_t>(
                        static_cast<int32_t>(nextIp) + static_cast<int32_t>(displacement));
                    target = (insn->address & ~uint64_t{0xFFFF}) | targetIp;
                    return true;
                }
                uint64_t next = 0;
                return CheckedAddressAdd(insn->address, insn->size, next) &&
                       CheckedAddressAddSigned(next, displacement, target);
            }
            target = static_cast<uint64_t>(immediate->imm);
            return !crossesUint64Boundary(target);
        }
        case Arch::ARM64: {
            const cs_arm64& a = d->arm64;
            const int i = branchTargetOperandIndex(insn, arch);
            if (i >= 0) {
                target = static_cast<uint64_t>(a.operands[i].imm);
                return !crossesUint64Boundary(target);
            }
            break;
        }
        case Arch::ARM: case Arch::THUMB: {
            const cs_arm& a = d->arm;
            const int i = branchTargetOperandIndex(insn, arch);
            if (i >= 0) {
                    // Capstone 4 exposes the A32/Thumb immediate through an
                    // int32_t field even though ARM's architectural address
                    // space is unsigned.  A valid branch into the upper half
                    // (for example firmware mapped at 0x80000000) therefore
                    // arrives sign-extended unless it is normalized first.
                target = static_cast<uint64_t>(
                    static_cast<uint32_t>(a.operands[i].imm));
                return !crossesUint64Boundary(target);
            }
            break;
        }
        case Arch::MIPS: case Arch::MIPS64: {
            const cs_mips& a = d->mips;
            const int i = branchTargetOperandIndex(insn, arch);
            if (i >= 0) {
                target = static_cast<uint64_t>(a.operands[i].imm);
                return !crossesUint64Boundary(target);
            }
            break;
        }
        case Arch::PPC: case Arch::PPC64: {
            const cs_ppc& a = d->ppc;
            const int i = branchTargetOperandIndex(insn, arch);
            if (i >= 0) {
                target = static_cast<uint64_t>(a.operands[i].imm);
                return !crossesUint64Boundary(target);
            }
            break;
        }
        case Arch::RISCV32: case Arch::RISCV64: {
            const cs_riscv& a = d->riscv;
            const int i = branchTargetOperandIndex(insn, arch);
            if (i >= 0) {
                target = static_cast<uint64_t>(a.operands[i].imm);
                return !crossesUint64Boundary(target);
            }
            break;
        }
        case Arch::JVM: break;   // never decoded by Capstone (JvmDisassembler backend)
        case Arch::GML: break;   // dedicated GameMaker decoder
    }
    return false;
}

static void appendHexBytes(std::string& out, const uint8_t* p, uint32_t n) {
    char tmp[4];
    for (uint32_t i = 0; i < n; ++i) {
        std::snprintf(tmp, sizeof(tmp), "%02X", p[i]);
        if (i) out.push_back(' ');
        out += tmp;
    }
}

CapstoneDisassembler::CapstoneDisassembler(Arch arch) : arch_(arch) {
    config_.engine = Engine::Capstone;
    config_.arch = arch;
    open();
}

CapstoneDisassembler::CapstoneDisassembler(const DecoderConfig& config)
    : config_(config), arch_(config.arch) {
    open();
}
CapstoneDisassembler::~CapstoneDisassembler() { close(); }

bool CapstoneDisassembler::open() {
    close();
    error_.clear();
    if (config_.byteOrder == ByteOrder::Big && ArchIsX86(arch_)) {
        error_ = "Capstone does not support big-endian x86 decoding";
        return false;
    }
    cs_arch a = CS_ARCH_X86;
    cs_mode m = CS_MODE_64;
    const cs_mode endian = config_.byteOrder == ByteOrder::Big
                         ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    auto addMode = [](cs_mode lhs, cs_mode rhs) {
        return static_cast<cs_mode>(static_cast<unsigned>(lhs) |
                                    static_cast<unsigned>(rhs));
    };
    switch (arch_) {
        case Arch::X86_16:  a = CS_ARCH_X86;   m = CS_MODE_16;   break;
        case Arch::X86:     a = CS_ARCH_X86;   m = CS_MODE_32;   break;
        case Arch::X64:     a = CS_ARCH_X86;   m = CS_MODE_64;   break;
        case Arch::ARM:
            a = CS_ARCH_ARM; m = addMode(CS_MODE_ARM, endian);
            if (config_.features.armV8) m = addMode(m, CS_MODE_V8);
            if (config_.features.armMClass) m = addMode(m, CS_MODE_MCLASS);
            break;
        case Arch::THUMB:
            a = CS_ARCH_ARM; m = addMode(CS_MODE_THUMB, endian);
            if (config_.features.armV8) m = addMode(m, CS_MODE_V8);
            if (config_.features.armMClass) m = addMode(m, CS_MODE_MCLASS);
            break;
        case Arch::ARM64:   a = CS_ARCH_ARM64; m = endian; break;
        case Arch::MIPS:
            a = CS_ARCH_MIPS; m = addMode(CS_MODE_MIPS32, endian);
            if (config_.features.mipsMicro) m = addMode(m, CS_MODE_MICRO);
            break;
        case Arch::MIPS64:
            a = CS_ARCH_MIPS; m = addMode(CS_MODE_MIPS64, endian);
            if (config_.features.mipsMicro) m = addMode(m, CS_MODE_MICRO);
            break;
        case Arch::PPC:     a = CS_ARCH_PPC; m = addMode(CS_MODE_32, endian); break;
        case Arch::PPC64:   a = CS_ARCH_PPC; m = addMode(CS_MODE_64, endian); break;
        case Arch::RISCV32:
            a = CS_ARCH_RISCV; m = addMode(CS_MODE_RISCV32, endian);
            if (config_.features.riscvCompressed) m = addMode(m, CS_MODE_RISCVC);
            break;
        case Arch::RISCV64:
            a = CS_ARCH_RISCV; m = addMode(CS_MODE_RISCV64, endian);
            if (config_.features.riscvCompressed) m = addMode(m, CS_MODE_RISCVC);
            break;
        case Arch::JVM:
            error_ = "JVM bytecode is decoded by JvmDisassembler";
            return false;
        case Arch::GML:
            error_ = "GML bytecode is decoded by GmlDisassembler";
            return false;
    }
    csh h = 0;
    const cs_err openError = cs_open(a, m, &h);
    if (openError != CS_ERR_OK) {
        error_ = std::string("Capstone initialization failed: ") + cs_strerror(openError);
        return false;
    }
    const cs_err detailError = cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    if (detailError != CS_ERR_OK) {
        error_ = std::string("Capstone detail mode failed: ") + cs_strerror(detailError);
        cs_close(&h);
        return false;
    }
    // One reusable instruction buffer for cs_disasm_iter (avoids a per-instruction
    // malloc/free in the decode loops).
    cs_insn* scratch = cs_malloc(h);
    if (!scratch) {
        error_ = "Capstone could not allocate its decode instruction";
        cs_close(&h);
        return false;
    }
    handle_  = static_cast<uintptr_t>(h);
    scratch_ = scratch;
    ok_      = true;
    return true;
}

void CapstoneDisassembler::close() {
    if (scratch_) {
        cs_free(static_cast<cs_insn*>(scratch_), 1);
        scratch_ = nullptr;
    }
    if (handle_) {
        csh h = static_cast<csh>(handle_);
        cs_close(&h);
        handle_ = 0;
    }
    ok_ = false;
}

static bool unconditionalTransfer(const cs_insn* insn, Arch arch) {
    switch (arch) {
        case Arch::X86_16: case Arch::X86: case Arch::X64:
            return insn->id == X86_INS_JMP || insn->id == X86_INS_LJMP;
        case Arch::ARM: case Arch::THUMB: {
            const cs_arm& arm = insn->detail->arm;
            return (insn->id == ARM_INS_B &&
                    (arm.cc == ARM_CC_AL || arm.cc == ARM_CC_INVALID)) ||
                   insn->id == ARM_INS_BX || insn->id == ARM_INS_BXJ;
        }
        case Arch::ARM64: {
            const cs_arm64& arm = insn->detail->arm64;
            return (insn->id == ARM64_INS_B &&
                    (arm.cc == ARM64_CC_AL || arm.cc == ARM64_CC_INVALID)) ||
                   insn->id == ARM64_INS_BR;
        }
        case Arch::MIPS: case Arch::MIPS64:
            return insn->id == MIPS_INS_J || insn->id == MIPS_INS_JR ||
                   insn->id == MIPS_INS_B;
        case Arch::PPC: case Arch::PPC64:
            return insn->id == PPC_INS_B || insn->id == PPC_INS_BA ||
                   insn->id == PPC_INS_BCTR;
        case Arch::RISCV32: case Arch::RISCV64:
            return insn->id == RISCV_INS_JAL || insn->id == RISCV_INS_JALR ||
                   insn->id == RISCV_INS_C_J || insn->id == RISCV_INS_C_JR;
        case Arch::JVM:
        case Arch::GML:
            return false;
    }
    return false;
}

static void fillTypedOperands(csh handle, const cs_insn* insn, Arch arch,
                              Instruction& out) {
    fillRegisterSets(handle, insn, out);
    const int flowTargetOperand = (out.isBranch || out.isCall) && !out.isRet
                                ? branchTargetOperandIndex(insn, arch) : -1;
    auto reg = [&](unsigned id, uint16_t width, OperandAccess access) {
        TypedOperand typed;
        typed.kind = OperandKind::Register;
        typed.registerName = normalizedRegisterName(handle, id);
        typed.widthBits = width;
        typed.access = access == OperandAccess::None
                     ? registerAccess(out, typed.registerName) : access;
        out.typedOperands.push_back(std::move(typed));
    };
    auto imm = [&](int64_t value, uint16_t width, bool pcRelative) {
        TypedOperand typed;
        typed.kind = OperandKind::Immediate;
        typed.access = OperandAccess::Read;
        typed.widthBits = width;
        typed.immediate = static_cast<uint64_t>(value);
        typed.immediateSigned = value < 0;
        typed.pcRelative = pcRelative;
        out.typedOperands.push_back(std::move(typed));
    };
    auto mem = [&](unsigned segment, unsigned base, unsigned index, int scale,
                   int64_t displacement, uint16_t width, OperandAccess access) {
        TypedOperand typed;
        typed.kind = OperandKind::Memory;
        typed.access = access;
        typed.widthBits = width;
        typed.segmentRegister = normalizedRegisterName(handle, segment);
        typed.baseRegister = normalizedRegisterName(handle, base);
        typed.indexRegister = normalizedRegisterName(handle, index);
        typed.scale = scale;
        typed.displacement = displacement;
        typed.displacementValid = true;
        typed.pcRelative = typed.baseRegister == "pc" || typed.baseRegister == "eip" ||
                           typed.baseRegister == "rip";
        out.typedOperands.push_back(std::move(typed));
    };

    switch (arch) {
        case Arch::X86_16: case Arch::X86: case Arch::X64: {
            const cs_x86& x86 = insn->detail->x86;
            fillX86Flags(x86, out);
            for (uint8_t i = 0; i < x86.op_count; ++i) {
                const cs_x86_op& op = x86.operands[i];
                if (op.type == X86_OP_REG)
                    reg(op.reg, static_cast<uint16_t>(op.size) * 8, capstoneAccess(op.access));
                else if (op.type == X86_OP_IMM)
                    imm(op.imm, static_cast<uint16_t>(op.size) * 8,
                        i == flowTargetOperand);
                else if (op.type == X86_OP_MEM)
                    mem(op.mem.segment, op.mem.base, op.mem.index, op.mem.scale, op.mem.disp,
                        static_cast<uint16_t>(op.size) * 8, capstoneAccess(op.access));
            }
            break;
        }
        case Arch::ARM: case Arch::THUMB: {
            const cs_arm& arm = insn->detail->arm;
            if (arm.cc != ARM_CC_AL && arm.cc != ARM_CC_INVALID)
                out.flagsRead |= SemanticFlagBit(SemanticFlag::Condition);
            if (arm.update_flags)
                out.flagsWritten |= SemanticFlagBit(SemanticFlag::Carry) |
                                    SemanticFlagBit(SemanticFlag::Zero) |
                                    SemanticFlagBit(SemanticFlag::Sign) |
                                    SemanticFlagBit(SemanticFlag::Overflow);
            for (uint8_t i = 0; i < arm.op_count; ++i) {
                const cs_arm_op& op = arm.operands[i];
                if (op.type == ARM_OP_REG)
                    reg(static_cast<unsigned>(op.reg), 0, capstoneAccess(op.access));
                else if (op.type == ARM_OP_IMM || op.type == ARM_OP_CIMM || op.type == ARM_OP_PIMM)
                    imm(op.imm, 0, i == flowTargetOperand);
                else if (op.type == ARM_OP_MEM)
                    mem(0, op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, 0,
                        capstoneAccess(op.access));
            }
            break;
        }
        case Arch::ARM64: {
            const cs_arm64& arm = insn->detail->arm64;
            if (arm.cc != ARM64_CC_AL && arm.cc != ARM64_CC_INVALID)
                out.flagsRead |= SemanticFlagBit(SemanticFlag::Condition);
            if (arm.update_flags)
                out.flagsWritten |= SemanticFlagBit(SemanticFlag::Carry) |
                                    SemanticFlagBit(SemanticFlag::Zero) |
                                    SemanticFlagBit(SemanticFlag::Sign) |
                                    SemanticFlagBit(SemanticFlag::Overflow);
            for (uint8_t i = 0; i < arm.op_count; ++i) {
                const cs_arm64_op& op = arm.operands[i];
                if (op.type == ARM64_OP_REG)
                    reg(op.reg, 0, capstoneAccess(op.access));
                else if (op.type == ARM64_OP_IMM || op.type == ARM64_OP_CIMM)
                    imm(op.imm, 0, i == flowTargetOperand);
                else if (op.type == ARM64_OP_MEM)
                    mem(0, op.mem.base, op.mem.index, 0, op.mem.disp, 0,
                        capstoneAccess(op.access));
            }
            break;
        }
        case Arch::MIPS: case Arch::MIPS64: {
            const cs_mips& mips = insn->detail->mips;
            for (uint8_t i = 0; i < mips.op_count; ++i) {
                const cs_mips_op& op = mips.operands[i];
                if (op.type == MIPS_OP_REG) reg(op.reg, 0, OperandAccess::None);
                else if (op.type == MIPS_OP_IMM) imm(op.imm, 0, i == flowTargetOperand);
                else if (op.type == MIPS_OP_MEM)
                    mem(0, op.mem.base, 0, 0, op.mem.disp, 0, OperandAccess::None);
            }
            break;
        }
        case Arch::PPC: case Arch::PPC64: {
            const cs_ppc& ppc = insn->detail->ppc;
            if (ppc.bc != PPC_BC_INVALID)
                out.flagsRead |= SemanticFlagBit(SemanticFlag::Condition);
            if (ppc.update_cr0)
                out.flagsWritten |= SemanticFlagBit(SemanticFlag::Condition);
            for (uint8_t i = 0; i < ppc.op_count; ++i) {
                const cs_ppc_op& op = ppc.operands[i];
                if (op.type == PPC_OP_REG) reg(op.reg, 0, OperandAccess::None);
                else if (op.type == PPC_OP_IMM) imm(op.imm, 0, i == flowTargetOperand);
                else if (op.type == PPC_OP_MEM)
                    mem(0, op.mem.base, 0, 0, op.mem.disp, 0, OperandAccess::None);
            }
            break;
        }
        case Arch::RISCV32: case Arch::RISCV64: {
            const cs_riscv& riscv = insn->detail->riscv;
            for (uint8_t i = 0; i < riscv.op_count; ++i) {
                const cs_riscv_op& op = riscv.operands[i];
                if (op.type == RISCV_OP_REG) reg(op.reg, 0, OperandAccess::None);
                else if (op.type == RISCV_OP_IMM) imm(op.imm, 0, i == flowTargetOperand);
                else if (op.type == RISCV_OP_MEM)
                    mem(0, op.mem.base, 0, 0, op.mem.disp, 0, OperandAccess::None);
            }
            break;
        }
        case Arch::JVM:
        case Arch::GML:
            break;
    }
}

static bool isLegacyX86Prefix(uint8_t byte) {
    switch (byte) {
        case 0xF0: case 0xF2: case 0xF3:
        case 0x2E: case 0x36: case 0x3E: case 0x26:
        case 0x64: case 0x65: case 0x66: case 0x67:
            return true;
        default:
            return false;
    }
}

static void fillX86FarTarget(const cs_insn* insn, Arch arch, Instruction& out) {
    if (arch != Arch::X86_16 || !insn->size) return;
    size_t pos = 0;
    bool offset32 = false;
    while (pos < insn->size && isLegacyX86Prefix(insn->bytes[pos])) {
        if (insn->bytes[pos] == 0x66) offset32 = true;
        ++pos;
    }
    if (pos >= insn->size || (insn->bytes[pos] != 0x9A && insn->bytes[pos] != 0xEA))
        return;
    ++pos;
    const size_t offsetBytes = offset32 ? 4 : 2;
    if (pos > insn->size || offsetBytes + 2 > insn->size - pos) return;
    uint32_t offset = 0;
    for (size_t i = 0; i < offsetBytes; ++i)
        offset |= static_cast<uint32_t>(insn->bytes[pos + i]) << (i * 8);
    pos += offsetBytes;
    const uint16_t segment = static_cast<uint16_t>(insn->bytes[pos]) |
                             static_cast<uint16_t>(insn->bytes[pos + 1] << 8);
    out.farTarget.valid = true;
    out.farTarget.segment = segment;
    out.farTarget.offset = offset;
    out.farTarget.offsetBits = static_cast<uint8_t>(offsetBytes * 8);
    out.farTarget.linearAddress = (static_cast<uint64_t>(segment) << 4) + offset;
    out.farTarget.linearAddressValid = true;
}

// Populate a UI Instruction from a decoded Capstone instruction. The static
// target of a relative branch/call is read from the immediate operand (Capstone
// resolves it to an absolute address) for every architecture, matching the Zydis
// backend so the CFG and function analyzer behave the same under either engine.
static void fillInstruction(csh handle, const cs_insn* insn, Arch arch, Instruction& out) {
    out = Instruction{};
    out.address  = insn->address;
    out.length   = insn->size;
    appendHexBytes(out.bytes, insn->bytes, insn->size);
    out.mnemonic = insn->mnemonic;
    out.operands = insn->op_str;
    if (ArchIsX86(arch)) normalizeMnemonicPrefixes(out);
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
    if (!out.isRet && !ArchIsX86(arch)) {
        std::string mn = insn->mnemonic; for (char& c : mn) c = (char)std::tolower((unsigned char)c);
        std::string op = insn->op_str;   for (char& c : op) c = (char)std::tolower((unsigned char)c);
        bool ret = false;
        switch (arch) {
            case Arch::ARM: case Arch::THUMB: case Arch::ARM64:
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

    if ((out.isBranch || out.isCall) && !out.isRet)
        out.branchTargetValid = branchTargetFor(insn, arch, out.branchTarget);

    fillX86FarTarget(insn, arch, out);

    if (ArchIsX86(arch))
        out.isRepString = isRepStringInsn(insn);

    fillTypedOperands(handle, insn, arch, out);
    if (out.isCall)
        out.flow.kind = (out.branchTargetValid || out.farTarget.valid)
                      ? FlowKind::DirectCall : FlowKind::IndirectCall;
    else if (out.isRet)
        out.flow.kind = FlowKind::Return;
    else if (out.isBranch) {
        if (unconditionalTransfer(insn, arch))
            out.flow.kind = (out.branchTargetValid || out.farTarget.valid)
                          ? FlowKind::UnconditionalBranch : FlowKind::IndirectBranch;
        else
            out.flow.kind = FlowKind::ConditionalBranch;
    }
    out.flow.directTarget = out.branchTarget;
    out.flow.directTargetValid = out.branchTargetValid;
    if ((arch == Arch::MIPS || arch == Arch::MIPS64) &&
        out.flow.kind != FlowKind::None)
        out.flow.delaySlots = 1;
}

bool CapstoneDisassembler::decodeOne(const uint8_t* data, size_t size,
                                     uint64_t va, Instruction& out) {
    if (!data || !ok_ || !scratch_) return false;
    size = ClampAddressableBytes(va, size);
    if (!size) return false;
    csh      h    = static_cast<csh>(handle_);
    cs_insn* insn = static_cast<cs_insn*>(scratch_);
    const uint8_t* code = data;
    size_t   left = size;
    uint64_t addr = va;
    if (!cs_disasm_iter(h, &code, &left, &addr, insn)) return false;
    fillInstruction(h, insn, arch_, out);
    out.address = va; // normalize the backend contract even at the top of VA space
    return true;
}

std::vector<Instruction> CapstoneDisassembler::disassemble(const uint8_t* data, size_t size,
                                                          uint64_t va, size_t maxInstructions) {
    std::vector<Instruction> result;
    if (!data || !ok_ || !scratch_) return result;
    size = ClampAddressableBytes(va, size);
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
            fillInstruction(h, insn, arch_, in);
            in.address = atVa;
            result.push_back(std::move(in));
        } else {
            // Preserve the ISA's natural decode alignment after malformed data:
            // A32/AArch64 consume one word and Thumb one halfword. Variable-width
            // modes retain byte resynchronization.
            const size_t step = std::min<size_t>(left, invalidDecodeWidth());
            Instruction in;
            in.address  = atVa;
            in.length   = static_cast<uint32_t>(step);
            appendHexBytes(in.bytes, at, static_cast<uint32_t>(step));
            in.mnemonic = "db";
            char b[8];
            for (size_t k = 0; k < step; ++k) {
                if (k) in.operands += ", ";
                std::snprintf(b, sizeof(b), "0x%02X", at[k]);
                in.operands += b;
            }
            result.push_back(std::move(in));
            code = at + step;
            left -= step;
            if (left) {
                if (!CheckedAddressAdd(atVa, static_cast<uint64_t>(step), addr)) break;
            }
        }
        if (maxInstructions && result.size() >= maxInstructions) break;
    }
    return result;
}

} // namespace ds
