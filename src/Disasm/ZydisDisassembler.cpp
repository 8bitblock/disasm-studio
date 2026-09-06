#include "ZydisDisassembler.h"
#include "../Core/AddressSpan.h"

#include <Zydis/Zydis.h>
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace ds {

static void appendHexBytes(std::string& out, const uint8_t* p, uint32_t n) {
    char tmp[4];
    for (uint32_t i = 0; i < n; ++i) {
        std::snprintf(tmp, sizeof(tmp), "%02X", p[i]);
        if (i) out.push_back(' ');
        out += tmp;
    }
}

static std::string normalizedRegisterName(ZydisRegister reg) {
    if (reg == ZYDIS_REGISTER_NONE) return {};
    const char* raw = ZydisRegisterGetString(reg);
    if (!raw) return {};
    std::string name(raw);
    for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return name;
}

static void addRegister(std::vector<std::string>& registers, const std::string& name) {
    if (!name.empty()) registers.push_back(name);
}

static void normalizeRegisterSet(std::vector<std::string>& registers) {
    std::sort(registers.begin(), registers.end());
    registers.erase(std::unique(registers.begin(), registers.end()), registers.end());
}

static OperandAccess operandAccess(ZydisOperandActions actions) {
    const bool reads = (actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
    const bool writes = (actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
    if (reads && writes) return OperandAccess::ReadWrite;
    if (reads) return OperandAccess::Read;
    if (writes) return OperandAccess::Write;
    return OperandAccess::None;
}

static uint64_t semanticFlagMask(ZydisAccessedFlagsMask mask) {
    uint64_t result = 0;
    if (mask & ZYDIS_CPUFLAG_CF)   result |= SemanticFlagBit(SemanticFlag::Carry);
    if (mask & ZYDIS_CPUFLAG_PF)   result |= SemanticFlagBit(SemanticFlag::Parity);
    if (mask & ZYDIS_CPUFLAG_AF)   result |= SemanticFlagBit(SemanticFlag::AuxCarry);
    if (mask & ZYDIS_CPUFLAG_ZF)   result |= SemanticFlagBit(SemanticFlag::Zero);
    if (mask & ZYDIS_CPUFLAG_SF)   result |= SemanticFlagBit(SemanticFlag::Sign);
    if (mask & ZYDIS_CPUFLAG_TF)   result |= SemanticFlagBit(SemanticFlag::Trap);
    if (mask & ZYDIS_CPUFLAG_IF)   result |= SemanticFlagBit(SemanticFlag::Interrupt);
    if (mask & ZYDIS_CPUFLAG_DF)   result |= SemanticFlagBit(SemanticFlag::Direction);
    if (mask & ZYDIS_CPUFLAG_OF)   result |= SemanticFlagBit(SemanticFlag::Overflow);
    if (mask & ZYDIS_CPUFLAG_NT)   result |= SemanticFlagBit(SemanticFlag::NestedTask);
    if (mask & ZYDIS_CPUFLAG_RF)   result |= SemanticFlagBit(SemanticFlag::Resume);
    if (mask & ZYDIS_CPUFLAG_AC)   result |= SemanticFlagBit(SemanticFlag::Alignment);
    if (mask & ZYDIS_CPUFLAG_VM)   result |= SemanticFlagBit(SemanticFlag::Virtual8086);
    if (mask & ZYDIS_CPUFLAG_VIF)  result |= SemanticFlagBit(SemanticFlag::VirtualInt);
    if (mask & ZYDIS_CPUFLAG_VIP)  result |= SemanticFlagBit(SemanticFlag::VirtualPend);
    if (mask & ZYDIS_CPUFLAG_ID)   result |= SemanticFlagBit(SemanticFlag::Id);
    return result;
}

static bool zydisPrefixForToken(std::string_view token, InstructionPrefix& prefix) {
    if (token == "lock")     prefix = InstructionPrefix::Lock;
    else if (token == "rep") prefix = InstructionPrefix::Rep;
    else if (token == "repe" || token == "repz") prefix = InstructionPrefix::Repe;
    else if (token == "repne" || token == "repnz") prefix = InstructionPrefix::Repne;
    else if (token == "bnd")      prefix = InstructionPrefix::Bnd;
    else if (token == "xacquire") prefix = InstructionPrefix::XAcquire;
    else if (token == "xrelease") prefix = InstructionPrefix::XRelease;
    else if (token == "notrack")  prefix = InstructionPrefix::NoTrack;
    else return false;
    return true;
}

static void addPrefix(Instruction& out, InstructionPrefix prefix) {
    if (std::find(out.prefixes.begin(), out.prefixes.end(), prefix) == out.prefixes.end())
        out.prefixes.push_back(prefix);
}

static void fillPrefixes(const ZydisDecodedInstruction& insn,
                         std::string_view formattedPrefix, Instruction& out) {
    size_t pos = 0;
    while (pos < formattedPrefix.size()) {
        pos = formattedPrefix.find_first_not_of(' ', pos);
        if (pos == std::string_view::npos) break;
        const size_t end = formattedPrefix.find(' ', pos);
        const std::string_view token = formattedPrefix.substr(
            pos, end == std::string_view::npos ? formattedPrefix.size() - pos : end - pos);
        InstructionPrefix prefix{};
        if (zydisPrefixForToken(token, prefix)) addPrefix(out, prefix);
        if (end == std::string_view::npos) break;
        pos = end + 1;
    }

    // Attribute fallbacks make prefix semantics independent of formatter
    // spelling/version while the parsed tokens above retain display order.
    if (insn.attributes & ZYDIS_ATTRIB_HAS_XACQUIRE) addPrefix(out, InstructionPrefix::XAcquire);
    if (insn.attributes & ZYDIS_ATTRIB_HAS_XRELEASE) addPrefix(out, InstructionPrefix::XRelease);
    if (insn.attributes & ZYDIS_ATTRIB_HAS_LOCK)     addPrefix(out, InstructionPrefix::Lock);
    if (insn.attributes & ZYDIS_ATTRIB_HAS_REPE)     addPrefix(out, InstructionPrefix::Repe);
    else if (insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) addPrefix(out, InstructionPrefix::Repne);
    else if (insn.attributes & ZYDIS_ATTRIB_HAS_REP) addPrefix(out, InstructionPrefix::Rep);
    if (insn.attributes & ZYDIS_ATTRIB_HAS_BND)      addPrefix(out, InstructionPrefix::Bnd);
    if (insn.attributes & ZYDIS_ATTRIB_HAS_NOTRACK)  addPrefix(out, InstructionPrefix::NoTrack);
}

static void fillTypedSemantics(const ZydisDecodedInstruction& insn,
                               const ZydisDecodedOperand* ops,
                               Instruction& out) {
    bool hasDirectFlowOperand = false;
    out.typedOperands.reserve(insn.operand_count_visible);
    for (uint8_t i = 0; i < insn.operand_count; ++i) {
        const ZydisDecodedOperand& op = ops[i];
        const OperandAccess access = operandAccess(op.actions);

        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const std::string name = normalizedRegisterName(op.reg.value);
            if (OperandReads(access)) addRegister(out.registersRead, name);
            if (OperandWrites(access)) addRegister(out.registersWritten, name);
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            // Address-generation registers are read independently of whether
            // the referenced memory itself is read or written.
            addRegister(out.registersRead, normalizedRegisterName(op.mem.segment));
            addRegister(out.registersRead, normalizedRegisterName(op.mem.base));
            addRegister(out.registersRead, normalizedRegisterName(op.mem.index));
        }

        if (i >= insn.operand_count_visible) continue;
        TypedOperand typed;
        typed.access = access;
        typed.widthBits = op.size;
        switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                typed.kind = OperandKind::Register;
                typed.registerName = normalizedRegisterName(op.reg.value);
                break;
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                typed.kind = OperandKind::Immediate;
                typed.immediateSigned = op.imm.is_signed != 0;
                typed.immediate = typed.immediateSigned
                    ? static_cast<uint64_t>(op.imm.value.s)
                    : op.imm.value.u;
                typed.pcRelative = op.imm.is_relative != 0;
                hasDirectFlowOperand = hasDirectFlowOperand || typed.pcRelative;
                break;
            case ZYDIS_OPERAND_TYPE_MEMORY:
                typed.kind = OperandKind::Memory;
                typed.segmentRegister = normalizedRegisterName(op.mem.segment);
                typed.baseRegister = normalizedRegisterName(op.mem.base);
                typed.indexRegister = normalizedRegisterName(op.mem.index);
                typed.scale = op.mem.scale;
                typed.displacementValid = op.mem.disp.has_displacement != 0;
                typed.displacement = op.mem.disp.value;
                typed.pcRelative = op.mem.base == ZYDIS_REGISTER_EIP ||
                                   op.mem.base == ZYDIS_REGISTER_RIP;
                break;
            case ZYDIS_OPERAND_TYPE_POINTER:
                typed.kind = OperandKind::Pointer;
                typed.immediate = (static_cast<uint64_t>(op.ptr.segment) << 32) |
                                  static_cast<uint64_t>(op.ptr.offset);
                hasDirectFlowOperand = true;
                break;
            default:
                break;
        }
        out.typedOperands.push_back(std::move(typed));
    }

    normalizeRegisterSet(out.registersRead);
    normalizeRegisterSet(out.registersWritten);

    if (insn.cpu_flags) {
        out.flagsRead = semanticFlagMask(insn.cpu_flags->tested);
        out.flagsWritten = semanticFlagMask(insn.cpu_flags->modified |
                                            insn.cpu_flags->set_0 |
                                            insn.cpu_flags->set_1 |
                                            insn.cpu_flags->undefined);
    }

    switch (insn.meta.category) {
        case ZYDIS_CATEGORY_CALL:
            out.flow.kind = hasDirectFlowOperand ? FlowKind::DirectCall : FlowKind::IndirectCall;
            break;
        case ZYDIS_CATEGORY_RET:
            out.flow.kind = FlowKind::Return;
            break;
        case ZYDIS_CATEGORY_COND_BR:
            out.flow.kind = FlowKind::ConditionalBranch;
            break;
        case ZYDIS_CATEGORY_UNCOND_BR:
            out.flow.kind = hasDirectFlowOperand
                ? FlowKind::UnconditionalBranch : FlowKind::IndirectBranch;
            break;
        default:
            break;
    }
}

// Decoder + formatter live for the lifetime of the instance; both depend only on
// the architecture and are read-only during decode/format, so they are built once.
struct ZydisDisassembler::ZyState {
    ZydisDecoder   decoder;
    ZydisFormatter formatter;
    bool           ready = false;
    std::string    error;
};

ZydisDisassembler::ZydisDisassembler(Arch arch)
    : arch_(arch), st_(std::make_unique<ZyState>()) {
    config_.engine = Engine::Zydis;
    config_.arch = arch;
    initialize();
}

ZydisDisassembler::ZydisDisassembler(const DecoderConfig& config)
    : config_(config), arch_(config.arch), st_(std::make_unique<ZyState>()) {
    initialize();
}

void ZydisDisassembler::initialize() {
    if (config_.byteOrder != ByteOrder::Little) {
        st_->error = "Zydis does not support big-endian x86 decoding";
        return;
    }
    ZydisMachineMode mode = ZYDIS_MACHINE_MODE_LONG_64;
    ZydisStackWidth width = ZYDIS_STACK_WIDTH_64;
    switch (arch_) {
        case Arch::X86_16:
            // REAL_16 selects 16-bit default operand and address widths; the
            // stack width separately models SP-based real-mode stack accesses.
            mode = ZYDIS_MACHINE_MODE_REAL_16;
            width = ZYDIS_STACK_WIDTH_16;
            break;
        case Arch::X86:
            mode = ZYDIS_MACHINE_MODE_LEGACY_32;
            width = ZYDIS_STACK_WIDTH_32;
            break;
        case Arch::X64:
            break;
        default:
            st_->error = "Zydis supports only x86-16, x86, and x64";
            return;
    }
    const ZyanStatus decoderStatus = ZydisDecoderInit(&st_->decoder, mode, width);
    if (ZYAN_FAILED(decoderStatus)) {
        char message[96];
        std::snprintf(message, sizeof(message), "Zydis decoder initialization failed (0x%08X)",
                      static_cast<unsigned>(decoderStatus));
        st_->error = message;
        return;
    }
    const ZyanStatus formatterStatus =
        ZydisFormatterInit(&st_->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    if (ZYAN_FAILED(formatterStatus)) {
        char message[96];
        std::snprintf(message, sizeof(message), "Zydis formatter initialization failed (0x%08X)",
                      static_cast<unsigned>(formatterStatus));
        st_->error = message;
        return;
    }
    st_->ready = true;
}

ZydisDisassembler::~ZydisDisassembler() = default;

bool ZydisDisassembler::ready() const { return st_ && st_->ready; }

std::string_view ZydisDisassembler::errorMessage() const {
    return st_ ? std::string_view(st_->error) : std::string_view("Zydis state unavailable");
}

bool ZydisDisassembler::decodeOne(const uint8_t* data, size_t size,
                                  uint64_t va, Instruction& out) {
    if (!data || !ready()) return false;
    size = ClampAddressableBytes(va, size);
    if (!size) return false;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&st_->decoder, data, size, &insn, ops)))
        return false;

    char buf[256] = {0};
    ZydisFormatterFormatInstruction(&st_->formatter, &insn, ops,
                                    insn.operand_count_visible, buf, sizeof(buf), va, nullptr);

    out = Instruction{};
    out.address  = va;
    out.length   = insn.length;
    appendHexBytes(out.bytes, data, insn.length);

    // Take the real mnemonic from Zydis metadata. The formatted string prefixes
    // legacy-prefix tokens (rep/lock/bnd/...), so a naive first-space split would
    // wrongly treat the prefix as the mnemonic (e.g. "rep movsb" -> "rep").
    const char* mn = ZydisMnemonicGetString(insn.mnemonic);
    out.mnemonic = mn ? mn : "";
    std::string s = buf;
    if (!out.mnemonic.empty()) {
        size_t pos = s.find(out.mnemonic);
        if (pos != std::string::npos) {
            fillPrefixes(insn, std::string_view(s).substr(0, pos), out);
            size_t after = pos + out.mnemonic.size();
            if (after < s.size() && s[after] == ' ') ++after;   // skip the single separator
            out.operands = (after < s.size()) ? s.substr(after) : std::string();
        }
    } else {
        // Fallback to the first-space split if the mnemonic string is unavailable.
        size_t sp = s.find(' ');
        if (sp == std::string::npos) out.mnemonic = s;
        else { out.mnemonic = s.substr(0, sp); out.operands = s.substr(sp + 1); }
    }
    fillPrefixes(insn, {}, out);

    out.isCall   = (insn.meta.category == ZYDIS_CATEGORY_CALL);
    out.isRet    = (insn.meta.category == ZYDIS_CATEGORY_RET);
    out.isBranch = out.isCall || out.isRet ||
                   insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
                   insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
    // Mandatory F2/F3 encodings on non-string instructions are not repeat
    // semantics.  Only the STRINGOP category is safe for debugger step-over.
    out.isRepString = insn.meta.category == ZYDIS_CATEGORY_STRINGOP &&
        (insn.attributes &
         (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) != 0;

    fillTypedSemantics(insn, ops, out);

    for (int i = 0; i < insn.operand_count_visible; ++i) {
        if (ops[i].type != ZYDIS_OPERAND_TYPE_POINTER) continue;
        out.farTarget.valid = true;
        out.farTarget.segment = ops[i].ptr.segment;
        out.farTarget.offset = ops[i].ptr.offset;
        out.farTarget.offsetBits = static_cast<uint8_t>(insn.operand_width);
        out.farTarget.linearAddress =
            (static_cast<uint64_t>(ops[i].ptr.segment) << 4) + ops[i].ptr.offset;
        out.farTarget.linearAddressValid = true;
        break;
    }

    // Resolve a static relative branch target when possible.
    for (int i = 0; i < insn.operand_count_visible; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
            uint64_t next = 0, target = 0;
            bool targetValid = false;
            if (arch_ == Arch::X86_16 && ops[i].size <= 16) {
                const uint16_t nextIp = static_cast<uint16_t>(
                    static_cast<uint16_t>(va) + insn.length);
                const uint16_t targetIp = static_cast<uint16_t>(
                    static_cast<int64_t>(nextIp) + ops[i].imm.value.s);
                target = (va & ~uint64_t{0xFFFF}) | targetIp;
                targetValid = true;
            } else {
                targetValid = CheckedAddressAdd(va, insn.length, next) &&
                              CheckedAddressAddSigned(next, ops[i].imm.value.s, target);
            }
            if (targetValid) {
                out.branchTarget = target;
                out.branchTargetValid = true;
            }
        }
    }
    out.flow.directTarget = out.branchTarget;
    out.flow.directTargetValid = out.branchTargetValid;
    return true;
}

std::vector<Instruction> ZydisDisassembler::disassemble(const uint8_t* data, size_t size,
                                                        uint64_t va, size_t maxInstructions) {
    std::vector<Instruction> result;
    if (!data || !ready()) return result;
    size = ClampAddressableBytes(va, size);
    size_t offset = 0;
    while (offset < size) {
        uint64_t atVa = 0;
        if (!CheckedAddressAdd(va, static_cast<uint64_t>(offset), atVa)) break;
        Instruction insn;
        if (!decodeOne(data + offset, size - offset, atVa, insn) ||
            !insn.length || insn.length > size - offset) {
            // Emit a 1-byte "db" pseudo-op so the stream never stalls.
            insn = Instruction{};
            insn.address = atVa;
            insn.length  = 1;
            appendHexBytes(insn.bytes, data + offset, 1);
            insn.mnemonic = "db";
            char b[8]; std::snprintf(b, sizeof(b), "0x%02X", data[offset]);
            insn.operands = b;
        }
        result.push_back(insn);
        offset += insn.length;
        if (maxInstructions && result.size() >= maxInstructions) break;
    }
    return result;
}

} // namespace ds
