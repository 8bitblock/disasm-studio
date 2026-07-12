#include "ZydisDisassembler.h"

#include <Zydis/Zydis.h>
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

// Decoder + formatter live for the lifetime of the instance; both depend only on
// the architecture and are read-only during decode/format, so they are built once.
struct ZydisDisassembler::ZyState {
    ZydisDecoder   decoder;
    ZydisFormatter formatter;
};

ZydisDisassembler::ZydisDisassembler(Arch arch)
    : arch_(arch), st_(std::make_unique<ZyState>()) {
    const ZydisMachineMode mode = (arch_ == Arch::X86)
        ? ZYDIS_MACHINE_MODE_LEGACY_32
        : ZYDIS_MACHINE_MODE_LONG_64;
    const ZydisStackWidth width = (arch_ == Arch::X86)
        ? ZYDIS_STACK_WIDTH_32
        : ZYDIS_STACK_WIDTH_64;
    ZydisDecoderInit(&st_->decoder, mode, width);
    ZydisFormatterInit(&st_->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

ZydisDisassembler::~ZydisDisassembler() = default;

bool ZydisDisassembler::decodeOne(const uint8_t* data, size_t size,
                                  uint64_t va, Instruction& out) {
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

    out.isCall   = (insn.meta.category == ZYDIS_CATEGORY_CALL);
    out.isRet    = (insn.meta.category == ZYDIS_CATEGORY_RET);
    out.isBranch = out.isCall || out.isRet ||
                   insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
                   insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
    // A REP/REPE/REPNE-prefixed string op (movs/stos/cmps/scas/lods/ins/outs) should
    // be treated as a single unit when stepping over / out, not single-stepped per
    // iteration. Zydis records the prefix in the instruction attributes.
    out.isRepString = (insn.attributes &
        (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) != 0;

    // Resolve a static relative branch target when possible.
    for (int i = 0; i < insn.operand_count_visible; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
            ZyanU64 target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[i], va, &target))) {
                out.branchTarget = target;
                out.branchTargetValid = true;
            }
        }
    }
    return true;
}

std::vector<Instruction> ZydisDisassembler::disassemble(const uint8_t* data, size_t size,
                                                        uint64_t va, size_t maxInstructions) {
    std::vector<Instruction> result;
    size_t offset = 0;
    while (offset < size) {
        Instruction insn;
        if (!decodeOne(data + offset, size - offset, va + offset, insn)) {
            // Emit a 1-byte "db" pseudo-op so the stream never stalls.
            insn = Instruction{};
            insn.address = va + offset;
            insn.length  = 1;
            appendHexBytes(insn.bytes, data + offset, 1);
            insn.mnemonic = "db";
            char b[8]; std::snprintf(b, sizeof(b), "0x%02X", data[offset]);
            insn.operands = b;
        }
        result.push_back(insn);
        offset += insn.length ? insn.length : 1;
        if (maxInstructions && result.size() >= maxInstructions) break;
    }
    return result;
}

} // namespace ds
