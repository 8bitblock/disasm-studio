//
// xref_arch_test.cpp
// End-to-end check that the cross-reference sweep (BuildXrefInto) recovers branch
// targets and data references correctly with the REAL Zydis decoder in x86 real
// mode (16-bit), x86 (32-bit), and x64 (64-bit) modes. The real-mode stream is
// decoded by both shipped backends so the manifest's Capstone x86 feature stays
// an executable contract rather than a compile-only claim.
//
// Build & run (Windows VS Dev Shell, from project root):
//   set V=vcpkg_installed\x64-windows-static\x64-windows-static
//   cl /nologo /std:c++20 /EHsc /MT /I src /I %V%\include ^
//      tests\xref_arch_test.cpp src\Core\XrefIndex.cpp src\Disasm\ZydisDisassembler.cpp ^
//      src\Disasm\CapstoneDisassembler.cpp ^
//      %V%\lib\Zydis.lib %V%\lib\Zycore.lib %V%\lib\capstone.lib
//   .\xref_arch_test.exe
//
#include "Core/XrefIndex.h"
#include "Core/InstructionReference.h"
#include "Disasm/CapstoneDisassembler.h"
#include "Disasm/ZydisDisassembler.h"

#include <algorithm>
#include <cstdio>
#include <limits>

using namespace ds;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

static bool hasRegister(const std::vector<std::string>& registers, const char* name) {
    return std::find(registers.begin(), registers.end(), name) != registers.end();
}

static bool hasPrefix(const Instruction& in, InstructionPrefix prefix) {
    return std::find(in.prefixes.begin(), in.prefixes.end(), prefix) != in.prefixes.end();
}

static const TypedOperand* operandOfKind(const Instruction& in, OperandKind kind,
                                         size_t ordinal = 0) {
    for (const TypedOperand& operand : in.typedOperands) {
        if (operand.kind != kind) continue;
        if (ordinal-- == 0) return &operand;
    }
    return nullptr;
}

int main() {
    // ---- construction contract / structured instruction text --------------
    {
        DecoderConfig invalidConfig;
        invalidConfig.engine = Engine::Capstone;
        invalidConfig.arch = Arch::X64;
        invalidConfig.byteOrder = ByteOrder::Big;
        CapstoneDisassembler invalidCapstone(invalidConfig);
        CHECK(!invalidCapstone.ready());
        CHECK(!invalidCapstone.errorMessage().empty());

        DecoderConfig identity;
        identity.engine = Engine::Capstone;
        identity.arch = Arch::RISCV64;
        CHECK(AnalysisIsaSignature(identity) ==
              AnalysisIsaSignature(Arch::RISCV64, Engine::Capstone));
        DecoderConfig changed = identity;
        CHECK(changed == identity);
        changed.byteOrder = ByteOrder::Big;
        CHECK(changed != identity &&
              AnalysisIsaSignature(changed) != AnalysisIsaSignature(identity));
        changed = identity; changed.features.riscvCompressed = false;
        CHECK(AnalysisIsaSignature(changed) != AnalysisIsaSignature(identity));
        changed = identity; changed.features.armV8 = true;
        CHECK(AnalysisIsaSignature(changed) != AnalysisIsaSignature(identity));
        changed = identity; changed.features.armMClass = true;
        CHECK(AnalysisIsaSignature(changed) != AnalysisIsaSignature(identity));
        changed = identity; changed.features.mipsMicro = true;
        CHECK(AnalysisIsaSignature(changed) != AnalysisIsaSignature(identity));

        invalidConfig.engine = Engine::Zydis;
        ZydisDisassembler invalidZydis(invalidConfig);
        CHECK(!invalidZydis.ready());
        CHECK(!invalidZydis.errorMessage().empty());

        DecoderConfig wrongArch;
        wrongArch.engine = Engine::Zydis;
        wrongArch.arch = Arch::ARM64;
        ZydisDisassembler nonX86Zydis(wrongArch);
        CHECK(!nonX86Zydis.ready());
        CHECK(!nonX86Zydis.errorMessage().empty());

        const uint8_t repMovsb[] = {0xF3, 0xA4};
        const uint8_t mandatoryF3[] = {0xF3, 0x0F, 0x10, 0xC0}; // movss xmm0,xmm0
        const uint8_t mandatoryF2[] = {0xF2, 0x0F, 0x10, 0xC0}; // movsd xmm0,xmm0
        const uint8_t lockAdd[] = {0xF0, 0x01, 0x18};            // lock add [rax],ebx
        const uint8_t acquireAdd[] = {0xF2, 0xF0, 0x01, 0x18};  // xacquire lock add [rax],ebx
        const uint8_t releaseAdd[] = {0xF3, 0xF0, 0x01, 0x18};  // xrelease lock add [rax],ebx
        const uint8_t bndCall[] = {0xF2, 0xE8, 0, 0, 0, 0};    // bnd call next
        const uint8_t noTrackJump[] = {0x3E, 0xFF, 0xE0};       // notrack jmp rax
        ZydisDisassembler z(Arch::X64);
        CapstoneDisassembler c(Arch::X64);
        Instruction in;
        CHECK(z.ready() && c.ready());
        CHECK(z.decodeOne(repMovsb, sizeof(repMovsb), 0x1000, in));
        CHECK(in.mnemonic == "movsb" && in.isRepString);
        CHECK(!in.prefixes.empty() && InstructionText(in).rfind("rep movsb", 0) == 0);
        CHECK(c.decodeOne(repMovsb, sizeof(repMovsb), 0x1000, in));
        CHECK(in.mnemonic == "movsb" && in.isRepString);
        CHECK(!in.prefixes.empty() && InstructionText(in).rfind("rep movsb", 0) == 0);
        CHECK(z.decodeOne(mandatoryF3, sizeof(mandatoryF3), 0x1100, in));
        CHECK(in.mnemonic == "movss" && !in.isRepString &&
              !hasPrefix(in, InstructionPrefix::Rep) &&
              !hasPrefix(in, InstructionPrefix::Repe) &&
              !hasPrefix(in, InstructionPrefix::Repne));
        CHECK(c.decodeOne(mandatoryF3, sizeof(mandatoryF3), 0x1100, in));
        CHECK(in.mnemonic == "movss" && !in.isRepString &&
              !hasPrefix(in, InstructionPrefix::Rep) &&
              !hasPrefix(in, InstructionPrefix::Repe) &&
              !hasPrefix(in, InstructionPrefix::Repne));
        CHECK(z.decodeOne(mandatoryF2, sizeof(mandatoryF2), 0x1110, in));
        CHECK(in.mnemonic == "movsd" && !in.isRepString &&
              !hasPrefix(in, InstructionPrefix::Repne));
        CHECK(c.decodeOne(mandatoryF2, sizeof(mandatoryF2), 0x1110, in));
        CHECK(in.mnemonic == "movsd" && !in.isRepString &&
              !hasPrefix(in, InstructionPrefix::Repne));
        CHECK(z.decodeOne(lockAdd, sizeof(lockAdd), 0x1200, in));
        CHECK(in.mnemonic == "add" && !in.prefixes.empty() &&
              InstructionText(in).rfind("lock add", 0) == 0);
        CHECK(c.decodeOne(lockAdd, sizeof(lockAdd), 0x1200, in));
        CHECK(in.mnemonic == "add" && !in.prefixes.empty() &&
              InstructionText(in).rfind("lock add", 0) == 0);

        // F2/F3 are semantic HLE prefixes only when paired with LOCK on an
        // eligible memory mutation; the same bytes above are mandatory SSE
        // opcode selectors and must not leak into semantic prefix metadata.
        for (IDisassembler* dis : std::initializer_list<IDisassembler*>{&z, &c}) {
            CHECK(dis->decodeOne(acquireAdd, sizeof(acquireAdd), 0x1210, in));
            CHECK(in.mnemonic == "add" && hasPrefix(in, InstructionPrefix::XAcquire) &&
                  hasPrefix(in, InstructionPrefix::Lock) && !in.isRepString &&
                  InstructionText(in).find("xacquire") != std::string::npos);
            CHECK(dis->decodeOne(releaseAdd, sizeof(releaseAdd), 0x1220, in));
            CHECK(in.mnemonic == "add" && hasPrefix(in, InstructionPrefix::XRelease) &&
                  hasPrefix(in, InstructionPrefix::Lock) && !in.isRepString &&
                  InstructionText(in).find("xrelease") != std::string::npos);
            CHECK(dis->decodeOne(bndCall, sizeof(bndCall), 0x1230, in));
            CHECK(in.mnemonic == "call" && hasPrefix(in, InstructionPrefix::Bnd) &&
                  !hasPrefix(in, InstructionPrefix::Repne) && !in.isRepString &&
                  InstructionText(in).rfind("bnd call", 0) == 0);
            CHECK(dis->decodeOne(noTrackJump, sizeof(noTrackJump), 0x1240, in));
            CHECK(in.mnemonic == "jmp" && hasPrefix(in, InstructionPrefix::NoTrack) &&
                  InstructionText(in).rfind("notrack jmp", 0) == 0);
        }
    }

    // ---- decoder-native semantic parity (Zydis <-> Capstone, x64) ----------
    // These assertions deliberately avoid display strings.  Both backends must
    // expose the same engine-independent flow, operand, register, and flag
    // contracts for the core instructions consumed by analysis.
    {
        ZydisDisassembler zydis(Arch::X64);
        CapstoneDisassembler capstone(Arch::X64);

        const uint8_t conditional[] = {0x75, 0x05};         // jne 0x1007
        Instruction z, c;
        CHECK(zydis.decodeOne(conditional, sizeof(conditional), 0x1000, z));
        CHECK(capstone.decodeOne(conditional, sizeof(conditional), 0x1000, c));
        CHECK(z.flow.kind == FlowKind::ConditionalBranch);
        CHECK(c.flow.kind == FlowKind::ConditionalBranch);
        CHECK(z.flow.directTargetValid && c.flow.directTargetValid);
        CHECK(z.flow.directTarget == 0x1007 && c.flow.directTarget == 0x1007);
        CHECK((z.flagsRead & SemanticFlagBit(SemanticFlag::Zero)) != 0);
        CHECK((c.flagsRead & SemanticFlagBit(SemanticFlag::Zero)) != 0);
        const TypedOperand* zCondImm = operandOfKind(z, OperandKind::Immediate);
        const TypedOperand* cCondImm = operandOfKind(c, OperandKind::Immediate);
        CHECK(zCondImm && zCondImm->pcRelative);
        CHECK(cCondImm && cCondImm->pcRelative);

        const uint8_t call[] = {0xE8, 0x05, 0x00, 0x00, 0x00}; // call 0x200a
        CHECK(zydis.decodeOne(call, sizeof(call), 0x2000, z));
        CHECK(capstone.decodeOne(call, sizeof(call), 0x2000, c));
        CHECK(z.flow.kind == FlowKind::DirectCall && c.flow.kind == FlowKind::DirectCall);
        CHECK(z.flow.directTargetValid && c.flow.directTargetValid);
        CHECK(z.flow.directTarget == 0x200A && c.flow.directTarget == 0x200A);

        const uint8_t ret[] = {0xC3};
        CHECK(zydis.decodeOne(ret, sizeof(ret), 0x3000, z));
        CHECK(capstone.decodeOne(ret, sizeof(ret), 0x3000, c));
        CHECK(z.flow.kind == FlowKind::Return && c.flow.kind == FlowKind::Return);
        CHECK(!z.flow.directTargetValid && !c.flow.directTargetValid);

        // mov rax, qword ptr [rbx + rcx*4 + 0x10]
        const uint8_t memory[] = {0x48, 0x8B, 0x44, 0x8B, 0x10};
        CHECK(zydis.decodeOne(memory, sizeof(memory), 0x4000, z));
        CHECK(capstone.decodeOne(memory, sizeof(memory), 0x4000, c));
        const TypedOperand* zDst = operandOfKind(z, OperandKind::Register);
        const TypedOperand* cDst = operandOfKind(c, OperandKind::Register);
        const TypedOperand* zMem = operandOfKind(z, OperandKind::Memory);
        const TypedOperand* cMem = operandOfKind(c, OperandKind::Memory);
        CHECK(zDst && zDst->registerName == "rax" && zDst->widthBits == 64 &&
              OperandWrites(zDst->access));
        CHECK(cDst && cDst->registerName == "rax" && cDst->widthBits == 64 &&
              OperandWrites(cDst->access));
        CHECK(zMem && zMem->widthBits == 64 && OperandReads(zMem->access) &&
              zMem->baseRegister == "rbx" && zMem->indexRegister == "rcx" &&
              zMem->scale == 4 && zMem->displacementValid && zMem->displacement == 0x10);
        CHECK(cMem && cMem->widthBits == 64 && OperandReads(cMem->access) &&
              cMem->baseRegister == "rbx" && cMem->indexRegister == "rcx" &&
              cMem->scale == 4 && cMem->displacementValid && cMem->displacement == 0x10);
        CHECK(hasRegister(z.registersRead, "rbx") && hasRegister(z.registersRead, "rcx"));
        CHECK(hasRegister(c.registersRead, "rbx") && hasRegister(c.registersRead, "rcx"));
        CHECK(hasRegister(z.registersWritten, "rax"));
        CHECK(hasRegister(c.registersWritten, "rax"));

        // add rax, rbx: destination is read/write and the arithmetic flag set
        // is normalized independently of each decoder's native bit layout.
        const uint8_t add[] = {0x48, 0x01, 0xD8};
        CHECK(zydis.decodeOne(add, sizeof(add), 0x5000, z));
        CHECK(capstone.decodeOne(add, sizeof(add), 0x5000, c));
        zDst = operandOfKind(z, OperandKind::Register, 0);
        cDst = operandOfKind(c, OperandKind::Register, 0);
        const TypedOperand* zSrc = operandOfKind(z, OperandKind::Register, 1);
        const TypedOperand* cSrc = operandOfKind(c, OperandKind::Register, 1);
        CHECK(zDst && zDst->registerName == "rax" && zDst->access == OperandAccess::ReadWrite);
        CHECK(cDst && cDst->registerName == "rax" && cDst->access == OperandAccess::ReadWrite);
        CHECK(zSrc && zSrc->registerName == "rbx" && OperandReads(zSrc->access));
        CHECK(cSrc && cSrc->registerName == "rbx" && OperandReads(cSrc->access));
        CHECK(hasRegister(z.registersRead, "rax") && hasRegister(z.registersRead, "rbx") &&
              hasRegister(z.registersWritten, "rax"));
        CHECK(hasRegister(c.registersRead, "rax") && hasRegister(c.registersRead, "rbx") &&
              hasRegister(c.registersWritten, "rax"));
        constexpr uint64_t arithmeticFlags =
            SemanticFlagBit(SemanticFlag::Carry) |
            SemanticFlagBit(SemanticFlag::Parity) |
            SemanticFlagBit(SemanticFlag::AuxCarry) |
            SemanticFlagBit(SemanticFlag::Zero) |
            SemanticFlagBit(SemanticFlag::Sign) |
            SemanticFlagBit(SemanticFlag::Overflow);
        CHECK((z.flagsWritten & arithmeticFlags) == arithmeticFlags);
        CHECK((c.flagsWritten & arithmeticFlags) == arithmeticFlags);
        CHECK((z.flagsWritten & arithmeticFlags) == (c.flagsWritten & arithmeticFlags));
    }

    // Real decoder metadata must not turn per-thread segment offsets into
    // static FILE references. Address generation and address-size remain exact.
    {
        ZydisDisassembler zydis(Arch::X64);
        CapstoneDisassembler capstone(Arch::X64);
        const uint8_t gsLoad[] = {0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0};
        const uint8_t fsCall[] = {0x64, 0xff, 0x14, 0x25, 0, 0x10, 0, 0};
        const uint8_t gsLea[] = {0x65, 0x48, 0x8d, 0x04, 0x25, 0x60, 0, 0, 0};
        const uint8_t absoluteZero[] = {0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0};
        const uint8_t eipRelative[] = {0x67, 0x48, 0x8b, 0x05, 0x20, 0, 0, 0};
        for (IDisassembler* dis : std::initializer_list<IDisassembler*>{&zydis, &capstone}) {
            Instruction in; uint64_t ref = 0;
            CHECK(dis->decodeOne(gsLoad, sizeof(gsLoad), 0x140000000ull, in));
            CHECK(!TryGetInstrDataRef(in, ref));
            XrefIndex refs;
            BuildXrefInto(refs, gsLoad, sizeof(gsLoad), 0x140000000ull, *dis);
            CHECK(!refs.sources(0x60));
            CHECK(dis->decodeOne(fsCall, sizeof(fsCall), 0x140000000ull, in));
            CHECK(InstructionIsCall(in) && !TryGetInstrDataRef(in, ref));
            CHECK(dis->decodeOne(gsLea, sizeof(gsLea), 0x140000000ull, in));
            CHECK(TryGetInstrDataRef(in, ref) && ref == 0x60);
            CHECK(dis->decodeOne(absoluteZero, sizeof(absoluteZero), 0x140000000ull, in));
            CHECK(TryGetInstrDataRef(in, ref) && ref == 0);
            CHECK(dis->decodeOne(eipRelative, sizeof(eipRelative), 0x140000000ull, in));
            CHECK(TryGetInstrDataRef(in, ref) && ref == 0x40000028);
        }
    }

    // MIPS retains the architectural instruction executed after a control
    // transfer as an explicit delay-slot count.
    {
        CapstoneDisassembler mips(Arch::MIPS);
        const uint8_t jump[] = {0x00, 0x04, 0x00, 0x08};   // j 0x1000 (little-endian)
        Instruction in;
        CHECK(mips.decodeOne(jump, sizeof(jump), 0x2000, in));
        CHECK(in.flow.kind == FlowKind::UnconditionalBranch);
        CHECK(in.flow.directTargetValid && in.flow.directTarget == 0x1000);
        CHECK(in.flow.delaySlots == 1);

        DecoderConfig ppcConfig;
        ppcConfig.engine = Engine::Capstone;
        ppcConfig.arch = Arch::PPC;
        ppcConfig.byteOrder = ByteOrder::Big;
        CapstoneDisassembler ppcBig(ppcConfig);
        const uint8_t ppcBranchBig[] = {0x48, 0x00, 0x00, 0x08};
        CHECK(ppcBig.ready());
        CHECK(ppcBig.decodeOne(ppcBranchBig, sizeof(ppcBranchBig), 0x4000, in));
        CHECK(in.flow.kind == FlowKind::UnconditionalBranch &&
              in.flow.directTargetValid && in.flow.directTarget == 0x4008);

        ppcConfig.byteOrder = ByteOrder::Little;
        CapstoneDisassembler ppcLittle(ppcConfig);
        const uint8_t ppcBranchLittle[] = {0x08, 0x00, 0x00, 0x48};
        CHECK(ppcLittle.ready());
        CHECK(ppcLittle.decodeOne(ppcBranchLittle, sizeof(ppcBranchLittle), 0x4000, in));
        CHECK(in.flow.kind == FlowKind::UnconditionalBranch &&
              in.flow.directTargetValid && in.flow.directTarget == 0x4008);
    }

    // DecoderConfig controls byte order and optional ISA extensions.
    {
        DecoderConfig bigMips;
        bigMips.engine = Engine::Capstone;
        bigMips.arch = Arch::MIPS;
        bigMips.byteOrder = ByteOrder::Big;
        CapstoneDisassembler mips(bigMips);
        const uint8_t jump[] = {0x08, 0x00, 0x04, 0x00}; // big-endian j 0x1000
        Instruction in;
        CHECK(mips.ready());
        CHECK(mips.decodeOne(jump, sizeof(jump), 0x2000, in));
        CHECK(in.flow.kind == FlowKind::UnconditionalBranch);
        CHECK(in.flow.directTargetValid && in.flow.directTarget == 0x1000);

        // Exercise a mixed-width chain rather than a single C.NOP: exact
        // checkpoints must advance 2, 2, then 4 bytes in both RV32 and RV64.
        const uint8_t compressedChain[] = {
            0x01, 0x00,             // c.nop
            0x85, 0x00,             // c.addi ra,1
            0x93, 0x80, 0x10, 0x00  // addi ra,ra,1
        };
        for (Arch arch : {Arch::RISCV32, Arch::RISCV64}) {
            DecoderConfig compressed;
            compressed.engine = Engine::Capstone;
            compressed.arch = arch;
            compressed.features.riscvCompressed = true;
            CapstoneDisassembler riscvC(compressed);
            CHECK(riscvC.ready());
            const auto chain = riscvC.disassemble(compressedChain, sizeof(compressedChain),
                                                  0x3000, 0);
            CHECK(chain.size() == 3);
            CHECK(chain.size() < 1 || (chain[0].address == 0x3000 && chain[0].length == 2));
            CHECK(chain.size() < 2 || (chain[1].address == 0x3002 && chain[1].length == 2));
            CHECK(chain.size() < 3 || (chain[2].address == 0x3004 && chain[2].length == 4));

            compressed.features.riscvCompressed = false;
            CapstoneDisassembler riscvBase(compressed);
            CHECK(riscvBase.ready());
            CHECK(!riscvBase.decodeOne(compressedChain, 2, 0x3000, in));
        }
    }

    // Bulk backends clamp the byte window at UINT64_MAX. Neither a successful
    // decode nor an invalid-data resync may continue at wrapped low VAs.
    {
        constexpr uint64_t kMax = (std::numeric_limits<uint64_t>::max)();
        const uint8_t nops[] = {0x90, 0x90, 0x90, 0x90};
        ZydisDisassembler z(Arch::X64);
        CapstoneDisassembler c(Arch::X64);
        const auto zv = z.disassemble(nops, sizeof(nops), kMax - 1, 0);
        const auto cv = c.disassemble(nops, sizeof(nops), kMax - 1, 0);
        CHECK(zv.size() == 2 && zv[0].address == kMax - 1 && zv[1].address == kMax);
        CHECK(cv.size() == 2 && cv[0].address == kMax - 1 && cv[1].address == kMax);

        const uint8_t wrapCall[] = {0xE8, 0x00, 0x00, 0x00, 0x00};
        const auto zCall = z.disassemble(wrapCall, sizeof(wrapCall), kMax - 4, 0);
        const auto cCall = c.disassemble(wrapCall, sizeof(wrapCall), kMax - 4, 0);
        CHECK(zCall.size() == 1 && zCall[0].isCall && !HasBranchTarget(zCall[0]));
        CHECK(cCall.size() == 1 && cCall[0].isCall && !HasBranchTarget(cCall[0]));

        const uint8_t sweepPastTop[] = {0x90, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00};
        XrefIndex topIdx;
        BuildXrefInto(topIdx, sweepPastTop, sizeof(sweepPastTop), kMax - 1, z);
        FinalizeXrefIndex(topIdx);
        CHECK(topIdx.sources(5) == nullptr); // wrapped offset 2 must never be decoded at VA 0

        CapstoneDisassembler a64(Arch::ARM64);
        const uint8_t invalid[] = {0xFF, 0xFF, 0xFF, 0xFF};
        const auto av = a64.disassemble(invalid, sizeof(invalid), kMax - 1, 0);
        CHECK(av.size() == 1 && av[0].address == kMax - 1 && av[0].length == 2);
    }

    // ---- x86-16 real mode: 16-bit immediate/near-branch widths ---------------
    {
        ZydisDisassembler dis(Arch::X86_16);
        // 0x1000: B8 34 12    mov ax,0x1234 (not the five-byte mov eax,imm32)
        // 0x1003: E8 1A 00    call 0x1020 (16-bit relative displacement)
        uint8_t code[] = { 0xB8,0x34,0x12, 0xE8,0x1A,0x00 };
        Instruction mov, call;
        CHECK(dis.decodeOne(code, sizeof(code), 0x1000, mov));
        CHECK(mov.length == 3 && mov.mnemonic == "mov");
        CHECK(mov.operands.find("ax") != std::string::npos);
        CHECK(dis.decodeOne(code + 3, sizeof(code) - 3, 0x1003, call));
        CHECK(call.length == 3 && call.isCall && HasBranchTarget(call));
        CHECK(call.branchTarget == 0x1020);

        XrefIndex idx; BuildXrefInto(idx, code, sizeof(code), 0x1000, dis); FinalizeXrefIndex(idx);
        const auto* target = idx.sources(0x1020);
        CHECK(target && target->size() == 1 && (*target)[0] == 0x1003);
    }

    {
        CapstoneDisassembler dis(Arch::X86_16);
        uint8_t code[] = { 0xB8,0x34,0x12, 0xE8,0x1A,0x00 };
        Instruction mov, call;
        CHECK(dis.decodeOne(code, sizeof(code), 0x1000, mov));
        CHECK(mov.length == 3 && mov.mnemonic == "mov" &&
              mov.operands.find("ax") != std::string::npos);
        CHECK(dis.decodeOne(code + 3, sizeof(code) - 3, 0x1003, call));
        CHECK(call.length == 3 && call.isCall && HasBranchTarget(call));
        CHECK(call.branchTarget == 0x1020);
    }

    // Real-mode near control transfers wrap the 16-bit IP, while far targets
    // retain selector:offset even when no flat-image alias is authoritative.
    {
        const uint8_t wrap[] = {0xEB, 0x00}; // next IP wraps FFFE -> 0000
        const uint8_t farJump[] = {0xEA, 0x34, 0x12, 0x78, 0x56};
        ZydisDisassembler z(Arch::X86_16);
        CapstoneDisassembler c(Arch::X86_16);
        Instruction in;
        CHECK(z.decodeOne(wrap, sizeof(wrap), 0x1FFFE, in));
        CHECK(in.branchTargetValid && in.branchTarget == 0x10000);
        CHECK(c.decodeOne(wrap, sizeof(wrap), 0x1FFFE, in));
        CHECK(in.branchTargetValid && in.branchTarget == 0x10000);

        CHECK(z.decodeOne(farJump, sizeof(farJump), 0x2000, in));
        CHECK(in.farTarget.valid && in.farTarget.segment == 0x5678 &&
              in.farTarget.offset == 0x1234 && in.farTarget.offsetBits == 16 &&
              in.farTarget.linearAddressValid && in.farTarget.linearAddress == 0x579B4);
        CHECK(c.decodeOne(farJump, sizeof(farJump), 0x2000, in));
        CHECK(in.farTarget.valid && in.farTarget.segment == 0x5678 &&
              in.farTarget.offset == 0x1234 && in.farTarget.offsetBits == 16 &&
              in.farTarget.linearAddressValid && in.farTarget.linearAddress == 0x579B4);
    }

    // ---- explicit Thumb/Thumb-2 mode ---------------------------------------
    // These bytes are 16-bit PUSH/B/return plus a 32-bit TBB. They must not be
    // routed through A32 merely because both use CS_ARCH_ARM.
    {
        CapstoneDisassembler dis(Arch::THUMB);
        const uint8_t push[] = { 0x00, 0xB5 }; // push {lr}
        Instruction in;
        CHECK(dis.decodeOne(push, sizeof(push), 0x1000, in));
        CHECK(in.length == 2 && in.mnemonic == "push" && in.operands.find("lr") != std::string::npos);

        const uint8_t branch[] = { 0x00, 0xE0 }; // b 0x1004 (architectural PC=1004h)
        CHECK(dis.decodeOne(branch, sizeof(branch), 0x1000, in));
        CHECK(in.length == 2 && in.mnemonic == "b" && in.isBranch &&
              HasBranchTarget(in) && in.branchTarget == 0x1004);

        const uint8_t table[] = { 0xDF, 0xE8, 0x00, 0xF0 }; // tbb [pc, r0]
        CHECK(dis.decodeOne(table, sizeof(table), 0x2000, in));
        CHECK(in.length == 4 && in.mnemonic == "tbb" && in.isBranch &&
              in.operands.find("pc") != std::string::npos);

        const uint8_t ret[] = { 0x70, 0x47 }; // bx lr
        CHECK(dis.decodeOne(ret, sizeof(ret), 0x3000, in));
        CHECK(in.length == 2 && in.isRet && in.isBranch);

        const uint8_t truncatedWide[] = { 0x00, 0xF0 }; // first half of a 32-bit Thumb encoding
        auto invalid = dis.disassemble(truncatedWide, sizeof(truncatedWide), 0x4000, 0);
        CHECK(invalid.size() == 1 && invalid[0].mnemonic == "db" &&
              invalid[0].address == 0x4000 && invalid[0].length == 2);

        // Capstone 4 stores cs_arm_op::imm as int32_t.  Upper-half firmware
        // targets must be interpreted as 32-bit architectural addresses, not
        // sign-extended to ffffffff8.......
        CHECK(dis.decodeOne(branch, sizeof(branch), 0x80000000ull, in));
        CHECK(in.length == 2 && in.isBranch && HasBranchTarget(in) &&
              in.branchTarget == 0x80000004ull);
    }

    // The same unsigned-address contract applies to full-width A32 branches.
    {
        CapstoneDisassembler dis(Arch::ARM);
        const uint8_t branch[] = { 0x00, 0x00, 0x00, 0xEA }; // b pc+8
        Instruction in;
        CHECK(dis.decodeOne(branch, sizeof(branch), 0x80000000ull, in));
        CHECK(in.length == 4 && in.isBranch && HasBranchTarget(in) &&
              in.branchTarget == 0x80000008ull);
    }

    // A malformed AArch64 word is represented as one aligned data directive,
    // never four byte-wise directives that desynchronize the following stream.
    {
        CapstoneDisassembler dis(Arch::ARM64);
        const uint8_t invalidWord[] = { 0xFF, 0xFF, 0xFF, 0xFF };
        auto invalid = dis.disassemble(invalidWord, sizeof(invalidWord), 0x5000, 0);
        CHECK(invalid.size() == 1 && invalid[0].mnemonic == "db" &&
              invalid[0].address == 0x5000 && invalid[0].length == 4);

        // Whole-program and targeted xref sweeps must recover by one natural
        // A64 word after malformed data, not advance bytewise and decode the
        // following branch from a permanently shifted stream.
        const uint8_t malformedThenBranch[] = {
            0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x14 // b 0x5004
        };
        XrefIndex idx;
        BuildXrefInto(idx, malformedThenBranch, sizeof(malformedThenBranch), 0x5000, dis);
        FinalizeXrefIndex(idx);
        const auto* refs = idx.sources(0x5004);
        CHECK(refs && refs->size() == 1 && (*refs)[0] == 0x5004);
        std::vector<uint64_t> targeted;
        CHECK(FindRefsInBuffer(malformedThenBranch, sizeof(malformedThenBranch),
                               0x5000, 0x5004, dis, targeted, 8));
        CHECK(targeted.size() == 1 && targeted[0] == 0x5004);

        // TBZ has two immediate operands (bit number, branch destination).
        // Only the final immediate is a PC-relative control-flow target.
        const uint8_t tbz[] = {0x40, 0x00, 0x28, 0x36}; // tbz w0,#5,0x6008
        Instruction branch;
        CHECK(dis.decodeOne(tbz, sizeof(tbz), 0x6000, branch));
        CHECK(branch.mnemonic == "tbz" && branch.branchTargetValid &&
              branch.branchTarget == 0x6008);
        const TypedOperand* bit = operandOfKind(branch, OperandKind::Immediate, 0);
        const TypedOperand* targetOp = operandOfKind(branch, OperandKind::Immediate, 1);
        CHECK(bit && bit->immediate == 5 && !bit->pcRelative);
        CHECK(targetOp && targetOp->pcRelative);

        // TBNZ has the identical operand shape.  Keep the high (X-register)
        // bit number in semantic hashing while selecting only the last
        // immediate as the branch target.
        const uint8_t tbnz[] = {0x41, 0x00, 0x28, 0xB7}; // tbnz x1,#37,0x6010
        CHECK(dis.decodeOne(tbnz, sizeof(tbnz), 0x6008, branch));
        CHECK(branch.mnemonic == "tbnz" && branch.branchTargetValid &&
              branch.branchTarget == 0x6010);
        bit = operandOfKind(branch, OperandKind::Immediate, 0);
        targetOp = operandOfKind(branch, OperandKind::Immediate, 1);
        CHECK(bit && bit->immediate == 37 && !bit->pcRelative);
        CHECK(targetOp && targetOp->immediate == 0x6010 && targetOp->pcRelative);
    }

    // ---- x64: relative call + RIP-relative data load --------------------------
    {
        ZydisDisassembler dis(Arch::X64);
        // 0x1000: E8 1B 00 00 00       call 0x1020         (0x1000 + 5 + 0x1B)
        // 0x1005: 48 8B 05 10 00 00 00 mov rax,[rip+0x10] -> abs 0x1005+7+0x10 = 0x101C
        uint8_t code[] = { 0xE8,0x1B,0x00,0x00,0x00,  0x48,0x8B,0x05,0x10,0x00,0x00,0x00 };
        XrefIndex idx; BuildXrefInto(idx, code, sizeof(code), 0x1000, dis); FinalizeXrefIndex(idx);

        const auto* call = idx.sources(0x1020);
        CHECK(call && call->size() == 1 && (*call)[0] == 0x1000);
        const auto* data = idx.sources(0x1005 + 7 + 0x10);   // RIP-relative resolved to absolute
        CHECK(data && data->size() == 1 && (*data)[0] == 0x1005);
    }

    // ---- x86: relative call + absolute (moffs32) data load --------------------
    {
        ZydisDisassembler dis(Arch::X86);
        // 0x401000: E8 1B 00 00 00   call 0x401020
        // 0x401005: A1 00 20 40 00   mov eax,[0x402000]   (32-bit absolute moffs)
        uint8_t code[] = { 0xE8,0x1B,0x00,0x00,0x00,  0xA1,0x00,0x20,0x40,0x00 };
        XrefIndex idx; BuildXrefInto(idx, code, sizeof(code), 0x401000, dis); FinalizeXrefIndex(idx);

        const auto* call = idx.sources(0x401020);
        CHECK(call && call->size() == 1 && (*call)[0] == 0x401000);
        const auto* data = idx.sources(0x402000);
        CHECK(data && data->size() == 1 && (*data)[0] == 0x401005);
    }

    // ---- arch sensitivity: identical bytes, different meaning -----------------
    // 8B 05 00 20 40 00 == "mov eax,[rip+0x402000]" in x64 but "mov eax,[0x402000]"
    // in x86 (ModRM mod=00 r/m=101). The sweep must follow the decoder's arch.
    {
        uint8_t code[] = { 0x8B,0x05,0x00,0x20,0x40,0x00 };
        ZydisDisassembler x86(Arch::X86), x64(Arch::X64);
        XrefIndex ix86; BuildXrefInto(ix86, code, sizeof(code), 0x401000, x86); FinalizeXrefIndex(ix86);
        XrefIndex ix64; BuildXrefInto(ix64, code, sizeof(code), 0x1000,   x64); FinalizeXrefIndex(ix64);
        CHECK(ix86.sources(0x402000) != nullptr);                 // absolute
        CHECK(ix64.sources(0x1000 + 6 + 0x402000) != nullptr);    // RIP-relative
    }

    // ---- x86 immediate pointers: real-decoder parity + ambiguous zero ---------
    // Crackmes commonly pass string addresses as `push offset` or materialize
    // them with `mov reg, offset`. Both shipped x86 decoders must feed the same
    // precomputed index. A bare `mov reg, 0` remains scalar/null even when a raw
    // image maps VA zero; explicit memory/control-flow references retain VA 0.
    {
        const uint8_t code[] = {
            0x68,0x00,0x20,0x40,0x00, // push 0x402000
            0xB8,0x00,0x20,0x40,0x00, // mov eax,0x402000
            0xB8,0x00,0x00,0x00,0x00, // mov eax,0
        };
        ZydisDisassembler zydis(Arch::X86);
        CapstoneDisassembler capstone(Arch::X86);
        IDisassembler* decoders[] = { &zydis, &capstone };
        XrefBuildLimits limits;
        limits.immediateTargetMapped = [](uint64_t target) {
            return target == 0x402000 || target == 0;
        };
        for (IDisassembler* decoder : decoders) {
            XrefIndex idx;
            CHECK(BuildXrefInto(idx, code, sizeof(code), 0x401000, *decoder,
                                nullptr, {}, limits));
            FinalizeXrefIndex(idx);
            const auto* stringRefs = idx.sources(0x402000);
            CHECK(stringRefs && stringRefs->size() == 2);
            CHECK(stringRefs && (*stringRefs)[0] == 0x401000 &&
                  (*stringRefs)[1] == 0x401005);
            CHECK(idx.access(0x401000) == 2 && idx.access(0x401005) == 2);
            CHECK(idx.sources(0) == nullptr);
            CHECK(idx.accessOf.count(0x40100A) == 0);
        }
    }

    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("xref_arch_test: all checks passed (x86-16 + x86 + x64 + ARM + Thumb + ARM64 + MIPS + PPC + RISC-V)\n");
    return 0;
}
