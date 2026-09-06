#include "Core/BinaryFile.h"
#include "Core/CFG.h"
#include "Core/Decompiler.h"
#include "Core/JumpTableResolver.h"
#include "Disasm/IDisassembler.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(x, msg) do { if (!(x)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

static constexpr uint64_t kBase = 0x100000;

struct FixtureDis final : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "jump-table-fixture"; }

    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || !n) return false;
        out = {};
        out.address = va;
        out.bytes = "90";
        if (p[0] == 0x90) {
            out.length = 1;
            out.mnemonic = "nop";
            return true;
        }
        if (p[0] == 0xE0) {
            out.length = 1;
            out.mnemonic = "ret";
            out.isBranch = true;
            out.isRet = true;
            out.flow.kind = FlowKind::Return;
            return true;
        }
        if ((p[0] == 0xC0 || p[0] == 0xC1) && n >= 2) {
            out.length = 2;
            out.mnemonic = "cmp";
            out.operands = p[0] == 0xC0 ? "r0, #1" : "r1, #1";
            return true;
        }
        auto reg = [](const char* name, uint16_t width, OperandAccess access) {
            TypedOperand operand; operand.kind = OperandKind::Register;
            operand.registerName = name; operand.widthBits = width; operand.access = access;
            return operand;
        };
        auto imm = [](uint64_t value) {
            TypedOperand operand; operand.kind = OperandKind::Immediate;
            operand.immediate = value; operand.widthBits = 64;
            operand.access = OperandAccess::Read; return operand;
        };
        auto tableMemory = [](uint64_t table, const char* index) {
            TypedOperand operand; operand.kind = OperandKind::Memory;
            operand.displacement = static_cast<int64_t>(table);
            operand.displacementValid = true; operand.indexRegister = index;
            operand.scale = 4; operand.widthBits = 32; operand.access = OperandAccess::Read;
            return operand;
        };
        out.length = 1;
        switch (p[0]) {
            case 0xD0: // RVA: mov eax,[table+index*4]
                out.mnemonic = "mov";
                out.typedOperands = {reg("eax", 32, OperandAccess::Write),
                                     tableMemory(kBase + 0xA0, "r10")};
                return true;
            case 0xD1:
                out.mnemonic = "add";
                out.typedOperands = {reg("rax", 64, OperandAccess::ReadWrite), imm(kBase)};
                return true;
            case 0xD2: // rel32 from table base
                out.mnemonic = "movsxd";
                out.typedOperands = {reg("rax", 64, OperandAccess::Write),
                                     tableMemory(kBase + 0xC0, "r10")};
                return true;
            case 0xD3:
                out.mnemonic = "add";
                out.typedOperands = {reg("rax", 64, OperandAccess::ReadWrite), imm(kBase + 0xC0)};
                return true;
            case 0xD4: { // lea rcx,[table+index*4+4]
                out.mnemonic = "lea";
                TypedOperand address = tableMemory(kBase + 0xE4, "r10");
                out.typedOperands = {reg("rcx", 64, OperandAccess::Write), address};
                return true;
            }
            case 0xD5:
                out.mnemonic = "movsxd";
                out.typedOperands = {reg("rdx", 64, OperandAccess::Write),
                                     tableMemory(kBase + 0xE0, "r10")};
                return true;
            case 0xD6:
                out.mnemonic = "add";
                out.typedOperands = {reg("rdx", 64, OperandAccess::ReadWrite),
                                     reg("rcx", 64, OperandAccess::Read)};
                return true;
            case 0xD7:
            case 0xD8:
                out.mnemonic = "jmp";
                out.operands = p[0] == 0xD7 ? "rax" : "rdx";
                out.isBranch = true;
                out.flow.kind = FlowKind::IndirectBranch;
                out.typedOperands = {reg(p[0] == 0xD7 ? "rax" : "rdx", 64,
                                         OperandAccess::Read)};
                return true;
            case 0xD9: {
                out.mnemonic = "jmp";
                out.operands = "qword ptr [rax*8 + 0x100400]";
                out.isBranch = true;
                out.flow.kind = FlowKind::IndirectBranch;
                TypedOperand memory = tableMemory(kBase + 0x400, "rax");
                memory.scale = 8;
                memory.widthBits = 64;
                out.typedOperands = {memory};
                return true;
            }
        }
        return false;
    }

    std::vector<Instruction> disassemble(const uint8_t* p, size_t n, uint64_t va,
                                         size_t maxInstructions) override {
        std::vector<Instruction> out;
        size_t offset = 0;
        while (offset < n && (!maxInstructions || out.size() < maxInstructions)) {
            Instruction instruction;
            if (!decodeOne(p + offset, n - offset, va + offset, instruction) ||
                !instruction.length)
                break;
            offset += instruction.length;
            out.push_back(std::move(instruction));
        }
        return out;
    }
};

static void putUnsigned(std::vector<uint8_t>& bytes, size_t offset,
                        uint64_t value, size_t width, ByteOrder order) {
    for (size_t i = 0; i < width; ++i) {
        const size_t shiftIndex = order == ByteOrder::Little ? i : width - 1 - i;
        bytes[offset + i] = static_cast<uint8_t>(value >> (shiftIndex * 8));
    }
}

static Instruction indirect(const std::string& operands, uint64_t address = kBase) {
    Instruction instruction;
    instruction.address = address;
    instruction.length = 2;
    instruction.mnemonic = "jmp";
    instruction.operands = operands;
    instruction.isBranch = true;
    instruction.flow.kind = FlowKind::IndirectBranch;
    return instruction;
}

static Instruction registerJump(const char* reg, uint64_t address) {
    Instruction instruction = indirect(reg, address);
    TypedOperand operand;
    operand.kind = OperandKind::Register;
    operand.registerName = reg;
    operand.widthBits = 64;
    operand.access = OperandAccess::Read;
    instruction.typedOperands = {operand};
    return instruction;
}

static void expectTargets(const JumpTableResolution& table,
                          std::initializer_list<uint64_t> expected,
                          const char* message) {
    CHECK(table.valid, message);
    CHECK(table.targets == std::vector<uint64_t>(expected), message);
}

int main() {
    std::vector<uint8_t> bytes(0x3000, 0xFF);
    for (size_t offset : {0x20u, 0x30u, 0x40u, 0x50u, 0x60u, 0x70u,
                          0x100u, 0x110u, 0x140u, 0x150u, 0x1A0u, 0x1B0u,
                          0x200u, 0x210u})
        bytes[offset] = 0x90;

    putUnsigned(bytes, 0x80, kBase + 0x20, 8, ByteOrder::Little);
    putUnsigned(bytes, 0x88, kBase + 0x30, 8, ByteOrder::Little);

    putUnsigned(bytes, 0xA0, 0x40, 4, ByteOrder::Little);
    putUnsigned(bytes, 0xA4, 0x50, 4, ByteOrder::Little);

    putUnsigned(bytes, 0xC0, static_cast<uint32_t>(-0x60), 4, ByteOrder::Little);
    putUnsigned(bytes, 0xC4, static_cast<uint32_t>(-0x50), 4, ByteOrder::Little);

    putUnsigned(bytes, 0xE0, 0x1C, 4, ByteOrder::Little); // next slot -> base+0x100
    putUnsigned(bytes, 0xE4, 0x28, 4, ByteOrder::Little); // next slot -> base+0x110

    putUnsigned(bytes, 0x120, kBase + 0x140, 8, ByteOrder::Big);
    putUnsigned(bytes, 0x128, kBase + 0x150, 8, ByteOrder::Big);

    bytes[0x17E] = 0xC0; bytes[0x17F] = 0x00; // cmp r0, #1
    bytes[0x184] = 0x0E; // (base+0x1A0 - PC) / 2
    bytes[0x185] = 0x16; // (base+0x1B0 - PC) / 2

    bytes[0x1BE] = 0xC1; bytes[0x1BF] = 0x00; // cmp r1, #1
    putUnsigned(bytes, 0x1C4, 0x1E, 2, ByteOrder::Big);
    putUnsigned(bytes, 0x1C6, 0x26, 2, ByteOrder::Big);

    bytes[0x280] = 0xD0; bytes[0x281] = 0xD1; bytes[0x282] = 0xD7;
    bytes[0x290] = 0xD2; bytes[0x291] = 0xD3; bytes[0x292] = 0xD7;
    bytes[0x2A0] = 0xD4; bytes[0x2A1] = 0xD5; bytes[0x2A2] = 0xD6;
    bytes[0x2A3] = 0xD8;
    bytes[0x300] = 0xD9;
    for (size_t i = 0; i < 1024; ++i)
        putUnsigned(bytes, 0x400 + i * 8, kBase + 0x20, 8, ByteOrder::Little);

    const std::string path = "ds_jump_table_resolver_tmp.bin";
    { std::ofstream f(path, std::ios::binary); f.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
    BinaryFile bin;
    CHECK(bin.loadRaw(path, kBase), "load shared jump-table fixture");
    FixtureDis dis;

    JumpTableResolution table = ResolveJumpTable(
        bin, dis, Arch::X64, ByteOrder::Little,
        indirect("[rax*8 + 0x100080]"));
    expectTargets(table, {kBase + 0x20, kBase + 0x30},
                  "x64 absolute pointer table resolves");
    CHECK(table.tableAddress == kBase + 0x80 && table.entryWidth == 8 &&
          table.encoding == JumpTableEncoding::AbsoluteVA && !table.evidence.empty(),
          "absolute result preserves table metadata and evidence");

    table = ResolveJumpTable(bin, dis, Arch::X86, ByteOrder::Little,
                             indirect("[eax*4 + 0x1000A0]"));
    CHECK(!table.valid,
          "a direct memory jump cannot reinterpret entries as RVAs without add evidence");

    table = ResolveJumpTable(bin, dis, Arch::X64, ByteOrder::Little,
                             indirect("[rax*4 + 0x1000C0]"));
    CHECK(!table.valid,
          "a direct memory jump cannot reinterpret entries as table-relative offsets");

    Instruction typed = indirect("");
    TypedOperand memory;
    memory.kind = OperandKind::Memory;
    memory.indexRegister = "rax";
    memory.scale = 4;
    memory.displacement = static_cast<int64_t>(kBase + 0xE0);
    memory.displacementValid = true;
    typed.typedOperands.push_back(memory);
    table = ResolveJumpTable(bin, dis, Arch::X64, ByteOrder::Little, typed);
    CHECK(!table.valid,
          "typed memory metadata alone is not evidence for next-slot-relative arithmetic");

    table = ResolveJumpTable(bin, dis, Arch::X64, ByteOrder::Little,
                             registerJump("rax", kBase + 0x282));
    expectTargets(table, {kBase + 0x40, kBase + 0x50},
                  "decoded load plus image-base add proves an RVA table");
    CHECK(table.encoding == JumpTableEncoding::RVA &&
          table.evidence.find("add(image base)") != std::string::npos,
          "RVA result retains dispatch evidence");

    table = ResolveJumpTable(bin, dis, Arch::X64, ByteOrder::Little,
                             registerJump("rax", kBase + 0x292));
    expectTargets(table, {kBase + 0x60, kBase + 0x70},
                  "decoded signed load plus table-base add proves rel32 entries");
    CHECK(table.encoding == JumpTableEncoding::RelativeToTable,
          "table-relative encoding is reported distinctly");

    table = ResolveJumpTable(bin, dis, Arch::X64, ByteOrder::Little,
                             registerJump("rdx", kBase + 0x2A3));
    expectTargets(table, {kBase + 0x100, kBase + 0x110},
                  "decoded indexed next-slot LEA proves next-slot rel32 entries");
    CHECK(table.encoding == JumpTableEncoding::RelativeToNextSlot,
          "next-slot-relative encoding is reported distinctly");

    // The shared resolver is also offered register-indirect terminators by CFG.
    // This exercises the production integration, not only the resolver in isolation.
    auto sharedResolver = [&](const Instruction& instruction) {
        JumpTableResolution resolution = ResolveJumpTable(
            bin, dis, Arch::X64, ByteOrder::Little, instruction);
        ResolvedJumpTable resolved;
        if (resolution.valid) resolved.targets = std::move(resolution.targets);
        resolved.truncated = resolution.truncated;
        resolved.evidence = std::move(resolution.evidence);
        return resolved;
    };
    auto checkIntegratedSwitch = [&](uint64_t dispatchChunk,
                                     size_t dispatchSize,
                                     std::initializer_list<uint64_t> caseVAs,
                                     const char* message) {
        std::vector<CFGCodeChunk> chunks;
        size_t available = 0;
        const uint8_t* dispatchBytes = bin.ptrFromVA(dispatchChunk, available);
        chunks.push_back({dispatchBytes, dispatchSize, dispatchChunk});
        for (uint64_t target : caseVAs) {
            bytes[static_cast<size_t>(target - kBase)] = 0xE0;
            // BinaryFile owns the already-loaded image, so mutate through its patch API.
            const uint8_t retByte = 0xE0;
            CHECK(bin.writeImage(target, &retByte, 1), message);
            size_t targetAvailable = 0;
            chunks.push_back({bin.ptrFromVA(target, targetAvailable), 1, target});
        }
        ControlFlowGraph graph = BuildCFG(chunks, dis, 64, sharedResolver);
        const BasicBlock* dispatch = nullptr;
        for (const BasicBlock& block : graph.blocks)
            if (block.start == dispatchChunk) dispatch = &block;
        CHECK(dispatch && dispatch->isSwitch && dispatch->caseTargets.size() == caseVAs.size(),
              message);
        const std::string pseudo = Decompile(graph);
        CHECK(pseudo.find("switch (") != std::string::npos, message);
        CHECK(pseudo.find("unresolved indirect") == std::string::npos, message);
    };
    checkIntegratedSwitch(kBase + 0x280, 3,
                          {kBase + 0x40, kBase + 0x50},
                          "RVA register dispatch reaches CFG and decompiler");
    checkIntegratedSwitch(kBase + 0x290, 3,
                          {kBase + 0x60, kBase + 0x70},
                          "table-relative register dispatch reaches CFG and decompiler");
    checkIntegratedSwitch(kBase + 0x2A0, 4,
                          {kBase + 0x100, kBase + 0x110},
                          "next-slot-relative register dispatch reaches CFG and decompiler");

    // A table that reaches the hard 1,024-entry cap remains usable but explicitly
    // incomplete through CFG and decompiler diagnostics.
    {
        size_t dispatchAvailable = 0, targetAvailable = 0;
        std::vector<CFGCodeChunk> chunks = {
            {bin.ptrFromVA(kBase + 0x300, dispatchAvailable), 1, kBase + 0x300},
            {bin.ptrFromVA(kBase + 0x20, targetAvailable), 1, kBase + 0x20},
        };
        ControlFlowGraph capped = BuildCFG(chunks, dis, 2048, sharedResolver);
        CHECK(!capped.complete && capped.incompleteReason.find("entry cap") != std::string::npos,
              "CFG retains jump-table cap incompleteness");
        DecompResult pseudo = DecompileWithMap(capped);
        CHECK(!pseudo.complete && !pseudo.diagnostics.empty(),
              "decompiler retains jump-table cap diagnostic");
    }

    table = ResolveJumpTable(bin, dis, Arch::X64, ByteOrder::Big,
                             indirect("[rax*8 + 0x100120]"));
    expectTargets(table, {kBase + 0x140, kBase + 0x150},
                  "big-endian absolute pointer table resolves");
    CHECK(!ResolveJumpTable(bin, dis, Arch::X64, ByteOrder::Little,
                            indirect("[rax*8 + 0x100120]")).valid,
          "wrong byte order cannot silently manufacture the big-endian table");

    Instruction tbb;
    tbb.address = kBase + 0x180; tbb.length = 4;
    tbb.mnemonic = "tbb"; tbb.operands = "[pc, r0]";
    tbb.isBranch = true; tbb.flow.kind = FlowKind::IndirectBranch;
    table = ResolveJumpTable(bin, dis, Arch::THUMB, ByteOrder::Little, tbb);
    expectTargets(table, {kBase + 0x1A0, kBase + 0x1B0},
                  "Thumb TBB uses the decoded CMP bound and architectural PC");
    CHECK(table.tableAddress == kBase + 0x184 && table.entryWidth == 1 &&
          table.encoding == JumpTableEncoding::ThumbTBB,
          "TBB result preserves table metadata");
    Instruction unboundedTbb = tbb;
    unboundedTbb.address = kBase + 0x188; // no exact predecessor stream ending in a CMP bound
    CHECK(!ResolveJumpTable(bin, dis, Arch::THUMB, ByteOrder::Little,
                            unboundedTbb).valid,
          "Thumb tables without a decoded bounds check remain unresolved");

    Instruction tbh;
    tbh.address = kBase + 0x1C0; tbh.length = 4;
    tbh.mnemonic = "tbh"; tbh.operands = "[pc, r1, lsl #1]";
    tbh.isBranch = true; tbh.flow.kind = FlowKind::IndirectBranch;
    table = ResolveJumpTable(bin, dis, Arch::THUMB, ByteOrder::Big, tbh);
    expectTargets(table, {kBase + 0x200, kBase + 0x210},
                  "big-endian Thumb TBH reads halfwords in target byte order");
    CHECK(table.entryWidth == 2 && table.encoding == JumpTableEncoding::ThumbTBH,
          "TBH result preserves width and encoding");

    // A valid VA/table address of zero must not be confused with failure.
    std::vector<uint8_t> zeroBytes(0x80, 0xFF);
    putUnsigned(zeroBytes, 0, 0x30, 8, ByteOrder::Little);
    putUnsigned(zeroBytes, 8, 0x40, 8, ByteOrder::Little);
    zeroBytes[0x30] = zeroBytes[0x40] = 0x90;
    const std::string zeroPath = "ds_jump_table_zero_tmp.bin";
    { std::ofstream f(zeroPath, std::ios::binary); f.write(reinterpret_cast<const char*>(zeroBytes.data()), zeroBytes.size()); }
    BinaryFile zeroBin;
    CHECK(zeroBin.loadRaw(zeroPath, 0), "load zero-based raw fixture");
    table = ResolveJumpTable(zeroBin, dis, Arch::X64, ByteOrder::Little,
                             indirect("[rax*8 + 0x0]", 0x20));
    expectTargets(table, {0x30, 0x40}, "jump table at valid VA zero resolves");
    CHECK(table.tableAddress == 0, "validity is separate from numeric table address");

    // An indexed FS/GS offset cannot designate a static table, even when its
    // display text names a mapped table. Typed dynamic bases are authoritative.
    for (const char* segment : {"fs", "gs"}) {
        CHECK(!ResolveJumpTable(zeroBin, dis, Arch::X64, ByteOrder::Little,
              indirect(std::string(segment) + ":[rax*8 + 0x0]", 0x20)).valid,
              "legacy segment-relative table stays unresolved");
        Instruction segmented = indirect("[rax*8 + 0x0]", 0x20);
        TypedOperand memory; memory.kind = OperandKind::Memory;
        memory.segmentRegister = segment; memory.indexRegister = "rax";
        memory.scale = 8; memory.displacementValid = true;
        segmented.typedOperands = {memory};
        CHECK(!ResolveJumpTable(zeroBin, dis, Arch::X64, ByteOrder::Little, segmented).valid,
              "typed segment-relative table cannot fall back to display text");
        segmented.typedOperands[0].segmentRegister.clear();
        segmented.typedOperands[0].baseRegister = "rbx";
        CHECK(!ResolveJumpTable(zeroBin, dis, Arch::X64, ByteOrder::Little, segmented).valid,
              "typed dynamic table base cannot fall back to display text");
    }

    std::remove(path.c_str());
    std::remove(zeroPath.c_str());
    if (g_fail) {
        std::printf("jump_table_resolver_test: %d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("jump_table_resolver_test: all checks passed\n");
    return 0;
}
