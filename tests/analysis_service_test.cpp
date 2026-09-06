//
// analysis_service_test.cpp
// Unit-tests the background analysis foundation (AnalysisJobs + AnalysisService)
// with a stub disassembler — the threading/epoch/coalescing mechanics and the
// ported string scanner, none of which need Windows/Zydis/ImGui.
//
// Compile + run (MSVC dev shell), from the repo root:
//   cl /nologo /std:c++20 /EHsc /I src tests\analysis_service_test.cpp ^
//      src\Core\AnalysisService.cpp src\Core\AnalysisJobs.cpp src\Core\XrefIndex.cpp ^
//      src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp ^
//      src\Core\AlgoScan.cpp src\Core\SigMatch.cpp
//
#include "Core/AnalysisService.h"
#include "Core/AnalysisJobs.h"
#include "Core/BinaryFile.h"
#include "Core/Project.h"
#include "Core/XrefIndex.h"
#include "Disasm/IDisassembler.h"

#include <algorithm>
#include <chrono>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <limits>
#include <stdexcept>
#include <thread>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

// Minimal decoder: every byte is a 1-byte "nop"; no branches/calls/rets.
struct StubDisasm : IDisassembler {
    uint64_t highestVA = 0;
    size_t decodeCalls = 0;
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "stub"; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || size == 0) return false;
        highestVA = decodeCalls ? std::max(highestVA, va) : va;
        ++decodeCalls;
        out = Instruction{};
        out.address = va; out.length = 1; out.mnemonic = "nop"; out.bytes = "90";
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t va, size_t maxInstructions) override {
        std::vector<Instruction> v;
        size_t off = 0;
        while (off < size && (maxInstructions == 0 || v.size() < maxInstructions)) {
            Instruction in;
            if (!decodeOne(data + off, size - off, va + off, in)) break;
            v.push_back(in); off += in.length;
        }
        return v;
    }
};

struct GateDisasm : StubDisasm {
    std::shared_ptr<std::atomic<bool>> release;
    std::shared_ptr<std::atomic<int>> entered;
    GateDisasm(std::shared_ptr<std::atomic<bool>> r,
               std::shared_ptr<std::atomic<int>> e)
        : release(std::move(r)), entered(std::move(e)) {}
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!release->load(std::memory_order_acquire)) {
            entered->fetch_add(1, std::memory_order_acq_rel);
            while (!release->load(std::memory_order_acquire))
                std::this_thread::yield();
        }
        return StubDisasm::decodeOne(data, size, va, out);
    }
};

struct SharedCountDisasm : StubDisasm {
    explicit SharedCountDisasm(std::shared_ptr<std::atomic<size_t>> c) : calls(std::move(c)) {}
    std::shared_ptr<std::atomic<size_t>> calls;
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        calls->fetch_add(1, std::memory_order_relaxed);
        return StubDisasm::decodeOne(data, size, va, out);
    }
};

struct FixedFailDisasm : StubDisasm {
    explicit FixedFailDisasm(uint32_t width) : width(width) {}
    uint32_t width;
    uint32_t invalidDecodeWidth() const override { return width; }
    bool decodeOne(const uint8_t*, size_t, uint64_t, Instruction&) override { return false; }
};

// Fails at the aligned first word, produces a misleading valid instruction if
// a caller retries bytewise, and exposes the real call only at the next aligned
// word. This makes fixed-width recovery behavior observable in call-graph tests.
struct FixedWidthCallDisasm : StubDisasm {
    explicit FixedWidthCallDisasm(uint64_t base, uint32_t width)
        : base(base), width(width) {}
    uint64_t base;
    uint32_t width;
    uint32_t invalidDecodeWidth() const override { return width; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || size < width) return false;
        const uint64_t delta = va - base;
        if (delta == 0) return false;
        out = {}; out.address = va; out.length = width; out.mnemonic = "nop";
        if (delta == width) {
            out.mnemonic = "bl"; out.isCall = out.isBranch = true;
            out.branchTarget = base + width * 2; out.branchTargetValid = true;
        }
        return true;
    }
};

// Tiny byte-scripted decoder used to prove that the synthetic raw section feeds
// recursive function discovery, whole-image listing, call graph, and xrefs.
// E8 <offset> calls rawBase+offset; C3 returns; every other byte is a nop.
struct RawFlowDisasm : StubDisasm {
    explicit RawFlowDisasm(uint64_t rawBase) : rawBase(rawBase) {}
    uint64_t rawBase;
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || !size) return false;
        out = Instruction{};
        out.address = va;
        if (data[0] == 0xE8 && size >= 2) {
            out.length = 2; out.mnemonic = "call"; out.isCall = true; out.isBranch = true;
            out.branchTarget = rawBase + data[1];
            out.branchTargetValid = true;
        } else if (data[0] == 0xC3) {
            out.length = 1; out.mnemonic = "ret"; out.isRet = true; out.isBranch = true;
        } else {
            out.length = 1; out.mnemonic = "nop";
        }
        return true;
    }
};

static constexpr uint64_t kNetworkServiceImageBase = 0x140000000ull;
static constexpr uint64_t kNetworkServiceStringVA =
    kNetworkServiceImageBase + 0x2000;
static constexpr uint64_t kNetworkServiceSendIat =
    kNetworkServiceImageBase + 0x2160;
static constexpr uint64_t kNetworkServiceReadIat =
    kNetworkServiceImageBase + 0x2168;
static constexpr uint64_t kNetworkServiceRecvIat =
    kNetworkServiceImageBase + 0x2260;
static constexpr uint64_t kNetworkServiceHostIat =
    kNetworkServiceImageBase + 0x2268;
static constexpr uint64_t kNetworkServiceStrcmpIat =
    kNetworkServiceImageBase + 0x2270;

static constexpr uint64_t kAuthorizationImageBase = 0x180000000ull;
static constexpr uint64_t kAuthorizationReadIat =
    kAuthorizationImageBase + 0x2200;
static constexpr uint64_t kAuthorizationRegGetIat =
    kAuthorizationImageBase + 0x2220;
static constexpr uint64_t kAuthorizationRegSetIat =
    kAuthorizationImageBase + 0x2228;
static constexpr uint64_t kAuthorizationLocalInputIat =
    kAuthorizationImageBase + 0x2240;
static constexpr uint64_t kAuthorizationDialogIat =
    kAuthorizationImageBase + 0x2248;
static constexpr uint64_t kAuthorizationStrcmpIat =
    kAuthorizationImageBase + 0x2260;
static constexpr uint64_t kAuthorizationHostileStrcmpIat =
    kAuthorizationImageBase + 0x22A0;
static constexpr uint64_t kAuthorizationSubkey =
    kAuthorizationImageBase + 0x2500;
static constexpr uint64_t kAuthorizationValue =
    kAuthorizationImageBase + 0x2540;
static constexpr uint64_t kAuthorizationSuccessA =
    kAuthorizationImageBase + 0x2580;
static constexpr uint64_t kAuthorizationSuccessB =
    kAuthorizationImageBase + 0x25A0;
static constexpr uint64_t kAuthorizationExpectedSerial =
    kAuthorizationImageBase + 0x25C0;
static constexpr uint64_t kAuthorizationFailureText =
    kAuthorizationImageBase + 0x25E0;

// Dedicated production-adapter fixture imports.  These live in the tail of
// the authorization fixture's .rdata section so the main regression fixture
// can keep its original IAT layout unchanged.
static constexpr uint64_t kAuthorizationProvenanceRegSetValueIat =
    kAuthorizationImageBase + 0x2710;
static constexpr uint64_t kAuthorizationProvenanceProtectedIat =
    kAuthorizationImageBase + 0x2718;
static constexpr uint64_t kAuthorizationProvenanceVerifyIat =
    kAuthorizationImageBase + 0x2800;
static constexpr uint64_t kAuthorizationProvenanceHostileProtectedIat =
    kAuthorizationImageBase + 0x2200;
static constexpr uint64_t kAuthorizationMachineRegGetIat =
    kAuthorizationImageBase + 0x2700;
static constexpr uint64_t kAuthorizationMachineIdentityIat =
    kAuthorizationImageBase + 0x2920;
static constexpr uint64_t kAuthorizationHostileMachineIdentityIat =
    kAuthorizationImageBase + 0x29A0;

// Production-shaped service fixture decoder: one exact immediate pointer to the
// endpoint followed by imported Send/Read calls and a return.  The PE loader,
// function discovery, xref pass, import adapter, and triage pass all remain real.
struct NetworkServiceDisasm : StubDisasm {
    static void reg(Instruction& out, const char* name, OperandAccess access) {
        TypedOperand operand;
        operand.kind = OperandKind::Register;
        operand.access = access;
        operand.registerName = name;
        const std::string_view regName(name);
        operand.widthBits =
            regName == "eax" || regName == "ebx" || regName == "ecx" ||
            regName == "edx" || regName == "esi" || regName == "edi" ||
            regName == "esp" || regName == "ebp" ||
            (regName.size() >= 3 && regName.front() == 'r' &&
             regName.back() == 'd')
                ? 32
                : 64;
        out.typedOperands.push_back(std::move(operand));
        if (OperandReads(access)) out.registersRead.push_back(name);
        if (OperandWrites(access)) out.registersWritten.push_back(name);
    }
    static void localMemory(Instruction& out, int64_t displacement,
                            OperandAccess access) {
        TypedOperand operand;
        operand.kind = OperandKind::Memory;
        operand.access = access;
        operand.baseRegister = "rbp";
        operand.displacement = displacement;
        operand.displacementValid = true;
        operand.widthBits = 64;
        out.typedOperands.push_back(std::move(operand));
        out.registersRead.push_back("rbp");
    }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        out = Instruction{};
        out.address = va;
        out.length = 1;
        if (data[0] == 0xA1 || data[0] == 0xA0) {
            out.mnemonic = "movabs";
            const uint64_t literal = data[0] == 0xA0
                ? kNetworkServiceStringVA + 0x40
                : kNetworkServiceStringVA;
            out.operands = "rax, 0x" + std::to_string(literal);
            reg(out, "rax", OperandAccess::Write);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.widthBits = 64;
            immediate.immediate = literal;
            out.typedOperands.push_back(std::move(immediate));
        } else if (data[0] == 0xA2 || data[0] == 0xA3 || data[0] == 0xA4 ||
                   data[0] == 0xC1 || data[0] == 0xC2 ||
                   data[0] == 0xC4 || data[0] == 0xC5 ||
                   data[0] == 0xC6) {
            const uint64_t target = data[0] == 0xA2
                                  ? kNetworkServiceSendIat
                                  : data[0] == 0xA3
                                  ? kNetworkServiceReadIat
                                  : data[0] == 0xA4
                                  ? kNetworkServiceImageBase + 0x1100
                                  : data[0] == 0xC1
                                  ? kNetworkServiceRecvIat
                                  : data[0] == 0xC2
                                  ? kNetworkServiceImageBase + 0x1140
                                  : data[0] == 0xC4
                                  ? kNetworkServiceHostIat
                                  : data[0] == 0xC5
                                  ? kNetworkServiceImageBase + 0x1160
                                  : kNetworkServiceStrcmpIat;
            out.mnemonic = "call";
            out.operands = "0x" + std::to_string(target);
            out.isCall = true;
            out.isBranch = true;
            out.branchTarget = target;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::DirectCall;
            out.flow.directTarget = target;
            out.flow.directTargetValid = true;
        } else if (data[0] == 0xA5) {
            out.mnemonic = "mov";
            out.operands = "rbx, rax";
            reg(out, "rbx", OperandAccess::Write);
            reg(out, "rax", OperandAccess::Read);
        } else if (data[0] == 0xA6) {
            out.mnemonic = "test";
            out.operands = "rbx, rbx";
            reg(out, "rbx", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xA7) {
            out.mnemonic = "je";
            out.operands = "0x" + std::to_string(
                kNetworkServiceImageBase + 0x1010);
            out.isBranch = true;
            out.branchTarget = kNetworkServiceImageBase + 0x1010;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::ConditionalBranch;
            out.flow.directTarget = out.branchTarget;
            out.flow.directTargetValid = true;
            out.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xA8) {
            out.mnemonic = "mov";
            out.operands = "[rbp - 0x8], rax";
            localMemory(out, -8, OperandAccess::Write);
            reg(out, "rax", OperandAccess::Read);
        } else if (data[0] == 0xA9) {
            out.mnemonic = "mov";
            out.operands = "rax, [rbp - 0x8]";
            reg(out, "rax", OperandAccess::Write);
            localMemory(out, -8, OperandAccess::Read);
        } else if (data[0] == 0xB1) {
            out.mnemonic = "test";
            out.operands = "rax, 1";
            reg(out, "rax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero) |
                               SemanticFlagBit(SemanticFlag::Sign);
        } else if (data[0] == 0xB2) {
            out.mnemonic = "js";
            out.operands = "0x" + std::to_string(
                kNetworkServiceImageBase + 0x1105);
            out.isBranch = true;
            out.branchTarget = kNetworkServiceImageBase + 0x1105;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::ConditionalBranch;
            out.flow.directTarget = out.branchTarget;
            out.flow.directTargetValid = true;
            out.flagsRead = SemanticFlagBit(SemanticFlag::Sign);
        } else if (data[0] == 0xB3) {
            out.mnemonic = "add";
            out.operands = "rax, 1";
            reg(out, "rax", OperandAccess::ReadWrite);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = 1;
            out.typedOperands.push_back(std::move(immediate));
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero) |
                               SemanticFlagBit(SemanticFlag::Sign);
        } else if (data[0] == 0xB4) {
            out.mnemonic = "test";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xB5) {
            out.mnemonic = "je";
            out.operands = "0x" + std::to_string(
                kNetworkServiceImageBase + 0x1109);
            out.isBranch = true;
            out.branchTarget = kNetworkServiceImageBase + 0x1109;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::ConditionalBranch;
            out.flow.directTarget = out.branchTarget;
            out.flow.directTargetValid = true;
            out.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xD1) {
            out.mnemonic = "test";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero) |
                               SemanticFlagBit(SemanticFlag::Sign);
        } else if (data[0] == 0xD3) {
            out.mnemonic = "cmp";
            out.operands = "0, eax";
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = 0;
            immediate.widthBits = 32;
            out.typedOperands.push_back(std::move(immediate));
            reg(out, "eax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero) |
                               SemanticFlagBit(SemanticFlag::Sign) |
                               SemanticFlagBit(SemanticFlag::Overflow);
        } else if (data[0] == 0xD5) {
            out.mnemonic = "test";
            out.operands = "eax, eax";
            reg(out, "eax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero) |
                               SemanticFlagBit(SemanticFlag::Sign);
        } else if (data[0] == 0xE1) {
            out.mnemonic = "inc";
            out.operands = "rcx";
            reg(out, "rcx", OperandAccess::ReadWrite);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero) |
                               SemanticFlagBit(SemanticFlag::Sign) |
                               SemanticFlagBit(SemanticFlag::Overflow);
        } else if (data[0] == 0xD2 || data[0] == 0xD4 ||
                   data[0] == 0xD6 || data[0] == 0xD7) {
            const uint64_t target = data[0] == 0xD2
                ? kNetworkServiceImageBase + 0x1144
                : data[0] == 0xD4
                ? kNetworkServiceImageBase + 0x1147
                : data[0] == 0xD6
                ? kNetworkServiceImageBase + 0x114B
                : kNetworkServiceImageBase + 0x1150;
            out.mnemonic = data[0] == 0xD4 ? "jl" : "js";
            out.operands = "0x" + std::to_string(target);
            out.isBranch = true;
            out.branchTarget = target;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::ConditionalBranch;
            out.flow.directTarget = target;
            out.flow.directTargetValid = true;
            out.flagsRead = SemanticFlagBit(SemanticFlag::Sign);
        } else if (data[0] == 0xF1) {
            out.mnemonic = "cmp";
            out.operands = "byte ptr [rax], 0";
            TypedOperand memory;
            memory.kind = OperandKind::Memory;
            memory.access = OperandAccess::Read;
            memory.baseRegister = "rax";
            memory.widthBits = 8;
            out.typedOperands.push_back(std::move(memory));
            out.registersRead.push_back("rax");
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xF2) {
            out.mnemonic = "je";
            out.operands = "0x" + std::to_string(
                kNetworkServiceImageBase + 0x1165);
            out.isBranch = true;
            out.branchTarget = kNetworkServiceImageBase + 0x1165;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::ConditionalBranch;
            out.flow.directTarget = out.branchTarget;
            out.flow.directTargetValid = true;
            out.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xF3) {
            out.mnemonic = "mov";
            out.operands = "[rsp + 0x20], [rbx]";
            TypedOperand destination;
            destination.kind = OperandKind::Memory;
            destination.access = OperandAccess::Write;
            destination.baseRegister = "rsp";
            destination.displacement = 0x20;
            destination.displacementValid = true;
            destination.widthBits = 64;
            out.typedOperands.push_back(std::move(destination));
            TypedOperand source;
            source.kind = OperandKind::Memory;
            source.access = OperandAccess::Read;
            source.baseRegister = "rbx";
            source.widthBits = 64;
            out.typedOperands.push_back(std::move(source));
            out.registersRead = {"rsp", "rbx"};
        } else if (data[0] == 0xF4) {
            out.mnemonic = "xchg";
            out.operands = "rcx, [rbx]";
            reg(out, "rcx", OperandAccess::ReadWrite);
            TypedOperand memory;
            memory.kind = OperandKind::Memory;
            memory.access = OperandAccess::ReadWrite;
            memory.baseRegister = "rbx";
            memory.widthBits = 64;
            out.typedOperands.push_back(std::move(memory));
            out.registersRead.push_back("rbx");
        } else if (data[0] == 0xF5) {
            out.mnemonic = "test";
            out.operands = "rcx, rcx";
            reg(out, "rcx", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xF6 || data[0] == 0xF7) {
            const uint64_t target = kNetworkServiceImageBase +
                (data[0] == 0xF6 ? 0x116B : 0x1166);
            out.mnemonic = "je";
            out.operands = "0x" + std::to_string(target);
            out.isBranch = true;
            out.branchTarget = target;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::ConditionalBranch;
            out.flow.directTarget = target;
            out.flow.directTargetValid = true;
            out.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
        } else if (data[0] == 0xC3) {
            out.mnemonic = "ret";
            out.isRet = true;
            out.isBranch = true;
            out.flow.kind = FlowKind::Return;
        } else {
            out.mnemonic = "nop";
        }
        return true;
    }
};

// Scripted x64 fixture for the production authorization adapter. Entry calls a
// startup RegGetValue gate and an activation function. The activation function
// reads a network reply, passes its buffer through a direct helper, checks the
// helper return, and writes the exact registry identity only on the allow arm.
struct AuthorizationServiceDisasm : StubDisasm {
    static void reg(Instruction& out, const char* name, OperandAccess access) {
        TypedOperand operand;
        operand.kind = OperandKind::Register;
        operand.access = access;
        operand.registerName = name;
        operand.widthBits = 64;
        out.typedOperands.push_back(std::move(operand));
        if (OperandReads(access)) out.registersRead.push_back(name);
        if (OperandWrites(access)) out.registersWritten.push_back(name);
    }
    static void absoluteMemory(Instruction& out, uint64_t address) {
        TypedOperand operand;
        operand.kind = OperandKind::Memory;
        operand.access = OperandAccess::Read;
        operand.displacement = static_cast<int64_t>(address);
        operand.displacementValid = true;
        out.typedOperands.push_back(std::move(operand));
    }
    static void localMemory(Instruction& out, const char* base,
                            int64_t displacement, OperandAccess access) {
        TypedOperand operand;
        operand.kind = OperandKind::Memory;
        operand.access = access;
        operand.baseRegister = base;
        operand.displacement = displacement;
        operand.displacementValid = true;
        operand.widthBits = 64;
        out.typedOperands.push_back(std::move(operand));
        out.registersRead.push_back(base);
    }
    static void call(Instruction& out, uint64_t target) {
        out.mnemonic = "call";
        out.operands = "0x" + std::to_string(target);
        out.isCall = out.isBranch = true;
        out.branchTarget = target;
        out.branchTargetValid = true;
        out.flow.kind = FlowKind::DirectCall;
        out.flow.directTarget = target;
        out.flow.directTargetValid = true;
    }
    static void branch(Instruction& out, const char* mnemonic, uint64_t target) {
        out.mnemonic = mnemonic;
        out.operands = "0x" + std::to_string(target);
        out.isBranch = true;
        out.branchTarget = target;
        out.branchTargetValid = true;
        out.flow.kind = FlowKind::ConditionalBranch;
        out.flow.directTarget = target;
        out.flow.directTargetValid = true;
        out.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
    }
    static void ret(Instruction& out) {
        out.mnemonic = "ret";
        out.isRet = out.isBranch = true;
        out.flow.kind = FlowKind::Return;
    }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        out = {};
        out.address = va;
        out.length = 1;
        const uint64_t rva = va - kAuthorizationImageBase;
        auto movImm = [&](const char* destination, uint64_t value) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, 0x%llx", destination,
                          static_cast<unsigned long long>(value));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = value;
            out.typedOperands.push_back(std::move(immediate));
        };
        auto leaAbsolute = [&](const char* destination, uint64_t address) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [0x%llx]", destination,
                          static_cast<unsigned long long>(address));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            absoluteMemory(out, address);
        };
        auto leaLocal = [&](const char* destination, int64_t displacement) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [rbp - 0x%llx]", destination,
                          static_cast<unsigned long long>(-displacement));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            localMemory(out, "rbp", displacement, OperandAccess::Read);
        };
        auto movStack = [&](uint64_t offset, const char* source) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text), "[rsp + 0x%llx], %s",
                          static_cast<unsigned long long>(offset), source);
            out.operands = text;
            localMemory(out, "rsp", static_cast<int64_t>(offset),
                        OperandAccess::Write);
            reg(out, source, OperandAccess::Read);
        };
        auto testRax = [&] {
            out.mnemonic = "test";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto xorRax = [&] {
            out.mnemonic = "xor";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::ReadWrite);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto jump = [&](uint64_t target) {
            out.mnemonic = "jmp";
            out.operands = "0x" + std::to_string(target);
            out.isBranch = true;
            out.branchTarget = target;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::UnconditionalBranch;
            out.flow.directTarget = target;
            out.flow.directTargetValid = true;
        };

        if (rva >= 0x158A && rva <= 0x15CA) {
            // Sixty-five distinct path effects exercise the adapter's explicit
            // 64-effect completeness boundary.
            leaAbsolute("rax", kAuthorizationSuccessA);
            return true;
        }

        switch (rva) {
        case 0x1000: call(out, kAuthorizationImageBase + 0x1100); break;
        case 0x1001: call(out, kAuthorizationImageBase + 0x1200); break;
        case 0x1002: call(out, kAuthorizationImageBase + 0x1400); break;
        case 0x1003: call(out, kAuthorizationImageBase + 0x1420); break;
        case 0x1004: call(out, kAuthorizationImageBase + 0x1450); break;
        case 0x1005: call(out, kAuthorizationImageBase + 0x1520); break;
        case 0x1006: call(out, kAuthorizationImageBase + 0x1540); break;
        case 0x1007: call(out, kAuthorizationImageBase + 0x1560); break;
        case 0x1008: call(out, kAuthorizationImageBase + 0x1580); break;
        // Entry/main returns 0 or 1 after a credential comparison. Neither
        // integer has authorization direction without a proven caller contract.
        case 0x1009: movImm("rcx", 1); break;
        case 0x100A: movImm("rdx", 101); break;
        case 0x100B: leaLocal("r8", -0x180); break;
        case 0x100C: movImm("r9", 64); break;
        case 0x100D: call(out, kAuthorizationLocalInputIat); break;
        case 0x100E: leaLocal("rcx", -0x180); break;
        case 0x100F: leaAbsolute("rdx", kAuthorizationExpectedSerial); break;
        case 0x1010: call(out, kAuthorizationStrcmpIat); break;
        case 0x1011: testRax(); break;
        case 0x1012: branch(out, "jne", kAuthorizationImageBase + 0x1016); break;
        case 0x1013: movImm("rax", 1); break;
        case 0x1014: ret(out); break;
        case 0x1016: xorRax(); break;
        case 0x1017: ret(out); break;

        case 0x1100: movImm("rcx", 0x80000001u); break;
        case 0x1101: leaAbsolute("rdx", kAuthorizationSubkey); break;
        case 0x1102: leaAbsolute("r8", kAuthorizationValue); break;
        case 0x1103: movImm("r9", 0); break;
        case 0x1104: movImm("rax", 0); break;
        case 0x1105: movStack(0x20, "rax"); break;
        case 0x1106: leaLocal("rbx", -0x40); break;
        case 0x1107: movStack(0x28, "rbx"); break;
        case 0x1108: leaLocal("rax", -0x48); break;
        case 0x1109: movStack(0x30, "rax"); break;
        case 0x110A: call(out, kAuthorizationRegGetIat); break;
        case 0x110B: testRax(); break;
        case 0x110C: branch(out, "jne", kAuthorizationImageBase + 0x1113); break;
        case 0x110D: leaLocal("rax", -0x40); break;
        case 0x110E: testRax(); break;
        case 0x110F: branch(out, "je", kAuthorizationImageBase + 0x1113); break;
        case 0x1110:
            out.mnemonic = "movzx";
            out.operands = "eax, byte ptr [rbp - 0x40]";
            reg(out, "eax", OperandAccess::Write);
            localMemory(out, "rbp", -0x40, OperandAccess::Read);
            break;
        case 0x1111:
            out.mnemonic = "cmp";
            out.operands = "eax, 1";
            reg(out, "eax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
            break;
        case 0x1112: branch(out, "je", kAuthorizationImageBase + 0x1120); break;
        case 0x1113: xorRax(); break;
        case 0x1114: ret(out); break;
        case 0x1120: leaAbsolute("rax", kAuthorizationSuccessA); break;
        case 0x1121: leaAbsolute("rbx", kAuthorizationSuccessB); break;
        case 0x1122: movImm("rax", 1); break;
        case 0x1123: ret(out); break;

        case 0x1200: movImm("rcx", 1); break;
        case 0x1201: leaLocal("rdx", -0x80); break;
        case 0x1202: movImm("r8", 32); break;
        case 0x1203: leaLocal("r9", -0x88); break;
        case 0x1204: call(out, kAuthorizationReadIat); break;
        case 0x1205: leaLocal("rcx", -0x80); break;
        case 0x1206: call(out, kAuthorizationImageBase + 0x1300); break;
        case 0x1207: testRax(); break;
        case 0x1208: branch(out, "jne", kAuthorizationImageBase + 0x1220); break;
        case 0x1209: xorRax(); break;
        case 0x120A: ret(out); break;
        case 0x1220: movImm("rcx", 0x80000001u); break;
        case 0x1221: leaAbsolute("rdx", kAuthorizationSubkey); break;
        case 0x1222: leaAbsolute("r8", kAuthorizationValue); break;
        case 0x1223: movImm("r9", 1); break;
        case 0x1224: leaLocal("rax", -0x40); break;
        case 0x1225: movStack(0x20, "rax"); break;
        case 0x1226: movImm("rax", 4); break;
        case 0x1227: movStack(0x28, "rax"); break;
        case 0x1228: call(out, kAuthorizationRegSetIat); break;
        case 0x1229: leaAbsolute("rax", kAuthorizationSuccessA); break;
        case 0x122A: leaAbsolute("rbx", kAuthorizationSuccessB); break;
        case 0x122B: movImm("rax", 1); break;
        case 0x122C: ret(out); break;

        case 0x1300:
            out.mnemonic = "mov"; out.operands = "[rbp - 0x8], rcx";
            localMemory(out, "rbp", -8, OperandAccess::Write);
            reg(out, "rcx", OperandAccess::Read);
            break;
        case 0x1301:
            out.mnemonic = "mov"; out.operands = "rax, [rbp - 0x8]";
            reg(out, "rax", OperandAccess::Write);
            localMemory(out, "rbp", -8, OperandAccess::Read);
            break;
        case 0x1302:
            out.mnemonic = "movzx";
            out.operands = "eax, byte ptr [rax]";
            reg(out, "eax", OperandAccess::Write);
            {
                TypedOperand memory;
                memory.kind = OperandKind::Memory;
                memory.access = OperandAccess::Read;
                memory.baseRegister = "rax";
                memory.widthBits = 8;
                out.typedOperands.push_back(std::move(memory));
            }
            out.registersRead.push_back("rax");
            break;
        case 0x1303: ret(out); break;

        case 0x1400:
            out.mnemonic = "mov";
            out.operands = "rdx, rbx";
            reg(out, "rdx", OperandAccess::Write);
            reg(out, "rbx", OperandAccess::Read);
            break;
        case 0x1401: call(out, kAuthorizationReadIat); break;
        case 0x1402:
            out.mnemonic = "cmp";
            out.operands = "byte ptr [rbx], 0x50";
            {
                TypedOperand memory;
                memory.kind = OperandKind::Memory;
                memory.access = OperandAccess::Read;
                memory.baseRegister = "rbx";
                memory.widthBits = 8;
                out.typedOperands.push_back(std::move(memory));
            }
            out.registersRead.push_back("rbx");
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
            break;
        case 0x1403: branch(out, "jne", kAuthorizationImageBase + 0x1410); break;
        case 0x1404: ret(out); break;
        case 0x1410: ret(out); break;

        // The output storage is proven by LEA at the API call.  A later LEA
        // produces only its address and must not become a reply-content gate;
        // the subsequent MOVZX load is genuine content lineage and must stay.
        case 0x1420: movImm("rcx", 1); break;
        case 0x1421: leaLocal("rdx", -0xa0); break;
        case 0x1422: movImm("r8", 32); break;
        case 0x1423: leaLocal("r9", -0xa8); break;
        case 0x1424: call(out, kAuthorizationReadIat); break;
        case 0x1425: leaLocal("rax", -0xa0); break;
        case 0x1426: testRax(); break;
        case 0x1427: branch(out, "je", kAuthorizationImageBase + 0x1429); break;
        case 0x1428: out.mnemonic = "nop"; break;
        case 0x1429:
            out.mnemonic = "movzx";
            out.operands = "eax, byte ptr [rbp - 0xa0]";
            reg(out, "eax", OperandAccess::Write);
            localMemory(out, "rbp", -0xa0, OperandAccess::Read);
            break;
        case 0x142A:
            out.mnemonic = "cmp";
            out.operands = "eax, 0x51";
            reg(out, "eax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
            break;
        case 0x142B: branch(out, "jne", kAuthorizationImageBase + 0x1430); break;
        case 0x142C: ret(out); break;
        case 0x1430: ret(out); break;

        // This helper receives the proven reply-buffer pointer but never
        // dereferences it.  Its unrelated constant return controls a caller
        // branch and must not become a reply-content decision.
        case 0x1450: movImm("rcx", 1); break;
        case 0x1451: leaLocal("rdx", -0xc0); break;
        case 0x1452: movImm("r8", 32); break;
        case 0x1453: leaLocal("r9", -0xc8); break;
        case 0x1454: call(out, kAuthorizationReadIat); break;
        case 0x1455: leaLocal("rcx", -0xc0); break;
        case 0x1456: call(out, kAuthorizationImageBase + 0x1500); break;
        case 0x1457: testRax(); break;
        case 0x1458: branch(out, "jne", kAuthorizationImageBase + 0x1460); break;
        case 0x1459: ret(out); break;
        case 0x1460: ret(out); break;
        case 0x1500: movImm("rax", 1); break;
        case 0x1501: ret(out); break;

        // Common local crackme shape: a dialog edit control fills a fixed
        // stack buffer, strcmp consumes that exact origin plus a static serial,
        // and the adjacent branch selects the accept/reject path.
        case 0x1520: movImm("rcx", 1); break;
        case 0x1521: movImm("rdx", 100); break;
        case 0x1522: leaLocal("r8", -0x100); break;
        case 0x1523: movImm("r9", 64); break;
        case 0x1524: call(out, kAuthorizationLocalInputIat); break;
        case 0x1525: leaLocal("rcx", -0x100); break;
        case 0x1526: leaAbsolute("rdx", kAuthorizationExpectedSerial); break;
        case 0x1527: call(out, kAuthorizationStrcmpIat); break;
        case 0x1528: testRax(); break;
        case 0x1529: branch(out, "jne", kAuthorizationImageBase + 0x1534); break;
        case 0x152A: leaAbsolute("rax", kAuthorizationSuccessA); break;
        case 0x152B: leaAbsolute("rbx", kAuthorizationSuccessB); break;
        case 0x152C: movImm("rax", 1); break;
        case 0x152D: ret(out); break;
        // A denial dialog is not protected-application continuation. Even its
        // generic return value of one remains direction-neutral.
        case 0x1534: leaAbsolute("rdx", kAuthorizationFailureText); break;
        case 0x1535: call(out, kAuthorizationDialogIat); break;
        case 0x1536: movImm("rax", 1); break;
        case 0x1537: ret(out); break;

        // A reply buffer reaches an unrelated.dll!strcmp lookalike. Exact
        // module+symbol validation must reject it as an equality contract.
        case 0x1540: movImm("rcx", 1); break;
        case 0x1541: leaLocal("rdx", -0x140); break;
        case 0x1542: movImm("r8", 32); break;
        case 0x1543: leaLocal("r9", -0x148); break;
        case 0x1544: call(out, kAuthorizationReadIat); break;
        case 0x1545: leaLocal("rcx", -0x140); break;
        case 0x1546: leaAbsolute("rdx", kAuthorizationExpectedSerial); break;
        case 0x1547: call(out, kAuthorizationHostileStrcmpIat); break;
        case 0x1548: testRax(); break;
        case 0x1549: branch(out, "jne", kAuthorizationImageBase + 0x1550); break;
        case 0x154A: ret(out); break;
        case 0x1550: ret(out); break;

        // The two decision edges reconverge at 0x1578. Shared-tail success
        // strings must not be attributed to either edge; the paired scanner's
        // decision-block exclusion is the corresponding back-edge boundary.
        case 0x1560: movImm("rcx", 1); break;
        case 0x1561: movImm("rdx", 102); break;
        case 0x1562: leaLocal("r8", -0x1c0); break;
        case 0x1563: movImm("r9", 64); break;
        case 0x1564: call(out, kAuthorizationLocalInputIat); break;
        case 0x1565: leaLocal("rcx", -0x1c0); break;
        case 0x1566: leaAbsolute("rdx", kAuthorizationExpectedSerial); break;
        case 0x1567: call(out, kAuthorizationStrcmpIat); break;
        case 0x1568: testRax(); break;
        case 0x1569: branch(out, "jne", kAuthorizationImageBase + 0x1570); break;
        case 0x156A: jump(kAuthorizationImageBase + 0x1578); break;
        case 0x1570: jump(kAuthorizationImageBase + 0x1578); break;
        case 0x1578: leaAbsolute("rax", kAuthorizationSuccessA); break;
        case 0x1579: leaAbsolute("rbx", kAuthorizationSuccessB); break;
        case 0x157A: ret(out); break;

        // One branch contains 65 distinct success-text references; retaining
        // only 64 must surface path incompleteness instead of a silent verdict.
        case 0x1580: movImm("rcx", 1); break;
        case 0x1581: movImm("rdx", 103); break;
        case 0x1582: leaLocal("r8", -0x200); break;
        case 0x1583: movImm("r9", 64); break;
        case 0x1584: call(out, kAuthorizationLocalInputIat); break;
        case 0x1585: leaLocal("rcx", -0x200); break;
        case 0x1586: leaAbsolute("rdx", kAuthorizationExpectedSerial); break;
        case 0x1587: call(out, kAuthorizationStrcmpIat); break;
        case 0x1588: testRax(); break;
        case 0x1589: branch(out, "jne", kAuthorizationImageBase + 0x15F8); break;
        case 0x15CB: ret(out); break;
        case 0x15F8: xorRax(); break;
        case 0x15F9: ret(out); break;
        default:
            out.mnemonic = "nop";
            break;
        }
        return true;
    }
};

// Clean production-adapter fixture for secondary-gate recovery.  An exact
// persisted-entitlement read proves the first predicate call is on its allow
// arm.  That predicate's true arm calls a helper, and only inside that helper
// does a second predicate guard the protected operation.
struct InterprocAuthorizationServiceDisasm : AuthorizationServiceDisasm {
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        out = {};
        out.address = va;
        out.length = 1;
        const uint64_t rva = va - kAuthorizationImageBase;
        auto movImm = [&](const char* destination, uint64_t value) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, 0x%llx", destination,
                          static_cast<unsigned long long>(value));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = value;
            out.typedOperands.push_back(std::move(immediate));
        };
        auto leaAbsolute = [&](const char* destination, uint64_t address) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [0x%llx]", destination,
                          static_cast<unsigned long long>(address));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            absoluteMemory(out, address);
        };
        auto leaLocal = [&](const char* destination, int64_t displacement) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [rbp - 0x%llx]", destination,
                          static_cast<unsigned long long>(-displacement));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            localMemory(out, "rbp", displacement, OperandAccess::Read);
        };
        auto movStack = [&](uint64_t offset, const char* source) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text), "[rsp + 0x%llx], %s",
                          static_cast<unsigned long long>(offset), source);
            out.operands = text;
            localMemory(out, "rsp", static_cast<int64_t>(offset),
                        OperandAccess::Write);
            reg(out, source, OperandAccess::Read);
        };
        auto testRax = [&] {
            out.mnemonic = "test";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto xorRax = [&] {
            out.mnemonic = "xor";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::ReadWrite);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };

        switch (rva) {
        case 0x1000: call(out, kAuthorizationImageBase + 0x1100); break;
        case 0x1001: ret(out); break;

        // Exact persisted-entitlement read (`isPro`) and byte-value gate.
        case 0x1100: movImm("rcx", 0x80000001u); break;
        case 0x1101: leaAbsolute("rdx", kAuthorizationSubkey); break;
        case 0x1102: leaAbsolute("r8", kAuthorizationValue); break;
        case 0x1103: movImm("r9", 0); break;
        case 0x1104: movImm("rax", 0); break;
        case 0x1105: movStack(0x20, "rax"); break;
        case 0x1106: leaLocal("rbx", -0x40); break;
        case 0x1107: movStack(0x28, "rbx"); break;
        case 0x1108: leaLocal("rax", -0x48); break;
        case 0x1109: movStack(0x30, "rax"); break;
        case 0x110A: call(out, kAuthorizationRegGetIat); break;
        case 0x110B: testRax(); break;
        case 0x110C:
            branch(out, "jne", kAuthorizationImageBase + 0x1113); break;
        case 0x110D: leaLocal("rax", -0x40); break;
        case 0x110E: testRax(); break;
        case 0x110F:
            branch(out, "je", kAuthorizationImageBase + 0x1113); break;
        case 0x1110:
            out.mnemonic = "movzx";
            out.operands = "eax, byte ptr [rbp - 0x40]";
            reg(out, "eax", OperandAccess::Write);
            localMemory(out, "rbp", -0x40, OperandAccess::Read);
            break;
        case 0x1111:
            out.mnemonic = "cmp";
            out.operands = "eax, 1";
            reg(out, "eax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
            break;
        case 0x1112:
            branch(out, "je", kAuthorizationImageBase + 0x1120); break;
        case 0x1113: leaAbsolute("rax", kAuthorizationFailureText); break;
        case 0x1114: leaAbsolute("rbx", kAuthorizationFailureText); break;
        case 0x1115: xorRax(); break;
        case 0x1116: ret(out); break;
        case 0x1120: leaAbsolute("rax", kAuthorizationSuccessA); break;
        case 0x1121: leaAbsolute("rbx", kAuthorizationSuccessB); break;
        case 0x1122: call(out, kAuthorizationImageBase + 0x1500); break;
        case 0x1123: testRax(); break;
        case 0x1124:
            branch(out, "je", kAuthorizationImageBase + 0x112A); break;
        case 0x1125: call(out, kAuthorizationImageBase + 0x1200); break;
        case 0x1126: movImm("rax", 1); break;
        case 0x1127: ret(out); break;
        case 0x112A: xorRax(); break;
        case 0x112B: ret(out); break;

        case 0x1200: call(out, kAuthorizationImageBase + 0x1300); break;
        case 0x1201: testRax(); break;
        case 0x1202:
            branch(out, "je", kAuthorizationImageBase + 0x1207); break;
        case 0x1203: call(out, kAuthorizationImageBase + 0x1400); break;
        case 0x1204: movImm("rax", 1); break;
        case 0x1205: ret(out); break;
        case 0x1207: xorRax(); break;
        case 0x1208: ret(out); break;

        case 0x1300: movImm("rax", 1); break;
        case 0x1301: ret(out); break;

        // This callee deliberately leaves RAX unproved, so it remains an
        // operation rather than a third boolean predicate.
        case 0x1400: movImm("rcx", 2); break;
        case 0x1401: ret(out); break;

        case 0x1500: movImm("rax", 1); break;
        case 0x1501: ret(out); break;
        default: out.mnemonic = "nop"; break;
        }
        return true;
    }
};

// Negative control for the paired closure: the same helper is also invoked by
// the global predicate's false arm, so the nested predicate is not exclusive.
struct SharedInterprocAuthorizationServiceDisasm final
    : InterprocAuthorizationServiceDisasm {
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        const uint64_t rva = va - kAuthorizationImageBase;
        if (rva == 0x112A) {
            out = {};
            out.address = va;
            out.length = 1;
            call(out, kAuthorizationImageBase + 0x1200);
            return true;
        }
        if (rva == 0x112B) {
            out = {};
            out.address = va;
            out.length = 1;
            out.mnemonic = "xor";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::ReadWrite);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
            return true;
        }
        if (rva == 0x112C) {
            out = {};
            out.address = va;
            out.length = 1;
            ret(out);
            return true;
        }
        return InterprocAuthorizationServiceDisasm::decodeOne(
            data, size, va, out);
    }
};

// Production-shaped fixture for the Authorization Trail adapter's strongest
// field-source and protected-operation claims.  Three independent object
// fields deliberately exercise: a local-format-only allow arm, an unconverted
// zero-is-success verifier status, and a verifier-success-only materialization.
// The final predicate also guards both a durable license/config write and an
// exact DLL-qualified state-changing API so those operation classes cannot be
// conflated.
struct AuthorizationProvenanceServiceDisasm final
    : AuthorizationServiceDisasm {
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        out = {};
        out.address = va;
        out.length = 1;
        const uint64_t rva = va - kAuthorizationImageBase;

        auto movImm = [&](const char* destination, uint64_t value) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, 0x%llx", destination,
                          static_cast<unsigned long long>(value));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = value;
            out.typedOperands.push_back(std::move(immediate));
        };
        auto movReg = [&](const char* destination, const char* source) {
            out.mnemonic = "mov";
            out.operands = std::string(destination) + ", " + source;
            reg(out, destination, OperandAccess::Write);
            reg(out, source, OperandAccess::Read);
        };
        auto leaAbsolute = [&](const char* destination, uint64_t address) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [0x%llx]", destination,
                          static_cast<unsigned long long>(address));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            absoluteMemory(out, address);
        };
        auto leaLocal = [&](const char* destination, int64_t displacement) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [rbp - 0x%llx]", destination,
                          static_cast<unsigned long long>(-displacement));
            out.operands = text;
            reg(out, destination, OperandAccess::Write);
            localMemory(out, "rbp", displacement, OperandAccess::Read);
        };
        auto testRax = [&] {
            out.mnemonic = "test";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::Read);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto xorRax = [&] {
            out.mnemonic = "xor";
            out.operands = "rax, rax";
            reg(out, "rax", OperandAccess::ReadWrite);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto fieldMemory = [&](const char* base, int64_t displacement,
                               OperandAccess access) {
            TypedOperand memory;
            memory.kind = OperandKind::Memory;
            memory.access = access;
            memory.baseRegister = base;
            memory.displacement = displacement;
            memory.displacementValid = true;
            memory.widthBits = 8;
            out.typedOperands.push_back(std::move(memory));
            out.registersRead.push_back(base);
        };
        auto storeFieldImmediate = [&](int64_t displacement) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text),
                          "byte ptr [rbx + 0x%llx], 1",
                          static_cast<unsigned long long>(displacement));
            out.operands = text;
            fieldMemory("rbx", displacement, OperandAccess::Write);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = 1;
            immediate.widthBits = 8;
            out.typedOperands.push_back(std::move(immediate));
        };
        auto storeFieldAl = [&](int64_t displacement) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text),
                          "byte ptr [rbx + 0x%llx], al",
                          static_cast<unsigned long long>(displacement));
            out.operands = text;
            fieldMemory("rbx", displacement, OperandAccess::Write);
            reg(out, "al", OperandAccess::Read);
        };
        auto readField = [&](int64_t displacement) {
            out.mnemonic = "movzx";
            char text[96]{};
            std::snprintf(text, sizeof(text),
                          "eax, byte ptr [rcx + 0x%llx]",
                          static_cast<unsigned long long>(displacement));
            out.operands = text;
            reg(out, "eax", OperandAccess::Write);
            fieldMemory("rcx", displacement, OperandAccess::Read);
        };

        switch (rva) {
        case 0x1000: call(out, kAuthorizationImageBase + 0x1100); break;
        case 0x1001: call(out, kAuthorizationImageBase + 0x1300); break;
        case 0x1002: call(out, kAuthorizationImageBase + 0x1500); break;
        // A second predicate reads the same verified field, but is called from
        // an unrelated entry path rather than from the materializing store.
        // Exact field equality must not inherit the store-to-0x1580 proof.
        case 0x1003: call(out, kAuthorizationImageBase + 0x1590); break;
        case 0x1004: ret(out); break;

        // Exact local input and equality comparison, but no reply, verifier,
        // or persisted-entitlement source.  The field write must stay visible
        // without source-linking the predicate which reads it.
        case 0x1100: movReg("rbx", "rcx"); break;
        case 0x1101: movImm("rcx", 1); break;
        case 0x1102: movImm("rdx", 100); break;
        case 0x1103: leaLocal("r8", -0x100); break;
        case 0x1104: movImm("r9", 64); break;
        case 0x1105: call(out, kAuthorizationLocalInputIat); break;
        case 0x1106: leaLocal("rcx", -0x100); break;
        case 0x1107: leaAbsolute("rdx", kAuthorizationExpectedSerial); break;
        case 0x1108: call(out, kAuthorizationStrcmpIat); break;
        case 0x1109: testRax(); break;
        case 0x110A:
            branch(out, "jne", kAuthorizationImageBase + 0x1130); break;
        case 0x110B: leaAbsolute("rax", kAuthorizationSuccessA); break;
        case 0x110C: leaAbsolute("rdx", kAuthorizationSuccessB); break;
        case 0x110D: storeFieldImmediate(0x110); break;
        case 0x110E: movReg("rcx", "rbx"); break;
        case 0x110F: call(out, kAuthorizationImageBase + 0x1200); break;
        case 0x1110: testRax(); break;
        case 0x1111:
            branch(out, "je", kAuthorizationImageBase + 0x1130); break;
        // Exact protected API on the true arm of the local-format-derived,
        // authorization-unlinked field predicate.  Its operation stays
        // visible, but must not support Feature permitted.
        case 0x1112:
            call(out, kAuthorizationProvenanceProtectedIat); break;
        case 0x1113: movImm("rax", 1); break;
        case 0x1114: ret(out); break;
        case 0x1130: leaAbsolute("rdx", kAuthorizationFailureText); break;
        case 0x1131: xorRax(); break;
        case 0x1132: ret(out); break;
        case 0x1200: readField(0x110); break;
        case 0x1201: ret(out); break;

        // BCryptVerifySignature returns zero on success.  Storing AL directly
        // would store zero for success, so this cannot prove a nonzero-is-true
        // field even though the raw status has exact verifier provenance.
        case 0x1300: movReg("rbx", "rcx"); break;
        case 0x1301: movImm("rcx", 1); break;
        case 0x1302: movImm("rdx", 0); break;
        case 0x1303: leaLocal("r8", -0x80); break;
        case 0x1304: movImm("r9", 32); break;
        case 0x1305: call(out, kAuthorizationProvenanceVerifyIat); break;
        case 0x1306: storeFieldAl(0x120); break;
        case 0x1307: movReg("rcx", "rbx"); break;
        case 0x1308: call(out, kAuthorizationImageBase + 0x1400); break;
        case 0x1309: testRax(); break;
        case 0x130A:
            branch(out, "je", kAuthorizationImageBase + 0x1320); break;
        case 0x130B: movImm("rax", 1); break;
        case 0x130C: ret(out); break;
        case 0x1320: xorRax(); break;
        case 0x1321: ret(out); break;
        case 0x1400: readField(0x120); break;
        case 0x1401: ret(out); break;

        // Here the exact zero-is-success status controls a branch and only its
        // success edge materializes logical true in the field.  That predicate
        // then gates a persistent config write and a distinct protected action.
        case 0x1500: movReg("rbx", "rcx"); break;
        case 0x1501: movImm("rcx", 1); break;
        case 0x1502: movImm("rdx", 0); break;
        case 0x1503: leaLocal("r8", -0xc0); break;
        case 0x1504: movImm("r9", 32); break;
        case 0x1505: call(out, kAuthorizationProvenanceVerifyIat); break;
        case 0x1506: testRax(); break;
        case 0x1507:
            branch(out, "jne", kAuthorizationImageBase + 0x1530); break;
        case 0x1508: storeFieldImmediate(0x138); break;
        case 0x1509: movReg("rcx", "rbx"); break;
        case 0x150A: call(out, kAuthorizationImageBase + 0x1580); break;
        case 0x150B: testRax(); break;
        case 0x150C:
            branch(out, "je", kAuthorizationImageBase + 0x1530); break;
        case 0x150D: movImm("rcx", 0x80000001u); break;
        case 0x150E: leaAbsolute("rdx", kAuthorizationValue); break;
        case 0x150F: movImm("r8", 0); break;
        case 0x1510: movImm("r9", 1); break;
        case 0x1511:
            call(out, kAuthorizationProvenanceRegSetValueIat); break;
        case 0x1512:
            call(out, kAuthorizationProvenanceHostileProtectedIat); break;
        case 0x1513:
            call(out, kAuthorizationProvenanceProtectedIat); break;
        case 0x1514: movImm("rax", 1); break;
        case 0x1515: ret(out); break;
        case 0x1530: xorRax(); break;
        case 0x1531: ret(out); break;
        case 0x1580: readField(0x138); break;
        case 0x1581: ret(out); break;
        case 0x1590: readField(0x138); break;
        case 0x1591: ret(out); break;

        default: out.mnemonic = "nop"; break;
        }
        return true;
    }
};

enum class MachineBindingVariant : uint8_t {
    Positive = 0,
    OverwrittenOutput,
    ContentAsPointer,
    ZeroLength,
    WrongLength,
    WrongVerifierPolarity,
    UnrelatedVerifierBranch,
    IncompleteScope,
    WrongMachineDll,
};

// Production-shaped machine-binding fixture. A typed persisted `isPro` read is
// the strong authorization source. On its allow arm, GetVolumeInformationW
// writes a DWORD volume serial to a direct stack address; only the positive
// variant preserves exactly those four bytes into BCryptVerifySignature and
// lets BCrypt's documented success arm alone reach CreateServiceW.
struct MachineBindingServiceDisasm final : AuthorizationServiceDisasm {
    explicit MachineBindingServiceDisasm(MachineBindingVariant selected)
        : variant(selected) {}

    MachineBindingVariant variant = MachineBindingVariant::Positive;

    static void typedReg(Instruction& out, const char* name,
                         OperandAccess access, uint16_t widthBits) {
        TypedOperand operand;
        operand.kind = OperandKind::Register;
        operand.access = access;
        operand.registerName = name;
        operand.widthBits = widthBits;
        out.typedOperands.push_back(std::move(operand));
        if (OperandReads(access)) out.registersRead.push_back(name);
        if (OperandWrites(access)) out.registersWritten.push_back(name);
    }

    static void typedMemory(Instruction& out, const char* base,
                            int64_t displacement, OperandAccess access,
                            uint16_t widthBits) {
        TypedOperand operand;
        operand.kind = OperandKind::Memory;
        operand.access = access;
        operand.baseRegister = base;
        operand.displacement = displacement;
        operand.displacementValid = true;
        operand.widthBits = widthBits;
        out.typedOperands.push_back(std::move(operand));
        out.registersRead.push_back(base);
    }

    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        const uint64_t rva = va - kAuthorizationImageBase;
        out = {};
        out.address = va;
        out.length = 1;

        auto widthFor = [](std::string_view name) -> uint16_t {
            return name == "eax" || name == "ecx" || name == "edx" ||
                   name == "r8d" || name == "r9d" ? 32 : 64;
        };
        auto movImm = [&](const char* destination, uint64_t value) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, 0x%llx", destination,
                          static_cast<unsigned long long>(value));
            out.operands = text;
            typedReg(out, destination, OperandAccess::Write,
                     widthFor(destination));
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = value;
            immediate.widthBits = widthFor(destination);
            out.typedOperands.push_back(std::move(immediate));
        };
        auto xorReg = [&](const char* name) {
            out.mnemonic = "xor";
            out.operands = std::string(name) + ", " + name;
            typedReg(out, name, OperandAccess::ReadWrite, widthFor(name));
            typedReg(out, name, OperandAccess::Read, widthFor(name));
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto leaAbsolute = [&](const char* destination, uint64_t address) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [0x%llx]", destination,
                          static_cast<unsigned long long>(address));
            out.operands = text;
            typedReg(out, destination, OperandAccess::Write, 64);
            absoluteMemory(out, address);
        };
        auto leaRbp = [&](const char* destination, int64_t displacement) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [rbp - 0x%llx]",
                          destination,
                          static_cast<unsigned long long>(-displacement));
            out.operands = text;
            typedReg(out, destination, OperandAccess::Write, 64);
            typedMemory(out, "rbp", displacement, OperandAccess::Read, 64);
        };
        auto leaRsp = [&](const char* destination, int64_t displacement) {
            out.mnemonic = "lea";
            char text[96]{};
            std::snprintf(text, sizeof(text), "%s, [rsp + 0x%llx]",
                          destination,
                          static_cast<unsigned long long>(displacement));
            out.operands = text;
            typedReg(out, destination, OperandAccess::Write, 64);
            typedMemory(out, "rsp", displacement, OperandAccess::Read, 64);
        };
        auto movStack = [&](int64_t displacement, const char* source) {
            out.mnemonic = "mov";
            char text[96]{};
            std::snprintf(text, sizeof(text), "[rsp + 0x%llx], %s",
                          static_cast<unsigned long long>(displacement), source);
            out.operands = text;
            typedMemory(out, "rsp", displacement, OperandAccess::Write, 64);
            typedReg(out, source, OperandAccess::Read, widthFor(source));
        };
        auto testEax = [&] {
            out.mnemonic = "test";
            out.operands = "eax, eax";
            typedReg(out, "eax", OperandAccess::Read, 32);
            typedReg(out, "eax", OperandAccess::Read, 32);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto cmpEaxOne = [&] {
            out.mnemonic = "cmp";
            out.operands = "eax, 1";
            typedReg(out, "eax", OperandAccess::Read, 32);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = 1;
            immediate.widthBits = 32;
            out.typedOperands.push_back(std::move(immediate));
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        };
        auto movzxPersistedByte = [&] {
            out.mnemonic = "movzx";
            out.operands = "eax, byte ptr [rbp - 0x40]";
            typedReg(out, "eax", OperandAccess::Write, 32);
            typedMemory(out, "rbp", -0x40, OperandAccess::Read, 8);
        };
        auto overwriteOutput = [&] {
            out.mnemonic = "mov";
            out.operands = "dword ptr [rsp + 0x80], 0";
            typedMemory(out, "rsp", 0x80, OperandAccess::Write, 32);
            TypedOperand immediate;
            immediate.kind = OperandKind::Immediate;
            immediate.access = OperandAccess::Read;
            immediate.immediate = 0;
            immediate.widthBits = 32;
            out.typedOperands.push_back(std::move(immediate));
        };
        auto contentAsPointer = [&] {
            out.mnemonic = "mov";
            out.operands = "r8d, dword ptr [rsp + 0x80]";
            typedReg(out, "r8d", OperandAccess::Write, 32);
            typedMemory(out, "rsp", 0x80, OperandAccess::Read, 32);
        };

        switch (rva) {
        case 0x1000: call(out, kAuthorizationImageBase + 0x1100); break;
        case 0x1001: ret(out); break;

        // Exact typed persisted entitlement source and allow/deny split.
        case 0x1100: movImm("rcx", 0x80000001u); break;
        case 0x1101: leaAbsolute("rdx", kAuthorizationSubkey); break;
        case 0x1102: leaAbsolute("r8", kAuthorizationValue); break;
        case 0x1103: movImm("r9", 0); break;
        case 0x1104: xorReg("rax"); break;
        case 0x1105: movStack(0x20, "rax"); break;
        case 0x1106: leaRbp("rbx", -0x40); break;
        case 0x1107: movStack(0x28, "rbx"); break;
        case 0x1108: leaRbp("rax", -0x48); break;
        case 0x1109: movStack(0x30, "rax"); break;
        case 0x110A: call(out, kAuthorizationMachineRegGetIat); break;
        case 0x110B: testEax(); break;
        case 0x110C:
            branch(out, "jne", kAuthorizationImageBase + 0x1113); break;
        case 0x110D: leaRbp("rax", -0x40); break;
        case 0x110E:
            out.mnemonic = "test";
            out.operands = "rax, rax";
            typedReg(out, "rax", OperandAccess::Read, 64);
            typedReg(out, "rax", OperandAccess::Read, 64);
            out.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
            break;
        case 0x110F:
            branch(out, "je", kAuthorizationImageBase + 0x1113); break;
        case 0x1110: movzxPersistedByte(); break;
        case 0x1111: cmpEaxOne(); break;
        case 0x1112:
            branch(out, "je", kAuthorizationImageBase + 0x1120); break;
        case 0x1113: leaAbsolute("rax", kAuthorizationFailureText); break;
        case 0x1114: leaAbsolute("rbx", kAuthorizationFailureText); break;
        case 0x1115: xorReg("eax"); break;
        case 0x1116: ret(out); break;

        // Fixed DWORD machine output followed by an exact status partition.
        case 0x1120: leaAbsolute("rax", kAuthorizationSuccessA); break;
        case 0x1121: leaAbsolute("rbx", kAuthorizationSuccessB); break;
        case 0x1122: xorReg("rax"); break;
        case 0x1123: movStack(0x20, "rax"); break;
        case 0x1124: movStack(0x28, "rax"); break;
        case 0x1125: movStack(0x30, "rax"); break;
        case 0x1126: movStack(0x38, "rax"); break;
        case 0x1127: xorReg("rcx"); break;
        case 0x1128: xorReg("rdx"); break;
        case 0x1129: xorReg("r8"); break;
        case 0x112A: leaRsp("r9", 0x80); break;
        case 0x112B:
            call(out,
                 variant == MachineBindingVariant::WrongMachineDll
                     ? kAuthorizationHostileMachineIdentityIat
                     : kAuthorizationMachineIdentityIat);
            break;
        case 0x112C: testEax(); break;
        case 0x112D:
            branch(out, "je", kAuthorizationImageBase + 0x1190); break;
        case 0x112E:
            if (variant == MachineBindingVariant::OverwrittenOutput)
                overwriteOutput();
            else
                out.mnemonic = "nop";
            break;

        // BCryptVerifySignature(message=&slot, cbMessage=4), except for the
        // explicitly hostile pointer/extent variants.
        case 0x112F: movImm("rcx", 1); break;
        case 0x1130: xorReg("rdx"); break;
        case 0x1131:
            if (variant == MachineBindingVariant::ContentAsPointer)
                contentAsPointer();
            else
                leaRsp("r8", 0x80);
            break;
        case 0x1132:
            movImm("r9",
                variant == MachineBindingVariant::ZeroLength ? 0 :
                variant == MachineBindingVariant::WrongLength ? 8 : 4);
            break;
        case 0x1133: leaRsp("rax", 0xC0); break;
        case 0x1134: movStack(0x20, "rax"); break;
        case 0x1135: movImm("rax", 64); break;
        case 0x1136: movStack(0x28, "rax"); break;
        case 0x1137: xorReg("rax"); break;
        case 0x1138: movStack(0x30, "rax"); break;
        case 0x1139: call(out, kAuthorizationProvenanceVerifyIat); break;
        case 0x113A:
            if (variant == MachineBindingVariant::WrongVerifierPolarity)
                cmpEaxOne();
            else
                testEax();
            break;
        case 0x113B:
            if (variant == MachineBindingVariant::WrongVerifierPolarity)
                branch(out, "jne", kAuthorizationImageBase + 0x1140);
            else
                branch(out, "jne", kAuthorizationImageBase + 0x1190);
            break;
        case 0x113C:
            if (variant == MachineBindingVariant::UnrelatedVerifierBranch)
                out.mnemonic = "nop";
            else if (variant == MachineBindingVariant::WrongVerifierPolarity)
                xorReg("eax");
            else
                call(out, kAuthorizationProvenanceProtectedIat);
            break;
        case 0x113D:
            if (variant == MachineBindingVariant::WrongVerifierPolarity)
                ret(out);
            else if (variant == MachineBindingVariant::IncompleteScope) {
                out.mnemonic = "jmp";
                out.operands = "0x" + std::to_string(
                    kAuthorizationImageBase + 0x1800);
                out.isBranch = true;
                out.branchTarget = kAuthorizationImageBase + 0x1800;
                out.branchTargetValid = true;
                out.flow.kind = FlowKind::UnconditionalBranch;
                out.flow.directTarget = out.branchTarget;
                out.flow.directTargetValid = true;
            }
            else
                movImm("eax", 1);
            break;
        case 0x113E: ret(out); break;

        // The wrong-polarity target deliberately contains the protected call:
        // `eax != 1` includes both zero-success and unrelated nonzero errors.
        case 0x1140: call(out, kAuthorizationProvenanceProtectedIat); break;
        case 0x1141: movImm("eax", 1); break;
        case 0x1142: ret(out); break;

        case 0x1190: leaAbsolute("rdx", kAuthorizationFailureText); break;
        case 0x1191: xorReg("eax"); break;
        case 0x1192: ret(out); break;
        default: out.mnemonic = "nop"; break;
        }
        return true;
    }
};

// Recognizes return bytes so the raw entry cannot linearly reach later code.
// A code-pointer table is therefore the only evidence for the other entries.
struct PointerSeedDisasm : StubDisasm {
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || !size) return false;
        out = Instruction{};
        out.address = va;
        out.length = 1;
        if (data[0] == 0xC3) {
            out.mnemonic = "ret";
            out.isRet = true;
            out.isBranch = true;
        } else {
            out.mnemonic = "nop";
        }
        return true;
    }
};

static std::string writeTempBlob() {
    std::string path = "ds_anajobs_tmp.bin";
    std::ofstream f(path, std::ios::binary);
    char z = 0; char ff = (char)0xFF;             // 0xFF: non-printable, non-zero separator
    const char* ascii = "Hello, world!";          // ASCII run at offset 0
    f.write(ascii, (std::streamsize)std::strlen(ascii));
    f.write(&ff, 1);
    f.write("no", 2); f.write(&ff, 1);            // < 4 chars: ignored (FF stops a wide chain)
    for (const char* s = "Wide"; *s; ++s) { f.write(s, 1); f.write(&z, 1); }  // UTF-16LE "Wide"
    f.write(&ff, 1);                              // terminate the wide run (non-zero)
    return path;
}

template <typename T>
static void putFixture(std::vector<uint8_t>& bytes, size_t offset, T value) {
    CHECK(offset <= bytes.size() && sizeof(value) <= bytes.size() - offset,
          "ABI fixture write is in bounds");
    if (offset <= bytes.size() && sizeof(value) <= bytes.size() - offset)
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static std::vector<uint8_t> buildAbiPe64() {
    std::vector<uint8_t> bytes(0x600, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    putFixture<uint32_t>(bytes, 0x3c, pe);
    putFixture<uint32_t>(bytes, pe, 0x00004550u);
    const size_t coff = pe + 4;
    putFixture<uint16_t>(bytes, coff + 0, 0x8664); // AMD64
    putFixture<uint16_t>(bytes, coff + 2, 1);
    putFixture<uint16_t>(bytes, coff + 16, 0xf0);
    putFixture<uint16_t>(bytes, coff + 18, 0x22);
    const size_t opt = coff + 20;
    putFixture<uint16_t>(bytes, opt + 0, 0x20b);
    putFixture<uint32_t>(bytes, opt + 16, 0x1000);
    putFixture<uint64_t>(bytes, opt + 24, 0x140000000ull);
    putFixture<uint32_t>(bytes, opt + 32, 0x1000);
    putFixture<uint32_t>(bytes, opt + 36, 0x200);
    putFixture<uint32_t>(bytes, opt + 56, 0x2000);
    putFixture<uint32_t>(bytes, opt + 60, 0x400);
    putFixture<uint32_t>(bytes, opt + 108, 16);
    const size_t section = opt + 0xf0;
    std::memcpy(bytes.data() + section, ".text\0\0\0", 8);
    putFixture<uint32_t>(bytes, section + 8, 0x200);
    putFixture<uint32_t>(bytes, section + 12, 0x1000);
    putFixture<uint32_t>(bytes, section + 16, 0x200);
    putFixture<uint32_t>(bytes, section + 20, 0x400);
    putFixture<uint32_t>(bytes, section + 36, 0x60000020u);
    bytes[0x400] = 0xc3;
    return bytes;
}

static std::vector<uint8_t> buildNetworkServicePe64(
    bool includeEndpoint = true, bool includeSendCall = true,
    bool includeDuplicateEndpoint = false) {
    std::vector<uint8_t> bytes(0xC00, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    putFixture<uint32_t>(bytes, 0x3c, pe);
    putFixture<uint32_t>(bytes, pe, 0x00004550u);
    const size_t coff = pe + 4;
    putFixture<uint16_t>(bytes, coff + 0, 0x8664);
    putFixture<uint16_t>(bytes, coff + 2, 2);
    putFixture<uint16_t>(bytes, coff + 16, 0xf0);
    putFixture<uint16_t>(bytes, coff + 18, 0x22);
    const size_t opt = coff + 20;
    putFixture<uint16_t>(bytes, opt + 0, 0x20b);
    putFixture<uint32_t>(bytes, opt + 16, 0x1000);
    putFixture<uint64_t>(bytes, opt + 24, kNetworkServiceImageBase);
    putFixture<uint32_t>(bytes, opt + 32, 0x1000);
    putFixture<uint32_t>(bytes, opt + 36, 0x200);
    putFixture<uint32_t>(bytes, opt + 56, 0x3000);
    putFixture<uint32_t>(bytes, opt + 60, 0x400);
    putFixture<uint32_t>(bytes, opt + 108, 16);
    // Import data directory [1].
    putFixture<uint32_t>(bytes, opt + 120, 0x2100);
    putFixture<uint32_t>(bytes, opt + 124, 0x40);

    const size_t text = opt + 0xf0;
    std::memcpy(bytes.data() + text, ".text\0\0\0", 8);
    putFixture<uint32_t>(bytes, text + 8, 0x200);
    putFixture<uint32_t>(bytes, text + 12, 0x1000);
    putFixture<uint32_t>(bytes, text + 16, 0x200);
    putFixture<uint32_t>(bytes, text + 20, 0x400);
    putFixture<uint32_t>(bytes, text + 36, 0x60000020u);
    const size_t rdata = text + 40;
    std::memcpy(bytes.data() + rdata, ".rdata\0\0", 8);
    putFixture<uint32_t>(bytes, rdata + 8, 0x600);
    putFixture<uint32_t>(bytes, rdata + 12, 0x2000);
    putFixture<uint32_t>(bytes, rdata + 16, 0x600);
    putFixture<uint32_t>(bytes, rdata + 20, 0x600);
    putFixture<uint32_t>(bytes, rdata + 36, 0x40000040u);

    bytes[0x400] = 0xA1; // endpoint immediate-pointer reference
    bytes[0x401] = includeSendCall ? 0xA2 : 0x90; // optional WinHttpSendRequest
    bytes[0x402] = 0xA4; // direct status-return wrapper
    bytes[0x403] = 0xA5; // caller copy rax -> rbx
    bytes[0x404] = 0xA6; // caller checks the wrapper return
    bytes[0x405] = 0xA7; // zero/failure arm
    bytes[0x406] = 0xC2; // exercise signed recv-return checks in a helper
    bytes[0x407] = 0xC5; // exercise pointer-return/pointee separation
    bytes[0x408] = includeDuplicateEndpoint ? 0xA0 : 0xC3;
    bytes[0x409] = 0xC3;
    bytes[0x410] = 0xC3;
    bytes[0x500] = 0xA3; // wrapper calls WinHttpReadData
    bytes[0x501] = 0xA8; // wrapper spills the original status return
    bytes[0x502] = 0xB1; // bit-mask test is not a whole-status sign check
    bytes[0x503] = 0xB2;
    bytes[0x504] = 0x90;
    bytes[0x505] = 0xB3; // transformed rax must lose return-contract meaning
    bytes[0x506] = 0xB4;
    bytes[0x507] = 0xB5;
    bytes[0x508] = 0x90;
    bytes[0x509] = 0xA9; // reload the exact saved status for return
    bytes[0x50A] = 0xC3;
    bytes[0x540] = 0xC1; // recv returns a signed 32-bit byte count
    bytes[0x541] = 0xD1; // test rax,rax: wrong sign width on Win64
    bytes[0x542] = 0xD2;
    bytes[0x543] = 0x90;
    bytes[0x544] = 0xD3; // cmp 0,eax: subtraction direction is reversed
    bytes[0x545] = 0xD4;
    bytes[0x546] = 0x90;
    bytes[0x547] = 0xD5; // flags are clobbered before this branch
    bytes[0x548] = 0xE1;
    bytes[0x549] = 0xD6;
    bytes[0x54A] = 0x90;
    bytes[0x54B] = 0xD5; // canonical 32-bit sign test
    bytes[0x54C] = 0xD7;
    bytes[0x54D] = 0xC3;
    bytes[0x550] = 0xC3;
    bytes[0x560] = 0xC4; // gethostbyname returns a pointer
    bytes[0x561] = 0xA5; // retain the pointer in nonvolatile rbx
    bytes[0x562] = 0xF3; // a pointee-valued call argument is not the API scalar
    bytes[0x563] = 0xC6; // strcmp result controls the following branch
    bytes[0x564] = 0xD1;
    bytes[0x565] = 0xF7;
    bytes[0x566] = 0xF4; // address-dependent xchg must discard status lineage
    bytes[0x567] = 0xF5;
    bytes[0x568] = 0xF6;
    bytes[0x569] = 0xC3;
    bytes[0x56B] = 0xC3;
    if (includeEndpoint) {
        const char endpoint[] = "https://generic-service.example.net/activate";
        std::memcpy(bytes.data() + 0x600, endpoint, sizeof(endpoint));
        if (includeDuplicateEndpoint)
            std::memcpy(bytes.data() + 0x640, endpoint, sizeof(endpoint));
    }

    // IMAGE_IMPORT_DESCRIPTOR at RVA 0x2100 (file 0x700).
    putFixture<uint32_t>(bytes, 0x700 + 0, 0x2140); // OriginalFirstThunk
    putFixture<uint32_t>(bytes, 0x700 + 12, 0x2180); // DLL name
    putFixture<uint32_t>(bytes, 0x700 + 16, 0x2160); // FirstThunk/IAT
    // ws2_32.dll!recv descriptor, followed by a zero descriptor.
    putFixture<uint32_t>(bytes, 0x714 + 0, 0x21E0);
    putFixture<uint32_t>(bytes, 0x714 + 12, 0x2280);
    putFixture<uint32_t>(bytes, 0x714 + 16, 0x2260);
    putFixture<uint64_t>(bytes, 0x740 + 0, 0x21A0);
    putFixture<uint64_t>(bytes, 0x740 + 8, 0x21C0);
    putFixture<uint64_t>(bytes, 0x760 + 0, 0x21A0);
    putFixture<uint64_t>(bytes, 0x760 + 8, 0x21C0);
    std::memcpy(bytes.data() + 0x780, "winhttp.dll", 12);
    putFixture<uint16_t>(bytes, 0x7A0, 0);
    std::memcpy(bytes.data() + 0x7A2, "WinHttpSendRequest", 19);
    putFixture<uint16_t>(bytes, 0x7C0, 0);
    std::memcpy(bytes.data() + 0x7C2, "WinHttpReadData", 16);
    putFixture<uint64_t>(bytes, 0x7E0, 0x22A0);
    putFixture<uint64_t>(bytes, 0x7E8, 0x22C0);
    putFixture<uint64_t>(bytes, 0x7F0, 0x22E0);
    putFixture<uint64_t>(bytes, 0x860, 0x22A0);
    putFixture<uint64_t>(bytes, 0x868, 0x22C0);
    putFixture<uint64_t>(bytes, 0x870, 0x22E0);
    std::memcpy(bytes.data() + 0x880, "ws2_32.dll", 11);
    putFixture<uint16_t>(bytes, 0x8A0, 0);
    std::memcpy(bytes.data() + 0x8A2, "recv", 5);
    putFixture<uint16_t>(bytes, 0x8C0, 0);
    std::memcpy(bytes.data() + 0x8C2, "gethostbyname", 14);
    putFixture<uint16_t>(bytes, 0x8E0, 0);
    std::memcpy(bytes.data() + 0x8E2, "strcmp", 7);
    return bytes;
}

static std::vector<uint8_t> buildAuthorizationServicePe64() {
    std::vector<uint8_t> bytes(0x1400, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    putFixture<uint32_t>(bytes, 0x3c, pe);
    putFixture<uint32_t>(bytes, pe, 0x00004550u);
    const size_t coff = pe + 4;
    putFixture<uint16_t>(bytes, coff + 0, 0x8664); // AMD64
    putFixture<uint16_t>(bytes, coff + 2, 2);
    putFixture<uint16_t>(bytes, coff + 16, 0xf0);
    putFixture<uint16_t>(bytes, coff + 18, 0x22);
    const size_t opt = coff + 20;
    putFixture<uint16_t>(bytes, opt + 0, 0x20b);
    putFixture<uint32_t>(bytes, opt + 16, 0x1000);
    putFixture<uint64_t>(bytes, opt + 24, kAuthorizationImageBase);
    putFixture<uint32_t>(bytes, opt + 32, 0x1000);
    putFixture<uint32_t>(bytes, opt + 36, 0x200);
    putFixture<uint32_t>(bytes, opt + 56, 0x3000);
    putFixture<uint32_t>(bytes, opt + 60, 0x400);
    putFixture<uint32_t>(bytes, opt + 108, 16);
    // Normal import directory and PE32+ TLS directory.
    putFixture<uint32_t>(bytes, opt + 120, 0x2100);
    putFixture<uint32_t>(bytes, opt + 124, 0x78);
    putFixture<uint32_t>(bytes, opt + 184, 0x2400);
    putFixture<uint32_t>(bytes, opt + 188, 40);

    const size_t text = opt + 0xf0;
    std::memcpy(bytes.data() + text, ".text\0\0\0", 8);
    putFixture<uint32_t>(bytes, text + 8, 0x600);
    putFixture<uint32_t>(bytes, text + 12, 0x1000);
    putFixture<uint32_t>(bytes, text + 16, 0x600);
    putFixture<uint32_t>(bytes, text + 20, 0x400);
    putFixture<uint32_t>(bytes, text + 36, 0x60000020u);
    const size_t rdata = text + 40;
    std::memcpy(bytes.data() + rdata, ".rdata\0\0", 8);
    putFixture<uint32_t>(bytes, rdata + 8, 0xa00);
    putFixture<uint32_t>(bytes, rdata + 12, 0x2000);
    putFixture<uint32_t>(bytes, rdata + 16, 0xa00);
    putFixture<uint32_t>(bytes, rdata + 20, 0xa00);
    putFixture<uint32_t>(bytes, rdata + 36, 0x40000040u);

    // winhttp.dll descriptor: WinHttpReadData at IAT RVA 0x2200.
    putFixture<uint32_t>(bytes, 0xb00 + 0, 0x2180);
    putFixture<uint32_t>(bytes, 0xb00 + 12, 0x2300);
    putFixture<uint32_t>(bytes, 0xb00 + 16, 0x2200);
    putFixture<uint64_t>(bytes, 0xb80 + 0, 0x2320);
    putFixture<uint64_t>(bytes, 0xc00 + 0, 0x2320);
    std::memcpy(bytes.data() + 0xd00, "winhttp.dll", 12);
    putFixture<uint16_t>(bytes, 0xd20, 0);
    std::memcpy(bytes.data() + 0xd22, "WinHttpReadData", 16);

    // advapi32.dll descriptor: RegGetValueW and RegSetKeyValueW.
    putFixture<uint32_t>(bytes, 0xb14 + 0, 0x21a0);
    putFixture<uint32_t>(bytes, 0xb14 + 12, 0x2340);
    putFixture<uint32_t>(bytes, 0xb14 + 16, 0x2220);
    putFixture<uint64_t>(bytes, 0xba0 + 0, 0x2360);
    putFixture<uint64_t>(bytes, 0xba0 + 8, 0x2380);
    putFixture<uint64_t>(bytes, 0xc20 + 0, 0x2360);
    putFixture<uint64_t>(bytes, 0xc20 + 8, 0x2380);
    std::memcpy(bytes.data() + 0xd40, "advapi32.dll", 13);
    putFixture<uint16_t>(bytes, 0xd60, 0);
    std::memcpy(bytes.data() + 0xd62, "RegGetValueW", 13);
    putFixture<uint16_t>(bytes, 0xd80, 0);
    std::memcpy(bytes.data() + 0xd82, "RegSetKeyValueW", 16);

    // user32.dll descriptor: input plus a denial-dialog API.
    putFixture<uint32_t>(bytes, 0xb28 + 0, 0x21c0);
    putFixture<uint32_t>(bytes, 0xb28 + 12, 0x23a0);
    putFixture<uint32_t>(bytes, 0xb28 + 16, 0x2240);
    putFixture<uint64_t>(bytes, 0xbc0 + 0, 0x23e0);
    putFixture<uint64_t>(bytes, 0xbc0 + 8, 0x24a0);
    putFixture<uint64_t>(bytes, 0xc40 + 0, 0x23e0);
    putFixture<uint64_t>(bytes, 0xc40 + 8, 0x24a0);
    std::memcpy(bytes.data() + 0xda0, "user32.dll", 11);
    putFixture<uint16_t>(bytes, 0xde0, 0);
    std::memcpy(bytes.data() + 0xde2, "GetDlgItemTextA", 16);
    putFixture<uint16_t>(bytes, 0xea0, 0);
    std::memcpy(bytes.data() + 0xea2, "DialogBoxParamA", 16);

    // ucrtbase.dll descriptor: strcmp at IAT RVA 0x2260.
    putFixture<uint32_t>(bytes, 0xb3c + 0, 0x21e0);
    putFixture<uint32_t>(bytes, 0xb3c + 12, 0x23c0);
    putFixture<uint32_t>(bytes, 0xb3c + 16, 0x2260);
    putFixture<uint64_t>(bytes, 0xbe0 + 0, 0x2460);
    putFixture<uint64_t>(bytes, 0xc60 + 0, 0x2460);
    std::memcpy(bytes.data() + 0xdc0, "ucrtbase.dll", 13);
    putFixture<uint16_t>(bytes, 0xe60, 0);
    std::memcpy(bytes.data() + 0xe62, "strcmp", 7);

    // Hostile lookalike descriptor: an unrelated module exports `strcmp`.
    // It must never inherit the UCRT equality contract.
    putFixture<uint32_t>(bytes, 0xb50 + 0, 0x2280);
    putFixture<uint32_t>(bytes, 0xb50 + 12, 0x23d0);
    putFixture<uint32_t>(bytes, 0xb50 + 16, 0x22a0);
    putFixture<uint64_t>(bytes, 0xc80 + 0, 0x2480);
    putFixture<uint64_t>(bytes, 0xca0 + 0, 0x2480);
    std::memcpy(bytes.data() + 0xdd0, "unrelated.dll", 14);
    putFixture<uint16_t>(bytes, 0xe80, 0);
    std::memcpy(bytes.data() + 0xe82, "strcmp", 7);

    // The startup gate is both entry-reachable and a validated TLS root.
    putFixture<uint64_t>(bytes, 0xe00 + 24,
                         kAuthorizationImageBase + 0x2440);
    putFixture<uint64_t>(bytes, 0xe40 + 0,
                         kAuthorizationImageBase + 0x1100);
    putFixture<uint64_t>(bytes, 0xe40 + 8, 0);

    const char subkey[] = "Software\\Acme\\Crackme";
    const char value[] = "isPro";
    const char successA[] = "access granted";
    const char successB[] = "valid license";
    const char expectedSerial[] = "OPEN-SESAME";
    const char failureText[] = "invalid password";
    std::memcpy(bytes.data() + 0xf00, subkey, sizeof(subkey));
    std::memcpy(bytes.data() + 0xf40, value, sizeof(value));
    std::memcpy(bytes.data() + 0xf80, successA, sizeof(successA));
    std::memcpy(bytes.data() + 0xfa0, successB, sizeof(successB));
    std::memcpy(bytes.data() + 0xfc0, expectedSerial, sizeof(expectedSerial));
    std::memcpy(bytes.data() + 0xfe0, failureText, sizeof(failureText));
    return bytes;
}

static std::vector<uint8_t> buildAuthorizationProvenancePe64() {
    std::vector<uint8_t> bytes = buildAuthorizationServicePe64();

    // A deliberately deceptive API-set-looking basename must not inherit an
    // exact protected-operation contract merely because its symbol spelling
    // matches.  Repurpose this fixture's otherwise-unused WinHTTP descriptor.
    putFixture<uint32_t>(bytes, 0xb00 + 0, 0x2880);
    putFixture<uint32_t>(bytes, 0xb00 + 12, 0x28a0);
    putFixture<uint32_t>(bytes, 0xb00 + 16, 0x2200);
    putFixture<uint64_t>(bytes, 0x1280, 0x28c0);
    putFixture<uint64_t>(bytes, 0xc00, 0x28c0);
    std::memcpy(bytes.data() + 0x12a0,
                "api-ms-win-security-fake.dll", 29);
    putFixture<uint16_t>(bytes, 0x12c0, 0);
    std::memcpy(bytes.data() + 0x12c2, "CreateServiceW", 15);

    // Move the advapi32 thunk arrays into unused .rdata tail space and extend
    // them with one persistence API which is also state-changing plus a
    // separate protected operation.  This leaves the base fixture untouched.
    putFixture<uint32_t>(bytes, 0xb14 + 0, 0x2740); // OriginalFirstThunk
    putFixture<uint32_t>(bytes, 0xb14 + 16, 0x2700); // FirstThunk/IAT
    putFixture<uint64_t>(bytes, 0x1140 + 0, 0x2360); // RegGetValueW
    putFixture<uint64_t>(bytes, 0x1140 + 8, 0x2380); // RegSetKeyValueW
    putFixture<uint64_t>(bytes, 0x1140 + 16, 0x2780); // RegSetValueExW
    putFixture<uint64_t>(bytes, 0x1140 + 24, 0x27a0); // CreateServiceW
    putFixture<uint64_t>(bytes, 0x1100 + 0, 0x2360);
    putFixture<uint64_t>(bytes, 0x1100 + 8, 0x2380);
    putFixture<uint64_t>(bytes, 0x1100 + 16, 0x2780);
    putFixture<uint64_t>(bytes, 0x1100 + 24, 0x27a0);
    putFixture<uint16_t>(bytes, 0x1180, 0);
    std::memcpy(bytes.data() + 0x1182, "RegSetValueExW", 15);
    putFixture<uint16_t>(bytes, 0x11a0, 0);
    std::memcpy(bytes.data() + 0x11a2, "CreateServiceW", 15);

    // Repurpose only this dedicated fixture's hostile-lookalike descriptor as
    // an exact bcrypt import. BCryptVerifySignature has a documented
    // zero-is-success contract, which is the subtle polarity under test.
    putFixture<uint32_t>(bytes, 0xb50 + 0, 0x27c0);
    putFixture<uint32_t>(bytes, 0xb50 + 12, 0x2840);
    putFixture<uint32_t>(bytes, 0xb50 + 16, 0x2800);
    putFixture<uint64_t>(bytes, 0x11c0, 0x2860);
    putFixture<uint64_t>(bytes, 0x1200, 0x2860);
    std::memcpy(bytes.data() + 0x1240, "bcrypt.dll", 11);
    putFixture<uint16_t>(bytes, 0x1260, 0);
    std::memcpy(bytes.data() + 0x1262, "BCryptVerifySignature", 22);
    return bytes;
}

static std::vector<uint8_t> buildMachineBindingPe64() {
    std::vector<uint8_t> bytes = buildAuthorizationProvenancePe64();

    // Repurpose two imports unused by this dedicated fixture. Both expose the
    // same symbol spelling so the negative proves that the loader-backed DLL
    // half of the machine-identity catalog identity is mandatory.
    putFixture<uint32_t>(bytes, 0xb28 + 0, 0x2900);
    putFixture<uint32_t>(bytes, 0xb28 + 12, 0x2940);
    putFixture<uint32_t>(bytes, 0xb28 + 16, 0x2920);
    putFixture<uint64_t>(bytes, 0x1300 + 0, 0x2960);
    putFixture<uint64_t>(bytes, 0x1300 + 8, 0);
    putFixture<uint64_t>(bytes, 0x1320 + 0, 0x2960);
    putFixture<uint64_t>(bytes, 0x1320 + 8, 0);
    const char kernel32[] = "kernel32.dll";
    std::memcpy(bytes.data() + 0x1340, kernel32, sizeof(kernel32));
    putFixture<uint16_t>(bytes, 0x1360, 0);
    const char machineApi[] = "GetVolumeInformationW";
    std::memcpy(bytes.data() + 0x1362, machineApi, sizeof(machineApi));

    putFixture<uint32_t>(bytes, 0xb3c + 0, 0x2980);
    putFixture<uint32_t>(bytes, 0xb3c + 12, 0x29c0);
    putFixture<uint32_t>(bytes, 0xb3c + 16, 0x29a0);
    putFixture<uint64_t>(bytes, 0x1380 + 0, 0x29d0);
    putFixture<uint64_t>(bytes, 0x1380 + 8, 0);
    putFixture<uint64_t>(bytes, 0x13a0 + 0, 0x29d0);
    putFixture<uint64_t>(bytes, 0x13a0 + 8, 0);
    const char unrelated[] = "unrelated.dll";
    std::memcpy(bytes.data() + 0x13c0, unrelated, sizeof(unrelated));
    putFixture<uint16_t>(bytes, 0x13d0, 0);
    std::memcpy(bytes.data() + 0x13d2, machineApi, sizeof(machineApi));
    return bytes;
}

static std::vector<uint8_t> buildAbiElf64() {
    std::vector<uint8_t> bytes(0x200, 0);
    std::memcpy(bytes.data(), "\x7f" "ELF", 4);
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // current version
    putFixture<uint16_t>(bytes, 16, 2);       // ET_EXEC
    putFixture<uint16_t>(bytes, 18, 0x3e);    // EM_X86_64
    putFixture<uint32_t>(bytes, 20, 1);
    putFixture<uint64_t>(bytes, 24, 0x400080);
    putFixture<uint64_t>(bytes, 32, 64);      // program-header table
    putFixture<uint16_t>(bytes, 52, 64);
    putFixture<uint16_t>(bytes, 54, 56);
    putFixture<uint16_t>(bytes, 56, 1);
    const size_t ph = 64;
    putFixture<uint32_t>(bytes, ph + 0, 1);    // PT_LOAD
    putFixture<uint32_t>(bytes, ph + 4, 5);    // PF_R | PF_X
    putFixture<uint64_t>(bytes, ph + 8, 0);
    putFixture<uint64_t>(bytes, ph + 16, 0x400000);
    putFixture<uint64_t>(bytes, ph + 24, 0x400000);
    putFixture<uint64_t>(bytes, ph + 32, bytes.size());
    putFixture<uint64_t>(bytes, ph + 40, bytes.size());
    putFixture<uint64_t>(bytes, ph + 48, 0x1000);
    return bytes;
}

static std::vector<uint8_t> buildAbiMachO64() {
    std::vector<uint8_t> bytes(0x200, 0);
    putFixture<uint32_t>(bytes, 0, 0xfeedfacfu);
    putFixture<uint32_t>(bytes, 4, 0x01000007u); // CPU_TYPE_X86_64
    putFixture<uint32_t>(bytes, 8, 3);
    putFixture<uint32_t>(bytes, 12, 2);          // MH_EXECUTE
    putFixture<uint32_t>(bytes, 16, 1);
    putFixture<uint32_t>(bytes, 20, 72 + 80);
    const size_t command = 32;
    putFixture<uint32_t>(bytes, command + 0, 0x19); // LC_SEGMENT_64
    putFixture<uint32_t>(bytes, command + 4, 72 + 80);
    std::memcpy(bytes.data() + command + 8, "__TEXT", 6);
    putFixture<uint64_t>(bytes, command + 24, 0x100000000ull);
    putFixture<uint64_t>(bytes, command + 32, 0x1000);
    putFixture<uint64_t>(bytes, command + 40, 0);
    putFixture<uint64_t>(bytes, command + 48, bytes.size());
    putFixture<uint32_t>(bytes, command + 56, 7);
    putFixture<uint32_t>(bytes, command + 60, 5);
    putFixture<uint32_t>(bytes, command + 64, 1);
    const size_t section = command + 72;
    std::memcpy(bytes.data() + section, "__text", 6);
    std::memcpy(bytes.data() + section + 16, "__TEXT", 6);
    putFixture<uint64_t>(bytes, section + 32, 0x100000100ull);
    putFixture<uint64_t>(bytes, section + 40, 0x100);
    putFixture<uint32_t>(bytes, section + 48, 0x100);
    putFixture<uint32_t>(bytes, section + 52, 4);
    putFixture<uint32_t>(bytes, section + 64, 0x80000400u);
    bytes[0x100] = 0xc3;
    return bytes;
}

static bool loadAbiFixture(const char* path, const std::vector<uint8_t>& bytes,
                           BinaryFile& binary) {
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        if (!output.good()) return false;
    }
    const bool loaded = binary.load(path);
    std::remove(path);
    return loaded;
}

int main() {
    const uint64_t base = 0x140000000ull;
    std::string path = writeTempBlob();
    BinaryFile bin;
    CHECK(bin.loadRaw(path, base), "loadRaw");
    CHECK(bin.format() == BinFormat::Raw && bin.entryPoint() == 0,
          "raw format retains an honest no-header-entry model");
    CHECK(bin.machine() == MachineArch::Unknown,
          "raw loader leaves architecture selection to the caller");

    // Regression for the derived-cache budget: nested trail allocations must
    // count toward the 256-MiB LRU, not merely their top-level row objects.
    {
        AnalysisResult empty;
        AnalysisResult nested;
        nested.crackmeTriageValid = true;
        nested.crackmeTriage.label.assign(1024, 'L');
        CrackmeTriageRoute route;
        route.path.assign(2048, 'R');
        nested.crackmeTriage.routes.push_back(std::move(route));
        NetworkArtifact artifact;
        artifact.value.assign(8192, 'A');
        artifact.functionAddresses.resize(32, 0x401000);
        CrackmeTriageLiteralSource source;
        source.literal.assign(4096, 'S');
        artifact.sources.push_back(std::move(source));
        nested.crackmeTriage.artifacts.push_back(std::move(artifact));
        NetworkReturnFlow returnFlow;
        returnFlow.functionName.assign(2048, 'F');
        returnFlow.useInstruction.assign(4096, 'I');
        returnFlow.useSummary.assign(4096, 'U');
        returnFlow.decisionInstruction.assign(4096, 'D');
        returnFlow.evidence.assign(4096, 'E');
        returnFlow.honestyLabel.assign(2048, 'H');
        nested.crackmeTriage.returnFlows.push_back(std::move(returnFlow));
        NetworkReplyDecisionFlow replyDecision;
        replyDecision.functionName.assign(2048, 'N');
        replyDecision.outputRole.assign(2048, 'O');
        replyDecision.outputExpression.assign(4096, 'X');
        replyDecision.comparisonInstruction.assign(4096, 'C');
        replyDecision.comparisonSummary.assign(4096, 'M');
        replyDecision.expectedValue.assign(4096, 'V');
        replyDecision.decisionInstruction.assign(4096, 'B');
        replyDecision.takenPathSummary.assign(4096, 'K');
        replyDecision.fallthroughPathSummary.assign(4096, 'P');
        replyDecision.evidence.assign(4096, 'Q');
        replyDecision.honestyLabel.assign(2048, 'Y');
        nested.crackmeTriage.replyDecisionFlows.push_back(
            std::move(replyDecision));
        CrackmeTrail trail;
        trail.artifactIndices.resize(64, 0);
        trail.correlationIndices.resize(64, 0);
        trail.returnFlowIndices.resize(64, 0);
        trail.replyDecisionFlowIndices.resize(64, 0);
        trail.label.assign(2048, 'T');
        nested.crackmeTriage.trails.push_back(std::move(trail));
        const size_t beforeAuthorization = EstimateAnalysisResultBytes(nested);
        PersistentStateOperation stateOperation;
        stateOperation.identity.display.assign(4096, 'P');
        stateOperation.identity.canonicalScope.assign(2048, 'S');
        stateOperation.identity.canonicalKey.assign(4096, 'K');
        stateOperation.identity.canonicalValue.assign(2048, 'V');
        stateOperation.apiDll.assign(1024, 'D');
        stateOperation.apiName.assign(1024, 'N');
        stateOperation.evidence.assign(4096, 'E');
        nested.crackmeTriage.authorization.stateOperations.push_back(
            std::move(stateOperation));
        AuthorizationFlow authorizationFlow;
        authorizationFlow.id.assign(2048, 'I');
        authorizationFlow.honestyLabel.assign(4096, 'H');
        AuthorizationEvidence authorizationEvidence;
        authorizationEvidence.text.assign(4096, 'A');
        authorizationFlow.takenPath.evidence.push_back(
            std::move(authorizationEvidence));
        AuthorizationStageRecord authorizationStage;
        authorizationStage.evidence.assign(4096, 'G');
        authorizationFlow.stages.push_back(std::move(authorizationStage));
        authorizationFlow.linkedStateWriteIndices.resize(64, 0);
        authorizationFlow.linkedStartupReadIndices.resize(64, 0);
        authorizationFlow.linkedStartupFlowIndices.resize(64, 0);
        nested.crackmeTriage.authorization.flows.push_back(
            std::move(authorizationFlow));
        CHECK(EstimateAnalysisResultBytes(nested) > beforeAuthorization + 20 * 1024,
              "cache estimate includes nested authorization allocations");
        CHECK(EstimateAnalysisResultBytes(nested) >
                  EstimateAnalysisResultBytes(empty) + 32 * 1024,
              "cache estimate includes nested crackme-triage allocations");
    }

    // Decompiler target selection is derived from the loaded image format, not
    // from host defaults or a compatibility x86 boolean. Structured metadata is
    // authoritative; Raw remains ABI-unknown unless the analyst supplies one.
    {
        BinaryFile pe, elf, macho;
        CHECK(loadAbiFixture("ds_abi_pe64.bin", buildAbiPe64(), pe) &&
              pe.format() == BinFormat::PE32Plus,
              "load PE32+ ABI fixture");
        CHECK(loadAbiFixture("ds_abi_elf64.bin", buildAbiElf64(), elf) &&
              elf.format() == BinFormat::ELF,
              "load ELF64 ABI fixture");
        CHECK(loadAbiFixture("ds_abi_macho64.bin", buildAbiMachO64(), macho) &&
              macho.format() == BinFormat::MachO,
              "load Mach-O64 ABI fixture");

        const DecompileTarget peTarget = DecompileTargetForBinary(pe, Arch::X64);
        const DecompileTarget elfTarget = DecompileTargetForBinary(elf, Arch::X64);
        const DecompileTarget machoTarget = DecompileTargetForBinary(macho, Arch::X64);
        const DecompileTarget rawTarget = DecompileTargetForBinary(bin, Arch::X64);
        CHECK(peTarget.architecture == Arch::X64 && peTarget.abi == DecompileABI::Win64,
              "PE32+ derives the Microsoft x64 ABI");
        CHECK(elfTarget.architecture == Arch::X64 && elfTarget.abi == DecompileABI::SysV64,
              "ELF64 derives the System V x64 ABI");
        CHECK(machoTarget.architecture == Arch::X64 && machoTarget.abi == DecompileABI::SysV64,
              "Mach-O64 derives the System V x64 ABI");
        CHECK(rawTarget.architecture == Arch::X64 && rawTarget.abi == DecompileABI::Unknown,
              "Raw x64 has no fabricated ABI");
        CHECK(DecompileTargetForBinary(bin, Arch::X64, "win64").abi == DecompileABI::Win64 &&
              DecompileTargetForBinary(bin, Arch::X64, "__sysv_abi").abi == DecompileABI::SysV64,
              "Raw analyst ABI overrides are exact");
        CHECK(DecompileTargetForBinary(bin, Arch::X86, "__stdcall").abi ==
                  DecompileABI::X86Stdcall &&
              DecompileTargetForBinary(bin, Arch::X86, "nonsense").abi ==
                  DecompileABI::Unknown,
              "Raw x86 accepts only recognized analyst ABI overrides");
        CHECK(DecompileTargetForBinary(pe, Arch::X64, "sysv64").abi == DecompileABI::Win64 &&
              DecompileTargetForBinary(elf, Arch::X64, "win64").abi == DecompileABI::SysV64,
              "structured image metadata remains authoritative over Raw-only overrides");
    }

    CHECK(bin.sections().size() == 1, "raw load creates exactly one synthetic section");
    if (bin.sections().size() == 1) {
        const Section& raw = bin.sections()[0];
        CHECK(raw.name == ".raw" && raw.executable, "synthetic raw section is executable and named");
        CHECK(raw.virtualAddress == 0 && raw.rawOffset == 0,
              "synthetic raw section begins at mapping/file offset zero");
        CHECK(raw.virtualSize == bin.bytes().size() && raw.rawSize == bin.bytes().size(),
              "synthetic raw section covers the complete blob");
    }
    CHECK(bin.firstCodeSection() == &bin.sections()[0], "raw section is the default code section");

    // Invalid fixed-width ARM words/Thumb halfwords remain aligned in lazy
    // listing pages; byte-at-a-time fallback would poison every later decode.
    {
        const uint8_t malformed[12] = {0xFF,0xFF,0xFF,0xFF, 0xAA,0xAA,0xAA,0xAA,
                                       0x55,0x55,0x55,0x55};
        FixedFailDisasm word(4);
        DecodedListingPage a32 = DecodeListingCodePage(malformed, sizeof(malformed),
                                                       0x1000, 8, 0, 4, word);
        CHECK(a32.instructions.size() == 2 && a32.instructions[0].length == 4 &&
              a32.instructions[1].address == 0x1004 && a32.instructions[1].length == 4,
              "A32/AArch64 invalid listing words preserve four-byte alignment");
        FixedFailDisasm halfword(2);
        DecodedListingPage thumb = DecodeListingCodePage(malformed, sizeof(malformed),
                                                         0x2000, 8, 0, 4, halfword);
        CHECK(thumb.instructions.size() == 4 && thumb.instructions[0].length == 2 &&
              thumb.instructions[3].address == 0x2006 && thumb.instructions[3].length == 2,
              "Thumb invalid listing halfwords preserve two-byte alignment");
    }

    // Call-graph sweeps use the same natural recovery width. A bytewise retry
    // would accept the fake unaligned decode and skip the real aligned call.
    {
        FixedWidthCallDisasm a32(base, 4);
        const std::vector<FuncResult> funcs = {
            { base, 8, "caller" }, { base + 8, 4, "callee" }
        };
        const std::vector<CallEdgeR> edges = BuildCallEdges(bin, a32, funcs);
        CHECK(edges.size() == 1 && edges[0].from == base && edges[0].to == base + 8,
              "A32 call-graph sweep recovers at the next four-byte boundary");
    }

    // A superseded call-graph pass must stop inside one large function rather
    // than making the patch mutation barrier wait for the 50k-instruction CFG
    // budget. Cancelled partial edges are never published as authoritative.
    {
        constexpr size_t kCallGraphBytes = 4096;
        BinaryFile cancellationBin;
        CHECK(cancellationBin.loadFromMemory(
                  std::vector<uint8_t>(kCallGraphBytes, 0x90), base,
                  "call-graph-cancellation"),
              "load whole-function call-graph cancellation fixture");
        StubDisasm cancellationDis;
        const std::vector<FuncResult> funcs = {
            { base, static_cast<uint32_t>(kCallGraphBytes), "large_function" }
        };
        const std::vector<CallEdgeR> edges = BuildCallEdges(
            cancellationBin, cancellationDis, funcs, {}, {}, {},
            [&] { return cancellationDis.decodeCalls >= 4; });
        CHECK(edges.empty(), "cancelled call-graph sweep publishes no partial edges");
        CHECK(cancellationDis.decodeCalls <= 256 &&
                  cancellationDis.decodeCalls < kCallGraphBytes,
              "call-graph cancellation is observed inside a large function");
    }

    // AnalysisJobs must preserve AlgoScan's existing bounded cancellation hook;
    // dropping it here makes a patch wait for a complete whole-image scan.
    {
        size_t cancellationPolls = 0;
        const std::vector<AlgoMatch> matches = ScanAlgorithmsJob(
            bin, nullptr, {}, [&] { ++cancellationPolls; return true; });
        CHECK(matches.empty(), "cancelled algorithm scan publishes no partial matches");
        CHECK(cancellationPolls != 0,
              "algorithm job forwards its cancellation callback to the scanner");
    }

    // Raw VA/file translation stays an exact inverse, rejects sub-base aliases,
    // and remains patchable through the same BinaryFile API as structured images.
    {
        uint64_t va = 0, off = 0;
        const uint64_t last = static_cast<uint64_t>(bin.bytes().size() - 1);
        CHECK(bin.offsetToVA(last, va) && va == base + last, "raw last offset maps to base+offset");
        CHECK(bin.vaToOffset(base + last, off) && off == last, "raw VA maps back to last offset");
        size_t avail = 0;
        CHECK(bin.ptrFromVA(base - 1, avail) == nullptr && avail == 0,
              "raw VA below the selected base is unmapped");
        CHECK(!bin.vaToOffset(base - 1, off), "raw patch mapping rejects a sub-base VA");
        const uint8_t original = bin.bytes()[3], replacement = original ^ 0x5A;
        CHECK(bin.writeImage(base + 3, &replacement, 1) == 1 && bin.bytes()[3] == replacement,
              "raw image patch writes through VA mapping");
        CHECK(bin.writeImage(base + 3, &original, 1) == 1 && bin.bytes()[3] == original,
              "raw image patch can be restored");
    }

    // Ordinary unknown bytes still auto-detect as Raw. Recognized malformed ELF
    // requires an explicit Open-as-Raw choice and leaves no partial parser state.
    BinaryFile autoRaw;
    CHECK(autoRaw.load(path), "ordinary load auto-detects an unknown blob as raw");
    CHECK(autoRaw.format() == BinFormat::Raw && autoRaw.imageBase() == 0,
          "auto-detected raw maps at zero");
    CHECK(autoRaw.sections().size() == 1 && autoRaw.sections()[0].executable,
          "auto-detected raw receives the synthetic executable section");
    {
        const std::string malformedPath = "ds_anajobs_malformed_elf.bin";
        std::vector<uint8_t> malformed(0x40, 0);
        std::memcpy(malformed.data(), "\x7F" "ELF", 4);
        malformed[4] = 2; malformed[5] = 1; // ELF64 little-endian
        malformed[18] = 0xB7;               // would select ARM64 before parse fallback
        { std::ofstream f(malformedPath, std::ios::binary);
          f.write((const char*)malformed.data(), (std::streamsize)malformed.size()); }
        BinaryFile rejected;
        CHECK(!rejected.load(malformedPath), "malformed recognized ELF is rejected");
        CHECK(!rejected.loaded() && rejected.format() == BinFormat::Unknown &&
              rejected.machine() == MachineArch::Unknown && rejected.sections().empty(),
              "rejected ELF clears all partial parser state");
        std::remove(malformedPath.c_str());
    }

    // A flat mapping is invalid if its final byte cannot be represented as a VA.
    {
        const uint64_t last = static_cast<uint64_t>(bin.bytes().size() - 1);
        BinaryFile boundary;
        CHECK(boundary.loadRaw(path, std::numeric_limits<uint64_t>::max() - last),
              "raw mapping ending exactly at UINT64_MAX is valid");
        uint64_t va = 0;
        CHECK(boundary.offsetToVA(last, va) && va == std::numeric_limits<uint64_t>::max(),
              "boundary raw mapping translates its final byte exactly");
        BinaryFile overflow;
        CHECK(!overflow.loadRaw(path, std::numeric_limits<uint64_t>::max() - last + 1),
              "raw mapping whose final VA wraps is rejected");
        CHECK(!overflow.loaded() && overflow.sections().empty(),
              "rejected overflowing raw mapping leaves no partial image");
        CHECK(!overflow.loadFromMemory(std::vector<uint8_t>(0x40, 0x90),
                                       std::numeric_limits<uint64_t>::max(), "overflow"),
              "non-PE memory fallback rejects an overflowing flat mapping");
    }

    // ---- ScanStringsImage ----
    auto strs = ScanStringsImage(bin);
    bool foundHello = false, foundWide = false;
    for (auto& s : strs) {
        if (s.text == "Hello, world!" && !s.wide && s.address == base + 0) foundHello = true;
        if (s.text == "Wide" && s.wide) foundWide = true;
    }
    CHECK(foundHello, "ascii 'Hello, world!' at base+0");
    CHECK(foundWide,  "utf-16 'Wide'");
    for (size_t i = 1; i < strs.size(); ++i) CHECK(strs[i - 1].address <= strs[i].address, "strings sorted by address");

    // Cancellation is checked inside a single long printable run, not merely
    // between discovered strings or encoding passes. This is the pathological
    // shape that previously made cancelAndWaitIdle wait for the whole image.
    {
        constexpr size_t kCancelImageBytes = 4 * 1024 * 1024;
        BinaryFile cancellationBin;
        CHECK(cancellationBin.loadFromMemory(
                  std::vector<uint8_t>(kCancelImageBytes, static_cast<uint8_t>('A')),
                  base, "string-scan-cancellation"),
              "load whole-image string cancellation fixture");
        std::atomic<uint32_t> cancellationProgress{0};
        size_t cancellationPolls = 0;
        bool cancellationTruncated = true;
        std::vector<StrResult> cancelledStrings = ScanStringsImage(
            cancellationBin, kDefaultStringScanCap, &cancellationProgress,
            &cancellationTruncated, [&] { return ++cancellationPolls >= 3; });
        CHECK(cancelledStrings.empty(), "cancelled whole-image scan publishes no partial strings");
        CHECK(cancellationPolls == 3, "whole-image scan observes cancellation at a bounded checkpoint");
        CHECK(cancellationProgress.load(std::memory_order_relaxed) > 0 &&
                  cancellationProgress.load(std::memory_order_relaxed) < kCancelImageBytes,
              "cancelled whole-image scan stops before reporting full progress");
        CHECK(!cancellationTruncated, "cancellation is distinct from result-cap truncation");
    }

    // Raw base is a real function root (not entryRVA evidence), and the naming
    // layer describes it honestly. Explicit validity keeps VA 0 usable too.
    {
        StubDisasm dis;
        AnalyzeOut named = AnalyzeFunctionsNamed(bin, dis, strs, true, Arch::X64);
        CHECK(!named.functions.empty() && named.functions[0].address == base,
              "explicit raw base is the first discovered function");
        CHECK(named.functions[0].guessed && named.functions[0].name == "start" &&
              named.functions[0].reason.find("raw image base") != std::string::npos,
              "raw root naming is explicit and never claims a header entry point");

        std::vector<StrResult> zeroStrings = ScanStringsImage(autoRaw);
        AnalyzeOut zeroNamed = AnalyzeFunctionsNamed(autoRaw, dis, zeroStrings, true, Arch::X64);
        CHECK(!zeroNamed.functions.empty() && zeroNamed.functions[0].address == 0,
              "raw mapping at VA 0 retains an explicit function root");
        CHECK(zeroNamed.functions[0].guessed && zeroNamed.functions[0].name == "start",
              "FunctionNamer accepts an explicitly-valid raw root at VA 0");
        std::vector<ListRowR> zeroRows = BuildListingRows(autoRaw, zeroStrings);
        bool zeroRegion = false, zeroPage = false, zeroInsn = false;
        for (const auto& r : zeroRows) {
            zeroRegion  |= r.type == ListingRowType::RegionHeader && r.addr == 0;
            zeroPage    |= r.type == ListingRowType::CodePage && r.addr == 0;
            zeroInsn    |= r.type == ListingRowType::Normal && !r.divider && !r.strData && r.addr == 0;
        }
        CHECK(zeroRegion && zeroPage && !zeroInsn,
              "virtual listing emits a region and lazy code page at VA 0 without instructions");
    }

    // Architecture-neutral base/call seeds still run for non-x86 raw blobs,
    // while x86 byte-pattern prologues are gated by the selected decoder arch.
    {
        const std::string archPath = "ds_anajobs_raw_arch_tmp.bin";
        std::vector<uint8_t> bytes(32, 0x90);
        bytes[8] = 0x55; bytes[9] = 0x48; bytes[10] = 0x89; bytes[11] = 0xE5;
        bytes[16] = 0x55; bytes[17] = 0x8B; bytes[18] = 0xEC;
        { std::ofstream f(archPath, std::ios::binary);
          f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
        BinaryFile archBin;
        CHECK(archBin.loadRaw(archPath, base), "load raw architecture-gating fixture");
        StubDisasm dis;
        AnalyzeOut arm = AnalyzeFunctionsNamed(archBin, dis, {}, false, Arch::ARM64);
        CHECK(arm.functions.size() == 1 && arm.functions[0].address == base,
              "non-x86 raw analysis keeps the base seed but skips x86 prologues");
        AnalyzeOut x64 = AnalyzeFunctionsNamed(archBin, dis, {}, false, Arch::X64);
        bool sawX64Prologue = false;
        for (const auto& f : x64.functions) if (f.address == base + 8) sawX64Prologue = true;
        CHECK(sawX64Prologue, "x64 raw analysis applies x64 prologue discovery");
        AnalyzeOut x86 = AnalyzeFunctionsNamed(archBin, dis, {}, false, Arch::X86);
        bool sawX86Prologue = false;
        for (const auto& f : x86.functions) if (f.address == base + 16) sawX86Prologue = true;
        CHECK(sawX86Prologue, "x86 raw analysis applies x86 prologue discovery");
        std::remove(archPath.c_str());
    }

    // A real direct call inside a raw image flows through all pure whole-program
    // products: functions, divider rows, call graph, and target->source xrefs.
    {
        const std::string flowPath = "ds_anajobs_raw_flow_tmp.bin";
        std::vector<uint8_t> bytes(16, 0x90);
        bytes[0] = 0xE8; bytes[1] = 8; bytes[2] = 0xC3;
        bytes[8] = 0xE8; bytes[9] = 0; bytes[10] = 0xC3; // second function calls VA 0
        { std::ofstream f(flowPath, std::ios::binary);
          f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
        BinaryFile flowBin;
        CHECK(flowBin.loadRaw(flowPath, 0), "load raw control-flow fixture at VA 0");
        RawFlowDisasm dis(0);
        AnalyzeOut analyzed = AnalyzeFunctionsNamed(flowBin, dis, {}, false, Arch::ARM64);
        CHECK(analyzed.functions.size() == 2 && analyzed.functions[0].address == 0 &&
              analyzed.functions[1].address == 8,
              "raw recursive discovery follows a direct call from the base root");
        std::vector<ListRowR> rows = BuildListingRows(flowBin, {});
        bool pageCoversBoth = false;
        for (const auto& row : rows) if (row.type == ListingRowType::CodePage)
            pageCoversBoth |= row.addr == 0 && row.aux >= 16;
        CHECK(pageCoversBoth, "raw virtual listing page covers both discovered functions on demand");
        std::vector<CallEdgeR> calls = BuildCallEdges(flowBin, dis, analyzed.functions);
        bool callOut = false, callBackToZero = false;
        for (const auto& edge : calls) {
            callOut |= edge.from == 0 && edge.to == 8;
            callBackToZero |= edge.from == 8 && edge.to == 0;
        }
        CHECK(callOut && callBackToZero,
              "raw call graph preserves outbound and inbound-to-VA0 call edges");
        XrefIndex xrefs;
        size_t avail = 0;
        const uint8_t* p = flowBin.ptrFromVA(0, avail);
        BuildXrefInto(xrefs, p, avail, 0, dis);
        FinalizeXrefIndex(xrefs);
        const std::vector<uint64_t>* sources = xrefs.sources(8);
        CHECK(sources && sources->size() == 1 && (*sources)[0] == 0,
              "raw xref index maps the call target back to its source VA");
        const std::vector<uint64_t>* zeroSources = xrefs.sources(0);
        CHECK(zeroSources && zeroSources->size() == 1 && (*zeroSources)[0] == 8,
              "raw xref index preserves a known direct call target of VA 0");

        // An analyst noreturn decision turns the call into a terminal block and
        // removes caller fallthrough. Without this resolver calls remain ordinary
        // instructions because they normally return.
        const uint8_t noreturnBytes[] = { 0xE8, 4, 0x90, 0xC3, 0xC3 };
        RawFlowDisasm zeroFlow(0);
        ControlFlowGraph normal = BuildCFG(noreturnBytes, sizeof(noreturnBytes), 0,
                                           zeroFlow, 100);
        ControlFlowGraph terminal = BuildCFG(
            noreturnBytes, sizeof(noreturnBytes), 0, zeroFlow, 100, {},
            [](uint64_t target) { return target == 4; });
        CHECK(!normal.blocks.empty() && normal.blocks[0].end > 2,
              "ordinary direct call retains its fallthrough instructions");
        CHECK(!terminal.blocks.empty() && terminal.blocks[0].end == 2 &&
              terminal.blocks[0].isNoReturnCall && terminal.blocks[0].succ.empty(),
              "authoritative noreturn call suppresses the caller CFG fallthrough");

        const std::string deadCallPath = "ds_callgraph_noreturn_tail_tmp.bin";
        std::vector<uint8_t> deadCalls(16, 0x90);
        deadCalls[0] = 0xE8; deadCalls[1] = 8;   // live noreturn call
        deadCalls[2] = 0xE8; deadCalls[3] = 12;  // dead call in physical tail
        deadCalls[4] = 0xC3;
        deadCalls[8] = deadCalls[12] = 0xC3;
        { std::ofstream file(deadCallPath, std::ios::binary);
          file.write(reinterpret_cast<const char*>(deadCalls.data()),
                     static_cast<std::streamsize>(deadCalls.size())); }
        BinaryFile deadCallBin;
        CHECK(deadCallBin.loadRaw(deadCallPath, 0),
              "load call-graph noreturn-tail fixture");
        RawFlowDisasm deadCallDis(0);
        std::vector<FuncResult> deadCallFunctions = {
            {0, 5, "caller"}, {8, 1, "exit_like"}, {12, 1, "dead_callee"},
        };
        std::vector<CallEdgeR> reachableCalls = BuildCallEdges(
            deadCallBin, deadCallDis, deadCallFunctions, {},
            [](uint64_t target) { return target == 8; });
        CHECK(reachableCalls.size() == 1 && reachableCalls[0].from == 0 &&
              reachableCalls[0].to == 8,
              "call graph excludes calls decoded only in a noreturn dead tail");
        std::remove(deadCallPath.c_str());
        std::remove(flowPath.c_str());
    }

    // Code-pointer/vtable runs are fed back into FunctionAnalyzer exactly once,
    // recovering functions that have no entry, export, direct call, or prologue.
    {
        const std::string pointerPath = "ds_anajobs_pointer_seed_tmp.bin";
        constexpr uint64_t pointerBase = 0xA00000;
        std::vector<uint8_t> bytes(0xA0, 0x42);
        bytes[0] = bytes[0x20] = bytes[0x30] = bytes[0x40] = 0xC3;
        const uint64_t targets[] = { pointerBase + 0x20, pointerBase + 0x30,
                                     pointerBase + 0x40 };
        std::memcpy(bytes.data() + 0x80, targets, sizeof(targets));
        { std::ofstream f(pointerPath, std::ios::binary);
          f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
        BinaryFile pointerBin;
        CHECK(pointerBin.loadRaw(pointerPath, pointerBase),
              "load indirect-entry recovery fixture");
        PointerSeedDisasm dis;
        AnalyzeOut analyzed = AnalyzeFunctionsNamed(pointerBin, dis, {}, false, Arch::X64);
        bool found20 = false, found30 = false, found40 = false;
        for (const auto& function : analyzed.functions) {
            found20 |= function.address == pointerBase + 0x20;
            found30 |= function.address == pointerBase + 0x30;
            found40 |= function.address == pointerBase + 0x40;
        }
        CHECK(found20 && found30 && found40,
              "global pointer evidence recovers indirect-only functions");
        const CodeDataSpan* table = analyzed.codeData.find(pointerBase + 0x80);
        CHECK(analyzed.codeDataValid && table &&
              table->kind == CodeDataKind::PointerTable && table->elementWidth == 8,
              "final classifier map retains the dq code-pointer table");
        std::remove(pointerPath.c_str());
    }

    // Regression: the old scanner silently stopped at 20,000 and scanned narrow
    // strings first, so a narrow-heavy file could omit every UTF-16 result. The new
    // high safety cap must preserve a >20k mixed corpus in address order.
    {
        constexpr size_t kMany = 25050;
        std::vector<uint8_t> bytes;
        bytes.reserve(kMany * 18);
        for (size_t i = 0; i < kMany; ++i) {
            char word[24]; std::snprintf(word, sizeof(word), "%c%05zu", (i & 1) ? 'W' : 'A', i);
            if (i & 1) {
                for (const char* p = word; *p; ++p) { bytes.push_back((uint8_t)*p); bytes.push_back(0); }
            } else {
                bytes.insert(bytes.end(), word, word + std::strlen(word));
            }
            bytes.push_back(0xFF); bytes.push_back(0xFF);
        }
        std::vector<StrResult> many;
        bool truncated = false;
        ScanStringsBuffer(bytes.data(), bytes.size(), base, many,
                          kDefaultStringScanCap, &truncated);
        CHECK(many.size() == kMany, ">20k mixed strings survive the default scan cap");
        CHECK(!truncated, ">20k mixed scan is not falsely reported as truncated");
        size_t narrow = 0, wide = 0;
        for (const auto& s : many) { if (s.wide) ++wide; else ++narrow; }
        CHECK(narrow > 12000 && wide > 12000, "mixed scan retains both narrow and UTF-16 strings");
        for (size_t i = 1; i < many.size(); ++i)
            CHECK(many[i - 1].address < many[i].address, "large mixed result remains address-sorted");

        std::vector<StrResult> capped;
        truncated = false;
        ScanStringsBuffer(bytes.data(), bytes.size(), base, capped, 2000, &truncated);
        CHECK(capped.size() == 2000 && truncated, "explicit low cap is exact and surfaced");
        bool cappedHasWide = false;
        for (const auto& s : capped) if (s.wide) { cappedHasWide = true; break; }
        CHECK(cappedHasWide, "narrow results cannot starve UTF-16 results at the cap");
    }

    // The UI promises UTF-8 rather than merely accepting 7-bit ASCII.
    {
        const uint8_t utf8[] = { 'c','a','f',0xC3,0xA9,0 }; // caf\xC3\xA9: four code points
        std::vector<StrResult> u;
        ScanStringsBuffer(utf8, sizeof(utf8), base, u);
        CHECK(u.size() == 1 && u[0].text == std::string((const char*)utf8, 5),
              "valid printable UTF-8 string is extracted intact");

        std::vector<uint8_t> huge(5000, (uint8_t)'X'); huge.push_back(0);
        u.clear(); ScanStringsBuffer(huge.data(), huge.size(), base, u);
        CHECK(u.size() == 1 && u[0].text.size() == 512 && u[0].textTruncated,
              "pathological individual run is stored as an explicit bounded prefix");
    }

    // A live region at the top of the address space must not wrap a string hit
    // back to VA zero. The omitted, unrepresentable result is surfaced through
    // the same visible partial-result contract as the scan cap.
    {
        const uint8_t nearWrap[] = { 0xFF, 0xFF, 'w','r','a','p',0 };
        std::vector<StrResult> strings;
        bool truncated = false;
        ScanStringsBuffer(nearWrap, sizeof(nearWrap),
                          (std::numeric_limits<uint64_t>::max)() - 1,
                          strings, kDefaultStringScanCap, &truncated);
        CHECK(strings.empty(), "unrepresentable live string address is omitted");
        CHECK(truncated, "address-space truncation is surfaced to the caller");

        const uint8_t atZero[] = { 'z','e','r','o',0 };
        ScanStringsBuffer(atZero, sizeof(atZero), 0, strings,
                          kDefaultStringScanCap, &truncated);
        CHECK(strings.size() == 1 && strings[0].address == 0,
              "VA zero remains a valid live string address");
    }

    // ---- AnalysisService mechanics (worker pool, incremental per-pass delivery) ----
    AnalysisService svc([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
        return std::make_unique<StubDisasm>();
    });

    // Project-v3 decisions are copied into the worker request and applied before
    // either the function result or its dependent listing is published. VA zero
    // is a real key: undefining the heuristic raw root at zero must not be lost
    // to sentinel handling, while an exact analyst definition wins at VA 4.
    {
        AnalysisService overridden([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<StubDisasm>();
        });
        auto decisions = std::make_shared<ProjectAnalysisOverrides>();
        decisions->functions.push_back({ 0, PjFunctionAction::Undefine });
        decisions->functions.push_back({ 4, PjFunctionAction::Define, true, 3,
                                         PjOverrideBool::True, "__cdecl",
                                         "void analyst_root(void)", PjFunctionMode::Thumb });
        decisions->data.push_back({ 0, 4, PjDataKind::String, "char[4]" });
        const uint64_t e = overridden.epoch();
        overridden.requestBulkWithListing(
            &autoRaw, Engine::Zydis, Arch::X64, K_Funcs | K_Listing, false, e,
            std::make_shared<ListingLayout>(MakeDefaultListingLayout(autoRaw)), 77,
            {}, 0, {}, decisions);

        bool gotFunctions = false, gotListing = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && !(gotFunctions && gotListing)) {
            AnalysisResult result;
            while (overridden.tryTakeBulk(result)) {
                if (result.epoch != e) continue;
                if (result.funcsValid) {
                    gotFunctions = true;
                    bool sawZero = false, sawFour = false;
                    for (const FuncResult& fn : result.functions) {
                        sawZero |= fn.address == 0;
                        sawFour |= fn.address == 4 && fn.size == 3 && !fn.guessed &&
                                   fn.reason.find("analyst") != std::string::npos &&
                                   fn.analystDefined && fn.noreturnValid && fn.noreturn &&
                                   fn.analystMode == 2 && fn.callingConvention == "__cdecl" &&
                                   fn.prototype == "void analyst_root(void)";
                    }
                    CHECK(!sawZero && sawFour,
                          "analyst define/undefine and exact extent override heuristic functions");
                    const CodeDataSpan* span = result.codeData ? result.codeData->find(0) : nullptr;
                    CHECK(span && span->kind == CodeDataKind::String && span->size == 4 &&
                          span->confidence == CodeDataConfidence::High &&
                          span->evidence.find("analyst") != std::string::npos,
                          "analyst data span overrides heuristic code classification at VA zero");
                }
                if (result.listingValid) {
                    gotListing = true;
                    bool directiveAtZero = false;
                    for (const ListRowR& row : result.listRows)
                        directiveAtZero |= row.type == ListingRowType::DataDirective &&
                                           row.addr == 0 && row.dataKind == CodeDataKind::String;
                    CHECK(directiveAtZero,
                          "dependent listing is built from the authoritative data override map");
                }
            }
            if (!(gotFunctions && gotListing))
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(gotFunctions && gotListing, "override-aware function and listing results delivered");
        overridden.cancelAndWaitIdle();
    }

    // A listing-only request plans descriptors without invoking the decoder or
    // re-running function discovery. This is the critical fold/rebuild fast path.
    {
        auto calls = std::make_shared<std::atomic<size_t>>(0);
        AnalysisService listingOnly([calls](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<SharedCountDisasm>(calls);
        });
        const uint64_t e = listingOnly.epoch();
        auto layout = std::make_shared<ListingLayout>(MakeDefaultListingLayout(bin));
        listingOnly.requestBulkWithListing(&bin, Engine::Zydis, Arch::X64,
                                           K_Listing, false, e, layout, 9,
                                           std::make_shared<const std::vector<StrResult>>(strs));
        bool gotListing = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && !gotListing) {
            AnalysisResult result;
            while (listingOnly.tryTakeBulk(result))
                if (result.epoch == e && result.listingValid) gotListing = true;
            if (!gotListing) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(gotListing, "K_Listing-only descriptor result delivered");
        CHECK(calls->load(std::memory_order_relaxed) == 0,
              "K_Listing-only request makes zero decoder calls");
        listingOnly.cancelAndWaitIdle();
    }

    // On-demand exact page-boundary work runs on the pool, carries the immutable
    // listing revision, and is hard-capped so a far request cannot become an
    // O(section distance) decode sweep.
    {
        const std::string prefixPath = "ds_listing_prefix_service_tmp.bin";
        {
            std::vector<uint8_t> bytes(kListingCodePageBytes * 2 + 15, 0x90);
            std::ofstream f(prefixPath, std::ios::binary);
            f.write((const char*)bytes.data(), (std::streamsize)bytes.size());
        }
        constexpr uint64_t prefixBase = 0x900000;
        BinaryFile prefixBin;
        CHECK(prefixBin.loadRaw(prefixPath, prefixBase), "load prefix-worker fixture");
        auto calls = std::make_shared<std::atomic<size_t>>(0);
        AnalysisService prefixSvc([calls](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<SharedCountDisasm>(calls);
        });
        const uint64_t e = prefixSvc.epoch();
        constexpr uint64_t prefixTopology = 44;
        prefixSvc.requestListingPrefix(&prefixBin, Engine::Zydis, Arch::X64, e,
                                       prefixBase, prefixBase,
                                       prefixBase + kListingCodePageBytes, 33, 0,
                                       prefixTopology);
        AnalysisResult exact;
        bool gotExact = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && !gotExact) {
            AnalysisResult result;
            while (prefixSvc.tryTakeBulk(result)) {
                if (result.epoch == e && result.listingPrefixDone) {
                    exact = std::move(result); gotExact = true;
                }
            }
            if (!gotExact) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(gotExact && exact.listingPrefixValid && exact.listingRevision == 33 &&
              exact.listingTopologyGeneration == prefixTopology &&
              exact.listingPrefixTarget == prefixBase + kListingCodePageBytes,
              "K_ListingPrefix delivers revision/topology-tagged exact target result");
        CHECK(!exact.listingPrefixCheckpoints.empty() &&
              exact.listingPrefixCheckpoints.back().address ==
                  prefixBase + kListingCodePageBytes &&
              exact.listingPrefixCheckpoints.back().prefixSkip == 0,
              "K_ListingPrefix publishes the exact page checkpoint");
        CHECK(calls->load(std::memory_order_relaxed) <= kListingPrefixExactByteCap,
              "exact prefix worker remains inside its published decode-work cap");

        calls->store(0, std::memory_order_relaxed);
        prefixSvc.requestListingPrefix(&prefixBin, Engine::Zydis, Arch::X64, e,
                                       prefixBase, prefixBase,
                                       prefixBase + kListingPrefixExactByteCap + 1, 34);
        AnalysisResult rejected;
        bool gotRejected = false;
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && !gotRejected) {
            AnalysisResult result;
            while (prefixSvc.tryTakeBulk(result)) {
                if (result.epoch == e && result.listingPrefixDone) {
                    rejected = std::move(result); gotRejected = true;
                }
            }
            if (!gotRejected) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(gotRejected && !rejected.listingPrefixValid &&
              calls->load(std::memory_order_relaxed) == 0,
              "over-cap prefix worker rejects without decoder work");
        prefixSvc.cancelAndWaitIdle();
        std::remove(prefixPath.c_str());
    }

    // The pool emits ONE result per pass, so drain everything for `wantEpoch` and
    // merge the per-pass valid flags. Stops early once `done(merged)` holds.
    auto collect = [&](int ms, uint64_t wantEpoch,
                       const std::function<bool(const AnalysisResult&)>& done) -> AnalysisResult {
        AnalysisResult merged; merged.epoch = wantEpoch;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch != wantEpoch) continue;
                merged.kinds |= tmp.kinds;
                if (tmp.stringsValid) {
                    merged.strings = tmp.strings;
                    merged.stringsValid = true;
                    merged.stringsTruncated = tmp.stringsTruncated;
                }
                if (tmp.funcsValid)   { merged.functions = tmp.functions; merged.summary = tmp.summary;
                                        merged.codeData = tmp.codeData; merged.funcsValid = true; }
                if (tmp.listingValid) { merged.listRows = tmp.listRows;
                                        merged.listingCodeBytes = tmp.listingCodeBytes;
                                        merged.listingCodePages = tmp.listingCodePages;
                                        merged.listingRevision = tmp.listingRevision; merged.listingValid = true; }
                if (tmp.xref)         { merged.xref = tmp.xref; }
                if (tmp.algosValid)   { merged.algos = tmp.algos; merged.algosValid = true; }
                if (tmp.callGraphValid) {
                    merged.callEdges = tmp.callEdges;
                    merged.callGraphValid = true;
                }
                if (tmp.crackmeTriageValid) {
                    merged.crackmeTriage = std::move(tmp.crackmeTriage);
                    merged.crackmeTriageValid = true;
                }
                if (tmp.moduleBase)   merged.moduleBase = tmp.moduleBase;
            }
            if (done(merged)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return merged;
    };

    // Bulk K_Strings round-trips with the matching epoch.
    {
        uint64_t e = svc.epoch();
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, e);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) { return r.stringsValid; });
        CHECK(got.stringsValid, "bulk K_Strings produced a stringsValid result");
        CHECK(e == svc.epoch(), "epoch unchanged");
        bool h = false; for (auto& s : got.strings) if (s.text == "Hello, world!") h = true;
        CHECK(h, "worker scanned the ascii string");
    }

    // Epoch gating: a bumped epoch means no result is ever accepted as current.
    {
        uint64_t e = svc.epoch();
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, e);
        svc.bumpEpoch();
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (std::chrono::steady_clock::now() < deadline) {
            AnalysisResult got;
            if (svc.tryTakeBulk(got)) CHECK(got.epoch != svc.epoch(), "superseded result not current-epoch");
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // Incremental delivery: all four passes arrive (as separate results) and merge.
    {
        uint64_t e = svc.epoch();
        auto layout = std::make_shared<ListingLayout>(MakeDefaultListingLayout(bin));
        svc.requestBulkWithListing(&bin, Engine::Zydis, Arch::X64,
                                   K_Funcs | K_Strings | K_Listing | K_Xref,
                                   true, e, layout, 77);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) {
            return r.stringsValid && r.funcsValid && r.listingValid && r.xref != nullptr; });
        CHECK(got.stringsValid, "incremental: strings delivered");
        CHECK(got.funcsValid,   "incremental: funcs delivered");
        CHECK(got.codeData && !got.codeData->spans.empty(),
              "incremental: global code/data partition accompanies function discovery");
        CHECK(got.listingValid, "incremental: listing delivered");
        CHECK(got.listingRevision == 77, "incremental: immutable listing revision is carried to the result");
        CHECK(got.xref != nullptr, "incremental: xrefs delivered for the raw section");
        CHECK(got.xref && got.xref->complete &&
              got.xref->stopReason == XrefStopReason::None,
              "incremental: xref completeness metadata survives AnalysisService delivery");
        CHECK(!got.functions.empty() && got.functions[0].address == base,
              "incremental: raw base function delivered");
        CHECK(!got.listRows.empty() && got.listingCodeBytes == bin.bytes().size() &&
              got.listingCodePages == 1,
              "incremental: complete raw code-page map delivered without an instruction cap");
        CHECK(got.listRows[0].type == ListingRowType::RegionHeader && got.listRows[0].addr == base,
              "incremental: raw listing begins with the modeled section header");
        bool basePage = false, eagerInstruction = false;
        for (const auto& r : got.listRows) {
            basePage |= r.type == ListingRowType::CodePage && r.addr == base;
            eagerInstruction |= r.type == ListingRowType::Normal || r.divider;
        }
        CHECK(basePage && !eagerInstruction,
              "incremental: worker emits a lazy base page and no eager instruction rows");

        const ProgressSnapshot beforeLayoutReuse = svc.progress();
        svc.requestBulkWithListing(&bin, Engine::Zydis, Arch::X64,
                                   K_Funcs | K_Listing, true, e, layout, 78);
        AnalysisResult reused = collect(3000, e, [](const AnalysisResult& r) {
            return r.funcsValid && r.listingValid;
        });
        CHECK(reused.funcsValid && reused.listingValid && reused.listingRevision == 78 &&
              reused.listRows.size() == got.listRows.size() &&
              reused.listingCodeBytes == got.listingCodeBytes,
              "cached combined functions/listing request preserves the scanned-string layout");
        CHECK(svc.progress().cacheMisses == beforeLayoutReuse.cacheMisses &&
              svc.progress().cacheHits == beforeLayoutReuse.cacheHits + 3,
              "combined layout reuse retains string inputs and hits the same listing cache");
    }

    // K_CrackmeTriage is a self-contained public request.  Asking for only that
    // bit materializes and publishes every static dependency, then caches the
    // validity-bearing report under the schema-v3 analysis identity.
    {
        const std::string triagePath = "ds_crackme_triage_service_tmp.bin";
        {
            std::ofstream f(triagePath, std::ios::binary);
            const char payload[] =
                "https://pro.license-tmog.com/activate\0"
                "/deactivate\0"
                "server reply accepted; license valid\0";
            f.write(payload, static_cast<std::streamsize>(sizeof(payload)));
        }
        BinaryFile triageBin;
        CHECK(triageBin.loadRaw(triagePath, 0), "loadRaw crackme-triage service fixture");
        const uint64_t e = svc.epoch();
        const ProgressSnapshot before = svc.progress();
        svc.requestBulk(&triageBin, Engine::Zydis, Arch::X64,
                        K_CrackmeTriage, false, e);
        AnalysisResult got = collect(5000, e, [](const AnalysisResult& result) {
            return result.stringsValid && result.funcsValid && result.xref &&
                   result.callGraphValid && result.algosValid &&
                   result.crackmeTriageValid;
        });
        CHECK((got.kinds & K_CrackmeTriage) != 0,
              "K_CrackmeTriage result preserves its public request bit");
        CHECK((got.kinds & (K_Strings | K_Funcs | K_Xref | K_CallGraph | K_Intent)) ==
              (K_Strings | K_Funcs | K_Xref | K_CallGraph | K_Intent),
              "K_CrackmeTriage expands all approved implicit dependencies");
        CHECK(got.stringsValid && got.funcsValid && got.xref &&
              got.callGraphValid && got.algosValid,
              "K_CrackmeTriage dependencies are delivered for direct consumers");
        CHECK(got.crackmeTriageValid,
              "K_CrackmeTriage publishes a validity-bearing report");
        bool foundHost = false, foundActivate = false, foundDeactivate = false;
        for (const auto& endpoint : got.crackmeTriage.endpoints) {
            if (endpoint.host != "pro.license-tmog.com") continue;
            foundHost = true;
            foundActivate = std::find(endpoint.paths.begin(), endpoint.paths.end(),
                                      "/activate") != endpoint.paths.end();
            foundDeactivate = std::find(endpoint.paths.begin(), endpoint.paths.end(),
                                        "/deactivate") != endpoint.paths.end();
        }
        for (const auto& route : got.crackmeTriage.routes)
            foundDeactivate |= route.path == "/deactivate";
        CHECK(foundHost && foundActivate && foundDeactivate,
              "service triage extracts the target-shaped endpoint and routes");
        CHECK(got.crackmeTriage.label == "Unreferenced endpoint string",
              "service triage keeps the weaker label without API/xref correlation");
        CHECK(got.crackmeTriage.completeness.xrefsComplete,
              "service adapter propagates xref completeness");
        const ProgressSnapshot afterMiss = svc.progress();
        CHECK(afterMiss.cacheMisses >= before.cacheMisses + 6,
              "first self-contained triage request computes and caches its dependencies");

        svc.requestBulk(&triageBin, Engine::Zydis, Arch::X64,
                        K_CrackmeTriage, false, e);
        AnalysisResult cached = collect(5000, e, [](const AnalysisResult& result) {
            return result.crackmeTriageValid;
        });
        CHECK(cached.crackmeTriageValid &&
              cached.crackmeTriage.label == got.crackmeTriage.label,
              "identical triage request materializes the cached immutable report");
        CHECK(svc.progress().cacheHits > afterMiss.cacheHits,
              "second triage request records a derived-cache hit");
        svc.cancelAndWaitIdle();
        std::remove(triagePath.c_str());
    }

    // Production-like end-to-end static correlation: a real PE import table,
    // worker-discovered function, whole-image xrefs, and exact WinHTTP stages
    // identify a generic endpoint without executing the fixture.
    {
        BinaryFile networkBinary;
        CHECK(loadAbiFixture("ds_network_service_fixture.exe",
                             buildNetworkServicePe64(true, true, true),
                             networkBinary),
              "load production-shaped WinHTTP service fixture");
        bool sendImport = false, readImport = false, recvImport = false;
        bool hostImport = false;
        for (const auto& imported : networkBinary.imports()) {
            sendImport |= imported.name == "WinHttpSendRequest";
            readImport |= imported.name == "WinHttpReadData";
            recvImport |= imported.name == "recv";
            hostImport |= imported.name == "gethostbyname";
        }
        CHECK(sendImport && readImport && recvImport && hostImport,
              "PE fixture exposes exact WinHTTP and Winsock imports through BinaryFile");

        AnalysisService correlated([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<NetworkServiceDisasm>();
        });
        const uint64_t epoch = correlated.epoch();
        correlated.requestBulk(&networkBinary, Engine::Zydis, Arch::X64,
                               K_CrackmeTriage, false, epoch);
        AnalysisResult result;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline &&
               !result.crackmeTriageValid) {
            AnalysisResult next;
            while (correlated.tryTakeBulk(next)) {
                if (next.epoch == epoch && next.crackmeTriageValid) {
                    result = std::move(next);
                    break;
                }
            }
            if (!result.crackmeTriageValid)
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(result.crackmeTriageValid,
              "service publishes production-shaped correlated triage");
        if (result.crackmeTriageValid) {
            const auto& report = result.crackmeTriage;
            CHECK(!report.endpoints.empty() &&
                  report.endpoints.front().host == "generic-service.example.net",
                  "correlated generic service endpoint ranks first");
            CHECK(report.label == "Hosted reply-server path",
                  "exact send plus reply correlation satisfies hosted honesty gate");
            bool write = false, read = false, exactOwners = false;
            for (const auto& correlation : report.correlations) {
                write |= correlation.stage == NetworkStage::Write;
                read |= correlation.stage == NetworkStage::Read;
                exactOwners |= correlation.functionAddressValid &&
                    correlation.functionAddress == kNetworkServiceImageBase + 0x1000 &&
                    correlation.endpointFunctionAddressValid &&
                    correlation.endpointFunctionAddress == kNetworkServiceImageBase + 0x1000;
            }
            CHECK(write && read && exactOwners,
                  "service correlation retains WinHTTP flow and exact owners");
            CHECK(report.stages[(size_t)NetworkTrailStage::Request].correlationCount != 0 &&
                  report.stages[(size_t)NetworkTrailStage::Reply].correlationCount != 0,
                  "service report exposes correlated Request and Reply stages");

            size_t expectedEndpointOccurrences = 0;
            size_t expectedRouteOccurrences = 0;
            size_t expectedArtifactOccurrences = 0;
            for (const CrackmeTriageEndpoint& endpoint : report.endpoints)
                expectedEndpointOccurrences += endpoint.sources.size();
            for (const CrackmeTriageRoute& route : report.routes)
                expectedRouteOccurrences += route.sources.size();
            for (const NetworkArtifact& artifact : report.artifacts)
                if (artifact.kind == NetworkArtifactKind::License ||
                    artifact.kind == NetworkArtifactKind::Validation ||
                    artifact.kind == NetworkArtifactKind::Authentication ||
                    artifact.kind == NetworkArtifactKind::Success ||
                    artifact.kind == NetworkArtifactKind::Failure ||
                    artifact.kind == NetworkArtifactKind::ReplyMarker)
                    expectedArtifactOccurrences += artifact.sources.size();
            size_t endpointOccurrences = 0;
            size_t routeOccurrences = 0;
            size_t artifactOccurrences = 0;
            bool endpointXref = false;
            bool firstEndpointOccurrence = false;
            bool secondEndpointOccurrence = false;
            bool exactContainingFunction = false;
            bool nearbyBranchLead = false;
            bool proximityDisclaimed = false;
            for (const AuthorizationTrailStringAnchor& anchor :
                 report.authorizationTrail.stringAnchors) {
                endpointOccurrences += anchor.kind ==
                    AuthorizationTrailStringAnchorKind::Endpoint;
                if (anchor.kind ==
                        AuthorizationTrailStringAnchorKind::Endpoint &&
                    anchor.source.addressValid) {
                    firstEndpointOccurrence |= anchor.source.address >=
                            kNetworkServiceStringVA &&
                        anchor.source.address <
                            kNetworkServiceStringVA + 0x40;
                    secondEndpointOccurrence |= anchor.source.address >=
                            kNetworkServiceStringVA + 0x40 &&
                        anchor.source.address <
                            kNetworkServiceStringVA + 0x80;
                }
                routeOccurrences += anchor.kind ==
                    AuthorizationTrailStringAnchorKind::Route;
                artifactOccurrences +=
                    anchor.kind ==
                        AuthorizationTrailStringAnchorKind::LicenseArtifact ||
                    anchor.kind ==
                        AuthorizationTrailStringAnchorKind::ValidationArtifact ||
                    anchor.kind ==
                        AuthorizationTrailStringAnchorKind::AuthenticationArtifact;
                artifactOccurrences +=
                    anchor.kind ==
                        AuthorizationTrailStringAnchorKind::SuccessArtifact ||
                    anchor.kind ==
                        AuthorizationTrailStringAnchorKind::FailureArtifact ||
                    anchor.kind ==
                        AuthorizationTrailStringAnchorKind::ReplyMarkerArtifact;
                for (const AuthorizationTrailStringReference& reference :
                     anchor.references) {
                    if (!reference.reference.addressValid ||
                        reference.reference.address !=
                            kNetworkServiceImageBase + 0x1000)
                        continue;
                    endpointXref |= anchor.kind ==
                        AuthorizationTrailStringAnchorKind::Endpoint;
                    exactContainingFunction |=
                        reference.containingFunctionExact &&
                        reference.containingFunction.addressValid &&
                        reference.containingFunction.address ==
                            kNetworkServiceImageBase + 0x1000;
                    nearbyBranchLead |= reference.nearbyByCodeOrder &&
                        reference.nearbyBranch.addressValid &&
                        reference.nearbyBranch.address ==
                            kNetworkServiceImageBase + 0x1005 &&
                        reference.nearbyBranchAfterReference &&
                        reference.instructionDistance == 5;
                    proximityDisclaimed |= reference.evidence.find(
                        "not proof") != std::string::npos;
                }
            }
            CHECK(endpointOccurrences == expectedEndpointOccurrences &&
                  routeOccurrences == expectedRouteOccurrences &&
                  artifactOccurrences == expectedArtifactOccurrences,
                  "authorization string trace retains every source occurrence instead of sources.front()");
            CHECK(firstEndpointOccurrence && secondEndpointOccurrence,
                  "two equal endpoint literals retain independent source coordinates");
            CHECK(endpointXref && exactContainingFunction &&
                  nearbyBranchLead && proximityDisclaimed,
                  "authorization string trace joins the whole-image xref to its exact owner and bounded non-causal branch lead");

            bool wrapperStatus = false;
            bool callerTerminal = false;
            bool spillHop = false;
            bool reloadHop = false;
            bool returnHop = false;
            bool documentedPendingOrFailureArm = false;
            bool maskedSignIndeterminate = false;
            bool transformedCheckAbsent = true;
            bool transformDisclosed = false;
            for (const NetworkReturnFlow& flow : report.returnFlows) {
                if (!flow.apiIndexValid || flow.apiIndex >= report.apis.size() ||
                    report.apis[flow.apiIndex].canonicalName != "WinHttpReadData")
                    continue;
                wrapperStatus |= flow.functionAddressValid &&
                    flow.functionAddress == kNetworkServiceImageBase + 0x1100 &&
                    flow.lineageAnalysisAttempted;
                transformDisclosed |= !flow.lineageComplete &&
                    flow.lineageIncompleteReason.find("transformed") !=
                        std::string::npos;
                for (const CrackmeTriageReturnDecisionInput& decision :
                     flow.decisions) {
                    if (decision.comparisonAddressValid &&
                        decision.comparisonAddress ==
                            kNetworkServiceImageBase + 0x1102)
                        maskedSignIndeterminate |=
                            decision.takenDisposition ==
                                NetworkReturnDisposition::Indeterminate &&
                            decision.fallthroughDisposition ==
                                NetworkReturnDisposition::Indeterminate;
                    if (decision.comparisonAddressValid &&
                        decision.comparisonAddress ==
                            kNetworkServiceImageBase + 0x1106)
                        transformedCheckAbsent = false;
                    callerTerminal |= decision.comparisonAddressValid &&
                        decision.comparisonAddress ==
                            kNetworkServiceImageBase + 0x1004 &&
                        decision.decisionAddressValid &&
                        decision.decisionAddress ==
                            kNetworkServiceImageBase + 0x1005;
                    documentedPendingOrFailureArm |=
                        decision.takenDisposition ==
                            NetworkReturnDisposition::Indeterminate &&
                        decision.fallthroughDisposition ==
                            NetworkReturnDisposition::Success;
                    for (const ValueProvenanceHop& hop : decision.hops) {
                        spillHop |= hop.kind == ValueProvenanceHopKind::Store;
                        reloadHop |= hop.kind == ValueProvenanceHopKind::Reload;
                        returnHop |=
                            hop.kind == ValueProvenanceHopKind::ReturnFromHelper ||
                            hop.kind == ValueProvenanceHopKind::ReturnToCaller;
                    }
                }
            }
            CHECK(wrapperStatus && callerTerminal,
                  "network status lineage crosses a wrapper return into the caller check");
            CHECK(spillHop && reloadHop && returnHop,
                  "network status lineage retains spill, reload, and return hops");
            CHECK(documentedPendingOrFailureArm,
                  "WinHTTP BOOL zero branch remains pending-or-failure while nonzero is success");
            CHECK(maskedSignIndeterminate,
                  "test status,mask is not mislabeled as a whole-value sign test");
            CHECK(transformedCheckAbsent && transformDisclosed,
                  "arithmetic-derived status checks lose the original API contract and disclose incomplete lineage");

            bool wideSignIndeterminate = false;
            bool reversedCompareIndeterminate = false;
            bool clobberedFlagsNotPaired = true;
            bool exactWidthSignClassified = false;
            for (const NetworkReturnFlow& flow : report.returnFlows) {
                if (!flow.apiIndexValid || flow.apiIndex >= report.apis.size() ||
                    report.apis[flow.apiIndex].canonicalName != "recv")
                    continue;
                for (const CrackmeTriageReturnDecisionInput& decision :
                     flow.decisions) {
                    if (!decision.comparisonAddressValid) continue;
                    if (decision.comparisonAddress ==
                        kNetworkServiceImageBase + 0x1141)
                        wideSignIndeterminate |=
                            decision.takenDisposition ==
                                NetworkReturnDisposition::Indeterminate &&
                            decision.fallthroughDisposition ==
                                NetworkReturnDisposition::Indeterminate;
                    if (decision.comparisonAddress ==
                        kNetworkServiceImageBase + 0x1144)
                        reversedCompareIndeterminate |=
                            decision.takenDisposition ==
                                NetworkReturnDisposition::Indeterminate &&
                            decision.fallthroughDisposition ==
                                NetworkReturnDisposition::Indeterminate;
                    if (decision.comparisonAddress ==
                        kNetworkServiceImageBase + 0x1147)
                        clobberedFlagsNotPaired = false;
                    if (decision.comparisonAddress ==
                            kNetworkServiceImageBase + 0x114B &&
                        decision.decisionAddressValid &&
                        decision.decisionAddress ==
                            kNetworkServiceImageBase + 0x114C)
                        exactWidthSignClassified |=
                            decision.takenDisposition ==
                                NetworkReturnDisposition::Failure &&
                            decision.fallthroughDisposition ==
                                NetworkReturnDisposition::Success;
                }
            }
            CHECK(wideSignIndeterminate,
                  "zero-extended rax sign test does not inspect a signed Win32 return's bit 31");
            CHECK(reversedCompareIndeterminate,
                  "cmp zero,status is not classified like cmp status,zero");
            CHECK(clobberedFlagsNotPaired,
                  "compare-to-branch pairing stops when an intervening instruction rewrites flags");
            CHECK(exactWidthSignClassified,
                  "canonical 32-bit sign test retains documented recv failure/success arms");

            bool pointerFlowFound = false;
            bool addressArgumentDecisionAbsent = true;
            bool exchangeDecisionAbsent = true;
            bool pointeeUseDisclosed = false;
            for (const NetworkReturnFlow& flow : report.returnFlows) {
                if (!flow.apiIndexValid || flow.apiIndex >= report.apis.size() ||
                    report.apis[flow.apiIndex].canonicalName !=
                        "gethostbyname")
                    continue;
                pointerFlowFound = true;
                pointeeUseDisclosed |= !flow.lineageComplete &&
                    flow.lineageIncompleteReason.find("pointee") !=
                        std::string::npos;
                for (const CrackmeTriageReturnDecisionInput& decision :
                     flow.decisions) {
                    if (!decision.comparisonAddressValid) continue;
                    if (decision.comparisonAddress ==
                        kNetworkServiceImageBase + 0x1163)
                        addressArgumentDecisionAbsent = false;
                    if (decision.comparisonAddress ==
                        kNetworkServiceImageBase + 0x1167)
                        exchangeDecisionAbsent = false;
                }
            }
            CHECK(pointerFlowFound && addressArgumentDecisionAbsent &&
                      exchangeDecisionAbsent && pointeeUseDisclosed,
                  "pointee call arguments and address-dependent exchanges never inherit a pointer API return contract");
        }
        correlated.cancelAndWaitIdle();
    }

    // Exact network-import xref owners must survive the candidate cap even
    // when the request endpoint is assembled dynamically and leaves no
    // endpoint literal/correlation for candidate discovery.
    {
        BinaryFile dynamicEndpointBinary;
        CHECK(loadAbiFixture("ds_dynamic_endpoint_service_fixture.exe",
                             buildNetworkServicePe64(false, false),
                             dynamicEndpointBinary),
              "load exact-network-import fixture without endpoint literals");
        AnalysisService dynamicEndpointService(
            [](Engine, Arch) -> std::unique_ptr<IDisassembler> {
                return std::make_unique<NetworkServiceDisasm>();
            });
        const uint64_t epoch = dynamicEndpointService.epoch();
        dynamicEndpointService.requestBulk(
            &dynamicEndpointBinary, Engine::Zydis, Arch::X64,
            K_CrackmeTriage, false, epoch);
        AnalysisResult result;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline &&
               !result.crackmeTriageValid) {
            AnalysisResult next;
            while (dynamicEndpointService.tryTakeBulk(next)) {
                if (next.epoch == epoch && next.crackmeTriageValid) {
                    result = std::move(next);
                    break;
                }
            }
            if (!result.crackmeTriageValid)
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(result.crackmeTriageValid,
              "service publishes network triage without an endpoint literal");
        if (result.crackmeTriageValid) {
            const CrackmeTriageReport& report = result.crackmeTriage;
            CHECK(report.endpoints.empty(),
                  "dynamic-endpoint fixture has no static endpoint evidence");
            bool exactRead = false;
            bool callerDecision = false;
            for (const NetworkReturnFlow& flow : report.returnFlows) {
                if (!flow.apiIndexValid || flow.apiIndex >= report.apis.size() ||
                    report.apis[flow.apiIndex].canonicalName !=
                        "WinHttpReadData")
                    continue;
                exactRead |= flow.functionAddressValid &&
                    flow.functionAddress == kNetworkServiceImageBase + 0x1100;
                for (const CrackmeTriageReturnDecisionInput& decision :
                     flow.decisions)
                    callerDecision |= decision.decisionAddressValid &&
                        decision.decisionAddress ==
                            kNetworkServiceImageBase + 0x1005;
            }
            CHECK(exactRead && callerDecision,
                  "exact Read import owner drives wrapper-to-caller status provenance without endpoint evidence");
        }
        dynamicEndpointService.cancelAndWaitIdle();
    }

    // Production adapter regression: no endpoint literal is needed to recover
    // a TLS/entry startup gate. A reply buffer crosses a direct helper and a
    // register/stack spill, the allow arm writes durable state, and a later
    // startup read of the exact identity is linked back to that write.
    {
        BinaryFile authorizationBinary;
        CHECK(loadAbiFixture("ds_authorization_service_fixture.exe",
                             buildAuthorizationServicePe64(),
                             authorizationBinary),
              "load production-shaped remembered-access fixture");
        CHECK(authorizationBinary.peTls().directoryValid &&
              authorizationBinary.peTls().callbacks.size() == 1 &&
              authorizationBinary.peTls().callbacks.front() ==
                  kAuthorizationImageBase + 0x1100,
              "PE fixture exposes the startup gate as a validated TLS callback");

        AnalysisService authorizationService(
            [](Engine, Arch) -> std::unique_ptr<IDisassembler> {
                return std::make_unique<AuthorizationServiceDisasm>();
            });
        const uint64_t epoch = authorizationService.epoch();
        authorizationService.requestBulk(&authorizationBinary, Engine::Zydis,
                                         Arch::X64, K_CrackmeTriage, false,
                                         epoch);
        AnalysisResult result;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline &&
               !result.crackmeTriageValid) {
            AnalysisResult next;
            while (authorizationService.tryTakeBulk(next)) {
                if (next.epoch == epoch && next.crackmeTriageValid) {
                    result = std::move(next);
                    break;
                }
            }
            if (!result.crackmeTriageValid)
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(result.crackmeTriageValid,
              "service publishes remembered-access authorization analysis");
        if (result.crackmeTriageValid) {
            const CrackmeTriageReport& triage = result.crackmeTriage;
            const AuthorizationAnalysisReport& report = triage.authorization;
            CHECK(triage.endpoints.empty(),
                  "startup authorization remains visible without an endpoint");
            CHECK(!triage.replyDecisionFlows.empty(),
                  "reply buffer provenance reaches a helper comparison");
            bool bareReplyPointerRejected = true;
            bool replyLeaPointerRejected = true;
            bool replyMovzxContentRetained = false;
            bool dereferencingHelperRetained = false;
            bool pointerOnlyHelperRejected = true;
            bool hostileComparatorRejected = true;
            for (const NetworkReplyDecisionFlow& flow :
                  triage.replyDecisionFlows) {
                if (flow.comparisonAddressValid &&
                    flow.comparisonAddress ==
                        kAuthorizationImageBase + 0x1402)
                    bareReplyPointerRejected = false;
                if (flow.comparisonAddressValid &&
                    flow.comparisonAddress ==
                        kAuthorizationImageBase + 0x1426)
                    replyLeaPointerRejected = false;
                if (flow.comparisonAddressValid &&
                    flow.comparisonAddress ==
                        kAuthorizationImageBase + 0x142A &&
                    flow.decisionAddressValid &&
                    flow.decisionAddress ==
                        kAuthorizationImageBase + 0x142B)
                    replyMovzxContentRetained = true;
                if (flow.comparisonAddressValid &&
                    flow.comparisonAddress ==
                        kAuthorizationImageBase + 0x1206 &&
                    flow.decisionAddressValid &&
                    flow.decisionAddress ==
                        kAuthorizationImageBase + 0x1208)
                    dereferencingHelperRetained = true;
                if (flow.comparisonAddressValid &&
                    (flow.comparisonAddress ==
                         kAuthorizationImageBase + 0x1456 ||
                     flow.comparisonAddress ==
                         kAuthorizationImageBase + 0x1457))
                    pointerOnlyHelperRejected = false;
                if (flow.comparisonAddressValid &&
                    flow.comparisonAddress ==
                        kAuthorizationImageBase + 0x1547)
                    hostileComparatorRejected = false;
            }
            CHECK(bareReplyPointerRejected,
                  "bare reply-buffer register is not treated as proven output contents");
            CHECK(replyLeaPointerRejected,
                  "LEA of proven reply storage remains an address, not reply contents");
            CHECK(replyMovzxContentRetained,
                  "MOVZX from proven reply storage remains traceable to its branch");
            CHECK(dereferencingHelperRetained,
                  "helper dereference of a proven reply pointer remains traceable");
            CHECK(pointerOnlyHelperRejected,
                  "pointer-only helper return does not fabricate reply-content lineage");
            CHECK(hostileComparatorRejected,
                  "unrelated.dll!strcmp does not inherit an equality-comparator contract");

            size_t readIndex = (std::numeric_limits<size_t>::max)();
            size_t writeIndex = (std::numeric_limits<size_t>::max)();
            for (size_t index = 0; index < report.stateOperations.size(); ++index) {
                const PersistentStateOperation& operation =
                    report.stateOperations[index];
                if (operation.access == PersistentStateAccess::Read &&
                    operation.identity.kind == PersistentStateKind::Registry)
                    readIndex = index;
                if (operation.access == PersistentStateAccess::Write &&
                    operation.identity.kind == PersistentStateKind::Registry)
                    writeIndex = index;
            }
            const bool readFound = readIndex !=
                (std::numeric_limits<size_t>::max)();
            const bool writeFound = writeIndex !=
                (std::numeric_limits<size_t>::max)();
            CHECK(readFound && writeFound,
                  "production adapter retains exact registry read and write operations");
            if (readFound && writeFound) {
                CHECK(report.stateOperations[readIndex].startupReachable &&
                      report.stateOperations[readIndex].startupDepthValid &&
                      report.stateOperations[readIndex].startupDepth == 0,
                      "TLS-root registry read is startup reachable at depth zero");
                CHECK(PersistentStateIdentityEquivalentExact(
                          report.stateOperations[readIndex].identity,
                          report.stateOperations[writeIndex].identity),
                      "startup read and online-success write have one exact identity");
            }

            bool startupFlow = false;
            bool persistentOutputFlow = false;
            bool persistentOutputReload = false;
            bool persistentOutputComparison = false;
            bool persistentOutputBranch = false;
            bool pointerOnlyOutputCheckAbsent = true;
            bool proEntitlement = false;
            bool apiReturnEntitlement = false;
            bool unknownEntitlementLabelsEmpty = true;
            bool replyFlow = false;
            bool remembered = false;
            bool replyStage = false;
            bool writeStage = false;
            bool readStage = false;
            bool gateStage = false;
            bool localInputFlow = false;
            bool localLocations = false;
            bool localExpectedValue = false;
            bool localInputStage = false;
            bool localCompareStage = false;
            bool localOriginHop = false;
            bool localCompareHop = false;
            bool localBranchHop = false;
            bool mainReturnsDirectionNeutral = false;
            bool helperReturnsDirectionNeutral = false;
            bool denialDialogNotAllow = false;
            bool reconvergedTailExcluded = false;
            bool cappedPathIncomplete = false;
            for (const AuthorizationFlow& flow : report.flows) {
                if (flow.entitlementKind ==
                    AuthorizationEntitlementKind::Unknown)
                    unknownEntitlementLabelsEmpty &=
                        flow.entitlementLabel.empty();
                if (flow.gateSource == AuthorizationGateSource::ApiReturn)
                    apiReturnEntitlement |=
                        flow.entitlementKind ==
                            AuthorizationEntitlementKind::Pro &&
                        flow.entitlementLabel == "pro" &&
                        flow.originExpression == "rax";
                startupFlow |= flow.stateReadOperationIndexValid;
                if (flow.gateSource == AuthorizationGateSource::PersistentOutput) {
                    persistentOutputFlow |= flow.stateReadOperationIndexValid &&
                        !flow.originExpression.empty() &&
                        flow.expectedValue == "1";
                    proEntitlement |=
                        flow.entitlementKind ==
                            AuthorizationEntitlementKind::Pro &&
                        flow.entitlementLabel == "pro";
                    for (const ValueProvenanceHop& hop : flow.provenance) {
                        persistentOutputReload |=
                            hop.kind == ValueProvenanceHopKind::Reload &&
                            hop.addressValid &&
                            hop.address == kAuthorizationImageBase + 0x1110;
                        persistentOutputComparison |=
                            hop.kind == ValueProvenanceHopKind::Compare &&
                            hop.addressValid &&
                            hop.address == kAuthorizationImageBase + 0x1111;
                        persistentOutputBranch |=
                            hop.kind == ValueProvenanceHopKind::Branch &&
                            hop.addressValid &&
                            hop.address == kAuthorizationImageBase + 0x1112;
                        if (hop.kind == ValueProvenanceHopKind::Compare &&
                            hop.addressValid &&
                            hop.address == kAuthorizationImageBase + 0x110E)
                            pointerOnlyOutputCheckAbsent = false;
                    }
                }
                replyFlow |= flow.networkReplyFlowIndexValid;
                remembered |= flow.rememberedAccessLinked;
                if (flow.localInputFlow) {
                    localInputFlow |= !flow.networkReplyFlowIndexValid &&
                        flow.gateSource == AuthorizationGateSource::LocalInput;
                    localLocations |= flow.inputLocation.addressValid &&
                        flow.inputLocation.address ==
                            kAuthorizationImageBase + 0x1525 &&
                        flow.comparisonLocation.addressValid &&
                        flow.comparisonLocation.address ==
                            kAuthorizationImageBase + 0x1527 &&
                        flow.decisionLocation.addressValid &&
                        flow.decisionLocation.address ==
                            kAuthorizationImageBase + 0x1529;
                    localExpectedValue |= flow.expectedValue ==
                        "\"OPEN-SESAME\"";
                    for (const ValueProvenanceHop& hop : flow.provenance) {
                        localOriginHop |=
                            hop.kind == ValueProvenanceHopKind::Origin &&
                            hop.addressValid && hop.address ==
                                kAuthorizationImageBase + 0x1524;
                        localCompareHop |=
                            hop.kind == ValueProvenanceHopKind::Compare &&
                            hop.addressValid && hop.address ==
                                kAuthorizationImageBase + 0x1527;
                        localBranchHop |=
                            hop.kind == ValueProvenanceHopKind::Branch &&
                            hop.addressValid && hop.address ==
                                kAuthorizationImageBase + 0x1529;
                    }
                    auto directionNeutralAt = [&](uint64_t address) {
                        bool neutral = false;
                        bool directional = false;
                        auto inspect = [&](const AuthorizationPath& path) {
                            for (const AuthorizationEvidence& evidence :
                                 path.evidence) {
                                if (!evidence.location.addressValid ||
                                    evidence.location.address != address)
                                    continue;
                                neutral |= evidence.kind ==
                                    AuthorizationEvidenceKind::Unknown;
                                directional |= evidence.kind ==
                                        AuthorizationEvidenceKind::SuccessIndicator ||
                                    evidence.kind ==
                                        AuthorizationEvidenceKind::EarlyFailureReturn;
                            }
                        };
                        inspect(flow.takenPath);
                        inspect(flow.fallthroughPath);
                        return neutral && !directional;
                    };
                    if (flow.decisionLocation.addressValid &&
                        flow.decisionLocation.address ==
                            kAuthorizationImageBase + 0x1012) {
                        mainReturnsDirectionNeutral =
                            directionNeutralAt(kAuthorizationImageBase + 0x1013) &&
                            directionNeutralAt(kAuthorizationImageBase + 0x1016) &&
                            flow.takenPath.outcome == AuthorizationOutcome::Unknown &&
                            flow.fallthroughPath.outcome ==
                                AuthorizationOutcome::Unknown;
                    }
                    if (flow.decisionLocation.addressValid &&
                        flow.decisionLocation.address ==
                            kAuthorizationImageBase + 0x1529) {
                        helperReturnsDirectionNeutral =
                            directionNeutralAt(kAuthorizationImageBase + 0x152C) &&
                            directionNeutralAt(kAuthorizationImageBase + 0x1536);
                        bool dialogContinuation = false;
                        for (const AuthorizationEvidence& evidence :
                             flow.takenPath.evidence)
                            dialogContinuation |= evidence.kind ==
                                    AuthorizationEvidenceKind::ApplicationContinuation &&
                                evidence.location.addressValid &&
                                evidence.location.address ==
                                    kAuthorizationImageBase + 0x1535;
                        denialDialogNotAllow = !dialogContinuation &&
                            flow.takenPath.outcome !=
                                AuthorizationOutcome::LikelyAllow;
                    }
                    if (flow.decisionLocation.addressValid &&
                        flow.decisionLocation.address ==
                            kAuthorizationImageBase + 0x1569) {
                        bool sharedTailEvidence = false;
                        for (const AuthorizationPath* path :
                             {&flow.takenPath, &flow.fallthroughPath})
                            for (const AuthorizationEvidence& evidence :
                                 path->evidence)
                                sharedTailEvidence |=
                                    evidence.location.addressValid &&
                                    (evidence.location.address ==
                                         kAuthorizationImageBase + 0x1578 ||
                                     evidence.location.address ==
                                         kAuthorizationImageBase + 0x1579);
                        reconvergedTailExcluded = !sharedTailEvidence &&
                            flow.takenPath.complete &&
                            flow.fallthroughPath.complete &&
                            flow.takenPath.outcome == AuthorizationOutcome::Unknown &&
                            flow.fallthroughPath.outcome ==
                                AuthorizationOutcome::Unknown;
                    }
                    if (flow.decisionLocation.addressValid &&
                        flow.decisionLocation.address ==
                            kAuthorizationImageBase + 0x1589) {
                        const AuthorizationPath& capped = flow.fallthroughPath;
                        cappedPathIncomplete = !capped.complete &&
                            capped.evidence.size() == 64 &&
                            capped.honestyLabel.find("64-effect") !=
                                std::string::npos;
                    }
                }
                for (const AuthorizationStageRecord& stage : flow.stages) {
                    replyStage |= stage.stage == AuthorizationStage::ReplyCheck;
                    writeStage |= stage.stage == AuthorizationStage::StateWrite;
                    readStage |= stage.stage == AuthorizationStage::StartupRead;
                    gateStage |= stage.stage == AuthorizationStage::StartupGate;
                    if (flow.localInputFlow) {
                        localInputStage |=
                            stage.stage == AuthorizationStage::InputRead &&
                            stage.location.addressValid &&
                            stage.location.address ==
                                kAuthorizationImageBase + 0x1525;
                        localCompareStage |=
                            stage.stage == AuthorizationStage::Compare &&
                            stage.location.addressValid &&
                            stage.location.address ==
                                kAuthorizationImageBase + 0x1527;
                    }
                }
            }
            CHECK(startupFlow && replyFlow,
                  "analysis publishes both startup-only and network reply flows");
            CHECK(persistentOutputFlow && persistentOutputReload &&
                      persistentOutputComparison &&
                      persistentOutputBranch &&
                      pointerOnlyOutputCheckAbsent,
                  "startup gate follows a persisted byte load into its compare and branch");
            CHECK(proEntitlement,
                  "camel-case isPro identity tokenizes to the exact pro entitlement");
            CHECK(apiReturnEntitlement,
                  "persistent API status gate carries the same exact pro identity label without becoming output-content acceptance");
            CHECK(unknownEntitlementLabelsEmpty,
                  "unknown entitlement kinds do not fabricate a generic label");
            CHECK(remembered,
                  "online-success state write links to the exact next-launch read");
            CHECK(replyStage && writeStage && readStage && gateStage,
                  "remembered chain exposes reply, write, startup-read, and gate stages");
            CHECK(localInputFlow && localLocations && localExpectedValue,
                  "production adapter publishes the exact local input, comparison, decision, and expected serial");
            CHECK(localInputStage && localCompareStage && localOriginHop &&
                      localCompareHop && localBranchHop,
                  "local credential flow preserves input-ready/compare stages and ordered call/compare/branch provenance");
            CHECK(mainReturnsDirectionNeutral && helperReturnsDirectionNeutral,
                  "generic main/helper returns of zero or one remain direction-neutral without a proven contract");
            CHECK(denialDialogNotAllow,
                  "an exact denial dialog does not become application-continuation/allow evidence without success corroboration");
            CHECK(reconvergedTailExcluded,
                  "diamond reconvergence keeps shared-tail effects off both decision edges");
            CHECK(cappedPathIncomplete &&
                      !report.completeness.pathsComplete,
                  "the 64-effect adapter cap propagates path/report incompleteness");
            CHECK(report.completeness.startupRootsComplete &&
                  !report.completeness.startupDepthTruncated,
                  "entry/TLS startup traversal completes within its bounded budget");
        }
        authorizationService.cancelAndWaitIdle();
    }

    // Authorization Trail regression: a secondary predicate in a retained
    // helper must stay connected to a source-linked global predicate when the
    // helper is reachable only from the global predicate's true arm.
    {
        BinaryFile authorizationBinary;
        CHECK(loadAbiFixture("ds_authorization_interproc_fixture.exe",
                             buildAuthorizationServicePe64(),
                             authorizationBinary),
              "load interprocedural authorization fixture");
        AnalysisService authorizationService(
            [](Engine, Arch) -> std::unique_ptr<IDisassembler> {
                return std::make_unique<
                    InterprocAuthorizationServiceDisasm>();
            });
        const uint64_t epoch = authorizationService.epoch();
        authorizationService.requestBulk(&authorizationBinary, Engine::Zydis,
                                         Arch::X64, K_CrackmeTriage, false,
                                         epoch);
        AnalysisResult result;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline &&
               !result.crackmeTriageValid) {
            AnalysisResult next;
            while (authorizationService.tryTakeBulk(next)) {
                if (next.epoch == epoch && next.crackmeTriageValid) {
                    result = std::move(next);
                    break;
                }
            }
            if (!result.crackmeTriageValid)
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(result.crackmeTriageValid,
              "service publishes interprocedural authorization trail");
        if (result.crackmeTriageValid) {
            const AuthorizationTrailReport& trail =
                result.crackmeTriage.authorizationTrail;
            const AuthorizationTrailPredicate* global = nullptr;
            const AuthorizationTrailPredicate* secondary = nullptr;
            for (const AuthorizationTrailPredicate& predicate :
                 trail.predicates) {
                if (!predicate.function.addressValid) continue;
                if (predicate.function.address ==
                    kAuthorizationImageBase + 0x1500)
                    global = &predicate;
                if (predicate.function.address ==
                    kAuthorizationImageBase + 0x1300)
                    secondary = &predicate;
            }
            CHECK(trail.completeness.predicateRelationsComplete,
                  "paired direct-call closures complete for clean helper chain");
            CHECK(global && global->authorizationSourceLinked &&
                      global->role == AuthorizationTrailPredicateRole::Global,
                  "source-proved predicate is ranked as the global gate");
            CHECK(secondary && secondary->role ==
                      AuthorizationTrailPredicateRole::Secondary,
                  "predicate inside true-only helper is retained as a secondary gate");
            CHECK(secondary &&
                      secondary->evidence.find("secondary-path proof") !=
                          std::string::npos &&
                      secondary->evidence.find("0x180001125") !=
                          std::string::npos &&
                      secondary->evidence.find("0x180001202") !=
                          std::string::npos,
                  "secondary gate preserves its exact helper-chain and branch evidence");

            bool secondaryUseInHelper = false;
            bool guardedProtectedCall = false;
            if (secondary) {
                for (size_t useIndex : secondary->useIndices) {
                    if (useIndex >= trail.predicateUses.size()) continue;
                    const AuthorizationTrailPredicateUse& use =
                        trail.predicateUses[useIndex];
                    secondaryUseInHelper |= use.caller.addressValid &&
                        use.caller.address ==
                            kAuthorizationImageBase + 0x1200 &&
                        use.callsite.addressValid &&
                        use.callsite.address ==
                            kAuthorizationImageBase + 0x1200 &&
                        use.branch.addressValid &&
                        use.branch.address ==
                            kAuthorizationImageBase + 0x1202;
                }
                for (size_t operationIndex :
                     secondary->guardedOperationIndices) {
                    if (operationIndex >= trail.operations.size()) continue;
                    const AuthorizationTrailFeatureOperation& operation =
                        trail.operations[operationIndex];
                    guardedProtectedCall |= operation.location.addressValid &&
                        operation.location.address ==
                            kAuthorizationImageBase + 0x1203 &&
                        operation.kind ==
                            AuthorizationTrailOperationKind::FeatureAction;
                }
            }
            CHECK(secondaryUseInHelper,
                  "secondary predicate retains exact helper call and branch coordinates");
            CHECK(guardedProtectedCall,
                  "secondary predicate retains its downstream protected call");
            bool warnsGlobalOnlyInsufficient = false;
            for (const AuthorizationTrailWarning& warning : trail.warnings)
                warnsGlobalOnlyInsufficient |= warning.kind ==
                    AuthorizationTrailWarningKind::SecondaryGateRequired &&
                    !warning.secondaryPredicateIndices.empty() &&
                    !warning.operationIndices.empty();
            CHECK(warnsGlobalOnlyInsufficient,
                  "trail warns that changing only the global gate misses the helper gate");
        }
        authorizationService.cancelAndWaitIdle();

        AnalysisService sharedHelperService(
            [](Engine, Arch) -> std::unique_ptr<IDisassembler> {
                return std::make_unique<
                    SharedInterprocAuthorizationServiceDisasm>();
            });
        const uint64_t sharedEpoch = sharedHelperService.epoch();
        sharedHelperService.requestBulk(&authorizationBinary, Engine::Zydis,
                                        Arch::X64, K_CrackmeTriage, false,
                                        sharedEpoch);
        AnalysisResult sharedResult;
        const auto sharedDeadline = std::chrono::steady_clock::now() +
                                    std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < sharedDeadline &&
               !sharedResult.crackmeTriageValid) {
            AnalysisResult next;
            while (sharedHelperService.tryTakeBulk(next)) {
                if (next.epoch == sharedEpoch && next.crackmeTriageValid) {
                    sharedResult = std::move(next);
                    break;
                }
            }
            if (!sharedResult.crackmeTriageValid)
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(sharedResult.crackmeTriageValid,
              "service publishes shared-helper negative control");
        if (sharedResult.crackmeTriageValid) {
            const AuthorizationTrailReport& trail =
                sharedResult.crackmeTriage.authorizationTrail;
            bool globalRetained = false;
            bool nestedPromoted = false;
            for (const AuthorizationTrailPredicate& predicate :
                 trail.predicates) {
                globalRetained |= predicate.function.addressValid &&
                    predicate.function.address ==
                        kAuthorizationImageBase + 0x1500 &&
                    predicate.role ==
                        AuthorizationTrailPredicateRole::Global;
                nestedPromoted |= predicate.function.addressValid &&
                    predicate.function.address ==
                        kAuthorizationImageBase + 0x1300 &&
                    predicate.role ==
                        AuthorizationTrailPredicateRole::Secondary;
            }
            CHECK(trail.completeness.predicateRelationsComplete &&
                      globalRetained && !nestedPromoted,
                  "helper reachable from both arms cannot promote its nested predicate");
        }
        sharedHelperService.cancelAndWaitIdle();
    }

    // Authorization Trail provenance/operation regression: local format
    // acceptance cannot source-link an object boolean, a zero-is-success API
    // status cannot be copied raw into a nonzero-is-true field, and only a
    // distinct exact protected API (not the durable license write beside it)
    // may support the protected-operation stage.
    {
        BinaryFile authorizationBinary;
        CHECK(loadAbiFixture("ds_authorization_provenance_fixture.exe",
                             buildAuthorizationProvenancePe64(),
                             authorizationBinary),
              "load authorization provenance fixture");
        bool verifierImportParsed = false;
        bool protectedImportParsed = false;
        bool hostileProtectedImportParsed = false;
        for (const BinaryFile::Import& imported : authorizationBinary.imports()) {
            verifierImportParsed |= imported.addressKnown &&
                imported.iatVA == kAuthorizationProvenanceVerifyIat &&
                imported.dll == "bcrypt.dll" &&
                imported.name == "BCryptVerifySignature";
            protectedImportParsed |= imported.addressKnown &&
                imported.iatVA == kAuthorizationProvenanceProtectedIat &&
                imported.dll == "advapi32.dll" &&
                imported.name == "CreateServiceW";
            hostileProtectedImportParsed |= imported.addressKnown &&
                imported.iatVA == kAuthorizationProvenanceHostileProtectedIat &&
                imported.dll == "api-ms-win-security-fake.dll" &&
                imported.name == "CreateServiceW";
        }
        CHECK(verifierImportParsed,
              "authorization provenance fixture exposes exact bcrypt verifier import");
        CHECK(protectedImportParsed && hostileProtectedImportParsed,
              "authorization provenance fixture exposes canonical and hostile protected-operation imports");
        AnalysisService authorizationService(
            [](Engine, Arch) -> std::unique_ptr<IDisassembler> {
                return std::make_unique<
                    AuthorizationProvenanceServiceDisasm>();
            });
        const uint64_t epoch = authorizationService.epoch();
        authorizationService.requestBulk(&authorizationBinary, Engine::Zydis,
                                         Arch::X64, K_CrackmeTriage, false,
                                         epoch);
        AnalysisResult result;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline &&
               !result.crackmeTriageValid) {
            AnalysisResult next;
            while (authorizationService.tryTakeBulk(next)) {
                if (next.epoch == epoch && next.crackmeTriageValid) {
                    result = std::move(next);
                    break;
                }
            }
            if (!result.crackmeTriageValid)
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(result.crackmeTriageValid,
              "service publishes authorization provenance fixture");
        if (result.crackmeTriageValid) {
            const CrackmeTriageReport& triage = result.crackmeTriage;
            const AuthorizationTrailReport& trail = triage.authorizationTrail;

            auto predicateAt = [&](uint64_t address)
                -> const AuthorizationTrailPredicate* {
                for (const AuthorizationTrailPredicate& predicate :
                     trail.predicates)
                    if (predicate.function.addressValid &&
                        predicate.function.address == address)
                        return &predicate;
                return nullptr;
            };
            auto lineageAt = [&](int64_t displacement)
                -> const AuthorizationTrailFieldLineage* {
                for (const AuthorizationTrailFieldLineage& lineage :
                     trail.fieldLineages)
                    if (lineage.field.exact &&
                        lineage.field.displacement == displacement &&
                        lineage.field.widthBits == 8)
                        return &lineage;
                return nullptr;
            };
            auto hasDerivedWriteAt = [](const AuthorizationTrailFieldLineage* lineage,
                                        uint64_t address) {
                if (!lineage) return false;
                for (const AuthorizationTrailFieldAccess& write : lineage->writes)
                    if (write.location.addressValid &&
                        write.location.address == address &&
                        write.authorizationDerived)
                        return true;
                return false;
            };

            const AuthorizationTrailPredicate* localPredicate = predicateAt(
                kAuthorizationImageBase + 0x1200);
            const AuthorizationTrailPredicate* rawZeroPredicate = predicateAt(
                kAuthorizationImageBase + 0x1400);
            const AuthorizationTrailPredicate* verifiedPredicate = predicateAt(
                kAuthorizationImageBase + 0x1580);
            const AuthorizationTrailPredicate* sameFieldUnreachedPredicate =
                predicateAt(kAuthorizationImageBase + 0x1590);
            const AuthorizationTrailFieldLineage* localField = lineageAt(0x110);
            const AuthorizationTrailFieldLineage* rawZeroField = lineageAt(0x120);
            const AuthorizationTrailFieldLineage* verifiedField = lineageAt(0x138);

            CHECK(localPredicate && localField,
                  "adapter retains the local-format field and predicate");
            CHECK(localPredicate && !localPredicate->authorizationSourceLinked &&
                      localPredicate->role !=
                          AuthorizationTrailPredicateRole::Global &&
                      localField && !localField->authorizationSourceLinked &&
                      !hasDerivedWriteAt(localField,
                          kAuthorizationImageBase + 0x110D),
                  "local-format-only allow path does not source-link a field/global predicate");
            bool localUseHasLogicalWording = false;
            bool localUseOverstatesAuthorization = false;
            if (localPredicate) {
                for (size_t useIndex : localPredicate->useIndices) {
                    if (useIndex >= trail.predicateUses.size()) continue;
                    const std::string& evidence =
                        trail.predicateUses[useIndex].evidence;
                    localUseHasLogicalWording |=
                        evidence.find("logical true/false paths") !=
                        std::string::npos;
                    localUseOverstatesAuthorization |=
                        evidence.find("locked/permitted") !=
                            std::string::npos ||
                        evidence.find("permitted/locked") !=
                            std::string::npos;
                }
            }
            CHECK(localUseHasLogicalWording &&
                      !localUseOverstatesAuthorization,
                  "an unlinked boolean return use is labelled logical true/false, not permitted/locked");

            CHECK(rawZeroPredicate && rawZeroField,
                  "adapter retains raw zero-is-success verifier field and predicate");
            CHECK(rawZeroPredicate &&
                      !rawZeroPredicate->authorizationSourceLinked &&
                      rawZeroField && !rawZeroField->authorizationSourceLinked &&
                      !hasDerivedWriteAt(rawZeroField,
                          kAuthorizationImageBase + 0x1306),
                  "raw zero-is-success status cannot become a nonzero-is-true authorization field");

            CHECK(verifiedPredicate && verifiedField,
                  "adapter retains materialized verifier field and predicate");
            CHECK(verifiedPredicate &&
                      verifiedPredicate->authorizationSourceLinked,
                  "materialized zero-is-success result source-links its predicate");
            CHECK(sameFieldUnreachedPredicate &&
                      !sameFieldUnreachedPredicate->authorizationSourceLinked,
                  "an unrelated predicate reading the same exact field does not inherit another read's temporal source edge");
            CHECK(verifiedField && verifiedField->authorizationSourceLinked,
                  "materialized zero-is-success result source-links its exact field slice");
            CHECK(hasDerivedWriteAt(verifiedField,
                      kAuthorizationImageBase + 0x1508),
                  "zero-is-success verifier links only after a true-exclusive nonzero materialization");
            bool exactStoreReadEdge = false;
            if (verifiedField && verifiedPredicate &&
                sameFieldUnreachedPredicate) {
                for (const AuthorizationTrailFieldAccess& write :
                     verifiedField->writes) {
                    if (!write.location.addressValid ||
                        write.location.address !=
                            kAuthorizationImageBase + 0x1508)
                        continue;
                    const AuthorizationTrailFieldAccess* reachedRead = nullptr;
                    for (const AuthorizationTrailFieldAccess& read :
                         verifiedField->reads)
                        if (read.inputIndex ==
                            write.reachedReadAccessInputIndex) {
                            reachedRead = &read;
                            break;
                        }
                    exactStoreReadEdge =
                        write.reachedReadAccessInputIndexValid &&
                        write.reachedPredicateInputIndexValid &&
                        write.reachedPredicateInputIndex ==
                            verifiedPredicate->inputIndex &&
                        reachedRead && reachedRead->location.addressValid &&
                        reachedRead->location.address ==
                            kAuthorizationImageBase + 0x1580 &&
                        std::find(
                            verifiedField
                                ->sourceLinkedPredicateInputIndices.begin(),
                            verifiedField
                                ->sourceLinkedPredicateInputIndices.end(),
                            verifiedPredicate->inputIndex) !=
                            verifiedField
                                ->sourceLinkedPredicateInputIndices.end() &&
                        std::find(
                            verifiedField
                                ->sourceLinkedPredicateInputIndices.begin(),
                            verifiedField
                                ->sourceLinkedPredicateInputIndices.end(),
                            sameFieldUnreachedPredicate->inputIndex) ==
                            verifiedField
                                ->sourceLinkedPredicateInputIndices.end();
                }
            }
            CHECK(exactStoreReadEdge,
                  "adapter publishes the exact store/read/predicate edge and excludes the same-field-only reader");

            const AuthorizationPredicatePatchAdvice* tinyPredicateAdvice =
                nullptr;
            for (const AuthorizationPredicatePatchAdvice& advice :
                 triage.authorizationPatchAdvice)
                if (advice.function.addressValid &&
                    advice.function.address ==
                        kAuthorizationImageBase + 0x1580) {
                    tinyPredicateAdvice = &advice;
                    break;
                }
            bool refusesUnownedReplacement = false;
            if (tinyPredicateAdvice)
                for (AuthorizationPatchRefusal refusal :
                     tinyPredicateAdvice->advice.refusals)
                    refusesUnownedReplacement |= refusal ==
                        AuthorizationPatchRefusal::ReplacementExtentUnproven;
            CHECK(tinyPredicateAdvice &&
                      !tinyPredicateAdvice->advice.eligible &&
                      tinyPredicateAdvice->advice.suggestions.empty() &&
                      refusesUnownedReplacement,
                  "a two-byte field predicate cannot borrow adjacent function bytes for a six-byte patch plan");

            bool persistentWriteRetained = false;
            for (const PersistentStateOperation& operation :
                 triage.authorization.stateOperations) {
                persistentWriteRetained |=
                    operation.location.addressValid &&
                    operation.location.address ==
                        kAuthorizationImageBase + 0x1511 &&
                    operation.access == PersistentStateAccess::Write;
            }
            bool protectedActionRetained = false;
            bool unlinkedProtectedActionRetained = false;
            bool persistenceMasqueradesAsProtected = false;
            bool hostileModuleMasqueradesAsProtected = false;
            for (const AuthorizationTrailFeatureOperation& operation :
                 trail.operations) {
                protectedActionRetained |=
                    operation.location.addressValid &&
                    operation.location.address ==
                        kAuthorizationImageBase + 0x1513 &&
                    operation.kind ==
                        AuthorizationTrailOperationKind::ProtectedOperation &&
                    operation.feature.find("advapi32!") == 0 &&
                    operation.feature.find("CreateServiceW") !=
                        std::string::npos;
                unlinkedProtectedActionRetained |=
                    operation.location.addressValid &&
                    operation.location.address ==
                        kAuthorizationImageBase + 0x1112 &&
                    operation.kind ==
                        AuthorizationTrailOperationKind::ProtectedOperation;
                persistenceMasqueradesAsProtected |=
                    operation.location.addressValid &&
                    operation.location.address ==
                        kAuthorizationImageBase + 0x1511 &&
                    operation.kind ==
                        AuthorizationTrailOperationKind::ProtectedOperation;
                hostileModuleMasqueradesAsProtected |=
                    operation.location.addressValid &&
                    operation.location.address ==
                        kAuthorizationImageBase + 0x1512 &&
                    operation.kind ==
                        AuthorizationTrailOperationKind::ProtectedOperation;
            }
            const AuthorizationTrailConclusion* featureConclusion = nullptr;
            for (const AuthorizationTrailConclusion& conclusion :
                 trail.conclusions)
                if (conclusion.kind ==
                    AuthorizationTrailConclusionKind::FeaturePermitted)
                    featureConclusion = &conclusion;
            bool unlinkedProtectedStageCandidate = false;
            bool linkedProtectedStageSupported = false;
            for (const AuthorizationTrailStage& stage : trail.stages) {
                unlinkedProtectedStageCandidate |=
                    stage.stage ==
                        AuthorizationTrailStageKind::ProtectedOperation &&
                    stage.location.addressValid &&
                    stage.location.address ==
                        kAuthorizationImageBase + 0x1112 &&
                    stage.level == AuthorizationTrailEvidenceLevel::Candidate;
                linkedProtectedStageSupported |=
                    stage.stage ==
                        AuthorizationTrailStageKind::ProtectedOperation &&
                    stage.location.addressValid &&
                    stage.location.address ==
                        kAuthorizationImageBase + 0x1513 &&
                    stage.level == AuthorizationTrailEvidenceLevel::Supported;
            }
            CHECK(persistentWriteRetained,
                  "exact RegSetValueExW remains a persistent-state write");
            CHECK(!persistenceMasqueradesAsProtected,
                  "persistent license/config write does not masquerade as a protected operation");
            CHECK(!hostileModuleMasqueradesAsProtected,
                  "API-set-looking near-match DLL does not inherit a protected-operation contract");
            CHECK(protectedActionRetained,
                  "exact DLL-qualified protected API on the true-exclusive path is retained");
            CHECK(unlinkedProtectedActionRetained &&
                      unlinkedProtectedStageCandidate,
                  "an exact protected API guarded only by an authorization-unlinked predicate remains a candidate stage");
            CHECK(linkedProtectedStageSupported,
                  "the exact protected API guarded by a promoted authorization-linked predicate is a supported stage");
            CHECK(featureConclusion && featureConclusion->status ==
                      AuthorizationTrailConclusionStatus::Supported,
                  "an authorization-linked promoted predicate guard over an exact protected operation supports Feature permitted");
        }
        authorizationService.cancelAndWaitIdle();
    }

    // Machine-binding adapter regression: only a loader-exact, fixed-extent
    // machine output with success-exclusive, overwrite-free address lineage
    // into an exact verifier length and a strong authorization/protected sink
    // may publish supported MachineIdentityFlow evidence.
    {
        BinaryFile machineBinary;
        CHECK(loadAbiFixture("ds_machine_binding_fixture.exe",
                             buildMachineBindingPe64(), machineBinary),
              "load machine-binding fixture");
        bool exactMachineImport = false;
        bool hostileMachineImport = false;
        for (const BinaryFile::Import& imported : machineBinary.imports()) {
            exactMachineImport |= imported.addressKnown &&
                imported.iatVA == kAuthorizationMachineIdentityIat &&
                imported.dll == "kernel32.dll" &&
                imported.name == "GetVolumeInformationW";
            hostileMachineImport |= imported.addressKnown &&
                imported.iatVA == kAuthorizationHostileMachineIdentityIat &&
                imported.dll == "unrelated.dll" &&
                imported.name == "GetVolumeInformationW";
        }
        CHECK(exactMachineImport && hostileMachineImport,
              "machine-binding fixture exposes exact and hostile loader identities");

        auto analyzeMachine = [&](MachineBindingVariant variant) {
            AnalysisService service(
                [variant](Engine, Arch) -> std::unique_ptr<IDisassembler> {
                    return std::make_unique<MachineBindingServiceDisasm>(variant);
                });
            const uint64_t machineEpoch = service.epoch();
            service.requestBulk(&machineBinary, Engine::Zydis, Arch::X64,
                                K_CrackmeTriage, false, machineEpoch);
            AnalysisResult result;
            const auto deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(5);
            while (std::chrono::steady_clock::now() < deadline &&
                   !result.crackmeTriageValid) {
                AnalysisResult next;
                while (service.tryTakeBulk(next)) {
                    if (next.epoch == machineEpoch &&
                        next.crackmeTriageValid) {
                        result = std::move(next);
                        break;
                    }
                }
                if (!result.crackmeTriageValid)
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(2));
            }
            service.cancelAndWaitIdle();
            return result;
        };
        auto conclusionFor = [](const AuthorizationTrailReport& trail)
                -> const AuthorizationTrailConclusion* {
            for (const AuthorizationTrailConclusion& conclusion :
                 trail.conclusions)
                if (conclusion.kind ==
                    AuthorizationTrailConclusionKind::MachineBound)
                    return &conclusion;
            return nullptr;
        };
        auto hasEvidenceAt = [](
                const AuthorizationTrailConclusion* conclusion,
                AuthorizationTrailEvidenceKind kind, uint64_t address) {
            if (!conclusion) return false;
            for (const AuthorizationTrailConclusionEvidence& evidence :
                 conclusion->evidence)
                if (evidence.kind == kind &&
                    evidence.location.addressValid &&
                    evidence.location.address == address)
                    return true;
            return false;
        };

        const AnalysisResult positive = analyzeMachine(
            MachineBindingVariant::Positive);
        CHECK(positive.crackmeTriageValid,
              "machine-binding positive analysis completes");
        if (positive.crackmeTriageValid) {
            const AuthorizationTrailReport& trail =
                positive.crackmeTriage.authorizationTrail;
            const AuthorizationTrailConclusion* machine = conclusionFor(trail);
            CHECK(machine && machine->status ==
                      AuthorizationTrailConclusionStatus::Supported,
                  "exact machine-output/verifier/protected path supports machine binding");
            CHECK(hasEvidenceAt(
                      machine,
                      AuthorizationTrailEvidenceKind::MachineIdentityCapability,
                      kAuthorizationImageBase + 0x112B),
                  "exact machine API call remains visible as capability evidence");
            CHECK(hasEvidenceAt(
                      machine,
                      AuthorizationTrailEvidenceKind::MachineIdentityFlow,
                      kAuthorizationImageBase + 0x1139),
                  "only the exact verifier callsite publishes machine-flow evidence");
            bool caveatRetained = false;
            if (machine) {
                for (const AuthorizationTrailConclusionEvidence& evidence :
                     machine->evidence)
                    if (evidence.kind ==
                            AuthorizationTrailEvidenceKind::MachineIdentityFlow &&
                        evidence.evidence.find("OS-assigned volume serial") !=
                            std::string::npos &&
                        evidence.evidence.find(
                            "not the drive manufacturer's serial number") !=
                            std::string::npos)
                        caveatRetained = true;
            }
            CHECK(caveatRetained,
                  "supported machine-flow evidence preserves catalog identity-quality caveat");
            CHECK(machine && machine->honestyLabel.find("runtime") ==
                      std::string::npos,
                  "machine-bound core conclusion does not invent runtime success");
        }

        const MachineBindingVariant rejectedVariants[] = {
            MachineBindingVariant::OverwrittenOutput,
            MachineBindingVariant::ContentAsPointer,
            MachineBindingVariant::ZeroLength,
            MachineBindingVariant::WrongLength,
            MachineBindingVariant::WrongVerifierPolarity,
            MachineBindingVariant::UnrelatedVerifierBranch,
        };
        for (MachineBindingVariant variant : rejectedVariants) {
            const AnalysisResult rejected = analyzeMachine(variant);
            CHECK(rejected.crackmeTriageValid,
                  "machine-binding negative analysis completes");
            if (!rejected.crackmeTriageValid) continue;
            const AuthorizationTrailConclusion* machine = conclusionFor(
                rejected.crackmeTriage.authorizationTrail);
            CHECK(machine && machine->status ==
                      AuthorizationTrailConclusionStatus::Candidate,
                  "invalid machine lineage remains Candidate from capability only");
            CHECK(hasEvidenceAt(
                      machine,
                      AuthorizationTrailEvidenceKind::MachineIdentityCapability,
                      kAuthorizationImageBase + 0x112B) &&
                  !hasEvidenceAt(
                      machine,
                      AuthorizationTrailEvidenceKind::MachineIdentityFlow,
                      kAuthorizationImageBase + 0x1139),
                  "invalid pointer/extent/polarity/sink path cannot publish MachineIdentityFlow");
        }

        const AnalysisResult incomplete = analyzeMachine(
            MachineBindingVariant::IncompleteScope);
        CHECK(incomplete.crackmeTriageValid,
              "machine-binding incomplete-scope analysis completes");
        if (incomplete.crackmeTriageValid) {
            const AuthorizationTrailReport& trail =
                incomplete.crackmeTriage.authorizationTrail;
            const AuthorizationTrailConclusion* machine = conclusionFor(trail);
            CHECK(machine && machine->status ==
                      AuthorizationTrailConclusionStatus::Candidate &&
                      !trail.completeness.conclusionEvidenceComplete,
                  "incomplete graph downgrades machine binding and marks conclusion scope incomplete");
            CHECK(!hasEvidenceAt(
                      machine,
                      AuthorizationTrailEvidenceKind::MachineIdentityFlow,
                      kAuthorizationImageBase + 0x1139),
                  "incomplete scope cannot retain a previously plausible supported flow");
        }

        const AnalysisResult wrongDll = analyzeMachine(
            MachineBindingVariant::WrongMachineDll);
        CHECK(wrongDll.crackmeTriageValid,
              "machine-binding wrong-DLL analysis completes");
        if (wrongDll.crackmeTriageValid) {
            const AuthorizationTrailConclusion* machine = conclusionFor(
                wrongDll.crackmeTriage.authorizationTrail);
            CHECK(machine && machine->status ==
                      AuthorizationTrailConclusionStatus::Unknown &&
                      !hasEvidenceAt(
                          machine,
                          AuthorizationTrailEvidenceKind::MachineIdentityCapability,
                          kAuthorizationImageBase + 0x112B) &&
                      !hasEvidenceAt(
                          machine,
                          AuthorizationTrailEvidenceKind::MachineIdentityFlow,
                          kAuthorizationImageBase + 0x1139),
                  "same machine symbol from the wrong DLL gets no catalog capability or flow");
        }
    }

    // K_Intent: the algorithm recognizer runs as a background pass (after K_Funcs/K_Xref)
    // and delivers an algosValid result; a planted AES S-box is recognized.
    {
        std::string cpath = "ds_anajobs_crypto_tmp.bin";
        {
            std::ofstream f(cpath, std::ios::binary);
            std::vector<uint8_t> pad(32, (char)0x11);
            static const uint8_t sbox[16] = {
                0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76 };
            f.write((const char*)pad.data(), (std::streamsize)pad.size());
            f.write((const char*)sbox, 16);
            f.write((const char*)pad.data(), (std::streamsize)pad.size());
        }
        BinaryFile cbin;
        CHECK(cbin.loadRaw(cpath, base), "loadRaw crypto blob");
        uint64_t e = svc.epoch();
        svc.requestBulk(&cbin, Engine::Zydis, Arch::X64, K_Funcs | K_Xref | K_Intent, false, e);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) { return r.algosValid; });
        CHECK(got.algosValid, "K_Intent delivered an algosValid result");
        bool foundAes = false;
        for (auto& m : got.algos) if (m.name == "AES Rijndael S-box") foundAes = true;
        CHECK(foundAes, "AlgoScan found the planted AES S-box via the worker");
        svc.cancelAndWaitIdle();   // ensure no worker reads cbin after this scope
        std::remove(cpath.c_str());
    }

    // Module tagging: a job with a non-zero moduleBase rides through to the result.
    {
        uint64_t e = svc.epoch();
        const uint64_t modBase = 0x7FF000000000ull;
        svc.beginModuleBatch(1);
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, e, modBase);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) { return r.stringsValid; });
        CHECK(got.moduleBase == modBase, "result carries its moduleBase");
        // The batch of 1 completes and auto-resets the module counters.
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
        bool reset = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (svc.progress().modulesTotal == 0) { reset = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(reset, "module batch resets after the last module completes");
    }

    // ---- DecompileRegion (the K_Decompile job body) ----
    // The stub decodes every byte as a nop, so [base, base+8) builds a trivial CFG that
    // Decompile turns into a small but non-empty function body.
    {
        StubDisasm stub;
        DecompileNameMap names{ { base, "analyst_main" } };
        DecoderConfig exact;
        exact.engine = Engine::Zydis;
        exact.arch = Arch::X64;
        DecompResult t = DecompileRegion(bin, stub, exact, base, base + 8,
                                         &names, "int (a1)");
        CHECK(!t.text.empty(), "DecompileRegion produced non-empty pseudo-C");
        CHECK(t.text.find("int analyst_main(a1)") != std::string::npos,
              "DecompileRegion applies analyst function name and inferred signature");
        CHECK(stub.decodeCalls > 0 && stub.highestVA < base + 8,
              "DecompileRegion never decodes beyond its exclusive regionHi");
        // The per-line VA map parallels the text: one entry per '\n'-line.
        size_t nl = 0; for (char c : t.text) if (c == '\n') ++nl;
        CHECK(t.lineVA.size() == nl, "DecompileRegion lineVA parallels the text lines");
        // Empty/unmapped regions are structured incomplete results, not silent
        // successful emptiness, and retain parallel source vectors.
        DecompResult empty = DecompileRegion(bin, stub, exact, base, base);
        CHECK(!empty.complete && !empty.diagnostics.empty(),
              "DecompileRegion reports hi<=lo as incomplete");
        DecompResult unmapped = DecompileRegion(
            bin, stub, exact, 0xDEAD0000ull, 0xDEAD0010ull);
        CHECK(!unmapped.complete && unmapped.lineVA.size() == unmapped.lineOrigins.size(),
              "DecompileRegion reports an unmapped region with a parallel source map");

        BinaryFile high;
        const uint64_t highBase = std::numeric_limits<uint64_t>::max() - 32;
        CHECK(high.loadRaw(path, highBase), "loadRaw near the address-space limit");
        StubDisasm highStub;
        DecompResult highResult = DecompileRegion(
            high, highStub, exact, highBase, std::numeric_limits<uint64_t>::max());
        CHECK(!highResult.text.empty() && highStub.highestVA < std::numeric_limits<uint64_t>::max(),
              "DecompileRegion handles a high address without interval overflow");

        // Production completeness diagnostics are structured and additive: a
        // clipped ownership request can also report its missing mapped tail and
        // the analyzer's independently truncated ownership proof.
        DecoderConfig config;
        config.engine = Engine::Zydis; config.arch = Arch::X64;
        std::vector<FunctionChunk> oversized{ { base, 20000 } };
        StubDisasm diagnosticStub;
        DecompResult diagnostic = DecompileRegion(
            bin, diagnosticStub, config, base, base + 8, nullptr, {}, {},
            &oversized, true);
        auto hasDiagnostic = [&](DecompileDiagnosticKind kind) {
            for (const DecompileDiagnostic& item : diagnostic.diagnostics)
                if (item.kind == kind) return true;
            return false;
        };
        CHECK(!diagnostic.complete && diagnostic.text.find("WARNING: incomplete") != std::string::npos,
              "production decompile visibly reports incomplete output");
        CHECK(hasDiagnostic(DecompileDiagnosticKind::ClippedInput),
              "production decompile reports clipped byte input");
        CHECK(hasDiagnostic(DecompileDiagnosticKind::MissingChunk),
              "production decompile reports an unmapped/missing chunk tail");
        CHECK(hasDiagnostic(DecompileDiagnosticKind::TruncatedOwnership),
              "production decompile reports truncated ownership discovery");
    }

    // ---- K_Decompile bulk pass ----
    // A single-region job delivers a decompValid result tagged with the function VA and
    // the region it targeted (mirrors the K_Synthesis/K_PathExplore region-job contract).
    {
        uint64_t e = svc.epoch();
        auto names = std::make_shared<DecompileNameMap>();
        (*names)[base] = "worker_named_main";
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Decompile, false, e,
                        /*moduleBase=*/0, /*regionLo=*/base, /*regionHi=*/base + 8,
                        /*regionValid=*/true, names, "long (a1)", /*decompContext=*/77);
        AnalysisResult got; got.epoch = e;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
        bool have = false;
        while (std::chrono::steady_clock::now() < deadline && !have) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch != e) continue;
                if (tmp.decompValid) { got = tmp; have = true; }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have, "K_Decompile delivered a decompValid result");
        CHECK(got.decompVA == base, "K_Decompile result tagged with the region start VA");
        CHECK(got.regionValid && got.regionLo == base && got.regionHi == base + 8,
              "K_Decompile result carries its explicit region");
        CHECK(!got.decompText.empty(), "K_Decompile result has pseudo-C text");
        CHECK(got.decompText.find("long worker_named_main(a1)") != std::string::npos,
              "K_Decompile transports the immutable name/signature snapshot");
        CHECK(got.decompContext == 77, "K_Decompile echoes the caller name-context generation");
        svc.cancelAndWaitIdle();
    }

    {
        // The queue boundary refuses unsupported ISAs even when a non-UI caller
        // asks for F1 directly.  It still returns a tagged result so callers do
        // not wait forever for a pass that was silently skipped.
        const uint64_t e = svc.epoch();
        svc.requestBulk(&bin, Engine::Capstone, Arch::THUMB, K_Synthesis,
                        false, e, 0, base, base + 8, true);
        AnalysisResult got;
        bool have = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && !have) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch == e && tmp.synthValid) { got = std::move(tmp); have = true; }
            }
            if (!have) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have, "unsupported K_Synthesis request returns an explicit result");
        CHECK(got.regionLo == base && got.regionHi == base + 8 &&
              got.synth.rejectedReason.find("x86/x64-only") != std::string::npos &&
              got.synth.rejectedReason.find("Thumb") != std::string::npos,
              "AnalysisService rejects Thumb synthesis before symbolic execution");
        svc.cancelAndWaitIdle();
    }

    // Pending targeted passes for one module must not coalesce when their kinds
    // differ: they share region storage, so the old merge moved the first pass to
    // the second pass's address. Occupy every possible pool worker with gated jobs
    // to make both target requests deterministically pending together.
    {
        auto release = std::make_shared<std::atomic<bool>>(false);
        auto entered = std::make_shared<std::atomic<int>>(0);
        AnalysisService targeted([release, entered](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<GateDisasm>(release, entered);
        });
        const uint64_t e = targeted.epoch();
        for (uint64_t i = 0; i < 8; ++i)
            targeted.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Decompile,
                                 false, e, 0x100 + i, base, base + 2, true);

        auto enteredDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!entered->load(std::memory_order_acquire)
               && std::chrono::steady_clock::now() < enteredDeadline)
            std::this_thread::yield();
        CHECK(entered->load(std::memory_order_acquire) > 0,
              "targeted-coalescing test occupied an analysis worker");

        constexpr uint64_t targetModule = 0xBEEF;
        targeted.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Decompile,
                             false, e, targetModule, base, base + 4, true);
        targeted.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Synthesis,
                             false, e, targetModule, base + 8, base + 12, true);
        release->store(true, std::memory_order_release);

        bool sawDecompile = false, sawSynthesis = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline
               && !(sawDecompile && sawSynthesis)) {
            AnalysisResult got;
            while (targeted.tryTakeBulk(got)) {
                if (got.moduleBase != targetModule) continue;
                if (got.decompValid) {
                    sawDecompile = got.decompVA == base
                                && got.regionLo == base && got.regionHi == base + 4;
                }
                if (got.synthValid) {
                    sawSynthesis = got.regionLo == base + 8 && got.regionHi == base + 12;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(sawDecompile, "different targeted kind preserves decompile region");
        CHECK(sawSynthesis, "different targeted kind preserves synthesis region");
        targeted.cancelAndWaitIdle();
    }

    // VA 0 is a legitimate function address for raw/ELF/Mach-O images. Keep this
    // backend regression beside the BinaryView validity-flag fix: zero must not be
    // treated as the decompiler's "not initialized" sentinel.
    {
        BinaryFile zeroBin;
        CHECK(zeroBin.loadRaw(path, 0), "loadRaw at VA 0");
        uint64_t e = svc.epoch();
        svc.requestBulk(&zeroBin, Engine::Zydis, Arch::X64, K_Decompile, false, e,
                        /*moduleBase=*/0, /*regionLo=*/0, /*regionHi=*/8,
                        /*regionValid=*/true);
        AnalysisResult got;
        bool have = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
        while (std::chrono::steady_clock::now() < deadline && !have) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch == e && tmp.decompValid) { got = std::move(tmp); have = true; }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have && got.regionValid && got.decompVA == 0 && !got.decompText.empty(),
              "K_Decompile supports a real function at VA 0");
        svc.cancelAndWaitIdle();

        e = svc.epoch();
        svc.requestBulk(&zeroBin, Engine::Zydis, Arch::X64, K_PathExplore, false, e,
                        /*moduleBase=*/0, /*regionLo=*/0, /*regionHi=*/1,
                        /*regionValid=*/true);
        have = false;
        deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
        while (std::chrono::steady_clock::now() < deadline && !have) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch == e && tmp.pathValid) { got = std::move(tmp); have = true; }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have && got.regionValid && !got.pathTree.nodes.empty() &&
              got.pathTree.nodes[0].blockVA == 0,
              "K_PathExplore supports a real root at VA 0");
        svc.cancelAndWaitIdle();
    }

    // A decoder/factory exception is converted into an explicit result, does not
    // strand in-flight bookkeeping, and preserves a prefix request's target so
    // its UI pending owner can be retired and visibility can retry it.
    {
        const std::string retryPath = "ds_listing_prefix_retry_tmp.bin";
        {
            std::vector<uint8_t> bytes(kListingCodePageBytes * 2 + 15, 0x90);
            std::ofstream output(retryPath, std::ios::binary | std::ios::trunc);
            output.write(reinterpret_cast<const char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
        }
        constexpr uint64_t retryBase = 0xA00000;
        BinaryFile retryBin;
        CHECK(retryBin.loadRaw(retryPath, retryBase),
              "load failed-prefix retry fixture");
        auto attempts = std::make_shared<std::atomic<int>>(0);
        AnalysisService resilient([attempts](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            if (attempts->fetch_add(1, std::memory_order_relaxed) == 0)
                throw std::runtime_error("intentional factory failure");
            return std::make_unique<StubDisasm>();
        });

        const uint64_t e = resilient.epoch();
        constexpr uint64_t retryRevision = 91;
        constexpr uint64_t retryTopology = 13;
        resilient.requestListingPrefix(&retryBin, Engine::Zydis, Arch::X64, e,
                                       retryBase, retryBase,
                                       retryBase + kListingCodePageBytes,
                                       retryRevision, 0, retryTopology);
        AnalysisResult failure;
        bool gotFailure = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && !gotFailure) {
            AnalysisResult result;
            while (resilient.tryTakeBulk(result)) {
                if (result.epoch == e && result.failureValid) {
                    failure = std::move(result);
                    gotFailure = true;
                }
            }
            if (!gotFailure) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(gotFailure && failure.failure.find("intentional factory failure") != std::string::npos,
              "worker exception is published as a structured failure result");
        CHECK(failure.listingPrefixDone &&
              failure.listingPrefixTarget == retryBase + kListingCodePageBytes &&
              failure.listingRevision == retryRevision &&
              failure.listingTopologyGeneration == retryTopology,
              "failed prefix result preserves the pending-owner identity");
        CHECK(resilient.progress().jobsFailed == 1,
              "worker failure counter is observable");

        resilient.requestListingPrefix(&retryBin, Engine::Zydis, Arch::X64, e,
                                       retryBase, retryBase,
                                       retryBase + kListingCodePageBytes,
                                       retryRevision, 0, retryTopology);
        bool recovered = false;
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && !recovered) {
            AnalysisResult result;
            while (resilient.tryTakeBulk(result))
                if (result.epoch == e && result.listingPrefixDone &&
                    result.listingPrefixValid)
                    recovered = true;
            if (!recovered) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(recovered, "failed prefix request can be queued again and succeeds");
        resilient.cancelAndWaitIdle();
        std::remove(retryPath.c_str());
    }

    // Derived results are retained behind the complete analysis identity. The
    // second identical request is a service-level cache hit; changing only the
    // ordered-patch digest forces a miss even though this fixture's bytes were
    // intentionally left untouched.
    {
        AnalysisService cached([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<StubDisasm>();
        });
        auto waitStrings = [&](uint64_t epoch) {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (std::chrono::steady_clock::now() < deadline) {
                AnalysisResult result;
                while (cached.tryTakeBulk(result))
                    if (result.epoch == epoch && result.stringsValid) return true;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            return false;
        };

        const uint64_t epoch = cached.epoch();
        constexpr uint64_t patchIdentityA = 0x1111222233334444ull;
        constexpr uint64_t patchIdentityB = 0x5555666677778888ull;
        cached.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false,
                           epoch, 0, 0, 0, false, {}, {}, 0, {}, patchIdentityA);
        CHECK(waitStrings(epoch), "first cache fixture request completes");
        const ProgressSnapshot afterMiss = cached.progress();
        CHECK(afterMiss.cacheMisses >= 1 && afterMiss.cacheHits == 0,
              "first service request records a derived-cache miss");

        cached.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false,
                           epoch, 0, 0, 0, false, {}, {}, 0, {}, patchIdentityA);
        CHECK(waitStrings(epoch), "identical cache fixture request completes");
        const ProgressSnapshot afterHit = cached.progress();
        CHECK(afterHit.cacheHits == afterMiss.cacheHits + 1 &&
              afterHit.cacheMisses == afterMiss.cacheMisses,
              "identical service request reuses the immutable cached result");

        cached.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false,
                           epoch, 0, 0, 0, false, {}, {}, 0, {}, patchIdentityB);
        CHECK(waitStrings(epoch), "changed-patch cache fixture request completes");
        CHECK(cached.progress().cacheMisses == afterHit.cacheMisses + 1,
              "ordered patch digest change forces a service cache miss");
        cached.cancelAndWaitIdle();
    }

    // File bytes alone are not a sufficient cache identity for VA-bearing
    // passes.  Reopen one Raw blob at a different mapping base and prove both
    // Strings and CrackmeTriage carry the new FILE VA rather than a stale hit.
    {
        const std::string mappingPath = "ds_analysis_mapping_identity_tmp.bin";
        {
            std::ofstream output(mappingPath, std::ios::binary | std::ios::trunc);
            const char payload[] = "https://mapping.example.net/activate\0";
            output.write(payload, static_cast<std::streamsize>(sizeof(payload)));
        }
        constexpr uint64_t mappingBaseA = 0x100000;
        constexpr uint64_t mappingBaseB = 0x500000;
        BinaryFile mappingA, mappingB;
        CHECK(mappingA.loadRaw(mappingPath, mappingBaseA) &&
              mappingB.loadRaw(mappingPath, mappingBaseB),
              "load identical Raw mapping-identity fixtures");
        CHECK(mappingA.contentHash() == mappingB.contentHash(),
              "mapping-identity fixture has identical pristine bytes");

        AnalysisService mappingCached([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<StubDisasm>();
        });
        auto analyzeMapping = [&](BinaryFile& binary) {
            const uint64_t epoch = mappingCached.epoch();
            mappingCached.requestBulk(&binary, Engine::Zydis, Arch::X64,
                                      K_CrackmeTriage, false, epoch);
            AnalysisResult merged; merged.epoch = epoch;
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (std::chrono::steady_clock::now() < deadline) {
                AnalysisResult result;
                while (mappingCached.tryTakeBulk(result)) {
                    if (result.epoch != epoch) continue;
                    if (result.stringsValid) {
                        merged.strings = std::move(result.strings);
                        merged.stringsValid = true;
                    }
                    if (result.crackmeTriageValid) {
                        merged.crackmeTriage = std::move(result.crackmeTriage);
                        merged.crackmeTriageValid = true;
                    }
                }
                if (merged.stringsValid && merged.crackmeTriageValid) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            return merged;
        };
        auto endpointLiteralVA = [](const AnalysisResult& result) {
            for (const auto& endpoint : result.crackmeTriage.endpoints) {
                if (endpoint.host != "mapping.example.net") continue;
                for (const auto& source : endpoint.sources)
                    if (source.literalAddressValid &&
                        source.role == CrackmeLiteralRole::Host)
                        return source.literalAddress;
            }
            return uint64_t{0};
        };

        AnalysisResult firstMapping = analyzeMapping(mappingA);
        const ProgressSnapshot afterFirstMapping = mappingCached.progress();
        mappingCached.cancelAndWaitIdle();
        AnalysisResult secondMapping = analyzeMapping(mappingB);
        const ProgressSnapshot afterSecondMapping = mappingCached.progress();
        CHECK(firstMapping.stringsValid && firstMapping.crackmeTriageValid &&
              secondMapping.stringsValid && secondMapping.crackmeTriageValid,
              "mapping-identity service reports complete");
        CHECK(endpointLiteralVA(firstMapping) == mappingBaseA + 8 &&
              endpointLiteralVA(secondMapping) == mappingBaseB + 8,
              "triage literal FILE VAs follow each Raw mapping base");
        CHECK(!firstMapping.strings.empty() && !secondMapping.strings.empty() &&
              firstMapping.strings.front().address == mappingBaseA &&
              secondMapping.strings.front().address == mappingBaseB,
              "string FILE VAs follow each Raw mapping base");
        CHECK(afterSecondMapping.cacheMisses > afterFirstMapping.cacheMisses,
              "different mapping identity prevents stale service-cache reuse");
        mappingCached.cancelAndWaitIdle();
        std::remove(mappingPath.c_str());
    }

    // An xref-only request must reuse the same classified/override-applied scope
    // as bulk analysis, including immutable cache hits after a decision changes.
    {
        const std::string scopePath = "ds_service_xref_scope_tmp.bin";
        const uint8_t bytes[] = {0xe8, 0, 0xc3, 0xe8, 0, 0xc3};
        { std::ofstream f(scopePath, std::ios::binary); f.write((const char*)bytes, sizeof(bytes)); }
        BinaryFile scopeBin;
        CHECK(scopeBin.loadRaw(scopePath, 0), "load service xref scope fixture at VA zero");
        CHECK(scopeBin.setRawEntryPointVA(0), "explicit zero entry for service scope fixture");
        AnalysisService scopeService([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<RawFlowDisasm>(0);
        }, 1);
        auto data = std::make_shared<ProjectAnalysisOverrides>();
        data->data.push_back({3, 2, PjDataKind::Data, {}});
        auto code = std::make_shared<ProjectAnalysisOverrides>();
        code->data.push_back({3, 2, PjDataKind::Code, {}});
        auto request = [&](uint32_t kinds, const std::shared_ptr<ProjectAnalysisOverrides>& overrides) {
            const uint64_t epoch = scopeService.epoch();
            scopeService.requestBulk(&scopeBin, Engine::Zydis, Arch::X64, kinds, false,
                epoch, 0, 0, 0, false, {}, {}, 0, overrides);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            AnalysisResult found;
            while (std::chrono::steady_clock::now() < deadline) {
                AnalysisResult result;
                while (scopeService.tryTakeBulk(result))
                    if (result.epoch == epoch && result.xref) found = std::move(result);
                if (found.xref) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            return found;
        };
        AnalysisResult bulk = request(K_Funcs | K_Xref, data);
        const ProgressSnapshot afterBulk = scopeService.progress();
        AnalysisResult targeted = request(K_Xref, data);
        CHECK(bulk.xref && targeted.xref && bulk.xref->classificationApplied &&
              bulk.xref->sources(0) && *bulk.xref->sources(0) == std::vector<uint64_t>({0}) &&
              targeted.xref->toTarget == bulk.xref->toTarget,
              "bulk and xref-only builds exclude the same analyst data island");
        CHECK(targeted.xref && targeted.codeData &&
              targeted.xref->classificationScopeDigest == targeted.codeData->scopeDigest &&
              targeted.xrefImageRevision == scopeBin.imageRevision() &&
              targeted.xrefOverrideDigest == DigestAnalysisOverrides(data.get()) &&
              targeted.xrefDecoderSignature == AnalysisIsaSignature(Arch::X64, Engine::Zydis),
              "cached xrefs carry their exact image/decoder/override/classification identity");
        CHECK(scopeService.progress().cacheHits == afterBulk.cacheHits + 2 &&
              scopeService.progress().cacheMisses == afterBulk.cacheMisses,
              "xref-only reuse fetches classification and xrefs without fetching strings");
        AnalysisResult defined = request(K_Xref, code);
        CHECK(defined.xref && defined.xref->sources(0) &&
              *defined.xref->sources(0) == std::vector<uint64_t>({0, 3}) &&
              bulk.xref && defined.xref->classificationScopeDigest != bulk.xref->classificationScopeDigest,
              "a code override restores the island reference with a new scope identity");
        AnalysisResult restored = request(K_Xref, data);
        CHECK(restored.xref && bulk.xref && restored.xref->toTarget == bulk.xref->toTarget &&
              restored.xref->classificationScopeDigest == bulk.xref->classificationScopeDigest,
              "returning to the data decision restores its exact cached index");
        scopeService.cancelAndWaitIdle();
        std::remove(scopePath.c_str());
    }

    // cancelAndWaitIdle leaves the pool idle (no pending work, progress back to Idle).
    {
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, svc.epoch());
        svc.cancelAndWaitIdle();
        CHECK(!svc.bulkPending(), "no pending work after cancelAndWaitIdle");
        CHECK(svc.progress().phase == AnalysisPhase::Idle, "progress phase Idle after cancel");
    }

    std::remove(path.c_str());
    if (g_fail == 0) std::printf("analysis_service_test: all checks passed\n");
    else             std::printf("analysis_service_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
