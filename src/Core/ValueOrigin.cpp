#include "ValueOrigin.h"
#include "BinaryFile.h"
#include "JumpTableResolver.h"
#include <deque>
#include <map>
#include <set>
#include <tuple>

namespace ds {
namespace {
uint64_t lowMask(unsigned bits) { return bits >= 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }
uint64_t sliceMask(const RegisterSlice& r) { return lowMask(r.widthBits) << r.offsetBits; }
struct State { size_t block, before; RegisterSlice reg; uint64_t mask; };
bool valueOperation(IntermediateOpcode op) {
    switch (op) {
    case IntermediateOpcode::Copy: case IntermediateOpcode::Address:
    case IntermediateOpcode::ZeroExtend: case IntermediateOpcode::SignExtend:
    case IntermediateOpcode::Add: case IntermediateOpcode::Subtract:
    case IntermediateOpcode::And: case IntermediateOpcode::Or: case IntermediateOpcode::Xor:
    case IntermediateOpcode::Not: case IntermediateOpcode::Negate:
    case IntermediateOpcode::ShiftLeft: case IntermediateOpcode::ShiftRight:
    case IntermediateOpcode::ArithmeticShiftRight: return true;
    default: return false;
    }
}
}

bool ValueOriginRegister(const std::string& name, Arch arch, RegisterSlice& result) {
    if (!ArchIsX86_32Or64(arch)) return false;
    result = DescribeRegisterSlice(name, 0, arch);
    if (!result.widthBits || result.widthBits > (arch == Arch::X64 ? 64 : 32) ||
        result.widthBits + result.offsetBits > (arch == Arch::X64 ? 64 : 32)) return false;
    // DescribeRegisterSlice assigns widths only to general-purpose registers.
    return true;
}

ValueOriginResult TraceValueOrigin(const ControlFlowGraph& graph, Arch arch,
                                  uint64_t instructionVA, const std::string& registerName,
                                  const ValueOriginLimits& requestedLimits) {
    ValueOriginResult result;
    result.instructionVA = instructionVA;
    result.registerName = registerName;
    RegisterSlice selected;
    if (!ValueOriginRegister(registerName, arch, selected)) {
        result.status = "Select an x86/x64 general-purpose register."; return result;
    }
    result.registerName = selected.name;
    const size_t maxStates = std::min<size_t>(requestedLimits.maxStates, 8192);
    const size_t maxSources = std::min<size_t>(requestedLimits.maxSources, 2048);
    auto cancelled = [&] { return requestedLimits.cancelled && requestedLimits.cancelled(); };
    auto boundary = [&](ValueOriginBoundaryKind kind, uint64_t va, std::string message) {
        if (std::any_of(result.boundaries.begin(), result.boundaries.end(), [&](const auto& b) {
            return b.kind == kind && b.va == va && b.message == message;
        })) return;
        if (result.boundaries.size() < 128) result.boundaries.push_back({kind, va, std::move(message)});
    };
    if (graph.blocks.size() > 4096) {
        result.status = "Function exceeds the 4,096-block analysis limit."; return result;
    }
    size_t targetBlock = SIZE_MAX, targetBefore = 0, entry = SIZE_MAX, instructionCount = 0;
    std::vector<std::vector<IntermediateOperation>> operations(graph.blocks.size());
    for (size_t b = 0; b < graph.blocks.size(); ++b) {
        if (cancelled()) { result.cancelled = true; result.status = "Cancelled."; return result; }
        if (graph.blocks[b].start == graph.funcStart) entry = b;
        for (size_t i = 0; i < graph.blocks[b].insns.size(); ++i) {
            if (++instructionCount > 4096) { result.status = "Function exceeds the 4,096-instruction analysis limit."; return result; }
            const auto& in = graph.blocks[b].insns[i];
            if (in.address == instructionVA) {
                if (targetBlock != SIZE_MAX) { result.status = "Instruction ownership is ambiguous."; return result; }
                targetBlock = b; targetBefore = i;
            }
            operations[b].push_back(LiftInstructionSemantics(in, arch));
        }
    }
    if (targetBlock == SIZE_MAX || entry == SIZE_MAX) {
        result.status = "Selected instruction or function entry is outside the decoded scope."; return result;
    }
    std::vector<bool> reachable(graph.blocks.size());
    std::vector<size_t> pending{entry}; reachable[entry] = true;
    std::vector<std::vector<size_t>> predecessors(graph.blocks.size());
    size_t edges = 0;
    while (!pending.empty()) {
        if (cancelled()) { result.cancelled = true; return result; }
        const size_t b = pending.back(); pending.pop_back();
        for (size_t next : graph.blocks[b].succ) {
            if (++edges > 16384) { result.status = "Function exceeds the control-flow edge limit."; return result; }
            if (next >= graph.blocks.size()) {
                boundary(ValueOriginBoundaryKind::IncompleteGraph, graph.blocks[b].start, "Invalid control-flow successor."); continue;
            }
            auto& p = predecessors[next];
            if (std::find(p.begin(), p.end(), b) == p.end()) p.push_back(b);
            if (!reachable[next]) { reachable[next] = true; pending.push_back(next); }
        }
    }
    if (!reachable[targetBlock]) { result.status = "Selected instruction is not reachable from the known function entry."; return result; }
    result.valid = true;
    if (!graph.complete)
        boundary(ValueOriginBoundaryKind::IncompleteGraph, graph.funcStart,
                 "Incomplete function scope: " + graph.incompleteReason);
    std::deque<State> work{{targetBlock, targetBefore, selected, sliceMask(selected)}};
    std::map<std::tuple<size_t, size_t, std::string>, uint64_t> visited;
    std::set<uint64_t> sources;
    size_t states = 0;
    bool limitReached = false;
    auto queue = [&](size_t block, size_t before, RegisterSlice reg, uint64_t mask) {
        if (!mask) return;
        if (work.size() >= maxStates) { limitReached = true; return; }
        work.push_back({block, before, std::move(reg), mask});
    };
    while (!work.empty()) {
        if (cancelled()) { result = {}; result.cancelled = true; result.status = "Cancelled."; return result; }
        if (++states > maxStates) { limitReached = true; break; }
        State state = std::move(work.front()); work.pop_front();
        auto& seen = visited[{state.block, state.before, state.reg.storage}];
        if (seen & state.mask)
            boundary(ValueOriginBoundaryKind::Cycle, graph.blocks[state.block].start,
                     "Repeated dependency state; loop/shared paths are not unfolded again.");
        state.mask &= ~seen;
        if (!state.mask) continue;
        seen |= state.mask;
        if (!state.before) {
            const auto& pred = predecessors[state.block];
            if (state.block == entry || pred.empty())
                boundary(ValueOriginBoundaryKind::Incoming, graph.blocks[state.block].start,
                         state.reg.storage + " contains an incoming value outside this function's scope.");
            if (pred.size() > 1)
                boundary(ValueOriginBoundaryKind::Join, graph.blocks[state.block].start,
                         "Control-flow join: listed sources are alternatives; no executed path is known.");
            for (size_t p : pred) queue(p, operations[p].size(), state.reg, state.mask);
            continue;
        }
        const size_t i = state.before - 1;
        const auto& op = operations[state.block][i];
        if (op.opcode == IntermediateOpcode::Call) {
            boundary(ValueOriginBoundaryKind::Call, op.sourceVA,
                     "Call boundary: callee register effects are not proved by this local slice.");
            continue;
        }
        const bool invalidOperands = std::any_of(op.operands.begin(), op.operands.end(), [&](const auto& operand) {
            if (operand.decoded.kind != OperandKind::Register) return false;
            RegisterSlice described;
            return ValueOriginRegister(operand.reg.name, arch, described) &&
                operand.decoded.widthBits && operand.decoded.widthBits != described.widthBits;
        });
        uint64_t writeMask = 0, valueMask = 0;
        RegisterSlice destination;
        for (const auto& name : op.registersWritten) {
            RegisterSlice written;
            if (!ValueOriginRegister(name, arch, written) || written.storage != state.reg.storage) continue;
            valueMask |= sliceMask(written);
            writeMask |= written.zeroExtendsStorage ? UINT64_MAX : sliceMask(written);
        }
        if (!op.operands.empty() && op.operands.front().decoded.kind == OperandKind::Register)
            destination = op.operands.front().reg;
        const uint64_t affected = state.mask & writeMask;
        const bool unknown = invalidOperands || (op.unknownRegisterEffects && op.opcode != IntermediateOpcode::Branch &&
            op.opcode != IntermediateOpcode::Return && op.opcode != IntermediateOpcode::NoOperation);
        if (!affected) {
            if (unknown) boundary(ValueOriginBoundaryKind::Unsupported, op.sourceVA,
                                  "Unknown register effects prevent tracing past: " + op.instructionText);
            else queue(state.block, i, state.reg, state.mask);
            continue;
        }
        queue(state.block, i, state.reg, state.mask & ~writeMask);
        if (!valueOperation(op.opcode) || unknown || op.repeated || op.atomic) {
            boundary(ValueOriginBoundaryKind::Unsupported, op.sourceVA,
                     "Value transformation is unsupported: " + op.instructionText);
            continue;
        }
        if (sources.insert(op.sourceVA).second) {
            if (result.sources.size() >= maxSources) { limitReached = true; break; }
            result.sources.push_back({op.sourceVA, op.instructionText,
                (affected & valueMask) ? "Possible defining/transformation instruction" : "32-bit write clears the upper register bits"});
        }
        if (!(affected & valueMask)) continue; // EAX writes define upper RAX as zero.
        if (op.readsMemory || op.unknownMemoryEffects) {
            boundary(ValueOriginBoundaryKind::Memory, op.sourceVA,
                     "Memory load: the stored value and aliasing history are outside this register slice.");
            continue;
        }
        if (op.opcode == IntermediateOpcode::Address) {
            // LEA ignores segment bases and does not load memory. Only its
            // addressing registers contribute; RIP/EIP is an instruction constant.
            for (const auto& operand : op.operands) if (operand.decoded.kind == OperandKind::Memory) {
                for (const auto& name : {operand.decoded.baseRegister, operand.decoded.indexRegister}) {
                    RegisterSlice read;
                    if (ValueOriginRegister(name, arch, read)) queue(state.block, i, read, sliceMask(read));
                    else if (!name.empty() && name != "rip" && name != "eip")
                        boundary(ValueOriginBoundaryKind::Unsupported, op.sourceVA, "Address input is outside the supported register model.");
                }
            }
            continue;
        }
        // Copy/extension maps precisely to the source slice. This is necessary
        // for AL/AH and for the zero upper bits introduced by MOVZX/EAX writes.
        if ((op.opcode == IntermediateOpcode::Copy || op.opcode == IntermediateOpcode::ZeroExtend ||
             op.opcode == IntermediateOpcode::SignExtend) && op.operands.size() == 2 &&
            destination.storage == state.reg.storage && destination.widthBits) {
            const auto& source = op.operands[1];
            if (source.decoded.kind == OperandKind::Immediate) continue;
            if (source.decoded.kind == OperandKind::Register) {
                RegisterSlice sourceReg;
                if (!ValueOriginRegister(source.reg.name, arch, sourceReg)) {
                    boundary(ValueOriginBoundaryKind::Unsupported, op.sourceVA, "Source is outside the supported general-purpose registers."); continue;
                }
                const uint64_t wanted = (affected & valueMask) >> destination.offsetBits;
                uint64_t sourceBits = wanted & lowMask(sourceReg.widthBits);
                if (op.opcode == IntermediateOpcode::SignExtend && (wanted & ~lowMask(sourceReg.widthBits)))
                    sourceBits |= uint64_t{1} << (sourceReg.widthBits - 1);
                queue(state.block, i, sourceReg, sourceBits << sourceReg.offsetBits);
                continue;
            }
        }
        // XOR/SUB of exactly the same slices are constant-zero definitions.
        if ((op.opcode == IntermediateOpcode::Xor || op.opcode == IntermediateOpcode::Subtract) &&
            op.operands.size() == 2 && op.operands[0].decoded.kind == OperandKind::Register &&
            op.operands[1].decoded.kind == OperandKind::Register &&
            op.operands[0].reg.storage == op.operands[1].reg.storage &&
            op.operands[0].reg.offsetBits == op.operands[1].reg.offsetBits &&
            op.operands[0].reg.widthBits == op.operands[1].reg.widthBits) continue;
        for (const auto& name : op.registersRead) {
            RegisterSlice read;
            if (ValueOriginRegister(name, arch, read)) queue(state.block, i, read, sliceMask(read));
            else if (name != "rip" && name != "eip" && name != "rflags" && name != "eflags")
                boundary(ValueOriginBoundaryKind::Unsupported, op.sourceVA, "Input " + name + " is outside the supported register model.");
        }
    }
    if (limitReached) boundary(ValueOriginBoundaryKind::Limit, instructionVA, "Dependency/source budget reached; additional sources may exist.");
    std::sort(result.sources.begin(), result.sources.end(), [](const auto& a, const auto& b) { return a.va < b.va; });
    result.complete = result.boundaries.empty() && !limitReached;
    result.status = result.complete ? "Register dependencies resolved within the decoded function."
                                   : "Partial register dependencies; review the boundaries below.";
    return result;
}

ValueOriginResult BuildValueOrigin(const BinaryFile& bin, IDisassembler& decoder,
                                  Arch arch, const ValueOriginRequest& request,
                                  const std::function<bool()>& cancelled) {
    ValueOriginResult rejected; rejected.instructionVA = request.instructionVA;
    rejected.registerName = request.registerName;
    if (!ArchIsX86_32Or64(arch) || request.chunks.empty() || request.chunks.size() > 256) {
        rejected.status = "Value origins require bounded x86/x64 function ownership."; return rejected;
    }
    // The CFG decoder consults cancellation before every instruction read.
    struct CancelDecoder final : IDisassembler {
        IDisassembler& decoder; const std::function<bool()>& cancelled;
        CancelDecoder(IDisassembler& d, const std::function<bool()>& c) : decoder(d), cancelled(c) {}
        Engine engine() const override { return decoder.engine(); }
        const char* engineName() const override { return decoder.engineName(); }
        bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& in) override {
            return !(cancelled && cancelled()) && decoder.decodeOne(p, n, va, in);
        }
        std::vector<Instruction> disassemble(const uint8_t* p, size_t n, uint64_t va, size_t cap) override {
            std::vector<Instruction> out;
            for (size_t off = 0; off < n && (!cap || out.size() < cap);) {
                Instruction in;
                if (!decodeOne(p + off, n - off, va + off, in) || !in.length || in.length > n - off) break;
                off += in.length; out.push_back(std::move(in));
            }
            return out;
        }
    } checked(decoder, cancelled);
    std::vector<CFGCodeChunk> chunks;
    bool incomplete = request.ownershipTruncated;
    for (const auto& chunk : request.chunks) {
        if (cancelled && cancelled()) { rejected.cancelled = true; return rejected; }
        size_t available = 0;
        const uint8_t* bytes = bin.ptrFromVA(chunk.address, available);
        if (!bytes || !chunk.size) { incomplete = true; continue; }
        const uint64_t size = chunk.size;
        const size_t bounded = static_cast<size_t>(std::min<uint64_t>(size, available));
        incomplete |= bounded != size;
        chunks.push_back({bytes, bounded, chunk.address});
    }
    auto graph = BuildCFG(chunks, checked, 4096, {}, {},
        [&bin](const Instruction& in, uint64_t& target) { return bin.resolveInstructionTarget(in, target); });
    graph.funcStart = request.functionVA;
    for (const auto& block : graph.blocks) for (const auto& in : block.insns) {
        uint64_t target = 0;
        if (InstructionEndsBlock(in) && !InstructionIsCall(in) && !InstructionIsReturn(in) &&
            !bin.resolveInstructionTarget(in, target) && in.flow.kind != FlowKind::None) {
            graph.complete = false;
            graph.incompleteReason += " unresolved indirect control flow";
        }
    }
    if (incomplete) { graph.complete = false; graph.incompleteReason += " incomplete function ownership/backing"; }
    if (cancelled && cancelled()) { rejected.cancelled = true; return rejected; }
    return TraceValueOrigin(graph, arch, request.instructionVA, request.registerName, {8192, 2048, cancelled});
}
} // namespace ds
