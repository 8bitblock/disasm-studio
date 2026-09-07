#pragma once
#include "InstructionSemantics.h"
#include "FunctionAnalyzer.h"
#include <atomic>
#include <functional>
#include <memory>

namespace ds {
// The requested value is the register slice immediately BEFORE instructionVA.
// Results describe possible data dependencies, never a predicted runtime value.
struct ValueOriginRequest {
    uint64_t requestId = 0;
    uint64_t functionVA = 0;
    uint64_t instructionVA = 0;
    std::string registerName;
    std::vector<FunctionChunk> chunks;
    bool ownershipTruncated = false;
    std::shared_ptr<std::atomic<bool>> cancellation;
};
enum class ValueOriginBoundaryKind : uint8_t {
    Incoming, Join, Memory, Call, Unsupported, IncompleteGraph, Limit, Cycle
};
struct ValueOriginSource {
    uint64_t va = 0;
    std::string instruction;
    std::string reason;
};
struct ValueOriginBoundary {
    ValueOriginBoundaryKind kind = ValueOriginBoundaryKind::Unsupported;
    uint64_t va = 0;
    std::string message;
};
struct ValueOriginResult {
    uint64_t instructionVA = 0;
    std::string registerName;
    bool valid = false;
    bool complete = false;
    bool cancelled = false;
    std::string status;
    std::vector<ValueOriginSource> sources;
    std::vector<ValueOriginBoundary> boundaries;
};
struct ValueOriginLimits {
    size_t maxStates = 8192;
    size_t maxSources = 2048;
    std::function<bool()> cancelled;
};
bool ValueOriginRegister(const std::string& name, Arch arch, RegisterSlice& result);
ValueOriginResult TraceValueOrigin(const ControlFlowGraph& graph, Arch arch,
                                  uint64_t instructionVA, const std::string& registerName,
                                  const ValueOriginLimits& limits = {});
// Worker-only: the caller holds the normal BinaryFile borrowing/mutation barrier.
class BinaryFile;
ValueOriginResult BuildValueOrigin(const BinaryFile& bin, IDisassembler& decoder,
                                  Arch arch, const ValueOriginRequest& request,
                                  const std::function<bool()>& cancelled);
} // namespace ds
