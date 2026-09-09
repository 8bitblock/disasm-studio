#pragma once
#include "FunctionAnalyzer.h"
#include "StringActionEvidence.h"
#include "XrefIndex.h"
#include <atomic>
#include <memory>

namespace ds {
struct StringActionTraceStep {
    uint64_t va = 0;
    uint64_t functionVA = 0;
    std::string label;
};
struct StringActionTraceCandidate {
    uint64_t instructionVA = 0;
    uint64_t functionVA = 0;
    uint64_t stringRefVA = 0;
    uint64_t producerVA = 0;
    bool producerVAValid = false;
    std::string instruction;
    std::string action;
    std::string evidence;
    std::string suggestedName;
    float confidence = 0.0f;
    std::vector<StringActionTraceStep> path;
};
struct StringActionTraceResult {
    uint64_t stringVA = 0;
    std::string stringText;
    bool valid = false;
    // Complete only within the explicit depth/distance/decoded-function scope.
    // Even a complete report is candidate evidence, never a runtime proof.
    bool complete = false;
    bool cancelled = false;
    std::string status;
    std::vector<std::string> limitations;
    std::vector<StringActionTraceCandidate> candidates;
};
struct StringActionTraceLimits {
    size_t maxInputFunctions = 100000;
    size_t maxFunctions = 48;
    size_t maxReferences = 64;
    size_t maxInstructionsPerFunction = 4096;
    size_t maxTotalInstructions = 32768;
    size_t maxCandidates = 128;
    size_t maxDepth = 2;
    size_t maxInstructionDistance = 96;
    std::function<bool()> cancelled;
};
struct StringActionTraceRequest {
    uint64_t requestId = 0;
    uint64_t stringVA = 0;
    std::string stringText;
    std::vector<DiscoveredFunction> functions;
    std::shared_ptr<const XrefIndex> xrefs;
    std::shared_ptr<std::atomic<bool>> cancellation;
};
struct StringActionTraceFunction {
    ControlFlowGraph graph;
};
// Pure graph adapter for focused tests and existing decoded-function consumers.
StringActionTraceResult TraceStringActions(const std::vector<StringActionTraceFunction>& functions,
    Arch arch, uint64_t stringVA, const std::string& stringText,
    const StringActionTraceLimits& limits = {});
// Worker-only; caller holds the normal BinaryFile borrowing/mutation barrier.
class BinaryFile;
StringActionTraceResult BuildStringActionTrace(const BinaryFile& bin, IDisassembler& decoder,
    Arch arch, const StringActionTraceRequest& request,
    const std::function<bool()>& cancelled);
} // namespace ds
