#include "Core/TracePlan.h"
#include <cassert>
#include <iostream>

using namespace ds;

static Instruction instruction(uint64_t address, uint32_t length = 2,
                               const char* mnemonic = "mov") {
    Instruction in;
    in.address = address; in.length = length; in.mnemonic = mnemonic;
    return in;
}

int main() {
    // Address zero and the top representable exclusive end are legitimate.
    assert(TraceInstructionCanSeed(instruction(0)));
    assert(TraceInstructionCanSeed(instruction(UINT64_MAX - 2)));
    assert(!TraceInstructionCanSeed(instruction(UINT64_MAX - 1)));
    assert(!TraceInstructionCanSeed(instruction(0, 0)));
    assert(!TraceInstructionCanSeed(instruction(0, 16)));
    for (const auto* pseudo : {"db", "dw", "dd", "dq", ""})
        assert(!TraceInstructionCanSeed(instruction(0, 1, pseudo)));

    // A call's continuation and explicit exception/system transfers need an
    // independent observation, even when the legacy branch flag is absent.
    auto call = instruction(2);
    call.flow.kind = FlowKind::DirectCall;
    assert(TraceInstructionEndsSpan(call));
    auto ret = instruction(2);
    ret.flow.kind = FlowKind::Return;
    assert(TraceInstructionEndsSpan(ret));
    auto branch = instruction(2);
    branch.flow.kind = FlowKind::ConditionalBranch;
    assert(TraceInstructionEndsSpan(branch));
    for (const auto* transfer : {"int", "int3", "ud2", "hlt", "syscall", "sysenter"})
        assert(TraceInstructionEndsSpan(instruction(2, 2, transfer)));
    assert(!TraceInstructionEndsSpan(instruction(0)));

    std::vector<TraceCodeSpan> spans;
    assert(AppendTraceCodeSpan(spans, instruction(0), true));
    assert(AppendTraceCodeSpan(spans, call, false));
    assert(AppendTraceCodeSpan(spans, instruction(4), true));
    assert(AppendTraceCodeSpan(spans, instruction(6), false));
    // Folded, data, provisional, or unavailable bytes leave an actual gap.
    assert(AppendTraceCodeSpan(spans, instruction(100), false));
    assert(spans.size() == 3 && spans[0].end == 4 && spans[1].end == 8);
    assert(!AppendTraceCodeSpan(spans, instruction(7), false));
    assert(!AppendTraceCodeSpan(spans, instruction(102, 1, "db"), false));
    assert(!AppendTraceCodeSpan(spans, instruction(110), true, 3));
    assert(spans.size() == 3 && spans.back().end == 102);

    const std::vector<uint64_t> sites{0, 4, 6, 100};
    std::unordered_map<uint64_t, uint64_t> hits{{0, 1}, {4, 1}};
    assert(TraceCoveredByBlock(sites, spans, hits, 0));
    assert(TraceCoveredByBlock(sites, spans, hits, 2));
    assert(TraceCoveredByBlock(sites, spans, hits, 4));
    assert(!TraceCoveredByBlock(sites, spans, hits, 6)); // unhit interior entry
    assert(!TraceCoveredByBlock(sites, spans, hits, 8)); // exclusive end
    assert(!TraceCoveredByBlock(sites, spans, hits, 50)); // previous hit cannot cross gap
    assert(!TraceCoveredByBlock(sites, spans, hits, 100));
    hits[100] = 1;
    assert(TraceCoveredByBlock(sites, spans, hits, 100));
    assert(!TraceCoveredByBlock(sites, spans, hits, 102));
    assert(!TraceCoveredByBlock(sites, spans, hits, UINT64_MAX));
    // A span whose entry could not be admitted cannot inherit an earlier hit.
    assert(!TraceCoveredByBlock({0}, spans, hits, 4));
    hits[100] = 0;
    assert(!TraceCoveredByBlock(sites, spans, hits, 100));
    assert(!TraceCoveredByBlock({}, spans, hits, 0));
    assert(!TraceCoveredByBlock(sites, {}, hits, 0));
    assert(FindTraceCodeSpan(spans, 0) != nullptr);
    assert(FindTraceCodeSpan(spans, 8) == nullptr);
    assert(FindTraceCodeSpan(spans, 50) == nullptr);
    assert(FindTraceCodeSpan(spans, 100) != nullptr);
    std::cout << "trace_plan_test: all checks passed\n";
}
