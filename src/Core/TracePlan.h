#pragma once

#include "../Disasm/IDisassembler.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace ds {

// Trace shading is restricted to contiguous, exactly decoded native code.
// Separate spans retain data/undecoded gaps and control-transfer boundaries;
// the next planted address alone is never an upper bound on executed code.
struct TraceCodeSpan {
    uint64_t begin = 0;
    uint64_t end = 0; // exclusive
};

inline bool TraceInstructionCanSeed(const Instruction& in) {
    return in.length > 0 && in.length <= 15 &&
           in.address <= UINT64_MAX - in.length &&
           !in.mnemonic.empty() && in.mnemonic != "db" &&
           in.mnemonic != "dw" && in.mnemonic != "dd" && in.mnemonic != "dq";
}

inline bool TraceInstructionEndsSpan(const Instruction& in) {
    // A call may never return. Its continuation needs its own observation.
    // Decoder flow is authoritative; exception/system transfers also prevent
    // entry coverage from implying that the next instruction was reached.
    return InstructionEndsBlock(in) || InstructionIsCall(in) ||
           InstructionIsReturn(in) || in.mnemonic == "int" ||
           in.mnemonic == "int1" || in.mnemonic == "int3" ||
           in.mnemonic == "into" || in.mnemonic == "ud0" ||
           in.mnemonic == "ud1" || in.mnemonic == "ud2" ||
           in.mnemonic == "hlt" || in.mnemonic == "syscall" ||
           in.mnemonic == "sysenter" || in.mnemonic == "sysexit" ||
           in.mnemonic == "sysret" || in.mnemonic == "sysretq";
}

// Call only for exact listing rows, in increasing address order. False leaves
// the existing spans unchanged, including on a malformed row or budget limit.
inline bool AppendTraceCodeSpan(std::vector<TraceCodeSpan>& spans,
                                const Instruction& in, bool boundary,
                                size_t maxSpans = 65536) {
    if (!TraceInstructionCanSeed(in)) return false;
    if (!spans.empty() && in.address < spans.back().end) return false;
    if (!boundary && !spans.empty() && spans.back().end == in.address) {
        spans.back().end = in.address + in.length;
        return true;
    }
    if (spans.size() >= maxSpans) return false;
    spans.push_back({in.address, in.address + in.length});
    return true;
}

inline const TraceCodeSpan* FindTraceCodeSpan(const std::vector<TraceCodeSpan>& spans,
                                             uint64_t va) {
    auto span = std::upper_bound(spans.begin(), spans.end(), va,
        [](uint64_t address, const TraceCodeSpan& item) { return address < item.begin; });
    if (span == spans.begin()) return nullptr;
    --span;
    return va < span->end ? &*span : nullptr;
}

inline bool TraceCoveredByBlock(const std::vector<uint64_t>& starts,
                                const std::vector<TraceCodeSpan>& spans,
                                const std::unordered_map<uint64_t, uint64_t>& hits,
                                uint64_t va) {
    const auto* span = FindTraceCodeSpan(spans, va);
    if (!span) return false;
    auto site = std::upper_bound(starts.begin(), starts.end(), va);
    if (site == starts.begin()) return false;
    --site;
    if (*site < span->begin) return false;
    const auto hit = hits.find(*site);
    return hit != hits.end() && hit->second != 0;
}

} // namespace ds
