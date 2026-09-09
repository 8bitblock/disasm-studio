#pragma once
#include "Debugger.h"
#include "../Disasm/IDisassembler.h"
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace ds {

// An exact observation key, not a lossy address hash. An unwind revision changes
// even when a later stop happens to have the same instruction and stack pointer.
struct BacktraceStop {
    DebugTargetIdentity target{};
    uint32_t tid = 0;
    uint64_t rip = 0, rsp = 0, rbp = 0, revision = 0;
    bool is32 = false;
    struct Module {
        uint64_t base = 0, size = 0, generation = 0;
        bool operator==(const Module&) const = default;
    };
    std::vector<Module> modules;
};

inline bool BacktracePaused(const DbgSnapshot& snap) {
    return snap.state == DbgState::Paused && !snap.cleanupOnly &&
        DebugTargetIdentity{snap.pid, snap.sessionGeneration}.valid() && snap.activeTid;
}

inline BacktraceStop CaptureBacktraceStop(const DbgSnapshot& snap) {
    if (!BacktracePaused(snap)) return {};
    BacktraceStop stop;
    stop.target = {snap.pid, snap.sessionGeneration};
    stop.tid = snap.activeTid;
    stop.rip = snap.regs.rip; stop.rsp = snap.regs.rsp; stop.rbp = snap.regs.rbp;
    stop.revision = snap.stackRevision; stop.is32 = snap.is32;
    for (const auto& module : snap.modules)
        stop.modules.push_back({module.base, module.size, module.loadGeneration});
    return stop;
}

inline bool BacktraceStopMatches(const BacktraceStop& stop, const DbgSnapshot& snap) {
    if (!BacktracePaused(snap) || !DebugTargetIdentityMatches(stop.target,
            {snap.pid, snap.sessionGeneration}) || stop.tid != snap.activeTid ||
        stop.rip != snap.regs.rip || stop.rsp != snap.regs.rsp || stop.rbp != snap.regs.rbp ||
        stop.revision != snap.stackRevision || stop.is32 != snap.is32 ||
        stop.modules.size() != snap.modules.size()) return false;
    for (size_t i = 0; i < stop.modules.size(); ++i) {
        const auto& module = snap.modules[i];
        if (stop.modules[i] != BacktraceStop::Module{module.base, module.size,
                                                    module.loadGeneration}) return false;
    }
    return true;
}

inline bool BacktraceUnwindCurrent(const DbgSnapshot& snap) {
    return BacktracePaused(snap) && snap.stackRevision &&
        snap.stackTid == snap.activeTid && snap.stackRip == snap.regs.rip &&
        snap.stackRsp == snap.regs.rsp && snap.stackRbp == snap.regs.rbp &&
        !snap.frames.empty() && snap.frames.front().pc == snap.regs.rip &&
        snap.frames.front().stackPtr == snap.regs.rsp;
}

inline const DbgModule* BacktraceModuleAt(const DbgSnapshot& snap, uint64_t address) {
    const DbgModule* found = nullptr;
    for (const auto& module : snap.modules) {
        // Subtraction avoids a wrapped image-end accepting unrelated addresses.
        if (address >= module.base && address - module.base < module.size) {
            if (found) return nullptr; // ambiguous overlapping module ownership
            found = &module;
        }
    }
    return found;
}

inline std::string BacktraceModuleLabel(const DbgSnapshot& snap, uint64_t address) {
    const auto* module = BacktraceModuleAt(snap, address);
    if (!module) return "unmapped / unknown";
    char offset[32]{};
    std::snprintf(offset, sizeof(offset), "+0x%llX",
                  static_cast<unsigned long long>(address - module->base));
    return (module->name.empty() ? "unnamed module" : module->name) + std::string(offset);
}

struct BacktraceCallCandidate {
    uint64_t address = 0;
    unsigned matches = 0;
    bool unique() const { return matches == 1; }
};

// Backward x86 decoding cannot prove an instruction boundary. Retain the
// distinction even for one matching CALL suffix; two matches disable navigation.
inline BacktraceCallCandidate FindBacktraceCallCandidate(
    IDisassembler& decoder, const uint8_t* prefix, size_t size, uint64_t returnAddress) {
    BacktraceCallCandidate result;
    if (!prefix || !size || size > 15 || returnAddress < size) return result;
    for (size_t length = 2; length <= size; ++length) {
        Instruction instruction;
        if (decoder.decodeOne(prefix + size - length, length,
                returnAddress - length, instruction) && instruction.length == length &&
            InstructionIsCall(instruction)) {
            ++result.matches;
            result.address = returnAddress - length;
        }
    }
    if (!result.unique()) result.address = 0;
    return result;
}

} // namespace ds
