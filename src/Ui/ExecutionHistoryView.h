#pragma once

#include "Core/Debugger.h"
#include "Disasm/ZydisDisassembler.h"
#include <cstddef>
#include <limits>

namespace ds::ui {

// Inspection owns only a cursor and decoders. It has no debugger reference and
// cannot read present-day memory or change the target while browsing history.
class ExecutionHistoryView {
public:
    bool open = false;

    void sync(const ExecutionHistorySnapshot& history);
    bool canStepBack(const ExecutionHistorySnapshot& history) const;
    void stepBack(const ExecutionHistorySnapshot& history);
    void render(const ExecutionHistorySnapshot& history, const DbgSnapshot& live);
    size_t selectedIndex() const noexcept { return selected_; }

private:
    static constexpr size_t noSelection = std::numeric_limits<size_t>::max();
    bool sameRecording(const ExecutionHistorySnapshot& history) const;
    void select(size_t index, const ExecutionHistorySnapshot& history);

    DebugTargetIdentity target_{};
    uint32_t tid_ = 0;
    uint64_t generation_ = 0, revision_ = 0, selectedSequence_ = 0;
    size_t selected_ = noSelection;
    bool followingLatest_ = true;
    bool scrollToSelection_ = false;
    float viewportWidth_ = 0.0f, viewportHeight_ = 0.0f;
    ZydisDisassembler decoder64_{Arch::X64};
    ZydisDisassembler decoder32_{Arch::X86};
};

} // namespace ds::ui
