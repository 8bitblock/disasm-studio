#include "ExecutionHistoryView.h"
#include "Fonts.h"
#include "Theme.h"
#include "Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>

namespace ds::ui {

bool ExecutionHistoryView::sameRecording(const ExecutionHistorySnapshot& history) const {
    return target_.pid == history.target.pid &&
           target_.sessionGeneration == history.target.sessionGeneration &&
           tid_ == history.tid && generation_ == history.generation;
}

void ExecutionHistoryView::select(size_t index, const ExecutionHistorySnapshot& history) {
    if (index >= history.entries.size()) return;
    selected_ = index;
    selectedSequence_ = history.entries[index].sequence;
    followingLatest_ = index + 1 == history.entries.size();
    scrollToSelection_ = true;
}

void ExecutionHistoryView::sync(const ExecutionHistorySnapshot& history) {
    const bool changedOwner = !sameRecording(history);
    if (!changedOwner && revision_ == history.revision) return;
    target_ = history.target;
    tid_ = history.tid;
    generation_ = history.generation;
    revision_ = history.revision;
    if (changedOwner) followingLatest_ = true;
    if (history.entries.empty()) {
        selected_ = noSelection;
        selectedSequence_ = 0;
        followingLatest_ = true;
        scrollToSelection_ = false;
        return;
    }
    if (followingLatest_ || selected_ == noSelection) {
        select(history.entries.size() - 1, history);
    } else {
        // Sequence identity also keeps selection honest if an older prefix is
        // ever discarded. Never silently substitute another captured state.
        const auto found = std::find_if(history.entries.begin(), history.entries.end(),
            [&](const ExecutionHistoryEntry& entry) { return entry.sequence == selectedSequence_; });
        if (found == history.entries.end()) select(history.entries.size() - 1, history);
        else selected_ = static_cast<size_t>(found - history.entries.begin());
    }
}

bool ExecutionHistoryView::canStepBack(const ExecutionHistorySnapshot& history) const {
    if (history.entries.size() < 2) return false;
    if (!sameRecording(history) || selected_ >= history.entries.size() || followingLatest_)
        return true;
    return selected_ > 0;
}

void ExecutionHistoryView::stepBack(const ExecutionHistorySnapshot& history) {
    sync(history);
    open = true;
    if (selected_ != noSelection && selected_ > 0) select(selected_ - 1, history);
}

namespace {

std::string recordedBytes(const ExecutionHistoryEntry& entry, size_t count) {
    count = std::min(count, std::min<size_t>(entry.byteCount, entry.bytes.size()));
    if (!count) return "unavailable";
    std::string result;
    result.reserve(count * 3);
    for (size_t i = 0; i < count; ++i) {
        char byte[4]{};
        std::snprintf(byte, sizeof(byte), i ? " %02X" : "%02X", entry.bytes[i]);
        result += byte;
    }
    return result;
}

bool decodeRecorded(ZydisDisassembler& decoder, const ExecutionHistoryEntry& entry,
                    Instruction& instruction) {
    const size_t count = std::min<size_t>(entry.byteCount, entry.bytes.size());
    return count && decoder.decodeOne(entry.bytes.data(), count, entry.regs.rip, instruction) &&
           instruction.length && instruction.length <= count;
}

void recordedRegisters(const Registers& registers, bool is32) {
    struct Value { const char* name64; const char* name32; uint64_t value; };
    const Value values[] = {
        {"RIP", "EIP", registers.rip}, {"RSP", "ESP", registers.rsp},
        {"RBP", "EBP", registers.rbp}, {"RFLAGS", "EFLAGS", registers.rflags},
        {"RAX", "EAX", registers.rax}, {"RBX", "EBX", registers.rbx},
        {"RCX", "ECX", registers.rcx}, {"RDX", "EDX", registers.rdx},
        {"RSI", "ESI", registers.rsi}, {"RDI", "EDI", registers.rdi},
        {"R8", nullptr, registers.r8}, {"R9", nullptr, registers.r9},
        {"R10", nullptr, registers.r10}, {"R11", nullptr, registers.r11},
        {"R12", nullptr, registers.r12}, {"R13", nullptr, registers.r13},
        {"R14", nullptr, registers.r14}, {"R15", nullptr, registers.r15}
    };
    const int count = is32 ? 10 : 18;
    const int pairs = ImGui::GetContentRegionAvail().x >= 660.0f * theme::UiScale() ? 3 :
                      ImGui::GetContentRegionAvail().x >= 430.0f * theme::UiScale() ? 2 : 1;
    PushMono();
    if (BeginDataTable("##captured_registers", pairs * 2,
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0, ImGui::GetTextLineHeightWithSpacing() * 6.2f))) {
        for (int pair = 0; pair < pairs; ++pair) {
            ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed,
                                     ImGui::CalcTextSize("RFLAGS ").x);
            ImGui::TableSetupColumn("Captured value", ImGuiTableColumnFlags_WidthStretch);
        }
        for (int i = 0; i < count; ++i) {
            if (i % pairs == 0) ImGui::TableNextRow();
            ImGui::TableSetColumnIndex((i % pairs) * 2);
            ImGui::TextColored(theme::col::muted(), "%s", is32 ? values[i].name32 : values[i].name64);
            ImGui::TableNextColumn();
            const uint64_t value = is32 ? static_cast<uint32_t>(values[i].value) : values[i].value;
            ImGui::Text("%0*llX", is32 ? 8 : 16, static_cast<unsigned long long>(value));
        }
        EndDataTable();
    }
    PopMono();
}

} // namespace

void ExecutionHistoryView::render(const ExecutionHistorySnapshot& history, const DbgSnapshot& live) {
    sync(history);
    if (!open) return;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const float scale = theme::UiScale();
    const ImVec2 available(std::max(1.0f, viewport->WorkSize.x - 24.0f * scale),
                           std::max(1.0f, viewport->WorkSize.y - 24.0f * scale));
    ImGui::SetNextWindowSizeConstraints(ImVec2(std::min(360.0f * scale, available.x),
                                               std::min(240.0f * scale, available.y)), available);
    // Size constraints alone preserve the old position and can leave most of
    // an open inspector offscreen after the host window becomes smaller.
    const bool viewportShrank = viewport->WorkSize.x < viewportWidth_ ||
                                viewport->WorkSize.y < viewportHeight_;
    if (viewportShrank) scrollToSelection_ = true;
    viewportWidth_ = viewport->WorkSize.x;
    viewportHeight_ = viewport->WorkSize.y;
    ImGui::SetNextWindowPos(viewport->GetWorkCenter(),
        viewportShrank ? ImGuiCond_Always : ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(1040.0f * scale, available.x),
                                   std::min(740.0f * scale, available.y)), ImGuiCond_Appearing);
    if (!ImGui::Begin("Execution History", &open)) { ImGui::End(); return; }

    PanelHeader("Recorded instruction path - inspection only");
    ImGui::TextWrapped("One user-mode thread. Registers and instruction bytes were captured at each observed RIP; past memory is not recorded.");
    if (!history.status.empty()) ImGui::TextWrapped("%s", history.status.c_str());
    if (history.target.valid()) {
        ImGui::TextWrapped("PID %u  |  TID %u  |  %s  |  %zu / 10,000 observations%s",
            history.target.pid, history.tid, history.is32 ? "x86" : "x64", history.entries.size(),
            history.recording ? "  |  Recording" : "");
    }

    const bool currentOwner = DebugTargetIdentityMatches(history.target,
        {live.pid, live.sessionGeneration});
    if (live.state == DbgState::Paused) {
        char detail[144]{};
        std::snprintf(detail, sizeof(detail), "Live TID %u  %s %0*llX%s", live.tid,
            live.is32 ? "EIP" : "RIP", live.is32 ? 8 : 16,
            static_cast<unsigned long long>(live.regs.rip),
            history.target.valid() && !currentOwner ? "  (another session)" : "");
        StatePill("LIVE PAUSED", theme::col::warn());
        SameLineIfFits(ImGui::CalcTextSize(detail).x);
        ImGui::TextWrapped("%s", detail);
    } else {
        const char* state = live.state == DbgState::Running ? "LIVE RUNNING" :
                            live.state == DbgState::Terminated ? "TARGET EXITED" : "DETACHED";
        StatePill(state, live.state == DbgState::Running ? theme::col::good() : theme::col::muted());
    }

    if (history.entries.empty()) {
        ImGui::Spacing();
        ImGui::TextWrapped("No recorded path. At a pause, choose Record before running to the next breakpoint. Ordinary Continue cannot recover earlier instructions.");
        ImGui::End();
        return;
    }

    ImGui::BeginDisabled(!canStepBack(history));
    if (ImGui::Button("Step Back")) stepBack(history);
    ImGui::EndDisabled();
    ItemTooltip("Inspect the previous captured state. The live target stays at its current position.");
    SameLineIfFits(ImGui::CalcTextSize("Forward").x + ImGui::GetStyle().FramePadding.x * 2);
    ImGui::BeginDisabled(selected_ + 1 >= history.entries.size());
    if (ImGui::Button("Forward")) select(selected_ + 1, history);
    ImGui::EndDisabled();
    SameLineIfFits(ImGui::CalcTextSize("Latest").x + ImGui::GetStyle().FramePadding.x * 2);
    ImGui::BeginDisabled(selected_ + 1 >= history.entries.size());
    if (ImGui::Button("Latest")) select(history.entries.size() - 1, history);
    ImGui::EndDisabled();
    SameLineIfFits(ImGui::CalcTextSize("Observation 10000 / 10000").x);
    ImGui::TextDisabled("Observation %zu / %zu", selected_ + 1, history.entries.size());

    auto& decoder = history.is32 ? decoder32_ : decoder64_;
    const float reserve = ImGui::GetTextLineHeightWithSpacing() * 12.0f;
    const float tableHeight = std::clamp(ImGui::GetContentRegionAvail().y - reserve,
                                         130.0f * scale, 360.0f * scale);
    PushMono();
    if (ImGui::BeginTable("##recorded_path", 4,
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit,
            ImVec2(0, tableHeight), 870.0f * scale)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Sequence", ImGuiTableColumnFlags_WidthFixed, 75.0f * scale);
        ImGui::TableSetupColumn("Observed RIP", ImGuiTableColumnFlags_WidthFixed,
                                 ImGui::CalcTextSize(history.is32 ? "00000000  " : "0000000000000000  ").x);
        ImGui::TableSetupColumn("Captured bytes", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(history.entries.size()));
        if (scrollToSelection_ && selected_ < history.entries.size())
            clipper.IncludeItemByIndex(static_cast<int>(selected_));
        while (clipper.Step()) for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& entry = history.entries[static_cast<size_t>(row)];
            const bool selected = selected_ == static_cast<size_t>(row);
            Instruction instruction;
            const bool decoded = decodeRecorded(decoder, entry, instruction);
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(row);
            char sequence[40]{};
            std::snprintf(sequence, sizeof(sequence), "%llu%s", static_cast<unsigned long long>(entry.sequence),
                static_cast<size_t>(row) + 1 == history.entries.size() ? " *" : "");
            if (ImGui::Selectable(sequence, selected, ImGuiSelectableFlags_SpanAllColumns))
                select(static_cast<size_t>(row), history);
            if (selected && scrollToSelection_) { ImGui::SetScrollHereY(0.5f); scrollToSelection_ = false; }
            ImGui::TableNextColumn();
            ImGui::Text("%0*llX", history.is32 ? 8 : 16, static_cast<unsigned long long>(entry.regs.rip));
            ImGui::TableNextColumn();
            const std::string bytes = recordedBytes(entry, decoded ? instruction.length : entry.byteCount);
            ImGui::TextDisabled("%s", bytes.c_str());
            ItemTooltip(bytes.c_str());
            ImGui::TableNextColumn();
            const std::string text = decoded ? InstructionText(instruction) : entry.byteCount
                ? "undecodable / partial capture" : "instruction bytes unavailable";
            ImGui::TextUnformatted(text.c_str());
            ItemTooltip(text.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    PopMono();

    ImGui::TextWrapped("* Latest observation. Each RIP identifies an instruction about to execute; the final observed instruction may not have executed.");
    if (selected_ < history.entries.size()) {
        const auto& entry = history.entries[selected_];
        char heading[128]{};
        std::snprintf(heading, sizeof(heading), "Captured registers - sequence %llu, TID %u",
            static_cast<unsigned long long>(entry.sequence), history.tid);
        PanelHeader(heading);
        recordedRegisters(entry.regs, history.is32);
    }
    ImGui::End();
}

} // namespace ds::ui
