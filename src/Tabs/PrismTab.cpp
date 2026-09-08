#include "PrismTab.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace ds {

namespace {

ImVec4 stateColor(ThreadState state) {
    switch (state) {
        case ThreadState::Running:        return theme::col::good();
        case ThreadState::Waiting:        return theme::col::muted();
        case ThreadState::LockContention: return theme::col::bad();
        case ThreadState::Allocation:     return theme::col::warn();
        case ThreadState::IO:             return theme::col::call();
        case ThreadState::Gpu:            return theme::col::branch();
        default:                          return theme::col::muted();
    }
}

bool parsePid(const char* text, uint32_t& pid) {
    if (!text || !*text) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (errno || end == text || *end || value == 0 ||
        value > (std::numeric_limits<uint32_t>::max)()) return false;
    pid = static_cast<uint32_t>(value);
    return true;
}

ImU32 flameColor(const std::string& symbol, bool selected) {
    uint32_t hash = 2166136261u;
    for (unsigned char c : symbol) hash = (hash ^ c) * 16777619u;
    const ImVec4 palette[] = { theme::col::accent(), theme::col::good(),
        theme::col::warn(), theme::col::call(), theme::col::branch(), theme::col::jump() };
    ImVec4 color = palette[hash % IM_ARRAYSIZE(palette)];
    color.w = selected ? 1.0f : 0.82f;
    return ImGui::ColorConvertFloat4ToU32(color);
}

// Prefer the static listing only when AppContext can prove that the sampled runtime
// address belongs to the exact active image. Otherwise navigate to live assembly.
bool navigateAddress(AppContext& ctx, uint32_t sampledPid,
                     uint64_t sampledCreationTime, uint64_t runtimeAddress,
                     const DbgSnapshot& snapshot, bool forceLive = false) {
    const DebugTargetIdentity target{ snapshot.pid, snapshot.sessionGeneration };
    if (!runtimeAddress || !snapshot.attached() || snapshot.pid != sampledPid ||
        !sampledCreationTime ||
        ctx.debug.processCreationTimeForSession(target) != sampledCreationTime)
        return false;
    if (!forceLive && ctx.staticBinary().loaded()) {
        uint64_t runtimeBase = 0, runtimeSize = 0;
        if (ctx.debuggerRuntimeImage(snapshot, runtimeBase, runtimeSize) &&
            runtimeAddress >= runtimeBase && runtimeAddress - runtimeBase < runtimeSize) {
            const uint64_t delta = runtimeAddress - runtimeBase;
            if (delta <= (std::numeric_limits<uint64_t>::max)() - ctx.staticBinary().imageBase()) {
                const uint64_t staticAddress = ctx.staticBinary().imageBase() + delta;
                size_t available = 0;
                if (ctx.staticBinary().ptrFromVA(staticAddress, available) && available) {
                    ctx.gotoAddress(staticAddress);
                    return true;
                }
            }
        }
    }
    ctx.gotoAddressLive(runtimeAddress, target);
    return true;
}

void drawQuality(const PrismCollectionQuality& quality) {
    const ImVec4 color = quality.degraded ? theme::col::warn() : theme::col::good();
    ImGui::TextColored(color, "%s", PrismCollectorName(quality.collector));
    ImGui::SameLine();
    if (quality.wow64Target) ImGui::TextDisabled("WOW64 target");
    else                     ImGui::TextDisabled("native target");
    if (!quality.summary.empty()) ImGui::TextWrapped("%s", quality.summary.c_str());
    if (!quality.fallbackReason.empty()) {
        ImGui::TextColored(theme::col::warn(), "Fallback reason:");
        ImGui::SameLine();
        ImGui::TextWrapped("%s", quality.fallbackReason.c_str());
    }
    if (!quality.warning.empty())
        ImGui::TextColored(theme::col::warn(), "%s", quality.warning.c_str());
}

void drawFlameGraph(const PrismReport& report, AppContext& ctx, uint32_t sampledPid,
                    uint64_t sampledCreationTime, const DbgSnapshot& snapshot,
                    int& selectedNode) {
    if (report.flame.size() <= 1) {
        ImGui::TextDisabled("No stack frames are available for a flame graph.");
        return;
    }

    uint16_t maxDepth = 1;
    for (size_t i = 1; i < report.flame.size(); ++i)
        maxDepth = std::max(maxDepth, report.flame[i].depth);

    const float scale = theme::UiScale();
    const float rowHeight = 21.0f * scale;
    const float graphHeight = std::min(300.0f * scale,
                                       std::max(90.0f * scale, rowHeight * maxDepth + 4.0f));
    if (!ImGui::BeginChild("pr_flame", ImVec2(0, graphHeight), ImGuiChildFlags_None,
                           ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGui::EndChild();
        return;
    }

    const float width = std::max(ImGui::GetContentRegionAvail().x, 600.0f * scale);
    const float contentHeight = rowHeight * maxDepth + 2.0f;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImVec2 mouse = ImGui::GetMousePos();
    const bool childHovered = ImGui::IsWindowHovered();
    int hoveredNode = -1;

    for (size_t i = 1; i < report.flame.size(); ++i) {
        const PrismFlameNode& node = report.flame[i];
        if (node.x1 <= node.x0 || node.depth == 0) continue;
        const float left = origin.x + node.x0 * width;
        const float right = origin.x + node.x1 * width - 1.0f;
        const float top = origin.y + static_cast<float>(node.depth - 1) * rowHeight;
        const float bottom = top + rowHeight - 1.0f;
        if (right <= left || bottom < ImGui::GetWindowPos().y ||
            top > ImGui::GetWindowPos().y + ImGui::GetWindowSize().y) continue;

        const bool selected = selectedNode == static_cast<int>(i);
        draw->AddRectFilled(ImVec2(left, top), ImVec2(right, bottom),
                            flameColor(node.symbol, selected), 2.0f * scale);
        draw->AddRect(ImVec2(left, top), ImVec2(right, bottom),
                      ImGui::GetColorU32(selected ? theme::col::accent() : theme::col::lineSoft()),
                      2.0f * scale, 0, selected ? 2.0f : 1.0f);
        const float boxWidth = right - left;
        if (boxWidth > 34.0f * scale) {
            const ImVec2 textSize = ImGui::CalcTextSize(node.symbol.c_str());
            draw->PushClipRect(ImVec2(left + 3.0f, top), ImVec2(right - 2.0f, bottom), true);
            draw->AddText(ImVec2(left + 4.0f, top + (rowHeight - textSize.y) * 0.5f),
                          ImGui::GetColorU32(theme::col::windowBg()), node.symbol.c_str());
            draw->PopClipRect();
        }
        if (childHovered && mouse.x >= left && mouse.x < right &&
            mouse.y >= top && mouse.y < bottom) hoveredNode = static_cast<int>(i);
    }

    ImGui::Dummy(ImVec2(width, contentHeight));
    if (hoveredNode > 0) {
        const PrismFlameNode& node = report.flame[static_cast<size_t>(hoveredNode)];
        ImGui::BeginTooltip();
        ImGui::TextUnformatted(node.symbol.c_str());
        ImGui::Text("0x%llX  |  %llu samples  |  %llu self",
                    static_cast<unsigned long long>(node.address),
                    static_cast<unsigned long long>(node.samples),
                    static_cast<unsigned long long>(node.selfSamples));
        ImGui::TextDisabled("Click: exact static image when provable, otherwise live. Shift-click: live.");
        ImGui::EndTooltip();
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            selectedNode = hoveredNode;
            if (!navigateAddress(ctx, sampledPid, sampledCreationTime,
                                 node.address, snapshot,
                                 ImGui::GetIO().KeyShift))
                ui::Toast(ui::ToastKind::Info,
                          "Attach the Win32 debugger to this exact sampled process to navigate runtime addresses.");
        }
    }
    ImGui::EndChild();
}

void drawVerticalSplitter(const char* id, const ImVec2& localPos,
                          float height, float thickness, float contentWidth,
                          float& ratio, float minRatio, float maxRatio) {
    ImGui::SetCursorPos(localPos);
    const ImVec2 screenPos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton(id, ImVec2(thickness, std::max(1.0f, height)));
    const bool hot = ImGui::IsItemHovered() || ImGui::IsItemActive();
    if (hot) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
    if (ImGui::IsItemActive() && contentWidth > 1.0f)
        ratio += ImGui::GetIO().MouseDelta.x / contentWidth;
    ratio = std::clamp(ratio, minRatio, maxRatio);
    const float x = screenPos.x + thickness * 0.5f;
    ImGui::GetWindowDrawList()->AddLine(
        ImVec2(x, screenPos.y), ImVec2(x, screenPos.y + height),
        ImGui::GetColorU32(hot ? theme::col::accent() : theme::col::lineSoft()),
        hot ? 2.0f : 1.0f);
}

} // namespace

void PrismTab::render(AppContext& ctx) {
    const float scale = theme::UiScale();
    bool running = sampler_.running();
    ImGui::TextUnformatted("Prism");
    ui::SameLineIfFits(275.0f * scale);
    ImGui::TextDisabled("Process activity and sampled call paths");

    if (running) {
        ImGui::BeginDisabled(stopRequested_);
        if (ui::ToolbarIconButton(DS_ICON_STOP, "Stop", "Cancel Prism collection")) {
            sampler_.requestStop();
            stopRequested_ = true;
        }
        ImGui::EndDisabled();
        if (stopRequested_) {
            ImGui::SameLine();
            ImGui::TextDisabled("stopping...");
        }
    } else {
        stopRequested_ = false;
        if (ui::ToolbarIconButton(DS_ICON_PLAY, "Start", "Start profiling the target process")) {
            uint32_t pid = 0;
            if (!parsePid(pidBuf_, pid)) {
                ui::Toast(ui::ToastKind::Warn, "Enter a valid process ID first");
            } else {
                shownError_.clear();
                selectedTimeline_ = -1;
                selectedFlame_ = -1;
                std::string error;
                const PrismStartMode mode = static_cast<PrismStartMode>(startMode_);
                if (!sampler_.start(pid, mode, error))
                    ui::Toast(ui::ToastKind::Error, "Prism: " + error);
                else
                    ui::Toast(ui::ToastKind::Info,
                              "Prism started for pid " + std::to_string(pid) + " — " +
                              PrismStartModeName(mode));
            }
        }
    }

    running = sampler_.running();
    ui::SameLineIfFits(110.0f * scale);
    ImGui::SetNextItemWidth(110.0f * scale);
    ImGui::BeginDisabled(running);
    ImGui::InputTextWithHint("##prism_pid", "pid", pidBuf_, sizeof(pidBuf_),
                             ImGuiInputTextFlags_CharsDecimal);
    const DbgSnapshot targetSnapshot = ctx.debug.snapshot();
    if (targetSnapshot.attached()) {
        ui::SameLineIfFits(150.0f * scale);
        if (ImGui::SmallButton("Use debugger PID"))
            std::snprintf(pidBuf_, sizeof(pidBuf_), "%u", targetSnapshot.pid);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Select PID %u for the next profile. Start begins collection.", targetSnapshot.pid);
    }
    ui::SameLineIfFits(205.0f * scale);
    ImGui::SetNextItemWidth(205.0f * scale);
    const char* modes[] = { "Automatic (ETW preferred)", "ETW only", "Suspend-and-walk fallback" };
    ImGui::Combo("##prism_mode", &startMode_, modes, IM_ARRAYSIZE(modes));
    ImGui::EndDisabled();
    ui::SameLineIfFits(55.0f * scale);
    if (ImGui::SmallButton("Clear")) {
        sampler_.clearSamples();
        selectedTimeline_ = -1;
        selectedFlame_ = -1;
    }
    ui::SameLineIfFits(180.0f * scale);
    ImGui::TextDisabled("%zu observations%s", sampler_.sampleCount(),
                        sampler_.sampleCount() >= PrismSampler::kMaxSamples ? " (rolling)" : "");
    ImGui::Separator();

    if (running || sampler_.reportGeneration() != sampler_.sampleGeneration())
        ctx.wantContinuousRedraw = true;

    const std::string asyncError = sampler_.lastError();
    if (!asyncError.empty() && asyncError != shownError_) {
        shownError_ = asyncError;
        ui::Toast(ui::ToastKind::Error, "Prism: " + asyncError);
    }
    if (!asyncError.empty()) {
        ImGui::PushTextWrapPos();
        ImGui::TextColored(theme::col::bad(), "%s", asyncError.c_str());
        ImGui::PopTextWrapPos();
    }

    const std::shared_ptr<const PrismReport> reportPtr = sampler_.report();
    if (!reportPtr) {
        ImGui::TextDisabled("Preparing the profiling report...");
        ctx.wantContinuousRedraw = true;
        return;
    }
    const PrismReport& report = *reportPtr;
    if (sampler_.pid() != 0) {
        drawQuality(report.quality);
        ImGui::Separator();
    }

    if (report.totalSamples == 0) {
        ui::EmptyState(DS_ICON_LIGHTNING, running ? "Collecting observations..." : "No samples yet",
                       running ? "The collector is starting or waiting for activity. Its collection mode and any coverage limits appear above. Stop keeps the collected report."
                       : "Enter a running process ID and press Start. Prism prefers bounded ETW sampled-profile, "
                       "image/thread, scheduling/wait, and I/O evidence. If Windows policy blocks ETW, Automatic "
                       "mode uses the clearly labelled suspend-and-walk fallback (native or WOW64).",
                       nullptr);
        return;
    }

    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextColored(theme::col::accent(), "%s", report.headline.c_str());
    ImGui::TextWrapped("%s", report.verdict.c_str());
    ImGui::PopTextWrapPos();
    ImGui::Separator();

    if (!report.timeline.empty()) {
        ImGui::SeparatorText("Activity timeline");
        ui::ItemTooltip("Click a time slice to select its observation count and dominant thread state.");
        const ImVec2 start = ImGui::GetCursorScreenPos();
        const float width = std::max(1.0f, ImGui::GetContentRegionAvail().x);
        const float height = 18.0f * scale;
        ImGui::InvisibleButton("##prism_timeline", ImVec2(width, height));
        ImDrawList* draw = ImGui::GetWindowDrawList();
        const float cellWidth = width / static_cast<float>(report.timeline.size());
        for (size_t i = 0; i < report.timeline.size(); ++i) {
            const ImVec2 a(start.x + static_cast<float>(i) * cellWidth, start.y);
            const ImVec2 b(start.x + static_cast<float>(i + 1) * cellWidth - 1.0f, start.y + height);
            draw->AddRectFilled(a, b,
                ImGui::ColorConvertFloat4ToU32(stateColor(report.timeline[i].dominant)));
            if (selectedTimeline_ == static_cast<int>(i))
                draw->AddRect(a, b, ImGui::GetColorU32(theme::col::accent()), 0.0f, 0, 2.0f);
        }
        if (ImGui::IsItemHovered()) {
            int index = static_cast<int>((ImGui::GetMousePos().x - start.x) / cellWidth);
            index = std::clamp(index, 0, static_cast<int>(report.timeline.size()) - 1);
            const PrismTimeSlice& slice = report.timeline[static_cast<size_t>(index)];
            ImGui::SetTooltip("+%.3fs  %d observations  %s",
                              slice.startMs / 1000.0, slice.samples,
                              ThreadStateName(slice.dominant));
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) selectedTimeline_ = index;
        }
        if (selectedTimeline_ >= 0 && selectedTimeline_ < static_cast<int>(report.timeline.size())) {
            const PrismTimeSlice& slice = report.timeline[static_cast<size_t>(selectedTimeline_)];
            ImGui::TextDisabled("Selected +%.3fs: %d observations, dominant %s",
                                slice.startMs / 1000.0, slice.samples,
                                ThreadStateName(slice.dominant));
        }
        ImGui::Separator();
    }

    const DbgSnapshot navigationSnapshot = ctx.debug.snapshot();
    const uint64_t sampledCreationTime = sampler_.creationTime100ns();
    const DebugTargetIdentity navigationTarget{
        navigationSnapshot.pid, navigationSnapshot.sessionGeneration
    };
    const bool navigationOwnerExact = navigationSnapshot.attached() &&
        navigationSnapshot.pid == sampler_.pid() && sampledCreationTime &&
        ctx.debug.processCreationTimeForSession(navigationTarget) ==
            sampledCreationTime;
    if (ImGui::CollapsingHeader("Flame graph", ImGuiTreeNodeFlags_DefaultOpen)) {
        drawFlameGraph(report, ctx, sampler_.pid(), sampledCreationTime,
                       navigationSnapshot, selectedFlame_);
        if (report.flameTruncated)
            ImGui::TextColored(theme::col::warn(), "Flame graph reached its 4,096-node safety bound.");
    }

    ImGui::SeparatorText("Thread-state observations");
    ImGui::TextDisabled("Distribution of observations, not CPU utilization");
    const int stateColumns = std::clamp(
        static_cast<int>(ImGui::GetContentRegionAvail().x / (220.0f * scale)), 1, 4);
    if (ImGui::BeginTable("##prism_states", stateColumns,
                          ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoSavedSettings)) {
        for (const PrismStateStat& state : report.states) {
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(state.state));
            ImGui::TextWrapped("%s  %.0f%%  (%d)", ThreadStateName(state.state), state.pct, state.samples);
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, stateColor(state.state));
            ImGui::ProgressBar(state.pct / 100.0f, ImVec2(-1, 4.0f * scale), "");
            ImGui::PopStyleColor();
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::Separator();

    renderReportPanes(ctx, report, navigationSnapshot, sampledCreationTime,
                      navigationOwnerExact);
}

void PrismTab::renderReportPanes(AppContext& ctx, const PrismReport& report,
                                 const DbgSnapshot& navigationSnapshot,
                                 uint64_t sampledCreationTime, bool canNavigate) {
    const float scale = theme::UiScale();
    const bool compact = ImGui::GetContentRegionAvail().x < 900.0f * scale;
    if (compact) {
        static const char* views[] = { "Functions", "Threads & modules", "Call paths" };
        compactReportView_ = ui::TabStrip("##prism_report_views", views, 3, compactReportView_);
    }
    ImVec2 available = ImGui::GetContentRegionAvail();
    available.y = std::max(220.0f * scale, available.y);
    const ImVec2 paneStart = ImGui::GetCursorPos();
    const float splitter = 6.0f * scale;
    const float paneContentWidth = std::max(1.0f, available.x - splitter * 2.0f);
    const float minPane = std::min(170.0f * scale, paneContentWidth * 0.28f);
    const float minRatio = minPane / paneContentWidth;
    if (!compact) {
        firstPaneSplit_ = std::clamp(firstPaneSplit_, minRatio,
                                     std::max(minRatio, secondPaneSplit_ - minRatio));
        secondPaneSplit_ = std::clamp(secondPaneSplit_, firstPaneSplit_ + minRatio,
                                      std::max(firstPaneSplit_ + minRatio, 1.0f - minRatio));
    }
    const float functionWidth = compact ? available.x : paneContentWidth * firstPaneSplit_;
    const float middleWidth = compact ? available.x : paneContentWidth * (secondPaneSplit_ - firstPaneSplit_);
    const float pathWidth = compact ? available.x : paneContentWidth - functionWidth - middleWidth;
    const bool haveCpuWeights = report.totalCpuCycles != 0;

    if (!compact || compactReportView_ == 0) {
        ImGui::SetCursorPos(paneStart);
        ImGui::BeginChild("pr_funcs", ImVec2(functionWidth, available.y), ImGuiChildFlags_None);
        ImGui::SeparatorText(haveCpuWeights ? "CPU-weighted functions" : "Sampled leaf functions");
        if (ImGui::BeginTable("pr_ftbl", 3,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn(haveCpuWeights ? "CPU" : "Leaf",
                                    ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
            ImGui::TableSetupColumn(haveCpuWeights ? "Incl" : "Stack",
                                    ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
            ImGui::TableSetupColumn("Function");
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            for (const PrismFuncStat& function : report.functions) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                const float leafPct = haveCpuWeights ? function.cpuSelfPct : function.selfPct;
                const float inclusivePct = haveCpuWeights ? function.cpuInclusivePct : function.inclusivePct;
                const ImVec4 color = leafPct > 20.0f ? theme::col::bad()
                                   : leafPct > 5.0f ? theme::col::warn()
                                                    : ImGui::GetStyleColorVec4(ImGuiCol_Text);
                ImGui::TextColored(color, "%.0f%%", leafPct);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%.0f%%", inclusivePct);
                ImGui::TableSetColumnIndex(2);
                ImGui::PushID(reinterpret_cast<void*>(static_cast<uintptr_t>(function.address)));
                ImGui::BeginDisabled(!canNavigate || !function.address);
                if (ImGui::Selectable(function.symbol.c_str(), false,
                                      ImGuiSelectableFlags_SpanAllColumns) && function.address)
                    navigateAddress(ctx, sampler_.pid(), sampledCreationTime,
                                    function.address, navigationSnapshot,
                                    ImGui::GetIO().KeyShift);
                ImGui::EndDisabled();
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
                    if (!canNavigate)
                        ImGui::SetTooltip("%s\nAttach the Win32 debugger to the exact sampled process (PID %u) to navigate.",
                                          function.symbol.c_str(), sampler_.pid());
                    else
                        ImGui::SetTooltip("%s\n0x%llX\nClick: open code. Shift-click: open live code.",
                                          function.symbol.c_str(), static_cast<unsigned long long>(function.address));
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();
    }

    if (!compact) {
        drawVerticalSplitter("##prism_split_functions",
                             ImVec2(paneStart.x + functionWidth, paneStart.y),
                             available.y, splitter, paneContentWidth, firstPaneSplit_,
                             minRatio, std::max(minRatio, secondPaneSplit_ - minRatio));
        ImGui::SetCursorPos(ImVec2(paneStart.x + functionWidth + splitter, paneStart.y));
    } else if (compactReportView_ == 1) ImGui::SetCursorPos(paneStart);
    if (!compact || compactReportView_ == 1) {
        ImGui::BeginChild("pr_mid", ImVec2(middleWidth, available.y), ImGuiChildFlags_None);
        float halfHeight = ImGui::GetContentRegionAvail().y * 0.5f - 24.0f * scale;
        halfHeight = std::max(60.0f * scale, halfHeight);
        ImGui::SeparatorText("Threads");
        if (ImGui::BeginTable("pr_thr", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                         ImGuiTableFlags_Resizable,
                              ImVec2(0, halfHeight))) {
            ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 52.0f * scale);
            ImGui::TableSetupColumn("State");
            ImGui::TableSetupColumn("Obs", ImGuiTableColumnFlags_WidthFixed, 36.0f * scale);
            ImGui::TableSetupColumn("CPU", ImGuiTableColumnFlags_WidthFixed, 36.0f * scale);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            for (const PrismThreadStat& thread : report.threads) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%u", thread.threadId);
                if (ImGui::IsItemHovered() && !thread.topSymbol.empty())
                    ImGui::SetTooltip("hottest: %s", thread.topSymbol.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(stateColor(thread.dominant), "%s", ThreadStateName(thread.dominant));
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%.0f", thread.dominantPct);
                ImGui::TableSetColumnIndex(3);
                if (haveCpuWeights) ImGui::TextDisabled("%.0f", thread.cpuPct);
                else ImGui::TextDisabled("--");
            }
            ImGui::EndTable();
        }
        ImGui::Spacing();
        ImGui::SeparatorText("Modules");
        if (ImGui::BeginTable("pr_mod", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                         ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Module");
            ImGui::TableSetupColumn(haveCpuWeights ? "CPU" : "Leaf",
                                    ImGuiTableColumnFlags_WidthFixed, 46.0f * scale);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            int shown = 0;
            for (const PrismModuleStat& module : report.modules) {
                if (shown++ >= 20) break;
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(module.module.c_str());
                ui::ItemTooltip(module.module.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%.0f%%", haveCpuWeights ? module.cpuPct : module.selfPct);
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();
    }

    if (!compact) {
        drawVerticalSplitter("##prism_split_details",
                             ImVec2(paneStart.x + functionWidth + splitter + middleWidth,
                                    paneStart.y),
                             available.y, splitter, paneContentWidth, secondPaneSplit_,
                             firstPaneSplit_ + minRatio,
                             std::max(firstPaneSplit_ + minRatio, 1.0f - minRatio));
        ImGui::SetCursorPos(ImVec2(paneStart.x + functionWidth + splitter + middleWidth + splitter,
                                   paneStart.y));
    } else if (compactReportView_ == 2) ImGui::SetCursorPos(paneStart);
    if (!compact || compactReportView_ == 2) {
        ImGui::BeginChild("pr_paths", ImVec2(pathWidth, available.y), ImGuiChildFlags_None,
                           ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::SeparatorText("Hot call paths");
        for (size_t i = 0; i < report.hotPaths.size(); ++i) {
            const PrismHotPath& path = report.hotPaths[i];
            char header[72];
            std::snprintf(header, sizeof(header), "%.0f%%  (%d samples)###hp%zu",
                          path.pct, path.samples, i);
            if (ImGui::TreeNodeEx(header, i == 0 ? ImGuiTreeNodeFlags_DefaultOpen : 0)) {
                ui::PushMono();
                for (size_t frame = 0; frame < path.frames.size(); ++frame)
                    ImGui::Text("%*s%s", static_cast<int>(frame * 2), "", path.frames[frame].c_str());
                ui::PopMono();
                ImGui::TreePop();
            }
        }
        ImGui::EndChild();
    }
}

} // namespace ds
