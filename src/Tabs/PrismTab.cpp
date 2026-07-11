#include "PrismTab.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"

#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <limits>

namespace ds {

namespace {
// A theme color for each thread state (state bars + verdict tint).
ImVec4 stateColor(ThreadState s) {
    switch (s) {
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
    unsigned long long v = std::strtoull(text, &end, 10);
    if (errno || end == text || *end || v == 0 ||
        v > (unsigned long long)(std::numeric_limits<uint32_t>::max)())
        return false;
    pid = (uint32_t)v;
    return true;
}
} // namespace

void PrismTab::rebuild() {
    const uint64_t generation = sampler_.sampleGeneration();
    rep_ = BuildPrismReport(sampler_.snapshot());
    builtGeneration_ = generation;
}

void PrismTab::render(AppContext& ctx) {
    const float scale = theme::UiScale();

    // ---- Toolbar: PID + Start/Stop ----
    bool running = sampler_.running();
    if (running) {
        if (ui::ToolbarIconButton(DS_ICON_STOP, "Stop", "Stop sampling")) {
            sampler_.stop();
            rebuild();
            running = false;
        }
    } else {
        if (ui::ToolbarIconButton(DS_ICON_PLAY, "Start", "Start sampling the target process")) {
            uint32_t pid = 0;
            if (parsePid(pidBuf_, pid)) {
                shownError_.clear();
                std::string err;
                if (!sampler_.start(pid, err))
                    ui::Toast(ui::ToastKind::Error, "Prism: " + err);
                else {
                    ui::Toast(ui::ToastKind::Info, "Prism: sampling pid " + std::to_string(pid));
                    running = sampler_.running();
                    lastBuild_ = 0.0;
                    ctx.wantContinuousRedraw = true;
                    rebuild();
                }
            } else {
                ui::Toast(ui::ToastKind::Warn, "Enter a process ID first");
            }
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110.0f * scale);
    ImGui::InputTextWithHint("##prism_pid", "pid (e.g. 4312)", pidBuf_, sizeof(pidBuf_),
                             ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    ImGui::Checkbox("Auto-refresh", &autoRefresh_);
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) rebuild();
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) { sampler_.clearSamples(); rebuild(); }
    ImGui::SameLine();
    ImGui::TextDisabled("%zu observations%s", sampler_.sampleCount(),
                        sampler_.sampleCount() >= PrismSampler::kMaxSamples ? " (rolling window)" : "");
    ImGui::Separator();

    std::string asyncError = sampler_.lastError();
    if (!asyncError.empty() && asyncError != shownError_) {
        shownError_ = asyncError;
        ui::Toast(ui::ToastKind::Error, "Prism: " + asyncError);
    }

    // While sampling, keep the UI live and refresh the report on a throttle.
    if (running) {
        ctx.wantContinuousRedraw = true;
        double now = ImGui::GetTime();
        if (autoRefresh_ && now - lastBuild_ > 0.75) { rebuild(); lastBuild_ = now; }
    } else if (sampler_.sampleGeneration() != builtGeneration_) {
        // The target may exit without a Stop click. Publish its final rolling window.
        rebuild();
    }

    if (rep_.totalSamples == 0) {
        ui::EmptyState(DS_ICON_LIGHTNING, "No samples yet",
                       "Enter a running process's PID and press Start. Prism suspends each thread briefly, "
                       "walks its stack, separates thread-state occupancy from cycle-weighted CPU hotspots, "
                       "and keeps a bounded rolling window. (x64 targets; find PIDs in Communications.)",
                       nullptr);
        return;
    }

    // ---- Verdict ----
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextColored(theme::col::accent(), "%s", rep_.headline.c_str());
    ImGui::TextWrapped("%s", rep_.verdict.c_str());
    ImGui::PopTextWrapPos();
    ImGui::Separator();

    // ---- Activity over time (one cell per time slice, colored by dominant state) ----
    if (!rep_.timeline.empty()) {
        ImGui::TextColored(theme::col::muted(), "ACTIVITY OVER TIME  (%.1fs — dominant state per slice)",
                           rep_.spanMs / 1000.0f);
        ImVec2 p0 = ImGui::GetCursorScreenPos();
        float w  = ImGui::GetContentRegionAvail().x;
        float h  = 16.0f * scale;
        float cw = w / (float)rep_.timeline.size();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        for (size_t i = 0; i < rep_.timeline.size(); ++i) {
            ImU32 col = ImGui::ColorConvertFloat4ToU32(stateColor(rep_.timeline[i].dominant));
            ImVec2 a(p0.x + (float)i * cw, p0.y);
            ImVec2 b(p0.x + (float)(i + 1) * cw - 1.0f, p0.y + h);
            dl->AddRectFilled(a, b, col);
        }
        ImGui::Dummy(ImVec2(w, h));
        ImGui::Separator();
    }

    // ---- Thread-state breakdown (bars) ----
    ImGui::TextColored(theme::col::muted(), "THREAD-STATE OBSERVATIONS  (not CPU time)");
    for (const PrismStateStat& st : rep_.states) {
        ImVec4 c = stateColor(st.state);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, c);
        char overlay[64];
        std::snprintf(overlay, sizeof(overlay), "%s  %.0f%%  (%d)", ThreadStateName(st.state), st.pct, st.samples);
        ImGui::ProgressBar(st.pct / 100.0f, ImVec2(-1, 0), overlay);
        ImGui::PopStyleColor();
    }
    ImGui::Separator();

    // ---- Hot functions | threads + modules | hot paths ----
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float fnW  = avail.x * 0.40f;
    float midW = avail.x * 0.30f;

    ImGui::BeginChild("pr_funcs", ImVec2(fnW, 0), ImGuiChildFlags_Borders);
    const bool haveCpuWeights = rep_.totalCpuCycles != 0;
    ImGui::TextColored(theme::col::muted(), haveCpuWeights ? "CPU-WEIGHTED FUNCTIONS" : "SAMPLED LEAF FUNCTIONS");
    if (ImGui::BeginTable("pr_ftbl", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn(haveCpuWeights ? "CPU" : "Leaf", ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
        ImGui::TableSetupColumn(haveCpuWeights ? "Incl" : "Stack", ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
        ImGui::TableSetupColumn("Function");
        ImGui::TableHeadersRow();
        DbgSnapshot navSnap = ctx.debug.snapshot();
        const bool canNavigate = navSnap.attached() && navSnap.pid == sampler_.pid();
        for (const PrismFuncStat& f : rep_.functions) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            const float leafPct = haveCpuWeights ? f.cpuSelfPct : f.selfPct;
            const float inclPct = haveCpuWeights ? f.cpuInclusivePct : f.inclusivePct;
            ImVec4 col = leafPct > 20.0f ? theme::col::bad()
                       : leafPct > 5.0f  ? theme::col::warn() : ImGui::GetStyleColorVec4(ImGuiCol_Text);
            ImGui::TextColored(col, "%.0f%%", leafPct);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%.0f%%", inclPct);
            ImGui::TableSetColumnIndex(2);
            ImGui::PushID((void*)(uintptr_t)f.address);
            ImGui::BeginDisabled(!canNavigate || !f.address);
            if (ImGui::Selectable(f.symbol.c_str(), false, ImGuiSelectableFlags_SpanAllColumns) && f.address)
                ctx.gotoAddressLive(f.address);   // runtime (ASLR) address -> live view
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && !canNavigate)
                ImGui::SetTooltip("Attach the Win32 debugger to sampled PID %u to navigate this runtime address.", sampler_.pid());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    // Middle column: per-thread breakdown (top) + per-module self-time (bottom).
    ImGui::SameLine();
    ImGui::BeginChild("pr_mid", ImVec2(midW, 0), ImGuiChildFlags_Borders);
    float halfY = ImGui::GetContentRegionAvail().y * 0.5f - 24.0f * scale;
    if (halfY < 60.0f * scale) halfY = 60.0f * scale;
    ImGui::TextColored(theme::col::muted(), "THREADS");
    if (ImGui::BeginTable("pr_thr", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, halfY))) {
        ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 52.0f * scale);
        ImGui::TableSetupColumn("State");
        ImGui::TableSetupColumn("Obs", ImGuiTableColumnFlags_WidthFixed, 36.0f * scale);
        ImGui::TableSetupColumn("CPU", ImGuiTableColumnFlags_WidthFixed, 36.0f * scale);
        ImGui::TableHeadersRow();
        for (const PrismThreadStat& t : rep_.threads) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char tl[24]; std::snprintf(tl, sizeof(tl), "%u##thr%u", t.threadId, t.threadId);
            ImGui::Selectable(tl, false, ImGuiSelectableFlags_SpanAllColumns);
            if (ImGui::IsItemHovered() && !t.topSymbol.empty()) ImGui::SetTooltip("hottest: %s", t.topSymbol.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(stateColor(t.dominant), "%s", ThreadStateName(t.dominant));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextDisabled("%.0f", t.dominantPct);
            ImGui::TableSetColumnIndex(3);
            if (haveCpuWeights) ImGui::TextDisabled("%.0f", t.cpuPct);
            else                ImGui::TextDisabled("--");
        }
        ImGui::EndTable();
    }
    ImGui::Spacing();
    ImGui::TextColored(theme::col::muted(), "MODULES");
    if (ImGui::BeginTable("pr_mod", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Module");
        ImGui::TableSetupColumn(haveCpuWeights ? "CPU" : "Leaf", ImGuiTableColumnFlags_WidthFixed, 46.0f * scale);
        ImGui::TableHeadersRow();
        int shown = 0;
        for (const PrismModuleStat& m : rep_.modules) {
            if (shown++ >= 20) break;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(m.module.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%.0f%%", haveCpuWeights ? m.cpuPct : m.selfPct);
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("pr_paths", ImVec2(0, 0), ImGuiChildFlags_Borders);
    ImGui::TextColored(theme::col::muted(), "HOT CALL PATHS  (observation frequency)");
    for (size_t i = 0; i < rep_.hotPaths.size(); ++i) {
        const PrismHotPath& hp = rep_.hotPaths[i];
        char hdr[64]; std::snprintf(hdr, sizeof(hdr), "%.0f%%  (%d samples)###hp%zu", hp.pct, hp.samples, i);
        if (ImGui::TreeNodeEx(hdr, i == 0 ? ImGuiTreeNodeFlags_DefaultOpen : 0)) {
            ui::PushMono();
            for (size_t k = 0; k < hp.frames.size(); ++k)
                ImGui::Text("%*s%s", (int)(k * 2), "", hp.frames[k].c_str());
            ui::PopMono();
            ImGui::TreePop();
        }
    }
    ImGui::EndChild();
}

} // namespace ds
