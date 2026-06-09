#include "ProjectsTab.h"
#include "imgui.h"

#include <ctime>

namespace ds {

void ProjectsTab::refresh() {
    recents_ = LoadRecents();
    loaded_  = true;
}

static const char* baseName(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p.c_str() : p.c_str() + s + 1;
}

static std::string whenStr(int64_t unix) {
    if (!unix) return "-";
    std::time_t t = (std::time_t)unix;
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char b[32]; std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M", &tmv);
    return b;
}

void ProjectsTab::render(AppContext& ctx) {
    // Re-read the index on first paint and whenever the active project changes
    // (so a newly opened/saved target appears without a manual refresh).
    if (!loaded_ || lastSeenHash_ != ctx.project.hash) { refresh(); lastSeenHash_ = ctx.project.hash; }

    ImGui::TextDisabled("Recent analysis projects (persisted as JSON sidecars keyed by binary hash).");
    if (ImGui::Button("Open Binary...")) { if (ctx.openBinaryDialog()) ctx.requestedTab = "Binary View"; }
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) refresh();
    ImGui::SameLine();
    ImGui::TextDisabled("Use File > Open as Raw... for shellcode/firmware.");
    if (!openError_.empty()) ImGui::TextColored(ImVec4(0.9f, 0.4f, 0.4f, 1), "%s", openError_.c_str());
    ImGui::Separator();

    // Left: recent project list. Right: details.
    ImGui::BeginChild("proj_list", ImVec2(420, 0), ImGuiChildFlags_Borders);
    if (ImGui::BeginTable("projects", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Arch",   ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Opened", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableHeadersRow();
        int removeAt = -1;
        for (int i = 0; i < (int)recents_.size(); ++i) {
            const auto& r = recents_[i];
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0);
            const char* disp = r.name.empty() ? baseName(r.path) : r.name.c_str();
            if (ImGui::Selectable(disp, selected_ == i, ImGuiSelectableFlags_SpanAllColumns)) selected_ = i;
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                openError_ = ctx.loadBinaryPath(r.path) ? "" : ("Could not open " + r.path);
                if (openError_.empty()) ctx.requestedTab = "Binary View";
            }
            if (ImGui::BeginPopupContextItem("pctx")) {
                if (ImGui::MenuItem("Open")) {
                    openError_ = ctx.loadBinaryPath(r.path) ? "" : ("Could not open " + r.path);
                    if (openError_.empty()) ctx.requestedTab = "Binary View";
                }
                if (ImGui::MenuItem("Copy path")) ImGui::SetClipboardText(r.path.c_str());
                if (ImGui::MenuItem("Remove from list")) removeAt = i;
                ImGui::EndPopup();
            }
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(r.arch.empty() ? "-" : r.arch.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", whenStr(r.lastOpenedUnix).c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
        if (removeAt >= 0) { RemoveRecent(recents_[removeAt].hash); refresh(); selected_ = -1; }
    }
    if (recents_.empty()) ImGui::TextDisabled("No recent projects yet. Open a binary to start one.");
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("proj_detail", ImVec2(0, 0), ImGuiChildFlags_Borders);

    ImGui::SeparatorText("Selected");
    if (selected_ >= 0 && selected_ < (int)recents_.size()) {
        const auto& r = recents_[selected_];
        ImGui::Text("Name: %s", r.name.empty() ? baseName(r.path) : r.name.c_str());
        ImGui::TextWrapped("Path: %s", r.path.c_str());
        ImGui::Text("Arch: %s", r.arch.c_str());
        ImGui::Text("Hash: %016llX", (unsigned long long)r.hash);
        ImGui::Text("Last opened: %s", whenStr(r.lastOpenedUnix).c_str());
        if (ImGui::Button("Open this project")) {
            openError_ = ctx.loadBinaryPath(r.path) ? "" : ("Could not open " + r.path);
            if (openError_.empty()) ctx.requestedTab = "Binary View";
        }
    } else {
        ImGui::TextDisabled("Select a project (double-click to open).");
    }

    ImGui::SeparatorText("Loaded Binary");
    if (ctx.binary.loaded()) {
        ImGui::Text("Path: %s", ctx.binary.path().c_str());
        ImGui::Text("Format: %s", ctx.binary.formatName());
        ImGui::Text("Image base: 0x%llX", (unsigned long long)ctx.binary.imageBase());
        ImGui::Text("Entry point: 0x%llX",
                    (unsigned long long)(ctx.binary.imageBase() + ctx.binary.entryPoint()));
        ImGui::Text("Sections: %d", (int)ctx.binary.sections().size());
        ImGui::Separator();
        const ProjectState& p = ctx.project;
        ImGui::TextDisabled("Saved analysis:");
        ImGui::BulletText("%d comment(s), %d rename(s)", (int)p.comments.size(), (int)p.names.size());
        ImGui::BulletText("%d bookmark(s), %d breakpoint(s)", (int)p.bookmarks.size(), (int)p.breakpoints.size());
        ImGui::BulletText("%d patch(es)", (int)p.patches.size());
        if (ImGui::Button("Save project now")) ctx.saveProject();
        ImGui::SameLine();
        ImGui::TextDisabled("(auto-saved on close / exit)");
    } else {
        ImGui::TextDisabled("No binary loaded. Use Open Binary, or double-click a recent project.");
    }
    ImGui::EndChild();
}

} // namespace ds
