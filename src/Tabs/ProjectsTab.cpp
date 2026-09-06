#include "ProjectsTab.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "../Ui/Splitter.h"
#include "imgui.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <string_view>

namespace ds {

void ProjectsTab::refresh() {
    recents_ = LoadRecents();
    loaded_  = true;
    if (selectedHashValid_) {
        const auto selected = std::find_if(recents_.begin(), recents_.end(), [&](const RecentEntry& r) {
            return r.hash == selectedHash_;
        });
        if (selected == recents_.end()) selectedHashValid_ = false;
    }
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

static bool containsInsensitive(std::string_view text, std::string_view needle) {
    if (needle.empty()) return true;
    return std::search(text.begin(), text.end(), needle.begin(), needle.end(),
                       [](char a, char b) {
                           return std::tolower(static_cast<unsigned char>(a)) ==
                                  std::tolower(static_cast<unsigned char>(b));
                       }) != text.end();
}

static bool recentMatches(const RecentEntry& recent, std::string_view needle) {
    const char* display = recent.name.empty() ? baseName(recent.path) : recent.name.c_str();
    return containsInsensitive(display, needle) ||
           containsInsensitive(recent.path, needle) ||
           containsInsensitive(recent.arch, needle) ||
           containsInsensitive(recent.status, needle);
}

static int recentIndexForHash(const std::vector<RecentEntry>& recents, uint64_t hash) {
    for (int i = 0; i < static_cast<int>(recents.size()); ++i)
        if (recents[i].hash == hash) return i;
    return -1;
}

void ProjectsTab::render(AppContext& ctx) {
    // Re-read the index on first paint and whenever the active project changes
    // (so a newly opened/saved target appears without a manual refresh).
    const bool binaryLoaded = ctx.staticBinary().loaded();
    const uint64_t activeHash = ctx.staticProject().hash;
    const bool activeChanged = lastSeenHash_ != activeHash ||
                               lastSeenBinaryLoaded_ != binaryLoaded;
    if (!loaded_ || activeChanged) {
        refresh();
        if (binaryLoaded && recentIndexForHash(recents_, activeHash) >= 0) {
            selectedHash_ = activeHash;
            selectedHashValid_ = true;
        }
        lastSeenHash_ = activeHash;
        lastSeenBinaryLoaded_ = binaryLoaded;
    }

    auto openRecent = [&](const RecentEntry& recent) {
        selectedHash_ = recent.hash;
        selectedHashValid_ = true;
        if (ctx.beginBinaryLoadPath(recent.path)) {
            openError_.clear();
            ctx.requestedTab = "Binary View";
        } else {
            openError_ = ctx.documentCommandError().empty()
                ? "Could not start opening " + recent.path
                : ctx.documentCommandError();
        }
    };

    if (ui::ToolbarIconButton(DS_ICON_FOLDER, "Open Binary...", "Pick a binary to analyze (Ctrl+O)")) {
        if (ctx.openBinaryDialog()) ctx.requestedTab = "Binary View";
    }
    ImGui::SameLine();
    if (ui::ToolbarIconButton(DS_ICON_REFRESH, "Refresh", "Re-read the recent projects index")) {
        refresh();
        if (!selectedHashValid_ && binaryLoaded && recentIndexForHash(recents_, activeHash) >= 0) {
            selectedHash_ = activeHash;
            selectedHashValid_ = true;
        }
    }
    ImGui::SameLine();
    const char* toolbarHelp = "Recent analysis projects auto-save as JSON sidecars. "
                              "Use File > Open as Raw... for shellcode/firmware.";
    const char* compactHelp = ui::IconsLoaded() ? DS_ICON_INFO : "Info";
    const float toolbarRemaining = ImGui::GetContentRegionAvail().x;
    if (toolbarRemaining >= ImGui::CalcTextSize(toolbarHelp).x)
        ImGui::TextDisabled("%s", toolbarHelp);
    else if (toolbarRemaining >= ImGui::CalcTextSize(compactHelp).x)
        ImGui::TextDisabled("%s", compactHelp);
    else {
        ImGui::NewLine();
        ImGui::TextDisabled("%s", compactHelp);
    }
    ui::ItemTooltip(toolbarHelp, false);
    if (!openError_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::col::bad());
        ImGui::TextWrapped("%s", openError_.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::Separator();

    // Resizable master/detail workbench. The old fixed 420 px card wasted space
    // on small windows and could not take advantage of larger displays.
    const float scale = theme::UiScale();
    if (listWidth_ <= 0.0f) listWidth_ = 360.0f * scale;
    const ImVec2 panelSpace = ImGui::GetContentRegionAvail();
    const bool stacked = panelSpace.x < 620.0f * scale;
    if (!stacked)
        listWidth_ = std::clamp(listWidth_, 240.0f * scale,
                                panelSpace.x - 305.0f * scale);
    const float listHeight = stacked
        ? std::max(1.0f, std::min(260.0f * scale, panelSpace.y * 0.46f))
        : 0.0f;
    ImGui::BeginChild("proj_list", ImVec2(stacked ? 0.0f : listWidth_, listHeight),
                      ImGuiChildFlags_Borders);
    ImGui::SetNextItemWidth(-1.0f);
    ui::SearchBox("##project_filter", "Search recent projects...", filter_, sizeof(filter_));
    std::vector<int> visibleRecents;
    visibleRecents.reserve(recents_.size());
    const std::string_view filter(filter_);
    for (int i = 0; i < static_cast<int>(recents_.size()); ++i)
        if (recentMatches(recents_[i], filter)) visibleRecents.push_back(i);
    ImGui::TextDisabled("Showing %zu of %zu", visibleRecents.size(), recents_.size());
    ImGui::Separator();
    if (recents_.empty()) {
        // First run / cleared index: a hero card instead of an empty table.
        if (ui::EmptyState(DS_ICON_FOLDER, "No recent projects",
                           "Open a binary to start an analysis project - it saves automatically.",
                           "Open Binary...")) {
            if (ctx.openBinaryDialog()) ctx.requestedTab = "Binary View";
        }
    } else if (visibleRecents.empty()) {
        ui::EmptyState(DS_ICON_SEARCH, "No matching projects",
                       "Try a different name, path, architecture, or status.");
    } else if (ImGui::BeginTable("projects", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Arch",   ImGuiTableColumnFlags_WidthFixed, 50.0f * scale);
        ImGui::TableSetupColumn("Opened", ImGuiTableColumnFlags_WidthFixed, 120.0f * scale);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        int removeAt = -1;
        for (int i : visibleRecents) {
            const auto& r = recents_[i];
            const bool active = binaryLoaded && r.hash == activeHash;
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0);
            const char* disp = r.name.empty() ? baseName(r.path) : r.name.c_str();
            std::string rowLabel;
            if (active) rowLabel = ui::IconsLoaded() ? DS_ICON_CHECK " Active  " : "Active  ";
            rowLabel += disp;
            if (active) ImGui::PushStyleColor(ImGuiCol_Text, theme::col::good());
            if (ImGui::Selectable(rowLabel.c_str(), selectedHashValid_ && selectedHash_ == r.hash,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                selectedHash_ = r.hash;
                selectedHashValid_ = true;
            }
            if (active) ImGui::PopStyleColor();
            const bool rowHovered = ImGui::IsItemHovered();
            ui::ItemTooltip(r.path.c_str(), false);
            if ((rowHovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) ||
                (ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter))) {
                openRecent(r);
            }
            if (ImGui::BeginPopupContextItem("pctx")) {
                if (ImGui::MenuItem("Open")) {
                    openRecent(r);
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
        if (removeAt >= 0) {
            RemoveRecent(recents_[removeAt].hash);
            refresh();
        }
    }
    ImGui::EndChild();

    if (!stacked)
        ui::VSplitter("##projects_split", &listWidth_, 240.0f * scale,
                      300.0f * scale, 5.0f * scale);
    ImGui::BeginChild("proj_detail", ImVec2(0, 0), ImGuiChildFlags_Borders);

    ImGui::SeparatorText("Selected");
    const int selectedIndex = selectedHashValid_ ? recentIndexForHash(recents_, selectedHash_) : -1;
    if (selectedIndex >= 0) {
        const auto& r = recents_[selectedIndex];
        if (binaryLoaded && r.hash == activeHash) {
            ui::Badge("ACTIVE", theme::col::good());
            ImGui::SameLine();
            ImGui::TextDisabled("Currently loaded");
        }
        ui::KeyValueRow("Name", "%s", r.name.empty() ? baseName(r.path) : r.name.c_str());
        ui::KeyValueRow("Path", "%s", r.path.c_str());
        ui::ItemTooltip(r.path.c_str(), false);
        ui::KeyValueRow("Arch", "%s", r.arch.empty() ? "-" : r.arch.c_str());
        ui::KeyValueRow("Hash", "%016llX", (unsigned long long)r.hash);
        ui::KeyValueRow("Last opened", "%s", whenStr(r.lastOpenedUnix).c_str());
        if (ImGui::Button("Open this project")) {
            openRecent(r);
        }
    } else {
        ImGui::TextDisabled("Select a project (double-click to open).");
    }

    ImGui::SeparatorText("Loaded Binary");
    if (ctx.staticBinary().loaded()) {
        ui::KeyValueRow("Path", "%s", ctx.staticBinary().path().c_str());
        ui::ItemTooltip(ctx.staticBinary().path().c_str(), false);
        ui::KeyValueRow("Format", "%s", ctx.staticBinary().formatName());
        ui::KeyValueRow("Image base", "0x%llX",
                        (unsigned long long)ctx.staticBinary().imageBase());
        if (ctx.staticBinary().hasEntryPoint())
            ui::KeyValueRow("Entry point", "0x%llX",
                            (unsigned long long)ctx.staticBinary().entryPointVA());
        else
            ui::KeyValueRow("Entry point", "%s", "not specified");
        ui::KeyValueRow("Sections", "%d", (int)ctx.staticBinary().sections().size());
        if (ctx.staticFirmwareInfo().detected()) {
            ui::KeyValueRow("Firmware", "%s (%s confidence)",
                            FirmwareKindName(ctx.staticFirmwareInfo().primaryKind),
                            FirmwareConfidenceName(ctx.staticFirmwareInfo().confidence));
            if (!ctx.staticFirmwareInfo().entry.evidence.empty())
                ui::KeyValueRow("Boot recovery", "%s", ctx.staticFirmwareInfo().entry.evidence.c_str());
        }
        if (ctx.staticRuntimeInfo().wrapperLikely)
            ui::KeyValueRow("Runtime", "%s \xE2\x80\x94 wrapper, %.0f%%",
                            ctx.staticRuntimeInfo().wrapperRuntime.c_str(),
                            ctx.staticRuntimeInfo().wrapperConfidence * 100.0f);
        else if (ctx.staticRuntimeInfo().isStandaloneArchive)
            ui::KeyValueRow("Runtime", "ZIP/JAR archive \xE2\x80\x94 %zu entries",
                            ctx.staticJavaInfo().entries.size());
        ImGui::Separator();
        const ProjectState& p = ctx.staticProject();
        ImGui::TextDisabled("Project annotations:");
        ImGui::BulletText("%d comment(s), %d rename(s)", (int)p.comments.size(), (int)p.names.size());
        ImGui::BulletText("%d bookmark(s), %d breakpoint(s)", (int)p.bookmarks.size(), (int)p.breakpoints.size());
        ImGui::BulletText("%d patch(es)", (int)p.patches.size());
        if (ctx.staticBinary().isMappedImage()) {
            ImGui::TextWrapped("Live module annotations are kept for this session. "
                               "Use File > Export Analysis to keep a report.");
        } else {
            const bool saving = ctx.projectSaveState == AppContext::ProjectSaveState::Saving;
            ImGui::BeginDisabled(saving);
            if (ImGui::Button(saving ? "Saving project..." : "Save project now")) {
                if (!ctx.beginProjectSave())
                    ui::Toast(ui::ToastKind::Error, ctx.projectSaveError);
                else if (ctx.projectSaveState == AppContext::ProjectSaveState::Saving)
                    ui::Toast(ui::ToastKind::Info, "Project save queued.");
                else
                    ui::Toast(ui::ToastKind::Success, "Project is already saved.");
            }
            ImGui::EndDisabled();
            ImGui::TextDisabled("Autosaves after edits, on close, and on exit.");
        }
    } else {
        ImGui::TextDisabled("No binary loaded. Use Open Binary, or double-click a recent project.");
    }
    ImGui::EndChild();
}

} // namespace ds
