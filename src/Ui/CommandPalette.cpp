#include "CommandPalette.h"
#include "../App.h"
#include "../Core/Fuzzy.h"
#include "Fonts.h"
#include "Icons.h"
#include "Theme.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cstdio>
#include <cstring>

namespace ds::ui {

void CommandPalette::open(std::vector<PaletteItem> actions, std::vector<PaletteSymbol> symbols) {
    actions_ = std::move(actions);
    symbols_ = std::move(symbols);
    actionLower_.clear();
    actionLower_.reserve(actions_.size());
    for (const auto& a : actions_) {
        std::string l = a.label;
        for (char& c : l) c = (char)std::tolower((unsigned char)c);
        actionLower_.push_back(std::move(l));
    }
    query_[0]  = 0;
    lastQuery_ = "\x01";   // force a rebuild on the first frame
    sel_       = 0;
    open_      = true;
    focusNext_ = true;
}

void CommandPalette::close() {
    open_ = false;
    actions_.clear(); actionLower_.clear(); symbols_.clear(); results_.clear();
}

// Query -> scored result list. Empty query lists the actions in their given
// order (a menu); symbols only join in once the user types something.
void CommandPalette::rebuildResults() {
    results_.clear();
    std::string q = query_;
    for (char& c : q) c = (char)std::tolower((unsigned char)c);

    // A bare hex value (optional 0x) becomes a "go to address" entry on top.
    {
        std::string h = q;
        if (h.rfind("0x", 0) == 0) h = h.substr(2);
        bool hex = !h.empty() && h.size() <= 16;
        for (char c : h) if (!std::isxdigit((unsigned char)c)) { hex = false; break; }
        if (hex) {
            unsigned long long va = 0;
            std::sscanf(h.c_str(), "%llx", &va);
            results_.push_back({ 1 << 20, 2, 0, (uint64_t)va, false });
        }
    }

    if (q.empty()) {
        for (int i = 0; i < (int)actions_.size(); ++i) results_.push_back({ 0, 0, i, 0, false });
    } else {
        for (int i = 0; i < (int)actions_.size(); ++i) {
            int s = FuzzyScore(q.c_str(), actionLower_[i].c_str());
            if (s >= 0) results_.push_back({ s + 4, 0, i, 0, false }); // small action bias over symbols
        }
        for (int i = 0; i < (int)symbols_.size(); ++i) {
            int s = FuzzyScore(q.c_str(), symbols_[i].lower.c_str());
            if (s >= 0) results_.push_back({ s, 1, i, symbols_[i].addr, symbols_[i].live });
        }
        std::stable_sort(results_.begin(), results_.end(),
                         [](const Result& a, const Result& b) { return a.score > b.score; });
    }
    const size_t kMaxShown = 50;
    if (results_.size() > kMaxShown) results_.resize(kMaxShown);
    if (sel_ >= (int)results_.size()) sel_ = results_.empty() ? 0 : (int)results_.size() - 1;
    if (sel_ < 0) sel_ = 0;
}

void CommandPalette::render(AppContext& ctx) {
    if (!open_) return;
    const float s = theme::UiScale();
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float w = 560.0f * s;
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x * 0.5f,
                                   vp->WorkPos.y + vp->WorkSize.y * 0.16f),
                            ImGuiCond_Always, ImVec2(0.5f, 0.0f));
    ImGui::SetNextWindowSize(ImVec2(w, 0));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                             ImGuiWindowFlags_NoCollapse;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.0f * s);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    if (focusNext_) ImGui::SetNextWindowFocus();   // raise over the main window on open
    if (!ImGui::Begin("##cmdpalette", nullptr, flags)) {
        ImGui::End();
        ImGui::PopStyleVar(2);
        return;
    }

    // Query box, focused on open.
    if (focusNext_) { ImGui::SetKeyboardFocusHere(); focusNext_ = false; }
    ImGui::SetNextItemWidth(-FLT_MIN);
    bool enter = ImGui::InputTextWithHint("##palq", "Type a command, symbol, or 0x address...",
                                          query_, sizeof(query_),
                                          ImGuiInputTextFlags_EnterReturnsTrue);
    if (lastQuery_ != query_) { lastQuery_ = query_; rebuildResults(); }

    // Keyboard: arrows move the selection (single-line InputText ignores them).
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && sel_ + 1 < (int)results_.size()) { ++sel_; selMoved_ = true; }
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)   && sel_ > 0)                        { --sel_; selMoved_ = true; }

    int runIdx = -1;
    if ((enter || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter)) && !results_.empty())
        runIdx = sel_;

    // Result list.
    const float listH = 340.0f * s;
    ImGui::BeginChild("##palresults", ImVec2(0, listH), ImGuiChildFlags_None);
    const ImVec4 acc = theme::col::accent();
    for (int i = 0; i < (int)results_.size(); ++i) {
        const Result& r = results_[i];
        char label[320];
        const char* icon = nullptr;
        const char* detail = nullptr;
        char detailBuf[48];
        if (r.kind == 2) {
            std::snprintf(label, sizeof(label), "Go to address 0x%llX", (unsigned long long)r.va);
            icon = DS_ICON_CODE; detail = "address";
        } else if (r.kind == 1) {
            const PaletteSymbol& sym = symbols_[(size_t)r.idx];
            std::snprintf(label, sizeof(label), "%s", sym.name.c_str());
            std::snprintf(detailBuf, sizeof(detailBuf), "0x%llX", (unsigned long long)sym.addr);
            icon = DS_ICON_CODE; detail = detailBuf;
        } else {
            const PaletteItem& a = actions_[(size_t)r.idx];
            std::snprintf(label, sizeof(label), "%s", a.label.c_str());
            icon = a.icon; detail = a.detail.empty() ? nullptr : a.detail.c_str();
        }

        ImGui::PushID(i);
        if (i == sel_) ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(acc.x, acc.y, acc.z, 0.30f));
        char row[352];
        if (IconsLoaded() && icon) std::snprintf(row, sizeof(row), "%s  %s", icon, label);
        else                       std::snprintf(row, sizeof(row), "%s", label);
        if (ImGui::Selectable(row, i == sel_)) runIdx = i;
        if (i == sel_) {
            ImGui::PopStyleColor();
            if (selMoved_) { ImGui::SetScrollHereY(0.5f); selMoved_ = false; }
        }
        if (detail) {
            float dw = ImGui::CalcTextSize(detail).x;
            ImGui::SameLine(ImGui::GetWindowWidth() - dw - 16.0f * s);   // right-aligned hint
            ImGui::TextDisabled("%s", detail);
        }
        ImGui::PopID();
    }
    if (results_.empty()) ImGui::TextDisabled("No matches.");
    ImGui::EndChild();
    ImGui::TextDisabled("Enter run   Up/Down select   Esc close");

    const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    ImGui::End();
    ImGui::PopStyleVar(2);

    // Execute AFTER End() - an action may open dialogs / mutate app state.
    // Capture the callable BEFORE close() (which clears actions_).
    if (runIdx >= 0 && runIdx < (int)results_.size()) {
        Result r = results_[(size_t)runIdx];
        std::function<void()> action;
        if (r.kind == 0) action = actions_[(size_t)r.idx].run;
        close();
        if (r.kind != 0) {
            if (r.live) ctx.gotoAddressLive(r.va);
            else        ctx.gotoAddress(r.va);
        }
        else if (action) action();
        return;
    }

    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) close();
    else if (!focused && (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
                          ImGui::IsMouseClicked(ImGuiMouseButton_Right))) close();   // click-away
}

} // namespace ds::ui
