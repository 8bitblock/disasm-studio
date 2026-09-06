#pragma once
//
// Splitter.h
// A tiny vertical drag handle for resizing two side-by-side child panels that live
// INSIDE a single panel body (where ImGui's dock separators don't apply). Used for
// the Registers|Stack split and the Live view's listing|register-box split.
//
// Call it between the left child's EndChild() and the right child's BeginChild():
//
//     ImGui::BeginChild("left", ImVec2(*leftW, 0), ...);  ...  ImGui::EndChild();
//     ds::ui::VSplitter("##split", &leftW, minLeft, minRight, 6.0f);
//     ImGui::BeginChild("right", ImVec2(0, 0), ...);       ...  ImGui::EndChild();
//
// It draws a full-height invisible grab, shows the ResizeEW cursor on hover/drag, and
// updates *leftW by the mouse delta — clamped so neither side shrinks below its min.
//
#include "imgui.h"
#include "Theme.h"
#include <algorithm>
#include <cmath>

namespace ds::ui {

inline void VSplitter(const char* id, float* leftW, float minLeft, float minRight, float thickness) {
    ImGui::SameLine(0.0f, 0.0f);
    // Width remaining to the right of the left child = the right panel's current width;
    // total row width is that plus the left child we already laid out.
    const float rightAvail = ImGui::GetContentRegionAvail().x;
    const float total      = *leftW + rightAvail;
    const float h          = ImGui::GetContentRegionAvail().y;
    ImGui::InvisibleButton(id, ImVec2(thickness, h > 1.0f ? h : 1.0f));
    const bool hovered = ImGui::IsItemHovered();
    const bool active = ImGui::IsItemActive();
    if (hovered || active)
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
    const ImVec2 lo = ImGui::GetItemRectMin(), hiPoint = ImGui::GetItemRectMax();
    const float centerX = std::floor((lo.x + hiPoint.x) * 0.5f);
    ImGui::GetWindowDrawList()->AddLine(ImVec2(centerX, lo.y), ImVec2(centerX, hiPoint.y),
        ImGui::GetColorU32(active ? theme::col::accent()
            : hovered ? theme::col::muted() : theme::col::lineSoft()),
        std::max(1.0f, std::round(theme::UiScale())));
    if (active)
        *leftW += ImGui::GetIO().MouseDelta.x;
    const float hi = total - minRight - thickness;
    if (*leftW > hi)      *leftW = hi;
    if (*leftW < minLeft) *leftW = minLeft;
    ImGui::SameLine(0.0f, 0.0f);
}

} // namespace ds::ui
