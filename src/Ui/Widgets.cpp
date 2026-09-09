#include "Widgets.h"
#include "Fonts.h"
#include "Icons.h"
#include "Theme.h"
#include "imgui_internal.h"
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cctype>
#include <deque>

namespace ds::ui {

namespace {

ImVec4 blend(const ImVec4& base, const ImVec4& tint, float amount) {
    return ImVec4(base.x + (tint.x - base.x) * amount,
                  base.y + (tint.y - base.y) * amount,
                  base.z + (tint.z - base.z) * amount, 1.0f);
}

} // namespace

ImVec4 Dim(const ImVec4& c, float f) { return ImVec4(c.x * f, c.y * f, c.z * f, 1.0f); }

bool AccentButton(const char* label, const ImVec4& base, const char* tip, bool small) {
    const ImVec4 surface = theme::col::panelHeader();
    const ImVec4 fill = blend(surface, base, 0.08f);
    const ImVec4 hov = blend(surface, base, 0.14f);
    const ImVec4 active = blend(surface, base, 0.22f);
    ImGui::PushStyleColor(ImGuiCol_Button, fill);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, active);
    ImGui::PushStyleColor(ImGuiCol_Border, blend(theme::col::lineSoft(), base, 0.28f));
    bool r = small ? ImGui::SmallButton(label) : ImGui::Button(label);
    ImGui::PopStyleColor(4);
    ItemTooltip(tip);
    return r;
}

bool ToolbarIconButton(const char* icon, const char* label, const char* tip) {
    // "###" keeps the ImGui ID stable whether or not the icon glyph is shown.
    char buf[192];
    if (IconsLoaded() && icon && icon[0])
        std::snprintf(buf, sizeof(buf), "%s %s###tbib_%s", icon, label, label);
    else
        std::snprintf(buf, sizeof(buf), "%s###tbib_%s", label, label);

    // Inherit density and interaction colors so adjacent native inputs/buttons
    // share one row height across every tab and palette.
    bool r = ImGui::Button(buf);
    ItemTooltip(tip);
    return r;
}

bool SearchBox(const char* id, const char* hint, char* buf, size_t bufSize, float width) {
    const bool icons = IconsLoaded();
    if (width > 0.0f) ImGui::SetNextItemWidth(width);
    ImVec2 p = ImGui::GetCursorScreenPos();
    const ImGuiStyle& st = ImGui::GetStyle();
    const float scale = theme::UiScale();
    const float linePx = std::max(1.0f, std::round(scale));
    const float rounding = ImGui::GetFrameHeight() * 0.5f;
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, rounding);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, linePx);
    ImGui::PushStyleColor(ImGuiCol_Border,
        blend(theme::col::panel(), theme::col::readingText(), 0.09f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg,
        blend(theme::col::panel(), theme::col::readingText(), 0.045f));
    ImGui::PushStyleColor(ImGuiCol_TextDisabled, theme::col::faintText());
    float iconW = 0.0f;
    if (icons) {
        iconW = ImGui::CalcTextSize(DS_ICON_SEARCH).x + 5.0f * theme::UiScale();
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                            ImVec2(st.FramePadding.x + iconW, st.FramePadding.y));
    }
    bool r = ImGui::InputTextWithHint(id, hint, buf, bufSize,
                                      ImGuiInputTextFlags_EscapeClearsAll);
    if (ImGui::IsItemActive() || ImGui::IsItemFocused())
        ImGui::GetWindowDrawList()->AddRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(),
            ImGui::GetColorU32(theme::col::linkText()), rounding, 0, linePx);
    if (icons) {
        ImGui::PopStyleVar();
        // Magnifier inside the frame's left padding, vertically centered.
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(p.x + st.FramePadding.x, p.y + st.FramePadding.y),
            ImGui::GetColorU32(theme::col::faintText()), DS_ICON_SEARCH);
    }
    ImGui::PopStyleColor(3);
    ImGui::PopStyleVar(2);
    return r;
}

void ItemTooltip(const char* text, bool allowWhenDisabled) {
    if (!text || !text[0]) return;
    ImGuiHoveredFlags flags = ImGuiHoveredFlags_DelayNormal |
                              ImGuiHoveredFlags_NoSharedDelay;
    if (allowWhenDisabled) flags |= ImGuiHoveredFlags_AllowWhenDisabled;
    if (ImGui::IsItemHovered(flags)) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + std::max(1.0f,
            std::min(460.0f * theme::UiScale(), ImGui::GetMainViewport()->WorkSize.x - 32.0f * theme::UiScale())));
        ImGui::TextUnformatted(text);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void SameLineIfFits(float nextWidth) {
    const float right = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
    if (ImGui::GetItemRectMax().x + ImGui::GetStyle().ItemSpacing.x + nextWidth <= right)
        ImGui::SameLine();
}

void Badge(const char* text, const ImVec4& color) {
    const float s = theme::UiScale();
    const ImVec2 ts = ImGui::CalcTextSize(text);
    const float padX = 5.0f * s, padY = 1.0f * s;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float w = ts.x + padX * 2.0f, h = ts.y + padY * 2.0f;
    const float rounding = h * 0.5f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.07f)), rounding);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.42f)), rounding);
    dl->AddCircleFilled(ImVec2(p.x + padX * 0.5f, p.y + h * 0.5f),
                        1.25f * s, ImGui::GetColorU32(color));
    dl->AddText(ImVec2(p.x + padX, p.y + padY), ImGui::GetColorU32(color), text);
    ImGui::Dummy(ImVec2(w, h));
}

// ---- Workbench chrome ------------------------------------------------------

namespace {
void pushDataTableStyle() {
    const ImVec4 panel = theme::col::panel();
    const ImVec4 line = theme::col::paneLine();
    ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, theme::col::tableHeader());
    ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, line);
    ImGui::PushStyleColor(ImGuiCol_TableBorderLight, blend(panel, line, 0.32f));
    ImGui::PushStyleColor(ImGuiCol_TableRowBg, panel);
    ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, panel);
}

ImGuiTableFlags dataTableFlags(ImGuiTableFlags flags) {
    // Keep resizing, ordering, clipping and persistence policies unchanged.
    return (flags & ~(ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV)) |
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH;
}
}

bool BeginDataTable(const char* id, int columns, ImGuiTableFlags flags,
                    const ImVec2& size, float innerWidth) {
    pushDataTableStyle();
    if (ImGui::BeginTable(id, columns, dataTableFlags(flags), size, innerWidth)) return true;
    ImGui::PopStyleColor(5);
    return false;
}

bool BeginDataTableEx(const char* name, ImGuiID id, int columns, ImGuiTableFlags flags,
                      const ImVec2& size, float innerWidth) {
    pushDataTableStyle();
    if (ImGui::BeginTableEx(name, id, columns, dataTableFlags(flags), size, innerWidth)) return true;
    ImGui::PopStyleColor(5);
    return false;
}

void EndDataTable() {
    ImGui::EndTable();
    ImGui::PopStyleColor(5);
}

bool BeginCountTabItem(const char* label, size_t count, ImGuiTabItemFlags flags,
                       const ImVec4* color, bool marker) {
    const float scale = theme::UiScale();
    const ImVec4 ink = color ? *color : theme::col::secondaryText();
    const char* textEnd = ImGui::FindRenderedTextEnd(label);
    const ImVec2 nameSize = ImGui::CalcTextSize(label, textEnd);
    char countText[24]; std::snprintf(countText, sizeof(countText), "%zu", count);
    const float markerSpace = marker ? 12.0f * scale : 0.0f;
    const float gap = 8.0f * scale, padding = 5.0f * scale;
    const float countWidth = ImGui::CalcTextSize(countText).x + padding * 2.0f;
    ImGui::SetNextItemWidth(nameSize.x + markerSpace + gap + countWidth +
        ImGui::GetStyle().FramePadding.x * 2.0f);
    // Keep native text drawing: the first item also lays out the tab-list menu
    // and scroll arrows, which must retain their normal text color.
    ImGui::PushStyleVar(ImGuiStyleVar_TabRounding, ImGui::GetFrameHeight() * 0.5f);
    const bool visible = ImGui::BeginTabItem(label, nullptr, flags | ImGuiTabItemFlags_NoTooltip);
    ImGui::PopStyleVar();
    const ImRect bounds = GImGui->LastItemData.Rect;
    const ImGuiTabBar* bar = GImGui->CurrentTabBar;
    if (!bar || bounds.GetWidth() <= 0) return visible;
    if (!(flags & ImGuiTabItemFlags_NoTooltip) && !(bar->Flags & ImGuiTabBarFlags_NoTooltip) &&
        ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal)) {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted(label, textEnd);
        ImGui::SameLine(); ImGui::TextDisabled("(%zu)", count);
        ImGui::EndTooltip();
    }
    // Native resizing may make the requested width smaller. Let its normal
    // ellipsis handle those labels; the full count remains in the tooltip.
    const float neededWidth = nameSize.x + markerSpace + gap + countWidth + bar->FramePadding.x * 2.0f;
    if (bounds.GetWidth() + 0.5f < neededWidth) return visible;
    ImRect clip = bounds;
    clip.ClipWith(bar->BarRect);
    if (!(flags & (ImGuiTabItemFlags_Leading | ImGuiTabItemFlags_Trailing))) {
        clip.Min.x = std::max(clip.Min.x, bar->ScrollingRectMinX);
        clip.Max.x = std::min(clip.Max.x, bar->ScrollingRectMaxX);
    }
    if (clip.Max.x <= clip.Min.x || clip.Max.y <= clip.Min.y) return visible;
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->PushClipRect(clip.Min, clip.Max, true);
    const float x = bounds.Min.x + bar->FramePadding.x;
    const float y = bounds.GetCenter().y;
    if (marker) draw->AddCircleFilled(ImVec2(x + nameSize.x + gap, y),
        2.6f * scale, ImGui::GetColorU32(ink), 12);
    const ImVec2 text(x, y - nameSize.y * 0.5f);
    const float countX = text.x + nameSize.x + markerSpace + gap;
    const ImVec2 pillMin(countX, text.y - scale);
    const ImVec2 pillMax(countX + countWidth, text.y + nameSize.y + scale);
    const float rounding = (pillMax.y - pillMin.y) * 0.5f;
    draw->AddRectFilled(pillMin, pillMax,
        ImGui::GetColorU32(blend(theme::col::chrome(), ink, visible ? 0.23f : 0.12f)), rounding);
    draw->AddText(ImVec2(countX + padding, text.y), ImGui::GetColorU32(ink), countText);
    draw->PopClipRect();
    return visible;
}

void PaneHeading(const char* title, const char* detail, int count, const ImVec4* countColor) {
    if (!title) title = "";
    const float scale = theme::UiScale();
    const float pad = 9.0f * scale;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const float fontSize = ImGui::GetFontSize() * 0.82f;
    const float height = std::max(fontSize + 12.0f * scale, 28.0f * scale);
    std::string caption(title);
    for (char& ch : caption)
        if (static_cast<unsigned char>(ch) < 128)
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    ImFont* font = ImGui::GetFont();
    const ImVec2 titleSize = font->CalcTextSizeA(fontSize, FLT_MAX, 0.0f, caption.c_str());
    const float y = origin.y + (height - fontSize) * 0.5f;
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(origin, ImVec2(origin.x + width, origin.y + height),
        ImGui::GetColorU32(theme::col::chrome()));
    draw->AddLine(ImVec2(origin.x, origin.y + height),
        ImVec2(origin.x + width, origin.y + height),
        ImGui::GetColorU32(theme::col::paneLine()), std::max(1.0f, std::round(scale)));
    draw->PushClipRect(origin, ImVec2(origin.x + width, origin.y + height), true);
    draw->AddText(font, fontSize, ImVec2(origin.x + pad, y),
        ImGui::GetColorU32(theme::col::secondaryText()), caption.c_str());
    float nextX = origin.x + pad + titleSize.x + 8.0f * scale;
    if (count >= 0) {
        char number[24]; std::snprintf(number, sizeof(number), "%d", count);
        const float numberSize = fontSize * 0.95f;
        const ImVec2 numberText = font->CalcTextSizeA(numberSize, FLT_MAX, 0.0f, number);
        const float h = numberSize + 5.0f * scale;
        const float w = std::max(h, numberText.x + 10.0f * scale);
        const ImVec2 a(nextX, origin.y + (height - h) * 0.5f);
        const ImVec4 ink = countColor ? *countColor : theme::col::linkText();
        draw->AddRectFilled(a, ImVec2(a.x + w, a.y + h),
            ImGui::GetColorU32(blend(theme::col::chrome(), ink, 0.16f)), h * 0.5f);
        draw->AddText(font, numberSize,
            ImVec2(a.x + (w - numberText.x) * 0.5f, a.y + (h - numberSize) * 0.5f),
            ImGui::GetColorU32(ink), number);
        nextX += w + 10.0f * scale;
    }
    if (detail && detail[0] && nextX < origin.x + width - pad) {
        const ImVec2 detailSize = font->CalcTextSizeA(fontSize, FLT_MAX, 0.0f, detail);
        const float detailX = std::max(nextX, origin.x + width - pad - detailSize.x);
        draw->AddText(font, fontSize, ImVec2(detailX, y),
            ImGui::GetColorU32(theme::col::faintText()), detail);
    }
    draw->PopClipRect();
    if (GImGui->LogEnabled) {
        ImGui::LogRenderedText(&origin, title);
        if (detail && detail[0]) ImGui::LogRenderedText(&origin, detail);
    }
    ImGui::Dummy(ImVec2(width, height));
}

void PanelHeader(const char* title, const char* detail) {
    const float scale = theme::UiScale();
    const float pad = 6.0f * scale;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const float textWidth = std::max(1.0f, width - 2.0f * pad);
    const bool hasDetail = detail && detail[0];
    const ImVec2 titleSize = ImGui::CalcTextSize(title, nullptr, false, textWidth);
    const ImVec2 detailSize = hasDetail
        ? ImGui::CalcTextSize(detail, nullptr, false, textWidth) : ImVec2(0, 0);
    const bool inlineDetail = hasDetail &&
        ImGui::CalcTextSize(title).x + ImGui::CalcTextSize(detail).x + 16.0f * scale <= textWidth;
    const float height = titleSize.y + (hasDetail && !inlineDetail
        ? detailSize.y + 2.0f * scale : 0.0f) + 2.0f * pad;
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(origin, ImVec2(origin.x + width, origin.y + height),
                        ImGui::GetColorU32(theme::col::chrome()));
    draw->AddLine(ImVec2(origin.x, origin.y + height),
                  ImVec2(origin.x + width, origin.y + height),
                  ImGui::GetColorU32(theme::col::paneLine()),
                  std::max(1.0f, std::round(scale)));
    ImGui::BeginGroup();
    ImGui::SetCursorScreenPos(ImVec2(origin.x + pad, origin.y + pad));
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + textWidth);
    ImGui::TextUnformatted(title);
    if (hasDetail) {
        if (inlineDetail) ImGui::SameLine(0.0f, 16.0f * scale);
        else ImGui::SetCursorScreenPos(ImVec2(origin.x + pad,
            origin.y + pad + titleSize.y + 2.0f * scale));
        ImGui::PushStyleColor(ImGuiCol_Text, theme::col::secondaryText());
        ImGui::TextUnformatted(detail);
        ImGui::PopStyleColor();
    }
    ImGui::PopTextWrapPos();
    ImGui::SetCursorScreenPos(ImVec2(origin.x, origin.y + height));
    ImGui::Dummy(ImVec2(width, 0));
    ImGui::EndGroup();
}

bool ToolButton(const char* id, const char* icon, const char* fallback,
                const char* tip, bool hot, bool enabled) {
    const float s  = theme::UiScale();
    const float side = std::max(28.0f * s, ImGui::GetFrameHeight());
    const ImVec2 sz(side, side);
    const char* glyph = (IconsLoaded() && icon && icon[0]) ? icon : fallback;
    char lbl[96];
    std::snprintf(lbl, sizeof(lbl), "%s###tbn_%s", glyph, id);

    const ImVec4 acc  = theme::col::accent();
    const ImVec4 line = theme::col::lineSoft();
    const ImVec4 base = blend(theme::col::panelHeader(), acc, hot ? 0.12f : 0.0f);
    const ImVec4 hov  = blend(theme::col::panelHeader(), acc, hot ? 0.20f : 0.08f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, ImGui::GetStyle().FrameRounding);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, std::max(1.0f, std::round(s)));
    ImGui::PushStyleColor(ImGuiCol_Button,        base);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  blend(theme::col::panelHeader(), acc, 0.22f));
    ImGui::PushStyleColor(ImGuiCol_Border,        blend(line, acc, hot ? 0.40f : 0.0f));
    if (hot) ImGui::PushStyleColor(ImGuiCol_Text, theme::col::accent());
    if (!enabled) ImGui::BeginDisabled();
    bool r = ImGui::Button(lbl, sz);
    if (!enabled) ImGui::EndDisabled();
    if (hot) ImGui::PopStyleColor();
    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar(2);
    ItemTooltip(tip);
    return r && enabled;
}

void ToolbarDivider() {
    const float s = theme::UiScale();
    ImVec2 p = ImGui::GetCursorScreenPos();
    const float h    = ImGui::GetFrameHeight();
    const float padY = std::min(5.0f * s, h * 0.25f);
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p.x, p.y + padY), ImVec2(p.x, p.y + h - padY),
                                        ImGui::GetColorU32(theme::col::lineSoft()), std::max(1.0f, std::round(s)));
    ImGui::Dummy(ImVec2(std::max(1.0f, std::round(s)), h));
}

bool Pill(const char* id, const char* text, const ImVec4* valueCol, const char* tip) {
    const float s = theme::UiScale();
    const float rounding = ImGui::GetStyle().FrameRounding;
    PushMono();
    const ImVec2 ts = ImGui::CalcTextSize(text);
    PopMono();
    const float padX = ImGui::GetStyle().FramePadding.x + 2.0f * s;
    const float h    = std::max(ImGui::GetFrameHeight(), ts.y + ImGui::GetStyle().FramePadding.y * 2.0f);
    const float w    = ts.x + padX * 2.0f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool clicked = ImGui::InvisibleButton(id, ImVec2(w, h), ImGuiButtonFlags_EnableNav);
    const bool hovered = ImGui::IsItemHovered();
    const bool focused = ImGui::IsItemFocused();
    const bool held = ImGui::IsItemActive();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec4 fill = ImGui::GetStyleColorVec4(held ? ImGuiCol_ButtonActive :
        hovered ? ImGuiCol_ButtonHovered : ImGuiCol_Button);
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(fill), rounding);
    const ImVec4 border = (hovered || focused) ? theme::col::accent() : theme::col::lineSoft();
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(border),
                rounding, 0, std::max(1.0f, std::round(s)));
    const ImVec4 tc = valueCol ? *valueCol : ImGui::GetStyleColorVec4(ImGuiCol_Text);
    PushMono();
    dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
                ImVec2(p.x + padX, p.y + (h - ts.y) * 0.5f), ImGui::GetColorU32(tc), text);
    PopMono();
    ItemTooltip(tip, false);
    return clicked;
}

void StatePill(const char* state, const ImVec4& stateCol, const char* detail) {
    const float s = theme::UiScale();
    PushMono();
    const ImVec2 st = ImGui::CalcTextSize(state);
    const ImVec2 dt = (detail && detail[0]) ? ImGui::CalcTextSize(detail) : ImVec2(0, 0);
    PopMono();
    const float padX = ImGui::GetStyle().FramePadding.x + 2.0f * s, gap = (dt.x > 0 ? 8.0f * s : 0.0f);
    const float h = std::max(ImGui::GetFrameHeight(), st.y + ImGui::GetStyle().FramePadding.y * 2.0f);
    const float w = st.x + dt.x + gap + padX * 2.0f;
    const float rounding = h * 0.5f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
        ImGui::GetColorU32(blend(theme::col::panelHeader(), stateCol, 0.06f)), rounding);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
        ImGui::GetColorU32(blend(theme::col::lineSoft(), stateCol, 0.40f)),
        rounding, 0, std::max(1.0f, std::round(s)));
    dl->AddCircleFilled(ImVec2(p.x + padX * 0.5f, p.y + h * 0.5f),
                        std::min(1.75f * s, padX * 0.24f), ImGui::GetColorU32(stateCol));
    PushMono();
    dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
                ImVec2(p.x + padX, p.y + (h - st.y) * 0.5f), ImGui::GetColorU32(stateCol), state);
    if (dt.x > 0)
        dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
                    ImVec2(p.x + padX + st.x + gap, p.y + (h - dt.y) * 0.5f),
                    ImGui::GetColorU32(theme::col::muted()), detail);
    PopMono();
    ImGui::Dummy(ImVec2(w, h));
}

int TabStrip(const char* id, const char* const* labels, int count, int active,
             const bool* enabled) {
    if (!labels || count <= 0) return active;
    const float scale = theme::UiScale();
    int result = std::clamp(active, 0, count - 1);
    if (enabled && !enabled[result]) {
        for (int i = 0; i < count; ++i)
            if (enabled[i]) { result = i; break; }
    }
    ImGui::PushID(id);
    ImGuiStorage* storage = ImGui::GetStateStorage();
    const ImGuiID selectionKey = ImGui::GetID("##last_selection");
    const bool selectionChanged = storage->GetInt(selectionKey, -1) != result;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const float tabHeight = std::max(31.0f * scale, ImGui::GetFontSize() + 8.0f * scale);
    ImGui::GetWindowDrawList()->AddRectFilled(origin,
        ImVec2(origin.x + width, origin.y + tabHeight),
        ImGui::GetColorU32(theme::col::chrome()));
    ImGui::GetWindowDrawList()->AddLine(ImVec2(origin.x, origin.y + tabHeight),
        ImVec2(origin.x + width, origin.y + tabHeight),
        ImGui::GetColorU32(theme::col::paneLine()), std::max(1.0f, std::round(scale)));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
        ImVec2(12.0f * scale, (tabHeight - ImGui::GetFontSize()) * 0.5f));
    ImGui::PushStyleVar(ImGuiStyleVar_TabRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_TabBarBorderSize, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_Tab, theme::col::chrome());
    ImGui::PushStyleColor(ImGuiCol_TabSelected, theme::col::chrome());
    ImGui::PushStyleColor(ImGuiCol_TabHovered,
        blend(theme::col::chrome(), theme::col::readingText(), 0.035f));
    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::secondaryText());
    if (ImGui::BeginTabBar("##tabs", ImGuiTabBarFlags_FittingPolicyScroll |
                                    ImGuiTabBarFlags_TabListPopupButton)) {
        for (int i = 0; i < count; ++i) {
            ImGui::PushID(i);
            if (enabled && !enabled[i]) {
                ImGui::BeginDisabled();
                ImGui::TabItemButton(labels[i]);
                ImGui::EndDisabled();
            } else {
                const ImGuiTabItemFlags flags = selectionChanged && i == result
                    ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
                ImGui::PushStyleColor(ImGuiCol_Text,
                    i == result ? theme::col::linkText() : theme::col::secondaryText());
                if (ImGui::BeginTabItem(labels[i], nullptr, flags)) {
                    // Keep an explicit external handoff authoritative during
                    // the frame in which ImGui commits the new selection.
                    if (!selectionChanged) result = i;
                    const ImRect bounds = GImGui->LastItemData.Rect;
                    const ImGuiTabBar* bar = GImGui->CurrentTabBar;
                    if (bar) {
                        const float left = std::max(bounds.Min.x, bar->ScrollingRectMinX);
                        const float right = std::min(bounds.Max.x, bar->ScrollingRectMaxX);
                        if (right > left) ImGui::GetWindowDrawList()->AddRectFilled(
                            ImVec2(left, bounds.Max.y - 2.0f * scale),
                            ImVec2(right, bounds.Max.y), ImGui::GetColorU32(theme::col::linkText()));
                    }
                    ImGui::EndTabItem();
                }
                ImGui::PopStyleColor();
            }
            ImGui::PopID();
        }
        ImGui::EndTabBar();
    }
    storage->SetInt(selectionKey, result);
    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar(3);
    ImGui::PopID();
    return result;
}

void StatusDivider() {
    const float s = theme::UiScale();
    ImGui::SameLine(0.0f, 10.0f * s);
    ImVec2 p = ImGui::GetCursorScreenPos();
    const float lh = ImGui::GetTextLineHeight();
    const float h  = 12.0f * s;
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p.x, p.y + (lh - h) * 0.5f),
                                        ImVec2(p.x, p.y + (lh + h) * 0.5f),
                                        ImGui::GetColorU32(theme::col::lineSoft()), std::max(1.0f, std::round(s)));
    ImGui::Dummy(ImVec2(std::max(1.0f, std::round(s)), lh));
    ImGui::SameLine(0.0f, 10.0f * s);
}

void KeyValueRow(const char* key, const char* fmt, ...) {
    const float scale = theme::UiScale();
    const float origin = ImGui::GetCursorPosX();
    const float available = ImGui::GetContentRegionAvail().x;
    const float keyW = std::max(110.0f * scale,
        ImGui::CalcTextSize(key).x + ImGui::GetStyle().ItemSpacing.x);
    // Keep long paths and evidence readable in details panes. Use the row's
    // own origin so an indented/grouped caller does not overlap its key.
    ImGui::PushTextWrapPos(origin + std::max(1.0f, available));
    ImGui::TextColored(theme::col::muted(), "%s", key);
    if (available >= keyW + 150.0f * scale)
        ImGui::SameLine(origin + keyW);
    va_list args;
    va_start(args, fmt);
    ImGui::TextV(fmt, args);
    va_end(args);
    ImGui::PopTextWrapPos();
}

bool EmptyState(const char* icon, const char* title, const char* subtitle,
                const char* primaryButtonLabel) {
    const float s = theme::UiScale();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const bool hasIcon = IconsLoaded() && icon && icon[0];
    const bool hasSub  = subtitle && subtitle[0];
    const bool hasBtn  = primaryButtonLabel && primaryButtonLabel[0];

    // Empty tools keep the same left alignment as populated tools. The child
    // only owns layout/IDs; no card, border, hero glyph or extra surface is drawn.
    const float panelW = std::max(1.0f, std::min(avail.x, 620.0f * s));
    const float paddingX = 8.0f * s, paddingY = 8.0f * s;
    ImFont* glyphFont = gUiFont ? gUiFont : ImGui::GetFont();
    const float iconW = hasIcon
        ? glyphFont->CalcTextSizeA(glyphFont->FontSize, FLT_MAX, 0, icon).x + 10.0f * s
        : 0.0f;
    const float textW = std::max(1.0f, panelW - paddingX * 2.0f - iconW - 2.0f);
    float contentH = ImGui::CalcTextSize(title, nullptr, false, textW).y;
    if (hasSub) contentH += ImGui::GetStyle().ItemSpacing.y +
        ImGui::CalcTextSize(subtitle, nullptr, false, textW).y;
    if (hasBtn) contentH += 5.0f * s + ImGui::GetStyle().ItemSpacing.y * 2.0f +
                            ImGui::GetFrameHeight();
    if (hasIcon) contentH = std::max(contentH, glyphFont->FontSize);
    const float panelH = contentH + paddingY * 2.0f + 2.0f;
    const float topPad = std::clamp(avail.y - panelH, 0.0f, 20.0f * s);
    if (topPad > 0.0f) ImGui::Dummy(ImVec2(0, topPad));

    bool clicked = false;
    ImGui::PushID(title);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding,
        ImGui::GetStyle().ChildRounding);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                        ImVec2(paddingX, paddingY));
    ImGui::BeginChild("##empty_state", ImVec2(panelW, panelH),
                      ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoBackground);
    if (hasIcon) {
        ImGui::PushFont(glyphFont);
        ImGui::TextColored(theme::col::muted(), "%s", icon);
        ImGui::PopFont();
        ImGui::SameLine(0.0f, 10.0f * s);
    }
    ImGui::BeginGroup();
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + textW);
    ImGui::TextUnformatted(title);
    ImGui::PopTextWrapPos();
    if (hasSub) {
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + textW);
        ImGui::TextDisabled("%s", subtitle);
        ImGui::PopTextWrapPos();
    }
    if (hasBtn) {
        ImGui::Dummy(ImVec2(0, 5.0f * s));
        clicked = AccentButton(primaryButtonLabel, theme::col::accent());
    }
    ImGui::EndGroup();
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopID();
    return clicked;
}

// ---- Toasts ----------------------------------------------------------------

namespace {
struct ToastItem { ToastKind kind; std::string msg; double t0; };
std::deque<ToastItem> gToasts;
constexpr double kToastSolidS = 3.2;   // fully opaque until here...
constexpr double kToastEndS   = 4.0;   // ...then fade out to here
constexpr size_t kToastQueueCap = 8;
} // namespace

void Toast(ToastKind kind, std::string msg) {
    // A failing worker may report the same state on several adjacent frames.
    // Move one matching toast to the newest position instead of building a wall
    // of duplicates. Re-insertion keeps the deque chronologically ordered for
    // the inexpensive expiry pass below.
    for (auto it = gToasts.begin(); it != gToasts.end(); ++it) {
        if (it->kind == kind && it->msg == msg) {
            gToasts.erase(it);
            gToasts.push_back({ kind, std::move(msg), ImGui::GetTime() });
            return;
        }
    }
    gToasts.push_back({ kind, std::move(msg), ImGui::GetTime() });
    while (gToasts.size() > kToastQueueCap) gToasts.pop_front();
}

bool ToastsActive() { return !gToasts.empty(); }

void RenderToasts(float statusBarH) {
    if (gToasts.empty()) return;
    const double now = ImGui::GetTime();
    while (!gToasts.empty() && now - gToasts.front().t0 >= kToastEndS)
        gToasts.pop_front();   // entries are time-ordered, front is the oldest
    if (gToasts.empty()) return;

    const float s = theme::UiScale();
    const float margin = 12.0f * s, barW = 4.0f * s, pad = 10.0f * s;
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float cardW = std::max(120.0f * s,
        std::min(340.0f * s, vp->WorkSize.x - margin * 2.0f));
    float yBot = vp->WorkPos.y + vp->WorkSize.y - statusBarH - margin;

    ImDrawList* dl = ImGui::GetForegroundDrawList();
    const ImVec4 bg  = theme::col::menubar();
    const ImVec4 txt = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    int shown = 0;
    for (auto it = gToasts.rbegin(); it != gToasts.rend() && shown < 5; ++it) {
        const double age = now - it->t0;
        if (age >= kToastEndS) continue;
        ++shown;
        float alpha = age <= kToastSolidS
                    ? 1.0f
                    : 1.0f - (float)((age - kToastSolidS) / (kToastEndS - kToastSolidS));

        const ImVec4 kc = it->kind == ToastKind::Success ? theme::col::good()
                        : it->kind == ToastKind::Warn    ? theme::col::warn()
                        : it->kind == ToastKind::Error   ? theme::col::bad()
                                                         : theme::col::accent();
        const char* icon = !IconsLoaded()                  ? nullptr
                         : it->kind == ToastKind::Success ? DS_ICON_CHECK
                         : it->kind == ToastKind::Warn    ? DS_ICON_WARNING
                         : it->kind == ToastKind::Error   ? DS_ICON_ERROR
                                                          : DS_ICON_INFO;
        const float iconW = icon ? ImGui::CalcTextSize(icon).x + 6.0f * s : 0.0f;
        const float wrapW = cardW - barW - pad * 2.0f - iconW;
        const ImVec2 tsz  = ImGui::CalcTextSize(it->msg.c_str(), nullptr, false, wrapW);
        const float cardH = tsz.y + pad * 2.0f;

        const float x1 = vp->WorkPos.x + vp->WorkSize.x - margin;
        const float x0 = x1 - cardW;
        const float y1 = yBot, y0 = y1 - cardH;
        dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1),
                          ImGui::GetColorU32(ImVec4(bg.x, bg.y, bg.z, 0.97f * alpha)), 5.0f * s);
        dl->AddRect(ImVec2(x0, y0), ImVec2(x1, y1),
                    ImGui::GetColorU32(ImVec4(kc.x, kc.y, kc.z, 0.50f * alpha)), 5.0f * s);
        dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + barW, y1),
                          ImGui::GetColorU32(ImVec4(kc.x, kc.y, kc.z, alpha)), 5.0f * s);
        float tx = x0 + barW + pad;
        if (icon) {
            dl->AddText(ImVec2(tx, y0 + pad), ImGui::GetColorU32(ImVec4(kc.x, kc.y, kc.z, alpha)), icon);
            tx += iconW;
        }
        dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(tx, y0 + pad),
                    ImGui::GetColorU32(ImVec4(txt.x, txt.y, txt.z, alpha)),
                    it->msg.c_str(), nullptr, wrapW);
        yBot = y0 - 8.0f * s;
    }
}

} // namespace ds::ui
