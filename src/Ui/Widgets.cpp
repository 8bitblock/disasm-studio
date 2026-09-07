#include "Widgets.h"
#include "Fonts.h"
#include "Icons.h"
#include "Theme.h"
#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <deque>

namespace ds::ui {

namespace {

float linearChannel(float value) {
    value = std::clamp(value, 0.0f, 1.0f);
    return value <= 0.04045f ? value / 12.92f
                             : std::pow((value + 0.055f) / 1.055f, 2.4f);
}

float relativeLuminance(const ImVec4& color) {
    return 0.2126f * linearChannel(color.x) +
           0.7152f * linearChannel(color.y) +
           0.0722f * linearChannel(color.z);
}

ImVec4 contrastText(const ImVec4& background) {
    // WCAG's crossover for black vs. white contrast is roughly L=0.179.
    return relativeLuminance(background) > 0.179f
        ? ImVec4(0.025f, 0.035f, 0.045f, 1.0f)
        : ImVec4(0.975f, 0.985f, 0.995f, 1.0f);
}

ImVec4 blend(const ImVec4& base, const ImVec4& tint, float amount) {
    return ImVec4(base.x + (tint.x - base.x) * amount,
                  base.y + (tint.y - base.y) * amount,
                  base.z + (tint.z - base.z) * amount, 1.0f);
}

} // namespace

ImVec4 Dim(const ImVec4& c, float f) { return ImVec4(c.x * f, c.y * f, c.z * f, 1.0f); }

bool AccentButton(const char* label, const ImVec4& base, const char* tip, bool small) {
    const ImVec4 fill = blend(theme::col::panel(), base, 0.56f);
    const ImVec4 hov = blend(theme::col::panel(), base, 0.68f);
    const ImVec4 active = blend(theme::col::panel(), base, 0.78f);
    ImGui::PushStyleColor(ImGuiCol_Button, fill);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, active);
    ImGui::PushStyleColor(ImGuiCol_Text, contrastText(fill));
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
    ImGui::PushStyleColor(ImGuiCol_Button, theme::col::panelHeader());
    bool r = ImGui::Button(buf);
    ImGui::PopStyleColor();
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
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 2.0f * scale);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, linePx);
    ImGui::PushStyleColor(ImGuiCol_Border, theme::col::lineSoft());
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
            ImGui::GetColorU32(theme::col::accent()), 2.0f * scale, 0, linePx);
    if (icons) {
        ImGui::PopStyleVar();
        // Magnifier inside the frame's left padding, vertically centered.
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(p.x + st.FramePadding.x, p.y + st.FramePadding.y),
            ImGui::GetColorU32(theme::col::muted()), DS_ICON_SEARCH);
    }
    ImGui::PopStyleColor();
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
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.10f)), 2.0f * s);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.24f)), 2.0f * s);
    dl->AddText(ImVec2(p.x + padX, p.y + padY), ImGui::GetColorU32(color), text);
    ImGui::Dummy(ImVec2(w, h));
}

// ---- Workbench chrome ------------------------------------------------------

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
    const ImVec4 base = hot ? blend(theme::col::panelHeader(), acc, 0.12f) : theme::col::panelHeader();
    const ImVec4 hov  = hot ? blend(theme::col::panelHeader(), acc, 0.22f)
                            : ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 2.0f * s);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, hot ? std::max(1.0f, std::round(s)) : 0.0f);
    ImGui::PushStyleColor(ImGuiCol_Button,        base);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  blend(theme::col::panelHeader(), acc, 0.30f));
    ImGui::PushStyleColor(ImGuiCol_Border,        hot ? blend(theme::col::panelHeader(), acc, 0.45f) : line);
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
    ImVec4 fill = theme::col::panelHeader();
    if (held || hovered) {
        const ImVec4 accent = theme::col::accent();
        const float mix = held ? 0.20f : 0.08f;
        fill.x = fill.x * (1.0f - mix) + accent.x * mix;
        fill.y = fill.y * (1.0f - mix) + accent.y * mix;
        fill.z = fill.z * (1.0f - mix) + accent.z * mix;
    }
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(fill), 2.0f * s);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32((hovered || focused) ? theme::col::accent()
                                                       : theme::col::lineSoft()),
                2.0f * s, 0, std::max(1.0f, std::round(s)));
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
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(theme::col::panelHeader()), 2.0f * s);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(theme::col::lineSoft()),
                2.0f * s, 0, std::max(1.0f, std::round(s)));
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
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
        ImVec2(ImGui::GetStyle().FramePadding.x + 3.0f * scale, ImGui::GetStyle().FramePadding.y));
    ImGui::PushStyleVar(ImGuiStyleVar_TabRounding, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_Tab, theme::col::panelHeader());
    ImGui::PushStyleColor(ImGuiCol_TabSelected,
        blend(theme::col::panel(), ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered), 0.35f));
    if (ImGui::BeginTabBar("##tabs", ImGuiTabBarFlags_FittingPolicyScroll |
                                    ImGuiTabBarFlags_TabListPopupButton |
                                    ImGuiTabBarFlags_DrawSelectedOverline)) {
        for (int i = 0; i < count; ++i) {
            ImGui::PushID(i);
            if (enabled && !enabled[i]) {
                ImGui::BeginDisabled();
                ImGui::TabItemButton(labels[i]);
                ImGui::EndDisabled();
            } else {
                const ImGuiTabItemFlags flags = selectionChanged && i == result
                    ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
                if (ImGui::BeginTabItem(labels[i], nullptr, flags)) {
                    // Keep an explicit external handoff authoritative during
                    // the frame in which ImGui commits the new selection.
                    if (!selectionChanged) result = i;
                    ImGui::EndTabItem();
                }
            }
            ImGui::PopID();
        }
        ImGui::EndTabBar();
    }
    storage->SetInt(selectionKey, result);
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
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
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
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
