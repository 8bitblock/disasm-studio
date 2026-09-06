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

ImVec4 interactionTint(const ImVec4& base, float amount) {
    const bool light = relativeLuminance(base) > 0.38f;
    const ImVec4 target = light ? ImVec4(0, 0, 0, base.w)
                                : ImVec4(1, 1, 1, base.w);
    return ImVec4(base.x + (target.x - base.x) * amount,
                  base.y + (target.y - base.y) * amount,
                  base.z + (target.z - base.z) * amount, base.w);
}

} // namespace

ImVec4 Dim(const ImVec4& c, float f) { return ImVec4(c.x * f, c.y * f, c.z * f, 1.0f); }

bool AccentButton(const char* label, const ImVec4& base, const char* tip, bool small) {
    const ImVec4 hov = interactionTint(base, 0.12f);
    const ImVec4 active = interactionTint(base, 0.20f);
    ImGui::PushStyleColor(ImGuiCol_Button, base);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, active);
    ImGui::PushStyleColor(ImGuiCol_Text, contrastText(base));
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

    // Keep every tab-local toolbar on the same compact, outlined visual
    // vocabulary as the app debugger bar.  A shared implementation matters
    // here: Projects, Communications, scanners, Cortex, Prism, and Binary View
    // all use this helper, so none of them has to hand-roll Midnight chrome.
    const float s = theme::UiScale();
    const ImVec4 acc = theme::col::accent();
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.0f * s, 4.0f * s));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f * s);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Button, theme::col::panelHeader());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                          ImVec4(acc.x, acc.y, acc.z, 0.24f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(acc.x, acc.y, acc.z, 0.38f));
    ImGui::PushStyleColor(ImGuiCol_Border, theme::col::line());
    bool r = ImGui::Button(buf);
    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar(3);
    ItemTooltip(tip);
    return r;
}

bool SearchBox(const char* id, const char* hint, char* buf, size_t bufSize, float width) {
    const bool icons = IconsLoaded();
    if (width > 0.0f) ImGui::SetNextItemWidth(width);
    ImVec2 p = ImGui::GetCursorScreenPos();
    const ImGuiStyle& st = ImGui::GetStyle();
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f * theme::UiScale());
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, theme::col::line());
    float iconW = 0.0f;
    if (icons) {
        iconW = ImGui::CalcTextSize(DS_ICON_SEARCH).x + 5.0f * theme::UiScale();
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                            ImVec2(st.FramePadding.x + iconW, st.FramePadding.y));
    }
    bool r = ImGui::InputTextWithHint(id, hint, buf, bufSize,
                                      ImGuiInputTextFlags_EscapeClearsAll);
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
    if (ImGui::IsItemHovered(flags)) ImGui::SetTooltip("%s", text);
}

void SameLineIfFits(float nextWidth) {
    const float right = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
    if (ImGui::GetItemRectMax().x + ImGui::GetStyle().ItemSpacing.x + nextWidth <= right)
        ImGui::SameLine();
}

void Badge(const char* text, const ImVec4& color) {
    const float s = theme::UiScale();
    const ImVec2 ts = ImGui::CalcTextSize(text);
    const float padX = 7.0f * s, padY = 2.0f * s;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float w = ts.x + padX * 2.0f, h = ts.y + padY * 2.0f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.16f)), h * 0.5f);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.55f)), h * 0.5f);
    dl->AddText(ImVec2(p.x + padX, p.y + padY), ImGui::GetColorU32(color), text);
    ImGui::Dummy(ImVec2(w, h));
}

// ---- Wireframe chrome kit ---------------------------------------------------

bool ToolButton(const char* id, const char* icon, const char* fallback,
                const char* tip, bool hot, bool enabled) {
    const float s  = theme::UiScale();
    const ImVec2 sz(30.0f * s, 30.0f * s);
    const char* glyph = (IconsLoaded() && icon && icon[0]) ? icon : fallback;
    char lbl[96];
    std::snprintf(lbl, sizeof(lbl), "%s###tbn_%s", glyph, id);

    const ImVec4 acc  = theme::col::accent();
    const ImVec4 line = theme::col::line();
    const ImVec4 base = hot ? ImVec4(acc.x, acc.y, acc.z, 0.14f) : theme::col::panelHeader();
    const ImVec4 hov  = hot ? ImVec4(acc.x, acc.y, acc.z, 0.26f)
                            : ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f * s);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Button,        base);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(acc.x, acc.y, acc.z, 0.35f));
    ImGui::PushStyleColor(ImGuiCol_Border,        hot ? acc : line);
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
    const float h    = 24.0f * s;
    const float padY = (ImGui::GetFrameHeight() > h) ? (ImGui::GetFrameHeight() - h) * 0.5f : 0.0f;
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p.x, p.y + padY), ImVec2(p.x, p.y + padY + h),
                                        ImGui::GetColorU32(theme::col::lineSoft()), 1.0f * s);
    ImGui::Dummy(ImVec2(1.0f * s, h));
}

bool Pill(const char* id, const char* text, const ImVec4* valueCol, const char* tip) {
    const float s = theme::UiScale();
    PushMono();
    const ImVec2 ts = ImGui::CalcTextSize(text);
    PopMono();
    const float padX = 10.0f * s;
    const float h    = 28.0f * s;
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
        const float mix = held ? 0.26f : 0.12f;
        fill.x = fill.x * (1.0f - mix) + accent.x * mix;
        fill.y = fill.y * (1.0f - mix) + accent.y * mix;
        fill.z = fill.z * (1.0f - mix) + accent.z * mix;
    }
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(fill), 4.0f * s);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32((hovered || focused) ? theme::col::accent()
                                                       : theme::col::line()),
                4.0f * s, 0, focused ? 2.0f : 1.0f);
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
    const float padX = 12.0f * s, gap = (dt.x > 0 ? 8.0f * s : 0.0f);
    const float h = 28.0f * s;
    const float w = st.x + dt.x + gap + padX * 2.0f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(theme::col::panelHeader()), 4.0f * s);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(ImVec4(stateCol.x, stateCol.y, stateCol.z, 0.65f)),
                4.0f * s, 0, 1.0f);
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
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(11.0f * scale, 4.0f * scale));
    ImGui::PushStyleVar(ImGuiStyleVar_TabRounding, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_Tab, theme::col::panelHeader());
    ImGui::PushStyleColor(ImGuiCol_TabSelected, theme::col::panel());
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
                                        ImGui::GetColorU32(theme::col::lineSoft()), 1.0f);
    ImGui::Dummy(ImVec2(1.0f, lh));
    ImGui::SameLine(0.0f, 10.0f * s);
}

void KeyValueRow(const char* key, const char* fmt, ...) {
    const float keyW = 110.0f * theme::UiScale();
    ImGui::TextColored(theme::col::muted(), "%s", key);
    ImGui::SameLine(keyW);
    va_list args;
    va_start(args, fmt);
    ImGui::TextV(fmt, args);
    va_end(args);
}

bool EmptyState(const char* icon, const char* title, const char* subtitle,
                const char* primaryButtonLabel) {
    const float s = theme::UiScale();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const bool hasIcon = IconsLoaded() && gIconFontLarge && icon && icon[0];
    const bool hasSub  = subtitle && subtitle[0];
    const bool hasBtn  = primaryButtonLabel && primaryButtonLabel[0];

    // Empty tools should still read like part of the workbench.  Use a compact
    // flat onboarding panel instead of the former oversized marketing hero that
    // consumed most of the viewport.
    const float panelW = std::max(1.0f, std::min(avail.x, 620.0f * s));
    const float paddingX = 14.0f * s, paddingY = 12.0f * s;
    const float iconW = hasIcon
        ? gIconFontLarge->CalcTextSizeA(gIconFontLarge->FontSize, FLT_MAX, 0, icon).x + 14.0f * s
        : 0.0f;
    const float textW = std::max(1.0f, panelW - paddingX * 2.0f - iconW - 2.0f);
    float contentH = ImGui::CalcTextSize(title, nullptr, false, textW).y;
    if (hasSub) contentH += ImGui::GetStyle().ItemSpacing.y +
        ImGui::CalcTextSize(subtitle, nullptr, false, textW).y;
    if (hasBtn) contentH += 5.0f * s + ImGui::GetStyle().ItemSpacing.y * 2.0f +
                            ImGui::GetFrameHeight();
    if (hasIcon) contentH = std::max(contentH, gIconFontLarge->FontSize);
    const float panelH = contentH + paddingY * 2.0f + 2.0f;
    const float topPad = std::clamp((avail.y - panelH) * 0.18f, 0.0f, 56.0f * s);
    if (topPad > 0.0f) ImGui::Dummy(ImVec2(0, topPad));
    const float xPad = (avail.x - panelW) * 0.5f;
    if (xPad > 0.0f) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + xPad);

    bool clicked = false;
    ImGui::PushID(title);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                        ImVec2(14.0f * s, 12.0f * s));
    ImGui::BeginChild("##empty_state", ImVec2(panelW, panelH),
                      ImGuiChildFlags_Borders);
    if (hasIcon) {
        ImGui::PushFont(gIconFontLarge);
        ImGui::TextColored(theme::col::accent(), "%s", icon);
        ImGui::PopFont();
        ImGui::SameLine(0.0f, 14.0f * s);
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
        const ImVec4 acc = theme::col::accent();
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(acc.x, acc.y, acc.z, 0.20f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(acc.x, acc.y, acc.z, 0.34f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(acc.x, acc.y, acc.z, 0.46f));
        ImGui::PushStyleColor(ImGuiCol_Border, acc);
        clicked = ImGui::Button(primaryButtonLabel);
        ImGui::PopStyleColor(4);
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
