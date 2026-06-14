#include "Widgets.h"
#include "Fonts.h"
#include "Icons.h"
#include "Theme.h"
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <deque>

namespace ds::ui {

ImVec4 Dim(const ImVec4& c, float f) { return ImVec4(c.x * f, c.y * f, c.z * f, 1.0f); }

bool AccentButton(const char* label, const ImVec4& base, const char* tip, bool small) {
    ImVec4 hov(base.x * 1.2f, base.y * 1.2f, base.z * 1.2f, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Button, base);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hov);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, base);
    bool r = small ? ImGui::SmallButton(label) : ImGui::Button(label);
    ImGui::PopStyleColor(3);
    if (tip && tip[0] && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("%s", tip);
    return r;
}

bool ToolbarIconButton(const char* icon, const char* label, const char* tip) {
    // "###" keeps the ImGui ID stable whether or not the icon glyph is shown.
    char buf[192];
    if (IconsLoaded() && icon && icon[0])
        std::snprintf(buf, sizeof(buf), "%s %s###tbib_%s", icon, label, label);
    else
        std::snprintf(buf, sizeof(buf), "%s###tbib_%s", label, label);
    bool r = ImGui::Button(buf);
    if (tip && tip[0] && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("%s", tip);
    return r;
}

bool SearchBox(const char* id, const char* hint, char* buf, size_t bufSize, float width) {
    const bool icons = IconsLoaded();
    if (width > 0.0f) ImGui::SetNextItemWidth(width);
    ImVec2 p = ImGui::GetCursorScreenPos();
    const ImGuiStyle& st = ImGui::GetStyle();
    float iconW = 0.0f;
    if (icons) {
        iconW = ImGui::CalcTextSize(DS_ICON_SEARCH).x + 5.0f * theme::UiScale();
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
                            ImVec2(st.FramePadding.x + iconW, st.FramePadding.y));
    }
    bool r = ImGui::InputTextWithHint(id, hint, buf, bufSize);
    if (icons) {
        ImGui::PopStyleVar();
        // Magnifier inside the frame's left padding, vertically centered.
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(p.x + st.FramePadding.x, p.y + st.FramePadding.y),
            ImGui::GetColorU32(theme::col::muted()), DS_ICON_SEARCH);
    }
    return r;
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
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f * s);
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
    if (tip && tip[0] && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("%s", tip);
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
    const float h    = 30.0f * s;
    const float w    = ts.x + padX * 2.0f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool clicked = ImGui::InvisibleButton(id, ImVec2(w, h));
    bool hovered = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(theme::col::panelHeader()), 6.0f * s);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(hovered ? theme::col::accent() : theme::col::line()),
                6.0f * s, 0, 1.0f);
    const ImVec4 tc = valueCol ? *valueCol : ImGui::GetStyleColorVec4(ImGuiCol_Text);
    PushMono();
    dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
                ImVec2(p.x + padX, p.y + (h - ts.y) * 0.5f), ImGui::GetColorU32(tc), text);
    PopMono();
    if (tip && tip[0] && hovered) ImGui::SetTooltip("%s", tip);
    return clicked;
}

void StatePill(const char* state, const ImVec4& stateCol, const char* detail) {
    const float s = theme::UiScale();
    PushMono();
    const ImVec2 st = ImGui::CalcTextSize(state);
    const ImVec2 dt = (detail && detail[0]) ? ImGui::CalcTextSize(detail) : ImVec2(0, 0);
    PopMono();
    const float padX = 12.0f * s, gap = (dt.x > 0 ? 8.0f * s : 0.0f);
    const float h = 30.0f * s;
    const float w = st.x + dt.x + gap + padX * 2.0f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                      ImGui::GetColorU32(theme::col::panelHeader()), 6.0f * s);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ImGui::GetColorU32(ImVec4(stateCol.x, stateCol.y, stateCol.z, 0.65f)),
                6.0f * s, 0, 1.0f);
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
    const float s = theme::UiScale();
    const float h = 27.0f * s;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p0    = ImGui::GetCursorScreenPos();
    const float  fullW = ImGui::GetContentRegionAvail().x;

    // Strip background + bottom border (wf-tabstrip).
    dl->AddRectFilled(p0, ImVec2(p0.x + fullW, p0.y + h),
                      ImGui::GetColorU32(theme::col::panelHeader()));
    dl->AddLine(ImVec2(p0.x, p0.y + h), ImVec2(p0.x + fullW, p0.y + h),
                ImGui::GetColorU32(theme::col::line()), 1.0f * s);

    int result = active;
    float x = p0.x;
    ImGui::PushID(id);
    for (int i = 0; i < count; ++i) {
        const bool en = !enabled || enabled[i];
        const ImVec2 ts = ImGui::CalcTextSize(labels[i]);
        const float w = ts.x + 22.0f * s;
        ImGui::SetCursorScreenPos(ImVec2(x, p0.y));
        ImGui::PushID(i);
        bool clicked = ImGui::InvisibleButton("##tab", ImVec2(w, h));
        bool hovered = ImGui::IsItemHovered();
        ImGui::PopID();
        if (clicked && en) result = i;

        if (i == active) {
            // Active tab: panel fill + 2px accent underline (wf-tab.is-active).
            dl->AddRectFilled(ImVec2(x, p0.y), ImVec2(x + w, p0.y + h),
                              ImGui::GetColorU32(theme::col::panel()));
            dl->AddRectFilled(ImVec2(x, p0.y + h - 2.0f * s), ImVec2(x + w, p0.y + h),
                              ImGui::GetColorU32(theme::col::accent()));
        }
        ImVec4 tc = !en           ? ImVec4(theme::col::muted().x, theme::col::muted().y,
                                           theme::col::muted().z, 0.55f)
                  : i == active   ? ImGui::GetStyleColorVec4(ImGuiCol_Text)
                  : hovered       ? ImGui::GetStyleColorVec4(ImGuiCol_Text)
                                  : theme::col::muted();
        dl->AddText(ImVec2(x + 11.0f * s, p0.y + (h - ts.y) * 0.5f),
                    ImGui::GetColorU32(tc), labels[i]);
        // Soft separator on the tab's right edge.
        dl->AddLine(ImVec2(x + w, p0.y + 5.0f * s), ImVec2(x + w, p0.y + h - 5.0f * s),
                    ImGui::GetColorU32(theme::col::lineSoft()), 1.0f);
        x += w;
    }
    ImGui::PopID();

    // Claim the full strip rect in the layout.
    ImGui::SetCursorScreenPos(p0);
    ImGui::Dummy(ImVec2(fullW, h));
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

    // Vertical centering, weighted slightly above center like the welcome hero.
    float blockH = ImGui::GetTextLineHeight();                       // title
    if (hasIcon) blockH += gIconFontLarge->FontSize + 10.0f * s;
    if (hasSub)  blockH += ImGui::GetTextLineHeightWithSpacing();
    if (hasBtn)  blockH += ImGui::GetFrameHeight() + 16.0f * s;
    float topPad = (avail.y - blockH) * 0.40f;
    if (topPad > 0.0f) ImGui::Dummy(ImVec2(0, topPad));

    auto centerX = [&](float w) {
        float off = (avail.x - w) * 0.5f;
        if (off > 0.0f) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + off);
    };

    if (hasIcon) {
        ImGui::PushFont(gIconFontLarge);
        centerX(ImGui::CalcTextSize(icon).x);
        ImGui::TextColored(theme::col::accent(), "%s", icon);
        ImGui::PopFont();
        ImGui::Dummy(ImVec2(0, 10.0f * s));
    }
    centerX(ImGui::CalcTextSize(title).x);
    ImGui::TextUnformatted(title);
    if (hasSub) {
        centerX(ImGui::CalcTextSize(subtitle).x);
        ImGui::TextDisabled("%s", subtitle);
    }
    bool clicked = false;
    if (hasBtn) {
        ImGui::Dummy(ImVec2(0, 16.0f * s));
        const ImGuiStyle& st = ImGui::GetStyle();
        float btnW = std::max(180.0f * s, ImGui::CalcTextSize(primaryButtonLabel).x + st.FramePadding.x * 4.0f);
        const ImVec4 acc = theme::col::accent();
        ImGui::PushStyleColor(ImGuiCol_Button,        Dim(acc, 0.85f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, acc);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  Dim(acc, 0.70f));
        ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(1, 1, 1, 1));
        centerX(btnW);
        clicked = ImGui::Button(primaryButtonLabel, ImVec2(btnW, 0));
        ImGui::PopStyleColor(4);
    }
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
    const float margin = 12.0f * s, cardW = 340.0f * s, barW = 4.0f * s, pad = 10.0f * s;
    ImGuiViewport* vp = ImGui::GetMainViewport();
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
