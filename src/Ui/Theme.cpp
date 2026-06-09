#include "Theme.h"
#include "imgui.h"

namespace ds::theme {

// A theme is just a small set of core colors; the full ImGui style is derived
// from them in applyColors() so every palette stays internally consistent.
namespace {

struct Palette {
    ImVec4 bg0, bg1, bg2, bg3;   // window / frame / hovered / active backgrounds
    ImVec4 child, popup, menubar;
    ImVec4 text, muted, border;
    ImVec4 accent, good, warn, bad, call, branch;
    bool   light = false;
};

static ImVec4 V(float r, float g, float b, float a = 1.0f) { return ImVec4(r, g, b, a); }
static ImVec4 mix(const ImVec4& a, const ImVec4& b, float t) {
    return ImVec4(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t,
                  a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t);
}

static Palette PaletteFor(ThemeId id) {
    Palette p;
    switch (id) {
        default:
        case ThemeId::Midnight:
            p.bg0=V(0.082f,0.090f,0.110f); p.bg1=V(0.110f,0.120f,0.145f);
            p.bg2=V(0.145f,0.158f,0.190f); p.bg3=V(0.180f,0.196f,0.235f);
            p.child=V(0.095f,0.103f,0.125f); p.popup=V(0.075f,0.082f,0.100f,0.98f); p.menubar=V(0.105f,0.114f,0.138f);
            p.text=V(0.90f,0.91f,0.93f); p.muted=V(0.55f,0.58f,0.64f); p.border=V(0.24f,0.26f,0.30f,0.60f);
            p.accent=V(0.26f,0.59f,0.98f); p.good=V(0.40f,0.85f,0.50f); p.warn=V(0.95f,0.74f,0.35f);
            p.bad=V(0.93f,0.45f,0.45f); p.call=V(0.45f,0.72f,1.00f); p.branch=V(0.95f,0.78f,0.42f);
            break;
        case ThemeId::Slate:
            p.bg0=V(0.110f,0.118f,0.128f); p.bg1=V(0.150f,0.160f,0.172f);
            p.bg2=V(0.190f,0.202f,0.216f); p.bg3=V(0.238f,0.252f,0.268f);
            p.child=V(0.128f,0.136f,0.148f); p.popup=V(0.098f,0.105f,0.115f,0.98f); p.menubar=V(0.140f,0.150f,0.162f);
            p.text=V(0.88f,0.89f,0.90f); p.muted=V(0.55f,0.57f,0.60f); p.border=V(0.30f,0.32f,0.34f,0.60f);
            p.accent=V(0.30f,0.74f,0.72f); p.good=V(0.45f,0.82f,0.52f); p.warn=V(0.92f,0.73f,0.36f);
            p.bad=V(0.90f,0.46f,0.46f); p.call=V(0.45f,0.80f,0.78f); p.branch=V(0.93f,0.76f,0.42f);
            break;
        case ThemeId::Light:
            p.bg0=V(0.935f,0.945f,0.960f); p.bg1=V(0.985f,0.990f,1.000f);
            p.bg2=V(0.900f,0.920f,0.950f); p.bg3=V(0.820f,0.860f,0.920f);
            p.child=V(0.965f,0.975f,0.988f); p.popup=V(1.000f,1.000f,1.000f,0.98f); p.menubar=V(0.900f,0.918f,0.945f);
            p.text=V(0.12f,0.14f,0.18f); p.muted=V(0.40f,0.43f,0.48f); p.border=V(0.68f,0.72f,0.78f,0.85f);
            p.accent=V(0.16f,0.50f,0.92f); p.good=V(0.16f,0.60f,0.30f); p.warn=V(0.78f,0.54f,0.10f);
            p.bad=V(0.82f,0.25f,0.25f); p.call=V(0.13f,0.44f,0.84f); p.branch=V(0.66f,0.44f,0.06f);
            p.light=true;
            break;
        case ThemeId::Monokai:
            p.bg0=V(0.157f,0.157f,0.137f); p.bg1=V(0.200f,0.200f,0.176f);
            p.bg2=V(0.243f,0.243f,0.212f); p.bg3=V(0.298f,0.298f,0.259f);
            p.child=V(0.176f,0.176f,0.153f); p.popup=V(0.137f,0.137f,0.118f,0.98f); p.menubar=V(0.188f,0.188f,0.165f);
            p.text=V(0.95f,0.95f,0.90f); p.muted=V(0.55f,0.55f,0.50f); p.border=V(0.33f,0.33f,0.28f,0.60f);
            p.accent=V(0.65f,0.89f,0.18f); p.good=V(0.65f,0.89f,0.18f); p.warn=V(0.99f,0.59f,0.12f);
            p.bad=V(0.98f,0.15f,0.45f); p.call=V(0.40f,0.85f,0.94f); p.branch=V(0.99f,0.84f,0.36f);
            break;
        case ThemeId::SolarizedDark:
            p.bg0=V(0.000f,0.169f,0.212f); p.bg1=V(0.027f,0.212f,0.259f);
            p.bg2=V(0.063f,0.259f,0.310f); p.bg3=V(0.102f,0.310f,0.360f);
            p.child=V(0.012f,0.188f,0.235f); p.popup=V(0.000f,0.149f,0.188f,0.98f); p.menubar=V(0.027f,0.212f,0.259f);
            p.text=V(0.58f,0.63f,0.63f); p.muted=V(0.40f,0.48f,0.51f); p.border=V(0.10f,0.31f,0.36f,0.70f);
            p.accent=V(0.149f,0.545f,0.824f); p.good=V(0.522f,0.600f,0.000f); p.warn=V(0.710f,0.537f,0.000f);
            p.bad=V(0.863f,0.196f,0.184f); p.call=V(0.165f,0.631f,0.596f); p.branch=V(0.827f,0.212f,0.510f);
            break;
        case ThemeId::Dracula:
            p.bg0=V(0.157f,0.165f,0.212f); p.bg1=V(0.196f,0.207f,0.275f);
            p.bg2=V(0.239f,0.251f,0.329f); p.bg3=V(0.290f,0.310f,0.408f);
            p.child=V(0.176f,0.184f,0.243f); p.popup=V(0.137f,0.145f,0.188f,0.98f); p.menubar=V(0.188f,0.200f,0.267f);
            p.text=V(0.95f,0.95f,0.96f); p.muted=V(0.55f,0.56f,0.66f); p.border=V(0.33f,0.34f,0.44f,0.60f);
            p.accent=V(0.741f,0.576f,0.976f); p.good=V(0.314f,0.980f,0.482f); p.warn=V(0.945f,0.980f,0.549f);
            p.bad=V(1.000f,0.333f,0.400f); p.call=V(0.545f,0.914f,0.992f); p.branch=V(1.000f,0.722f,0.424f);
            break;
        case ThemeId::Nord:
            p.bg0=V(0.180f,0.204f,0.251f); p.bg1=V(0.231f,0.259f,0.322f);
            p.bg2=V(0.263f,0.298f,0.369f); p.bg3=V(0.302f,0.341f,0.420f);
            p.child=V(0.204f,0.231f,0.282f); p.popup=V(0.157f,0.180f,0.227f,0.98f); p.menubar=V(0.220f,0.247f,0.310f);
            p.text=V(0.85f,0.87f,0.91f); p.muted=V(0.50f,0.55f,0.62f); p.border=V(0.30f,0.34f,0.42f,0.60f);
            p.accent=V(0.506f,0.631f,0.757f); p.good=V(0.639f,0.745f,0.549f); p.warn=V(0.922f,0.796f,0.545f);
            p.bad=V(0.749f,0.380f,0.416f); p.call=V(0.561f,0.737f,0.733f); p.branch=V(0.851f,0.616f,0.510f);
            break;
        case ThemeId::Matrix:
            p.bg0=V(0.020f,0.040f,0.020f); p.bg1=V(0.040f,0.070f,0.040f);
            p.bg2=V(0.060f,0.110f,0.060f); p.bg3=V(0.090f,0.160f,0.090f);
            p.child=V(0.030f,0.050f,0.030f); p.popup=V(0.012f,0.030f,0.012f,0.98f); p.menubar=V(0.040f,0.080f,0.040f);
            p.text=V(0.40f,0.95f,0.45f); p.muted=V(0.30f,0.55f,0.32f); p.border=V(0.12f,0.30f,0.14f,0.70f);
            p.accent=V(0.20f,0.90f,0.30f); p.good=V(0.30f,0.95f,0.40f); p.warn=V(0.85f,0.95f,0.30f);
            p.bad=V(0.95f,0.45f,0.30f); p.call=V(0.40f,0.95f,0.55f); p.branch=V(0.70f,0.95f,0.40f);
            break;
    }
    return p;
}

// Current theme + its resolved palette. Initialized to the default so the col::*
// helpers are valid even before ApplyTheme() is first called.
static ThemeId g_theme   = ThemeId::Midnight;
static Palette g_pal     = PaletteFor(ThemeId::Midnight);
static float   g_scale   = 1.0f;   // HiDPI UI scale (1.0 = 96 DPI)
static Density g_density = Density::Comfortable;   // roomier default

// Spacing/padding multiplier for the current density (applied on top of HiDPI k).
// Comfortable = 1.0 is the new baseline; Compact is the old tighter look.
static float densityFactor() {
    switch (g_density) {
        case Density::Compact:  return 0.88f;
        case Density::Spacious: return 1.18f;
        default:                return 1.0f;
    }
}

static void applyMetrics() {
    ImGuiStyle& s = ImGui::GetStyle();
    const float k = g_scale;     // scale every pixel metric so HiDPI stays crisp
    const float d = k * densityFactor();   // spacing/padding also scale with density
    s.WindowRounding    = 6.0f * k;
    s.ChildRounding     = 6.0f * k;
    s.FrameRounding     = 5.0f * k;
    s.PopupRounding     = 5.0f * k;
    s.ScrollbarRounding = 9.0f * k;
    s.GrabRounding      = 4.0f * k;
    s.TabRounding       = 6.0f * k;

    s.WindowBorderSize  = 1.0f;
    s.ChildBorderSize   = 1.0f;
    s.FrameBorderSize   = 0.0f;
    s.TabBorderSize     = 0.0f;
    s.PopupBorderSize   = 1.0f;

    s.WindowPadding     = ImVec2(12 * d, 12 * d);
    s.FramePadding      = ImVec2(10 * d, 6 * d);
    s.CellPadding       = ImVec2(8 * d, 5 * d);
    s.ItemSpacing       = ImVec2(10 * d, 8 * d);
    s.ItemInnerSpacing  = ImVec2(8 * d, 6 * d);
    s.IndentSpacing     = 20.0f * d;
    s.ScrollbarSize     = 14.0f * d;
    s.GrabMinSize       = 12.0f * d;

    s.WindowTitleAlign  = ImVec2(0.0f, 0.5f);
    s.WindowMenuButtonPosition = ImGuiDir_None;
    s.SeparatorTextBorderSize = 2.0f;
}

static void applyColors(const Palette& p) {
    ImVec4* c = ImGui::GetStyle().Colors;
    const ImVec4 acc    = p.accent;
    const ImVec4 accDim = ImVec4(acc.x, acc.y, acc.z, 0.40f);

    c[ImGuiCol_Text]                  = p.text;
    c[ImGuiCol_TextDisabled]          = p.muted;
    c[ImGuiCol_WindowBg]              = p.bg0;
    c[ImGuiCol_ChildBg]               = p.child;
    c[ImGuiCol_PopupBg]               = p.popup;
    c[ImGuiCol_Border]                = p.border;
    c[ImGuiCol_BorderShadow]          = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]               = p.bg1;
    c[ImGuiCol_FrameBgHovered]        = p.bg2;
    c[ImGuiCol_FrameBgActive]         = p.bg3;
    c[ImGuiCol_TitleBg]               = p.bg0;
    c[ImGuiCol_TitleBgActive]         = p.bg1;
    c[ImGuiCol_TitleBgCollapsed]      = p.bg0;
    c[ImGuiCol_MenuBarBg]             = p.menubar;
    c[ImGuiCol_ScrollbarBg]           = mix(p.bg0, ImVec4(0, 0, 0, 1), p.light ? 0.04f : 0.20f);
    c[ImGuiCol_ScrollbarGrab]         = p.bg3;
    c[ImGuiCol_ScrollbarGrabHovered]  = mix(p.bg3, acc, 0.40f);
    c[ImGuiCol_ScrollbarGrabActive]   = acc;
    c[ImGuiCol_CheckMark]             = acc;
    c[ImGuiCol_SliderGrab]            = acc;
    c[ImGuiCol_SliderGrabActive]      = acc;
    c[ImGuiCol_Button]                = mix(p.bg1, acc, 0.14f);
    c[ImGuiCol_ButtonHovered]         = mix(p.bg1, acc, 0.50f);
    c[ImGuiCol_ButtonActive]          = acc;
    c[ImGuiCol_Header]                = mix(p.bg1, acc, 0.22f);
    c[ImGuiCol_HeaderHovered]         = mix(p.bg1, acc, 0.50f);
    c[ImGuiCol_HeaderActive]          = accDim;
    c[ImGuiCol_Separator]             = p.border;
    c[ImGuiCol_SeparatorHovered]      = accDim;
    c[ImGuiCol_SeparatorActive]       = acc;
    c[ImGuiCol_ResizeGrip]            = mix(p.bg2, p.bg0, 0.30f);
    c[ImGuiCol_ResizeGripHovered]     = accDim;
    c[ImGuiCol_ResizeGripActive]      = acc;
    c[ImGuiCol_Tab]                   = mix(p.bg0, p.bg1, 0.60f);
    c[ImGuiCol_TabHovered]            = mix(p.bg1, acc, 0.50f);
    c[ImGuiCol_TabActive]             = mix(p.bg1, acc, 0.30f);
    c[ImGuiCol_TabUnfocused]          = p.bg0;
    c[ImGuiCol_TabUnfocusedActive]    = mix(p.bg1, acc, 0.14f);
    c[ImGuiCol_TableHeaderBg]         = mix(p.bg1, p.bg2, 0.50f);
    c[ImGuiCol_TableBorderStrong]     = p.border;
    c[ImGuiCol_TableBorderLight]      = mix(p.border, p.bg1, 0.50f);
    c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]         = p.light ? ImVec4(0, 0, 0, 0.030f) : ImVec4(1, 1, 1, 0.025f);
    c[ImGuiCol_TextSelectedBg]        = accDim;
    c[ImGuiCol_DragDropTarget]        = p.warn;
    c[ImGuiCol_NavHighlight]          = acc;
}

} // namespace

void ApplyTheme(ThemeId id) {
    if (id < ThemeId::Midnight || id >= ThemeId::Count) id = ThemeId::Midnight;
    g_theme = id;
    g_pal   = PaletteFor(id);
    applyMetrics();
    applyColors(g_pal);
}

void ApplyTheme() { ApplyTheme(g_theme); }

void SetUiScale(float scale) { g_scale = (scale > 0.5f && scale < 8.0f) ? scale : 1.0f; }
float UiScale() { return g_scale; }

void    SetDensity(Density d) { g_density = d; }
Density CurrentDensity()      { return g_density; }

const char* DensityName(Density d) {
    switch (d) {
        case Density::Compact:     return "Compact";
        case Density::Comfortable: return "Comfortable";
        case Density::Spacious:    return "Spacious";
        default:                   return "?";
    }
}

ThemeId CurrentTheme() { return g_theme; }

const char* ThemeName(ThemeId id) {
    switch (id) {
        case ThemeId::Midnight:      return "Midnight";
        case ThemeId::Slate:         return "Slate";
        case ThemeId::Light:         return "Light";
        case ThemeId::Monokai:       return "Monokai";
        case ThemeId::SolarizedDark: return "Solarized Dark";
        case ThemeId::Dracula:       return "Dracula";
        case ThemeId::Nord:          return "Nord";
        case ThemeId::Matrix:        return "Matrix";
        default:                     return "?";
    }
}

namespace col {
    ImVec4 accent()    { return g_pal.accent; }
    ImVec4 good()      { return g_pal.good; }
    ImVec4 warn()      { return g_pal.warn; }
    ImVec4 bad()       { return g_pal.bad; }
    ImVec4 muted()     { return g_pal.muted; }
    ImVec4 call()      { return g_pal.call; }
    ImVec4 branch()    { return g_pal.branch; }
    ImVec4 selection() { return ImVec4(g_pal.accent.x, g_pal.accent.y, g_pal.accent.z, 1.0f); }
    ImVec4 menubar()   { return g_pal.menubar; }
    ImVec4 windowBg()  { return g_pal.bg0; }
}

} // namespace ds::theme
