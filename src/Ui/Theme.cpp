#include "Theme.h"
#include "imgui.h"

#include <algorithm>
#include <cmath>

namespace ds::theme {

// A theme is just a small set of core colors; the full ImGui style is derived
// from them in applyColors() so every palette stays internally consistent.
namespace {

struct Palette {
    ImVec4 bg0, bg1, bg2, bg3;   // window / frame / hovered / active backgrounds
    ImVec4 child, popup, menubar;
    ImVec4 text, muted, border;
    ImVec4 accent, good, warn, bad, call, branch, jump;
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
            // DisasmStudio Midnight: near-black navy canvas, subtly lifted
            // graphite panels, crisp blue-gray dividers, and one cyan-blue
            // interaction accent.  The restrained surface contrast keeps dense
            // disassembly and data tables readable without looking like a stack
            // of unrelated cards.
            p.bg0=V(0.024f,0.047f,0.066f); p.bg1=V(0.041f,0.078f,0.106f);
            p.bg2=V(0.063f,0.129f,0.176f); p.bg3=V(0.082f,0.184f,0.255f);
            p.child=V(0.029f,0.059f,0.082f); p.popup=V(0.020f,0.041f,0.058f,0.985f); p.menubar=V(0.027f,0.055f,0.075f);
            p.text=V(0.855f,0.894f,0.925f); p.muted=V(0.500f,0.570f,0.630f); p.border=V(0.122f,0.196f,0.251f);
            p.accent=V(0.055f,0.553f,0.890f); p.good=V(0.302f,0.773f,0.420f); p.warn=V(0.945f,0.690f,0.251f);
            p.bad=V(0.965f,0.294f,0.263f); p.call=V(0.235f,0.671f,0.973f); p.branch=V(0.945f,0.735f,0.345f);
            p.jump=V(0.690f,0.455f,0.941f);
            break;
        case ThemeId::Slate:
            p.bg0=V(0.110f,0.118f,0.128f); p.bg1=V(0.150f,0.160f,0.172f);
            p.bg2=V(0.190f,0.202f,0.216f); p.bg3=V(0.238f,0.252f,0.268f);
            p.child=V(0.128f,0.136f,0.148f); p.popup=V(0.098f,0.105f,0.115f,0.98f); p.menubar=V(0.140f,0.150f,0.162f);
            p.text=V(0.88f,0.89f,0.90f); p.muted=V(0.55f,0.57f,0.60f); p.border=V(0.30f,0.32f,0.34f,0.60f);
            p.accent=V(0.30f,0.74f,0.72f); p.good=V(0.45f,0.82f,0.52f); p.warn=V(0.92f,0.73f,0.36f);
            p.bad=V(0.90f,0.46f,0.46f); p.call=V(0.45f,0.80f,0.78f); p.branch=V(0.93f,0.76f,0.42f);
            p.jump=V(0.76f,0.56f,0.92f);
            break;
        case ThemeId::Light:
            p.bg0=V(0.935f,0.945f,0.960f); p.bg1=V(0.985f,0.990f,1.000f);
            p.bg2=V(0.900f,0.920f,0.950f); p.bg3=V(0.820f,0.860f,0.920f);
            p.child=V(0.965f,0.975f,0.988f); p.popup=V(1.000f,1.000f,1.000f,0.98f); p.menubar=V(0.900f,0.918f,0.945f);
            p.text=V(0.12f,0.14f,0.18f); p.muted=V(0.40f,0.43f,0.48f); p.border=V(0.68f,0.72f,0.78f,0.85f);
            p.accent=V(0.16f,0.50f,0.92f); p.good=V(0.16f,0.60f,0.30f); p.warn=V(0.78f,0.54f,0.10f);
            p.bad=V(0.82f,0.25f,0.25f); p.call=V(0.13f,0.44f,0.84f); p.branch=V(0.66f,0.44f,0.06f);
            p.jump=V(0.52f,0.22f,0.78f);
            p.light=true;
            break;
        case ThemeId::Monokai:
            p.bg0=V(0.157f,0.157f,0.137f); p.bg1=V(0.200f,0.200f,0.176f);
            p.bg2=V(0.243f,0.243f,0.212f); p.bg3=V(0.298f,0.298f,0.259f);
            p.child=V(0.176f,0.176f,0.153f); p.popup=V(0.137f,0.137f,0.118f,0.98f); p.menubar=V(0.188f,0.188f,0.165f);
            p.text=V(0.95f,0.95f,0.90f); p.muted=V(0.55f,0.55f,0.50f); p.border=V(0.33f,0.33f,0.28f,0.60f);
            p.accent=V(0.65f,0.89f,0.18f); p.good=V(0.65f,0.89f,0.18f); p.warn=V(0.99f,0.59f,0.12f);
            p.bad=V(0.98f,0.15f,0.45f); p.call=V(0.40f,0.85f,0.94f); p.branch=V(0.99f,0.84f,0.36f);
            p.jump=V(0.68f,0.51f,0.98f);
            break;
        case ThemeId::SolarizedDark:
            p.bg0=V(0.000f,0.169f,0.212f); p.bg1=V(0.027f,0.212f,0.259f);
            p.bg2=V(0.063f,0.259f,0.310f); p.bg3=V(0.102f,0.310f,0.360f);
            p.child=V(0.012f,0.188f,0.235f); p.popup=V(0.000f,0.149f,0.188f,0.98f); p.menubar=V(0.027f,0.212f,0.259f);
            p.text=V(0.58f,0.63f,0.63f); p.muted=V(0.40f,0.48f,0.51f); p.border=V(0.10f,0.31f,0.36f,0.70f);
            p.accent=V(0.149f,0.545f,0.824f); p.good=V(0.522f,0.600f,0.000f); p.warn=V(0.710f,0.537f,0.000f);
            p.bad=V(0.863f,0.196f,0.184f); p.call=V(0.165f,0.631f,0.596f); p.branch=V(0.827f,0.212f,0.510f);
            p.jump=V(0.424f,0.443f,0.769f);
            break;
        case ThemeId::Dracula:
            p.bg0=V(0.157f,0.165f,0.212f); p.bg1=V(0.196f,0.207f,0.275f);
            p.bg2=V(0.239f,0.251f,0.329f); p.bg3=V(0.290f,0.310f,0.408f);
            p.child=V(0.176f,0.184f,0.243f); p.popup=V(0.137f,0.145f,0.188f,0.98f); p.menubar=V(0.188f,0.200f,0.267f);
            p.text=V(0.95f,0.95f,0.96f); p.muted=V(0.55f,0.56f,0.66f); p.border=V(0.33f,0.34f,0.44f,0.60f);
            p.accent=V(0.741f,0.576f,0.976f); p.good=V(0.314f,0.980f,0.482f); p.warn=V(0.945f,0.980f,0.549f);
            p.bad=V(1.000f,0.333f,0.400f); p.call=V(0.545f,0.914f,0.992f); p.branch=V(1.000f,0.722f,0.424f);
            p.jump=V(1.000f,0.475f,0.776f);
            break;
        case ThemeId::Nord:
            p.bg0=V(0.180f,0.204f,0.251f); p.bg1=V(0.231f,0.259f,0.322f);
            p.bg2=V(0.263f,0.298f,0.369f); p.bg3=V(0.302f,0.341f,0.420f);
            p.child=V(0.204f,0.231f,0.282f); p.popup=V(0.157f,0.180f,0.227f,0.98f); p.menubar=V(0.220f,0.247f,0.310f);
            p.text=V(0.85f,0.87f,0.91f); p.muted=V(0.50f,0.55f,0.62f); p.border=V(0.30f,0.34f,0.42f,0.60f);
            p.accent=V(0.506f,0.631f,0.757f); p.good=V(0.639f,0.745f,0.549f); p.warn=V(0.922f,0.796f,0.545f);
            p.bad=V(0.749f,0.380f,0.416f); p.call=V(0.561f,0.737f,0.733f); p.branch=V(0.851f,0.616f,0.510f);
            p.jump=V(0.706f,0.557f,0.678f);
            break;
        case ThemeId::Matrix:
            p.bg0=V(0.020f,0.040f,0.020f); p.bg1=V(0.040f,0.070f,0.040f);
            p.bg2=V(0.060f,0.110f,0.060f); p.bg3=V(0.090f,0.160f,0.090f);
            p.child=V(0.030f,0.050f,0.030f); p.popup=V(0.012f,0.030f,0.012f,0.98f); p.menubar=V(0.040f,0.080f,0.040f);
            p.text=V(0.40f,0.95f,0.45f); p.muted=V(0.30f,0.55f,0.32f); p.border=V(0.12f,0.30f,0.14f,0.70f);
            p.accent=V(0.20f,0.90f,0.30f); p.good=V(0.30f,0.95f,0.40f); p.warn=V(0.85f,0.95f,0.30f);
            p.bad=V(0.95f,0.45f,0.30f); p.call=V(0.40f,0.95f,0.55f); p.branch=V(0.70f,0.95f,0.40f);
            p.jump=V(0.35f,0.90f,0.80f);
            break;
        case ThemeId::Paper:
            // Warm paper + ink with an amber accent (the wireframe palette):
            // page = warm off-white, panels slightly brighter, lines are soft
            // warm grays, and the single accent is amber.
            p.bg0=V(0.925f,0.918f,0.894f); p.bg1=V(0.938f,0.931f,0.908f);
            p.bg2=V(0.905f,0.896f,0.868f); p.bg3=V(0.862f,0.850f,0.816f);
            p.child=V(0.972f,0.966f,0.948f); p.popup=V(0.984f,0.980f,0.964f,0.98f); p.menubar=V(0.938f,0.931f,0.908f);
            p.text=V(0.245f,0.230f,0.200f); p.muted=V(0.520f,0.500f,0.455f); p.border=V(0.700f,0.685f,0.640f,0.95f);
            p.accent=V(0.875f,0.565f,0.220f); p.good=V(0.270f,0.560f,0.300f); p.warn=V(0.760f,0.520f,0.090f);
            p.bad=V(0.780f,0.270f,0.230f); p.call=V(0.230f,0.430f,0.700f); p.branch=V(0.700f,0.460f,0.090f);
            p.jump=V(0.530f,0.290f,0.700f);
            p.light=true;
            break;
    }
    return p;
}

// Current theme + its resolved palette. Initialized to the default so the col::*
// helpers are valid even before ApplyTheme() is first called.
static ThemeId g_theme   = ThemeId::Midnight;
static Palette g_pal     = PaletteFor(ThemeId::Midnight);
static float   g_scale   = 1.0f;   // HiDPI UI scale (1.0 = 96 DPI)
static Density g_density = Density::Compact;       // dense RE-workbench default

// Spacing/padding multiplier for the current density (applied on top of HiDPI k).
// Comfortable = 1.0 is the baseline; Compact is intentionally information-dense.
static float densityFactor() {
    switch (g_density) {
        case Density::Compact:  return 0.82f;
        case Density::Spacious: return 1.18f;
        default:                return 1.0f;
    }
}

static void applyMetrics() {
    ImGuiStyle& s = ImGui::GetStyle();
    const float k = g_scale;     // scale every pixel metric so HiDPI stays crisp
    const float d = k * densityFactor();   // spacing/padding also scale with density
    // Borders are rasterized as lines, so keep their physical thickness on an
    // integer pixel even at fractional Windows DPI scales (125%, 150%, ...).
    const float linePx = std::max(1.0f, std::round(k));
    const float separatorPx = linePx;
    // Workbench surfaces are contiguous IDE panes, not floating cards.  Keep
    // rounding for dialogs/popups, but make child panels and tabs share crisp
    // square edges like the approved desktop concept.
    s.WindowRounding    = 4.0f * k;
    s.ChildRounding     = 0.0f;
    s.FrameRounding     = 2.0f * k;
    s.PopupRounding     = 4.0f * k;
    s.ScrollbarRounding = 2.0f * k;
    s.GrabRounding      = 2.0f * k;
    s.TabRounding       = 0.0f;

    s.WindowBorderSize  = linePx;
    s.ChildBorderSize   = linePx;
    s.FrameBorderSize   = linePx;
    s.TabBorderSize     = 0.0f;
    s.PopupBorderSize   = linePx;

    s.WindowPadding     = ImVec2(7.0f * d, 6.0f * d);
    s.FramePadding      = ImVec2(7.0f * d, 3.0f * d);
    s.CellPadding       = ImVec2(7.0f * d, 2.0f * d);
    s.ItemSpacing       = ImVec2(7.0f * d, 4.0f * d);
    s.ItemInnerSpacing  = ImVec2(5.0f * d, 3.0f * d);
    s.IndentSpacing     = 16.0f * d;
    s.ScrollbarSize     = 11.0f * d;
    s.GrabMinSize       = 9.0f * d;

    s.WindowTitleAlign  = ImVec2(0.0f, 0.5f);
    s.WindowMenuButtonPosition = ImGuiDir_None;
    s.SeparatorTextBorderSize = separatorPx;
}

static void applyColors(const Palette& p) {
    ImVec4* c = ImGui::GetStyle().Colors;
    const ImVec4 acc    = p.accent;
    const ImVec4 accDim = ImVec4(acc.x, acc.y, acc.z, 0.34f);
    const ImVec4 accSoft = mix(p.bg1, acc, 0.22f);
    const ImVec4 rowAlt = mix(p.child, p.bg1, 0.34f);

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
    c[ImGuiCol_Button]                = mix(p.bg1, p.bg2, 0.38f);
    c[ImGuiCol_ButtonHovered]         = mix(p.bg1, acc, 0.42f);
    c[ImGuiCol_ButtonActive]          = mix(p.bg1, acc, 0.68f);
    c[ImGuiCol_Header]                = accSoft;
    c[ImGuiCol_HeaderHovered]         = mix(p.bg1, acc, 0.42f);
    c[ImGuiCol_HeaderActive]          = mix(p.bg1, acc, 0.58f);
    c[ImGuiCol_Separator]             = p.border;
    c[ImGuiCol_SeparatorHovered]      = accDim;
    c[ImGuiCol_SeparatorActive]       = acc;
    c[ImGuiCol_ResizeGrip]            = mix(p.bg2, p.bg0, 0.30f);
    c[ImGuiCol_ResizeGripHovered]     = accDim;
    c[ImGuiCol_ResizeGripActive]      = acc;
    c[ImGuiCol_Tab]                   = mix(p.bg0, p.bg1, 0.58f);
    c[ImGuiCol_TabHovered]            = mix(p.bg1, acc, 0.38f);
    c[ImGuiCol_TabActive]             = mix(p.bg1, acc, 0.24f);
    c[ImGuiCol_TabUnfocused]          = p.bg0;
    c[ImGuiCol_TabUnfocusedActive]    = mix(p.bg1, acc, 0.12f);
    c[ImGuiCol_TableHeaderBg]         = mix(p.bg1, p.bg2, 0.34f);
    c[ImGuiCol_TableBorderStrong]     = p.border;
    c[ImGuiCol_TableBorderLight]      = mix(p.border, p.bg1, 0.38f);
    c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]         = p.light ? ImVec4(0, 0, 0, 0.030f) : rowAlt;
    c[ImGuiCol_TextSelectedBg]        = accDim;
    c[ImGuiCol_DragDropTarget]        = p.warn;
    c[ImGuiCol_NavHighlight]          = acc;
    c[ImGuiCol_PlotLines]             = p.call;
    c[ImGuiCol_PlotLinesHovered]      = p.warn;
    c[ImGuiCol_PlotHistogram]         = p.accent;
    c[ImGuiCol_PlotHistogramHovered]  = p.warn;
    c[ImGuiCol_NavWindowingHighlight] = p.text;
    c[ImGuiCol_NavWindowingDimBg]     = ImVec4(0.0f, 0.0f, 0.0f, p.light ? 0.12f : 0.32f);
    c[ImGuiCol_ModalWindowDimBg]      = ImVec4(0.0f, 0.0f, 0.0f, p.light ? 0.18f : 0.54f);
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
        case ThemeId::Paper:         return "Paper";
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
    ImVec4 jump()      { return g_pal.jump; }
    ImVec4 selection() { return ImVec4(g_pal.accent.x, g_pal.accent.y, g_pal.accent.z, 1.0f); }
    ImVec4 menubar()   { return g_pal.menubar; }
    ImVec4 windowBg()  { return g_pal.bg0; }

    ImVec4 panel()       { return g_pal.child; }
    ImVec4 panelHeader() { return g_pal.menubar; }
    ImVec4 line()        { return ImVec4(g_pal.border.x, g_pal.border.y, g_pal.border.z, 1.0f); }
    ImVec4 lineSoft()    { return mix(g_pal.border, g_pal.bg1, 0.45f); }
}

} // namespace ds::theme
