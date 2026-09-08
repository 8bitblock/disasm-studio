#include "Theme.h"
#include "Core/Preferences.h"
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
            // Graphite surfaces keep code and data in the foreground. Preserve
            // the established semantic colors: breakpoint, execution, call and
            // branch glows must remain recognizable against the quieter chrome.
            p.bg0=V(0.067f,0.075f,0.086f); p.bg1=V(0.094f,0.106f,0.122f);
            p.bg2=V(0.137f,0.153f,0.176f); p.bg3=V(0.192f,0.212f,0.239f);
            p.child=V(0.078f,0.086f,0.102f); p.popup=V(0.094f,0.106f,0.122f,0.995f); p.menubar=V(0.094f,0.106f,0.122f);
            // The release design uses readable secondary labels on the same
            // graphite surfaces; dim addresses and disabled controls must not
            // make the feature inventory disappear into the surrounding chrome.
            p.text=V(0.855f,0.878f,0.906f); p.muted=V(0.631f,0.667f,0.722f); p.border=V(0.180f,0.200f,0.231f);
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
            p.text=V(0.12f,0.14f,0.18f); p.muted=V(0.38f,0.41f,0.46f); p.border=V(0.68f,0.72f,0.78f,0.85f);
            p.accent=V(0.10f,0.39f,0.75f); p.good=V(0.12f,0.43f,0.23f); p.warn=V(0.57f,0.36f,0.04f);
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
            // Warm paper + ink with an amber accent:
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
        case ThemeId::Axiom:
            // Sampled from the user's component references. Color identifies
            // selection and real state; broad surfaces stay near-black.
            p.bg0=V(14/255.f,20/255.f,29/255.f); p.bg1=V(21/255.f,29/255.f,40/255.f);
            p.bg2=V(26/255.f,39/255.f,56/255.f); p.bg3=V(35/255.f,53/255.f,74/255.f);
            p.child=V(13/255.f,19/255.f,27/255.f); p.popup=V(17/255.f,24/255.f,33/255.f);
            p.menubar=V(14/255.f,20/255.f,29/255.f);
            p.text=V(230/255.f,237/255.f,247/255.f); p.muted=V(145/255.f,164/255.f,188/255.f);
            p.border=V(28/255.f,38/255.f,52/255.f);
            p.accent=V(125/255.f,184/255.f,255/255.f); p.good=V(86/255.f,221/255.f,187/255.f);
            p.warn=V(246/255.f,196/255.f,83/255.f); p.bad=V(255/255.f,96/255.f,120/255.f);
            p.call=V(107/255.f,217/255.f,234/255.f); p.branch=V(191/255.f,160/255.f,255/255.f);
            p.jump=V(177/255.f,144/255.f,242/255.f);
            break;
    }
    return p;
}

// Current theme + its resolved palette. Initialized to the default so the col::*
// helpers are valid even before ApplyTheme() is first called.
static ThemeId g_theme   = ThemeId::Midnight;
static Palette g_pal     = PaletteFor(ThemeId::Midnight);
static float   g_scale   = 1.0f;   // HiDPI UI scale (1.0 = 96 DPI)
static int     g_zoomPercent = kDefaultUiZoomPercent;
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
    // Round compact controls and selection rows, while structural panes stay
    // contiguous like the user's references. Geometry is shared by every palette.
    s.WindowRounding    = 6.0f * k;
    s.ChildRounding     = 0.0f;
    s.FrameRounding     = 5.0f * k;
    s.PopupRounding     = 6.0f * k;
    s.ScrollbarRounding = 4.0f * k;
    s.GrabRounding      = 4.0f * k;
    s.TabRounding       = 5.0f * k;

    s.WindowBorderSize  = linePx;
    s.ChildBorderSize   = linePx;
    // A quiet keyline separates compact controls on every palette.
    s.FrameBorderSize   = linePx;
    s.TabBorderSize     = 0.0f;
    s.PopupBorderSize   = linePx;

    s.WindowPadding     = ImVec2(7.0f * d, 6.0f * d);
    s.FramePadding      = ImVec2(7.0f * d, 3.0f * d);
    s.CellPadding       = ImVec2(7.0f * d, 2.0f * d);
    s.ItemSpacing       = ImVec2(7.0f * d, 4.0f * d);
    s.ItemInnerSpacing  = ImVec2(5.0f * d, 3.0f * d);
    s.IndentSpacing     = 16.0f * d;
    // Hit targets scale with DPI, even in Compact density. Density changes the
    // information spacing without making scrolling or sliders harder to grab.
    s.ScrollbarSize     = 12.0f * k;
    s.GrabMinSize       = 12.0f * k;

    s.WindowTitleAlign  = ImVec2(0.0f, 0.5f);
    s.WindowMenuButtonPosition = ImGuiDir_None;
    s.SeparatorTextBorderSize = separatorPx;
    s.SeparatorTextPadding = ImVec2(0.0f, 3.0f * d);
    s.SeparatorTextAlign = ImVec2(0.0f, 0.5f);
}

static void applyColors(const Palette& p) {
    ImVec4* c = ImGui::GetStyle().Colors;
    const ImVec4 acc    = p.accent;
    const ImVec4 accDim = ImVec4(acc.x, acc.y, acc.z, 0.34f);
    const ImVec4 accSoft = mix(p.child, acc, p.light ? 0.17f : 0.15f);
    const ImVec4 softBorder = mix(p.bg1, p.border, 0.60f);

    c[ImGuiCol_Text]                  = p.text;
    c[ImGuiCol_TextDisabled]          = p.muted;
    c[ImGuiCol_WindowBg]              = p.bg0;
    c[ImGuiCol_ChildBg]               = p.child;
    c[ImGuiCol_PopupBg]               = p.popup;
    c[ImGuiCol_Border]                = softBorder;
    c[ImGuiCol_BorderShadow]          = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]               = p.bg1;
    c[ImGuiCol_FrameBgHovered]        = p.bg2;
    c[ImGuiCol_FrameBgActive]         = mix(p.bg2, acc, 0.10f);
    c[ImGuiCol_TitleBg]               = p.bg0;
    c[ImGuiCol_TitleBgActive]         = p.bg1;
    c[ImGuiCol_TitleBgCollapsed]      = p.bg0;
    c[ImGuiCol_MenuBarBg]             = p.menubar;
    c[ImGuiCol_ScrollbarBg]           = p.bg0;
    c[ImGuiCol_ScrollbarGrab]         = p.bg3;
    c[ImGuiCol_ScrollbarGrabHovered]  = mix(p.bg3, p.muted, 0.40f);
    c[ImGuiCol_ScrollbarGrabActive]   = acc;
    c[ImGuiCol_CheckMark]             = acc;
    c[ImGuiCol_SliderGrab]            = acc;
    c[ImGuiCol_SliderGrabActive]      = acc;
    c[ImGuiCol_Button]                = mix(p.bg1, p.bg2, 0.30f);
    c[ImGuiCol_ButtonHovered]         = mix(p.bg2, acc, 0.10f);
    c[ImGuiCol_ButtonActive]          = mix(p.bg2, acc, 0.22f);
    c[ImGuiCol_Header]                = accSoft;
    c[ImGuiCol_HeaderHovered]         = mix(p.bg2, acc, 0.14f);
    c[ImGuiCol_HeaderActive]          = mix(p.bg2, acc, 0.25f);
    c[ImGuiCol_Separator]             = softBorder;
    c[ImGuiCol_SeparatorHovered]      = accDim;
    c[ImGuiCol_SeparatorActive]       = acc;
    c[ImGuiCol_ResizeGrip]            = mix(p.bg2, p.bg0, 0.30f);
    c[ImGuiCol_ResizeGripHovered]     = accDim;
    c[ImGuiCol_ResizeGripActive]      = acc;
    c[ImGuiCol_Tab]                   = p.menubar;
    c[ImGuiCol_TabHovered]            = mix(p.bg2, acc, 0.10f);
    c[ImGuiCol_TabActive]             = mix(p.child, p.bg2, 0.35f);
    c[ImGuiCol_TabSelectedOverline]   = acc;
    c[ImGuiCol_TabUnfocused]          = p.bg0;
    c[ImGuiCol_TabUnfocusedActive]    = p.bg1;
    c[ImGuiCol_TabDimmedSelectedOverline] = mix(p.muted, acc, 0.35f);
    c[ImGuiCol_TableHeaderBg]         = mix(p.menubar, p.bg2, 0.18f);
    c[ImGuiCol_TableBorderStrong]     = softBorder;
    c[ImGuiCol_TableBorderLight]      = mix(p.bg1, p.border, 0.30f);
    c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]         = p.light ? ImVec4(0, 0, 0, 0.020f)
                                               : ImVec4(1, 1, 1, 0.018f);
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

    if (g_theme == ThemeId::Axiom) {
        c[ImGuiCol_Button]            = p.bg1;
        c[ImGuiCol_ButtonHovered]     = p.bg2;
        c[ImGuiCol_ButtonActive]      = p.bg3;
        c[ImGuiCol_FrameBgActive]     = p.bg2;
        c[ImGuiCol_Header]            = V(19/255.f,38/255.f,60/255.f);
        c[ImGuiCol_HeaderHovered]     = V(23/255.f,43/255.f,65/255.f);
        c[ImGuiCol_HeaderActive]      = V(28/255.f,49/255.f,70/255.f);
        c[ImGuiCol_TabHovered]        = p.bg2;
        c[ImGuiCol_TabActive]         = p.bg2;
        c[ImGuiCol_TabUnfocusedActive]= p.bg1;
        c[ImGuiCol_TableHeaderBg]     = p.menubar;
        c[ImGuiCol_TableRowBgAlt]     = ImVec4(1, 1, 1, 0.012f);
        c[ImGuiCol_TextSelectedBg]    = ImVec4(acc.x, acc.y, acc.z, 0.26f);
    }
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

void SetUiZoomPercent(int percent) {
    g_zoomPercent = std::clamp(percent, kMinUiZoomPercent, kMaxUiZoomPercent);
}
int UiZoomPercent() { return g_zoomPercent; }

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
        case ThemeId::Axiom:         return "Axiom";
        default:                     return "?";
    }
}

namespace col {
    ImVec4 accent()    { return g_pal.accent; }
    ImVec4 accentAlt() { return g_pal.accent; }
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
    ImVec4 code()        { return g_theme == ThemeId::Axiom ? g_pal.bg0 : g_pal.child; }
    ImVec4 breakpointFill() { return g_theme == ThemeId::Axiom
        ? V(44/255.f,22/255.f,28/255.f) : mix(g_pal.child, g_pal.bad, 0.12f); }
    ImVec4 breakpointOutline() { return g_theme == ThemeId::Axiom
        ? V(78/255.f,34/255.f,43/255.f) : mix(g_pal.border, g_pal.bad, 0.30f); }
    ImVec4 pauseSurface() { return g_theme == ThemeId::Axiom
        ? V(37/255.f,30/255.f,16/255.f) : mix(g_pal.child, g_pal.warn, 0.08f); }
    ImVec4 line()        { return ImVec4(g_pal.border.x, g_pal.border.y, g_pal.border.z, 1.0f); }
    ImVec4 lineSoft()    { return mix(g_pal.border, g_pal.bg1, 0.60f); }
}

} // namespace ds::theme
