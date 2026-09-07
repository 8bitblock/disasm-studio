#pragma once
//
// Theme.h
// Centralized ImGui visual style for DisasmStudio. Multiple cohesive palettes
// (dark + light) are selectable at runtime; ApplyTheme(id) sets the global style
// plus consistent rounding/spacing. Accent colors are exposed so widgets (debug
// state, breakpoints, call/branch coloring, etc.) stay on-palette per theme.
//
struct ImVec4;

namespace ds::theme {

// Built-in palettes. Keep `Count` last so the menu can iterate the set.
enum class ThemeId {
    Midnight,       // neutral graphite dark, blue accent
    Slate,          // neutral gray dark, teal accent
    Light,          // bright/paper light theme
    Monokai,        // warm dark, green/pink
    SolarizedDark,  // classic solarized base03
    Dracula,        // purple/pink dark
    Nord,           // cold blue-gray
    Matrix,         // black + phosphor green
    Paper,          // warm paper + ink, amber accent
    Count
};

// Apply the current theme (Midnight until ApplyTheme(id) picks another). Call
// once after the ImGui context exists; safe to call again to restyle live.
void ApplyTheme();
// Select + apply a specific theme.
void ApplyTheme(ThemeId id);

ThemeId     CurrentTheme();
const char* ThemeName(ThemeId id);   // human label for menus

// Global UI scale (HiDPI). Set at startup and again when the main window moves
// between monitors; all style metrics (padding/spacing/rounding/scrollbars) are
// derived from fixed baselines in ApplyTheme, so repeated changes never scale
// cumulatively. Fonts are rebuilt separately. Clamped to a sane range.
void  SetUiScale(float scale);
float UiScale();

// User zoom is independent of Windows DPI. Changing it queues a crisp font
// and layout rebuild in the host between frames; UiScale remains the applied
// DPI * zoom until that rebuild, so a frame never mixes two scales.
void SetUiZoomPercent(int percent);
int UiZoomPercent();

// UI density. Only the spacing/padding metrics are scaled by this (on top of the
// HiDPI UiScale); rounding/borders are unaffected. Compact is the workbench
// default so code, tables, and result lists expose more rows. SetDensity takes
// effect on the next ApplyTheme().
enum class Density { Compact, Comfortable, Spacious };
void        SetDensity(Density d);
Density     CurrentDensity();
const char* DensityName(Density d);   // human label for menus

// Shared accent colors (resolved against the *current* theme), so tabs don't
// each invent their own and recolor automatically when the theme changes.
namespace col {
    ImVec4 accent();     // primary accent
    ImVec4 good();       // green (running / ok)
    ImVec4 warn();       // amber (paused / multiple)
    ImVec4 bad();        // red (return / error / breakpoint)
    ImVec4 muted();      // dim text
    ImVec4 call();       // call instructions
    ImVec4 branch();     // branch instructions
    ImVec4 jump();       // jump-TARGET highlight (violet/magenta family, distinct from good/accent)
    ImVec4 selection();  // multi-line selection highlight (RGBA, pre-alpha)
    ImVec4 menubar();    // menu-bar / status-bar background (palette, not hardcoded)
    ImVec4 windowBg();   // primary window background (e.g. the D3D clear color)

    // Shared workbench surfaces and dividers. Semantic highlights above remain
    // independent of this deliberately subdued surrounding chrome.
    ImVec4 panel();        // panel body background (child bg)
    ImVec4 panelHeader();  // panel tab-strip / toolbar background
    ImVec4 line();         // primary pane/widget divider
    ImVec4 lineSoft();     // soft inner divider line
}

} // namespace ds::theme
