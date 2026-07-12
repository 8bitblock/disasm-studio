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
    Midnight,       // deep blue dark
    Slate,          // neutral gray dark, teal accent
    Light,          // bright/paper light theme
    Monokai,        // warm dark, green/pink
    SolarizedDark,  // classic solarized base03
    Dracula,        // purple/pink dark
    Nord,           // cold blue-gray
    Matrix,         // black + phosphor green
    Paper,          // warm paper + ink, amber accent (the wireframe look; default)
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

// UI density. Only the spacing/padding metrics are scaled by this (on top of the
// HiDPI UiScale); rounding/borders are unaffected. Comfortable is the roomier
// default. SetDensity takes effect on the next ApplyTheme().
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

    // Wireframe panel-chrome tokens (used by the ui:: panel/toolbar widgets so
    // the bordered-panel look stays on-palette in every theme).
    ImVec4 panel();        // panel body background (child bg)
    ImVec4 panelHeader();  // panel tab-strip / toolbar-chip background
    ImVec4 line();         // strong panel/widget border ("ink" line)
    ImVec4 lineSoft();     // soft inner divider line
}

} // namespace ds::theme
