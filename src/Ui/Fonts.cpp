#include "Fonts.h"
#include "imgui.h"
#include <fstream>

namespace ds::ui {

ImFont* gUiFont        = nullptr;
ImFont* gMonoFont      = nullptr;
ImFont* gIconFontLarge = nullptr;
static bool gIconsLoaded = false;

bool IconsLoaded() { return gIconsLoaded; }

// Prefer crisp Windows system fonts; fall back to the built-in font. A
// proportional face for the UI, a monospace face for code/hex views, and the
// Segoe MDL2 Assets icon font merged into the UI face (its glyphs live in the
// Private Use Area, so the merge can't shadow any real text glyph).
void LoadFonts(float dpi) {
    ImGuiIO& io = ImGui::GetIO();
    if (!(dpi > 0.5f && dpi < 8.0f)) dpi = 1.0f;

    // Font pointers and the atlas texture are invalidated as one unit. The host
    // calls the renderer's InvalidateDeviceObjects() before a live rebuild, so
    // clearing here cannot leave the DX11 backend referring to the old texture.
    io.FontDefault = nullptr;
    gUiFont = nullptr;
    gMonoFont = nullptr;
    gIconFontLarge = nullptr;
    gIconsLoaded = false;
    io.Fonts->Clear();

    auto fileExists = [](const char* p) { std::ifstream f(p); return f.good(); };
    const float uiPx   = 17.0f * dpi;
    const float monoPx = 16.0f * dpi;
    const char* kIconTtf = "C:\\Windows\\Fonts\\segmdl2.ttf";
    // Must outlive the atlas build (ImGui keeps the pointer).
    static const ImWchar kIconRange[] = { 0xE000, 0xF8FF, 0 };

    ImFont* uiFont = nullptr;
    if (fileExists("C:\\Windows\\Fonts\\segoeui.ttf"))
        uiFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", uiPx);
    if (!uiFont) {
        // Keep the built-in fallback at the same physical size as Segoe UI;
        // AddFontDefault() without a config would stay at its 13 px baseline.
        ImFontConfig fallback;
        fallback.SizePixels = uiPx;
        uiFont = io.Fonts->AddFontDefault(&fallback);
    }

    // Merge the icon glyphs into whatever UI font we ended up with (MergeMode
    // appends to the most recently added font). Slightly undersized + snapped
    // so the squarish MDL2 glyphs sit nicely on the text baseline.
    if (fileExists(kIconTtf)) {
        ImFontConfig cfg;
        cfg.MergeMode        = true;
        cfg.PixelSnapH       = true;
        cfg.GlyphMinAdvanceX = uiPx * 0.9f;              // near-uniform advance: toolbar icons align
        cfg.GlyphOffset      = ImVec2(0.0f, 2.0f * dpi); // MDL2 glyphs ride high; nudge down
        if (io.Fonts->AddFontFromFileTTF(kIconTtf, uiPx * 0.92f, &cfg, kIconRange))
            gIconsLoaded = true;
    }
    gUiFont = uiFont;
    io.FontDefault = gUiFont;

    ImFont* mono = nullptr;
    if (fileExists("C:\\Windows\\Fonts\\consola.ttf"))
        mono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", monoPx);
    else if (fileExists("C:\\Windows\\Fonts\\cour.ttf"))
        mono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\cour.ttf", monoPx);
    gMonoFont = mono; // null -> PushMono() uses the default font

    // Big icon face for hero/empty-state cards and the navigation rail.
    if (gIconsLoaded)
        gIconFontLarge = io.Fonts->AddFontFromFileTTF(kIconTtf, 30.0f * dpi, nullptr, kIconRange);
}

void PushMono() {
    ImGui::PushFont(gMonoFont ? gMonoFont : ImGui::GetFont());
}
void PopMono() {
    ImGui::PopFont();
}

} // namespace ds::ui
