#pragma once
//
// Fonts.h
// Global font handles set once at startup. Code views push the monospace face
// so addresses, bytes, and instructions align into clean columns.
//
struct ImFont;

namespace ds::ui {

extern ImFont* gUiFont;        // proportional UI font (may be null -> default)
extern ImFont* gMonoFont;      // monospace face for code/hex (may be null -> default)
extern ImFont* gIconFontLarge; // big Segoe MDL2 glyphs for hero cards / the nav rail (may be null)

// Build the font atlas: UI + mono faces, with the Segoe MDL2 Assets icon font
// merged into the UI font (PUA range) when present. Call once before the first
// frame (and from any future DPI-rebuild path so the merge isn't forgotten).
void LoadFonts(float dpi);

// True when segmdl2.ttf was found and merged - gate every icon emission on
// this so a missing font degrades to text-only instead of '?' boxes.
bool IconsLoaded();

// Push/pop the monospace font. Always balanced even if gMonoFont is null.
void PushMono();
void PopMono();

} // namespace ds::ui
