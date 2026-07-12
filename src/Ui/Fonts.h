#pragma once
//
// Fonts.h
// Global font handles owned by the current atlas. They are initialized at
// startup and replaced together during a between-frame DPI atlas rebuild.
// Code views push the monospace face so addresses, bytes, and instructions
// align into clean columns.
//
struct ImFont;

namespace ds::ui {

extern ImFont* gUiFont;        // proportional UI font (may be null -> default)
extern ImFont* gMonoFont;      // monospace face for code/hex (may be null -> default)
extern ImFont* gIconFontLarge; // big Segoe MDL2 glyphs for hero cards / the nav rail (may be null)

// Rebuild the complete font atlas at the requested UI scale: UI + mono faces,
// with the Segoe MDL2 Assets icon font merged into the UI font (PUA range) when
// present. Safe before the first frame. For a live rebuild, call only between
// frames and invalidate the renderer's font device objects first.
void LoadFonts(float dpi);

// True when segmdl2.ttf was found and merged - gate every icon emission on
// this so a missing font degrades to text-only instead of '?' boxes.
bool IconsLoaded();

// Push/pop the monospace font. Always balanced even if gMonoFont is null.
void PushMono();
void PopMono();

} // namespace ds::ui
