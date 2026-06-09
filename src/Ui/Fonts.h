#pragma once
//
// Fonts.h
// Global font handles set once at startup. Code views push the monospace face
// so addresses, bytes, and instructions align into clean columns.
//
struct ImFont;

namespace ds::ui {

extern ImFont* gUiFont;    // proportional UI font (may be null -> default)
extern ImFont* gMonoFont;  // monospace face for code/hex (may be null -> default)

// Push/pop the monospace font. Always balanced even if gMonoFont is null.
void PushMono();
void PopMono();

} // namespace ds::ui
