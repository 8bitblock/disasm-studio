#pragma once
//
// Widgets.h
// Small shared UI vocabulary (colored/toolbar buttons, search boxes, badges,
// key-value rows, empty-state hero cards, toast notifications) so the tabs
// stop hand-rolling form rows. All colors are passed in from theme::col::*
// (or derived from the style) and all pixel metrics scale by theme::UiScale().
//
#include "imgui.h"
#include <cstddef>
#include <string>

namespace ds::ui {

// base * f with alpha forced to 1 - for deriving button bases from theme colors
// (dimmed so the automatic hover/active tints have headroom to read).
ImVec4 Dim(const ImVec4& c, float f);

// Colored button: base color + auto hover/active tints + optional tooltip.
// `small` renders an ImGui::SmallButton (toolbar-height) instead.
bool AccentButton(const char* label, const ImVec4& base, const char* tip = nullptr, bool small = false);

// Icon + label toolbar button. The icon is dropped (text-only) when the icon
// font is missing; the ImGui ID stays stable either way.
bool ToolbarIconButton(const char* icon, const char* label, const char* tip = nullptr);

// InputTextWithHint with an embedded magnifier glyph. Returns true when edited.
// width <= 0 leaves the item width untouched (caller may SetNextItemWidth).
bool SearchBox(const char* id, const char* hint, char* buf, size_t bufSize, float width = 0.0f);

// Small rounded pill: tinted fill + outline + colored text.
void Badge(const char* text, const ImVec4& color);

// ---- Wireframe chrome kit --------------------------------------------------
// The bordered-panel / icon-toolbar vocabulary from the design wireframes
// (disassembler-wireframes.html). Everything routes through theme::col::* so
// all palettes (incl. Light/Paper) stay correct.

// Square bordered icon button (wf-tbtn): 30x30 (scaled), 1px line border,
// panel-header fill. `hot` tints border/fill with the accent (the "primary
// action" look). Falls back to `fallback` text when the icon font is missing.
// The ImGui ID comes from `id` only, so icon/fallback swaps keep state.
bool ToolButton(const char* id, const char* icon, const char* fallback,
                const char* tip = nullptr, bool hot = false, bool enabled = true);

// Thin vertical divider between toolbar groups (wf-tdiv).
void ToolbarDivider();

// Bordered rounded mono chip (wf-arch / wf-state). Returns true when clicked.
// `valueCol` colors the text (nullptr = normal text color).
bool Pill(const char* id, const char* text, const ImVec4* valueCol = nullptr,
          const char* tip = nullptr);

// State pill: bordered chip with a bold colored state word + optional muted
// mono detail ("PAUSED  pid 4312  rip 7FF6..."), right of the state word.
void StatePill(const char* state, const ImVec4& stateCol, const char* detail = nullptr);

// Wireframe tab strip (wf-tabstrip): full-width 27px strip on the panel-header
// background with a bottom border; the active tab gets the panel fill plus a
// 2px accent underline. Returns the (possibly changed) active index.
// `enabled` (optional, length `count`) grays out and ignores clicks per tab.
int TabStrip(const char* id, const char* const* labels, int count, int active,
             const bool* enabled = nullptr);

// Thin vertical divider for the status bar segments (wf-sb-div).
void StatusDivider();

// "Key   value" row with a fixed-width muted key column (printf-style value).
void KeyValueRow(const char* key, const char* fmt, ...);

// Centered hero card for empty views: big glyph (icon font), title, muted
// subtitle, optional primary action button. Returns true when the button is
// clicked. Centers within the current content region, so it works both for a
// whole tab and for a single pane child.
bool EmptyState(const char* icon, const char* title, const char* subtitle,
                const char* primaryButtonLabel = nullptr);

// ---- Toast notifications -------------------------------------------------
// Fire-and-forget, non-blocking result messages (bottom-right stack, ~4s).
enum class ToastKind { Info, Success, Warn, Error };
void Toast(ToastKind kind, std::string msg);
// Draw the active toasts; call once per frame after the status bar.
// statusBarH = height of the status bar so the stack sits just above it.
void RenderToasts(float statusBarH);
// True while any toast is alive (the fade must keep the render loop awake).
bool ToastsActive();

} // namespace ds::ui
