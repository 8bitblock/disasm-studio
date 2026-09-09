#pragma once
//
// Widgets.h
// Small shared UI vocabulary (colored/toolbar buttons, search boxes, badges,
// key-value rows, compact empty-state panels, toast notifications) so the tabs
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

// Restrained colored action: base color mixed with the active panel palette,
// distinct hover/active tints, readable text, and an optional tooltip.
// `small` renders an ImGui::SmallButton (toolbar-height) instead.
bool AccentButton(const char* label, const ImVec4& base, const char* tip = nullptr, bool small = false);

// Icon + label toolbar button. The icon is dropped (text-only) when the icon
// font is missing; the ImGui ID stays stable either way.
bool ToolbarIconButton(const char* icon, const char* label, const char* tip = nullptr);

// InputTextWithHint with an embedded magnifier glyph. Returns true when edited.
// width <= 0 leaves the item width untouched (caller may SetNextItemWidth).
bool SearchBox(const char* id, const char* hint, char* buf, size_t bufSize, float width = 0.0f);

// Continue a toolbar row only when the next control fits; otherwise retain the
// normal next-line cursor position. Pass the next control's physical width.
void SameLineIfFits(float nextWidth);

// Show a conventional delayed tooltip for the most recently submitted item.
// Delaying routine hints keeps dense tables/toolbars calm while still exposing
// help on intent. Disabled controls are included by default so they can explain
// why an action is unavailable.
void ItemTooltip(const char* text, bool allowWhenDisabled = true);

// Compact status tag with caller-supplied color. Every theme uses a quiet outlined
// capsule and a small state dot inside the existing padding.
void Badge(const char* text, const ImVec4& color);

// ---- Workbench chrome ------------------------------------------------------
// Compact full-width section heading with a hairline divider. Detail is optional, wraps when needed,
// and never changes the current ID scope or creates a separately scrolling pane.
void PanelHeader(const char* title, const char* detail = nullptr);

// Mockup pane heading: compact uppercase label, adjacent count capsule and
// optional trailing context. The supplied title remains available to ImGui's
// native text log. A negative count omits the capsule; context clips to fit.
void PaneHeading(const char* title, const char* detail = nullptr, int count = -1,
                 const ImVec4* countColor = nullptr);

// Shared data-list presentation: subdued headers, horizontal hairlines and
// palette-aware rows. IDs, columns, sizing and saved settings stay caller-owned.
// Call EndDataTable only when BeginDataTable/BeginDataTableEx returned true.
bool BeginDataTable(const char* id, int columns, ImGuiTableFlags flags = 0,
                    const ImVec2& size = ImVec2(0, 0), float innerWidth = 0.0f);
bool BeginDataTableEx(const char* name, ImGuiID id, int columns, ImGuiTableFlags flags = 0,
                      const ImVec2& size = ImVec2(0, 0), float innerWidth = 0.0f);
void EndDataTable();

// Native tab identity and navigation with a compact count capsule. Pass the
// original label, including any ### suffix, to retain nested table/settings IDs.
// End an open tab with ImGui::EndTabItem as usual. Counts must be real inventory.
bool BeginCountTabItem(const char* label, size_t count, ImGuiTabItemFlags flags = 0,
                       const ImVec4* color = nullptr, bool marker = false);

// Contiguous panes, compact controls and subdued dividers. All colors route
// through theme::col::* so every palette (including Light/Paper) stays correct.

// Compact square icon button, at least 28x28 (scaled). `hot` gives the action
// a subtle accent border/fill. Falls back to `fallback` text without an icon font.
// The ImGui ID comes from `id` only, so icon/fallback swaps keep state.
bool ToolButton(const char* id, const char* icon, const char* fallback,
                const char* tip = nullptr, bool hot = false, bool enabled = true);

// Thin vertical divider between toolbar groups.
void ToolbarDivider();

// Compact mono control with a subtle border. Returns true when clicked.
// `valueCol` colors the text (nullptr = normal text color).
bool Pill(const char* id, const char* text, const ImVec4* valueCol = nullptr,
          const char* tip = nullptr);

// State label: outlined capsule with a colored state dot/word + optional muted
// mono detail ("PAUSED  pid 4312  rip 7FF6..."), right of the state word.
void StatePill(const char* state, const ImVec4& stateCol, const char* detail = nullptr);

// Flat native tab strip with a bottom selection underline, overflow scrolling
// and a tab-list menu. The
// caller owns selection; disabled destinations remain visible but unavailable.
// Returns the (possibly changed) active index.
// `enabled` (optional, length `count`) grays out and ignores clicks per tab.
int TabStrip(const char* id, const char* const* labels, int count, int active,
             const bool* enabled = nullptr);

// Thin vertical divider for the status bar segments.
void StatusDivider();

// Muted key + wrapping value (printf-style). Stacks in narrow detail panes;
// the value remains the last item for caller tooltips.
void KeyValueRow(const char* key, const char* fmt, ...);

// Compact unboxed guidance for empty views: small glyph, title, muted subtitle,
// and optional primary action. Returns true when the action is clicked.
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
