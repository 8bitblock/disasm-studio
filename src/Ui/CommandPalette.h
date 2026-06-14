#pragma once
//
// CommandPalette.h
// Ctrl+K overlay: one fuzzy-matched list over app actions, analyzed/exported
// symbols, and a typed hex address. Enter executes, Esc closes, Up/Down move.
// The App builds the action list (capturing its own state) and hands in a
// snapshot of the Binary View's symbol index when opening.
//
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

struct AppContext;

namespace ui {

struct PaletteItem {
    std::string           label;            // shown + fuzzy-matched
    std::string           detail;           // muted right-aligned hint (shortcut, category)
    const char*           icon = nullptr;   // optional DS_ICON_* glyph
    std::function<void()> run;
};

// Palette-owned symbol entry (copied at open() so the source index can't be
// invalidated underneath the open palette).
struct PaletteSymbol {
    uint64_t    addr;
    std::string name;
    std::string lower;   // pre-lowercased for FuzzyScore
};

class CommandPalette {
public:
    void open(std::vector<PaletteItem> actions, std::vector<PaletteSymbol> symbols);
    void close();
    bool isOpen() const { return open_; }
    void render(AppContext& ctx);   // call once per frame, after the main UI

private:
    struct Result { int score; int kind; int idx; uint64_t va; };  // kind: 0=action 1=symbol 2=goto-address

    void rebuildResults();

    bool                        open_       = false;
    bool                        focusNext_  = false;
    int                         sel_        = 0;
    bool                        selMoved_   = false;
    char                        query_[160] = "";
    std::string                 lastQuery_  = "\x01";   // != "" so the first frame rebuilds
    std::vector<PaletteItem>    actions_;
    std::vector<std::string>    actionLower_;
    std::vector<PaletteSymbol>  symbols_;
    std::vector<Result>         results_;
};

} // namespace ui
} // namespace ds
