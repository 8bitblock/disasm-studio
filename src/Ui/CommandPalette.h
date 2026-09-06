#pragma once
//
// CommandPalette.h
// Ctrl+K overlay: app actions plus the asynchronous unified investigation index
// (addresses, functions, strings, imports, comments, resources, byte hits,
// xrefs, live modules, network/authorization trails, and recent queries). Enter executes, Esc closes, and
// Up/Down move. Large-corpus build/search work stays on InvestigationService.
//
#include "../Core/InvestigationService.h"
#include "../Core/DebugTargetIdentity.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ds {

struct AppContext;

namespace ui {

struct PaletteItem {
    std::string           label;            // shown + fuzzy-matched
    std::string           detail;           // muted right-aligned hint (shortcut, category)
    std::string           searchAliases;    // hidden command-palette vocabulary
    const char*           icon = nullptr;   // optional DS_ICON_* glyph
    std::function<void()> run;
};

class CommandPalette {
public:
    using RememberQuery =
        std::function<void(std::string, InvestigationIdentity)>;

    void open(std::vector<PaletteItem> actions,
              InvestigationService* investigation,
              uint64_t generation,
              std::vector<InvestigationRecentQuery> recentQueries,
              DebugTargetIdentity liveTarget,
              RememberQuery rememberQuery = {});
    // App calls this when an incrementally-collected document snapshot replaces
    // the service session. An open palette automatically reissues its current
    // query against the new generation.
    void updateInvestigationSession(InvestigationService* investigation,
                                    uint64_t generation,
                                    DebugTargetIdentity liveTarget);
    void close();
    bool isOpen() const { return open_; }
    void render(AppContext& ctx);   // call once per frame, after the main UI

private:
    // kind: 0 = app action, 1 = investigation result, 2 = local recent query.
    struct Result { int score = 0; int kind = 0; int idx = 0; };

    void submitInvestigationSearch();
    void pollInvestigationSearch();
    void rebuildResults();

    bool                        open_       = false;
    bool                        focusNext_  = false;
    int                         sel_        = 0;
    bool                        selMoved_   = false;
    char                        query_[160] = "";
    std::string                 lastQuery_  = "\x01";   // != "" so the first frame rebuilds
    std::vector<PaletteItem>    actions_;
    std::vector<std::string>    actionLower_;
    std::vector<InvestigationRecentQuery> recentQueries_;
    InvestigationService*       investigation_ = nullptr; // App-owned; outlives the palette
    uint64_t                     investigationGeneration_ = 0;
    DebugTargetIdentity          liveTarget_{};
    uint64_t                     searchRequestId_ = 0;
    uint64_t                     seenSearchRequestId_ = 0;
    std::shared_ptr<const InvestigationSearchPublication> searchPublication_;
    RememberQuery               rememberQuery_;
    std::vector<Result>         results_;
};

} // namespace ui
} // namespace ds
