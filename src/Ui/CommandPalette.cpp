#include "CommandPalette.h"
#include "../App.h"
#include "../Core/Fuzzy.h"
#include "Fonts.h"
#include "Icons.h"
#include "Theme.h"
#include "Widgets.h"
#include "imgui.h"
#include "imgui_internal.h"
#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace ds::ui {

namespace {

const char* categoryName(InvestigationCategory category) {
    switch (category) {
    case InvestigationCategory::Address:       return "address";
    case InvestigationCategory::Function:      return "function";
    case InvestigationCategory::StringLiteral: return "string";
    case InvestigationCategory::Import:        return "import";
    case InvestigationCategory::Comment:       return "comment";
    case InvestigationCategory::Resource:      return "resource";
    case InvestigationCategory::ByteResult:    return "bytes";
    case InvestigationCategory::Xref:          return "xref";
    case InvestigationCategory::LiveModule:    return "module";
    case InvestigationCategory::NetworkTrail:  return "network trail";
    case InvestigationCategory::Authorization: return "authorization";
    case InvestigationCategory::RecentQuery:   return "recent";
    }
    return "result";
}

const char* identityName(InvestigationIdentity identity) {
    return identity == InvestigationIdentity::Live ? "LIVE" : "FILE";
}

std::string replayRecentQuery(std::string query, InvestigationIdentity identity) {
    // A bare numeric expression defaults to FILE. Preserve the history row's
    // recorded LIVE identity when replaying it; explicit live:/file:/va: text is
    // already unambiguous and ordinary text queries remain unchanged.
    const InvestigationParsedAddress parsed = ParseInvestigationAddress(query);
    std::string_view spelling(query);
    while (!spelling.empty() && std::isspace(static_cast<unsigned char>(spelling.front())))
        spelling.remove_prefix(1);
    auto startsInsensitive = [&](std::string_view prefix) {
        if (spelling.size() < prefix.size()) return false;
        for (size_t i = 0; i < prefix.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(spelling[i])) !=
                std::tolower(static_cast<unsigned char>(prefix[i]))) return false;
        }
        return true;
    };
    const bool explicitlyScoped = startsInsensitive("file:") ||
                                  startsInsensitive("va:") ||
                                  startsInsensitive("live:");
    if (identity == InvestigationIdentity::Live &&
        parsed.status == InvestigationAddressParseStatus::Valid &&
        parsed.identity != InvestigationIdentity::Live && !explicitlyScoped)
        query.insert(0, "live:");
    return query;
}

} // namespace

void CommandPalette::open(std::vector<PaletteItem> actions,
                          InvestigationService* investigation,
                          uint64_t generation,
                          std::vector<InvestigationRecentQuery> recentQueries,
                          DebugTargetIdentity liveTarget,
                          RememberQuery rememberQuery) {
    actions_ = std::move(actions);
    recentQueries_ = std::move(recentQueries);
    if (recentQueries_.size() > 32) recentQueries_.resize(32);
    investigation_ = investigation;
    investigationGeneration_ = generation;
    liveTarget_ = liveTarget;
    rememberQuery_ = std::move(rememberQuery);
    searchRequestId_ = seenSearchRequestId_ = 0;
    searchPublication_.reset();
    actionLower_.clear();
    actionLower_.reserve(actions_.size());
    for (const auto& a : actions_) {
        std::string l = a.label;
        if (!a.searchAliases.empty()) {
            l.push_back(' ');
            l += a.searchAliases;
        }
        for (char& c : l) c = (char)std::tolower((unsigned char)c);
        actionLower_.push_back(std::move(l));
    }
    query_[0]  = 0;
    lastQuery_ = "\x01";   // force a rebuild on the first frame
    sel_       = 0;
    selMoved_  = true;
    selectionExplicit_ = false;
    open_      = true;
    focusNext_ = true;
}

void CommandPalette::updateInvestigationSession(InvestigationService* investigation,
                                                uint64_t generation,
                                                DebugTargetIdentity liveTarget) {
    if (investigation_ == investigation && investigationGeneration_ == generation &&
        liveTarget_.pid == liveTarget.pid &&
        liveTarget_.sessionGeneration == liveTarget.sessionGeneration)
        return;
    investigation_ = investigation;
    investigationGeneration_ = generation;
    liveTarget_ = liveTarget;
    searchRequestId_ = seenSearchRequestId_ = 0;
    searchPublication_.reset();
    if (open_ && query_[0]) submitInvestigationSearch();
    if (open_) rebuildResults();
}

void CommandPalette::close() {
    open_ = false;
    actions_.clear();
    actionLower_.clear();
    recentQueries_.clear();
    results_.clear();
    searchPublication_.reset();
    searchRequestId_ = seenSearchRequestId_ = 0;
    investigation_ = nullptr;
    investigationGeneration_ = 0;
    liveTarget_ = {};
    rememberQuery_ = {};
}

void CommandPalette::submitInvestigationSearch() {
    searchPublication_.reset();
    seenSearchRequestId_ = 0;
    searchRequestId_ = 0;
    if (!investigation_ || !investigationGeneration_ || !query_[0]) return;
    InvestigationSearchOptions options;
    options.maxResults = 64;
    searchRequestId_ = investigation_->requestSearch(
        investigationGeneration_, std::string(query_), options);
}

void CommandPalette::pollInvestigationSearch() {
    if (!investigation_ || !searchRequestId_) return;
    auto publication = investigation_->latestSearch();
    if (!publication || publication->generation != investigationGeneration_ ||
        publication->requestId != searchRequestId_ ||
        publication->requestId == seenSearchRequestId_)
        return;
    if (publication->query != query_) return;
    searchPublication_ = std::move(publication);
    seenSearchRequestId_ = searchPublication_->requestId;
    rebuildResults();
}

// Query -> a small merged result list. Only the command list is fuzzy-matched
// here; investigation traversal and ranking have already happened on the worker.
void CommandPalette::rebuildResults() {
    // Worker completion and incremental session refresh can reorder evidence.
    // Preserve an explicitly selected local action across both paths; editing
    // the query resets this intent before rebuilding the list.
    const bool keepAction = selectionExplicit_ && sel_ >= 0 &&
        sel_ < static_cast<int>(results_.size()) && results_[sel_].kind == 0;
    const Result selectedAction = keepAction ? results_[sel_] : Result{};
    results_.clear();
    std::string q = query_;
    for (char& c : q) c = (char)std::tolower((unsigned char)c);

    constexpr size_t kMaxShown = 50;
    if (q.empty()) {
        // Keep a bounded slice of history at the top of the zero-query view.
        // Commands remain fuzzy-searchable, while recent investigations no
        // longer disappear behind a long command list and the result cap.
        constexpr size_t kRecentPreview = 8;
        const size_t recentCount = std::min(recentQueries_.size(), kRecentPreview);
        for (size_t i = 0; i < recentCount; ++i)
            results_.push_back({ 1, 2, static_cast<int>(i) });
        for (int i = 0; i < (int)actions_.size(); ++i)
            results_.push_back({ 0, 0, i });
    } else {
        const InvestigationParsedAddress parsed = ParseInvestigationAddress(q);
        const bool malformedAddress =
            parsed.status == InvestigationAddressParseStatus::Malformed ||
            parsed.status == InvestigationAddressParseStatus::Overflow;
        // A recognized-but-invalid address must stay an error. Do not let local
        // action fuzzy matching reinterpret e.g. "live:" as an unrelated command.
        if (!malformedAddress) {
            for (int i = 0; i < (int)actions_.size(); ++i) {
                int s = FuzzyScore(q.c_str(), actionLower_[i].c_str());
                if (s >= 0) results_.push_back({ 8000 + std::min(s, 1500), 0, i });
            }
        }
        if (searchPublication_ && searchPublication_->query == query_ &&
            searchPublication_->result.complete) {
            const auto& hits = searchPublication_->result.results;
            for (int i = 0; i < (int)hits.size(); ++i)
                results_.push_back({ static_cast<int>(hits[(size_t)i].score), 1, i });
        }
        std::stable_sort(results_.begin(), results_.end(),
                         [](const Result& a, const Result& b) { return a.score > b.score; });
    }
    if (results_.size() > kMaxShown) results_.resize(kMaxShown);
    if (keepAction) {
        const auto selected = std::find_if(results_.begin(), results_.end(),
            [&](const Result& result) {
                return result.kind == 0 && result.idx == selectedAction.idx;
            });
        if (selected != results_.end()) {
            sel_ = static_cast<int>(selected - results_.begin());
        } else {
            // The result cap must not silently evict the user's pending action.
            if (results_.size() >= kMaxShown) results_.pop_back();
            results_.push_back(selectedAction);
            sel_ = static_cast<int>(results_.size()) - 1;
        }
        selMoved_ = true;
    }
    if (sel_ >= (int)results_.size()) sel_ = results_.empty() ? 0 : (int)results_.size() - 1;
    if (sel_ < 0) sel_ = 0;
}

void CommandPalette::render(AppContext& ctx) {
    if (!open_) return;
    const float s = theme::UiScale();
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const ImGuiStyle& style = ImGui::GetStyle();

    // A full-viewport input surface sits above the workbench and below the
    // palette. Besides providing the dim treatment, it owns outside clicks so
    // dismissing the palette can never trigger a debugger control underneath.
    ImGui::SetNextWindowViewport(vp->ID);
    ImGui::SetNextWindowPos(vp->Pos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(vp->Size, ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg,
                          ImGui::GetStyleColorVec4(ImGuiCol_ModalWindowDimBg));
    const ImGuiWindowFlags blockerFlags =
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoFocusOnAppearing;
    bool dismissFromOutside = false;
    if (ImGui::Begin("##cmdpalette_blocker", nullptr, blockerFlags)) {
        // This surface must own mouse input above every workbench window, not
        // merely be submitted after them. Native menu bars and newly focused
        // panes can change display order independently of render order. Restore
        // the overlay pair explicitly without stealing the query's key focus.
        ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
        ImGui::SetCursorScreenPos(vp->Pos);
        dismissFromOutside = ImGui::InvisibleButton(
            "##cmdpalette_dismiss", vp->Size,
            ImGuiButtonFlags_MouseButtonLeft |
            ImGuiButtonFlags_MouseButtonRight |
            ImGuiButtonFlags_MouseButtonMiddle);
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
    if (dismissFromOutside) {
        close();
        return;
    }

    // Preserve the desktop proportions when space permits, but clamp both axes
    // to the work area so small windows and high-DPI displays retain the query,
    // results, and keyboard-help footer.
    const float marginX = std::min(16.0f * s, vp->WorkSize.x * 0.04f);
    const float marginY = std::min(18.0f * s, vp->WorkSize.y * 0.04f);
    const float maxW = std::max(1.0f, vp->WorkSize.x - marginX * 2.0f);
    const float maxH = std::max(1.0f, vp->WorkSize.y - marginY * 2.0f);
    const float w = std::min(740.0f * s, maxW);
    const float desiredH = 390.0f * s + ImGui::GetFrameHeight() +
                           ImGui::GetTextLineHeightWithSpacing() * 2.0f +
                           style.WindowPadding.y * 2.0f +
                           style.ItemSpacing.y * 2.0f;
    const float h = std::min(desiredH, maxH);
    const float minY = vp->WorkPos.y + marginY;
    const float maxY = vp->WorkPos.y + vp->WorkSize.y - marginY - h;
    const float preferredY = vp->WorkPos.y + vp->WorkSize.y * 0.16f;
    const float paletteY = std::max(minY, std::min(preferredY, maxY));

    ImGui::SetNextWindowViewport(vp->ID);
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x * 0.5f,
                                   paletteY),
                            ImGuiCond_Always, ImVec2(0.5f, 0.0f));
    ImGui::SetNextWindowSize(ImVec2(w, h), ImGuiCond_Always);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                             ImGuiWindowFlags_NoCollapse;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 5.0f * s);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    if (focusNext_) ImGui::SetNextWindowFocus();   // raise over the main window on open
    if (!ImGui::Begin("##cmdpalette", nullptr, flags)) {
        ImGui::End();
        ImGui::PopStyleVar(2);
        return;
    }
    ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());

    ImGui::TextUnformatted("Go to anything");
    SameLineIfFits(ImGui::CalcTextSize("Commands and FILE / LIVE evidence").x);
    ImGui::TextDisabled("Commands and FILE / LIVE evidence");

    // Query box, focused on open. The worker and selection identities are
    // unchanged; the extra room is for result context and long symbol names.
    if (focusNext_) { ImGui::SetKeyboardFocusHere(); focusNext_ = false; }
    ImGui::SetNextItemWidth(-FLT_MIN);
    bool enter = ImGui::InputTextWithHint("##palq",
                                          "Search commands, addresses, functions, strings, imports, xrefs...",
                                          query_, sizeof(query_),
                                          ImGuiInputTextFlags_EnterReturnsTrue |
                                          ImGuiInputTextFlags_CallbackHistory,
                                          [](ImGuiInputTextCallbackData*) { return 0; });
    if (lastQuery_ != query_) {
        lastQuery_ = query_;
        sel_ = 0;
        selMoved_ = true;
        selectionExplicit_ = false;
        submitInvestigationSearch();
        rebuildResults();
    }
    pollInvestigationSearch();
    const bool awaitingSearchPublication = searchRequestId_ != 0 &&
                                            seenSearchRequestId_ != searchRequestId_;
    if (awaitingSearchPublication) ctx.wantContinuousRedraw = true;
    if (investigation_) {
        const InvestigationServicePending pending = investigation_->pending();
        if (pending.generation == investigationGeneration_ &&
            (pending.buildQueued || pending.searchQueued || pending.building || pending.searching))
            ctx.wantContinuousRedraw = true;
    }

    // CallbackHistory keeps Up/Down owned by the query instead of moving ImGui
    // navigation focus to a result. The callback leaves text unchanged; these
    // keys select a result here, so Enter still submits the retained query.
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && sel_ + 1 < (int)results_.size()) {
        ++sel_; selMoved_ = true; selectionExplicit_ = true;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && sel_ > 0) {
        --sel_; selMoved_ = true; selectionExplicit_ = true;
    }

    int runIdx = -1;
    if ((enter || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter)) && !results_.empty())
        runIdx = sel_;

    // Result list.
    const float footerH = ImGui::GetTextLineHeightWithSpacing();
    const float listH = std::max(
        1.0f, std::min(390.0f * s,
                       ImGui::GetContentRegionAvail().y - footerH -
                       style.ItemSpacing.y));
    ImGui::BeginChild("##palresults", ImVec2(0, listH), ImGuiChildFlags_None);
    const ImVec4 acc = theme::col::accent();
    const ImGuiTableFlags resultTableFlags =
        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoSavedSettings |
        ImGuiTableFlags_PadOuterX;
    if (ImGui::BeginTable("##palette_rows", 1, resultTableFlags)) {
        ImGui::TableSetupColumn("Result", ImGuiTableColumnFlags_WidthStretch,
                                1.0f);
        for (int i = 0; i < (int)results_.size(); ++i) {
            const Result& r = results_[i];
            const char* label = "";
            const char* icon = nullptr;
            const char* detail = nullptr;
            char detailBuf[192];
            const InvestigationResult* investigationResult = nullptr;
            if (r.kind == 2) {
                const InvestigationRecentQuery& recent = recentQueries_[(size_t)r.idx];
                label = recent.query.c_str();
                std::snprintf(detailBuf, sizeof(detailBuf), "%s recent query",
                              identityName(recent.identity));
                icon = DS_ICON_CODE; detail = detailBuf;
            } else if (r.kind == 1 && searchPublication_ &&
                       r.idx >= 0 && (size_t)r.idx < searchPublication_->result.results.size()) {
                investigationResult = &searchPublication_->result.results[(size_t)r.idx];
                label = investigationResult->label.c_str();
                if (investigationResult->location.valid) {
                    std::snprintf(detailBuf, sizeof(detailBuf), "%s 0x%llX  %s",
                                  identityName(investigationResult->location.identity),
                                  (unsigned long long)investigationResult->location.value,
                                  categoryName(investigationResult->category));
                } else if (investigationResult->fileOffsetValid) {
                    std::snprintf(detailBuf, sizeof(detailBuf), "FILE+0x%llX  %s",
                                  (unsigned long long)investigationResult->fileOffset,
                                  categoryName(investigationResult->category));
                } else {
                    std::snprintf(detailBuf, sizeof(detailBuf), "%s",
                                  categoryName(investigationResult->category));
                }
                icon = DS_ICON_CODE; detail = detailBuf;
            } else {
                const PaletteItem& a = actions_[(size_t)r.idx];
                label = a.label.c_str();
                icon = a.icon; detail = a.detail.empty() ? nullptr : a.detail.c_str();
            }

            ImGui::PushID(i);
            const float rowHeight = ImGui::GetTextLineHeight() * 2.0f +
                3.0f * s + style.CellPadding.y * 2.0f;
            ImGui::TableNextRow(ImGuiTableRowFlags_None, rowHeight);
            ImGui::TableSetColumnIndex(0);
            const ImVec2 rowAt = ImGui::GetCursorScreenPos();
            if (i == sel_)
                ImGui::PushStyleColor(ImGuiCol_Header,
                                      ImVec4(acc.x, acc.y, acc.z, 0.17f));
            std::string row;
            if (IconsLoaded() && icon) { row = icon; row += "  "; }
            row += label;
            // Result text is data: render it separately so ## stays literal,
            // long names elide within the row, and tooltips retain the full text.
            if (ImGui::Selectable("##palette_result", i == sel_,
                                  ImGuiSelectableFlags_SpanAllColumns,
                                  ImVec2(0, rowHeight - ImGui::GetStyle().CellPadding.y * 2.0f)))
                runIdx = i;
            bool rowHovered = ImGui::IsItemHovered();
            const float textRight = rowAt.x + ImGui::GetContentRegionAvail().x;
            ImGui::RenderTextEllipsis(ImGui::GetWindowDrawList(), rowAt,
                ImVec2(textRight, rowAt.y + ImGui::GetTextLineHeight()), textRight, textRight,
                row.c_str(), row.c_str() + row.size(), nullptr);
            if (i == sel_) {
                ImGui::PopStyleColor();
                if (selMoved_) { ImGui::SetScrollHereY(0.5f); selMoved_ = false; }
            }

            if (detail) {
                const ImVec2 detailAt(rowAt.x,
                    rowAt.y + ImGui::GetTextLineHeight() + 3.0f * s);
                ImGui::PushStyleColor(ImGuiCol_Text, theme::col::muted());
                ImGui::RenderTextEllipsis(ImGui::GetWindowDrawList(), detailAt,
                    ImVec2(textRight, detailAt.y + ImGui::GetTextLineHeight()), textRight, textRight,
                    detail, detail + std::strlen(detail), nullptr);
                ImGui::PopStyleColor();
            }
            if (rowHovered) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ImGui::GetFontSize() * 42.0f);
                ImGui::TextWrapped("%s", label);
                if (detail) ImGui::TextDisabled("%s", detail);
                if (investigationResult && !investigationResult->detail.empty())
                    ImGui::TextWrapped("%s", investigationResult->detail.c_str());
                if (investigationResult && !investigationResult->evidence.empty()) {
                    ImGui::Separator();
                    ImGui::TextWrapped("%s", investigationResult->evidence.c_str());
                }
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (results_.empty()) {
        bool waiting = awaitingSearchPublication;
        if (investigation_ && query_[0]) {
            const auto pending = investigation_->pending();
            waiting = waiting ||
                      (pending.generation == investigationGeneration_ &&
                       (pending.buildQueued || pending.searchQueued ||
                        pending.building || pending.searching));
        }
        if (waiting) ImGui::TextDisabled("Indexing / searching...");
        else if (searchPublication_ && !searchPublication_->result.error.empty())
            ImGui::TextColored(theme::col::bad(), "%s", searchPublication_->result.error.c_str());
        else ImGui::TextDisabled(query_[0] ? "No matches." : "No commands or recent queries.");
    }
    ImGui::EndChild();
    ImGui::TextDisabled("Enter open   Up/Down select   Esc close");
    if (investigation_ && ImGui::IsItemHovered()) {
        const InvestigationServiceStats stats = investigation_->stats();
        ImGui::SetTooltip("Search requests combined: %llu\nSearch requests dropped: %llu",
                          (unsigned long long)stats.coalesced,
                          (unsigned long long)stats.dropped);
    }

    ImGui::End();
    ImGui::PopStyleVar(2);

    // Execute AFTER End() - an action may open dialogs / mutate app state.
    // Capture the callable BEFORE close() (which clears actions_).
    if (runIdx >= 0 && runIdx < (int)results_.size()) {
        const Result r = results_[(size_t)runIdx];
        std::function<void()> action;
        if (r.kind == 0) action = actions_[(size_t)r.idx].run;
        if (r.kind == 2) {
            const InvestigationRecentQuery& item = recentQueries_[(size_t)r.idx];
            const std::string recent = replayRecentQuery(item.query, item.identity);
            std::snprintf(query_, sizeof(query_), "%s", recent.c_str());
            lastQuery_ = query_;
            sel_ = 0;
            selMoved_ = true;
            selectionExplicit_ = false;
            focusNext_ = true;
            submitInvestigationSearch();
            rebuildResults();
            return;
        }
        if (r.kind == 1 && searchPublication_ && r.idx >= 0 &&
            (size_t)r.idx < searchPublication_->result.results.size()) {
            const InvestigationResult hit = searchPublication_->result.results[(size_t)r.idx];
            if (hit.category == InvestigationCategory::RecentQuery) {
                const std::string recent = replayRecentQuery(hit.label,
                                                             hit.location.identity);
                std::snprintf(query_, sizeof(query_), "%s", recent.c_str());
                lastQuery_ = query_;
                sel_ = 0;
                selMoved_ = true;
                selectionExplicit_ = false;
                focusNext_ = true;
                submitInvestigationSearch();
                rebuildResults();
                return;
            }
            if (hit.category == InvestigationCategory::NetworkTrail) {
                const std::string executedQuery = query_;
                const InvestigationIdentity identity = hit.location.identity;
                RememberQuery remember = rememberQuery_;
                close();
                if (remember) remember(executedQuery, identity);
                if (hit.location.valid) {
                    // Keep the Triage workspace visible while honoring the
                    // mapped literal/callsite selected from the typed result.
                    ctx.gotoAddress(hit.location.value);
                    ctx.openCrackmeTriage(TriageWorkspaceView::NetworkTrail);
                } else if (hit.fileOffsetValid) {
                    ctx.openCrackmeTriageAtFileOffset(hit.fileOffset);
                } else {
                    ctx.openCrackmeTriage(TriageWorkspaceView::NetworkTrail);
                }
                return;
            }
            if (hit.category == InvestigationCategory::Authorization) {
                const std::string executedQuery = query_;
                const InvestigationIdentity identity = hit.location.identity;
                RememberQuery remember = rememberQuery_;
                close();
                if (remember) remember(executedQuery, identity);
                if (hit.location.valid) {
                    ctx.gotoAddress(hit.location.value);
                    ctx.openCrackmeAuthorization(hit.focusId);
                } else if (hit.fileOffsetValid) {
                    ctx.openCrackmeAuthorizationAtFileOffset(
                        hit.fileOffset, hit.focusId);
                } else {
                    ctx.openCrackmeAuthorization(hit.focusId);
                }
                return;
            }
            if (!hit.location.valid) {
                ui::Toast(ui::ToastKind::Info,
                          "This result has no validated address to open.");
                return;
            }
            const std::string executedQuery = query_;
            const InvestigationIdentity identity = hit.location.identity;
            const uint64_t address = hit.location.value;
            // close() retires the palette session. Capture the exact owner with
            // the selected address before closing so LIVE handoffs survive it.
            const DebugTargetIdentity target = liveTarget_;
            RememberQuery remember = rememberQuery_;
            close();
            if (remember) remember(executedQuery, identity);
            if (identity == InvestigationIdentity::Live) {
                const DbgSnapshot* snapshot = ctx.frameDebugSnapshot;
                if (!snapshot || !snapshot->attached() ||
                    !DebugTargetIdentityMatches(
                        { snapshot->pid, snapshot->sessionGeneration }, target)) {
                    ui::Toast(ui::ToastKind::Warn,
                              "This live result belongs to an earlier debugger session.");
                    return;
                }
                ctx.gotoAddressLive(address, target);
            } else {
                ctx.gotoAddress(address);
            }
            return;
        }
        close();
        if (action) action();
        return;
    }

    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) close();
}

} // namespace ds::ui
