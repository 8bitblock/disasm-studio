#pragma once

#include "BinaryViewTab.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ds {

// Fixed-window multi-document host for Binary View. Each stable DocumentId owns
// exactly one retained child, while only the active child may render or advance
// bounded investigation collection in a frame.
class BinaryViewHostTab final : public ITab {
public:
    const char* name() const override { return "Binary View"; }
    void render(AppContext& ctx) override;

    // Invoked by AppContext's queued topology barrier while the outgoing active
    // document is still addressable through the static compatibility accessors.
    bool prepareDocumentTransition(AppContext& ctx, DocumentId id, bool closing,
                                   std::string& error);
    void retireDocument(AppContext& ctx, DocumentId id);
    bool prepareTypeDraftsForExit(AppContext& ctx);
    // Global modal: must render even when a different feature tab is visible.
    // Returns true to resume the app's ordinary verified exit path.
    bool renderTypeDraftPrompt(AppContext& ctx);

    void advanceInvestigationSnapshot(
        AppContext& ctx,
        const std::vector<InvestigationRecentQuery>& recentQueries,
        uint64_t recentRevision,
        size_t recordBudget = 768);
    std::shared_ptr<const InvestigationSnapshot> investigationSnapshot() const {
        return investigationPublished_;
    }
    uint64_t investigationSnapshotGeneration() const {
        return investigationGeneration_;
    }
    bool investigationSnapshotBuilding() const { return investigationBuilding_; }

    // Compatibility surface for callers which still request the bounded symbol
    // picker directly. Mismatched/invalid targets return an empty collection.
    const std::vector<BinaryViewTab::SymEntry>& paletteSymbols(AppContext& ctx);
    BinaryViewTab::ContextActionTarget cursorActionTarget(AppContext& ctx);
    bool contextualActionAvailable(AppContext& ctx, BinaryViewTab::ContextAction action,
        const BinaryViewTab::ContextActionTarget& target, std::string& reason);
    bool dispatchContextAction(AppContext& ctx, BinaryViewTab::ContextAction action,
        const BinaryViewTab::ContextActionTarget& target);

private:
    BinaryViewTab* synchronizeActive(AppContext& ctx);
    void publishActive(bool documentChanged);
    void bumpInvestigationGeneration();
    static std::shared_ptr<const InvestigationSnapshot> emptySnapshot();

    std::unordered_map<uint64_t, std::unique_ptr<BinaryViewTab>> children_;
    DocumentId activeDocument_{};
    BinaryViewTab* activeChild_ = nullptr;
    uint64_t activeImageGeneration_ = 0;
    uint64_t activeChildInvestigationGeneration_ = 0;
    bool awaitingActiveRevalidation_ = false;
    DocumentId pendingTypeDraft_{};
    bool typeDraftExit_ = false;
    bool openTypeDraftPrompt_ = false;
    std::string typeDraftPromptError_;

    std::shared_ptr<const InvestigationSnapshot> investigationPublished_;
    uint64_t investigationGeneration_ = 0;
    bool investigationBuilding_ = false;
};

} // namespace ds
