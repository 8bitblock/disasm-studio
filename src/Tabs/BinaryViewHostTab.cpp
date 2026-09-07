#include "BinaryViewHostTab.h"

#include "imgui.h"
#include "../Ui/Theme.h"

#include <cstdio>
#include <utility>

namespace ds {

std::shared_ptr<const InvestigationSnapshot> BinaryViewHostTab::emptySnapshot() {
    static const auto empty = std::make_shared<const InvestigationSnapshot>();
    return empty;
}

void BinaryViewHostTab::bumpInvestigationGeneration() {
    ++investigationGeneration_;
    if (!investigationGeneration_) ++investigationGeneration_;
}

void BinaryViewHostTab::publishActive(bool documentChanged) {
    if (!activeChild_) {
        const bool hadTarget = static_cast<bool>(activeDocument_);
        activeDocument_ = {};
        activeImageGeneration_ = 0;
        activeChildInvestigationGeneration_ = 0;
        awaitingActiveRevalidation_ = false;
        investigationPublished_ = emptySnapshot();
        investigationBuilding_ = false;
        if (documentChanged || hadTarget) bumpInvestigationGeneration();
        return;
    }
    if (awaitingActiveRevalidation_) {
        investigationPublished_ = emptySnapshot();
        investigationBuilding_ = true;
        return;
    }

    const uint64_t childGeneration =
        activeChild_->investigationSnapshotGeneration();
    const auto childSnapshot = activeChild_->investigationSnapshot();
    const bool changed = documentChanged ||
        childGeneration != activeChildInvestigationGeneration_ ||
        (childSnapshot && childSnapshot != investigationPublished_);
    activeChildInvestigationGeneration_ = childGeneration;
    investigationPublished_ = childSnapshot ? childSnapshot : emptySnapshot();
    investigationBuilding_ = activeChild_->investigationSnapshotBuilding();
    if (changed) bumpInvestigationGeneration();
}

BinaryViewTab* BinaryViewHostTab::synchronizeActive(AppContext& ctx) {
    const DocumentId id = ctx.staticDocumentId();
    if (!id) {
        activeChild_ = nullptr;
        publishActive(static_cast<bool>(activeDocument_));
        return nullptr;
    }

    auto it = children_.find(id.value);
    if (it == children_.end()) {
        try {
            auto created = std::make_unique<BinaryViewTab>(id);
            it = children_.emplace(id.value, std::move(created)).first;
        } catch (...) {
            // Never leave a published null slot or let a recoverable view-owner
            // allocation failure expose another document through this host.
            activeChild_ = nullptr;
            publishActive(true);
            return nullptr;
        }
    }
    BinaryViewTab* child = it->second.get();
    if (!child || child->documentId() != id) {
        // A corrupt/mis-keyed child is never rebound to another Core owner.
        activeChild_ = nullptr;
        publishActive(true);
        return nullptr;
    }

    const uint64_t imageGeneration = ctx.staticImageGeneration();
    const bool switched = activeDocument_ != id || activeChild_ != child ||
                          activeImageGeneration_ != imageGeneration;
    activeDocument_ = id;
    activeChild_ = child;
    activeImageGeneration_ = imageGeneration;
    if (switched) {
        activeChildInvestigationGeneration_ =
            child->investigationSnapshotGeneration();
        // The child's cached snapshot is not trusted until its exact image
        // generation has passed through synchronizeDocumentImage().
        investigationPublished_ = emptySnapshot();
        investigationBuilding_ = true;
        awaitingActiveRevalidation_ = true;
        // Host generation is independent of every child counter. This edge is
        // unconditional, so equal child generations can never alias a switch.
        bumpInvestigationGeneration();
    }
    return child;
}

void BinaryViewHostTab::render(AppContext& ctx) {
    BinaryViewTab* child = synchronizeActive(ctx);
    if (!child) return;

    char scope[72];
    std::snprintf(scope, sizeof(scope),
                  "BinaryView.Document.%016llX.Image.%016llX",
                  static_cast<unsigned long long>(activeDocument_.value),
                  static_cast<unsigned long long>(activeImageGeneration_));
    ImGui::PushID(scope);
    child->render(ctx);
    ImGui::PopID();
    publishActive(false);
}

bool BinaryViewHostTab::prepareDocumentTransition(AppContext& ctx, DocumentId id,
                                                  bool closing,
                                                  std::string& error) {
    error.clear();
    if (!id) {
        error = "Invalid Binary View document identity.";
        return false;
    }

    const auto it = children_.find(id.value);
    if (it == children_.end() || !it->second) return true;
    BinaryViewTab& child = *it->second;
    if (child.documentId() != id) {
        error = "Binary View child identity mismatch; transition refused.";
        return false;
    }

    if (closing && child.hasUnsavedTypeDraft()) {
        ctx.setTypeDraftPending(id, true);
        pendingTypeDraft_ = id;
        typeDraftExit_ = false;
        openTypeDraftPrompt_ = true;
        typeDraftPromptError_.clear();
        error = "Resolve the unsaved Types draft to close this document.";
        return false;
    }

    if (ctx.staticDocumentId() == id)
        return child.prepareDocumentTransition(ctx, closing, error);

    // An inactive child was mirrored during its last deactivation. Its Project
    // cannot be touched through ctx (which now names another document), but close
    // still must retire its document-owned workers before Core releases ownership.
    if (closing) {
        child.retireDocument(ctx);
        return true;
    }

    error = "Only the active Binary View can prepare a document switch.";
    return false;
}

bool BinaryViewHostTab::prepareTypeDraftsForExit(AppContext& ctx) {
    for (const auto& document : ctx.staticDocuments()) {
        const auto found = children_.find(document.id.value);
        if (found == children_.end() || !found->second || !found->second->hasUnsavedTypeDraft()) continue;
        pendingTypeDraft_ = document.id;
        ctx.setTypeDraftPending(document.id, true);
        typeDraftExit_ = true;
        openTypeDraftPrompt_ = true;
        typeDraftPromptError_.clear();
        return false;
    }
    return true;
}

bool BinaryViewHostTab::renderTypeDraftPrompt(AppContext& ctx) {
    if (openTypeDraftPrompt_) {
        ImGui::OpenPopup("Unsaved Types definition");
        openTypeDraftPrompt_ = false;
    }
    bool resumeExit = false;
    ImGui::SetNextWindowSize(ImVec2(480.0f * theme::UiScale(), 0), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Unsaved Types definition", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        const auto found = children_.find(pendingTypeDraft_.value);
        BinaryViewTab* child = found == children_.end() ? nullptr : found->second.get();
        if (!child) {
            pendingTypeDraft_ = {};
            ImGui::CloseCurrentPopup();
        } else {
            std::string title;
            for (const auto& document : ctx.staticDocuments())
                if (document.id == pendingTypeDraft_) title = document.title;
            ImGui::TextWrapped("%s has an unsaved definition: %s", title.c_str(), child->typeDraftName().c_str());
            ImGui::TextWrapped("Save the definition, discard the draft, or cancel %s.", typeDraftExit_ ? "exit" : "closing this document");
            if (!typeDraftPromptError_.empty())
                ImGui::TextColored(theme::col::bad(), "%s", typeDraftPromptError_.c_str());
            bool resolved = false;
            if (ImGui::Button("Save")) resolved = child->saveTypeDraft(ctx, true, typeDraftPromptError_);
            ImGui::SameLine();
            if (ImGui::Button("Discard")) { child->discardTypeDraft(ctx); resolved = true; }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) {
                pendingTypeDraft_ = {};
                typeDraftPromptError_.clear();
                ImGui::CloseCurrentPopup();
            } else if (resolved) {
                if (typeDraftExit_ || ctx.queueCloseStaticDocument(pendingTypeDraft_)) {
                    resumeExit = typeDraftExit_;
                    pendingTypeDraft_ = {};
                    typeDraftPromptError_.clear();
                    ImGui::CloseCurrentPopup();
                } else typeDraftPromptError_ = ctx.documentCommandError();
            }
        }
        ImGui::EndPopup();
    }
    return resumeExit;
}

void BinaryViewHostTab::retireDocument(AppContext& ctx, DocumentId id) {
    if (!id) return;
    auto it = children_.find(id.value);
    if (it != children_.end()) {
        if (it->second) it->second->retireDocument(ctx);
        children_.erase(it);
    }
    if (activeDocument_ == id) {
        activeChild_ = nullptr;
        activeDocument_ = {};
        activeImageGeneration_ = 0;
        activeChildInvestigationGeneration_ = 0;
        awaitingActiveRevalidation_ = false;
        investigationPublished_ = emptySnapshot();
        investigationBuilding_ = false;
        bumpInvestigationGeneration();
    }
}

void BinaryViewHostTab::advanceInvestigationSnapshot(
    AppContext& ctx,
    const std::vector<InvestigationRecentQuery>& recentQueries,
    uint64_t recentRevision,
    size_t recordBudget) {
    BinaryViewTab* child = synchronizeActive(ctx);
    if (!child) return;
    child->advanceInvestigationSnapshot(ctx, recentQueries, recentRevision,
                                        recordBudget);
    awaitingActiveRevalidation_ = false;
    publishActive(false);
}

const std::vector<BinaryViewTab::SymEntry>&
BinaryViewHostTab::paletteSymbols(AppContext& ctx) {
    static const std::vector<BinaryViewTab::SymEntry> empty;
    BinaryViewTab* child = synchronizeActive(ctx);
    return child ? child->paletteSymbols(ctx) : empty;
}

BinaryViewTab::ContextActionTarget BinaryViewHostTab::cursorActionTarget(AppContext& ctx) {
    BinaryViewTab* child = synchronizeActive(ctx);
    return child ? child->cursorActionTarget(ctx) : BinaryViewTab::ContextActionTarget{};
}

bool BinaryViewHostTab::contextualActionAvailable(AppContext& ctx,
    BinaryViewTab::ContextAction action, const BinaryViewTab::ContextActionTarget& target,
    std::string& reason) {
    BinaryViewTab* child = synchronizeActive(ctx);
    if (!child) { reason = "No active Binary View document."; return false; }
    return child->contextualActionAvailable(ctx, action, target, reason);
}

bool BinaryViewHostTab::dispatchContextAction(AppContext& ctx,
    BinaryViewTab::ContextAction action, const BinaryViewTab::ContextActionTarget& target) {
    BinaryViewTab* child = synchronizeActive(ctx);
    return child && child->dispatchContextAction(ctx, action, target);
}

} // namespace ds
