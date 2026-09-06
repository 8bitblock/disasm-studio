#include "SemanticTransfer.h"

#include <algorithm>

namespace ds {
namespace {

const SemanticFunction* findFunction(const SemanticImage& image, uint64_t address) {
    // The BinaryFile adapter sorts functions, but the pure public model does not
    // require that precondition. A bounded linear lookup avoids invoking binary
    // search on a caller-supplied unsorted range.
    auto any = std::find_if(image.functions.begin(), image.functions.end(),
                            [&](const SemanticFunction& function) {
                                return function.address == address;
                            });
    return any == image.functions.end() ? nullptr : &*any;
}

} // namespace

SemanticTransferApplyResult ApplySemanticTransferProposal(
    ProjectState& project,
    uint64_t activeContentHash,
    const SemanticImage& targetImage,
    const MetadataTransferProposal& proposal,
    const SemanticTransferAddressValidator& addressIsMapped) {
    SemanticTransferApplyResult result;
    if (!activeContentHash || project.hash != activeContentHash ||
        targetImage.contentIdentity != activeContentHash) {
        result.status = SemanticTransferStatus::WrongProject;
        result.message = "proposal target is not the active project";
        return result;
    }
    const SemanticFunction* function = findFunction(targetImage, proposal.targetFunction);
    if (!function) {
        result.status = SemanticTransferStatus::InvalidProposal;
        result.message = "target function is absent from the immutable semantic image";
        return result;
    }

    uint64_t targetAddress = function->address;
    if (proposal.kind == MetadataTransferKind::Comment ||
        proposal.kind == MetadataTransferKind::Bookmark) {
        if (!proposal.targetInstructionValid ||
            proposal.targetInstructionIndex >= function->instructions.size()) {
            result.status = SemanticTransferStatus::InvalidProposal;
            result.message = "proposal has no checked target-instruction mapping";
            return result;
        }
        targetAddress = function->instructions[proposal.targetInstructionIndex].address;
    }
    result.targetAddressValid = true;
    result.targetAddress = targetAddress;
    bool mapped = false;
    try { mapped = addressIsMapped && addressIsMapped(targetAddress); }
    catch (...) { mapped = false; }
    if (!mapped) {
        result.status = SemanticTransferStatus::UnmappedTarget;
        result.message = "target address is not mapped by the active binary";
        return result;
    }

    switch (proposal.kind) {
        case MetadataTransferKind::Name: {
            if (proposal.value.empty()) {
                result.status = SemanticTransferStatus::InvalidProposal;
                result.message = "empty names are not transferred";
                return result;
            }
            auto existing = project.names.find(targetAddress);
            if (existing != project.names.end() && existing->second == proposal.value) {
                result.status = SemanticTransferStatus::Unchanged;
                result.message = "name already matches";
                return result;
            }
            project.names[targetAddress] = proposal.value;
            break;
        }
        case MetadataTransferKind::Comment: {
            if (proposal.value.empty()) {
                result.status = SemanticTransferStatus::InvalidProposal;
                result.message = "empty comments are not transferred";
                return result;
            }
            auto existing = project.comments.find(targetAddress);
            if (existing != project.comments.end() && existing->second == proposal.value) {
                result.status = SemanticTransferStatus::Unchanged;
                result.message = "comment already matches";
                return result;
            }
            project.comments[targetAddress] = proposal.value;
            break;
        }
        case MetadataTransferKind::Prototype: {
            if (proposal.value.empty()) {
                result.status = SemanticTransferStatus::InvalidProposal;
                result.message = "empty prototypes are not transferred";
                return result;
            }
            auto overrideIt = std::find_if(project.functionOverrides.begin(),
                                            project.functionOverrides.end(),
                [&](const PjFunctionOverride& item) { return item.address == targetAddress; });
            if (overrideIt != project.functionOverrides.end() &&
                overrideIt->action == PjFunctionAction::Undefine) {
                result.status = SemanticTransferStatus::TargetExplicitlyUndefined;
                result.message = "target function is explicitly undefined by the analyst";
                return result;
            }
            if (overrideIt == project.functionOverrides.end()) {
                PjFunctionOverride item;
                item.address = targetAddress;
                item.action = PjFunctionAction::Define;
                item.prototype = proposal.value;
                project.functionOverrides.push_back(std::move(item));
            } else {
                if (overrideIt->prototype == proposal.value) {
                    result.status = SemanticTransferStatus::Unchanged;
                    result.message = "prototype already matches";
                    return result;
                }
                overrideIt->prototype = proposal.value;
            }
            break;
        }
        case MetadataTransferKind::Bookmark: {
            auto existing = std::find_if(project.bookmarks.begin(), project.bookmarks.end(),
                [&](const PjBookmark& bookmark) { return bookmark.address == targetAddress; });
            if (existing != project.bookmarks.end()) {
                result.status = SemanticTransferStatus::Unchanged;
                result.message = "bookmark already exists";
                return result;
            }
            project.bookmarks.push_back({targetAddress, "transferred bookmark"});
            break;
        }
    }
    result.status = SemanticTransferStatus::Applied;
    result.message = "metadata transferred";
    return result;
}

} // namespace ds
