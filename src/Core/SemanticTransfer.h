#pragma once
// Explicit metadata-transfer application for SemanticDiff proposals.
// This helper is intentionally separate from matching: proposals stay inert
// until a caller selects one and supplies an exact active-project identity plus
// a mapped-address validator.

#include "Project.h"
#include "SemanticDiff.h"

#include <functional>
#include <string>

namespace ds {

enum class SemanticTransferStatus : uint8_t {
    Applied,
    Unchanged,
    WrongProject,
    InvalidProposal,
    UnmappedTarget,
    TargetExplicitlyUndefined,
};

struct SemanticTransferApplyResult {
    SemanticTransferStatus status = SemanticTransferStatus::InvalidProposal;
    bool targetAddressValid = false;
    uint64_t targetAddress = 0;
    std::string message;
};

using SemanticTransferAddressValidator = std::function<bool(uint64_t)>;

// `targetImage` must be the proposal's target side, selected by direction by the
// caller.  ProjectState is changed only for Applied.  No save, reanalysis, or UI
// side effect occurs here.
SemanticTransferApplyResult ApplySemanticTransferProposal(
    ProjectState& project,
    uint64_t activeContentHash,
    const SemanticImage& targetImage,
    const MetadataTransferProposal& proposal,
    const SemanticTransferAddressValidator& addressIsMapped);

} // namespace ds
