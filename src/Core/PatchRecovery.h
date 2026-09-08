#pragma once

#include "PatchedImage.h"

namespace ds {

enum class PatchRecoveryError { None, ImageChanged, InvalidSelection, CommitFailed };

struct PatchRecoveryResult {
    bool success = false;
    bool imageChanged = false;
    PatchRecoveryError error = PatchRecoveryError::None;
    PatchSetImageResult selection;
};

// The first call starts on freshly loaded bytes. A failed validation or commit
// retains every record in its original order and leaves the source pristine.
// The caller supplies its normal lifetime-safe, atomic image commit boundary.
// A retry cannot turn an unrelated image mutation into new pristine authority.
template <typename Commit>
PatchRecoveryResult RecoverSavedPatchSelection(const BinaryFile& binary,
                                                ProjectState& project,
                                                Commit&& commit) {
    PatchRecoveryResult result;
    if (project.patchRecoveryPending &&
        project.patchRecoveryImageRevision != binary.imageRevision()) {
        result.error = PatchRecoveryError::ImageChanged;
        return result;
    }
    project.patchRecoveryPending = true;
    project.patchRecoveryImageRevision = binary.imageRevision();
    result.selection = BuildPatchSetImageForSelection(
        binary, project.patches, project.patchSets, {},
        PatchSetImageSource::Pristine);
    if (!result.selection.success) {
        result.error = PatchRecoveryError::InvalidSelection;
        return result;
    }
    result.imageChanged = result.selection.image != binary.bytes();
    if (result.imageChanged && !commit(std::move(result.selection.image))) {
        result.error = PatchRecoveryError::CommitFailed;
        return result;
    }
    project.patchRecoveryPending = false;
    project.patchRecoveryImageRevision = 0;
    result.success = true;
    return result;
}

// Forgetting is an explicit metadata action on an unapplied record, never a
// byte revert. Keep recovery pending until the remaining complete selection
// passes the same checks (including the empty-list/patch-set metadata case).
inline bool ForgetUnrestoredPatch(const BinaryFile& binary, ProjectState& project,
                                  size_t index) {
    if (!project.patchRecoveryPending ||
        project.patchRecoveryImageRevision != binary.imageRevision() ||
        index >= project.patches.size()) return false;
    project.patches.erase(project.patches.begin() + static_cast<std::ptrdiff_t>(index));
    return true;
}

} // namespace ds
