#pragma once
//
// PatchedImage.h
// Pure, transactional construction of the disk image used by File -> Save
// Binary As. A persisted patch list is authoritative: silently dropping one
// malformed or unmapped record would write a file that differs from the
// analysis shown to the user, so the complete list is validated before the
// output vector is allocated or changed.
//

#include "BinaryFile.h"
#include "PatchSet.h"
#include "Project.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <vector>

namespace ds {

enum class PatchedImageError : uint8_t {
    None = 0,
    ImageNotLoaded,
    EmptyReplacement,
    OriginalSizeMismatch,
    AddressRangeOverflow,
    RangeNotFileBacked,
    OriginalBytesMismatch,
    SourcePatchStateMismatch,
    RemovalIndexInvalid,
    MappingChanged,
    AllocationFailure,
};

// Restoration starts from freshly loaded file bytes and can therefore verify
// each persisted `orig` span. Save Binary As starts from the UI's already-
// patched image, where that comparison would reject correct state. Requiring an
// explicit mode prevents a future caller from silently choosing the wrong rule.
enum class PatchedImageSource : uint8_t {
    Pristine,
    AlreadyPatched,
};

struct PatchedImageResult {
    bool success = false;
    std::vector<uint8_t> image;
    size_t appliedPatches = 0;
    size_t failedPatch = std::numeric_limits<size_t>::max();
    uint64_t failedAddress = 0;
    PatchedImageError error = PatchedImageError::None;
};

// A patch removal can only change bytes inside the removed record.  Returning
// the smallest single VA span containing those changes lets the caller publish
// it through BinaryFile::writeImage instead of allocating and swapping a copy
// of the complete file image.  `success && bytes.empty()` is an intentional
// no-op: later ordered patches completely shadowed the removed record.
struct PatchRemovalSpanResult {
    bool success = false;
    uint64_t address = 0;
    std::vector<uint8_t> bytes;
    size_t appliedPatches = 0;
    size_t failedPatch = std::numeric_limits<size_t>::max();
    uint64_t failedAddress = 0;
    PatchedImageError error = PatchedImageError::None;
};

inline const char* PatchedImageErrorText(PatchedImageError error) {
    switch (error) {
    case PatchedImageError::None:                 return "no error";
    case PatchedImageError::ImageNotLoaded:       return "the source image is not loaded";
    case PatchedImageError::EmptyReplacement:     return "the replacement byte sequence is empty";
    case PatchedImageError::OriginalSizeMismatch: return "the original and replacement byte counts differ";
    case PatchedImageError::AddressRangeOverflow: return "the patch address range overflows";
    case PatchedImageError::RangeNotFileBacked:   return "the complete patch range is not contiguous file-backed data";
    case PatchedImageError::OriginalBytesMismatch:return "the saved original bytes do not match the pristine image";
    case PatchedImageError::SourcePatchStateMismatch:
        return "the source image does not contain the complete ordered patch state";
    case PatchedImageError::RemovalIndexInvalid:  return "the patch removal index is invalid";
    case PatchedImageError::MappingChanged:       return "the image mapping changed after preflight";
    case PatchedImageError::AllocationFailure:    return "there was not enough memory to build the output image";
    }
    return "unknown patch error";
}

namespace patched_image_detail {

// Shared record preflight.  Keeping the full-image and span-only builders on
// this one path prevents the fast removal path from accepting a list that Save
// Binary As would reject.  Result is intentionally structural: both public
// result types expose the same diagnostic fields.
template <typename Result>
inline bool ValidatePatchRecords(const BinaryFile& binary,
                                 const std::vector<PjPatch>& patches,
                                 PatchedImageSource sourceState,
                                 Result& result) {
    if (!binary.loaded()) {
        result.error = PatchedImageError::ImageNotLoaded;
        return false;
    }

    for (size_t i = 0; i < patches.size(); ++i) {
        const PjPatch& patch = patches[i];
        result.failedPatch = i;
        result.failedAddress = patch.address;
        if (patch.bytes.empty()) {
            result.error = PatchedImageError::EmptyReplacement;
            return false;
        }
        if (patch.orig.size() != patch.bytes.size()) {
            result.error = PatchedImageError::OriginalSizeMismatch;
            return false;
        }
        if (patch.bytes.size() >
            std::numeric_limits<uint64_t>::max() - patch.address) {
            result.error = PatchedImageError::AddressRangeOverflow;
            return false;
        }
        if (!binary.canWriteImage(patch.address, patch.bytes.size())) {
            result.error = PatchedImageError::RangeNotFileBacked;
            return false;
        }
        if (sourceState == PatchedImageSource::Pristine) {
            uint64_t fileOffset = 0;
            const auto& source = binary.bytes();
            if (!binary.vaToOffset(patch.address, fileOffset) ||
                fileOffset > source.size() ||
                patch.orig.size() >
                    source.size() - static_cast<size_t>(fileOffset)) {
                result.error = PatchedImageError::MappingChanged;
                return false;
            }
            const auto first =
                source.begin() + static_cast<size_t>(fileOffset);
            if (!std::equal(patch.orig.begin(), patch.orig.end(), first)) {
                result.error = PatchedImageError::OriginalBytesMismatch;
                return false;
            }
        }
    }
    return true;
}

// Prove the same AlreadyPatched invariant as rebuilding and comparing the full
// image, without allocating storage proportional to that image.  A byte that
// differs from an earlier patch is valid only if a later record covers the same
// file byte; the last record covering every file offset must already match the
// source.  File offsets (rather than VAs) preserve the full builder's semantics
// even for hostile structured images with aliased raw mappings.
// Later coverage is found directly from the caller-owned list, so auxiliary
// allocation is constant and the only eventual allocation is the removed span.
template <typename Result>
inline bool ValidateAlreadyPatchedSource(const BinaryFile& binary,
                                         const std::vector<PjPatch>& patches,
                                         Result& result) {
    const auto& source = binary.bytes();
    for (size_t i = 0; i < patches.size(); ++i) {
        const PjPatch& patch = patches[i];
        uint64_t fileOffset = 0;
        if (!binary.vaToOffset(patch.address, fileOffset) ||
            fileOffset > source.size() ||
            patch.bytes.size() >
                source.size() - static_cast<size_t>(fileOffset)) {
            result.appliedPatches = 0;
            result.failedPatch = i;
            result.failedAddress = patch.address;
            result.error = PatchedImageError::MappingChanged;
            return false;
        }

        const uint64_t patchFileEnd =
            fileOffset + static_cast<uint64_t>(patch.bytes.size());
        size_t offset = 0;
        while (offset < patch.bytes.size()) {
            const auto mismatch = std::mismatch(
                patch.bytes.begin() + offset, patch.bytes.end(),
                source.begin() + static_cast<size_t>(fileOffset) + offset);
            if (mismatch.first == patch.bytes.end()) break;

            offset = static_cast<size_t>(mismatch.first - patch.bytes.begin());
            const uint64_t mismatchFileOffset =
                fileOffset + static_cast<uint64_t>(offset);
            uint64_t coveredUntil = mismatchFileOffset;
            for (size_t laterIndex = i + 1;
                 laterIndex < patches.size(); ++laterIndex) {
                const PjPatch& later = patches[laterIndex];
                uint64_t laterFileOffset = 0;
                if (!binary.vaToOffset(later.address, laterFileOffset) ||
                    laterFileOffset > source.size() ||
                    later.bytes.size() >
                        source.size() -
                            static_cast<size_t>(laterFileOffset)) {
                    result.appliedPatches = 0;
                    result.failedPatch = laterIndex;
                    result.failedAddress = later.address;
                    result.error = PatchedImageError::MappingChanged;
                    return false;
                }
                const uint64_t laterFileEnd =
                    laterFileOffset +
                    static_cast<uint64_t>(later.bytes.size());
                if (laterFileOffset <= mismatchFileOffset &&
                    mismatchFileOffset < laterFileEnd)
                    coveredUntil = std::max(coveredUntil, laterFileEnd);
            }
            if (coveredUntil == mismatchFileOffset) {
                result.appliedPatches = 0;
                result.failedPatch = std::numeric_limits<size_t>::max();
                result.failedAddress = 0;
                result.error = PatchedImageError::SourcePatchStateMismatch;
                return false;
            }

            const uint64_t skipEnd = std::min(patchFileEnd, coveredUntil);
            offset = static_cast<size_t>(skipEnd - fileOffset);
        }
    }
    return true;
}

} // namespace patched_image_detail

inline PatchedImageResult BuildPatchedImage(const BinaryFile& binary,
                                            const std::vector<PjPatch>& patches,
                                            PatchedImageSource sourceState) {
    PatchedImageResult result;
    // Phase 1: validate every record against the immutable source mapping. Do
    // not allocate/copy the output yet: one bad later record invalidates the
    // whole saved list, including every otherwise-valid record before it.
    if (!patched_image_detail::ValidatePatchRecords(
            binary, patches, sourceState, result))
        return result;

    // Phase 2: the whole list is valid. Build a private copy, preserving list
    // order so overlapping records remain later-wins. No BinaryFile mutation is
    // involved, and any unexpected failure discards the private copy.
    try {
        result.image = binary.bytes();
        for (size_t i = 0; i < patches.size(); ++i) {
            const PjPatch& patch = patches[i];
            uint64_t fileOffset = 0;
            if (!binary.vaToOffset(patch.address, fileOffset) ||
                fileOffset > result.image.size() ||
                patch.bytes.size() > result.image.size() - static_cast<size_t>(fileOffset)) {
                result.image.clear();
                result.appliedPatches = 0;
                result.failedPatch = i;
                result.failedAddress = patch.address;
                result.error = PatchedImageError::MappingChanged;
                return result;
            }
            std::copy(patch.bytes.begin(), patch.bytes.end(),
                      result.image.begin() + static_cast<size_t>(fileOffset));
            ++result.appliedPatches;
        }
    } catch (const std::bad_alloc&) {
        result.image.clear();
        result.appliedPatches = 0;
        result.error = PatchedImageError::AllocationFailure;
        return result;
    } catch (const std::length_error&) {
        result.image.clear();
        result.appliedPatches = 0;
        result.error = PatchedImageError::AllocationFailure;
        return result;
    }

    // Save As receives the UI's allegedly already-patched image. Reapplying the
    // complete ordered list must therefore be an idempotent operation. If it
    // changes even one byte, the in-memory source never received (or no longer
    // contains) the advertised patch state; publishing the candidate would turn
    // a prior restore rejection into a silent patch-on-save.
    if (sourceState == PatchedImageSource::AlreadyPatched &&
        result.image != binary.bytes()) {
        result.image.clear();
        result.appliedPatches = 0;
        result.failedPatch = std::numeric_limits<size_t>::max();
        result.failedAddress = 0;
        result.error = PatchedImageError::SourcePatchStateMismatch;
        return result;
    }

    result.success = true;
    result.failedPatch = std::numeric_limits<size_t>::max();
    result.failedAddress = 0;
    result.error = PatchedImageError::None;
    return result;
}

// Construct the exact image produced by removing one record from an already-
// patched source.  The source must first prove that it contains the complete
// ordered list.  Restoration and survivor replay then happen only in this
// private vector, so callers can publish the result with one no-throw swap.
inline PatchedImageResult BuildImageAfterPatchRemoval(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    size_t removeIndex) {
    if (removeIndex >= patches.size()) {
        PatchedImageResult failed;
        failed.error = PatchedImageError::RemovalIndexInvalid;
        failed.failedPatch = removeIndex;
        return failed;
    }

    PatchedImageResult result = BuildPatchedImage(
        binary, patches, PatchedImageSource::AlreadyPatched);
    if (!result.success) return result;

    const PjPatch& removed = patches[removeIndex];
    uint64_t fileOffset = 0;
    if (!binary.vaToOffset(removed.address, fileOffset) ||
        fileOffset > result.image.size() ||
        removed.orig.size() > result.image.size() - static_cast<size_t>(fileOffset)) {
        result.image.clear();
        result.success = false;
        result.appliedPatches = 0;
        result.failedPatch = removeIndex;
        result.failedAddress = removed.address;
        result.error = PatchedImageError::MappingChanged;
        return result;
    }
    std::copy(removed.orig.begin(), removed.orig.end(),
              result.image.begin() + static_cast<size_t>(fileOffset));

    result.appliedPatches = 0;
    for (size_t i = 0; i < patches.size(); ++i) {
        if (i == removeIndex) continue;
        const PjPatch& survivor = patches[i];
        if (!binary.vaToOffset(survivor.address, fileOffset) ||
            fileOffset > result.image.size() ||
            survivor.bytes.size() > result.image.size() - static_cast<size_t>(fileOffset)) {
            result.image.clear();
            result.success = false;
            result.appliedPatches = 0;
            result.failedPatch = i;
            result.failedAddress = survivor.address;
            result.error = PatchedImageError::MappingChanged;
            return result;
        }
        std::copy(survivor.bytes.begin(), survivor.bytes.end(),
                  result.image.begin() + static_cast<size_t>(fileOffset));
        ++result.appliedPatches;
    }

    result.failedPatch = std::numeric_limits<size_t>::max();
    result.failedAddress = 0;
    result.error = PatchedImageError::None;
    return result;
}

// Plan the exact write needed to remove one record from an already-patched
// image.  This has BuildImageAfterPatchRemoval's fail-closed validation and
// ordered survivor semantics, but allocates at most the removed record's byte
// count.  The returned range is trimmed to the smallest single contiguous span
// containing all changed bytes; unchanged interior bytes remain in that span.
inline PatchRemovalSpanResult BuildPatchRemovalSpan(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    size_t removeIndex) {
    PatchRemovalSpanResult result;
    if (removeIndex >= patches.size()) {
        result.error = PatchedImageError::RemovalIndexInvalid;
        result.failedPatch = removeIndex;
        return result;
    }

    if (!patched_image_detail::ValidatePatchRecords(
            binary, patches, PatchedImageSource::AlreadyPatched, result))
        return result;
    if (!patched_image_detail::ValidateAlreadyPatchedSource(
            binary, patches, result))
        return result;

    const PjPatch& removed = patches[removeIndex];
    const auto& source = binary.bytes();
    uint64_t removedFileOffset = 0;
    if (!binary.vaToOffset(removed.address, removedFileOffset) ||
        removedFileOffset > source.size() ||
        removed.orig.size() >
            source.size() - static_cast<size_t>(removedFileOffset)) {
        result.appliedPatches = 0;
        result.failedPatch = removeIndex;
        result.failedAddress = removed.address;
        result.error = PatchedImageError::MappingChanged;
        return result;
    }

    try {
        result.bytes = removed.orig;
    } catch (const std::bad_alloc&) {
        result.bytes.clear();
        result.error = PatchedImageError::AllocationFailure;
        return result;
    } catch (const std::length_error&) {
        result.bytes.clear();
        result.error = PatchedImageError::AllocationFailure;
        return result;
    }

    const uint64_t removedFileEnd =
        removedFileOffset + static_cast<uint64_t>(removed.orig.size());
    result.appliedPatches = 0;
    for (size_t i = 0; i < patches.size(); ++i) {
        if (i == removeIndex) continue;
        const PjPatch& survivor = patches[i];

        // Mirror the full-image builder's post-preflight mapping check for
        // every survivor, including records that do not intersect the output.
        uint64_t survivorFileOffset = 0;
        if (!binary.vaToOffset(survivor.address, survivorFileOffset) ||
            survivorFileOffset > source.size() ||
            survivor.bytes.size() >
                source.size() - static_cast<size_t>(survivorFileOffset)) {
            result.bytes.clear();
            result.appliedPatches = 0;
            result.failedPatch = i;
            result.failedAddress = survivor.address;
            result.error = PatchedImageError::MappingChanged;
            return result;
        }

        const uint64_t survivorFileEnd =
            survivorFileOffset +
            static_cast<uint64_t>(survivor.bytes.size());
        const uint64_t overlapBegin =
            std::max(removedFileOffset, survivorFileOffset);
        const uint64_t overlapEnd =
            std::min(removedFileEnd, survivorFileEnd);
        if (overlapBegin < overlapEnd) {
            const size_t sourceOffset =
                static_cast<size_t>(overlapBegin - survivorFileOffset);
            const size_t outputOffset =
                static_cast<size_t>(overlapBegin - removedFileOffset);
            const size_t overlapSize =
                static_cast<size_t>(overlapEnd - overlapBegin);
            std::copy_n(survivor.bytes.begin() + sourceOffset, overlapSize,
                        result.bytes.begin() + outputOffset);
        }
        ++result.appliedPatches;
    }

    // Drop equal edges so a shadowed removal avoids both the image write and
    // its revision-driven analysis invalidation.  One span deliberately keeps
    // any unchanged holes between its first and last changed bytes.
    const size_t sourceOffset = static_cast<size_t>(removedFileOffset);
    size_t firstChanged = 0;
    while (firstChanged < result.bytes.size() &&
           result.bytes[firstChanged] == source[sourceOffset + firstChanged])
        ++firstChanged;
    if (firstChanged == result.bytes.size()) {
        result.bytes.clear();
        result.address = removed.address;
    } else {
        size_t changedEnd = result.bytes.size();
        while (changedEnd > firstChanged &&
               result.bytes[changedEnd - 1] ==
                   source[sourceOffset + changedEnd - 1])
            --changedEnd;
        if (firstChanged != 0) {
            std::move(result.bytes.begin() + firstChanged,
                      result.bytes.begin() + changedEnd,
                      result.bytes.begin());
        }
        result.bytes.resize(changedEnd - firstChanged);
        result.address =
            removed.address + static_cast<uint64_t>(firstChanged);
    }

    result.success = true;
    result.failedPatch = std::numeric_limits<size_t>::max();
    result.failedAddress = 0;
    result.error = PatchedImageError::None;
    return result;
}

// Named patch-set transitions deliberately use a separate result type from the
// legacy flat-list helpers above. A plan error (for example two enabled
// experiments writing different bytes to the same location) is distinct from
// a file-mapping or source-state error and retains both conflicting indices.
enum class PatchSetImageSource : uint8_t {
    Pristine,
    CurrentEnabledSets,
};

enum class PatchSetImageError : uint8_t {
    None = 0,
    ImageNotLoaded,
    InvalidPlan,
    RangeNotFileBacked,
    MappingChanged,
    OriginalBytesMismatch,
    CurrentStateMismatch,
    AllocationFailure,
};

struct PatchSetDiffSpan {
    uint64_t fileOffset = 0;
    bool addressValid = false;
    uint64_t address = 0;
    std::vector<uint8_t> before;
    std::vector<uint8_t> after;
};

struct PatchSetImageResult {
    bool success = false;
    std::vector<uint8_t> image;
    std::vector<PatchSetDiffSpan> changes;
    uint64_t changedByteCount = 0;
    bool changesTruncated = false;
    PjPatchSetPlan currentPlan;
    PjPatchSetPlan desiredPlan;
    PatchSetImageError error = PatchSetImageError::None;
    size_t failedPatch = std::numeric_limits<size_t>::max();
    uint64_t failedAddress = 0;
};

struct PatchSetComparisonResult {
    bool success = false;
    std::vector<PatchSetDiffSpan> differences; // left -> right
    uint64_t differentByteCount = 0;
    bool differencesTruncated = false;
    PjPatchSetPlan currentPlan;
    PjPatchSetPlan leftPlan;
    PjPatchSetPlan rightPlan;
    PatchSetImageError error = PatchSetImageError::None;
    size_t failedPatch = std::numeric_limits<size_t>::max();
    uint64_t failedAddress = 0;
};

inline const char* PatchSetImageErrorText(PatchSetImageError error) {
    switch (error) {
    case PatchSetImageError::None: return "no error";
    case PatchSetImageError::ImageNotLoaded: return "the source image is not loaded";
    case PatchSetImageError::InvalidPlan: return "the patch-set selection is invalid";
    case PatchSetImageError::RangeNotFileBacked: return "a patch range is not contiguous file-backed data";
    case PatchSetImageError::MappingChanged: return "the image mapping changed while composing patch sets";
    case PatchSetImageError::OriginalBytesMismatch: return "saved pristine bytes disagree with the source or one another";
    case PatchSetImageError::CurrentStateMismatch: return "the source image does not match the currently enabled patch sets";
    case PatchSetImageError::AllocationFailure: return "there was not enough memory to compose patch sets";
    }
    return "unknown patch set image error";
}

namespace patched_image_detail {

struct MappedPatchRecord {
    size_t index = 0;
    uint64_t fileOffset = 0;
    uint64_t fileEnd = 0;
};

template <typename Result>
inline bool MapAndValidatePatchSetRecords(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    const std::vector<uint8_t>& active,
    std::vector<MappedPatchRecord>& mapped,
    Result& result,
    PjPatchSetPlan* diagnosticPlan) {
    try {
        mapped.clear();
        mapped.reserve(patches.size());
    } catch (const std::bad_alloc&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    } catch (const std::length_error&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    }

    const auto& source = binary.bytes();
    for (size_t i = 0; i < patches.size(); ++i) {
        const PjPatch& patch = patches[i];
        result.failedPatch = i;
        result.failedAddress = patch.address;
        uint64_t fileOffset = 0;
        if (!binary.canWriteImage(patch.address, patch.bytes.size()) ||
            !binary.vaToOffset(patch.address, fileOffset)) {
            result.error = PatchSetImageError::RangeNotFileBacked;
            return false;
        }
        if (fileOffset > source.size() || patch.bytes.size() >
                source.size() - static_cast<size_t>(fileOffset)) {
            result.error = PatchSetImageError::MappingChanged;
            return false;
        }
        mapped.push_back({ i, fileOffset,
            fileOffset + static_cast<uint64_t>(patch.bytes.size()) });
    }

    std::stable_sort(mapped.begin(), mapped.end(),
        [](const MappedPatchRecord& a, const MappedPatchRecord& b) {
            if (a.fileOffset != b.fileOffset) return a.fileOffset < b.fileOffset;
            return a.index < b.index;
        });
    uint64_t comparedBytes = 0;
    for (size_t oi = 0; oi < mapped.size(); ++oi) {
        const MappedPatchRecord& firstMap = mapped[oi];
        const PjPatch& first = patches[firstMap.index];
        for (size_t oj = oi + 1; oj < mapped.size(); ++oj) {
            const MappedPatchRecord& secondMap = mapped[oj];
            if (secondMap.fileOffset >= firstMap.fileEnd) break;
            const PjPatch& second = patches[secondMap.index];
            const uint64_t overlapBegin =
                std::max(firstMap.fileOffset, secondMap.fileOffset);
            const uint64_t overlapEnd =
                std::min(firstMap.fileEnd, secondMap.fileEnd);
            if (overlapBegin >= overlapEnd) continue;
            const uint64_t count = overlapEnd - overlapBegin;
            if (count > kMaxPatchSetOverlapComparisonBytes -
                    std::min(comparedBytes,
                             kMaxPatchSetOverlapComparisonBytes)) {
                if (diagnosticPlan) {
                    diagnosticPlan->success = false;
                    diagnosticPlan->error =
                        PjPatchSetPlanError::OverlapValidationBudgetExceeded;
                    diagnosticPlan->failedPatch = firstMap.index;
                    diagnosticPlan->conflictingPatch = secondMap.index;
                    diagnosticPlan->conflictAddress = first.address;
                }
                result.failedPatch = firstMap.index;
                result.failedAddress = first.address;
                result.error = PatchSetImageError::InvalidPlan;
                return false;
            }
            comparedBytes += count;
            const size_t firstOffset = static_cast<size_t>(
                overlapBegin - firstMap.fileOffset);
            const size_t secondOffset = static_cast<size_t>(
                overlapBegin - secondMap.fileOffset);
            const size_t overlapSize = static_cast<size_t>(count);
            if (!std::equal(first.orig.begin() + firstOffset,
                            first.orig.begin() + firstOffset + overlapSize,
                            second.orig.begin() + secondOffset)) {
                if (diagnosticPlan) {
                    diagnosticPlan->success = false;
                    diagnosticPlan->error =
                        PjPatchSetPlanError::OriginalOverlapMismatch;
                    diagnosticPlan->failedPatch = firstMap.index;
                    diagnosticPlan->conflictingPatch = secondMap.index;
                    diagnosticPlan->conflictAddress = first.address;
                }
                result.failedPatch = firstMap.index;
                result.failedAddress = first.address;
                result.error = PatchSetImageError::OriginalBytesMismatch;
                return false;
            }
            if (active[firstMap.index] && active[secondMap.index] &&
                !std::equal(first.bytes.begin() + firstOffset,
                            first.bytes.begin() + firstOffset + overlapSize,
                            second.bytes.begin() + secondOffset) &&
                !(first.patchSetId == kUngroupedPatchSetId &&
                  second.patchSetId == kUngroupedPatchSetId)) {
                if (diagnosticPlan) {
                    diagnosticPlan->success = false;
                    diagnosticPlan->error =
                        PjPatchSetPlanError::ActiveOverlapConflict;
                    diagnosticPlan->failedPatch = firstMap.index;
                    diagnosticPlan->conflictingPatch = secondMap.index;
                    diagnosticPlan->conflictAddress = first.address;
                }
                result.failedPatch = firstMap.index;
                result.failedAddress = first.address;
                result.error = PatchSetImageError::InvalidPlan;
                return false;
            }
        }
    }
    return true;
}

inline std::vector<uint8_t> ActiveMask(size_t patchCount,
                                       const PjPatchSetPlan& plan) {
    std::vector<uint8_t> result(patchCount, 0);
    for (size_t index : plan.activePatchIndices)
        if (index < result.size()) result[index] = 1;
    return result;
}

template <typename Result>
inline bool PreparePatchSetPristine(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    const std::vector<PjPatchSet>& sets,
    PatchSetImageSource sourceState,
    PjPatchSetPlan& currentPlan,
    std::vector<MappedPatchRecord>& mapped,
    std::vector<uint8_t>& pristine,
    Result& result) {
    if (!binary.loaded()) {
        result.error = PatchSetImageError::ImageNotLoaded;
        return false;
    }
    currentPlan = BuildPatchSetPlan(patches, sets);
    if (!currentPlan.success) {
        result.error = PatchSetImageError::InvalidPlan;
        return false;
    }
    std::vector<uint8_t> currentMask;
    try {
        currentMask = ActiveMask(patches.size(), currentPlan);
    } catch (const std::bad_alloc&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    } catch (const std::length_error&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    }
    if (!MapAndValidatePatchSetRecords(binary, patches, currentMask, mapped,
                                       result, &currentPlan))
        return false;

    try {
        pristine = binary.bytes();
    } catch (const std::bad_alloc&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    } catch (const std::length_error&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    }

    if (sourceState == PatchSetImageSource::Pristine) {
        for (const MappedPatchRecord& record : mapped) {
            const PjPatch& patch = patches[record.index];
            const auto first = pristine.begin() +
                static_cast<size_t>(record.fileOffset);
            if (!std::equal(patch.orig.begin(), patch.orig.end(), first)) {
                result.failedPatch = record.index;
                result.failedAddress = patch.address;
                result.error = PatchSetImageError::OriginalBytesMismatch;
                pristine.clear();
                return false;
            }
        }
        return true;
    }

    // Reconstruct one canonical pristine image, then verify every original
    // span against it. This also catches two disjoint VAs which alias one file
    // range and advertise incompatible originals.
    for (const MappedPatchRecord& record : mapped) {
        const PjPatch& patch = patches[record.index];
        std::copy(patch.orig.begin(), patch.orig.end(), pristine.begin() +
                  static_cast<size_t>(record.fileOffset));
    }
    for (const MappedPatchRecord& record : mapped) {
        const PjPatch& patch = patches[record.index];
        const auto first = pristine.begin() +
            static_cast<size_t>(record.fileOffset);
        if (!std::equal(patch.orig.begin(), patch.orig.end(), first)) {
            result.failedPatch = record.index;
            result.failedAddress = patch.address;
            result.error = PatchSetImageError::OriginalBytesMismatch;
            pristine.clear();
            return false;
        }
    }

    std::vector<uint8_t> expected;
    try {
        expected = pristine;
        for (size_t index : currentPlan.activePatchIndices) {
            const MappedPatchRecord* record = nullptr;
            for (const MappedPatchRecord& candidate : mapped)
                if (candidate.index == index) { record = &candidate; break; }
            if (!record) {
                result.failedPatch = index;
                result.failedAddress = patches[index].address;
                result.error = PatchSetImageError::MappingChanged;
                pristine.clear();
                return false;
            }
            const PjPatch& patch = patches[index];
            std::copy(patch.bytes.begin(), patch.bytes.end(), expected.begin() +
                      static_cast<size_t>(record->fileOffset));
        }
    } catch (const std::bad_alloc&) {
        pristine.clear();
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    } catch (const std::length_error&) {
        pristine.clear();
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    }
    if (expected != binary.bytes()) {
        pristine.clear();
        result.error = PatchSetImageError::CurrentStateMismatch;
        return false;
    }
    return true;
}

inline const MappedPatchRecord* FindMappedRecord(
    const std::vector<MappedPatchRecord>& mapped, size_t index) {
    const auto it = std::find_if(mapped.begin(), mapped.end(),
        [index](const MappedPatchRecord& record) {
            return record.index == index;
        });
    return it == mapped.end() ? nullptr : &*it;
}

template <typename Result>
inline bool ComposePatchSetSelection(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    const std::vector<PjPatchSet>& sets,
    const std::vector<PjPatchSetEnableOverride>& overrides,
    const std::vector<MappedPatchRecord>& mapped,
    const std::vector<uint8_t>& pristine,
    PjPatchSetPlan& plan,
    std::vector<uint8_t>& image,
    Result& result) {
    plan = BuildPatchSetPlan(patches, sets, overrides);
    if (!plan.success) {
        result.error = PatchSetImageError::InvalidPlan;
        return false;
    }
    std::vector<uint8_t> mask;
    try {
        mask = ActiveMask(patches.size(), plan);
    } catch (const std::bad_alloc&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    } catch (const std::length_error&) {
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    }
    std::vector<MappedPatchRecord> checked;
    if (!MapAndValidatePatchSetRecords(binary, patches, mask, checked, result,
                                       &plan))
        return false;
    // Mapping was already captured before source verification. Require exact
    // stability instead of composing against a subtly different alias map.
    if (checked.size() != mapped.size()) {
        result.error = PatchSetImageError::MappingChanged;
        return false;
    }
    for (size_t i = 0; i < mapped.size(); ++i) {
        if (checked[i].index != mapped[i].index ||
            checked[i].fileOffset != mapped[i].fileOffset ||
            checked[i].fileEnd != mapped[i].fileEnd) {
            result.error = PatchSetImageError::MappingChanged;
            return false;
        }
    }

    try {
        image = pristine;
        for (size_t index : plan.activePatchIndices) {
            const MappedPatchRecord* record = FindMappedRecord(mapped, index);
            if (!record) {
                result.failedPatch = index;
                result.failedAddress = patches[index].address;
                result.error = PatchSetImageError::MappingChanged;
                image.clear();
                return false;
            }
            const PjPatch& patch = patches[index];
            std::copy(patch.bytes.begin(), patch.bytes.end(), image.begin() +
                      static_cast<size_t>(record->fileOffset));
        }
    } catch (const std::bad_alloc&) {
        image.clear();
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    } catch (const std::length_error&) {
        image.clear();
        result.error = PatchSetImageError::AllocationFailure;
        return false;
    }
    return true;
}

template <typename Result>
inline void BuildPatchSetDiffSpans(const BinaryFile& binary,
                                   const std::vector<uint8_t>& before,
                                   const std::vector<uint8_t>& after,
                                   std::vector<PatchSetDiffSpan>& spans,
                                   uint64_t& differentByteCount,
                                   bool& truncated,
                                   Result& result) {
    constexpr size_t kMaxSpans = 65'536;
    spans.clear();
    differentByteCount = 0;
    truncated = false;
    if (before.size() != after.size()) {
        result.error = PatchSetImageError::MappingChanged;
        return;
    }
    try {
        size_t offset = 0;
        while (offset < before.size()) {
            while (offset < before.size() && before[offset] == after[offset])
                ++offset;
            if (offset == before.size()) break;
            const size_t begin = offset;
            uint64_t beginVA = 0;
            const bool beginVAValid =
                binary.offsetToVA(static_cast<uint64_t>(begin), beginVA);
            ++offset;
            while (offset < before.size() && before[offset] != after[offset]) {
                uint64_t nextVA = 0;
                const bool nextVAValid = binary.offsetToVA(
                    static_cast<uint64_t>(offset), nextVA);
                if (nextVAValid != beginVAValid ||
                    (nextVAValid &&
                     (beginVA > std::numeric_limits<uint64_t>::max() -
                                      static_cast<uint64_t>(offset - begin) ||
                      nextVA != beginVA +
                                    static_cast<uint64_t>(offset - begin))))
                    break;
                ++offset;
            }
            const size_t count = offset - begin;
            differentByteCount += static_cast<uint64_t>(count);
            if (spans.size() >= kMaxSpans) {
                truncated = true;
                continue;
            }
            PatchSetDiffSpan span;
            span.fileOffset = static_cast<uint64_t>(begin);
            span.addressValid = beginVAValid;
            span.address = beginVA;
            span.before.assign(before.begin() + begin, before.begin() + offset);
            span.after.assign(after.begin() + begin, after.begin() + offset);
            spans.push_back(std::move(span));
        }
    } catch (const std::bad_alloc&) {
        spans.clear();
        differentByteCount = 0;
        truncated = false;
        result.error = PatchSetImageError::AllocationFailure;
    } catch (const std::length_error&) {
        spans.clear();
        differentByteCount = 0;
        truncated = false;
        result.error = PatchSetImageError::AllocationFailure;
    }
}

} // namespace patched_image_detail

// Compose a requested experiment selection from pristine bytes. With
// CurrentEnabledSets, the source must first exactly match the project's saved
// enabled state; stale or partially-applied UI state is rejected transactionally.
inline PatchSetImageResult BuildPatchSetImageForSelection(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    const std::vector<PjPatchSet>& sets,
    const std::vector<PjPatchSetEnableOverride>& desiredOverrides = {},
    PatchSetImageSource sourceState = PatchSetImageSource::CurrentEnabledSets) {
    PatchSetImageResult result;
    std::vector<patched_image_detail::MappedPatchRecord> mapped;
    std::vector<uint8_t> pristine;
    if (!patched_image_detail::PreparePatchSetPristine(
            binary, patches, sets, sourceState, result.currentPlan, mapped,
            pristine, result))
        return result;
    if (!patched_image_detail::ComposePatchSetSelection(
            binary, patches, sets, desiredOverrides, mapped, pristine,
            result.desiredPlan, result.image, result))
        return result;
    patched_image_detail::BuildPatchSetDiffSpans(
        binary, binary.bytes(), result.image, result.changes,
        result.changedByteCount, result.changesTruncated, result);
    if (result.error != PatchSetImageError::None) {
        result.image.clear();
        return result;
    }
    result.success = true;
    result.failedPatch = std::numeric_limits<size_t>::max();
    result.failedAddress = 0;
    return result;
}

// Compare two selections against one verified pristine reconstruction. Neither
// selection mutates BinaryFile, and the result remains meaningful when the
// caller's current enabled state is neither the left nor the right selection.
inline PatchSetComparisonResult ComparePatchSetSelections(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    const std::vector<PjPatchSet>& sets,
    const std::vector<PjPatchSetEnableOverride>& leftOverrides,
    const std::vector<PjPatchSetEnableOverride>& rightOverrides,
    PatchSetImageSource sourceState = PatchSetImageSource::CurrentEnabledSets) {
    PatchSetComparisonResult result;
    std::vector<patched_image_detail::MappedPatchRecord> mapped;
    std::vector<uint8_t> pristine;
    if (!patched_image_detail::PreparePatchSetPristine(
            binary, patches, sets, sourceState, result.currentPlan, mapped,
            pristine, result))
        return result;
    std::vector<uint8_t> left;
    std::vector<uint8_t> right;
    if (!patched_image_detail::ComposePatchSetSelection(
            binary, patches, sets, leftOverrides, mapped, pristine,
            result.leftPlan, left, result) ||
        !patched_image_detail::ComposePatchSetSelection(
            binary, patches, sets, rightOverrides, mapped, pristine,
            result.rightPlan, right, result))
        return result;
    patched_image_detail::BuildPatchSetDiffSpans(
        binary, left, right, result.differences, result.differentByteCount,
        result.differencesTruncated, result);
    if (result.error != PatchSetImageError::None) return result;
    result.success = true;
    result.failedPatch = std::numeric_limits<size_t>::max();
    result.failedAddress = 0;
    return result;
}

} // namespace ds
