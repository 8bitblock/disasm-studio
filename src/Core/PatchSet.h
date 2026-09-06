#pragma once
//
// PatchSet.h
// Dependency-light validation and selection for named patch experiments.
// A project keeps one ordered patch vector and assigns each record to a stable
// set id. Filtering therefore preserves deterministic global application order.
// Conflicting overlaps between named/independently-toggleable sets fail closed;
// only the implicit legacy set (id 0) retains pre-v4 ordered later-wins behavior.
//

#include "Project.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

namespace ds {

inline constexpr uint64_t kUngroupedPatchSetId = 0;
inline constexpr size_t kMaxNamedPatchSets = 128;
inline constexpr size_t kMaxPatchSetNameBytes = 128;
// Editing can temporarily create more records than the on-disk cap; adjacent
// records are losslessly coalesced/split by Project.cpp before persistence.
inline constexpr size_t kMaxPatchSetRecords = 131'072;
inline constexpr size_t kMaxPatchSetTotalBytes = 32u * 1024u * 1024u;
// One in-memory record may span the whole admitted total; Project.cpp splits
// it into bounded JSON tokens before persistence.
inline constexpr size_t kMaxPatchSetRecordBytes = kMaxPatchSetTotalBytes;
inline constexpr uint64_t kMaxPatchSetOverlapComparisonBytes =
    64ull * 1024ull * 1024ull;

struct PjPatchSetEnableOverride {
    uint64_t id = 0;
    bool enabled = true;
};

enum class PjPatchSetPlanError : uint8_t {
    None = 0,
    TooManySets,
    InvalidSetId,
    InvalidSetName,
    DuplicateSetId,
    DuplicateSetName,
    TooManyPatches,
    EmptyReplacement,
    OriginalSizeMismatch,
    PatchTooLarge,
    TotalPatchBytesExceeded,
    AddressRangeOverflow,
    UnknownPatchSet,
    DuplicateSelectionOverride,
    OverlapValidationBudgetExceeded,
    OriginalOverlapMismatch,
    ActiveOverlapConflict,
    IdSpaceExhausted,
    AllocationFailure,
};

struct PjPatchSetPlan {
    bool success = false;
    std::vector<size_t> activePatchIndices; // always in global application order
    PjPatchSetPlanError error = PjPatchSetPlanError::None;
    size_t failedPatch = std::numeric_limits<size_t>::max();
    size_t conflictingPatch = std::numeric_limits<size_t>::max();
    uint64_t failedSetId = 0;
    uint64_t conflictAddress = 0;
};

inline const char* PjPatchSetPlanErrorText(PjPatchSetPlanError error) {
    switch (error) {
    case PjPatchSetPlanError::None: return "no error";
    case PjPatchSetPlanError::TooManySets: return "too many named patch sets";
    case PjPatchSetPlanError::InvalidSetId: return "patch set id zero is reserved";
    case PjPatchSetPlanError::InvalidSetName: return "patch set name is invalid";
    case PjPatchSetPlanError::DuplicateSetId: return "patch set id is duplicated";
    case PjPatchSetPlanError::DuplicateSetName: return "patch set name is duplicated";
    case PjPatchSetPlanError::TooManyPatches: return "too many patch records";
    case PjPatchSetPlanError::EmptyReplacement: return "a replacement byte sequence is empty";
    case PjPatchSetPlanError::OriginalSizeMismatch: return "original and replacement byte counts differ";
    case PjPatchSetPlanError::PatchTooLarge: return "a patch record exceeds the bounded size";
    case PjPatchSetPlanError::TotalPatchBytesExceeded: return "total patch bytes exceed the bounded size";
    case PjPatchSetPlanError::AddressRangeOverflow: return "a patch address range overflows";
    case PjPatchSetPlanError::UnknownPatchSet: return "a patch or selection names an unknown set";
    case PjPatchSetPlanError::DuplicateSelectionOverride: return "a selection overrides one set more than once";
    case PjPatchSetPlanError::OverlapValidationBudgetExceeded: return "overlap validation exceeded its bounded comparison budget";
    case PjPatchSetPlanError::OriginalOverlapMismatch: return "overlapping records disagree about pristine bytes";
    case PjPatchSetPlanError::ActiveOverlapConflict: return "enabled patch sets write conflicting bytes";
    case PjPatchSetPlanError::IdSpaceExhausted: return "no patch set id remains available";
    case PjPatchSetPlanError::AllocationFailure: return "there was not enough memory to plan patch sets";
    }
    return "unknown patch set error";
}

namespace patch_set_detail {

inline bool ValidName(const std::string& name) {
    if (name.empty() || name.size() > kMaxPatchSetNameBytes) return false;
    const unsigned char first = static_cast<unsigned char>(name.front());
    const unsigned char last = static_cast<unsigned char>(name.back());
    if (std::isspace(first) || std::isspace(last)) return false;
    for (unsigned char c : name) {
        if (c < 0x20 || c == 0x7F) return false;
    }
    return true;
}

inline bool EqualNameAsciiInsensitive(const std::string& a,
                                      const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const unsigned char ac = static_cast<unsigned char>(a[i]);
        const unsigned char bc = static_cast<unsigned char>(b[i]);
        if (ac < 0x80 && bc < 0x80) {
            if (std::tolower(ac) != std::tolower(bc)) return false;
        } else if (ac != bc) {
            return false;
        }
    }
    return true;
}

inline const PjPatchSet* FindSet(const std::vector<PjPatchSet>& sets,
                                 uint64_t id) {
    if (id == kUngroupedPatchSetId) return nullptr;
    const auto it = std::find_if(sets.begin(), sets.end(),
        [id](const PjPatchSet& set) { return set.id == id; });
    return it == sets.end() ? nullptr : &*it;
}

inline bool ReplacementBytesAgree(const PjPatch& a, const PjPatch& b,
                                  uint64_t overlapBegin,
                                  uint64_t overlapEnd) {
    const size_t aOffset = static_cast<size_t>(overlapBegin - a.address);
    const size_t bOffset = static_cast<size_t>(overlapBegin - b.address);
    const size_t count = static_cast<size_t>(overlapEnd - overlapBegin);
    return std::equal(a.bytes.begin() + aOffset,
                      a.bytes.begin() + aOffset + count,
                      b.bytes.begin() + bOffset);
}

inline bool OriginalBytesAgree(const PjPatch& a, const PjPatch& b,
                               uint64_t overlapBegin,
                               uint64_t overlapEnd) {
    const size_t aOffset = static_cast<size_t>(overlapBegin - a.address);
    const size_t bOffset = static_cast<size_t>(overlapBegin - b.address);
    const size_t count = static_cast<size_t>(overlapEnd - overlapBegin);
    return std::equal(a.orig.begin() + aOffset,
                      a.orig.begin() + aOffset + count,
                      b.orig.begin() + bOffset);
}

} // namespace patch_set_detail

inline bool IsValidPatchSetName(const std::string& name) {
    return patch_set_detail::ValidName(name);
}

inline const PjPatchSet* FindPatchSet(const std::vector<PjPatchSet>& sets,
                                      uint64_t id) {
    return patch_set_detail::FindSet(sets, id);
}

inline bool NextPatchSetId(const std::vector<PjPatchSet>& sets,
                           uint64_t& out) {
    uint64_t greatest = 0;
    for (const PjPatchSet& set : sets) greatest = std::max(greatest, set.id);
    if (greatest == std::numeric_limits<uint64_t>::max()) return false;
    out = greatest + 1;
    return out != kUngroupedPatchSetId;
}

inline PjPatchSetPlan BuildPatchSetPlan(
    const std::vector<PjPatch>& patches,
    const std::vector<PjPatchSet>& sets,
    const std::vector<PjPatchSetEnableOverride>& overrides = {}) {
    PjPatchSetPlan result;
    if (sets.size() > kMaxNamedPatchSets) {
        result.error = PjPatchSetPlanError::TooManySets;
        return result;
    }
    if (patches.size() > kMaxPatchSetRecords) {
        result.error = PjPatchSetPlanError::TooManyPatches;
        return result;
    }

    for (size_t i = 0; i < sets.size(); ++i) {
        const PjPatchSet& set = sets[i];
        result.failedSetId = set.id;
        if (set.id == kUngroupedPatchSetId) {
            result.error = PjPatchSetPlanError::InvalidSetId;
            return result;
        }
        if (!patch_set_detail::ValidName(set.name)) {
            result.error = PjPatchSetPlanError::InvalidSetName;
            return result;
        }
        for (size_t j = 0; j < i; ++j) {
            if (sets[j].id == set.id) {
                result.error = PjPatchSetPlanError::DuplicateSetId;
                return result;
            }
            if (patch_set_detail::EqualNameAsciiInsensitive(
                    sets[j].name, set.name)) {
                result.error = PjPatchSetPlanError::DuplicateSetName;
                return result;
            }
        }
    }

    for (size_t i = 0; i < overrides.size(); ++i) {
        result.failedSetId = overrides[i].id;
        if (overrides[i].id != kUngroupedPatchSetId &&
            !patch_set_detail::FindSet(sets, overrides[i].id)) {
            result.error = PjPatchSetPlanError::UnknownPatchSet;
            return result;
        }
        for (size_t j = 0; j < i; ++j) {
            if (overrides[j].id == overrides[i].id) {
                result.error = PjPatchSetPlanError::DuplicateSelectionOverride;
                return result;
            }
        }
    }

    auto enabled = [&](uint64_t id) {
        for (const PjPatchSetEnableOverride& value : overrides)
            if (value.id == id) return value.enabled;
        if (id == kUngroupedPatchSetId) return true;
        const PjPatchSet* set = patch_set_detail::FindSet(sets, id);
        return set && set->enabled;
    };

    size_t totalBytes = 0;
    std::vector<uint8_t> active;
    std::vector<size_t> addressOrder;
    try {
        active.assign(patches.size(), 0);
        addressOrder.resize(patches.size());
        result.activePatchIndices.reserve(patches.size());
    } catch (const std::bad_alloc&) {
        result.error = PjPatchSetPlanError::AllocationFailure;
        return result;
    } catch (const std::length_error&) {
        result.error = PjPatchSetPlanError::AllocationFailure;
        return result;
    }

    for (size_t i = 0; i < patches.size(); ++i) {
        const PjPatch& patch = patches[i];
        result.failedPatch = i;
        result.failedSetId = patch.patchSetId;
        if (patch.bytes.empty()) {
            result.error = PjPatchSetPlanError::EmptyReplacement;
            return result;
        }
        if (patch.orig.size() != patch.bytes.size()) {
            result.error = PjPatchSetPlanError::OriginalSizeMismatch;
            return result;
        }
        if (patch.bytes.size() > kMaxPatchSetRecordBytes) {
            result.error = PjPatchSetPlanError::PatchTooLarge;
            return result;
        }
        if (patch.bytes.size() > kMaxPatchSetTotalBytes -
                (std::min)(totalBytes, kMaxPatchSetTotalBytes)) {
            result.error = PjPatchSetPlanError::TotalPatchBytesExceeded;
            return result;
        }
        totalBytes += patch.bytes.size();
        if (patch.address > std::numeric_limits<uint64_t>::max() -
                static_cast<uint64_t>(patch.bytes.size())) {
            result.error = PjPatchSetPlanError::AddressRangeOverflow;
            return result;
        }
        if (patch.patchSetId != kUngroupedPatchSetId &&
            !patch_set_detail::FindSet(sets, patch.patchSetId)) {
            result.error = PjPatchSetPlanError::UnknownPatchSet;
            return result;
        }
        active[i] = enabled(patch.patchSetId) ? 1 : 0;
        if (active[i]) result.activePatchIndices.push_back(i);
        addressOrder[i] = i;
    }

    std::stable_sort(addressOrder.begin(), addressOrder.end(),
        [&](size_t a, size_t b) {
            if (patches[a].address != patches[b].address)
                return patches[a].address < patches[b].address;
            return a < b;
        });

    uint64_t comparedBytes = 0;
    for (size_t oi = 0; oi < addressOrder.size(); ++oi) {
        const size_t i = addressOrder[oi];
        const PjPatch& first = patches[i];
        const uint64_t firstEnd =
            first.address + static_cast<uint64_t>(first.bytes.size());
        for (size_t oj = oi + 1; oj < addressOrder.size(); ++oj) {
            const size_t j = addressOrder[oj];
            const PjPatch& second = patches[j];
            if (second.address >= firstEnd) break;
            const uint64_t secondEnd =
                second.address + static_cast<uint64_t>(second.bytes.size());
            const uint64_t overlapBegin =
                std::max(first.address, second.address);
            const uint64_t overlapEnd = std::min(firstEnd, secondEnd);
            if (overlapBegin >= overlapEnd) continue;
            const uint64_t count = overlapEnd - overlapBegin;
            if (count > kMaxPatchSetOverlapComparisonBytes -
                    std::min(comparedBytes,
                             kMaxPatchSetOverlapComparisonBytes)) {
                result.failedPatch = i;
                result.conflictingPatch = j;
                result.conflictAddress = overlapBegin;
                result.error =
                    PjPatchSetPlanError::OverlapValidationBudgetExceeded;
                return result;
            }
            comparedBytes += count;
            if (!patch_set_detail::OriginalBytesAgree(
                    first, second, overlapBegin, overlapEnd)) {
                result.failedPatch = i;
                result.conflictingPatch = j;
                result.conflictAddress = overlapBegin;
                result.error = PjPatchSetPlanError::OriginalOverlapMismatch;
                return result;
            }
            if (active[i] && active[j] &&
                !patch_set_detail::ReplacementBytesAgree(
                    first, second, overlapBegin, overlapEnd) &&
                !(first.patchSetId == kUngroupedPatchSetId &&
                  second.patchSetId == kUngroupedPatchSetId)) {
                result.failedPatch = i;
                result.conflictingPatch = j;
                result.conflictAddress = overlapBegin;
                result.error = PjPatchSetPlanError::ActiveOverlapConflict;
                return result;
            }
        }
    }

    result.success = true;
    result.error = PjPatchSetPlanError::None;
    result.failedPatch = std::numeric_limits<size_t>::max();
    result.conflictingPatch = std::numeric_limits<size_t>::max();
    result.failedSetId = 0;
    result.conflictAddress = 0;
    return result;
}

// Take an owned snapshot of exactly the records selected by a validated plan.
// Background consumers must not copy ProjectState::patches directly: that would
// silently apply disabled experiments and could compose mutually-exclusive
// alternatives. The output is cleared on every failure so callers fail closed.
inline PjPatchSetPlan SnapshotActivePatchRecords(
    const std::vector<PjPatch>& patches,
    const std::vector<PjPatchSet>& sets,
    std::vector<PjPatch>& snapshot,
    const std::vector<PjPatchSetEnableOverride>& overrides = {}) {
    snapshot.clear();
    PjPatchSetPlan plan = BuildPatchSetPlan(patches, sets, overrides);
    if (!plan.success) return plan;

    try {
        std::vector<PjPatch> selected;
        selected.reserve(plan.activePatchIndices.size());
        for (size_t index : plan.activePatchIndices)
            selected.push_back(patches[index]);
        snapshot.swap(selected);
    } catch (const std::bad_alloc&) {
        plan.success = false;
        plan.error = PjPatchSetPlanError::AllocationFailure;
        plan.activePatchIndices.clear();
    } catch (const std::length_error&) {
        plan.success = false;
        plan.error = PjPatchSetPlanError::AllocationFailure;
        plan.activePatchIndices.clear();
    }
    return plan;
}

} // namespace ds
