#pragma once

#include "DebugTargetIdentity.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ds {

// Runtime bytes are deliberately transient: persisted patch.orig always belongs
// to the pristine FILE image, while these records retain the exact bytes observed
// in one debugger session so a live revert never writes FILE bytes into a relocated
// or self-modified process.
struct LivePatchOriginal {
    DebugTargetIdentity owner{};
    uint64_t runtimeVA = 0;
    std::vector<uint8_t> bytes;
};

using LivePatchOriginalMap = std::unordered_map<uint64_t, LivePatchOriginal>;

inline constexpr size_t kMaxLivePatchOriginalRecords = 4096;
inline constexpr size_t kMaxLivePatchOriginalSpan = 1u << 20;
inline constexpr size_t kMaxLivePatchOriginalBytes = 32u * 1024u * 1024u;

enum class LivePatchOriginalError : uint8_t {
    None = 0,
    InvalidIdentity,
    EmptySpan,
    SpanTooLarge,
    AddressOverflow,
    ReadFailed,
    OwnerConflict,
    RuntimeMappingConflict,
    RecordLimit,
    ByteLimit,
    AccountingMismatch,
};

struct LivePatchOriginalPlan {
    bool success = false;
    LivePatchOriginalError error = LivePatchOriginalError::None;
    LivePatchOriginal original;
    size_t retainedBytesAfter = 0;
};

inline const char* LivePatchOriginalErrorText(LivePatchOriginalError error) {
    switch (error) {
    case LivePatchOriginalError::None:                   return "no error";
    case LivePatchOriginalError::InvalidIdentity:        return "the debugger session identity is invalid";
    case LivePatchOriginalError::EmptySpan:              return "the runtime patch span is empty";
    case LivePatchOriginalError::SpanTooLarge:           return "the runtime patch span exceeds the safety limit";
    case LivePatchOriginalError::AddressOverflow:        return "the runtime patch span overflows its address space";
    case LivePatchOriginalError::ReadFailed:              return "the exact-session runtime read was incomplete";
    case LivePatchOriginalError::OwnerConflict:          return "a retained original belongs to another debugger session";
    case LivePatchOriginalError::RuntimeMappingConflict: return "the live module mapping changed within the session";
    case LivePatchOriginalError::RecordLimit:            return "the runtime-original record limit was reached";
    case LivePatchOriginalError::ByteLimit:              return "the runtime-original byte budget was reached";
    case LivePatchOriginalError::AccountingMismatch:     return "the runtime-original byte accounting is inconsistent";
    }
    return "unknown runtime-original error";
}

// Given an identity-checked read of the current runtime span, reconstruct its
// pre-patch bytes by substituting originals retained for overlapping patches in
// the same session. This makes overlapping patches and same-address repatches
// reversible without ever borrowing persisted FILE originals.
inline LivePatchOriginalPlan PlanLivePatchOriginal(
    const LivePatchOriginalMap& retained,
    size_t retainedBytes,
    DebugTargetIdentity owner,
    uint64_t fileVA,
    uint64_t runtimeVA,
    std::vector<uint8_t> observed) {
    LivePatchOriginalPlan result;
    auto fail = [&](LivePatchOriginalError error) {
        result.error = error;
        return result;
    };

    if (!owner.valid()) return fail(LivePatchOriginalError::InvalidIdentity);
    if (observed.empty()) return fail(LivePatchOriginalError::EmptySpan);
    if (observed.size() > kMaxLivePatchOriginalSpan)
        return fail(LivePatchOriginalError::SpanTooLarge);
    const uint64_t span = static_cast<uint64_t>(observed.size());
    if (fileVA > std::numeric_limits<uint64_t>::max() - span ||
        runtimeVA > std::numeric_limits<uint64_t>::max() - span)
        return fail(LivePatchOriginalError::AddressOverflow);

    const auto exact = retained.find(fileVA);
    if (exact != retained.end()) {
        if (!DebugTargetIdentityMatches(exact->second.owner, owner))
            return fail(LivePatchOriginalError::OwnerConflict);
        if (exact->second.runtimeVA != runtimeVA)
            return fail(LivePatchOriginalError::RuntimeMappingConflict);
    }

    for (const auto& [priorFileVA, prior] : retained) {
        if (!DebugTargetIdentityMatches(prior.owner, owner) || prior.bytes.empty()) continue;

        size_t outOffset = 0;
        size_t priorOffset = 0;
        if (priorFileVA <= fileVA) {
            const uint64_t delta = fileVA - priorFileVA;
            if (delta >= prior.bytes.size()) continue;
            priorOffset = static_cast<size_t>(delta);
        } else {
            const uint64_t delta = priorFileVA - fileVA;
            if (delta >= observed.size()) continue;
            outOffset = static_cast<size_t>(delta);
        }

        const size_t count = std::min(observed.size() - outOffset,
                                      prior.bytes.size() - priorOffset);
        if (!count) continue;
        if (prior.runtimeVA > std::numeric_limits<uint64_t>::max() - priorOffset ||
            runtimeVA + outOffset != prior.runtimeVA + priorOffset)
            return fail(LivePatchOriginalError::RuntimeMappingConflict);
        std::copy_n(prior.bytes.begin() + priorOffset, count,
                    observed.begin() + outOffset);
    }

    const size_t oldSize = exact == retained.end() ? 0 : exact->second.bytes.size();
    if (retainedBytes < oldSize)
        return fail(LivePatchOriginalError::AccountingMismatch);
    if (exact == retained.end() && retained.size() >= kMaxLivePatchOriginalRecords)
        return fail(LivePatchOriginalError::RecordLimit);
    const size_t withoutOld = retainedBytes - oldSize;
    if (observed.size() > kMaxLivePatchOriginalBytes -
            std::min(withoutOld, kMaxLivePatchOriginalBytes))
        return fail(LivePatchOriginalError::ByteLimit);

    result.success = true;
    result.original.owner = owner;
    result.original.runtimeVA = runtimeVA;
    result.original.bytes = std::move(observed);
    result.retainedBytesAfter = withoutOld + result.original.bytes.size();
    return result;
}

inline const LivePatchOriginal* FindLivePatchOriginal(
    const LivePatchOriginalMap& retained,
    uint64_t fileVA,
    DebugTargetIdentity owner,
    uint64_t runtimeVA,
    size_t size) {
    const auto found = retained.find(fileVA);
    if (found == retained.end() ||
        !DebugTargetIdentityMatches(found->second.owner, owner) ||
        found->second.runtimeVA != runtimeVA ||
        found->second.bytes.size() != size)
        return nullptr;
    return &found->second;
}

inline bool LivePatchSpansOverlap(uint64_t a, size_t aSize,
                                  uint64_t b, size_t bSize) {
    if (!aSize || !bSize) return false;
    return a <= b ? b - a < static_cast<uint64_t>(aSize)
                  : a - b < static_cast<uint64_t>(bSize);
}

} // namespace ds
