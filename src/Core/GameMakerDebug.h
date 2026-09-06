#pragma once

#include "GameMakerDebugProtocol.h"
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

inline constexpr size_t kGmlMaxWatches = 4096;
inline constexpr size_t kGmlMaxVariableNameBytes = 1024;
inline constexpr size_t kGmlMaxCodeRegions = 262144;
inline constexpr size_t kGmlMaxInstructionBoundaries = 16u * 1024u * 1024u;

inline bool GmlLocationHasIdentity(const GmlCodeLocation& location) noexcept {
    return location.archiveHash != 0 && location.codeIndex != kGmlNoCodeIndex &&
           location.parentCodeIndex != location.codeIndex && location.reserved == 0;
}
inline bool GmlPauseIdentityValid(const GmlPauseIdentity& id) noexcept {
    return id.pid && id.tid && id.sessionGeneration && id.helperGeneration && id.stopSequence;
}
inline bool GmlPauseIdentityMatches(const GmlPauseIdentity& a,
                                     const GmlPauseIdentity& b) noexcept {
    return GmlPauseIdentityValid(a) && GmlPauseIdentityValid(b) && a == b;
}

struct GmlCodeRegion {
    uint32_t codeIndex = 0;
    uint32_t parentCodeIndex = kGmlNoCodeIndex;
    uint32_t byteSize = 0;
    std::span<const uint32_t> instructionOffsets; // sorted, exact starts
    bool complete = false;
    uint32_t entryOffset = 0; // child entry lower bound in the shared root blob
};
bool ValidateGmlCodeLocation(const GmlCodeLocation& location, uint64_t archiveHash,
                             std::span<const GmlCodeRegion> regions) noexcept;
// Canonical root breakpoints also match a child executing that root offset.
// Child-qualified breakpoints remain exact to their selected CODE identity.
bool GmlBreakpointMatches(const GmlCodeLocation& breakpoint,
                          const GmlCodeLocation& current) noexcept;

struct GmlVariableTarget {
    uint64_t archiveHash = 0;
    GmlVariableScope scope = GmlVariableScope::Global;
    uint32_t objectIndex = kGmlNoCodeIndex;
    std::string variableName;
    // Transient selectors never enter project files. A frame watch is bound to
    // one thread/frame incarnation across stops; an instance watch is bound to
    // one helper/session lifetime. Numeric writes still require the exact stop.
    GmlPauseIdentity owner;
    uint64_t instanceId = 0;
    uint64_t frameId = 0;
};
inline bool GmlVariableTargetPersistent(const GmlVariableTarget& target) noexcept {
    return target.archiveHash && !target.variableName.empty() &&
        target.variableName.size() <= kGmlMaxVariableNameBytes &&
        target.variableName.find('\0') == std::string::npos &&
        ((target.scope == GmlVariableScope::Global && target.objectIndex == kGmlNoCodeIndex) ||
         (target.scope == GmlVariableScope::UniqueObject && target.objectIndex != kGmlNoCodeIndex)) &&
        target.owner == GmlPauseIdentity{} && !target.instanceId && !target.frameId;
}
struct GmlSavedBreakpoint {
    GmlCodeLocation location;
    bool enabled = true; // saved intent only; does not grant attachment/arming authority
};
struct GmlSavedWatch { GmlVariableTarget target; std::string label; };

struct GmlVariableCandidate {
    GmlVariableScope scope = GmlVariableScope::Global;
    uint32_t objectIndex = kGmlNoCodeIndex;
    std::string_view variableName;
    uint64_t instanceId = 0;
    uint64_t frameId = 0;
    size_t slotIndex = 0;
};
enum class GmlVariableResolveStatus { Resolved, InvalidTarget, StaleOwner, Missing, Ambiguous, Incomplete };
struct GmlVariableResolveResult {
    GmlVariableResolveStatus status = GmlVariableResolveStatus::InvalidTarget;
    size_t slotIndex = 0;
    bool resolved() const noexcept { return status == GmlVariableResolveStatus::Resolved; }
};
GmlVariableResolveResult ResolveGmlVariableTarget(
    const GmlVariableTarget& target, uint64_t archiveHash,
    const GmlPauseIdentity& current, std::span<const GmlVariableCandidate> candidates,
    bool complete) noexcept;
// `complete` above certifies coverage of all matching instances and variables,
// not merely that the visible numeric-slot page was copied without an error.

struct GmlProtocolValidation {
    bool valid = false;
    std::string error;
};
GmlProtocolValidation ValidateGmlHelperStop(const GmlHelperStop& stop,
    uint64_t nonce, const GmlPauseIdentity& expected, uint64_t archiveHash);
GmlProtocolValidation ValidateGmlHelperControl(const GmlHelperControl& control,
    uint64_t nonce, const GmlPauseIdentity& expected, uint64_t archiveHash,
    uint64_t lastCommandSequence);

// Helper-side stepping model: progressSequence advances at every dispatch, even
// when a loop revisits the same offset. Frame ids are incarnation ids so recursive
// calls and reused native stack addresses cannot masquerade as the anchor frame.
struct GmlExecutionPoint {
    GmlPauseIdentity identity;
    GmlCodeLocation location;
    uint64_t frameId = 0;
    uint64_t parentFrameId = 0;
    uint64_t progressSequence = 0;
    uint32_t depth = 0;
    bool ancestryComplete = false;
    std::span<const uint64_t> ancestorFrameIds; // nearest parent first
};
struct GmlStepPlan {
    GmlControlCommand command = GmlControlCommand::None;
    GmlPauseIdentity owner;
    GmlCodeLocation location;
    uint64_t frameId = 0, parentFrameId = 0, progressSequence = 0;
    uint32_t depth = 0;
    uint32_t ancestorCount = 0;
    std::array<uint64_t, kGmlMaxFrames> ancestorFrameIds{};
};
enum class GmlStepDecision { Continue, Stop, Stale, Invalid };
bool MakeGmlStepPlan(GmlControlCommand command, const GmlExecutionPoint& anchor,
                     GmlStepPlan& output) noexcept;
GmlStepDecision EvaluateGmlStep(const GmlStepPlan& plan,
                               const GmlExecutionPoint& point) noexcept;

enum class GmlBooleanEncoding : uint32_t { Unknown = 0, Float64, Int32, Int64 };
struct GmlNumericLayout {
    uint32_t realTag = 0, int32Tag = 7, int64Tag = 10, booleanTag = 13;
    bool validated = false; // set only by a completely matched built-in adapter
    GmlBooleanEncoding booleanEncoding = GmlBooleanEncoding::Unknown;
};
struct GmlNumericEditPlan {
    GmlPauseIdentity owner;
    uint64_t valueAddress = 0;
    GmlRValue expectedValue; // caller rechecks the entire tagged slot under its stop lock
    std::array<uint8_t, 8> bytes{};
    uint32_t byteCount = 0; // payload only, never the flags or type tag
};
bool PlanGmlNumericEdit(const GmlPauseIdentity& captured,
    const GmlPauseIdentity& current, const GmlHelperNumericSlot& slot,
    const GmlRValue& freshValue, const GmlNumericLayout& layout,
    std::string_view text, GmlNumericEditPlan& output, std::string* error = nullptr);

} // namespace ds
