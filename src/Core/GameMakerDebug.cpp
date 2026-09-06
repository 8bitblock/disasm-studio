#include "GameMakerDebug.h"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>

namespace ds {
namespace {
bool sameSession(const GmlPauseIdentity& a, const GmlPauseIdentity& b) noexcept {
    return GmlPauseIdentityValid(a) && GmlPauseIdentityValid(b) &&
        a.pid == b.pid && a.sessionGeneration == b.sessionGeneration &&
        a.helperGeneration == b.helperGeneration;
}
bool userRange(uint64_t address, uint64_t size) noexcept {
    constexpr uint64_t maximum = 0x00007FFFFFFFFFFFull;
    return address && size && address <= maximum && size - 1 <= maximum - address;
}
bool numericKind(GmlNumericKind kind) noexcept {
    return kind >= GmlNumericKind::Real && kind <= GmlNumericKind::Boolean;
}
bool pointValid(const GmlExecutionPoint& point) noexcept {
    if (!GmlPauseIdentityValid(point.identity) || !GmlLocationHasIdentity(point.location) ||
        !point.frameId || !point.progressSequence || !point.ancestryComplete ||
        point.depth >= kGmlMaxFrames || point.ancestorFrameIds.size() != point.depth ||
        (point.depth ? point.parentFrameId != point.ancestorFrameIds.front()
                     : point.parentFrameId != 0)) return false;
    for (size_t i = 0; i < point.ancestorFrameIds.size(); ++i) {
        const uint64_t id = point.ancestorFrameIds[i];
        if (!id || id == point.frameId) return false;
        for (size_t j = 0; j < i; ++j)
            if (point.ancestorFrameIds[j] == id) return false;
    }
    return true;
}
GmlProtocolValidation fail(const char* error) { return { false, error }; }
}

bool ValidateGmlCodeLocation(const GmlCodeLocation& location, uint64_t archiveHash,
                             std::span<const GmlCodeRegion> regions) noexcept {
    if (!GmlLocationHasIdentity(location) || location.archiveHash != archiveHash ||
        regions.size() > kGmlMaxCodeRegions) return false;
    const GmlCodeRegion* found = nullptr;
    for (const GmlCodeRegion& region : regions) {
        if (region.codeIndex != location.codeIndex) continue;
        if (found) return false; // duplicate code identity is not authoritative
        found = &region;
    }
    if (!found || !found->complete || found->parentCodeIndex != location.parentCodeIndex ||
        location.byteOffset < found->entryOffset || location.byteOffset >= found->byteSize ||
        found->instructionOffsets.empty() || found->instructionOffsets.size() > kGmlMaxInstructionBoundaries)
        return false;
    // Input is normally a cached exact decoder result. Validate its sorted unique
    // shape here rather than allowing malformed boundaries to arm a breakpoint.
    uint32_t previous = 0;
    bool first = true, matched = false;
    for (uint32_t offset : found->instructionOffsets) {
        if (offset >= found->byteSize || (!first && offset <= previous)) return false;
        matched = matched || offset == location.byteOffset;
        previous = offset;
        first = false;
    }
    return matched;
}

bool GmlBreakpointMatches(const GmlCodeLocation& breakpoint,
                          const GmlCodeLocation& current) noexcept {
    if (!GmlLocationHasIdentity(breakpoint) || !GmlLocationHasIdentity(current) ||
        breakpoint.archiveHash != current.archiveHash || breakpoint.byteOffset != current.byteOffset)
        return false;
    return (breakpoint.codeIndex == current.codeIndex && breakpoint.parentCodeIndex == current.parentCodeIndex) ||
        (breakpoint.parentCodeIndex == kGmlNoCodeIndex && current.parentCodeIndex == breakpoint.codeIndex);
}

GmlVariableResolveResult ResolveGmlVariableTarget(
    const GmlVariableTarget& target, uint64_t archiveHash,
    const GmlPauseIdentity& current, std::span<const GmlVariableCandidate> candidates,
    bool complete) noexcept {
    if (!GmlPauseIdentityValid(current) || !target.archiveHash || target.archiveHash != archiveHash ||
        target.variableName.empty() || target.variableName.size() > kGmlMaxVariableNameBytes ||
        target.variableName.find('\0') != std::string::npos || candidates.size() > kGmlMaxNumericSlots)
        return {};
    if (target.scope == GmlVariableScope::Global || target.scope == GmlVariableScope::UniqueObject) {
        if (!GmlVariableTargetPersistent(target)) return {};
    } else if (target.scope == GmlVariableScope::SessionInstance) {
        if (!target.instanceId || target.frameId || target.objectIndex == kGmlNoCodeIndex) return {};
        if (!sameSession(target.owner, current)) return { GmlVariableResolveStatus::StaleOwner };
    } else if (target.scope == GmlVariableScope::FrameLocal) {
        if (!target.frameId || target.instanceId || target.objectIndex != kGmlNoCodeIndex) return {};
        if (!sameSession(target.owner, current) || target.owner.tid != current.tid) return { GmlVariableResolveStatus::StaleOwner };
    } else return {};
    // Absence/uniqueness cannot be proved from truncated instance enumeration.
    if (!complete) return { GmlVariableResolveStatus::Incomplete };
    GmlVariableResolveResult result{ GmlVariableResolveStatus::Missing };
    for (const auto& candidate : candidates) {
        if (candidate.variableName != target.variableName) continue;
        bool match = false;
        switch (target.scope) {
        case GmlVariableScope::Global:
            match = candidate.scope == GmlVariableScope::Global && !candidate.instanceId && !candidate.frameId;
            break;
        case GmlVariableScope::UniqueObject:
            match = candidate.scope == GmlVariableScope::SessionInstance && candidate.instanceId &&
                    candidate.objectIndex == target.objectIndex;
            break;
        case GmlVariableScope::SessionInstance:
            match = candidate.scope == GmlVariableScope::SessionInstance &&
                candidate.instanceId == target.instanceId && candidate.objectIndex == target.objectIndex;
            break;
        case GmlVariableScope::FrameLocal:
            match = candidate.scope == GmlVariableScope::FrameLocal && candidate.frameId == target.frameId;
            break;
        }
        if (!match) continue;
        if (candidate.slotIndex >= kGmlMaxNumericSlots) return {};
        if (result.resolved()) return { GmlVariableResolveStatus::Ambiguous };
        result = { GmlVariableResolveStatus::Resolved, candidate.slotIndex };
    }
    return result;
}

GmlProtocolValidation ValidateGmlHelperStop(const GmlHelperStop& stop,
    uint64_t nonce, const GmlPauseIdentity& expected, uint64_t archiveHash) {
    if (stop.magic != kGmlProtocolMagic || stop.version != kGmlProtocolVersion ||
        stop.byteSize != sizeof(stop)) return fail("helper stop protocol/version mismatch");
    if (!nonce || stop.nonce != nonce || !GmlPauseIdentityMatches(stop.identity, expected))
        return fail("helper stop belongs to another session/thread/sequence");
    if (!GmlLocationHasIdentity(stop.location) || stop.location.archiveHash != archiveHash ||
        stop.reason < GmlStopReason::Breakpoint || stop.reason > GmlStopReason::Error ||
        stop.reserved || !stop.frameCount || stop.frameCount > kGmlMaxFrames ||
        stop.numericSlotCount > kGmlMaxNumericSlots || stop.framesComplete > 1 || stop.variablesComplete > 1 ||
        stop.globalsComplete > 1 || stop.scopeReserved || stop.instanceCount > kGmlMaxInstances ||
        stop.instancesComplete > 1 || stop.instanceVariablesComplete > 1 || stop.instancesReserved ||
        stop.selectionReserved || (stop.selectedInstanceId && stop.selectedObjectIndex != kGmlNoCodeIndex) ||
        (stop.instanceVariablesComplete && (!stop.instancesComplete ||
            (!stop.selectedInstanceId && stop.selectedObjectIndex == kGmlNoCodeIndex))))
        return fail("helper stop has invalid location/count/flags");
    for (uint32_t i = 0; i < stop.frameCount; ++i) {
        const auto& frame = stop.frames[i];
        if (!frame.frameId || frame.reserved || frame.ownerReserved || frame.depth >= kGmlMaxFrames ||
            (frame.flags & ~kGmlFrameKnownFlags) || frame.localsAvailability > GmlValueAvailability::Truncated ||
            frame.selfAvailability > GmlValueAvailability::Truncated ||
            (frame.localsAvailability == GmlValueAvailability::Available && !frame.localObject) ||
            (frame.selfAvailability == GmlValueAvailability::Available && !frame.selfObject) ||
            (frame.localObject && !userRange(frame.localObject, 1)) ||
            (frame.selfObject && !userRange(frame.selfObject, 1)) ||
            (frame.logicalAnchor && !userRange(frame.logicalAnchor, 1)) ||
            (frame.argumentCount && !userRange(frame.arguments, uint64_t(frame.argumentCount) * sizeof(GmlRValue))) ||
            ((frame.flags & kGmlFrameAddressValid) && !userRange(frame.frameAddress, 1)) ||
            ((frame.flags & kGmlFrameStackTopValid) && !userRange(frame.operandStackTop, 1)) ||
            !GmlLocationHasIdentity(frame.location) || frame.location.archiveHash != archiveHash ||
            (i == 0 && frame.location != stop.location)) return fail("invalid helper frame");
        for (uint32_t j = 0; j < i; ++j)
            if (stop.frames[j].frameId == frame.frameId) return fail("cyclic helper frames");
        if (i + 1 < stop.frameCount && (frame.parentFrameId != stop.frames[i + 1].frameId ||
            frame.depth != stop.frames[i + 1].depth + 1)) return fail("inexact helper frame ancestry");
        if (i + 1 == stop.frameCount && stop.framesComplete && (frame.parentFrameId || frame.depth))
            return fail("helper frame stack marked complete without a root");
    }
    for (uint32_t i = 0; i < stop.numericSlotCount; ++i) {
        const auto& slot = stop.numericSlots[i];
        if (slot.reserved || slot.ownerReserved || slot.writable > 1 || !numericKind(slot.kind) ||
            slot.availability > GmlValueAvailability::Truncated || slot.storage > GmlSlotStorage::Copied ||
            slot.scope > GmlVariableScope::FrameLocal || slot.nameLength > sizeof(slot.name) ||
            (slot.ownerObject && !userRange(slot.ownerObject, 1)) ||
            (slot.nameLength && slot.nameLength < sizeof(slot.name) &&
             (slot.name[slot.nameLength] != '\0' || std::memchr(slot.name, '\0', slot.nameLength))) ||
            (slot.storage == GmlSlotStorage::Canonical && !userRange(slot.address, sizeof(GmlRValue))) ||
            (slot.writable && (!userRange(slot.ownerObject, 1) || slot.storage != GmlSlotStorage::Canonical ||
                               slot.availability != GmlValueAvailability::Available)))
            return fail("invalid helper numeric slot");
        if (slot.frameId) {
            bool found = false;
            for (uint32_t j = 0; j < stop.frameCount; ++j)
                found = found || stop.frames[j].frameId == slot.frameId;
            if (!found) return fail("numeric slot refers to an uncaptured frame");
        }
    }
    for (uint32_t i = 0; i < stop.instanceCount; ++i) {
        const auto& instance = stop.instances[i];
        if (!instance.instanceId || !userRange(instance.objectAddress, 1) || instance.objectIndex == kGmlNoCodeIndex ||
            instance.reserved || instance.variablesAvailability > GmlValueAvailability::Truncated)
            return fail("invalid helper instance");
        for (uint32_t j = 0; j < i; ++j)
            if (stop.instances[j].instanceId == instance.instanceId || stop.instances[j].objectAddress == instance.objectAddress)
                return fail("duplicate helper instance");
    }
    return { true, {} };
}

GmlProtocolValidation ValidateGmlHelperControl(const GmlHelperControl& control,
    uint64_t nonce, const GmlPauseIdentity& expected, uint64_t archiveHash,
    uint64_t lastCommandSequence) {
    if (control.magic != kGmlProtocolMagic || control.version != kGmlProtocolVersion ||
        control.byteSize != sizeof(control)) return fail("helper control protocol/version mismatch");
    if (!nonce || control.nonce != nonce || !GmlPauseIdentityMatches(control.expectedStop, expected) ||
        !control.commandSequence || control.commandSequence <= lastCommandSequence)
        return fail("stale helper control session/sequence");
    if (control.reserved || control.selectionReserved ||
        (control.selectedInstanceId && control.selectedObjectIndex != kGmlNoCodeIndex) ||
        control.command < GmlControlCommand::Continue ||
        control.command > GmlControlCommand::Disable || control.breakpointCount > kGmlMaxBreakpoints)
        return fail("invalid helper command/count");
    const bool step = control.command >= GmlControlCommand::StepInto && control.command <= GmlControlCommand::StepOut;
    if (step && (!control.anchorFrameId || !GmlLocationHasIdentity(control.anchorLocation) ||
        control.anchorLocation.archiveHash != archiveHash || control.anchorDepth >= kGmlMaxFrames ||
        (control.anchorDepth ? !control.anchorParentFrameId : control.anchorParentFrameId != 0)))
        return fail("invalid helper step anchor");
    for (uint32_t i = 0; i < control.breakpointCount; ++i) {
        if (!GmlLocationHasIdentity(control.breakpoints[i]) || control.breakpoints[i].archiveHash != archiveHash)
            return fail("invalid helper breakpoint identity");
        for (uint32_t j = 0; j < i; ++j)
            if (control.breakpoints[i] == control.breakpoints[j]) return fail("duplicate helper breakpoint");
    }
    return { true, {} };
}

bool MakeGmlStepPlan(GmlControlCommand command, const GmlExecutionPoint& anchor,
                     GmlStepPlan& output) noexcept {
    output = {};
    if (command < GmlControlCommand::StepInto || command > GmlControlCommand::StepOut ||
        !pointValid(anchor)) return false;
    output.command = command;
    output.owner = anchor.identity;
    output.location = anchor.location;
    output.frameId = anchor.frameId;
    output.parentFrameId = anchor.parentFrameId;
    output.progressSequence = anchor.progressSequence;
    output.depth = anchor.depth;
    output.ancestorCount = static_cast<uint32_t>(anchor.ancestorFrameIds.size());
    std::copy(anchor.ancestorFrameIds.begin(), anchor.ancestorFrameIds.end(), output.ancestorFrameIds.begin());
    return true;
}

GmlStepDecision EvaluateGmlStep(const GmlStepPlan& plan, const GmlExecutionPoint& point) noexcept {
    if (!GmlPauseIdentityMatches(plan.owner, point.identity) ||
        plan.location.archiveHash != point.location.archiveHash) return GmlStepDecision::Stale;
    if (!pointValid(point) || !plan.frameId || !plan.progressSequence ||
        plan.ancestorCount != plan.depth || plan.ancestorCount >= kGmlMaxFrames ||
        plan.command < GmlControlCommand::StepInto || plan.command > GmlControlCommand::StepOut)
        return GmlStepDecision::Invalid;
    if (point.progressSequence < plan.progressSequence) return GmlStepDecision::Stale;
    if (point.progressSequence == plan.progressSequence) return GmlStepDecision::Continue;
    if (plan.command == GmlControlCommand::StepInto) return GmlStepDecision::Stop;
    if (point.frameId == plan.frameId) {
        if (point.depth != plan.depth) return GmlStepDecision::Invalid;
        return plan.command == GmlControlCommand::StepOver ? GmlStepDecision::Stop : GmlStepDecision::Continue;
    }
    if (point.depth > plan.depth && point.ancestorFrameIds[point.depth - plan.depth - 1] == plan.frameId)
        return GmlStepDecision::Continue;
    if (std::find(point.ancestorFrameIds.begin(), point.ancestorFrameIds.end(), plan.frameId) != point.ancestorFrameIds.end())
        return GmlStepDecision::Invalid; // the same incarnation cannot change depth
    // pointValid requires complete, consistent ancestry on the same thread.
    // Its absence proves that the anchor left the active GML call chain, even
    // after unwinding past every caller or returning from a top-level event.
    // Stop at this next GML boundary; never manufacture a native caller frame.
    return GmlStepDecision::Stop;
}

bool PlanGmlNumericEdit(const GmlPauseIdentity& captured,
    const GmlPauseIdentity& current, const GmlHelperNumericSlot& slot,
    const GmlRValue& freshValue, const GmlNumericLayout& layout,
    std::string_view text, GmlNumericEditPlan& output, std::string* error) {
    output = {};
    if (error) error->clear();
    auto reject = [&](const char* message) { if (error) *error = message; return false; };
    if (!GmlPauseIdentityMatches(captured, current)) return reject("GML stop is stale");
    if (!layout.validated || !numericKind(slot.kind) || slot.writable != 1 || slot.reserved ||
        slot.storage != GmlSlotStorage::Canonical || slot.availability != GmlValueAvailability::Available ||
        !userRange(slot.address, sizeof(GmlRValue))) return reject("slot is not a validated writable numeric value");
    const uint32_t tags[] = { layout.realTag, layout.int32Tag, layout.int64Tag, layout.booleanTag };
    for (size_t i = 0; i < 4; ++i)
        for (size_t j = 0; j < i; ++j)
            if (tags[i] == tags[j]) return reject("numeric adapter tags are ambiguous");
    if (slot.value != freshValue || slot.value.typeTag != tags[static_cast<uint32_t>(slot.kind) - 1])
        return reject("numeric value or type changed since this stop was captured");
    if (text.empty() || text.size() > 128) return reject("enter one bounded numeric value");
    uint64_t payload = 0;
    uint32_t size = 8;
    if (slot.kind == GmlNumericKind::Real) {
        double value = 0;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || !std::isfinite(value))
            return reject("real value must be a finite decimal number");
        payload = std::bit_cast<uint64_t>(value);
    } else if (slot.kind == GmlNumericKind::Boolean) {
        bool value = false;
        if (text == "true" || text == "1") value = true;
        else if (text == "false" || text == "0") value = false;
        else return reject("boolean value must be true, false, 0 or 1");
        switch (layout.booleanEncoding) {
        case GmlBooleanEncoding::Float64: payload = std::bit_cast<uint64_t>(value ? 1.0 : 0.0); break;
        case GmlBooleanEncoding::Int32: payload = value ? 1 : 0; size = 4; break;
        case GmlBooleanEncoding::Int64: payload = value ? 1 : 0; break;
        default: return reject("boolean storage is not proved for this runner adapter");
        }
    } else {
        int64_t value = 0;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
            return reject("integer value must be a complete signed decimal integer");
        if (slot.kind == GmlNumericKind::Int32) {
            if (value < INT32_MIN || value > INT32_MAX) return reject("integer does not fit the existing int32 type");
            size = 4;
            payload = static_cast<uint32_t>(static_cast<int32_t>(value));
        } else payload = static_cast<uint64_t>(value);
    }
    GmlNumericEditPlan plan;
    plan.owner = current;
    plan.valueAddress = slot.address;
    plan.expectedValue = freshValue;
    plan.byteCount = size;
    for (uint32_t i = 0; i < size; ++i) plan.bytes[i] = static_cast<uint8_t>(payload >> (i * 8));
    output = plan;
    return true;
}

} // namespace ds
