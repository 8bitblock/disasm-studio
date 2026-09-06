#include "Core/GameMakerDebug.h"
#include <array>
#include <bit>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace ds;
static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)

static GmlPauseIdentity owner() { return { 12, 34, 56, 78, 90 }; }
static GmlCodeLocation location(uint32_t offset = 0) { return { 0xFEDCBA9876543210ull, 0, offset }; }
static GmlHelperNumericSlot numericSlot(GmlNumericKind kind, uint32_t tag, uint64_t payload = 0) {
    GmlHelperNumericSlot slot;
    slot.address = 0x12345000;
    slot.ownerObject = 0x56789000;
    slot.value = { payload, 0x12345678, tag };
    slot.kind = kind;
    slot.writable = 1;
    slot.storage = GmlSlotStorage::Canonical;
    slot.availability = GmlValueAvailability::Available;
    return slot;
}
static uint64_t editedPayload(const GmlNumericEditPlan& plan) {
    uint64_t bits = 0;
    for (uint32_t i = 0; i < plan.byteCount; ++i) bits |= uint64_t(plan.bytes[i]) << (i * 8);
    return bits;
}

int main() {
    // Zero CODE index and zero instruction offset are exact valid identities.
    const std::array<uint32_t, 3> starts{ 0, 4, 12 };
    std::array<GmlCodeRegion, 1> code{ GmlCodeRegion{ 0, kGmlNoCodeIndex, 16, starts, true } };
    CHECK(ValidateGmlCodeLocation(location(), location().archiveHash, code));
    CHECK(ValidateGmlCodeLocation(location(12), location().archiveHash, code));
    CHECK(!ValidateGmlCodeLocation(location(1), location().archiveHash, code));
    CHECK(!ValidateGmlCodeLocation(location(16), location().archiveHash, code));
    CHECK(!ValidateGmlCodeLocation(location(), 123, code));
    auto child = location(); child.parentCodeIndex = 1;
    CHECK(!ValidateGmlCodeLocation(child, child.archiveHash, code));
    code[0].parentCodeIndex = 1;
    CHECK(ValidateGmlCodeLocation(child, child.archiveHash, code));
    code[0].entryOffset = 4;
    CHECK(!ValidateGmlCodeLocation(child, child.archiveHash, code));
    child.byteOffset = 4;
    CHECK(ValidateGmlCodeLocation(child, child.archiveHash, code));
    auto rootLocation = child; rootLocation.codeIndex = 1; rootLocation.parentCodeIndex = kGmlNoCodeIndex;
    CHECK(GmlBreakpointMatches(rootLocation, child));
    CHECK(!GmlBreakpointMatches(child, rootLocation));
    CHECK(GmlBreakpointMatches(child, child));
    code[0].complete = false;
    CHECK(!ValidateGmlCodeLocation(child, child.archiveHash, code));
    code[0].complete = true;
    const std::array<uint32_t, 3> malformed{ 0, 4, 4 };
    code[0].instructionOffsets = malformed;
    CHECK(!ValidateGmlCodeLocation(child, child.archiveHash, code));
    auto invalidLocation = location(); invalidLocation.reserved = 1;
    CHECK(!GmlLocationHasIdentity(invalidLocation));

    auto stop = std::make_unique<GmlHelperStop>();
    stop->nonce = 123;
    stop->identity = owner();
    stop->location = location();
    stop->reason = GmlStopReason::Breakpoint;
    stop->frameCount = 2;
    stop->framesComplete = 1;
    stop->variablesComplete = 1;
    stop->frames[0] = { 200, 100, 55, location(), 1 };
    stop->frames[1] = { 100, 0, 55, location(4), 0 };
    stop->numericSlotCount = 1;
    stop->numericSlots[0] = numericSlot(GmlNumericKind::Int32, 7);
    stop->numericSlots[0].frameId = 200;
    auto validStop = [&] { return ValidateGmlHelperStop(*stop, 123, owner(), location().archiveHash).valid; };
    CHECK(validStop());
    stop->version++; CHECK(!validStop()); stop->version--;
    stop->byteSize--; CHECK(!validStop()); stop->byteSize++;
    stop->nonce++; CHECK(!validStop()); stop->nonce--;
    stop->identity.stopSequence++; CHECK(!validStop()); stop->identity.stopSequence--;
    stop->identity.tid++; CHECK(!validStop()); stop->identity.tid--;
    stop->identity.helperGeneration++; CHECK(!validStop()); stop->identity.helperGeneration--;
    stop->identity.sessionGeneration++; CHECK(!validStop()); stop->identity.sessionGeneration--;
    stop->frameCount = kGmlMaxFrames + 1; CHECK(!validStop()); stop->frameCount = 2;
    stop->numericSlotCount = kGmlMaxNumericSlots + 1; CHECK(!validStop()); stop->numericSlotCount = 1;
    stop->frames[0].parentFrameId = 333; CHECK(!validStop()); stop->frames[0].parentFrameId = 100;
    stop->frames[1].frameId = 200; CHECK(!validStop()); stop->frames[1].frameId = 100;
    stop->frames[1].parentFrameId = 333; CHECK(!validStop()); stop->frames[1].parentFrameId = 0;
    stop->numericSlots[0].storage = GmlSlotStorage::Copied; CHECK(!validStop());
    stop->numericSlots[0].writable = 0; CHECK(validStop());
    stop->numericSlots[0].storage = GmlSlotStorage::Canonical;
    stop->numericSlots[0].writable = 1;
    stop->numericSlots[0].frameId = 333; CHECK(!validStop()); stop->numericSlots[0].frameId = 200;
    stop->numericSlots[0].ownerObject = 0; CHECK(!validStop()); stop->numericSlots[0].ownerObject = 0x56789000;
    stop->numericSlots[0].ownerReserved = 1; CHECK(!validStop()); stop->numericSlots[0].ownerReserved = 0;
    stop->globalsComplete = 2; CHECK(!validStop()); stop->globalsComplete = 1;
    stop->scopeReserved = 1; CHECK(!validStop()); stop->scopeReserved = 0;
    stop->frames[0].localsAvailability = GmlValueAvailability::Available; CHECK(!validStop());
    stop->frames[0].localObject = 0x56789000; CHECK(validStop());
    stop->frames[0].selfAvailability = GmlValueAvailability::Available; CHECK(!validStop());
    stop->frames[0].selfObject = 0x56789000; CHECK(validStop());
    stop->frames[0].argumentCount = 1; CHECK(!validStop());
    stop->frames[0].arguments = 0x12345000; CHECK(validStop());

    auto control = std::make_unique<GmlHelperControl>();
    control->nonce = 123;
    control->expectedStop = owner();
    control->command = GmlControlCommand::StepOver;
    control->commandSequence = 2;
    control->anchorFrameId = 200;
    control->anchorParentFrameId = 100;
    control->anchorDepth = 1;
    control->anchorLocation = location();
    control->breakpointCount = 1;
    control->breakpoints[0] = location();
    auto validControl = [&] { return ValidateGmlHelperControl(*control, 123, owner(), location().archiveHash, 1).valid; };
    CHECK(validControl());
    control->commandSequence = 1; CHECK(!validControl()); control->commandSequence = 2;
    control->anchorParentFrameId = 0; CHECK(!validControl()); control->anchorParentFrameId = 100;
    control->breakpointCount = 2; control->breakpoints[1] = location(); CHECK(!validControl());
    control->breakpoints[1] = location(4); CHECK(validControl());
    control->breakpointCount = kGmlMaxBreakpoints + 1; CHECK(!validControl());

    // Same offset after actual execution is a step; recursion is identified by
    // frame incarnation. Complete ancestry proves a top-level frame has left
    // the active chain without labelling a subsequent event as its caller.
    const std::array<uint64_t, 1> parents{100};
    const std::array<uint64_t, 2> nestedParents{200, 100};
    GmlExecutionPoint point{ owner(), location(), 200, 100, 50, 1, true, parents };
    GmlStepPlan plan;
    CHECK(MakeGmlStepPlan(GmlControlCommand::StepInto, point, plan));
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Continue);
    point.progressSequence++;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Stop);
    CHECK(MakeGmlStepPlan(GmlControlCommand::StepOver, point, plan));
    point.progressSequence++;
    point.frameId = 300; point.parentFrameId = 200; point.depth = 2; point.ancestorFrameIds = nestedParents;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Continue);
    point.frameId = 200; point.parentFrameId = 100; point.depth = 1; point.ancestorFrameIds = parents;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Stop);
    CHECK(MakeGmlStepPlan(GmlControlCommand::StepOut, point, plan));
    point.progressSequence++;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Continue);
    point.frameId = 100; point.parentFrameId = 0; point.depth = 0; point.ancestorFrameIds = {};
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Stop);
    point.frameId = 400;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Stop);
    CHECK(MakeGmlStepPlan(GmlControlCommand::StepOut, point, plan));
    point.progressSequence++;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Continue);
    point.frameId = 500;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Stop);
    point.ancestryComplete = false;
    CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Invalid);
    point.ancestryComplete = true;
    CHECK(MakeGmlStepPlan(GmlControlCommand::StepInto, point, plan));
    point.identity.tid++; CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Stale); point.identity.tid--;
    point.identity.stopSequence++; CHECK(EvaluateGmlStep(plan, point) == GmlStepDecision::Stale); point.identity.stopSequence--;
    point.ancestryComplete = false; CHECK(!MakeGmlStepPlan(GmlControlCommand::StepOver, point, plan));

    GmlNumericLayout layout; layout.validated = true;
    GmlNumericEditPlan edit;
    std::string error;
    auto slot = numericSlot(GmlNumericKind::Int32, 7, 0xDEADBEEF0000000Aull);
    auto editTo = [&](std::string_view text) {
        return PlanGmlNumericEdit(owner(), owner(), slot, slot.value, layout, text, edit, &error);
    };
    CHECK(editTo("-2147483648"));
    CHECK(edit.byteCount == 4 && editedPayload(edit) == 0x80000000ull);
    CHECK(edit.expectedValue.payload == 0xDEADBEEF0000000Aull && edit.expectedValue.flags == slot.value.flags);
    CHECK(!editTo("2147483648") && edit.byteCount == 0);
    CHECK(!editTo("1x") && !editTo("1.0") && !editTo(" 1"));
    auto stale = owner(); stale.stopSequence++;
    CHECK(!PlanGmlNumericEdit(owner(), stale, slot, slot.value, layout, "2", edit));
    auto fresh = slot.value; fresh.typeTag = 10;
    CHECK(!PlanGmlNumericEdit(owner(), owner(), slot, fresh, layout, "2", edit));
    fresh = slot.value; fresh.payload++;
    CHECK(!PlanGmlNumericEdit(owner(), owner(), slot, fresh, layout, "2", edit));
    slot.storage = GmlSlotStorage::Copied; CHECK(!editTo("2")); slot.storage = GmlSlotStorage::Canonical;
    slot.address = 0x00007FFFFFFFFFFF; CHECK(!editTo("2")); slot.address = 0x12345000;
    layout.validated = false; CHECK(!editTo("2")); layout.validated = true;
    layout.int64Tag = 7; CHECK(!editTo("2")); layout.int64Tag = 10;
    slot = numericSlot(GmlNumericKind::Int64, 10);
    CHECK(editTo("9223372036854775807") && editedPayload(edit) == uint64_t(INT64_MAX));
    CHECK(editTo("-9223372036854775808") && editedPayload(edit) == (uint64_t(1) << 63));
    CHECK(!editTo("9223372036854775808"));
    slot = numericSlot(GmlNumericKind::Real, 0);
    CHECK(editTo("1.25") && editedPayload(edit) == std::bit_cast<uint64_t>(1.25));
    CHECK(editTo("-0") && editedPayload(edit) == (uint64_t(1) << 63));
    CHECK(!editTo("nan") && !editTo("inf") && !editTo("1e9999"));
    slot = numericSlot(GmlNumericKind::Boolean, 13);
    CHECK(!editTo("true")); // first runner has not yet proved Boolean representation
    layout.booleanEncoding = GmlBooleanEncoding::Float64;
    CHECK(editTo("true") && editedPayload(edit) == std::bit_cast<uint64_t>(1.0));
    CHECK(editTo("false") && editedPayload(edit) == 0);
    CHECK(!editTo("2"));
    layout.booleanEncoding = GmlBooleanEncoding::Int32;
    CHECK(editTo("true") && edit.byteCount == 4 && editedPayload(edit) == 1);

    GmlVariableTarget target;
    target.archiveHash = location().archiveHash;
    target.variableName = "score";
    CHECK(GmlVariableTargetPersistent(target));
    std::vector<GmlVariableCandidate> candidates{
        { GmlVariableScope::Global, kGmlNoCodeIndex, "score", 0, 0, 3 },
        { GmlVariableScope::SessionInstance, 7, "score", 99, 0, 4 }
    };
    auto resolve = [&] { return ResolveGmlVariableTarget(target, target.archiveHash, owner(), candidates, true); };
    CHECK(resolve().resolved() && resolve().slotIndex == 3);
    target.scope = GmlVariableScope::UniqueObject; target.objectIndex = 7;
    CHECK(GmlVariableTargetPersistent(target));
    CHECK(resolve().resolved() && resolve().slotIndex == 4);
    candidates.push_back({ GmlVariableScope::SessionInstance, 7, "score", 100, 0, 5 });
    CHECK(resolve().status == GmlVariableResolveStatus::Ambiguous);
    target.scope = GmlVariableScope::SessionInstance; target.instanceId = 99; target.owner = owner();
    CHECK(!GmlVariableTargetPersistent(target));
    CHECK(resolve().resolved() && resolve().slotIndex == 4);
    target.owner.helperGeneration++; CHECK(resolve().status == GmlVariableResolveStatus::StaleOwner);
    target.owner = owner(); target.owner.stopSequence--; // same instance survives another stop
    CHECK(resolve().resolved());
    CHECK(ResolveGmlVariableTarget(target, target.archiveHash, owner(), candidates, false).status == GmlVariableResolveStatus::Incomplete);
    target.scope = GmlVariableScope::FrameLocal; target.objectIndex = kGmlNoCodeIndex; target.instanceId = 0; target.frameId = 200;
    CHECK(resolve().status == GmlVariableResolveStatus::Missing);
    candidates.push_back({ GmlVariableScope::FrameLocal, kGmlNoCodeIndex, "score", 0, 200, 6 });
    CHECK(resolve().resolved() && resolve().slotIndex == 6);
    target.owner.tid++; CHECK(resolve().status == GmlVariableResolveStatus::StaleOwner);
    target.owner = owner();target.owner.helperGeneration++;CHECK(resolve().status == GmlVariableResolveStatus::StaleOwner);
    target.owner = owner();candidates.back().frameId=201;CHECK(resolve().status == GmlVariableResolveStatus::Missing);

    std::printf("gamemaker_debug_test: %s\n", failures ? "FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
