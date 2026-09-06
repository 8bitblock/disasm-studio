#include "Core/AuthorizationFieldAlias.h"

#include <algorithm>
#include <cstdio>
#include <string>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static AuthorizationFieldRoot root(uint64_t functionVA, uint32_t parameter) {
    AuthorizationFieldRoot result;
    result.functionVA = functionVA;
    result.functionVAValid = true;
    result.formalParameterIndex = parameter;
    result.formalParameterIndexValid = true;
    return result;
}

static ObjectFieldAccessObservation access(
    uint64_t functionVA, uint32_t parameter, uint64_t instructionVA,
    int64_t displacement, uint16_t width, ObjectFieldAccessKind kind) {
    ObjectFieldAccessObservation result;
    result.functionVA = functionVA;
    result.functionVAValid = true;
    result.instructionVA = instructionVA;
    result.instructionVAValid = true;
    result.operandIndex = 1;
    result.operandIndexValid = true;
    result.rootParameterIndex = parameter;
    result.rootParameterIndexValid = true;
    result.rootAbiLocation = parameter == 0 ? "rcx" : "rdx";
    result.displacement = displacement;
    result.displacementValid = true;
    result.widthBits = width;
    result.widthKnown = true;
    result.access = kind;
    result.exact = true;
    result.confidence = 0.95f;
    result.evidence = "exact decoded memory operand";
    return result;
}

static AuthorizationFieldRootBindingInput binding(
    AuthorizationFieldRoot source, AuthorizationFieldRoot target,
    uint64_t callVA) {
    AuthorizationFieldRootBindingInput result;
    result.callerRoot = source;
    result.calleeFormal = target;
    result.callVA = callVA;
    result.callVAValid = true;
    result.directTargetVA = target.functionVA;
    result.directTargetVAValid = true;
    result.argumentIndex = target.formalParameterIndex;
    result.argumentIndexValid = true;
    result.callerRootBias = 0;
    result.callerRootBiasValid = true;
    result.directCallExact = true;
    result.argumentSourceExact = true;
    result.complete = true;
    result.confidence = 1.0f;
    result.evidence = "direct call with unchanged formal-root argument";
    return result;
}

static bool rejectedFor(const AuthorizationFieldAliasReport& report,
                        size_t inputIndex,
                        AuthorizationFieldBindingRejectReason reason) {
    return std::any_of(report.rejectedBindings.begin(),
                       report.rejectedBindings.end(),
        [&](const AuthorizationRejectedFieldBinding& row) {
            return row.inputIndex == inputIndex && row.reason == reason;
        });
}

static const AuthorizationStableFieldIdentity* fieldAt(
    const AuthorizationFieldAliasReport& report, int64_t displacement,
    uint16_t width) {
    for (const auto& field : report.fields) {
        if (field.displacement == displacement && field.widthBits == width)
            return &field;
    }
    return nullptr;
}

static void transitiveCorrelationPreservesZeroVA() {
    AuthorizationFieldAliasInput input;
    // Function and callsite VA zero are both valid coordinates.
    input.accesses.push_back(access(0, 0, 0, 0x138, 8,
                                    ObjectFieldAccessKind::Write));
    input.accesses.push_back(access(0x200, 0, 0x210, 0x138, 8,
                                    ObjectFieldAccessKind::Read));
    input.bindings.push_back(binding(root(0, 0), root(0x100, 1), 0));
    input.bindings.push_back(binding(root(0x100, 1), root(0x200, 0),
                                     0x110));

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(report.completeness.complete);
    CHECK(report.completeness.allBindingsResolved);
    CHECK(report.completeness.acceptedBindingCount == 2);
    CHECK(report.objects.size() == 1);
    CHECK(report.objects[0].aliases.size() == 3);
    CHECK(report.objects[0].canonicalRoot.functionVAValid);
    CHECK(report.objects[0].canonicalRoot.functionVA == 0);
    CHECK(report.objects[0].stableId.find("0000000000000000") !=
          std::string::npos);
    CHECK(report.fields.size() == 1);
    CHECK(report.fields[0].writes.size() == 1);
    CHECK(report.fields[0].reads.size() == 1);
    CHECK(report.fields[0].writes[0].instructionVAValid);
    CHECK(report.fields[0].writes[0].instructionVA == 0);
}

static void displacementAndWidthAloneNeverMerge() {
    AuthorizationFieldAliasInput input;
    input.accesses.push_back(access(0x1000, 0, 0x1010, 0x20, 8,
                                    ObjectFieldAccessKind::Read));
    input.accesses.push_back(access(0x2000, 0, 0x2010, 0x20, 8,
                                    ObjectFieldAccessKind::Write));
    input.accesses.push_back(access(0x1000, 0, 0x1014, 0x20, 32,
                                    ObjectFieldAccessKind::Read));
    ObjectFieldAccessObservation widthless =
        access(0x1000, 0, 0x1018, 0x20, 8, ObjectFieldAccessKind::Read);
    widthless.widthKnown = false;
    input.accesses.push_back(widthless);

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(report.objects.size() == 2);
    CHECK(report.fields.size() == 3);
    CHECK(report.completeness.acceptedAccessCount == 3);
    CHECK(report.completeness.rejectedAccessCount == 1);
    CHECK(report.rejectedAccesses.size() == 1);
    CHECK(report.rejectedAccesses[0].reason ==
          AuthorizationFieldAccessRejectReason::MissingWidth);

    size_t widthConflicts = 0;
    for (const auto& field : report.fields)
        if (field.objectIndex == 0 && field.displacement == 0x20 &&
            field.overlapsDifferentWidth)
            ++widthConflicts;
    CHECK(widthConflicts == 2);
}

static void unrelatedCallersAreAmbiguous() {
    AuthorizationFieldAliasInput input;
    input.accesses.push_back(access(0x3000, 0, 0x3010, 8, 8,
                                    ObjectFieldAccessKind::Read));
    input.bindings.push_back(binding(root(0x1000, 0), root(0x3000, 0),
                                     0x1010));
    input.bindings.push_back(binding(root(0x2000, 0), root(0x3000, 0),
                                     0x2010));

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(report.completeness.complete); // rejection itself was fully computed
    CHECK(!report.completeness.allBindingsResolved);
    CHECK(report.completeness.acceptedBindingCount == 0);
    CHECK(report.completeness.rejectedBindingCount == 2);
    CHECK(rejectedFor(report, 0,
                      AuthorizationFieldBindingRejectReason::AmbiguousCalleeFormal));
    CHECK(rejectedFor(report, 1,
                      AuthorizationFieldBindingRejectReason::AmbiguousCalleeFormal));
    CHECK(report.objects.size() == 3);
}

static void sameCallConflictsAreDistinguished() {
    AuthorizationFieldAliasInput input;
    input.bindings.push_back(binding(root(0x1000, 0), root(0x3000, 0),
                                     0x1500));
    input.bindings.push_back(binding(root(0x1000, 1), root(0x3000, 0),
                                     0x1500));

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(report.completeness.acceptedBindingCount == 0);
    CHECK(rejectedFor(report, 0,
                      AuthorizationFieldBindingRejectReason::ConflictingBinding));
    CHECK(rejectedFor(report, 1,
                      AuthorizationFieldBindingRejectReason::ConflictingBinding));
}

static void cyclesAreNeverUnioned() {
    AuthorizationFieldAliasInput input;
    input.bindings.push_back(binding(root(0x1000, 0), root(0x2000, 0),
                                     0x1010));
    input.bindings.push_back(binding(root(0x2000, 0), root(0x1000, 0),
                                     0x2010));
    input.bindings.push_back(binding(root(0x3000, 0), root(0x3000, 0),
                                     0x3010));
    input.bindings.push_back(binding(root(0x4000, 0), root(0x4000, 1),
                                     0x4010));

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(report.completeness.acceptedBindingCount == 0);
    CHECK(report.completeness.rejectedBindingCount == 4);
    CHECK(rejectedFor(report, 0,
                      AuthorizationFieldBindingRejectReason::CyclicBinding));
    CHECK(rejectedFor(report, 1,
                      AuthorizationFieldBindingRejectReason::CyclicBinding));
    CHECK(rejectedFor(report, 2,
                      AuthorizationFieldBindingRejectReason::CyclicBinding));
    CHECK(rejectedFor(report, 3,
                      AuthorizationFieldBindingRejectReason::CyclicBinding));
    CHECK(report.objects.size() == 2);
}

static void provedDiamondIsTransitivelyUnioned() {
    AuthorizationFieldAliasInput input;
    const auto a = root(0x1000, 0);
    const auto b = root(0x2000, 0);
    const auto c = root(0x3000, 0);
    const auto d = root(0x4000, 0);
    input.bindings.push_back(binding(a, b, 0x1010));
    input.bindings.push_back(binding(a, c, 0x1020));
    input.bindings.push_back(binding(b, d, 0x2010));
    input.bindings.push_back(binding(c, d, 0x3010));
    input.accesses.push_back(access(0x4000, 0, 0x4010, 4, 8,
                                    ObjectFieldAccessKind::ReadWrite));

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(report.completeness.allBindingsResolved);
    CHECK(report.completeness.acceptedBindingCount == 4);
    CHECK(report.objects.size() == 1);
    CHECK(report.objects[0].aliases.size() == 4);
    CHECK(report.fields.size() == 1);
    CHECK(report.fields[0].reads.size() == 1);
    CHECK(report.fields[0].writes.size() == 1);
    CHECK(report.fields[0].reads[0].inputIndex ==
          report.fields[0].writes[0].inputIndex);
}

static void staleAdapterMetadataIsRejected() {
    AuthorizationFieldAliasInput input;
    auto wrongTarget = binding(root(0x1000, 0), root(0x2000, 1), 0x1010);
    wrongTarget.directTargetVA = 0x2100;
    input.bindings.push_back(wrongTarget);
    auto wrongArgument = binding(root(0x1000, 0), root(0x2000, 1), 0x1020);
    wrongArgument.argumentIndex = 0;
    input.bindings.push_back(wrongArgument);
    auto guessedSource = binding(root(0x1000, 0), root(0x2000, 1), 0x1030);
    guessedSource.argumentSourceExact = false;
    input.bindings.push_back(guessedSource);
    auto adjustedRoot = binding(root(0x1000, 0), root(0x2000, 1), 0x1040);
    adjustedRoot.callerRootBias = 0x20;
    input.bindings.push_back(adjustedRoot);

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(rejectedFor(report, 0,
                      AuthorizationFieldBindingRejectReason::CalleeTargetMismatch));
    CHECK(rejectedFor(report, 1,
                      AuthorizationFieldBindingRejectReason::FormalArgumentMismatch));
    CHECK(rejectedFor(report, 2,
                      AuthorizationFieldBindingRejectReason::InexactArgumentSource));
    CHECK(rejectedFor(report, 3,
                      AuthorizationFieldBindingRejectReason::AdjustedRoot));
}

static void capsAndScopeRemainHonest() {
    AuthorizationFieldAliasInput input;
    input.accessesComplete = false;
    input.accessesIncompleteReason = "candidate function cap reached";
    input.bindingsComplete = false;
    input.bindingsIncompleteReason = "call-root extraction incomplete";
    input.accesses.push_back(access(0x1000, 0, 0x1010, 1, 8,
                                    ObjectFieldAccessKind::Read));
    input.accesses.push_back(access(0x2000, 0, 0x2010, 1, 8,
                                    ObjectFieldAccessKind::Read));
    input.accesses.push_back(access(0x3000, 0, 0x3010, 1, 8,
                                    ObjectFieldAccessKind::Read));
    input.limits.maxRoots = 2;

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(!report.completeness.complete);
    CHECK(!report.completeness.accessesScopeComplete);
    CHECK(!report.completeness.bindingsScopeComplete);
    CHECK(report.completeness.rootsTruncated);
    CHECK(report.completeness.acceptedAccessCount == 2);
    CHECK(report.completeness.rejectedAccessCount == 1);
    CHECK(report.objects.size() == 2);
    CHECK(!report.objects[0].complete);
    const auto* field = fieldAt(report, 1, 8);
    CHECK(field != nullptr);
    CHECK(field && !field->complete);
}

static void outputCapsStayBounded() {
    AuthorizationFieldAliasInput input;
    input.accesses.push_back(access(0x1000, 0, 0x1010, 4, 8,
                                    ObjectFieldAccessKind::Read));
    input.accesses.push_back(access(0x1000, 0, 0x1011, 4, 8,
                                    ObjectFieldAccessKind::Read));
    input.bindings.push_back(binding(root(0x1000, 0), root(0x2000, 0),
                                     0x1020));
    input.bindings.push_back(binding(root(0x2000, 0), root(0x3000, 0),
                                     0x2020));
    input.limits.maxBindingInputs = 1;
    input.limits.maxAliasesPerObject = 1;
    input.limits.maxAccessesPerField = 1;

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(!report.completeness.complete);
    CHECK(report.completeness.bindingInputsTruncated);
    CHECK(report.completeness.aliasesTruncated);
    CHECK(report.completeness.fieldAccessesTruncated);
    CHECK(report.completeness.processedBindingCount == 1);
    CHECK(report.completeness.acceptedBindingCount == 1);
    CHECK(report.objects.size() == 1);
    CHECK(report.objects[0].aliases.size() == 1);
    CHECK(report.fields.size() == 1);
    CHECK(report.fields[0].reads.size() == 1);
    CHECK(!report.fields[0].complete);
}

static void cancellationPublishesNoPartialIdentity() {
    AuthorizationFieldAliasInput input;
    input.accesses.push_back(access(0, 0, 0, 0, 8,
                                    ObjectFieldAccessKind::Read));
    input.cancelled = [] { return true; };

    const auto report = CorrelateAuthorizationFieldAliases(input);
    CHECK(report.completeness.cancelled);
    CHECK(!report.completeness.complete);
    CHECK(report.objects.empty());
    CHECK(report.fields.empty());
    CHECK(report.acceptedBindings.empty());
}

static void funcAnnotateFactsAdaptLosslessly() {
    FuncAnnotations annotations;
    annotations.fieldAccessAnalysisAttempted = true;
    annotations.fieldAccessesComplete = true;
    annotations.directCallFormalBindingAnalysisAttempted = true;
    annotations.directCallFormalBindingsComplete = true;
    annotations.fieldAccesses.push_back(access(
        0, 2, 0, 0x18, 8, ObjectFieldAccessKind::Read));

    DirectCallFormalBindingObservation observation;
    observation.callerFunctionVA = 0;
    observation.callerFunctionVAValid = true;
    observation.callerRootParameterIndex = 2;
    observation.callerRootParameterIndexValid = true;
    observation.callerRootAbiLocation = "r8";
    observation.callerRootBias = 0;
    observation.callerRootBiasValid = true;
    observation.callVA = 0;
    observation.callVAValid = true;
    observation.calleeFunctionVA = 0x5000;
    observation.calleeFunctionVAValid = true;
    observation.calleeFormalParameterIndex = 1;
    observation.calleeFormalParameterIndexValid = true;
    observation.calleeAbiLocation = "rdx";
    observation.directCallTargetExact = true;
    observation.argumentRootExact = true;
    observation.confidence = 0.99f;
    observation.evidence = "must-dataflow proof";
    annotations.directCallFormalBindings.push_back(observation);

    AuthorizationFieldAliasInput input;
    AppendAuthorizationFieldAliasFacts(input, annotations);
    CHECK(input.accessesComplete);
    CHECK(input.bindingsComplete);
    CHECK(input.accesses.size() == 1);
    CHECK(input.bindings.size() == 1);
    CHECK(input.bindings[0].callerRoot.functionVAValid);
    CHECK(input.bindings[0].callerRoot.functionVA == 0);
    CHECK(input.bindings[0].callVAValid && input.bindings[0].callVA == 0);
    CHECK(input.bindings[0].calleeFormal.functionVA == 0x5000);
    CHECK(input.bindings[0].argumentIndex == 1);
    CHECK(input.bindings[0].callerRootBiasValid &&
          input.bindings[0].callerRootBias == 0);

    annotations.directCallFormalBindingsComplete = false;
    annotations.directCallFormalBindingIncompleteReason =
        "candidate function cap reached";
    AuthorizationFieldAliasInput incomplete;
    AppendAuthorizationFieldAliasFacts(incomplete, annotations);
    CHECK(!incomplete.bindingsComplete);
    CHECK(incomplete.bindingsIncompleteReason.find("candidate function cap") !=
          std::string::npos);
}

int main() {
    transitiveCorrelationPreservesZeroVA();
    displacementAndWidthAloneNeverMerge();
    unrelatedCallersAreAmbiguous();
    sameCallConflictsAreDistinguished();
    cyclesAreNeverUnioned();
    provedDiamondIsTransitivelyUnioned();
    staleAdapterMetadataIsRejected();
    capsAndScopeRemainHonest();
    outputCapsStayBounded();
    cancellationPublishesNoPartialIdentity();
    funcAnnotateFactsAdaptLosslessly();

    if (failures) return 1;
    std::puts("authorization field-alias tests passed");
    return 0;
}
