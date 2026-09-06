#include "Core/AuthorizationTrail.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

namespace {

int failures = 0;
#define CHECK(c, m) do { if (!(c)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, m); ++failures; \
} } while (0)

AuthorizationLocation loc(uint64_t address, uint64_t function,
                          const char* name = {}) {
    AuthorizationLocation result;
    result.address = address;
    result.addressValid = true;
    result.fileOffset = address;
    result.fileOffsetValid = true;
    result.functionAddress = function;
    result.functionAddressValid = true;
    if (name) result.functionName = name;
    return result;
}

AuthorizationTrailPredicateCandidateInput predicate(
    uint64_t address, const char* name, bool sourceLinked) {
    AuthorizationTrailPredicateCandidateInput result;
    result.function = loc(address, address, name);
    result.returnContract =
        AuthorizationTrailBooleanContract::CanonicalZeroOrOne;
    result.returnAnalysisComplete = true;
    result.sideEffectLight = true;
    result.authorizationSourceLinked = sourceLinked;
    result.confidence = 0.95f;
    result.evidence = std::string(name) + " returns a canonical boolean";
    return result;
}

AuthorizationTrailPredicateUseInput branchUse(
    size_t predicateIndex, uint64_t caller, uint64_t callsite) {
    AuthorizationTrailPredicateUseInput result;
    result.predicateIndex = predicateIndex;
    result.predicateIndexValid = true;
    result.callsite = loc(callsite, caller);
    result.caller = loc(caller, caller);
    result.comparison = loc(callsite + 5, caller);
    result.branch = loc(callsite + 7, caller);
    result.trueDestination = loc(callsite + 0x10, caller);
    result.falseDestination = loc(callsite + 9, caller);
    result.useKind = AuthorizationTrailUseKind::Branched;
    result.resultWidthBits = 8;
    result.flagsPreserved = true;
    result.branchUseProven = true;
    result.confidence = 0.95f;
    result.evidence =
        "call; test al, al; conditional branch on the boolean result";
    return result;
}

const AuthorizationTrailPredicate* predicateAt(
    const AuthorizationTrailReport& report, uint64_t address) {
    for (const auto& item : report.predicates)
        if (item.function.addressValid && item.function.address == address)
            return &item;
    return nullptr;
}

const AuthorizationTrailConclusion* conclusion(
    const AuthorizationTrailReport& report,
    AuthorizationTrailConclusionKind kind) {
    for (const auto& item : report.conclusions)
        if (item.kind == kind) return &item;
    return nullptr;
}

bool avoidsRuntimeSuccessClaim(const std::string& text) {
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char value) {
                       return static_cast<char>(std::tolower(value));
                   });
    static constexpr const char* overstated[] = {
        "runtime success",
        "runtime accepted",
        "runtime verified",
        "runtime authorization succeeded",
        "entitlement was accepted",
        "machine binding succeeded"
    };
    for (const char* phrase : overstated)
        if (lower.find(phrase) != std::string::npos) return false;
    return true;
}

AuthorizationTrailFieldIdentity activeField(uint16_t widthBits = 8) {
    AuthorizationTrailFieldIdentity field;
    field.base = AuthorizationTrailFieldBaseKind::RootParameter;
    field.rootAddress = 0; // Valid VA zero is a real root function.
    field.rootAddressValid = true;
    field.rootOrdinal = 0;
    field.rootOrdinalValid = true;
    field.displacement = 0x138;
    field.widthBits = widthBits;
    field.exact = true;
    field.display = "[object+0x138]";
    return field;
}

AuthorizationTrailConclusionEvidenceInput conclusionEvidence(
    AuthorizationTrailConclusionKind claim,
    AuthorizationTrailEvidenceKind evidence,
    uint64_t address) {
    AuthorizationTrailConclusionEvidenceInput result;
    result.conclusion = claim;
    result.kind = evidence;
    result.location = loc(address, address);
    result.evidence = "typed conclusion evidence";
    result.confidence = 0.9f;
    return result;
}

AuthorizationTrailInput representativeInput() {
    AuthorizationTrailInput input;
    // The global source link is established by the ordered field proof below,
    // not asserted independently by the candidate adapter.
    input.predicateCandidates.push_back(predicate(0, "IsPro", false));
    input.predicateCandidates.push_back(
        predicate(0x2000, "IsFeatureLicensed", false));

    // Global predicate: 19 distinct branch-consuming callers, including valid
    // caller VA zero. Secondary predicate: 18 distinct callers plus duplicate
    // spam. Raw callsites and unique caller fan-out stay independent.
    for (size_t i = 0; i < 19; ++i) {
        const uint64_t caller = static_cast<uint64_t>(i) * 0x100;
        input.predicateUses.push_back(
            branchUse(0, caller, 0x10000 + i * 0x10));
    }
    for (size_t i = 0; i < 18; ++i) {
        const uint64_t caller = 0x3000 + static_cast<uint64_t>(i) * 0x100;
        input.predicateUses.push_back(
            branchUse(1, caller, 0x20000 + i * 0x10));
    }
    input.predicateUses.push_back(input.predicateUses[19]); // exact duplicate
    input.predicateUses.push_back(
        branchUse(1, 0x3000, 0x22000)); // same caller, distinct callsite
    input.predicateUses.push_back(
        branchUse(1, 0x3000, 0x22010)); // same caller, distinct callsite

    AuthorizationTrailFieldAccessInput write;
    write.field = activeField();
    write.access = AuthorizationTrailFieldAccessKind::Write;
    write.location = loc(0x5000, 0x5000);
    write.authorizationDerived = true;
    // The read below is input #1. A source edge must name both that exact
    // access and its exact predicate; field equality alone is insufficient.
    write.reachedReadAccessInputIndex = 1;
    write.reachedReadAccessInputIndexValid = true;
    write.reachedPredicateInputIndex = 0;
    write.reachedPredicateInputIndexValid = true;
    write.evidence = "signature result writes object.active";
    input.fieldAccesses.push_back(write);

    AuthorizationTrailFieldAccessInput read;
    read.field = activeField();
    read.access = AuthorizationTrailFieldAccessKind::Read;
    read.location = loc(1, 0, "IsPro");
    read.predicateIndex = 0;
    read.predicateIndexValid = true;
    read.contributesToPredicateReturn = true;
    read.evidence = "IsPro reads object.active";
    input.fieldAccesses.push_back(read);

    // Same display string is not identity. Different owner, width, non-exact
    // root, and a zero-width slice must not join the exact lineage above.
    AuthorizationTrailFieldAccessInput otherOwner = read;
    otherOwner.field.rootAddress = 0x9999;
    otherOwner.location = loc(0x9000, 0x9000);
    input.fieldAccesses.push_back(otherOwner);
    AuthorizationTrailFieldAccessInput otherWidth = read;
    otherWidth.field = activeField(32);
    otherWidth.location = loc(0x9001, 0x9000);
    input.fieldAccesses.push_back(otherWidth);
    AuthorizationTrailFieldAccessInput inexact = read;
    inexact.field.exact = false;
    inexact.location = loc(0x9002, 0x9000);
    input.fieldAccesses.push_back(inexact);
    AuthorizationTrailFieldAccessInput zeroWidth = read;
    zeroWidth.field.widthBits = 0;
    zeroWidth.location = loc(0x9003, 0x9000);
    input.fieldAccesses.push_back(zeroWidth);

    AuthorizationTrailFeatureOperationInput branding;
    branding.location = loc(0x7000, 0x7000);
    branding.kind = AuthorizationTrailOperationKind::BrandingOrCosmetic;
    branding.feature = "Task Manager TMOG PRO branding";
    branding.evidence = "window-title literal";
    branding.confidence = 0.9f;
    input.operations.push_back(branding);

    AuthorizationTrailFeatureOperationInput protectedAction;
    protectedAction.location = loc(0x8000, 0x8000);
    protectedAction.kind = AuthorizationTrailOperationKind::ProtectedOperation;
    protectedAction.feature = "protected export operation";
    protectedAction.evidence = "branch-exclusive action call";
    protectedAction.confidence = 0.9f;
    input.operations.push_back(protectedAction);

    AuthorizationTrailOperationGuardInput globalBranding;
    globalBranding.predicateIndex = 0;
    globalBranding.predicateIndexValid = true;
    globalBranding.operationIndex = 0;
    globalBranding.operationIndexValid = true;
    globalBranding.location = loc(0x7010, 0x7000);
    globalBranding.branchExclusive = true;
    globalBranding.permitsOperation = true;
    input.operationGuards.push_back(globalBranding);

    AuthorizationTrailOperationGuardInput secondaryAction = globalBranding;
    secondaryAction.predicateIndex = 1;
    secondaryAction.operationIndex = 1;
    secondaryAction.location = loc(0x8010, 0x8000);
    input.operationGuards.push_back(secondaryAction);
    input.operationGuards.push_back(secondaryAction); // duplicate guard

    AuthorizationTrailPredicateRelationInput relation;
    relation.upstreamPredicateIndex = 0;
    relation.upstreamPredicateIndexValid = true;
    relation.downstreamPredicateIndex = 1;
    relation.downstreamPredicateIndexValid = true;
    relation.location = loc(0x6000, 0x6000);
    relation.branchExclusive = true;
    relation.onPermittedPath = true;
    relation.downstreamResultRequired = true;
    relation.evidence = "global allow path reaches required feature predicate";
    input.predicateRelations.push_back(relation);
    input.predicateRelations.push_back(relation); // duplicate relation

    auto addStage = [&](AuthorizationTrailStageKind stage,
                        AuthorizationTrailEvidenceKind kind,
                        uint64_t address, const char* label) {
        AuthorizationTrailStageEvidenceInput item;
        item.stage = stage;
        item.kind = kind;
        item.location = loc(address, address);
        item.label = label;
        item.evidence = label;
        item.confidence = 0.9f;
        input.stageEvidence.push_back(std::move(item));
    };
    addStage(AuthorizationTrailStageKind::Input,
             AuthorizationTrailEvidenceKind::InputRead,
             0xA000, "key input");
    addStage(AuthorizationTrailStageKind::FormatValidation,
             AuthorizationTrailEvidenceKind::FormatConstraint,
             0xA100, "32 hexadecimal digits");
    addStage(AuthorizationTrailStageKind::RemoteRequest,
             AuthorizationTrailEvidenceKind::TransportSuccess,
             0xA200, "POST /activate");
    addStage(AuthorizationTrailStageKind::EntitlementParsing,
             AuthorizationTrailEvidenceKind::EntitlementParse,
             0xA300, "entitlement parser");
    addStage(AuthorizationTrailStageKind::CryptoVerification,
             AuthorizationTrailEvidenceKind::CryptoPrimitivePresence,
             0xA400, "RSA constants/import present");
    addStage(AuthorizationTrailStageKind::StatePersistence,
             AuthorizationTrailEvidenceKind::PersistentState,
             0xA500, "stored license state");

    input.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::LocalFormatValid,
        AuthorizationTrailEvidenceKind::FormatConstraint, 0xA100));
    input.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::ServerAccepted,
        AuthorizationTrailEvidenceKind::TransportSuccess, 0xA200));
    input.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::SignatureVerified,
        AuthorizationTrailEvidenceKind::CryptoPrimitivePresence, 0xA400));
    input.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::FeaturePermitted,
        AuthorizationTrailEvidenceKind::FeatureControl, 0x8000));
    input.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::EmbeddedExpectedKey,
        AuthorizationTrailEvidenceKind::ExpectedKeySearchNegative, 0xB000));
    input.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::PrivateSigningMaterial,
        AuthorizationTrailEvidenceKind::PrivateMaterialSearchNegative, 0xB100));
    input.completeness.expectedKeySearchComplete = true;
    input.completeness.privateMaterialSearchComplete = true;
    return input;
}

void rankedFanoutSecondaryAndFields() {
    const AuthorizationTrailInput input = representativeInput();
    const AuthorizationTrailReport report = RunAuthorizationTrail(input);
    CHECK(report.completeness.complete,
          "representative authorization trail should be complete");
    CHECK(report.predicates.size() == 2,
          "two unique predicate candidates should be retained");

    const AuthorizationTrailPredicate* global = predicateAt(report, 0);
    const AuthorizationTrailPredicate* secondary = predicateAt(report, 0x2000);
    CHECK(global != nullptr && secondary != nullptr,
          "valid predicate VA zero and secondary address must survive");
    if (global && secondary) {
        CHECK(global->role == AuthorizationTrailPredicateRole::Global,
              "19-consumer source-linked predicate should be global");
        CHECK(secondary->role == AuthorizationTrailPredicateRole::Secondary,
              "required downstream feature predicate should be secondary");
        CHECK(global->uniqueCallerCount == 19 &&
              global->uniqueBranchCallerCount == 19,
              "global fanout must count 19 distinct branch callers including VA zero");
        CHECK(secondary->uniqueCallerCount == 18 &&
              secondary->uniqueBranchCallerCount == 18,
              "duplicate secondary callsites must not inflate 18 unique callers");
        CHECK(secondary->callsiteCount == 20 &&
              secondary->branchConsumerCount == 20,
              "two distinct extra callsites remain visible separately from caller fanout");
        CHECK(global->rankScore > secondary->rankScore,
              "global predicate should rank above the secondary predicate");
        CHECK(global->authorizationSourceLinked,
              "exact field lineage should retain authorization source link");
    }
    CHECK(!report.predicates.empty() &&
          report.predicates.front().function.addressValid &&
          report.predicates.front().function.address == 0,
          "ranked predicate order should put the global VA-zero predicate first");

    CHECK(report.fieldLineages.size() == 1,
          "only equal exact owner/offset/width slices should form a lineage");
    if (!report.fieldLineages.empty()) {
        CHECK(report.fieldLineages.front().authorizationSourceLinked,
              "write-to-read field lineage should feed the predicate return");
        CHECK(report.fieldLineages.front().field.rootAddressValid &&
              report.fieldLineages.front().field.rootAddress == 0,
              "field lineage must preserve valid root VA zero");
        CHECK(report.fieldLineages.front().field.widthBits == 8,
              "field lineage width must remain exact");
    }
    CHECK(report.completeness.unlinkedFieldAccessCount >= 4,
          "owner/width/inexact/zero-width field mismatches remain unlinked");
    CHECK(AuthorizationTrailFieldIdentityEquivalentExact(
              activeField(8), activeField(8)),
          "identical exact field slices should compare equal");
    CHECK(!AuthorizationTrailFieldIdentityEquivalentExact(
              activeField(8), activeField(32)),
          "different field widths must not compare equal");
    AuthorizationTrailFieldIdentity invalid = activeField();
    invalid.exact = false;
    CHECK(!AuthorizationTrailFieldIdentityEquivalentExact(activeField(), invalid),
          "non-exact field identity must never correlate");
    AuthorizationTrailFieldIdentity overflowing = activeField();
    overflowing.displacement = (std::numeric_limits<int64_t>::max)();
    CHECK(!AuthorizationTrailFieldIdentityEquivalentExact(
              overflowing, overflowing),
          "field slice whose displacement plus width overflows must be invalid");

    CHECK(report.warnings.size() == 1,
          "one consolidated secondary-gate warning should be produced");
    if (!report.warnings.empty()) {
        CHECK(report.warnings.front().globalPredicateIndexValid,
              "secondary warning should reference the global predicate");
        CHECK(report.warnings.front().secondaryPredicateIndices.size() == 1 &&
              report.warnings.front().operationIndices.size() == 1,
              "duplicate relations/guards must not duplicate warning references");
        CHECK(report.warnings.front().text.find("insufficient") !=
                  std::string::npos,
              "warning should explicitly say the global result is insufficient");
    }

    for (size_t i = 1; i < report.stages.size(); ++i)
        CHECK(static_cast<uint8_t>(report.stages[i - 1].stage) <=
                  static_cast<uint8_t>(report.stages[i].stage),
              "trail stages must remain in semantic order");
    bool globalStage = false, secondaryStage = false, operationStage = false;
    for (const auto& stage : report.stages) {
        globalStage |= stage.stage == AuthorizationTrailStageKind::GlobalPredicate &&
                       stage.location.addressValid && stage.location.address == 0;
        secondaryStage |=
            stage.stage == AuthorizationTrailStageKind::FeaturePredicate &&
            stage.location.addressValid && stage.location.address == 0x2000;
        operationStage |=
            stage.stage == AuthorizationTrailStageKind::ProtectedOperation &&
            stage.location.addressValid && stage.location.address == 0x8000;
    }
    CHECK(globalStage && secondaryStage && operationStage,
          "ranked predicates and protected action should synthesize trail stages");
}

void exactFieldEdgeIdentity() {
    AuthorizationTrailInput twoReaders = representativeInput();
    AuthorizationTrailFieldAccessInput unrelatedReader =
        twoReaders.fieldAccesses[1];
    unrelatedReader.location = loc(0x2010, 0x2000,
                                   "IsFeatureLicensed");
    unrelatedReader.predicateIndex = 1;
    unrelatedReader.evidence =
        "a second predicate reads the same exact object field";
    twoReaders.fieldAccesses.push_back(std::move(unrelatedReader));

    AuthorizationTrailReport report = RunAuthorizationTrail(twoReaders);
    const AuthorizationTrailPredicate* reached = predicateAt(report, 0);
    const AuthorizationTrailPredicate* sameFieldOnly =
        predicateAt(report, 0x2000);
    CHECK(report.completeness.complete && reached && sameFieldOnly,
          "two-reader edge-identity fixture remains complete");
    CHECK(reached && reached->authorizationSourceLinked,
          "the predicate named by the exact store-to-read edge is source-linked");
    CHECK(sameFieldOnly && !sameFieldOnly->authorizationSourceLinked,
          "a second contributing reader of the same field is not source-linked by spatial equality");
    CHECK(report.fieldLineages.size() == 1 &&
              report.fieldLineages.front().predicateInputIndices.size() == 2 &&
              report.fieldLineages.front()
                      .sourceLinkedPredicateInputIndices.size() == 1 &&
              report.fieldLineages.front()
                      .sourceLinkedPredicateInputIndices.front() == 0,
          "lineage output distinguishes all field readers from the one exact reached predicate");
    if (!report.fieldLineages.empty() &&
        !report.fieldLineages.front().writes.empty()) {
        const AuthorizationTrailFieldAccess& write =
            report.fieldLineages.front().writes.front();
        CHECK(write.authorizationDerived &&
                  write.reachedReadAccessInputIndexValid &&
                  write.reachedReadAccessInputIndex == 1 &&
                  write.reachedPredicateInputIndexValid &&
                  write.reachedPredicateInputIndex == 0,
              "validated output preserves the exact reached read and predicate identities");
    }

    auto expectRejectedEdge = [&](AuthorizationTrailInput malformed,
                                  const char* message) {
        const AuthorizationTrailReport rejected =
            RunAuthorizationTrail(malformed);
        bool anySourceLinked = false;
        for (const AuthorizationTrailPredicate& item : rejected.predicates)
            anySourceLinked |= item.authorizationSourceLinked;
        CHECK(rejected.completeness.invalidReferences &&
                  !rejected.completeness.fieldAccessesComplete &&
                  !rejected.completeness.complete && !anySourceLinked,
              message);
    };

    AuthorizationTrailInput partial = representativeInput();
    partial.fieldAccesses[0].reachedPredicateInputIndexValid = false;
    expectRejectedEdge(std::move(partial),
        "a partially validity-bearing field edge fails closed");

    AuthorizationTrailInput outOfRange = representativeInput();
    outOfRange.fieldAccesses[0].reachedReadAccessInputIndex = 9999;
    expectRejectedEdge(std::move(outOfRange),
        "an out-of-range reached-read identity fails closed");

    AuthorizationTrailInput self = representativeInput();
    self.fieldAccesses[0].reachedReadAccessInputIndex = 0;
    expectRejectedEdge(std::move(self),
        "a write cannot name itself as its reached read");

    AuthorizationTrailInput nonRead = representativeInput();
    AuthorizationTrailFieldAccessInput secondWrite = nonRead.fieldAccesses[0];
    secondWrite.location = loc(0x5001, 0x5000);
    secondWrite.authorizationDerived = false;
    secondWrite.reachedReadAccessInputIndexValid = false;
    secondWrite.reachedPredicateInputIndexValid = false;
    nonRead.fieldAccesses.push_back(std::move(secondWrite));
    nonRead.fieldAccesses[0].reachedReadAccessInputIndex =
        nonRead.fieldAccesses.size() - 1;
    expectRejectedEdge(std::move(nonRead),
        "a store-to-read edge cannot target another write");

    AuthorizationTrailInput crossField = representativeInput();
    crossField.fieldAccesses[0].reachedReadAccessInputIndex = 2;
    expectRejectedEdge(std::move(crossField),
        "a store-to-read edge cannot cross exact field identities");

    AuthorizationTrailInput wrongPredicate = representativeInput();
    wrongPredicate.fieldAccesses[0].reachedPredicateInputIndex = 1;
    expectRejectedEdge(std::move(wrongPredicate),
        "a reached predicate identity must match the exact target read");
}

void honestIndependentConclusions() {
    const AuthorizationTrailReport report =
        RunAuthorizationTrail(representativeInput());
    const auto* format = conclusion(
        report, AuthorizationTrailConclusionKind::LocalFormatValid);
    const auto* server = conclusion(
        report, AuthorizationTrailConclusionKind::ServerAccepted);
    const auto* signature = conclusion(
        report, AuthorizationTrailConclusionKind::SignatureVerified);
    const auto* feature = conclusion(
        report, AuthorizationTrailConclusionKind::FeaturePermitted);
    const auto* key = conclusion(
        report, AuthorizationTrailConclusionKind::EmbeddedExpectedKey);
    const auto* privateMaterial = conclusion(
        report, AuthorizationTrailConclusionKind::PrivateSigningMaterial);
    CHECK(format && format->status ==
                        AuthorizationTrailConclusionStatus::Supported,
          "exact format constraint should support only the local format conclusion");
    CHECK(server && server->status ==
                        AuthorizationTrailConclusionStatus::Candidate,
          "transport success must not support server acceptance");
    CHECK(signature && signature->status ==
                           AuthorizationTrailConclusionStatus::Candidate,
          "crypto presence must not support signature verification");
    CHECK(feature && feature->status ==
                         AuthorizationTrailConclusionStatus::Supported,
          "branch-exclusive feature-control evidence may support the static feature conclusion");
    CHECK(key && key->status ==
                     AuthorizationTrailConclusionStatus::NotFoundInCompleteScope,
          "expected-key absence requires and should retain complete search scope");
    CHECK(privateMaterial && privateMaterial->status ==
                                 AuthorizationTrailConclusionStatus::NotFoundInCompleteScope,
          "private-material absence requires and should retain complete search scope");
    CHECK(privateMaterial &&
              privateMaterial->honestyLabel.find("marker-search scope") !=
                  std::string::npos &&
              privateMaterial->honestyLabel.find("does not establish") !=
                  std::string::npos,
          "private-material negative wording must stay scoped to the supplied marker search");

    AuthorizationTrailInput stronger = representativeInput();
    stronger.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::ServerAccepted,
        AuthorizationTrailEvidenceKind::ReplyContentAcceptance, 0xC000));
    stronger.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::SignatureVerified,
        AuthorizationTrailEvidenceKind::SignatureVerificationResult, 0xC100));
    const AuthorizationTrailReport supported = RunAuthorizationTrail(stronger);
    CHECK(conclusion(supported, AuthorizationTrailConclusionKind::ServerAccepted)
                  ->status == AuthorizationTrailConclusionStatus::Supported,
          "reply-content acceptance may support server acceptance");
    CHECK(conclusion(supported,
                     AuthorizationTrailConclusionKind::SignatureVerified)
                  ->status == AuthorizationTrailConclusionStatus::Supported,
          "checked verifier-result evidence may support static signature verification");
}

void machineBindingEvidenceHonesty() {
    AuthorizationTrailInput capabilityInput;
    capabilityInput.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::MachineBound,
        AuthorizationTrailEvidenceKind::MachineIdentityCapability, 0xD000));
    const AuthorizationTrailReport capability =
        RunAuthorizationTrail(capabilityInput);
    const AuthorizationTrailConclusion* capabilityConclusion = conclusion(
        capability, AuthorizationTrailConclusionKind::MachineBound);
    CHECK(capabilityConclusion && capabilityConclusion->status ==
              AuthorizationTrailConclusionStatus::Candidate,
          "machine-identity API/capability presence must remain only a candidate");
    CHECK(capabilityConclusion &&
              capabilityConclusion->honestyLabel.find(
                  "requires exact machine-identity data flow") !=
                  std::string::npos &&
              avoidsRuntimeSuccessClaim(
                  capabilityConclusion->honestyLabel),
          "capability-only machine-binding wording must require data flow and avoid runtime-success claims");

    AuthorizationTrailInput flowInput;
    flowInput.conclusionEvidence.push_back(conclusionEvidence(
        AuthorizationTrailConclusionKind::MachineBound,
        AuthorizationTrailEvidenceKind::MachineIdentityFlow, 0xD100));
    const AuthorizationTrailReport flow = RunAuthorizationTrail(flowInput);
    const AuthorizationTrailConclusion* flowConclusion = conclusion(
        flow, AuthorizationTrailConclusionKind::MachineBound);
    CHECK(flowConclusion && flowConclusion->status ==
              AuthorizationTrailConclusionStatus::Supported,
          "complete exact machine-identity flow may support static machine binding");
    CHECK(flowConclusion &&
              flowConclusion->honestyLabel.find(
                  "data flow was supplied by the adapter") !=
                  std::string::npos &&
              avoidsRuntimeSuccessClaim(flowConclusion->honestyLabel),
          "supported machine-binding wording must describe adapter evidence without claiming runtime success");

    AuthorizationTrailInput incompleteFlowInput;
    AuthorizationTrailConclusionEvidenceInput incompleteFlow =
        conclusionEvidence(
            AuthorizationTrailConclusionKind::MachineBound,
            AuthorizationTrailEvidenceKind::MachineIdentityFlow, 0xD200);
    incompleteFlow.complete = false;
    incompleteFlowInput.conclusionEvidence.push_back(incompleteFlow);
    const AuthorizationTrailReport incomplete =
        RunAuthorizationTrail(incompleteFlowInput);
    const AuthorizationTrailConclusion* incompleteConclusion = conclusion(
        incomplete, AuthorizationTrailConclusionKind::MachineBound);
    CHECK(incompleteConclusion && incompleteConclusion->status ==
              AuthorizationTrailConclusionStatus::Candidate,
          "incomplete machine-identity flow must downgrade to candidate");
    CHECK(!incomplete.completeness.conclusionEvidenceComplete &&
              !incomplete.completeness.complete,
          "incomplete machine-identity flow must mark conclusion scope incomplete");
    CHECK(incompleteConclusion &&
              !incompleteConclusion->evidence.empty() &&
              !incompleteConclusion->evidence.front().complete &&
              avoidsRuntimeSuccessClaim(
                  incompleteConclusion->honestyLabel),
          "incomplete flow evidence must remain visibly incomplete without a runtime-success claim");
}

void unrelatedFanoutCannotBecomeGlobal() {
    AuthorizationTrailInput input;
    input.predicateCandidates.push_back(
        predicate(0x1000, "AuthorizationBacked", true));
    input.predicateCandidates.push_back(
        predicate(0x2000, "HighFanoutDecoy", false));

    input.predicateUses.push_back(branchUse(0, 0x3000, 0x3010));
    for (size_t i = 0; i < 32; ++i) {
        input.predicateUses.push_back(branchUse(
            1, 0x4000 + static_cast<uint64_t>(i) * 0x100,
            0x8000 + static_cast<uint64_t>(i) * 0x10));
    }

    const AuthorizationTrailReport report = RunAuthorizationTrail(input);
    const auto* linked = predicateAt(report, 0x1000);
    const auto* decoy = predicateAt(report, 0x2000);
    CHECK(linked && linked->role == AuthorizationTrailPredicateRole::Global,
          "a source-linked boolean predicate may be selected as the global gate");
    CHECK(decoy && decoy->role == AuthorizationTrailPredicateRole::Candidate,
          "unrelated high-fanout boolean predicate must remain a ranked candidate");

    AuthorizationTrailInput decoyOnly;
    decoyOnly.predicateCandidates.push_back(
        predicate(0x5000, "OnlyUnlinkedDecoy", false));
    for (size_t i = 0; i < 24; ++i) {
        decoyOnly.predicateUses.push_back(branchUse(
            0, 0x9000 + static_cast<uint64_t>(i) * 0x100,
            0xC000 + static_cast<uint64_t>(i) * 0x10));
    }
    const AuthorizationTrailReport decoyReport =
        RunAuthorizationTrail(decoyOnly);
    const auto* onlyDecoy = predicateAt(decoyReport, 0x5000);
    CHECK(onlyDecoy &&
              onlyDecoy->role == AuthorizationTrailPredicateRole::Candidate,
          "fan-out alone must not synthesize a global authorization predicate");
}

void featurePermissionRequiresProtectedOperationGuard() {
    auto makeInput = [](AuthorizationTrailOperationKind operationKind,
                        bool sourceLinked = true) {
        AuthorizationTrailInput input;
        input.predicateCandidates.push_back(
            predicate(0x1000, "AuthorizationGate", sourceLinked));
        input.predicateUses.push_back(branchUse(0, 0x2000, 0x2010));

        AuthorizationTrailFeatureOperationInput operation;
        operation.location = loc(0x3000, 0x3000);
        operation.kind = operationKind;
        operation.feature = "candidate feature operation";
        operation.evidence = "heuristic action classification";
        operation.confidence = 0.9f;
        input.operations.push_back(operation);

        AuthorizationTrailOperationGuardInput guard;
        guard.predicateIndex = 0;
        guard.predicateIndexValid = true;
        guard.operationIndex = 0;
        guard.operationIndexValid = true;
        guard.location = loc(0x2020, 0x2000);
        guard.branchExclusive = true;
        guard.permitsOperation = true;
        input.operationGuards.push_back(guard);

        input.conclusionEvidence.push_back(conclusionEvidence(
            AuthorizationTrailConclusionKind::FeaturePermitted,
            AuthorizationTrailEvidenceKind::FeatureControl, 0x3000));
        return input;
    };

    const AuthorizationTrailReport featureAction = RunAuthorizationTrail(
        makeInput(AuthorizationTrailOperationKind::FeatureAction));
    CHECK(conclusion(featureAction,
                     AuthorizationTrailConclusionKind::FeaturePermitted)
                  ->status == AuthorizationTrailConclusionStatus::Candidate,
          "a guarded heuristic feature action must remain only a permission candidate");

    const AuthorizationTrailReport userInterface = RunAuthorizationTrail(
        makeInput(AuthorizationTrailOperationKind::UserInterface));
    CHECK(conclusion(userInterface,
                     AuthorizationTrailConclusionKind::FeaturePermitted)
                  ->status == AuthorizationTrailConclusionStatus::Candidate,
          "a guarded UI operation must remain only a permission candidate");

    const AuthorizationTrailReport protectedOperation = RunAuthorizationTrail(
        makeInput(AuthorizationTrailOperationKind::ProtectedOperation));
    CHECK(conclusion(protectedOperation,
                     AuthorizationTrailConclusionKind::FeaturePermitted)
                  ->status == AuthorizationTrailConclusionStatus::Supported,
          "an authorization-linked promoted predicate's exact branch-exclusive protected-operation guard may support feature permission");

    const AuthorizationTrailReport unlinkedProtectedOperation =
        RunAuthorizationTrail(makeInput(
            AuthorizationTrailOperationKind::ProtectedOperation, false));
    CHECK(conclusion(unlinkedProtectedOperation,
                     AuthorizationTrailConclusionKind::FeaturePermitted)
                  ->status == AuthorizationTrailConclusionStatus::Candidate,
          "an unlinked predicate guard over a protected operation must remain a permission candidate");
    bool unlinkedStageStayedCandidate = false;
    for (const AuthorizationTrailStage& stage :
         unlinkedProtectedOperation.stages) {
        unlinkedStageStayedCandidate |=
            stage.stage == AuthorizationTrailStageKind::ProtectedOperation &&
            stage.location.addressValid && stage.location.address == 0x3000 &&
            stage.level == AuthorizationTrailEvidenceLevel::Candidate &&
            stage.honestyLabel.find(
                "no authorization-linked promoted predicate guard") !=
                std::string::npos;
    }
    CHECK(unlinkedStageStayedCandidate,
          "the protected-operation stage must disclose a missing authorization-linked promoted guard");

    AuthorizationTrailInput wrongGuardOwner = makeInput(
        AuthorizationTrailOperationKind::ProtectedOperation);
    wrongGuardOwner.predicateCandidates.push_back(
        predicate(0x1100, "UnlinkedGuard", false));
    wrongGuardOwner.predicateUses.push_back(branchUse(1, 0x2100, 0x2110));
    wrongGuardOwner.operationGuards.front().predicateIndex = 1;
    const AuthorizationTrailReport wrongGuardOwnerReport =
        RunAuthorizationTrail(wrongGuardOwner);
    CHECK(conclusion(wrongGuardOwnerReport,
                     AuthorizationTrailConclusionKind::FeaturePermitted)
                  ->status == AuthorizationTrailConclusionStatus::Candidate,
          "a same-location guard owned by an unlinked candidate cannot borrow a different linked Global predicate");

    AuthorizationTrailInput unpromoted = makeInput(
        AuthorizationTrailOperationKind::ProtectedOperation);
    unpromoted.predicateUses.clear();
    const AuthorizationTrailReport unpromotedReport =
        RunAuthorizationTrail(unpromoted);
    CHECK(conclusion(unpromotedReport,
                     AuthorizationTrailConclusionKind::FeaturePermitted)
                  ->status == AuthorizationTrailConclusionStatus::Candidate,
          "a source-linked predicate that was not promoted from proven branch consumers cannot support feature permission");

    AuthorizationTrailInput mismatched =
        makeInput(AuthorizationTrailOperationKind::ProtectedOperation);
    mismatched.conclusionEvidence.front().location = loc(0x4000, 0x4000);
    const AuthorizationTrailReport mismatchedReport =
        RunAuthorizationTrail(mismatched);
    CHECK(conclusion(mismatchedReport,
                     AuthorizationTrailConclusionKind::FeaturePermitted)
                  ->status == AuthorizationTrailConclusionStatus::Candidate,
          "feature-control evidence at another location must not borrow a protected guard");
}

void secondaryCoverageSetDifference() {
    AuthorizationTrailInput input = representativeInput();
    AuthorizationTrailOperationGuardInput alsoGlobal;
    alsoGlobal.predicateIndex = 0;
    alsoGlobal.predicateIndexValid = true;
    alsoGlobal.operationIndex = 1;
    alsoGlobal.operationIndexValid = true;
    alsoGlobal.location = loc(0x8020, 0x8000);
    alsoGlobal.branchExclusive = true;
    alsoGlobal.permitsOperation = true;
    input.operationGuards.push_back(alsoGlobal);
    input.limits.maxWarnings = 0;
    const AuthorizationTrailReport covered = RunAuthorizationTrail(input);
    CHECK(covered.warnings.empty(),
          "no warning is needed when the global gate covers every secondary operation");
    CHECK(!covered.completeness.warningsTruncated &&
          covered.completeness.complete,
          "zero warning capacity is harmless when coverage needs no warning");
}

void stringToDecisionRetainsOccurrencesAndLimits() {
    AuthorizationTrailInput input;

    AuthorizationTrailStringAnchorInput later;
    later.kind = AuthorizationTrailStringAnchorKind::ValidationArtifact;
    later.label = "not recognised";
    later.literal = "not recognised";
    later.source = loc(0x9000, 0x9000, "literal_later");
    later.evidence = "second literal occurrence";

    AuthorizationTrailStringReferenceInput laterReference;
    laterReference.reference = loc(0x2100, 0x2000, "validate_key");
    laterReference.containingFunction =
        loc(0x2000, 0x2000, "validate_key");
    laterReference.containingFunctionExact = true;
    laterReference.nearbyBranch = loc(0x2108, 0x2000, "validate_key");
    laterReference.instructionDistance = 3;
    laterReference.nearbyBranchAfterReference = true;
    laterReference.nearbyByCodeOrder = true;
    laterReference.branchSearchComplete = true;
    laterReference.evidence =
        "nearest by code order; proximity is not data dependency";
    later.references.push_back(laterReference);
    input.stringAnchors.push_back(later);

    AuthorizationTrailStringAnchorInput earlier = later;
    earlier.source = loc(0x8000, 0x8000, "literal_earlier");
    earlier.evidence = "first literal occurrence";
    earlier.references.front().reference =
        loc(0x1100, 0x1000, "read_key");
    earlier.references.front().containingFunction =
        loc(0x1000, 0x1000, "read_key");
    earlier.references.front().nearbyBranch =
        loc(0x10F8, 0x1000, "read_key");
    earlier.references.front().nearbyBranchAfterReference = false;
    input.stringAnchors.push_back(earlier);

    const AuthorizationTrailReport report = RunAuthorizationTrail(input);
    CHECK(report.stringAnchors.size() == 2,
          "equal authorization literals at distinct coordinates remain distinct occurrences");
    if (report.stringAnchors.size() == 2) {
        CHECK(report.stringAnchors[0].source.address == 0x8000 &&
              report.stringAnchors[1].source.address == 0x9000,
              "string occurrences are deterministically ordered by exact source coordinate");
        const AuthorizationTrailStringReference& reference =
            report.stringAnchors[1].references.front();
        CHECK(reference.containingFunctionExact &&
              reference.containingFunction.address == 0x2000,
              "string xref retains its exact containing function");
        CHECK(reference.nearbyByCodeOrder &&
              reference.nearbyBranch.address == 0x2108 &&
              reference.instructionDistance == 3 &&
              reference.evidence.find("not data dependency") !=
                  std::string::npos,
              "nearby branch retains direction/distance and an explicit non-causal label");
    }
    CHECK(report.completeness.stringAnchorsComplete &&
          report.completeness.complete,
          "complete string/xref inputs preserve overall trail completeness");
    CHECK(std::string(AuthorizationTrailStringAnchorKindText(
              AuthorizationTrailStringAnchorKind::ValidationArtifact)) ==
              "Validation artifact",
          "string anchor kind has a stable user-facing label");

    AuthorizationTrailInput partial = input;
    partial.stringAnchors.front().xrefScopeComplete = false;
    partial.stringAnchors.front().complete = false;
    partial.completeness.stringAnchorsComplete = false;
    const AuthorizationTrailReport partialReport =
        RunAuthorizationTrail(partial);
    CHECK(!partialReport.completeness.stringAnchorsComplete &&
          !partialReport.completeness.complete &&
          partialReport.completeness.reason.find(
              "string-to-decision anchors incomplete") != std::string::npos,
          "partial whole-image xref scope is explicit in report completeness");

    AuthorizationTrailInput capped;
    AuthorizationTrailStringAnchorInput crowded = later;
    crowded.references.push_back(laterReference);
    crowded.references.back().reference =
        loc(0x2200, 0x2000, "validate_key");
    capped.stringAnchors.push_back(std::move(crowded));
    capped.limits.maxStringReferences = 1;
    const AuthorizationTrailReport cappedReport =
        RunAuthorizationTrail(capped);
    CHECK(cappedReport.stringAnchors.size() == 1 &&
          cappedReport.stringAnchors.front().references.size() == 1 &&
          cappedReport.stringAnchors.front().referencesTruncated &&
          cappedReport.completeness.stringReferencesTruncated &&
          !cappedReport.completeness.complete,
          "whole-report string reference cap is visible and fail-closed");
}

void incompleteScopesCapsAndCancellation() {
    AuthorizationTrailInput spatialOnly = representativeInput();
    spatialOnly.fieldAccesses.front().reachedReadAccessInputIndexValid = false;
    spatialOnly.fieldAccesses.front().reachedPredicateInputIndexValid = false;
    AuthorizationTrailReport report = RunAuthorizationTrail(spatialOnly);
    const AuthorizationTrailPredicate* spatialPredicate =
        predicateAt(report, 0);
    CHECK(!report.fieldLineages.empty() &&
              !report.fieldLineages.front().authorizationSourceLinked &&
              spatialPredicate && !spatialPredicate->authorizationSourceLinked &&
              spatialPredicate->role ==
                  AuthorizationTrailPredicateRole::Candidate,
          "matching field coordinates without ordered clobber-free flow cannot source-link a predicate");

    AuthorizationTrailInput incomplete = representativeInput();
    incomplete.completeness.predicateUsesComplete = false;
    report = RunAuthorizationTrail(incomplete);
    CHECK(!report.completeness.complete,
          "explicitly incomplete predicate-use scope must propagate");
    for (const auto& item : report.predicates)
        CHECK(item.role == AuthorizationTrailPredicateRole::Candidate,
              "global/secondary roles must be withheld for incomplete rank scope");
    CHECK(conclusion(report, AuthorizationTrailConclusionKind::EmbeddedExpectedKey)
                  ->status == AuthorizationTrailConclusionStatus::Unknown,
          "incomplete core scope must suppress expected-key absence");
    CHECK(conclusion(report,
                     AuthorizationTrailConclusionKind::PrivateSigningMaterial)
                  ->status == AuthorizationTrailConclusionStatus::Unknown,
          "incomplete core scope must suppress private-material absence");

    AuthorizationTrailInput capped = representativeInput();
    capped.limits.maxPredicateUses = 5;
    report = RunAuthorizationTrail(capped);
    CHECK(report.completeness.usesTruncated &&
          !report.completeness.complete,
          "predicate-use cap must be explicit and make fanout incomplete");
    CHECK(conclusion(report, AuthorizationTrailConclusionKind::EmbeddedExpectedKey)
                  ->status == AuthorizationTrailConclusionStatus::Unknown,
          "internal cap must suppress negative expected-key conclusion");

    AuthorizationTrailInput missingSearch = representativeInput();
    missingSearch.completeness.expectedKeySearchComplete = false;
    missingSearch.completeness.privateMaterialSearchComplete = false;
    report = RunAuthorizationTrail(missingSearch);
    CHECK(report.completeness.complete,
          "optional negative-search scopes do not invalidate positive trail facts");
    CHECK(conclusion(report, AuthorizationTrailConclusionKind::EmbeddedExpectedKey)
                  ->status == AuthorizationTrailConclusionStatus::Unknown &&
          conclusion(report,
                     AuthorizationTrailConclusionKind::PrivateSigningMaterial)
                  ->status == AuthorizationTrailConclusionStatus::Unknown,
          "omitted negative-search scopes must fail closed");

    AuthorizationTrailInput incompleteConclusion = representativeInput();
    AuthorizationTrailConclusionEvidenceInput partial = conclusionEvidence(
        AuthorizationTrailConclusionKind::MachineBound,
        AuthorizationTrailEvidenceKind::Generic, 0xD000);
    partial.complete = false;
    incompleteConclusion.conclusionEvidence.push_back(partial);
    report = RunAuthorizationTrail(incompleteConclusion);
    CHECK(!report.completeness.conclusionEvidenceComplete,
          "one incomplete conclusion row must mark its retained scope incomplete");
    CHECK(conclusion(report, AuthorizationTrailConclusionKind::EmbeddedExpectedKey)
                  ->status == AuthorizationTrailConclusionStatus::Unknown &&
          conclusion(report,
                     AuthorizationTrailConclusionKind::PrivateSigningMaterial)
                  ->status == AuthorizationTrailConclusionStatus::Unknown,
          "an incomplete retained conclusion scope must suppress every absence claim");

    AuthorizationTrailInput warningCapped = representativeInput();
    warningCapped.limits.maxWarnings = 0;
    report = RunAuthorizationTrail(warningCapped);
    CHECK(report.warnings.empty() && report.completeness.warningsTruncated &&
          !report.completeness.complete,
          "warning cap must be explicit rather than silently hiding a secondary gate");

    AuthorizationTrailInput cancelled = representativeInput();
    cancelled.cancelled = [] { return true; };
    report = RunAuthorizationTrail(cancelled);
    CHECK(report.completeness.cancelled && !report.completeness.complete,
          "cancellation must be explicit");
    CHECK(report.predicates.empty() && report.stages.empty() &&
          report.conclusions.empty() && report.warnings.empty(),
          "cancelled analysis must not publish a timing-dependent partial report");
}

void deterministicOrdering() {
    AuthorizationTrailInput input;
    input.predicateCandidates.push_back(predicate(0x4000, "EqualB", false));
    input.predicateCandidates.push_back(predicate(0x3000, "EqualA", false));
    input.predicateUses.push_back(branchUse(0, 0x5000, 0x5010));
    input.predicateUses.push_back(branchUse(1, 0x6000, 0x6010));
    const AuthorizationTrailReport first = RunAuthorizationTrail(input);
    std::reverse(input.predicateUses.begin(), input.predicateUses.end());
    const AuthorizationTrailReport second = RunAuthorizationTrail(input);
    CHECK(first.predicates.size() == 2 && second.predicates.size() == 2,
          "equal-rank deterministic fixture should retain two predicates");
    if (first.predicates.size() == 2 && second.predicates.size() == 2) {
        CHECK(first.predicates[0].function.address == 0x3000 &&
              first.predicates[1].function.address == 0x4000,
              "equal ranking must use static address as a total tie-break");
        CHECK(second.predicates[0].function.address ==
                  first.predicates[0].function.address &&
              second.predicates[1].function.address ==
                  first.predicates[1].function.address,
              "predicate ordering must not depend on use input order");
        CHECK(second.predicates[0].uniqueBranchCallerCount ==
                  first.predicates[0].uniqueBranchCallerCount &&
              second.predicates[1].uniqueBranchCallerCount ==
                  first.predicates[1].uniqueBranchCallerCount,
              "fanout must remain deterministic under use permutation");
    }
}

} // namespace

int main() {
    rankedFanoutSecondaryAndFields();
    exactFieldEdgeIdentity();
    honestIndependentConclusions();
    machineBindingEvidenceHonesty();
    unrelatedFanoutCannotBecomeGlobal();
    featurePermissionRequiresProtectedOperationGuard();
    secondaryCoverageSetDifference();
    stringToDecisionRetainsOccurrencesAndLimits();
    incompleteScopesCapsAndCancellation();
    deterministicOrdering();
    if (failures) {
        std::printf("%d authorization trail test(s) failed\n", failures);
        return 1;
    }
    std::puts("authorization trail tests passed");
    return 0;
}
