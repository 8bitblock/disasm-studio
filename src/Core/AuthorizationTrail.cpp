#include "AuthorizationTrail.h"

#include <algorithm>
#include <cmath>
#include <deque>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace ds {

namespace {

constexpr size_t kHardStringAnchors = 16384;
constexpr size_t kHardStringReferences = 131072;
constexpr size_t kHardStringReferencesPerAnchor = 16384;
constexpr size_t kHardPredicateCandidates = 4096;
constexpr size_t kHardPredicateUses = 65536;
constexpr size_t kHardFieldAccesses = 32768;
constexpr size_t kHardFieldLineages = 16384;
constexpr size_t kHardPredicateRelations = 32768;
constexpr size_t kHardOperations = 16384;
constexpr size_t kHardOperationGuards = 65536;
constexpr size_t kHardStageEvidence = 16384;
constexpr size_t kHardConclusionEvidence = 16384;
constexpr size_t kHardConsumersPerPredicate = 16384;
constexpr size_t kHardProvenanceHops = 256;
constexpr size_t kHardWarnings = 256;

float confidence(float value) {
    if (!std::isfinite(value)) return 0.0f;
    return (std::max)(0.0f, (std::min)(1.0f, value));
}

void appendReason(std::string& destination, const std::string& reason) {
    if (reason.empty()) return;
    if (!destination.empty()) destination += "; ";
    destination += reason;
}

template <typename T>
size_t boundedLimit(T requested, size_t hardLimit) {
    return (std::min)(static_cast<size_t>(requested), hardLimit);
}

bool stopped(const AuthorizationTrailInput& input) {
    return input.cancelled && input.cancelled();
}

void cancelReport(AuthorizationTrailReport& report) {
    report.stringAnchors.clear();
    report.predicateUses.clear();
    report.operations.clear();
    report.fieldLineages.clear();
    report.predicates.clear();
    report.stages.clear();
    report.conclusions.clear();
    report.warnings.clear();
    report.completeness.complete = false;
    report.completeness.cancelled = true;
    report.completeness.reason = "authorization trail analysis cancelled";
}

bool lessBool(bool left, bool right) {
    // Known/valid coordinates sort before absent coordinates.
    return left != right && left;
}

bool locationLess(const AuthorizationLocation& left,
                  const AuthorizationLocation& right) {
    if (left.functionAddressValid != right.functionAddressValid)
        return lessBool(left.functionAddressValid, right.functionAddressValid);
    if (left.functionAddressValid && left.functionAddress != right.functionAddress)
        return left.functionAddress < right.functionAddress;
    if (left.addressValid != right.addressValid)
        return lessBool(left.addressValid, right.addressValid);
    if (left.addressValid && left.address != right.address)
        return left.address < right.address;
    if (left.fileOffsetValid != right.fileOffsetValid)
        return lessBool(left.fileOffsetValid, right.fileOffsetValid);
    if (left.fileOffsetValid && left.fileOffset != right.fileOffset)
        return left.fileOffset < right.fileOffset;
    return left.functionName < right.functionName;
}

bool locationEquivalent(const AuthorizationLocation& left,
                        const AuthorizationLocation& right) {
    return left.address == right.address &&
           left.addressValid == right.addressValid &&
           left.fileOffset == right.fileOffset &&
           left.fileOffsetValid == right.fileOffsetValid &&
           left.functionAddress == right.functionAddress &&
           left.functionAddressValid == right.functionAddressValid;
}

bool functionIdentity(const AuthorizationLocation& location, uint64_t& value) {
    if (location.functionAddressValid) {
        value = location.functionAddress;
        return true;
    }
    if (location.addressValid) {
        value = location.address;
        return true;
    }
    return false;
}

std::string locationText(const AuthorizationLocation& location) {
    if (!location.functionName.empty()) return location.functionName;
    uint64_t address = 0;
    if (!functionIdentity(location, address)) return "unknown predicate";
    std::ostringstream text;
    text << "0x" << std::hex << std::uppercase << address;
    return text.str();
}

bool fieldIdentityValid(const AuthorizationTrailFieldIdentity& field) {
    if (!field.exact || field.base == AuthorizationTrailFieldBaseKind::Unknown ||
        !field.rootAddressValid || field.widthBits == 0)
        return false;
    if ((field.base == AuthorizationTrailFieldBaseKind::RootParameter ||
         field.base == AuthorizationTrailFieldBaseKind::StackObject) &&
        !field.rootOrdinalValid)
        return false;
    const uint64_t bytes = (static_cast<uint64_t>(field.widthBits) + 7u) / 8u;
    return field.displacement <=
        (std::numeric_limits<int64_t>::max)() -
            static_cast<int64_t>((std::min)(
                bytes, static_cast<uint64_t>((std::numeric_limits<int64_t>::max)())));
}

bool fieldLess(const AuthorizationTrailFieldIdentity& left,
               const AuthorizationTrailFieldIdentity& right) {
    if (left.base != right.base)
        return static_cast<uint8_t>(left.base) < static_cast<uint8_t>(right.base);
    if (left.rootAddressValid != right.rootAddressValid)
        return lessBool(left.rootAddressValid, right.rootAddressValid);
    if (left.rootAddress != right.rootAddress)
        return left.rootAddress < right.rootAddress;
    if (left.rootOrdinalValid != right.rootOrdinalValid)
        return lessBool(left.rootOrdinalValid, right.rootOrdinalValid);
    if (left.rootOrdinal != right.rootOrdinal)
        return left.rootOrdinal < right.rootOrdinal;
    if (left.displacement != right.displacement)
        return left.displacement < right.displacement;
    if (left.widthBits != right.widthBits)
        return left.widthBits < right.widthBits;
    if (left.exact != right.exact) return lessBool(left.exact, right.exact);
    return left.display < right.display;
}

bool operationRelevant(AuthorizationTrailOperationKind kind) {
    return kind == AuthorizationTrailOperationKind::FeatureAction ||
           kind == AuthorizationTrailOperationKind::ProtectedOperation;
}

AuthorizationTrailEvidenceLevel stageEvidenceLevel(
    const AuthorizationTrailStageEvidenceInput& item) {
    if (!item.complete) return AuthorizationTrailEvidenceLevel::Candidate;
    switch (item.stage) {
    case AuthorizationTrailStageKind::Input:
        return item.kind == AuthorizationTrailEvidenceKind::InputRead
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::FormatValidation:
        return item.kind == AuthorizationTrailEvidenceKind::FormatConstraint
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::RemoteRequest:
        return item.kind == AuthorizationTrailEvidenceKind::TransportOperation ||
               item.kind == AuthorizationTrailEvidenceKind::TransportSuccess
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::EntitlementParsing:
        return item.kind == AuthorizationTrailEvidenceKind::EntitlementParse ||
               item.kind == AuthorizationTrailEvidenceKind::ReplyContentAcceptance
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::CryptoVerification:
        // Constants, an import, or an unchecked crypto call are presence only.
        return item.kind ==
                   AuthorizationTrailEvidenceKind::SignatureVerificationResult
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::StatePersistence:
        return item.kind == AuthorizationTrailEvidenceKind::PersistentState
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::GlobalPredicate:
    case AuthorizationTrailStageKind::FeaturePredicate:
        return item.kind == AuthorizationTrailEvidenceKind::PredicateControl
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::ProtectedOperation:
        // A free-standing stage row has no predicate/guard identity.  It may
        // identify a protected operation, but cannot by itself prove that an
        // authorization predicate controls that operation.  The synthesized
        // operation row below is promoted only after checking the exact guard.
        return AuthorizationTrailEvidenceLevel::Candidate;
    case AuthorizationTrailStageKind::Count:
        break;
    }
    return AuthorizationTrailEvidenceLevel::Unknown;
}

std::string stageHonesty(const AuthorizationTrailStage& stage) {
    if (stage.kind == AuthorizationTrailEvidenceKind::TransportSuccess)
        return "Transport/API success does not establish server acceptance.";
    if (stage.kind == AuthorizationTrailEvidenceKind::CryptoPrimitivePresence)
        return "Cryptographic material or API presence does not establish signature verification.";
    if (stage.kind ==
        AuthorizationTrailEvidenceKind::SignatureVerificationResult)
        return "A static verifier-result path was recovered; no runtime signature outcome was observed.";
    if (!stage.complete)
        return "This stage is partial and cannot support an exhaustive authorization conclusion.";
    return {};
}

int conclusionStatusRank(AuthorizationTrailConclusionStatus status) {
    switch (status) {
    case AuthorizationTrailConclusionStatus::Supported: return 3;
    case AuthorizationTrailConclusionStatus::Candidate: return 2;
    case AuthorizationTrailConclusionStatus::NotFoundInCompleteScope: return 1;
    case AuthorizationTrailConclusionStatus::Unknown: return 0;
    }
    return 0;
}

AuthorizationTrailConclusionStatus positiveConclusionStatus(
    AuthorizationTrailConclusionKind conclusion,
    AuthorizationTrailEvidenceKind evidence,
    bool complete,
    bool provenProtectedOperationGuard = false) {
    AuthorizationTrailConclusionStatus result =
        AuthorizationTrailConclusionStatus::Unknown;
    switch (conclusion) {
    case AuthorizationTrailConclusionKind::LocalFormatValid:
        if (evidence == AuthorizationTrailEvidenceKind::FormatConstraint)
            result = AuthorizationTrailConclusionStatus::Supported;
        break;
    case AuthorizationTrailConclusionKind::ServerAccepted:
        if (evidence == AuthorizationTrailEvidenceKind::ReplyContentAcceptance)
            result = AuthorizationTrailConclusionStatus::Supported;
        else if (evidence == AuthorizationTrailEvidenceKind::TransportOperation ||
                 evidence == AuthorizationTrailEvidenceKind::TransportSuccess)
            result = AuthorizationTrailConclusionStatus::Candidate;
        break;
    case AuthorizationTrailConclusionKind::SignatureVerified:
        if (evidence ==
            AuthorizationTrailEvidenceKind::SignatureVerificationResult)
            result = AuthorizationTrailConclusionStatus::Supported;
        else if (evidence ==
                 AuthorizationTrailEvidenceKind::CryptoPrimitivePresence)
            result = AuthorizationTrailConclusionStatus::Candidate;
        break;
    case AuthorizationTrailConclusionKind::FeaturePermitted:
        if (evidence == AuthorizationTrailEvidenceKind::FeatureControl)
            result = provenProtectedOperationGuard
                ? AuthorizationTrailConclusionStatus::Supported
                : AuthorizationTrailConclusionStatus::Candidate;
        else if (evidence == AuthorizationTrailEvidenceKind::PredicateControl)
            result = AuthorizationTrailConclusionStatus::Candidate;
        break;
    case AuthorizationTrailConclusionKind::MachineBound:
        if (evidence == AuthorizationTrailEvidenceKind::MachineIdentityFlow)
            result = AuthorizationTrailConclusionStatus::Supported;
        else if (evidence ==
                 AuthorizationTrailEvidenceKind::MachineIdentityCapability)
            result = AuthorizationTrailConclusionStatus::Candidate;
        break;
    case AuthorizationTrailConclusionKind::EmbeddedExpectedKey:
        if (evidence == AuthorizationTrailEvidenceKind::ExpectedKeyLiteral)
            result = AuthorizationTrailConclusionStatus::Supported;
        break;
    case AuthorizationTrailConclusionKind::PrivateSigningMaterial:
        if (evidence == AuthorizationTrailEvidenceKind::PrivateSigningMaterial)
            result = AuthorizationTrailConclusionStatus::Supported;
        break;
    case AuthorizationTrailConclusionKind::Count:
        break;
    }
    if (!complete && result == AuthorizationTrailConclusionStatus::Supported)
        result = AuthorizationTrailConclusionStatus::Candidate;
    return result;
}

std::string conclusionHonesty(AuthorizationTrailConclusionKind kind,
                              AuthorizationTrailConclusionStatus status) {
    switch (kind) {
    case AuthorizationTrailConclusionKind::LocalFormatValid:
        return status == AuthorizationTrailConclusionStatus::Supported
            ? "The local acceptance condition was recovered; no particular key was tested."
            : "Local format acceptance was not established.";
    case AuthorizationTrailConclusionKind::ServerAccepted:
        return status == AuthorizationTrailConclusionStatus::Supported
            ? "Reply-content control flow supports acceptance; API success alone was not used and no runtime reply was observed."
            : "Transport/API success is not server acceptance.";
    case AuthorizationTrailConclusionKind::SignatureVerified:
        return status == AuthorizationTrailConclusionStatus::Supported
            ? "A verifier result controls the static path; no runtime signature outcome was observed."
            : "Cryptographic material or API presence is not signature verification.";
    case AuthorizationTrailConclusionKind::FeaturePermitted:
        return status == AuthorizationTrailConclusionStatus::Supported
            ? "An authorization-linked Global/Secondary predicate has an exact branch-exclusive guard over a protected operation; no runtime permission outcome was observed."
            : "A protected-operation location or predicate candidate alone does not establish that the feature is permitted.";
    case AuthorizationTrailConclusionKind::MachineBound:
        return status == AuthorizationTrailConclusionStatus::Supported
            ? "Exact machine-identity data flow was supplied by the adapter."
            : "Machine binding requires exact machine-identity data flow, not a name or registry access alone.";
    case AuthorizationTrailConclusionKind::EmbeddedExpectedKey:
        if (status == AuthorizationTrailConclusionStatus::NotFoundInCompleteScope)
            return "No expected-key literal was found within the explicitly complete static search scope.";
        if (status == AuthorizationTrailConclusionStatus::Supported)
            return "An expected-key literal was identified in the analyzed image.";
        return "Absence of an embedded expected key was not established for a complete scope.";
    case AuthorizationTrailConclusionKind::PrivateSigningMaterial:
        if (status == AuthorizationTrailConclusionStatus::NotFoundInCompleteScope)
            return "No private-key or signing-material marker was identified "
                   "within the explicitly complete marker-search scope; this "
                   "does not establish that private key material is absent "
                   "elsewhere and does not produce a real signed entitlement.";
        if (status == AuthorizationTrailConclusionStatus::Supported)
            return "Private signing material was identified in the analyzed image.";
        return "Absence of private signing material was not established for a complete scope.";
    case AuthorizationTrailConclusionKind::Count:
        break;
    }
    return {};
}

bool candidateLessByFunction(
    const AuthorizationTrailPredicateCandidateInput& left,
    const AuthorizationTrailPredicateCandidateInput& right) {
    if (locationLess(left.function, right.function)) return true;
    if (locationLess(right.function, left.function)) return false;
    if (left.returnContract != right.returnContract)
        return static_cast<uint8_t>(left.returnContract) <
               static_cast<uint8_t>(right.returnContract);
    if (left.authorizationSourceLinked != right.authorizationSourceLinked)
        return lessBool(left.authorizationSourceLinked,
                        right.authorizationSourceLinked);
    if (left.sideEffectLight != right.sideEffectLight)
        return lessBool(left.sideEffectLight, right.sideEffectLight);
    if (confidence(left.confidence) != confidence(right.confidence))
        return confidence(left.confidence) > confidence(right.confidence);
    return left.evidence < right.evidence;
}

bool sameCandidateFunction(
    const AuthorizationTrailPredicateCandidateInput& left,
    const AuthorizationTrailPredicateCandidateInput& right) {
    return locationEquivalent(left.function, right.function);
}

bool operationLessInput(const AuthorizationTrailFeatureOperationInput& left,
                        const AuthorizationTrailFeatureOperationInput& right) {
    if (locationLess(left.location, right.location)) return true;
    if (locationLess(right.location, left.location)) return false;
    if (left.kind != right.kind)
        return static_cast<uint8_t>(left.kind) < static_cast<uint8_t>(right.kind);
    if (left.feature != right.feature) return left.feature < right.feature;
    return left.evidence < right.evidence;
}

bool sameOperation(const AuthorizationTrailFeatureOperationInput& left,
                   const AuthorizationTrailFeatureOperationInput& right) {
    return left.kind == right.kind && left.feature == right.feature &&
           locationEquivalent(left.location, right.location);
}

bool coreScopeComplete(const AuthorizationTrailCompleteness& complete) {
    return !complete.cancelled && complete.stringAnchorsComplete &&
           complete.predicateCandidatesComplete &&
           complete.predicateUsesComplete && complete.fieldAccessesComplete &&
           complete.predicateRelationsComplete && complete.operationsComplete &&
           complete.operationGuardsComplete && complete.stageEvidenceComplete &&
           complete.conclusionEvidenceComplete &&
           !complete.stringAnchorsTruncated &&
           !complete.stringReferencesTruncated &&
           !complete.predicatesTruncated && !complete.usesTruncated &&
           !complete.fieldAccessesTruncated &&
           !complete.fieldLineagesTruncated &&
           !complete.relationsTruncated && !complete.operationsTruncated &&
           !complete.operationGuardsTruncated && !complete.stagesTruncated &&
           !complete.conclusionsTruncated && !complete.warningsTruncated &&
           !complete.consumersTruncated &&
           !complete.provenanceTruncated && !complete.invalidReferences;
}

void rejectReference(AuthorizationTrailCompleteness& complete,
                     const std::string& reason) {
    complete.invalidReferences = true;
    ++complete.rejectedReferenceCount;
    appendReason(complete.reason, reason);
}

} // namespace

const char* AuthorizationTrailPredicateRoleText(
    AuthorizationTrailPredicateRole role) {
    switch (role) {
    case AuthorizationTrailPredicateRole::Candidate: return "Candidate";
    case AuthorizationTrailPredicateRole::Global: return "Global";
    case AuthorizationTrailPredicateRole::Secondary: return "Secondary";
    }
    return "Candidate";
}

const char* AuthorizationTrailStageKindText(AuthorizationTrailStageKind kind) {
    switch (kind) {
    case AuthorizationTrailStageKind::Input: return "Input";
    case AuthorizationTrailStageKind::FormatValidation: return "Format validation";
    case AuthorizationTrailStageKind::RemoteRequest: return "Remote request";
    case AuthorizationTrailStageKind::EntitlementParsing: return "Entitlement parsing";
    case AuthorizationTrailStageKind::CryptoVerification: return "Cryptographic verification";
    case AuthorizationTrailStageKind::StatePersistence: return "Stored license state";
    case AuthorizationTrailStageKind::GlobalPredicate: return "Global predicate";
    case AuthorizationTrailStageKind::FeaturePredicate: return "Feature predicate";
    case AuthorizationTrailStageKind::ProtectedOperation: return "Protected operation";
    case AuthorizationTrailStageKind::Count: break;
    }
    return "Unknown";
}

const char* AuthorizationTrailConclusionKindText(
    AuthorizationTrailConclusionKind kind) {
    switch (kind) {
    case AuthorizationTrailConclusionKind::LocalFormatValid: return "Locally valid format";
    case AuthorizationTrailConclusionKind::ServerAccepted: return "Server accepted";
    case AuthorizationTrailConclusionKind::SignatureVerified: return "Signature verified";
    case AuthorizationTrailConclusionKind::FeaturePermitted: return "Feature permitted";
    case AuthorizationTrailConclusionKind::MachineBound: return "Machine-bound entitlement";
    case AuthorizationTrailConclusionKind::EmbeddedExpectedKey: return "Embedded expected key";
    case AuthorizationTrailConclusionKind::PrivateSigningMaterial: return "Private signing material";
    case AuthorizationTrailConclusionKind::Count: break;
    }
    return "Unknown";
}

const char* AuthorizationTrailConclusionStatusText(
    AuthorizationTrailConclusionStatus status) {
    switch (status) {
    case AuthorizationTrailConclusionStatus::Unknown: return "Unknown";
    case AuthorizationTrailConclusionStatus::Candidate: return "Candidate";
    case AuthorizationTrailConclusionStatus::Supported: return "Evidence-backed";
    case AuthorizationTrailConclusionStatus::NotFoundInCompleteScope:
        return "Not found in complete scope";
    }
    return "Unknown";
}

const char* AuthorizationTrailStringAnchorKindText(
    AuthorizationTrailStringAnchorKind kind) {
    switch (kind) {
    case AuthorizationTrailStringAnchorKind::Endpoint: return "Endpoint";
    case AuthorizationTrailStringAnchorKind::Route: return "Route";
    case AuthorizationTrailStringAnchorKind::LicenseArtifact:
        return "License artifact";
    case AuthorizationTrailStringAnchorKind::ValidationArtifact:
        return "Validation artifact";
    case AuthorizationTrailStringAnchorKind::AuthenticationArtifact:
        return "Authentication artifact";
    case AuthorizationTrailStringAnchorKind::SuccessArtifact:
        return "Success artifact";
    case AuthorizationTrailStringAnchorKind::FailureArtifact:
        return "Failure artifact";
    case AuthorizationTrailStringAnchorKind::ReplyMarkerArtifact:
        return "Reply marker";
    }
    return "Authorization string";
}

bool AuthorizationTrailFieldIdentityEquivalentExact(
    const AuthorizationTrailFieldIdentity& left,
    const AuthorizationTrailFieldIdentity& right) noexcept {
    if (!fieldIdentityValid(left) || !fieldIdentityValid(right) ||
        left.base != right.base || left.rootAddress != right.rootAddress ||
        left.displacement != right.displacement ||
        left.widthBits != right.widthBits)
        return false;
    if (left.base == AuthorizationTrailFieldBaseKind::RootParameter ||
        left.base == AuthorizationTrailFieldBaseKind::StackObject)
        return left.rootOrdinal == right.rootOrdinal;
    return true;
}

AuthorizationTrailReport RunAuthorizationTrail(
    const AuthorizationTrailInput& input) {
    AuthorizationTrailReport report;
    AuthorizationTrailCompleteness& complete = report.completeness;
    complete.stringAnchorsComplete =
        input.completeness.stringAnchorsComplete;
    complete.predicateCandidatesComplete =
        input.completeness.predicateCandidatesComplete;
    complete.predicateUsesComplete = input.completeness.predicateUsesComplete;
    complete.fieldAccessesComplete = input.completeness.fieldAccessesComplete;
    complete.predicateRelationsComplete =
        input.completeness.predicateRelationsComplete;
    complete.operationsComplete = input.completeness.operationsComplete;
    complete.operationGuardsComplete =
        input.completeness.operationGuardsComplete;
    complete.stageEvidenceComplete = input.completeness.stageEvidenceComplete;
    complete.conclusionEvidenceComplete =
        input.completeness.conclusionEvidenceComplete;
    complete.expectedKeySearchComplete =
        input.completeness.expectedKeySearchComplete;
    complete.privateMaterialSearchComplete =
        input.completeness.privateMaterialSearchComplete;

    if (stopped(input)) {
        cancelReport(report);
        return report;
    }

    const size_t stringAnchorLimit = boundedLimit(
        input.limits.maxStringAnchors, kHardStringAnchors);
    const size_t stringReferenceLimit = boundedLimit(
        input.limits.maxStringReferences, kHardStringReferences);
    const size_t stringReferencePerAnchorLimit = boundedLimit(
        input.limits.maxStringReferencesPerAnchor,
        kHardStringReferencesPerAnchor);
    const size_t predicateLimit = boundedLimit(
        input.limits.maxPredicateCandidates, kHardPredicateCandidates);
    const size_t useLimit = boundedLimit(input.limits.maxPredicateUses,
                                         kHardPredicateUses);
    const size_t fieldAccessLimit = boundedLimit(
        input.limits.maxFieldAccesses, kHardFieldAccesses);
    const size_t fieldLineageLimit = boundedLimit(
        input.limits.maxFieldLineages, kHardFieldLineages);
    const size_t relationLimit = boundedLimit(
        input.limits.maxPredicateRelations, kHardPredicateRelations);
    const size_t operationLimit = boundedLimit(input.limits.maxOperations,
                                               kHardOperations);
    const size_t guardLimit = boundedLimit(input.limits.maxOperationGuards,
                                           kHardOperationGuards);
    const size_t stageLimit = boundedLimit(input.limits.maxStageEvidence,
                                           kHardStageEvidence);
    const size_t conclusionLimit = boundedLimit(
        input.limits.maxConclusionEvidence, kHardConclusionEvidence);
    const size_t consumerLimit = boundedLimit(
        input.limits.maxConsumersPerPredicate, kHardConsumersPerPredicate);
    const size_t provenanceLimit = boundedLimit(
        input.limits.maxProvenanceHopsPerAccess, kHardProvenanceHops);
    const size_t warningLimit = boundedLimit(input.limits.maxWarnings,
                                             kHardWarnings);

    // ---- String-to-decision anchors -----------------------------------------
    // One row is retained per literal occurrence.  References are copied from
    // the whole-image xref adapter under both per-anchor and whole-report caps;
    // a nearby branch remains an explicitly non-causal navigation hint.
    const size_t stringAnchorScan = (std::min)(input.stringAnchors.size(),
                                               kHardStringAnchors);
    if (stringAnchorScan != input.stringAnchors.size()) {
        complete.stringAnchorsTruncated = true;
        complete.stringAnchorsComplete = false;
        appendReason(complete.reason, "string-anchor hard scan cap reached");
    }
    std::vector<size_t> stringAnchorOrder(stringAnchorScan);
    for (size_t i = 0; i < stringAnchorScan; ++i) stringAnchorOrder[i] = i;
    std::stable_sort(stringAnchorOrder.begin(), stringAnchorOrder.end(),
        [&](size_t left, size_t right) {
            const AuthorizationTrailStringAnchorInput& a = input.stringAnchors[left];
            const AuthorizationTrailStringAnchorInput& b = input.stringAnchors[right];
            if (a.kind != b.kind)
                return static_cast<uint8_t>(a.kind) < static_cast<uint8_t>(b.kind);
            if (a.label != b.label) return a.label < b.label;
            if (a.literal != b.literal) return a.literal < b.literal;
            if (locationLess(a.source, b.source)) return true;
            if (locationLess(b.source, a.source)) return false;
            return left < right;
        });

    size_t retainedStringReferences = 0;
    for (size_t orderedIndex : stringAnchorOrder) {
        if (stopped(input)) {
            cancelReport(report);
            return report;
        }
        if (report.stringAnchors.size() >= stringAnchorLimit) {
            complete.stringAnchorsTruncated = true;
            complete.stringAnchorsComplete = false;
            continue;
        }

        const AuthorizationTrailStringAnchorInput& source =
            input.stringAnchors[orderedIndex];
        AuthorizationTrailStringAnchor anchor;
        anchor.inputIndex = orderedIndex;
        anchor.kind = source.kind;
        anchor.label = source.label;
        anchor.literal = source.literal;
        anchor.source = source.source;
        anchor.xrefScopeComplete = source.xrefScopeComplete;
        anchor.referencesTruncated = source.referencesTruncated;
        anchor.complete = source.complete && source.xrefScopeComplete &&
                          !source.referencesTruncated;
        anchor.evidence = source.evidence;
        if (!source.xrefScopeComplete || source.referencesTruncated ||
            !source.complete)
            complete.stringAnchorsComplete = false;
        if (source.referencesTruncated) {
            complete.stringReferencesTruncated = true;
            appendReason(complete.reason,
                         "string-reference adapter cap reached");
        }

        const size_t referenceScan = (std::min)(
            source.references.size(), kHardStringReferencesPerAnchor);
        if (referenceScan != source.references.size()) {
            anchor.referencesTruncated = true;
            anchor.complete = false;
            complete.stringReferencesTruncated = true;
            complete.stringAnchorsComplete = false;
            appendReason(complete.reason,
                         "string-reference hard scan cap reached");
        }
        std::vector<size_t> referenceOrder(referenceScan);
        for (size_t i = 0; i < referenceOrder.size(); ++i)
            referenceOrder[i] = i;
        std::stable_sort(referenceOrder.begin(), referenceOrder.end(),
            [&](size_t left, size_t right) {
                const auto& a = source.references[left];
                const auto& b = source.references[right];
                if (locationLess(a.reference, b.reference)) return true;
                if (locationLess(b.reference, a.reference)) return false;
                if (locationLess(a.nearbyBranch, b.nearbyBranch)) return true;
                if (locationLess(b.nearbyBranch, a.nearbyBranch)) return false;
                return left < right;
            });

        size_t retainedForAnchor = 0;
        AuthorizationLocation priorReference;
        bool priorReferenceValid = false;
        size_t referenceCursor = 0;
        for (size_t referenceIndex : referenceOrder) {
            if ((referenceCursor++ & 0x3ffu) == 0 && stopped(input)) {
                cancelReport(report);
                return report;
            }
            const AuthorizationTrailStringReferenceInput& item =
                source.references[referenceIndex];
            if (!item.reference.addressValid) {
                rejectReference(complete,
                    "string xref has no valid instruction address");
                complete.stringAnchorsComplete = false;
                anchor.complete = false;
                continue;
            }
            // One instruction can reference both the literal substring and its
            // containing string start.  Present that retained xref once.
            if (priorReferenceValid &&
                locationEquivalent(priorReference, item.reference))
                continue;
            priorReference = item.reference;
            priorReferenceValid = true;

            if (retainedForAnchor >= stringReferencePerAnchorLimit ||
                retainedStringReferences >= stringReferenceLimit) {
                anchor.referencesTruncated = true;
                anchor.complete = false;
                complete.stringReferencesTruncated = true;
                complete.stringAnchorsComplete = false;
                continue;
            }

            AuthorizationTrailStringReference reference;
            reference.reference = item.reference;
            reference.containingFunction = item.containingFunction;
            reference.nearbyBranch = item.nearbyBranch;
            reference.instructionDistance = item.instructionDistance;
            reference.nearbyBranchAfterReference =
                item.nearbyBranchAfterReference;
            reference.nearbyByCodeOrder = item.nearbyByCodeOrder &&
                item.nearbyBranch.addressValid;
            reference.containingFunctionExact =
                item.containingFunctionExact &&
                item.containingFunction.addressValid;
            reference.branchSearchComplete = item.branchSearchComplete;
            reference.evidence = item.evidence;
            if (!reference.containingFunctionExact) {
                ++complete.unownedStringReferenceCount;
                complete.stringAnchorsComplete = false;
                anchor.complete = false;
            }
            if (!reference.branchSearchComplete) {
                ++complete.incompleteStringBranchSearchCount;
                complete.stringAnchorsComplete = false;
                anchor.complete = false;
            }
            anchor.references.push_back(std::move(reference));
            ++retainedForAnchor;
            ++retainedStringReferences;
        }
        if (anchor.referencesTruncated)
            appendReason(complete.reason,
                         "string-reference retention limit reached");
        report.stringAnchors.push_back(std::move(anchor));
    }
    if (complete.stringAnchorsTruncated)
        appendReason(complete.reason, "string-anchor retention limit reached");

    // ---- Predicate candidates -------------------------------------------------
    const size_t predicateScan = (std::min)(input.predicateCandidates.size(),
                                            kHardPredicateCandidates);
    if (predicateScan != input.predicateCandidates.size()) {
        complete.predicatesTruncated = true;
        complete.predicateCandidatesComplete = false;
        appendReason(complete.reason, "predicate-candidate hard scan cap reached");
    }
    std::vector<size_t> candidateOrder(predicateScan);
    for (size_t i = 0; i < predicateScan; ++i) candidateOrder[i] = i;
    std::sort(candidateOrder.begin(), candidateOrder.end(),
              [&](size_t left, size_t right) {
                  const auto& a = input.predicateCandidates[left];
                  const auto& b = input.predicateCandidates[right];
                  if (candidateLessByFunction(a, b)) return true;
                  if (candidateLessByFunction(b, a)) return false;
                  return left < right;
              });

    std::vector<AuthorizationTrailPredicate> predicateWork;
    std::unordered_map<size_t, size_t> predicateWorkByInput;
    for (size_t cursor = 0; cursor < candidateOrder.size();) {
        if (stopped(input)) {
            cancelReport(report);
            return report;
        }
        const size_t begin = cursor;
        const auto& first = input.predicateCandidates[candidateOrder[begin]];
        while (cursor < candidateOrder.size() &&
               sameCandidateFunction(
                   first, input.predicateCandidates[candidateOrder[cursor]]))
            ++cursor;

        uint64_t functionAddress = 0;
        if (!functionIdentity(first.function, functionAddress)) {
            for (size_t i = begin; i < cursor; ++i)
                rejectReference(complete,
                    "predicate candidate has no valid function location");
            complete.predicateCandidatesComplete = false;
            continue;
        }
        if (predicateWork.size() >= predicateLimit) {
            complete.predicatesTruncated = true;
            complete.predicateCandidatesComplete = false;
            continue;
        }

        AuthorizationTrailPredicate predicate;
        predicate.inputIndex = candidateOrder[begin];
        predicate.function = first.function;
        predicate.returnContract = first.returnContract;
        predicate.returnAnalysisComplete = true;
        predicate.sideEffectLight = true;
        predicate.complete = true;
        predicate.confidence = 0.0f;
        for (size_t i = begin; i < cursor; ++i) {
            const size_t original = candidateOrder[i];
            const auto& source = input.predicateCandidates[original];
            if (source.returnContract != predicate.returnContract) {
                predicate.returnContract =
                    AuthorizationTrailBooleanContract::Unknown;
                predicate.complete = false;
                complete.predicateCandidatesComplete = false;
            }
            predicate.returnAnalysisComplete &= source.returnAnalysisComplete;
            predicate.sideEffectLight &= source.sideEffectLight;
            predicate.authorizationSourceLinked |=
                source.authorizationSourceLinked;
            predicate.complete &= source.complete;
            predicate.confidence = (std::max)(
                predicate.confidence, confidence(source.confidence));
            if (predicate.evidence.empty() ||
                (!source.evidence.empty() && source.evidence < predicate.evidence))
                predicate.evidence = source.evidence;
        }
        if (!predicate.complete || !predicate.returnAnalysisComplete)
            complete.predicateCandidatesComplete = false;
        const size_t workIndex = predicateWork.size();
        predicateWork.push_back(std::move(predicate));
        for (size_t i = begin; i < cursor; ++i)
            predicateWorkByInput[candidateOrder[i]] = workIndex;
    }
    if (predicateWork.size() < candidateOrder.size() &&
        predicateWork.size() >= predicateLimit) {
        appendReason(complete.reason, "predicate-candidate limit reached");
    }

    // ---- Feature operations ---------------------------------------------------
    const size_t operationScan = (std::min)(input.operations.size(),
                                            kHardOperations);
    if (operationScan != input.operations.size()) {
        complete.operationsTruncated = true;
        complete.operationsComplete = false;
        appendReason(complete.reason, "feature-operation hard scan cap reached");
    }
    std::vector<size_t> operationOrder(operationScan);
    for (size_t i = 0; i < operationScan; ++i) operationOrder[i] = i;
    std::sort(operationOrder.begin(), operationOrder.end(),
              [&](size_t left, size_t right) {
                  const auto& a = input.operations[left];
                  const auto& b = input.operations[right];
                  if (operationLessInput(a, b)) return true;
                  if (operationLessInput(b, a)) return false;
                  return left < right;
              });
    std::unordered_map<size_t, size_t> operationReportByInput;
    for (size_t cursor = 0; cursor < operationOrder.size();) {
        if (stopped(input)) {
            cancelReport(report);
            return report;
        }
        const size_t begin = cursor;
        const auto& first = input.operations[operationOrder[begin]];
        while (cursor < operationOrder.size() &&
               sameOperation(first, input.operations[operationOrder[cursor]]))
            ++cursor;
        if (report.operations.size() >= operationLimit) {
            complete.operationsTruncated = true;
            complete.operationsComplete = false;
            continue;
        }
        AuthorizationTrailFeatureOperation operation;
        operation.inputIndex = operationOrder[begin];
        operation.location = first.location;
        operation.kind = first.kind;
        operation.feature = first.feature;
        operation.evidence = first.evidence;
        operation.confidence = confidence(first.confidence);
        operation.complete = true;
        for (size_t i = begin; i < cursor; ++i) {
            const auto& source = input.operations[operationOrder[i]];
            operation.complete &= source.complete;
            operation.confidence = (std::max)(
                operation.confidence, confidence(source.confidence));
            if (operation.evidence.empty() ||
                (!source.evidence.empty() && source.evidence < operation.evidence))
                operation.evidence = source.evidence;
        }
        if (!operation.complete) complete.operationsComplete = false;
        const size_t reportIndex = report.operations.size();
        report.operations.push_back(std::move(operation));
        for (size_t i = begin; i < cursor; ++i)
            operationReportByInput[operationOrder[i]] = reportIndex;
    }
    if (complete.operationsTruncated)
        appendReason(complete.reason, "feature-operation limit reached");

    // ---- Predicate uses -------------------------------------------------------
    struct RetainedUse {
        size_t inputIndex = 0;
        size_t predicateWorkIndex = 0;
    };
    const size_t useScan = (std::min)(input.predicateUses.size(),
                                      kHardPredicateUses);
    if (useScan != input.predicateUses.size()) {
        complete.usesTruncated = true;
        complete.predicateUsesComplete = false;
        appendReason(complete.reason, "predicate-use hard scan cap reached");
    }
    std::vector<RetainedUse> uses;
    uses.reserve(useScan);
    for (size_t i = 0; i < useScan; ++i) {
        if ((i & 0x3ffu) == 0 && stopped(input)) {
            cancelReport(report);
            return report;
        }
        const auto& source = input.predicateUses[i];
        if (!source.predicateIndexValid ||
            source.predicateIndex >= input.predicateCandidates.size()) {
            rejectReference(complete, "predicate use has an invalid predicate reference");
            complete.predicateUsesComplete = false;
            continue;
        }
        const auto retained = predicateWorkByInput.find(source.predicateIndex);
        if (retained == predicateWorkByInput.end()) {
            complete.usesTruncated = true;
            complete.predicateUsesComplete = false;
            continue;
        }
        uses.push_back({i, retained->second});
    }
    auto useLess = [&](const RetainedUse& left, const RetainedUse& right) {
        if (left.predicateWorkIndex != right.predicateWorkIndex)
            return left.predicateWorkIndex < right.predicateWorkIndex;
        const auto& a = input.predicateUses[left.inputIndex];
        const auto& b = input.predicateUses[right.inputIndex];
        if (locationLess(a.callsite, b.callsite)) return true;
        if (locationLess(b.callsite, a.callsite)) return false;
        if (locationLess(a.continuation, b.continuation)) return true;
        if (locationLess(b.continuation, a.continuation)) return false;
        if (locationLess(a.caller, b.caller)) return true;
        if (locationLess(b.caller, a.caller)) return false;
        if (locationLess(a.branch, b.branch)) return true;
        if (locationLess(b.branch, a.branch)) return false;
        if (locationLess(a.comparison, b.comparison)) return true;
        if (locationLess(b.comparison, a.comparison)) return false;
        if (locationLess(a.trueDestination, b.trueDestination)) return true;
        if (locationLess(b.trueDestination, a.trueDestination)) return false;
        if (locationLess(a.falseDestination, b.falseDestination)) return true;
        if (locationLess(b.falseDestination, a.falseDestination)) return false;
        if (a.useKind != b.useKind)
            return static_cast<uint8_t>(a.useKind) <
                   static_cast<uint8_t>(b.useKind);
        if (a.resultWidthBits != b.resultWidthBits)
            return a.resultWidthBits < b.resultWidthBits;
        if (a.flagsPreserved != b.flagsPreserved)
            return lessBool(a.flagsPreserved, b.flagsPreserved);
        if (a.branchUseProven != b.branchUseProven)
            return lessBool(a.branchUseProven, b.branchUseProven);
        if (a.complete != b.complete) return lessBool(a.complete, b.complete);
        return a.evidence < b.evidence;
    };
    auto sameUse = [&](const RetainedUse& left, const RetainedUse& right) {
        const auto& a = input.predicateUses[left.inputIndex];
        const auto& b = input.predicateUses[right.inputIndex];
        return left.predicateWorkIndex == right.predicateWorkIndex &&
               locationEquivalent(a.callsite, b.callsite) &&
               locationEquivalent(a.continuation, b.continuation) &&
               locationEquivalent(a.caller, b.caller) &&
               locationEquivalent(a.branch, b.branch) &&
               locationEquivalent(a.comparison, b.comparison) &&
               locationEquivalent(a.trueDestination, b.trueDestination) &&
               locationEquivalent(a.falseDestination, b.falseDestination) &&
               a.useKind == b.useKind &&
               a.resultWidthBits == b.resultWidthBits &&
               a.flagsPreserved == b.flagsPreserved &&
               a.branchUseProven == b.branchUseProven && a.complete == b.complete;
    };
    std::sort(uses.begin(), uses.end(), useLess);
    uses.erase(std::unique(uses.begin(), uses.end(), sameUse), uses.end());
    // Conflicting records for one exact call/branch cannot independently prove
    // a permitted arm. Check the full bounded scan before display truncation,
    // so a cap cannot hide the counter-evidence and restore a false proof.
    using DecisionKey = std::tuple<size_t, uint64_t, uint64_t>;
    struct DecisionFacts {
        std::set<uint64_t> comparisons, trueArms, falseArms, continuations;
        std::set<uint8_t> widths;
        bool conflicts() const {
            return comparisons.size() > 1 || trueArms.size() > 1 || falseArms.size() > 1 ||
                   continuations.size() > 1 || widths.size() > 1;
        }
    };
    std::map<DecisionKey, DecisionFacts> decisions;
    auto decisionKey = [](const RetainedUse& retained, const AuthorizationTrailPredicateUseInput& source) {
        return DecisionKey{ retained.predicateWorkIndex, source.callsite.address, source.branch.address };
    };
    for (const RetainedUse& retained : uses) {
        const auto& source = input.predicateUses[retained.inputIndex];
        if (!source.callsite.addressValid || !source.branch.addressValid || !source.branchUseProven) continue;
        auto& facts = decisions[decisionKey(retained, source)];
        if (source.comparison.addressValid) facts.comparisons.insert(source.comparison.address);
        if (source.trueDestination.addressValid) facts.trueArms.insert(source.trueDestination.address);
        if (source.falseDestination.addressValid) facts.falseArms.insert(source.falseDestination.address);
        if (source.continuation.addressValid) facts.continuations.insert(source.continuation.address);
        if (source.resultWidthBits) facts.widths.insert(source.resultWidthBits);
    }
    bool conflictingDecisions = false;
    if (uses.size() > useLimit) {
        uses.resize(useLimit);
        complete.usesTruncated = true;
        complete.predicateUsesComplete = false;
        appendReason(complete.reason, "predicate-use limit reached");
    }
    for (const RetainedUse& retained : uses) {
        const auto& source = input.predicateUses[retained.inputIndex];
        AuthorizationTrailPredicateUse use;
        use.inputIndex = retained.inputIndex;
        use.predicateInputIndex = source.predicateIndex;
        use.callsite = source.callsite;
        use.continuation = source.continuation;
        use.caller = source.caller;
        use.comparison = source.comparison;
        use.branch = source.branch;
        use.trueDestination = source.trueDestination;
        use.falseDestination = source.falseDestination;
        use.useKind = source.useKind;
        use.resultWidthBits = source.resultWidthBits;
        use.flagsPreserved = source.flagsPreserved;
        use.branchUseProven = source.branchUseProven;
        use.complete = source.complete;
        use.confidence = confidence(source.confidence);
        use.evidence = source.evidence;
        if (source.callsite.addressValid && source.branch.addressValid) {
            const auto found = decisions.find(decisionKey(retained, source));
            if (found != decisions.end() && found->second.conflicts()) {
                use.branchUseProven = false;
                use.complete = false;
                appendReason(use.evidence, "Conflicting return-use evidence for this call and branch; permitted arm is unresolved");
                conflictingDecisions = true;
            }
        }
        if (!use.complete) complete.predicateUsesComplete = false;
        const size_t reportIndex = report.predicateUses.size();
        report.predicateUses.push_back(std::move(use));
        AuthorizationTrailPredicate& predicate =
            predicateWork[retained.predicateWorkIndex];
        if (predicate.useIndices.size() < consumerLimit)
            predicate.useIndices.push_back(reportIndex);
        else {
            complete.consumersTruncated = true;
            complete.predicateUsesComplete = false;
        }
    }
    if (complete.consumersTruncated)
        appendReason(complete.reason, "per-predicate consumer navigation limit reached");
    if (conflictingDecisions)
        appendReason(complete.reason, "conflicting predicate-use comparison, continuation, width, or branch destinations");

    // Count callsites and caller functions independently. Caller VA zero is a
    // normal identity when its validity bit is true.
    for (size_t predicateIndex = 0;
         predicateIndex < predicateWork.size(); ++predicateIndex) {
        AuthorizationTrailPredicate& predicate = predicateWork[predicateIndex];
        std::set<uint64_t> callsites;
        std::set<uint64_t> callers;
        std::set<uint64_t> branchCallers;
        std::set<std::pair<uint64_t, uint64_t>> branchConsumers;
        for (size_t useIndex : predicate.useIndices) {
            if (useIndex >= report.predicateUses.size()) continue;
            const AuthorizationTrailPredicateUse& use =
                report.predicateUses[useIndex];
            if (use.callsite.addressValid) callsites.insert(use.callsite.address);
            uint64_t caller = 0;
            const bool callerValid = functionIdentity(use.caller, caller);
            if (callerValid) callers.insert(caller);
            const bool branch = use.complete && use.branchUseProven &&
                use.flagsPreserved &&
                use.useKind == AuthorizationTrailUseKind::Branched &&
                use.callsite.addressValid && use.branch.addressValid;
            if (branch) {
                branchConsumers.emplace(use.callsite.address, use.branch.address);
                if (callerValid) branchCallers.insert(caller);
            }
        }
        predicate.callsiteCount = callsites.size();
        predicate.uniqueCallerCount = callers.size();
        predicate.branchConsumerCount = branchConsumers.size();
        predicate.uniqueBranchCallerCount = branchCallers.size();
    }

    // ---- Exact field lineages -------------------------------------------------
    struct RetainedFieldAccess {
        size_t inputIndex = 0;
        size_t predicateWorkIndex = 0;
        bool predicateWorkIndexValid = false;
    };
    const size_t fieldScan = (std::min)(input.fieldAccesses.size(),
                                        kHardFieldAccesses);
    if (fieldScan != input.fieldAccesses.size()) {
        complete.fieldAccessesTruncated = true;
        complete.fieldAccessesComplete = false;
        appendReason(complete.reason, "field-access hard scan cap reached");
    }
    std::vector<RetainedFieldAccess> fieldAccesses;
    fieldAccesses.reserve(fieldScan);
    for (size_t i = 0; i < fieldScan; ++i) {
        if ((i & 0x3ffu) == 0 && stopped(input)) {
            cancelReport(report);
            return report;
        }
        const auto& source = input.fieldAccesses[i];
        RetainedFieldAccess retained;
        retained.inputIndex = i;
        if (source.predicateIndexValid) {
            if (source.predicateIndex >= input.predicateCandidates.size()) {
                rejectReference(complete,
                    "field access has an invalid predicate reference");
                complete.fieldAccessesComplete = false;
                continue;
            }
            const auto predicate = predicateWorkByInput.find(source.predicateIndex);
            if (predicate == predicateWorkByInput.end()) {
                complete.fieldAccessesTruncated = true;
                complete.fieldAccessesComplete = false;
                continue;
            }
            retained.predicateWorkIndex = predicate->second;
            retained.predicateWorkIndexValid = true;
        }
        fieldAccesses.push_back(retained);
    }
    auto fieldAccessLess = [&](const RetainedFieldAccess& left,
                               const RetainedFieldAccess& right) {
        const auto& a = input.fieldAccesses[left.inputIndex];
        const auto& b = input.fieldAccesses[right.inputIndex];
        if (fieldLess(a.field, b.field)) return true;
        if (fieldLess(b.field, a.field)) return false;
        if (a.access != b.access)
            return static_cast<uint8_t>(a.access) <
                   static_cast<uint8_t>(b.access);
        if (locationLess(a.location, b.location)) return true;
        if (locationLess(b.location, a.location)) return false;
        if (left.predicateWorkIndexValid != right.predicateWorkIndexValid)
            return lessBool(left.predicateWorkIndexValid,
                            right.predicateWorkIndexValid);
        if (left.predicateWorkIndex != right.predicateWorkIndex)
            return left.predicateWorkIndex < right.predicateWorkIndex;
        if (a.authorizationDerived != b.authorizationDerived)
            return lessBool(a.authorizationDerived, b.authorizationDerived);
        if (a.reachedReadAccessInputIndexValid !=
            b.reachedReadAccessInputIndexValid)
            return lessBool(a.reachedReadAccessInputIndexValid,
                            b.reachedReadAccessInputIndexValid);
        if (a.reachedReadAccessInputIndexValid &&
            a.reachedReadAccessInputIndex !=
                b.reachedReadAccessInputIndex)
            return a.reachedReadAccessInputIndex <
                   b.reachedReadAccessInputIndex;
        if (a.reachedPredicateInputIndexValid !=
            b.reachedPredicateInputIndexValid)
            return lessBool(a.reachedPredicateInputIndexValid,
                            b.reachedPredicateInputIndexValid);
        if (a.reachedPredicateInputIndexValid &&
            a.reachedPredicateInputIndex != b.reachedPredicateInputIndex)
            return a.reachedPredicateInputIndex <
                   b.reachedPredicateInputIndex;
        if (a.contributesToPredicateReturn !=
            b.contributesToPredicateReturn)
            return lessBool(a.contributesToPredicateReturn,
                            b.contributesToPredicateReturn);
        return a.evidence < b.evidence;
    };
    auto sameFieldAccess = [&](const RetainedFieldAccess& left,
                               const RetainedFieldAccess& right) {
        const auto& a = input.fieldAccesses[left.inputIndex];
        const auto& b = input.fieldAccesses[right.inputIndex];
        return AuthorizationTrailFieldIdentityEquivalentExact(a.field, b.field) &&
               a.access == b.access &&
               locationEquivalent(a.location, b.location) &&
               left.predicateWorkIndexValid == right.predicateWorkIndexValid &&
               (!left.predicateWorkIndexValid ||
               left.predicateWorkIndex == right.predicateWorkIndex) &&
               a.authorizationDerived == b.authorizationDerived &&
               a.reachedReadAccessInputIndexValid ==
                   b.reachedReadAccessInputIndexValid &&
               (!a.reachedReadAccessInputIndexValid ||
                a.reachedReadAccessInputIndex ==
                    b.reachedReadAccessInputIndex) &&
               a.reachedPredicateInputIndexValid ==
                   b.reachedPredicateInputIndexValid &&
               (!a.reachedPredicateInputIndexValid ||
                a.reachedPredicateInputIndex ==
                    b.reachedPredicateInputIndex) &&
               a.contributesToPredicateReturn ==
                   b.contributesToPredicateReturn;
    };
    std::sort(fieldAccesses.begin(), fieldAccesses.end(), fieldAccessLess);
    fieldAccesses.erase(
        std::unique(fieldAccesses.begin(), fieldAccesses.end(), sameFieldAccess),
        fieldAccesses.end());
    if (fieldAccesses.size() > fieldAccessLimit) {
        fieldAccesses.resize(fieldAccessLimit);
        complete.fieldAccessesTruncated = true;
        complete.fieldAccessesComplete = false;
        appendReason(complete.reason, "field-access limit reached");
    }
    std::unordered_map<size_t, size_t> retainedFieldAccessByInput;
    retainedFieldAccessByInput.reserve(fieldAccesses.size());
    for (size_t retainedIndex = 0;
         retainedIndex < fieldAccesses.size(); ++retainedIndex)
        retainedFieldAccessByInput.emplace(
            fieldAccesses[retainedIndex].inputIndex, retainedIndex);

    size_t fieldCursor = 0;
    while (fieldCursor < fieldAccesses.size()) {
        if (stopped(input)) {
            cancelReport(report);
            return report;
        }
        const size_t begin = fieldCursor;
        const auto& first = input.fieldAccesses[
            fieldAccesses[begin].inputIndex];
        if (!fieldIdentityValid(first.field)) {
            ++complete.unlinkedFieldAccessCount;
            ++fieldCursor;
            continue;
        }
        while (fieldCursor < fieldAccesses.size() &&
               AuthorizationTrailFieldIdentityEquivalentExact(
                   first.field,
                   input.fieldAccesses[fieldAccesses[fieldCursor].inputIndex]
                       .field))
            ++fieldCursor;

        AuthorizationTrailFieldLineage lineage;
        lineage.field = first.field;
        std::set<size_t> predicateInputs;
        std::set<size_t> sourceLinkedPredicateInputs;
        std::set<size_t> sourceLinkedPredicateWork;
        for (size_t i = begin; i < fieldCursor; ++i) {
            const RetainedFieldAccess& retained = fieldAccesses[i];
            const auto& source = input.fieldAccesses[retained.inputIndex];
            AuthorizationTrailFieldAccess access;
            access.inputIndex = retained.inputIndex;
            access.access = source.access;
            access.location = source.location;
            access.predicateInputIndex = source.predicateIndex;
            access.predicateInputIndexValid = source.predicateIndexValid;
            access.authorizationDerived = source.authorizationDerived;
            access.contributesToPredicateReturn =
                source.contributesToPredicateReturn;
            access.complete = source.complete;
            access.evidence = source.evidence;
            const size_t retainHops = (std::min)(source.provenance.size(),
                                                  provenanceLimit);
            access.provenance.assign(source.provenance.begin(),
                                     source.provenance.begin() + retainHops);
            if (retainHops != source.provenance.size()) {
                complete.provenanceTruncated = true;
                complete.fieldAccessesComplete = false;
                access.complete = false;
            }
            if (access.access == AuthorizationTrailFieldAccessKind::Write) {
                const bool claimsReachedRead =
                    source.reachedReadAccessInputIndexValid ||
                    source.reachedPredicateInputIndexValid;
                bool reachedReadValid = false;
                std::string invalidEdgeReason;
                if (claimsReachedRead) {
                    if (!source.reachedReadAccessInputIndexValid ||
                        !source.reachedPredicateInputIndexValid) {
                        invalidEdgeReason =
                            "field write has a partially valid store-to-read edge";
                    } else if (!access.complete ||
                               !access.authorizationDerived ||
                               !access.location.addressValid) {
                        invalidEdgeReason =
                            "field write edge lacks a complete exact authorization-derived store";
                    } else if (source.reachedReadAccessInputIndex ==
                               retained.inputIndex) {
                        invalidEdgeReason =
                            "field write edge refers to its own access";
                    } else {
                        const auto targetPosition =
                            retainedFieldAccessByInput.find(
                                source.reachedReadAccessInputIndex);
                        if (targetPosition ==
                                retainedFieldAccessByInput.end()) {
                            invalidEdgeReason =
                                "field write edge refers to an unavailable read access";
                        } else if (targetPosition->second < begin ||
                                   targetPosition->second >= fieldCursor) {
                            invalidEdgeReason =
                                "field write edge crosses exact field identities";
                        } else {
                            const RetainedFieldAccess& targetRetained =
                                fieldAccesses[targetPosition->second];
                            const AuthorizationTrailFieldAccessInput& target =
                                input.fieldAccesses[targetRetained.inputIndex];
                            const auto reachedPredicate =
                                predicateWorkByInput.find(
                                    source.reachedPredicateInputIndex);
                            if (target.access !=
                                    AuthorizationTrailFieldAccessKind::Read) {
                                invalidEdgeReason =
                                    "field write edge target is not a read access";
                            } else if (!target.complete ||
                                       !target.location.addressValid ||
                                       !target.contributesToPredicateReturn ||
                                       !target.predicateIndexValid) {
                                invalidEdgeReason =
                                    "field write edge target is not a complete exact predicate-return read";
                            } else if (target.predicateIndex !=
                                       source.reachedPredicateInputIndex) {
                                invalidEdgeReason =
                                    "field write edge predicate does not match the target read";
                            } else if (!targetRetained.predicateWorkIndexValid ||
                                       reachedPredicate ==
                                           predicateWorkByInput.end() ||
                                       targetRetained.predicateWorkIndex !=
                                           reachedPredicate->second) {
                                invalidEdgeReason =
                                    "field write edge predicate is unavailable or inconsistent";
                            } else {
                                reachedReadValid = true;
                                access.reachedReadAccessInputIndex =
                                    targetRetained.inputIndex;
                                access.reachedReadAccessInputIndexValid = true;
                                access.reachedPredicateInputIndex =
                                    source.reachedPredicateInputIndex;
                                access.reachedPredicateInputIndexValid = true;
                                sourceLinkedPredicateInputs.insert(
                                    source.reachedPredicateInputIndex);
                                sourceLinkedPredicateWork.insert(
                                    reachedPredicate->second);
                            }
                        }
                    }
                    if (!reachedReadValid) {
                        rejectReference(complete, invalidEdgeReason);
                        complete.fieldAccessesComplete = false;
                        access.complete = false;
                    }
                }
                lineage.complete &= access.complete;
                lineage.writes.push_back(std::move(access));
            } else {
                if (source.reachedReadAccessInputIndexValid ||
                    source.reachedPredicateInputIndexValid) {
                    rejectReference(complete,
                        "read access cannot own a store-to-read edge");
                    complete.fieldAccessesComplete = false;
                    access.complete = false;
                }
                if (retained.predicateWorkIndexValid && access.complete &&
                    access.contributesToPredicateReturn) {
                    predicateInputs.insert(source.predicateIndex);
                }
                lineage.complete &= access.complete;
                lineage.reads.push_back(std::move(access));
            }
        }
        if (lineage.writes.empty() || lineage.reads.empty()) {
            complete.unlinkedFieldAccessCount += fieldCursor - begin;
            continue;
        }
        if (report.fieldLineages.size() >= fieldLineageLimit) {
            complete.fieldLineagesTruncated = true;
            complete.fieldAccessesComplete = false;
            complete.unlinkedFieldAccessCount += fieldCursor - begin;
            continue;
        }
        lineage.predicateInputIndices.assign(predicateInputs.begin(),
                                             predicateInputs.end());
        lineage.sourceLinkedPredicateInputIndices.assign(
            sourceLinkedPredicateInputs.begin(),
            sourceLinkedPredicateInputs.end());
        lineage.authorizationSourceLinked =
            !sourceLinkedPredicateWork.empty() && lineage.complete;
        lineage.honestyLabel = lineage.authorizationSourceLinked
            ? "An exact stable field slice has an ordered, clobber-free authorization-derived store-to-read edge to the specifically named predicate. Other readers are not source-linked by field equality alone."
            : "The exact field slice has both reads and writes, but no complete exact authorization-derived store-to-specific-predicate-read edge was proved.";
        if (!lineage.complete) complete.fieldAccessesComplete = false;
        const size_t lineageIndex = report.fieldLineages.size();
        report.fieldLineages.push_back(std::move(lineage));
        if (report.fieldLineages.back().authorizationSourceLinked) {
            for (size_t workIndex : sourceLinkedPredicateWork) {
                if (workIndex >= predicateWork.size()) continue;
                predicateWork[workIndex].authorizationSourceLinked = true;
                predicateWork[workIndex].fieldLineageIndices.push_back(
                    lineageIndex);
            }
        }
    }
    if (complete.fieldLineagesTruncated)
        appendReason(complete.reason, "field-lineage limit reached");
    if (complete.provenanceTruncated)
        appendReason(complete.reason, "field provenance-hop limit reached");

    // ---- Branch-exclusive operation guards ----------------------------------
    struct GuardKey {
        size_t predicate = 0;
        size_t operation = 0;
        uint64_t location = 0;
        bool locationValid = false;
        bool operator<(const GuardKey& other) const {
            return std::tie(predicate, operation, locationValid, location) <
                   std::tie(other.predicate, other.operation,
                            other.locationValid, other.location);
        }
    };
    const size_t guardScan = (std::min)(input.operationGuards.size(),
                                        kHardOperationGuards);
    if (guardScan != input.operationGuards.size()) {
        complete.operationGuardsTruncated = true;
        complete.operationGuardsComplete = false;
        appendReason(complete.reason, "operation-guard hard scan cap reached");
    }
    std::map<GuardKey, size_t> guards;
    for (size_t i = 0; i < guardScan; ++i) {
        if ((i & 0x3ffu) == 0 && stopped(input)) {
            cancelReport(report);
            return report;
        }
        const auto& source = input.operationGuards[i];
        if (!source.predicateIndexValid ||
            source.predicateIndex >= input.predicateCandidates.size() ||
            !source.operationIndexValid ||
            source.operationIndex >= input.operations.size()) {
            rejectReference(complete, "operation guard has an invalid reference");
            complete.operationGuardsComplete = false;
            continue;
        }
        const auto predicate = predicateWorkByInput.find(source.predicateIndex);
        const auto operation = operationReportByInput.find(source.operationIndex);
        if (predicate == predicateWorkByInput.end() ||
            operation == operationReportByInput.end()) {
            complete.operationGuardsTruncated = true;
            complete.operationGuardsComplete = false;
            continue;
        }
        if (!source.complete) complete.operationGuardsComplete = false;
        if (!source.complete || !source.branchExclusive ||
            !source.permitsOperation)
            continue;
        GuardKey key;
        key.predicate = predicate->second;
        key.operation = operation->second;
        key.location = source.location.address;
        key.locationValid = source.location.addressValid;
        guards.emplace(key, i);
    }
    if (guards.size() > guardLimit) {
        size_t keep = 0;
        for (auto iterator = guards.begin(); iterator != guards.end();) {
            if (keep++ < guardLimit) {
                ++iterator;
            } else {
                iterator = guards.erase(iterator);
            }
        }
        complete.operationGuardsTruncated = true;
        complete.operationGuardsComplete = false;
        appendReason(complete.reason, "operation-guard limit reached");
    }
    for (const auto& [key, _] : guards) {
        if (key.predicate >= predicateWork.size() ||
            key.operation >= report.operations.size())
            continue;
        auto& guarded = predicateWork[key.predicate].guardedOperationIndices;
        guarded.push_back(key.operation);
    }
    for (auto& predicate : predicateWork) {
        auto& guarded = predicate.guardedOperationIndices;
        std::sort(guarded.begin(), guarded.end());
        guarded.erase(std::unique(guarded.begin(), guarded.end()), guarded.end());
        predicate.guardedOperationCount = guarded.size();
    }

    // ---- Predicate relations --------------------------------------------------
    using Relation = std::pair<size_t, size_t>;
    const size_t relationScan = (std::min)(input.predicateRelations.size(),
                                           kHardPredicateRelations);
    if (relationScan != input.predicateRelations.size()) {
        complete.relationsTruncated = true;
        complete.predicateRelationsComplete = false;
        appendReason(complete.reason, "predicate-relation hard scan cap reached");
    }
    std::set<Relation> relations;
    for (size_t i = 0; i < relationScan; ++i) {
        if ((i & 0x3ffu) == 0 && stopped(input)) {
            cancelReport(report);
            return report;
        }
        const auto& source = input.predicateRelations[i];
        if (!source.upstreamPredicateIndexValid ||
            source.upstreamPredicateIndex >= input.predicateCandidates.size() ||
            !source.downstreamPredicateIndexValid ||
            source.downstreamPredicateIndex >= input.predicateCandidates.size()) {
            rejectReference(complete, "predicate relation has an invalid reference");
            complete.predicateRelationsComplete = false;
            continue;
        }
        const auto upstream = predicateWorkByInput.find(
            source.upstreamPredicateIndex);
        const auto downstream = predicateWorkByInput.find(
            source.downstreamPredicateIndex);
        if (upstream == predicateWorkByInput.end() ||
            downstream == predicateWorkByInput.end()) {
            complete.relationsTruncated = true;
            complete.predicateRelationsComplete = false;
            continue;
        }
        if (!source.complete) complete.predicateRelationsComplete = false;
        if (!source.complete || !source.branchExclusive ||
            !source.onPermittedPath || !source.downstreamResultRequired ||
            upstream->second == downstream->second)
            continue;
        relations.emplace(upstream->second, downstream->second);
    }
    if (relations.size() > relationLimit) {
        while (relations.size() > relationLimit)
            relations.erase(std::prev(relations.end()));
        complete.relationsTruncated = true;
        complete.predicateRelationsComplete = false;
        appendReason(complete.reason, "predicate-relation limit reached");
    }

    // ---- Ranking and role classification -------------------------------------
    for (AuthorizationTrailPredicate& predicate : predicateWork) {
        size_t relevantOperations = 0;
        for (size_t operationIndex : predicate.guardedOperationIndices)
            if (operationIndex < report.operations.size() &&
                operationRelevant(report.operations[operationIndex].kind))
                ++relevantOperations;
        const float sourceScore = predicate.authorizationSourceLinked ? 1.0f : 0.0f;
        const float booleanScore =
            predicate.returnContract != AuthorizationTrailBooleanContract::Unknown
                ? (predicate.returnAnalysisComplete ? 1.0f : 0.5f)
                : 0.0f;
        const float fanoutScore = (std::min)(
            static_cast<float>(predicate.uniqueBranchCallerCount) / 20.0f,
            1.0f);
        const float operationScore = (std::min)(
            static_cast<float>(relevantOperations) / 8.0f, 1.0f);
        const float shapeScore = predicate.sideEffectLight ? 1.0f : 0.0f;
        predicate.rankScore = confidence(
            0.35f * sourceScore + 0.25f * booleanScore +
            0.20f * fanoutScore + 0.15f * operationScore +
            0.05f * shapeScore);
        // Confidence is a bounded tie-strengthener, not a substitute for the
        // typed boolean/data-flow evidence above.
        predicate.rankScore = confidence(
            0.90f * predicate.rankScore + 0.10f * predicate.confidence);
        predicate.honestyLabel =
            "Rank combines typed source lineage, complete boolean-return shape, distinct branch-consuming callers, and guarded operations; it is not runtime authorization proof.";
    }

    const bool roleScopeComplete =
        complete.predicateCandidatesComplete &&
        complete.predicateUsesComplete &&
        complete.predicateRelationsComplete && complete.operationsComplete &&
        complete.operationGuardsComplete && !complete.predicatesTruncated &&
        !complete.usesTruncated && !complete.relationsTruncated &&
        !complete.operationsTruncated && !complete.operationGuardsTruncated &&
        !complete.consumersTruncated && !complete.invalidReferences;

    auto eligible = [&](size_t index) {
        return index < predicateWork.size() &&
               predicateWork[index].returnContract !=
                   AuthorizationTrailBooleanContract::Unknown &&
               predicateWork[index].returnAnalysisComplete &&
               predicateWork[index].branchConsumerCount != 0;
    };
    auto globalEligible = [&](size_t index) {
        // Caller fan-out and a boolean-shaped return are useful ranking facts,
        // but neither connects a predicate to authorization. The source bit is
        // supplied directly by the adapter or promoted only by an exact
        // authorization-derived field-write -> predicate-return-read lineage.
        return eligible(index) &&
               predicateWork[index].authorizationSourceLinked;
    };
    auto strongerWorkPredicate = [&](size_t left, size_t right) {
        const auto& a = predicateWork[left];
        const auto& b = predicateWork[right];
        if (a.rankScore != b.rankScore) return a.rankScore > b.rankScore;
        if (a.uniqueBranchCallerCount != b.uniqueBranchCallerCount)
            return a.uniqueBranchCallerCount > b.uniqueBranchCallerCount;
        if (a.branchConsumerCount != b.branchConsumerCount)
            return a.branchConsumerCount > b.branchConsumerCount;
        if (a.uniqueCallerCount != b.uniqueCallerCount)
            return a.uniqueCallerCount > b.uniqueCallerCount;
        if (locationLess(a.function, b.function)) return true;
        if (locationLess(b.function, a.function)) return false;
        return a.evidence < b.evidence;
    };

    size_t globalWorkIndex = 0;
    bool globalWorkIndexValid = false;
    if (roleScopeComplete) {
        std::set<size_t> incoming;
        for (const Relation& relation : relations)
            if (eligible(relation.first) && eligible(relation.second))
                incoming.insert(relation.second);
        for (size_t i = 0; i < predicateWork.size(); ++i) {
            if (!globalEligible(i) || incoming.count(i)) continue;
            if (!globalWorkIndexValid || strongerWorkPredicate(i, globalWorkIndex)) {
                globalWorkIndex = i;
                globalWorkIndexValid = true;
            }
        }
        if (!globalWorkIndexValid) {
            for (size_t i = 0; i < predicateWork.size(); ++i) {
                if (!globalEligible(i)) continue;
                if (!globalWorkIndexValid ||
                    strongerWorkPredicate(i, globalWorkIndex)) {
                    globalWorkIndex = i;
                    globalWorkIndexValid = true;
                }
            }
        }
    }
    if (globalWorkIndexValid)
        predicateWork[globalWorkIndex].role =
            AuthorizationTrailPredicateRole::Global;

    std::set<size_t> secondaryWorkIndices;
    if (globalWorkIndexValid) {
        std::unordered_map<size_t, std::vector<size_t>> downstream;
        for (const Relation& relation : relations)
            downstream[relation.first].push_back(relation.second);
        std::deque<size_t> pending;
        std::set<size_t> seen;
        pending.push_back(globalWorkIndex);
        seen.insert(globalWorkIndex);
        while (!pending.empty()) {
            if (stopped(input)) {
                cancelReport(report);
                return report;
            }
            const size_t current = pending.front();
            pending.pop_front();
            const auto found = downstream.find(current);
            if (found == downstream.end()) continue;
            for (size_t next : found->second) {
                if (!seen.insert(next).second) continue;
                pending.push_back(next);
                if (!eligible(next)) continue;
                bool guardsRelevant = false;
                for (size_t operation :
                     predicateWork[next].guardedOperationIndices) {
                    guardsRelevant |= operation < report.operations.size() &&
                        operationRelevant(report.operations[operation].kind);
                }
                if (guardsRelevant) {
                    predicateWork[next].role =
                        AuthorizationTrailPredicateRole::Secondary;
                    secondaryWorkIndices.insert(next);
                }
            }
        }
    }

    std::vector<size_t> rankedWork(predicateWork.size());
    for (size_t i = 0; i < rankedWork.size(); ++i) rankedWork[i] = i;
    std::sort(rankedWork.begin(), rankedWork.end(), strongerWorkPredicate);
    std::unordered_map<size_t, size_t> reportPredicateByWork;
    report.predicates.reserve(rankedWork.size());
    for (size_t workIndex : rankedWork) {
        reportPredicateByWork[workIndex] = report.predicates.size();
        report.predicates.push_back(std::move(predicateWork[workIndex]));
    }

    // A protected-operation location is not permission evidence by itself.
    // Preserve the exact retained guard identity and require its predicate to
    // have survived the complete-scope role classification.  Global carries
    // a direct/exact source link; Secondary is the equivalent transitive link
    // established by the complete branch-exclusive predicate relation walk.
    auto hasAuthorizationLinkedPromotedGuardForOperation =
        [&](size_t operationIndex) {
            if (operationIndex >= report.operations.size()) return false;
            const AuthorizationTrailFeatureOperation& operation =
                report.operations[operationIndex];
            if (operation.kind !=
                    AuthorizationTrailOperationKind::ProtectedOperation ||
                !operation.complete)
                return false;
            for (const auto& [key, _] : guards) {
                if (key.operation != operationIndex) continue;
                const auto mapped = reportPredicateByWork.find(key.predicate);
                if (mapped == reportPredicateByWork.end() ||
                    mapped->second >= report.predicates.size())
                    continue;
                const AuthorizationTrailPredicate& predicate =
                    report.predicates[mapped->second];
                const bool linkedRole =
                    (predicate.role ==
                         AuthorizationTrailPredicateRole::Global &&
                     predicate.authorizationSourceLinked) ||
                    predicate.role ==
                        AuthorizationTrailPredicateRole::Secondary;
                if (linkedRole) return true;
            }
            return false;
        };

    // A secondary-only operation is an explicit warning: the top/global gate
    // does not by itself cover that operation. Duplicate guard/operation rows
    // have already been canonicalized above.
    if (globalWorkIndexValid) {
        std::set<size_t> globalOperations;
        for (size_t operation :
             report.predicates[reportPredicateByWork[globalWorkIndex]]
                 .guardedOperationIndices) {
            if (operation < report.operations.size() &&
                operationRelevant(report.operations[operation].kind))
                globalOperations.insert(operation);
        }
        std::set<size_t> uncoveredOperations;
        std::set<size_t> warningSecondaries;
        for (size_t secondaryWork : secondaryWorkIndices) {
            const size_t reportPredicate = reportPredicateByWork[secondaryWork];
            for (size_t operation :
                 report.predicates[reportPredicate].guardedOperationIndices) {
                if (operation >= report.operations.size() ||
                    !operationRelevant(report.operations[operation].kind) ||
                    globalOperations.count(operation))
                    continue;
                uncoveredOperations.insert(operation);
                warningSecondaries.insert(reportPredicate);
            }
        }
        if (!uncoveredOperations.empty()) {
            if (warningLimit == 0) {
                complete.warningsTruncated = true;
                appendReason(complete.reason,
                             "authorization warning limit reached");
            } else {
                AuthorizationTrailWarning warning;
                warning.globalPredicateIndex =
                    reportPredicateByWork[globalWorkIndex];
                warning.globalPredicateIndexValid = true;
                warning.secondaryPredicateIndices.assign(
                    warningSecondaries.begin(), warningSecondaries.end());
                warning.operationIndices.assign(uncoveredOperations.begin(),
                                                uncoveredOperations.end());
                warning.text = "The top/global predicate " +
                    locationText(
                        report.predicates[warning.globalPredicateIndex].function) +
                    " does not cover " +
                    std::to_string(warning.operationIndices.size()) +
                    " operation(s) guarded by downstream secondary predicate(s); its result alone is insufficient for every observed feature path.";
                report.warnings.push_back(std::move(warning));
            }
        }
    }

    // ---- Ordered authorization evidence inventory ---------------------------
    // Stage order is presentation order only. No predecessor/edge identity is
    // inferred between independently supplied or synthesized stage rows.
    const size_t stageScan = (std::min)(input.stageEvidence.size(),
                                        kHardStageEvidence);
    if (stageScan != input.stageEvidence.size()) {
        complete.stagesTruncated = true;
        complete.stageEvidenceComplete = false;
        appendReason(complete.reason, "stage-evidence hard scan cap reached");
    }
    std::vector<AuthorizationTrailStage> stages;
    stages.reserve(stageScan + report.predicates.size() + report.operations.size());
    for (size_t i = 0; i < stageScan; ++i) {
        if ((i & 0x3ffu) == 0 && stopped(input)) {
            cancelReport(report);
            return report;
        }
        const auto& source = input.stageEvidence[i];
        if (source.stage >= AuthorizationTrailStageKind::Count) {
            complete.stageEvidenceComplete = false;
            continue;
        }
        AuthorizationTrailStage stage;
        stage.inputIndex = i;
        stage.inputIndexValid = true;
        stage.stage = source.stage;
        stage.kind = source.kind;
        stage.level = stageEvidenceLevel(source);
        stage.location = source.location;
        stage.label = source.label;
        stage.evidence = source.evidence;
        stage.orderWithinStage = source.orderWithinStage;
        stage.confidence = confidence(source.confidence);
        stage.complete = source.complete;
        stage.honestyLabel = stageHonesty(stage);
        if (!stage.complete) complete.stageEvidenceComplete = false;
        stages.push_back(std::move(stage));
    }
    for (size_t i = 0; i < report.predicates.size(); ++i) {
        const AuthorizationTrailPredicate& predicate = report.predicates[i];
        if (predicate.role == AuthorizationTrailPredicateRole::Candidate) continue;
        AuthorizationTrailStage stage;
        stage.stage = predicate.role == AuthorizationTrailPredicateRole::Global
            ? AuthorizationTrailStageKind::GlobalPredicate
            : AuthorizationTrailStageKind::FeaturePredicate;
        stage.kind = AuthorizationTrailEvidenceKind::PredicateControl;
        stage.level = AuthorizationTrailEvidenceLevel::Supported;
        stage.location = predicate.function;
        stage.label = locationText(predicate.function);
        stage.evidence = predicate.evidence;
        stage.orderWithinStage = static_cast<uint32_t>((std::min)(
            i, static_cast<size_t>((std::numeric_limits<uint32_t>::max)())));
        stage.confidence = predicate.rankScore;
        stage.complete = predicate.complete && predicate.returnAnalysisComplete;
        stage.honestyLabel = predicate.honestyLabel;
        stages.push_back(std::move(stage));
    }
    for (size_t i = 0; i < report.operations.size(); ++i) {
        const AuthorizationTrailFeatureOperation& operation = report.operations[i];
        if (!operationRelevant(operation.kind)) continue;
        AuthorizationTrailStage stage;
        stage.stage = AuthorizationTrailStageKind::ProtectedOperation;
        stage.kind = AuthorizationTrailEvidenceKind::FeatureControl;
        const bool authorizationGuarded =
            hasAuthorizationLinkedPromotedGuardForOperation(i);
        stage.level = authorizationGuarded
            ? AuthorizationTrailEvidenceLevel::Supported
            : AuthorizationTrailEvidenceLevel::Candidate;
        stage.location = operation.location;
        stage.label = operation.feature;
        stage.evidence = operation.evidence;
        stage.orderWithinStage = static_cast<uint32_t>((std::min)(
            i, static_cast<size_t>((std::numeric_limits<uint32_t>::max)())));
        stage.confidence = operation.confidence;
        stage.complete = operation.complete;
        if (!operation.complete) {
            stage.honestyLabel = "The operation evidence is partial.";
        } else if (authorizationGuarded) {
            stage.honestyLabel =
                "An authorization-linked Global/Secondary predicate has an exact branch-exclusive guard over this static protected operation; execution and runtime permission were not observed.";
        } else {
            stage.honestyLabel =
                "The operation location is static evidence, but no authorization-linked promoted predicate guard connects it; execution and permission were not observed.";
        }
        stages.push_back(std::move(stage));
    }
    auto stageLess = [](const AuthorizationTrailStage& left,
                        const AuthorizationTrailStage& right) {
        if (left.stage != right.stage)
            return static_cast<uint8_t>(left.stage) <
                   static_cast<uint8_t>(right.stage);
        if (left.orderWithinStage != right.orderWithinStage)
            return left.orderWithinStage < right.orderWithinStage;
        if (locationLess(left.location, right.location)) return true;
        if (locationLess(right.location, left.location)) return false;
        if (left.kind != right.kind)
            return static_cast<uint8_t>(left.kind) <
                   static_cast<uint8_t>(right.kind);
        if (left.label != right.label) return left.label < right.label;
        return left.evidence < right.evidence;
    };
    auto sameStage = [](const AuthorizationTrailStage& left,
                        const AuthorizationTrailStage& right) {
        return left.stage == right.stage && left.kind == right.kind &&
               locationEquivalent(left.location, right.location) &&
               left.label == right.label && left.evidence == right.evidence;
    };
    std::sort(stages.begin(), stages.end(), stageLess);
    stages.erase(std::unique(stages.begin(), stages.end(), sameStage),
                 stages.end());
    if (stages.size() > stageLimit) {
        stages.resize(stageLimit);
        complete.stagesTruncated = true;
        complete.stageEvidenceComplete = false;
        appendReason(complete.reason, "stage-evidence limit reached");
    }
    report.stages = std::move(stages);

    // ---- Independent, honesty-filtered conclusions ---------------------------
    const size_t conclusionScan = (std::min)(
        input.conclusionEvidence.size(), kHardConclusionEvidence);
    if (conclusionScan != input.conclusionEvidence.size()) {
        complete.conclusionsTruncated = true;
        complete.conclusionEvidenceComplete = false;
        appendReason(complete.reason, "conclusion-evidence hard scan cap reached");
    }
    std::vector<size_t> conclusionOrder(conclusionScan);
    for (size_t i = 0; i < conclusionScan; ++i) conclusionOrder[i] = i;
    std::sort(conclusionOrder.begin(), conclusionOrder.end(),
              [&](size_t left, size_t right) {
                  const auto& a = input.conclusionEvidence[left];
                  const auto& b = input.conclusionEvidence[right];
                  if (a.conclusion != b.conclusion)
                      return static_cast<uint8_t>(a.conclusion) <
                             static_cast<uint8_t>(b.conclusion);
                  if (a.kind != b.kind)
                      return static_cast<uint8_t>(a.kind) <
                             static_cast<uint8_t>(b.kind);
                  if (locationLess(a.location, b.location)) return true;
                  if (locationLess(b.location, a.location)) return false;
                  if (a.evidence != b.evidence) return a.evidence < b.evidence;
                  return left < right;
              });
    if (conclusionOrder.size() > conclusionLimit) {
        conclusionOrder.resize(conclusionLimit);
        complete.conclusionsTruncated = true;
        complete.conclusionEvidenceComplete = false;
        appendReason(complete.reason, "conclusion-evidence limit reached");
    }

    // Determine the completeness gate before evaluating any negative-search
    // evidence. An incomplete row anywhere in the retained conclusion scope
    // must suppress absence claims even when the negative row itself is whole.
    for (size_t inputIndex : conclusionOrder)
        if (!input.conclusionEvidence[inputIndex].complete)
            complete.conclusionEvidenceComplete = false;
    const bool negativeCoreComplete = coreScopeComplete(complete);
    auto hasProvenProtectedOperationGuardAt =
        [&](const AuthorizationLocation& location) {
            for (const auto& [key, _] : guards) {
                if (key.operation >= report.operations.size()) continue;
                const auto& operation = report.operations[key.operation];
                if (operation.kind ==
                        AuthorizationTrailOperationKind::ProtectedOperation &&
                    operation.complete &&
                    locationEquivalent(location, operation.location) &&
                    hasAuthorizationLinkedPromotedGuardForOperation(
                        key.operation))
                    return true;
            }
            return false;
        };
    report.conclusions.reserve(static_cast<size_t>(
        AuthorizationTrailConclusionKind::Count));
    for (uint8_t rawKind = 0;
         rawKind < static_cast<uint8_t>(AuthorizationTrailConclusionKind::Count);
         ++rawKind) {
        const auto kind = static_cast<AuthorizationTrailConclusionKind>(rawKind);
        AuthorizationTrailConclusion conclusion;
        conclusion.kind = kind;
        bool sawCompleteNegative = false;
        for (size_t inputIndex : conclusionOrder) {
            const auto& source = input.conclusionEvidence[inputIndex];
            if (source.conclusion != kind) continue;
            AuthorizationTrailConclusionEvidence evidence;
            evidence.inputIndex = inputIndex;
            evidence.kind = source.kind;
            evidence.location = source.location;
            evidence.evidence = source.evidence;
            evidence.confidence = confidence(source.confidence);
            evidence.complete = source.complete;
            conclusion.evidence.push_back(std::move(evidence));
            if (!source.complete) complete.conclusionEvidenceComplete = false;

            AuthorizationTrailConclusionStatus status =
                positiveConclusionStatus(
                    kind, source.kind, source.complete,
                    kind == AuthorizationTrailConclusionKind::FeaturePermitted &&
                        source.kind ==
                            AuthorizationTrailEvidenceKind::FeatureControl &&
                        hasProvenProtectedOperationGuardAt(source.location));
            const bool keyNegative =
                kind == AuthorizationTrailConclusionKind::EmbeddedExpectedKey &&
                source.kind ==
                    AuthorizationTrailEvidenceKind::ExpectedKeySearchNegative;
            const bool privateNegative =
                kind ==
                    AuthorizationTrailConclusionKind::PrivateSigningMaterial &&
                source.kind ==
                    AuthorizationTrailEvidenceKind::PrivateMaterialSearchNegative;
            if (keyNegative)
                sawCompleteNegative |= source.complete && negativeCoreComplete &&
                    complete.expectedKeySearchComplete;
            if (privateNegative)
                sawCompleteNegative |= source.complete && negativeCoreComplete &&
                    complete.privateMaterialSearchComplete;
            if (conclusionStatusRank(status) >
                conclusionStatusRank(conclusion.status)) {
                conclusion.status = status;
                conclusion.confidence = confidence(source.confidence);
            } else if (status == conclusion.status) {
                conclusion.confidence = (std::max)(
                    conclusion.confidence, confidence(source.confidence));
            }
        }
        if (conclusion.status == AuthorizationTrailConclusionStatus::Unknown &&
            sawCompleteNegative)
            conclusion.status =
                AuthorizationTrailConclusionStatus::NotFoundInCompleteScope;
        conclusion.honestyLabel = conclusionHonesty(kind, conclusion.status);
        report.conclusions.push_back(std::move(conclusion));
    }

    complete.complete = coreScopeComplete(complete);
    if (!complete.stringAnchorsComplete)
        appendReason(complete.reason, "string-to-decision anchors incomplete");
    if (!complete.predicateCandidatesComplete)
        appendReason(complete.reason, "predicate candidates incomplete");
    if (!complete.predicateUsesComplete)
        appendReason(complete.reason, "predicate uses incomplete");
    if (!complete.fieldAccessesComplete)
        appendReason(complete.reason, "field accesses incomplete");
    if (!complete.predicateRelationsComplete)
        appendReason(complete.reason, "predicate relations incomplete");
    if (!complete.operationsComplete)
        appendReason(complete.reason, "feature operations incomplete");
    if (!complete.operationGuardsComplete)
        appendReason(complete.reason, "operation guards incomplete");
    if (!complete.stageEvidenceComplete)
        appendReason(complete.reason, "stage evidence incomplete");
    if (!complete.conclusionEvidenceComplete)
        appendReason(complete.reason, "conclusion evidence incomplete");
    return report;
}

} // namespace ds
