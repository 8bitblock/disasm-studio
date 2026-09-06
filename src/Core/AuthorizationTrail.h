#pragma once
//
// AuthorizationTrail.h
// Pure, bounded assembly of ranked authorization predicates and the evidence
// which connects input handling to feature operations. Decoder-facing code is
// expected to supply typed facts; this layer never decodes or executes a target.
//

#include "AuthorizationAnalysis.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

enum class AuthorizationTrailPredicateRole : uint8_t {
    Candidate = 0,
    Global,
    Secondary,
};

enum class AuthorizationTrailBooleanContract : uint8_t {
    Unknown = 0,
    CanonicalZeroOrOne,
    ZeroIsTrue,
    NonzeroIsTrue,
    OneIsTrue,
};

enum class AuthorizationTrailUseKind : uint8_t {
    Unknown = 0,
    Ignored,
    Compared,
    Branched,
    Stored,
    Returned,
};

// The enum order is conceptual presentation order for independently evidenced
// authorization stages; it does not assert predecessor edges between rows.
enum class AuthorizationTrailStageKind : uint8_t {
    Input = 0,
    FormatValidation,
    RemoteRequest,
    EntitlementParsing,
    CryptoVerification,
    StatePersistence,
    GlobalPredicate,
    FeaturePredicate,
    ProtectedOperation,
    Count,
};

enum class AuthorizationTrailEvidenceKind : uint8_t {
    Generic = 0,
    InputRead,
    FormatConstraint,
    TransportOperation,
    TransportSuccess,
    ReplyContentAcceptance,
    EntitlementParse,
    CryptoPrimitivePresence,
    SignatureVerificationResult,
    PersistentState,
    PredicateControl,
    FeatureControl,
    MachineIdentityCapability,
    MachineIdentityFlow,
    ExpectedKeyLiteral,
    ExpectedKeySearchNegative,
    PrivateSigningMaterial,
    PrivateMaterialSearchNegative,
};

enum class AuthorizationTrailEvidenceLevel : uint8_t {
    Unknown = 0,
    Candidate,
    Supported,
};

enum class AuthorizationTrailConclusionKind : uint8_t {
    LocalFormatValid = 0,
    ServerAccepted,
    SignatureVerified,
    FeaturePermitted,
    MachineBound,
    EmbeddedExpectedKey,
    PrivateSigningMaterial,
    Count,
};

enum class AuthorizationTrailConclusionStatus : uint8_t {
    Unknown = 0,
    Candidate,
    Supported,
    NotFoundInCompleteScope,
};

enum class AuthorizationTrailFieldBaseKind : uint8_t {
    Unknown = 0,
    GlobalAddress,
    RootParameter,
    StackObject,
};

enum class AuthorizationTrailFieldAccessKind : uint8_t {
    Read = 0,
    Write,
};

enum class AuthorizationTrailOperationKind : uint8_t {
    Unknown = 0,
    BrandingOrCosmetic,
    UserInterface,
    FeatureAction,
    ProtectedOperation,
};

enum class AuthorizationTrailWarningKind : uint8_t {
    SecondaryGateRequired = 0,
};

// A string anchor is one retained literal occurrence, not merely one normalized
// value.  Keeping endpoint, route, and authorization artifacts distinct lets a
// repeated literal at different file/VA coordinates retain every whole-image
// xref without pretending that proximity to a branch proves data dependence.
enum class AuthorizationTrailStringAnchorKind : uint8_t {
    Endpoint = 0,
    Route,
    LicenseArtifact,
    ValidationArtifact,
    AuthenticationArtifact,
    SuccessArtifact,
    FailureArtifact,
    ReplyMarkerArtifact,
};

const char* AuthorizationTrailPredicateRoleText(
    AuthorizationTrailPredicateRole role);
const char* AuthorizationTrailStageKindText(AuthorizationTrailStageKind kind);
const char* AuthorizationTrailConclusionKindText(
    AuthorizationTrailConclusionKind kind);
const char* AuthorizationTrailConclusionStatusText(
    AuthorizationTrailConclusionStatus status);
const char* AuthorizationTrailStringAnchorKindText(
    AuthorizationTrailStringAnchorKind kind);

struct AuthorizationTrailStringReferenceInput {
    // Exact referencing instruction and its exact owning function when the
    // bounded ownership model can prove one.
    AuthorizationLocation reference;
    AuthorizationLocation containingFunction;

    // The closest conditional branch in a bounded code-order window.  This is
    // intentionally a navigation lead only; nearbyByCodeOrder never means the
    // string value reaches the comparison/branch flags.
    AuthorizationLocation nearbyBranch;
    uint32_t instructionDistance = 0;
    bool nearbyBranchAfterReference = false;
    bool nearbyByCodeOrder = false;
    bool containingFunctionExact = false;
    bool branchSearchComplete = true;
    std::string evidence;
};

struct AuthorizationTrailStringAnchorInput {
    AuthorizationTrailStringAnchorKind kind =
        AuthorizationTrailStringAnchorKind::Endpoint;
    std::string label;
    std::string literal;
    AuthorizationLocation source;
    std::vector<AuthorizationTrailStringReferenceInput> references;
    bool xrefScopeComplete = true;
    bool referencesTruncated = false;
    bool complete = true;
    std::string evidence;
};

struct AuthorizationTrailPredicateCandidateInput {
    AuthorizationLocation function;
    AuthorizationTrailBooleanContract returnContract =
        AuthorizationTrailBooleanContract::Unknown;
    bool returnAnalysisComplete = true;
    bool sideEffectLight = false;

    // True only for an adapter-proven link from an authorization source. A
    // semantic name such as IsPro is not sufficient on its own.
    bool authorizationSourceLinked = false;
    bool complete = true;
    float confidence = 0.0f;
    std::string evidence;
};

struct AuthorizationTrailPredicateUseInput {
    size_t predicateIndex = 0; // index in predicateCandidates
    bool predicateIndexValid = false;
    AuthorizationLocation callsite;
    // Exact instruction immediately after callsite when the adapter decoded
    // the call length. This is the safe temporary-breakpoint location for a
    // register-only live return experiment.
    AuthorizationLocation continuation;
    AuthorizationLocation caller;
    AuthorizationLocation comparison;
    AuthorizationLocation branch;
    AuthorizationLocation trueDestination;
    AuthorizationLocation falseDestination;
    AuthorizationTrailUseKind useKind = AuthorizationTrailUseKind::Unknown;
    uint8_t resultWidthBits = 0; // normally 8, 32, or 64
    bool flagsPreserved = false;
    bool branchUseProven = false;
    bool complete = true;
    float confidence = 0.0f;
    std::string evidence;
};

// An exact field identity is rooted in one stable object identity. For a
// GlobalAddress rootAddress is the exact global/static base. For RootParameter
// it is the root function and rootOrdinal is the zero-based parameter. For a
// StackObject it is the owning function and rootOrdinal is an adapter-stable
// stack-object id. displacement and width are always part of the identity.
struct AuthorizationTrailFieldIdentity {
    AuthorizationTrailFieldBaseKind base =
        AuthorizationTrailFieldBaseKind::Unknown;
    uint64_t rootAddress = 0;
    bool rootAddressValid = false;
    uint32_t rootOrdinal = 0;
    bool rootOrdinalValid = false;
    int64_t displacement = 0;
    uint16_t widthBits = 0;
    bool exact = false;
    std::string display;
};

bool AuthorizationTrailFieldIdentityEquivalentExact(
    const AuthorizationTrailFieldIdentity& left,
    const AuthorizationTrailFieldIdentity& right) noexcept;

struct AuthorizationTrailFieldAccessInput {
    AuthorizationTrailFieldIdentity field;
    AuthorizationTrailFieldAccessKind access =
        AuthorizationTrailFieldAccessKind::Read;
    AuthorizationLocation location;

    // A read can identify the predicate whose returned boolean it contributes
    // to. For a write, authorizationDerived proves only the value arriving at
    // that store. An ordered store -> predicate-read proof additionally names
    // both its exact read access and exact predicate. These validity-bearing
    // input indices prevent one proved reader from source-linking every other
    // predicate that happens to read the same field slice. There is at most one
    // retained edge per write, so edge count remains bounded by the existing
    // field-access cap.
    size_t predicateIndex = 0;
    bool predicateIndexValid = false;
    bool authorizationDerived = false;
    size_t reachedReadAccessInputIndex = 0;
    bool reachedReadAccessInputIndexValid = false;
    size_t reachedPredicateInputIndex = 0;
    bool reachedPredicateInputIndexValid = false;
    bool contributesToPredicateReturn = false;
    std::vector<ValueProvenanceHop> provenance;
    bool complete = true;
    std::string evidence;
};

struct AuthorizationTrailPredicateRelationInput {
    size_t upstreamPredicateIndex = 0;
    bool upstreamPredicateIndexValid = false;
    size_t downstreamPredicateIndex = 0;
    bool downstreamPredicateIndexValid = false;
    AuthorizationLocation location;

    // All three must be true before this can classify a secondary gate.
    bool branchExclusive = false;
    bool onPermittedPath = false;
    bool downstreamResultRequired = false;
    bool complete = true;
    std::string evidence;
};

struct AuthorizationTrailFeatureOperationInput {
    AuthorizationLocation location;
    AuthorizationTrailOperationKind kind =
        AuthorizationTrailOperationKind::Unknown;
    std::string feature;
    std::string evidence;
    float confidence = 0.0f;
    bool complete = true;
};

struct AuthorizationTrailOperationGuardInput {
    size_t predicateIndex = 0;
    bool predicateIndexValid = false;
    size_t operationIndex = 0;
    bool operationIndexValid = false;
    AuthorizationLocation location;
    bool branchExclusive = false;
    bool permitsOperation = false;
    bool complete = true;
    std::string evidence;
};

struct AuthorizationTrailStageEvidenceInput {
    AuthorizationTrailStageKind stage = AuthorizationTrailStageKind::Input;
    AuthorizationTrailEvidenceKind kind =
        AuthorizationTrailEvidenceKind::Generic;
    AuthorizationLocation location;
    std::string label;
    std::string evidence;
    uint32_t orderWithinStage = 0;
    float confidence = 0.0f;
    bool complete = true;
};

struct AuthorizationTrailConclusionEvidenceInput {
    AuthorizationTrailConclusionKind conclusion =
        AuthorizationTrailConclusionKind::LocalFormatValid;
    AuthorizationTrailEvidenceKind kind =
        AuthorizationTrailEvidenceKind::Generic;
    AuthorizationLocation location;
    std::string evidence;
    float confidence = 0.0f;

    // Required for a negative-search conclusion in addition to the matching
    // global search-scope completeness bit below.
    bool complete = true;
};

struct AuthorizationTrailInputCompleteness {
    bool stringAnchorsComplete = true;
    bool predicateCandidatesComplete = true;
    bool predicateUsesComplete = true;
    bool fieldAccessesComplete = true;
    bool predicateRelationsComplete = true;
    bool operationsComplete = true;
    bool operationGuardsComplete = true;
    bool stageEvidenceComplete = true;
    bool conclusionEvidenceComplete = true;

    // Negative claims fail closed and require explicit complete-scope proof.
    // The adapter defines each supplied search scope: in particular,
    // privateMaterialSearchComplete proves completeness of its marker search,
    // not the absence of every possible private-key representation. These
    // optional scopes do not make the rest of the report incomplete.
    bool expectedKeySearchComplete = false;
    bool privateMaterialSearchComplete = false;
};

struct AuthorizationTrailLimits {
    size_t maxStringAnchors = 4096;
    size_t maxStringReferences = 32768;
    size_t maxStringReferencesPerAnchor = 4096;
    size_t maxPredicateCandidates = 512;
    size_t maxPredicateUses = 16384;
    size_t maxFieldAccesses = 4096;
    size_t maxFieldLineages = 2048;
    size_t maxPredicateRelations = 4096;
    size_t maxOperations = 4096;
    size_t maxOperationGuards = 8192;
    size_t maxStageEvidence = 4096;
    size_t maxConclusionEvidence = 4096;
    size_t maxConsumersPerPredicate = 4096;
    size_t maxProvenanceHopsPerAccess = 32;
    size_t maxWarnings = 64;
};

struct AuthorizationTrailInput {
    std::vector<AuthorizationTrailStringAnchorInput> stringAnchors;
    std::vector<AuthorizationTrailPredicateCandidateInput> predicateCandidates;
    std::vector<AuthorizationTrailPredicateUseInput> predicateUses;
    std::vector<AuthorizationTrailFieldAccessInput> fieldAccesses;
    std::vector<AuthorizationTrailPredicateRelationInput> predicateRelations;
    std::vector<AuthorizationTrailFeatureOperationInput> operations;
    std::vector<AuthorizationTrailOperationGuardInput> operationGuards;
    std::vector<AuthorizationTrailStageEvidenceInput> stageEvidence;
    std::vector<AuthorizationTrailConclusionEvidenceInput> conclusionEvidence;
    AuthorizationTrailInputCompleteness completeness;
    AuthorizationTrailLimits limits;
    std::function<bool()> cancelled;
};

struct AuthorizationTrailStringReference {
    AuthorizationLocation reference;
    AuthorizationLocation containingFunction;
    AuthorizationLocation nearbyBranch;
    uint32_t instructionDistance = 0;
    bool nearbyBranchAfterReference = false;
    bool nearbyByCodeOrder = false;
    bool containingFunctionExact = false;
    bool branchSearchComplete = true;
    std::string evidence;
};

struct AuthorizationTrailStringAnchor {
    size_t inputIndex = 0;
    AuthorizationTrailStringAnchorKind kind =
        AuthorizationTrailStringAnchorKind::Endpoint;
    std::string label;
    std::string literal;
    AuthorizationLocation source;
    std::vector<AuthorizationTrailStringReference> references;
    bool xrefScopeComplete = true;
    bool referencesTruncated = false;
    bool complete = true;
    std::string evidence;
};

struct AuthorizationTrailPredicateUse {
    size_t inputIndex = 0;
    size_t predicateInputIndex = 0;
    AuthorizationLocation callsite;
    AuthorizationLocation continuation;
    AuthorizationLocation caller;
    AuthorizationLocation comparison;
    AuthorizationLocation branch;
    AuthorizationLocation trueDestination;
    AuthorizationLocation falseDestination;
    AuthorizationTrailUseKind useKind = AuthorizationTrailUseKind::Unknown;
    uint8_t resultWidthBits = 0;
    bool flagsPreserved = false;
    bool branchUseProven = false;
    bool complete = true;
    float confidence = 0.0f;
    std::string evidence;
};

struct AuthorizationTrailFeatureOperation {
    size_t inputIndex = 0;
    AuthorizationLocation location;
    AuthorizationTrailOperationKind kind =
        AuthorizationTrailOperationKind::Unknown;
    std::string feature;
    std::string evidence;
    float confidence = 0.0f;
    bool complete = true;
};

struct AuthorizationTrailFieldAccess {
    size_t inputIndex = 0;
    AuthorizationTrailFieldAccessKind access =
        AuthorizationTrailFieldAccessKind::Read;
    AuthorizationLocation location;
    size_t predicateInputIndex = 0;
    bool predicateInputIndexValid = false;
    bool authorizationDerived = false;
    // These output references are valid only after the pure builder has
    // verified the exact same-field, complete, contributing read edge.
    size_t reachedReadAccessInputIndex = 0;
    bool reachedReadAccessInputIndexValid = false;
    size_t reachedPredicateInputIndex = 0;
    bool reachedPredicateInputIndexValid = false;
    bool contributesToPredicateReturn = false;
    std::vector<ValueProvenanceHop> provenance;
    bool complete = true;
    std::string evidence;
};

struct AuthorizationTrailFieldLineage {
    AuthorizationTrailFieldIdentity field;
    std::vector<AuthorizationTrailFieldAccess> writes;
    std::vector<AuthorizationTrailFieldAccess> reads;
    // All predicates with contributing reads remain visible. Only this second
    // list has an exact authorization-derived store -> read proof.
    std::vector<size_t> predicateInputIndices;
    std::vector<size_t> sourceLinkedPredicateInputIndices;
    bool authorizationSourceLinked = false;
    bool complete = true;
    std::string honestyLabel;
};

struct AuthorizationTrailPredicate {
    size_t inputIndex = 0;
    AuthorizationLocation function;
    AuthorizationTrailBooleanContract returnContract =
        AuthorizationTrailBooleanContract::Unknown;
    AuthorizationTrailPredicateRole role =
        AuthorizationTrailPredicateRole::Candidate;
    bool returnAnalysisComplete = true;
    bool authorizationSourceLinked = false;
    bool sideEffectLight = false;

    size_t callsiteCount = 0;
    size_t uniqueCallerCount = 0;
    size_t branchConsumerCount = 0;
    size_t uniqueBranchCallerCount = 0;
    size_t guardedOperationCount = 0;
    std::vector<size_t> useIndices; // indices in report.predicateUses
    std::vector<size_t> guardedOperationIndices; // indices in report.operations
    std::vector<size_t> fieldLineageIndices; // indices in report.fieldLineages

    float confidence = 0.0f;
    float rankScore = 0.0f;
    bool complete = true;
    std::string evidence;
    std::string honestyLabel;
};

struct AuthorizationTrailStage {
    size_t inputIndex = 0;
    bool inputIndexValid = false; // false for a synthesized predicate/operation stage
    AuthorizationTrailStageKind stage = AuthorizationTrailStageKind::Input;
    AuthorizationTrailEvidenceKind kind =
        AuthorizationTrailEvidenceKind::Generic;
    AuthorizationTrailEvidenceLevel level =
        AuthorizationTrailEvidenceLevel::Unknown;
    AuthorizationLocation location;
    std::string label;
    std::string evidence;
    std::string honestyLabel;
    uint32_t orderWithinStage = 0;
    float confidence = 0.0f;
    bool complete = true;
};

struct AuthorizationTrailConclusionEvidence {
    size_t inputIndex = 0;
    AuthorizationTrailEvidenceKind kind =
        AuthorizationTrailEvidenceKind::Generic;
    AuthorizationLocation location;
    std::string evidence;
    float confidence = 0.0f;
    bool complete = true;
};

struct AuthorizationTrailConclusion {
    AuthorizationTrailConclusionKind kind =
        AuthorizationTrailConclusionKind::LocalFormatValid;
    AuthorizationTrailConclusionStatus status =
        AuthorizationTrailConclusionStatus::Unknown;
    std::vector<AuthorizationTrailConclusionEvidence> evidence;
    float confidence = 0.0f;
    std::string honestyLabel;
};

struct AuthorizationTrailWarning {
    AuthorizationTrailWarningKind kind =
        AuthorizationTrailWarningKind::SecondaryGateRequired;
    size_t globalPredicateIndex = 0; // index in report.predicates
    bool globalPredicateIndexValid = false;
    std::vector<size_t> secondaryPredicateIndices; // report.predicates
    std::vector<size_t> operationIndices; // report.operations
    std::string text;
};

struct AuthorizationTrailCompleteness {
    bool complete = true;
    bool cancelled = false;
    bool stringAnchorsComplete = true;
    bool predicateCandidatesComplete = true;
    bool predicateUsesComplete = true;
    bool fieldAccessesComplete = true;
    bool predicateRelationsComplete = true;
    bool operationsComplete = true;
    bool operationGuardsComplete = true;
    bool stageEvidenceComplete = true;
    bool conclusionEvidenceComplete = true;
    bool expectedKeySearchComplete = false;
    bool privateMaterialSearchComplete = false;

    bool predicatesTruncated = false;
    bool stringAnchorsTruncated = false;
    bool stringReferencesTruncated = false;
    bool usesTruncated = false;
    bool fieldAccessesTruncated = false;
    bool fieldLineagesTruncated = false;
    bool relationsTruncated = false;
    bool operationsTruncated = false;
    bool operationGuardsTruncated = false;
    bool stagesTruncated = false;
    bool conclusionsTruncated = false;
    bool warningsTruncated = false;
    bool consumersTruncated = false;
    bool provenanceTruncated = false;
    bool invalidReferences = false;

    size_t unlinkedFieldAccessCount = 0;
    size_t unownedStringReferenceCount = 0;
    size_t incompleteStringBranchSearchCount = 0;
    size_t rejectedReferenceCount = 0;
    std::string reason;
};

struct AuthorizationTrailReport {
    std::vector<AuthorizationTrailStringAnchor> stringAnchors;
    std::vector<AuthorizationTrailPredicateUse> predicateUses;
    std::vector<AuthorizationTrailFeatureOperation> operations;
    std::vector<AuthorizationTrailFieldLineage> fieldLineages;
    std::vector<AuthorizationTrailPredicate> predicates; // rank order
    std::vector<AuthorizationTrailStage> stages; // semantic stage order
    std::vector<AuthorizationTrailConclusion> conclusions; // enum order
    std::vector<AuthorizationTrailWarning> warnings;
    AuthorizationTrailCompleteness completeness;
};

AuthorizationTrailReport RunAuthorizationTrail(
    const AuthorizationTrailInput& input);

} // namespace ds
