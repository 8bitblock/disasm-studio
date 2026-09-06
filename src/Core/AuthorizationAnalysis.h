#pragma once
//
// AuthorizationAnalysis.h
// Pure, bounded correlation of network-reply or local-input validation,
// durable state, and startup gates. Inputs are typed observations produced by
// decoder-facing adapters; this layer never executes a target and never
// promotes API success to product authorization.
//

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

enum class AuthorizationOutcome : uint8_t {
    Unknown = 0,
    LikelyAllow,
    LikelyDeny,
};

enum class AuthorizationStage : uint8_t {
    ReplyCheck = 0,
    AllowPath,
    DenyPath,
    StateWrite,
    StartupRead,
    StartupGate,
    InputRead,
    Compare,
};

enum class PersistentStateKind : uint8_t {
    Unknown = 0,
    Registry,
    File,
    Ini,
    Credential,
    DpapiTransform,
};

enum class PersistentStateAccess : uint8_t {
    Unknown = 0,
    Open,
    Read,
    Write,
    Protect,
    Unprotect,
};

enum class AuthorizationBranch : uint8_t {
    Unknown = 0,
    Taken,
    Fallthrough,
};

// Ordered, bounded provenance shared by network-status, local-input, and
// authorization value-flow reports. Every hop names the exact static
// instruction and owning function when available; callers must consult the
// enclosing completeness flag before treating the last retained hop as the
// end of the flow.
enum class ValueProvenanceHopKind : uint8_t {
    Origin = 0,
    Copy,
    Store,
    Reload,
    PassArgument,
    EnterHelper,
    ReturnFromHelper,
    ReturnToCaller,
    Compare,
    Branch,
};

const char* ValueProvenanceHopKindText(ValueProvenanceHopKind kind);

struct ValueProvenanceHop {
    ValueProvenanceHopKind kind = ValueProvenanceHopKind::Origin;
    uint64_t address = 0;
    bool addressValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::string functionName;
    std::string instruction;
    std::string fromExpression;
    std::string toExpression;
    std::string evidence;
    float confidence = 0.0f;
};

enum class AuthorizationGateSource : uint8_t {
    Unknown = 0,
    ApiReturn,
    PersistentOutput,
    LocalInput,
};

enum class AuthorizationEntitlementKind : uint8_t {
    Unknown = 0,
    Pro,
    Validated,
    Licensed,
    Activated,
    Premium,
    BooleanTrue,
};

const char* AuthorizationGateSourceText(AuthorizationGateSource source);
const char* AuthorizationEntitlementKindText(AuthorizationEntitlementKind kind);

// Evidence kinds have an intentionally narrow meaning.  API success is absent:
// it can prove an operation completed, but not that the program granted access.
enum class AuthorizationEvidenceKind : uint8_t {
    Unknown = 0,
    ProcessTermination,
    EarlyFailureReturn,
    FailureIndicator,
    SuccessIndicator,
    ApplicationContinuation,
    PersistentStateWrite,
};

const char* AuthorizationOutcomeText(AuthorizationOutcome outcome);
const char* AuthorizationStageText(AuthorizationStage stage);
const char* PersistentStateKindText(PersistentStateKind kind);
const char* PersistentStateAccessText(PersistentStateAccess access);
const char* AuthorizationEvidenceKindText(AuthorizationEvidenceKind kind);

// Every coordinate keeps zero independent from validity.  functionAddress is
// the owning function when known and is the coordinate used for startup reach.
struct AuthorizationLocation {
    uint64_t address = 0;
    bool addressValid = false;
    uint64_t fileOffset = 0;
    bool fileOffsetValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::string functionName;
};

struct AuthorizationEvidence {
    AuthorizationEvidenceKind kind = AuthorizationEvidenceKind::Unknown;
    AuthorizationLocation location;
    std::string text;
    // Optional adapter confidence in [0,1]. Zero means use the kind's
    // conservative default rather than "no evidence".
    float strength = 0.0f;
};

struct AuthorizationPathInput {
    AuthorizationLocation entry;
    std::vector<AuthorizationEvidence> evidence;
    bool complete = true;
    std::string incompleteReason;
};

struct AuthorizationPath {
    AuthorizationLocation entry;
    AuthorizationOutcome outcome = AuthorizationOutcome::Unknown;
    std::vector<AuthorizationEvidence> evidence;
    float allowScore = 0.0f;
    float denyScore = 0.0f;
    bool complete = true;
    std::string honestyLabel;
};

// canonicalScope/canonicalKey/canonicalValue together are the comparison key.
// exact=false deliberately prevents correlation for relative/computed paths,
// unresolved handles, custom stores, and partially recovered identities.
struct PersistentStateIdentity {
    PersistentStateKind kind = PersistentStateKind::Unknown;
    std::string canonicalScope;
    std::string canonicalKey;
    std::string canonicalValue;
    std::string display;
    bool valid = false;
    bool exact = false;
};

bool PersistentStateIdentityEquivalentExact(const PersistentStateIdentity& left,
                                            const PersistentStateIdentity& right);

struct PersistentStateOperationInput {
    PersistentStateAccess access = PersistentStateAccess::Unknown;
    PersistentStateIdentity identity;
    AuthorizationLocation location;
    std::string apiDll;
    std::string apiName;
    std::string evidence;
    bool operationComplete = true;

    // Optional branch ownership supplied by the local CFG adapter.  It is used
    // only when the referenced decision and branch are retained.
    size_t controllingDecisionIndex = 0;
    bool controllingDecisionIndexValid = false;
    AuthorizationBranch controllingBranch = AuthorizationBranch::Unknown;

    // DPAPI is a transform around a store, not a durable identity by itself.
    // A backing read/write may point at the protect/unprotect operation here.
    size_t transformOperationIndex = 0;
    bool transformOperationIndexValid = false;

    // Exact adapter-recovered output value/buffer.  This is intentionally
    // independent from the API status return: a successful registry/file read
    // does not prove that its persisted entitlement value was accepted.
    uint32_t outputArgumentIndex = 0;
    bool outputArgumentIndexValid = false;
    std::string outputExpression;
};

struct PersistentStateOperation {
    PersistentStateAccess access = PersistentStateAccess::Unknown;
    PersistentStateIdentity identity;
    AuthorizationLocation location;
    std::string apiDll;
    std::string apiName;
    std::string evidence;
    bool operationComplete = true;
    bool startupReachable = false;
    size_t startupDepth = 0;
    bool startupDepthValid = false;
    size_t controllingDecisionIndex = 0;
    bool controllingDecisionIndexValid = false;
    AuthorizationBranch controllingBranch = AuthorizationBranch::Unknown;
    size_t transformOperationIndex = 0;
    bool transformOperationIndexValid = false;
    uint32_t outputArgumentIndex = 0;
    bool outputArgumentIndexValid = false;
    std::string outputExpression;
};

struct AuthorizationFunctionInput {
    uint64_t address = 0;
    bool addressValid = false;
    std::string name;
};

struct AuthorizationCallEdgeInput {
    uint64_t caller = 0;
    bool callerValid = false;
    uint64_t callee = 0;
    bool calleeValid = false;
};

struct AuthorizationDecisionInput {
    AuthorizationLocation location;
    std::string comparison;
    AuthorizationPathInput takenPath;
    AuthorizationPathInput fallthroughPath;

    // Exact NetworkReplyDecisionFlow index retained by the caller.  Its
    // presence labels this as a reply-content check, not merely an API status.
    size_t networkReplyFlowIndex = 0;
    bool networkReplyFlowIndexValid = false;

    // Exact operation index when this branch consumes a state-read result.
    size_t stateReadOperationIndex = 0;
    bool stateReadOperationIndexValid = false;

    // Exact local credential/input-buffer provenance. This is deliberately
    // separate from a network reply and from persisted state: ordinary
    // crackmes commonly read a password/serial from a console or edit control
    // and compare that buffer without touching either subsystem.
    bool localInputFlow = false;
    AuthorizationLocation inputLocation;
    AuthorizationLocation comparisonLocation;
    std::string inputEvidence;
    std::string evidence;

    AuthorizationGateSource gateSource = AuthorizationGateSource::Unknown;
    AuthorizationEntitlementKind entitlementKind =
        AuthorizationEntitlementKind::Unknown;
    std::string entitlementLabel;
    std::string originExpression;
    std::string expectedValue;
    std::vector<ValueProvenanceHop> provenance;
    bool provenanceComplete = true;
    std::string provenanceIncompleteReason;
};

struct AuthorizationStageRecord {
    AuthorizationStage stage = AuthorizationStage::ReplyCheck;
    AuthorizationLocation location;
    AuthorizationOutcome outcome = AuthorizationOutcome::Unknown;
    size_t operationIndex = 0;
    bool operationIndexValid = false;
    std::string evidence;
};

struct AuthorizationFlow {
    std::string id; // deterministic within one report: reply:N, startup:N, or local:N
    size_t decisionIndex = 0;
    bool decisionIndexValid = false;
    size_t networkReplyFlowIndex = 0;
    bool networkReplyFlowIndexValid = false;
    size_t stateReadOperationIndex = 0;
    bool stateReadOperationIndexValid = false;
    bool localInputFlow = false;
    AuthorizationLocation inputLocation;
    AuthorizationLocation comparisonLocation;
    AuthorizationLocation decisionLocation;
    AuthorizationPath takenPath;
    AuthorizationPath fallthroughPath;
    std::vector<AuthorizationStageRecord> stages;
    std::vector<size_t> linkedStateWriteIndices;
    std::vector<size_t> linkedStartupReadIndices;
    std::vector<size_t> linkedStartupFlowIndices;
    bool rememberedAccessLinked = false;
    float confidence = 0.0f;
    std::string honestyLabel;

    AuthorizationGateSource gateSource = AuthorizationGateSource::Unknown;
    AuthorizationEntitlementKind entitlementKind =
        AuthorizationEntitlementKind::Unknown;
    std::string entitlementLabel;
    std::string originExpression;
    std::string expectedValue;
    std::vector<ValueProvenanceHop> provenance;
    bool provenanceComplete = true;
    std::string provenanceIncompleteReason;
};

struct AuthorizationAnalysisLimits {
    size_t maxFunctions = 256;
    size_t maxStartupDepth = 8;
    size_t maxCallEdges = 4096;
    size_t maxDecisions = 1024;
    size_t maxOperations = 2048;
    size_t maxFlows = 1024;
    size_t maxEvidencePerPath = 64;
    size_t maxLinksPerFlow = 64;
    size_t maxProvenanceHopsPerFlow = 32;
};

struct AuthorizationAnalysisInput {
    std::vector<AuthorizationLocation> startupRoots; // PE entry + validated TLS callbacks
    std::vector<AuthorizationFunctionInput> functions;
    std::vector<AuthorizationCallEdgeInput> callEdges;
    std::vector<AuthorizationDecisionInput> decisions;
    std::vector<PersistentStateOperationInput> stateOperations;
    bool startupRootsComplete = true;
    bool functionsComplete = true;
    bool callEdgesComplete = true;
    bool decisionsComplete = true;
    bool stateOperationsComplete = true;
    AuthorizationAnalysisLimits limits;
    std::function<bool()> cancelled;
};

struct AuthorizationAnalysisCompleteness {
    bool complete = true;
    bool cancelled = false;
    bool startupRootsComplete = true;
    bool callGraphComplete = true;
    bool decisionsComplete = true;
    bool stateOperationsComplete = true;
    bool pathsComplete = true;
    bool functionsTruncated = false;
    bool startupDepthTruncated = false;
    bool callEdgesTruncated = false;
    bool decisionsTruncated = false;
    bool operationsTruncated = false;
    bool flowsTruncated = false;
    bool evidenceTruncated = false;
    bool linksTruncated = false;
    bool provenanceTruncated = false;
    size_t startupFunctionsVisited = 0;
    std::string reason;
};

struct AuthorizationAnalysisReport {
    std::vector<PersistentStateOperation> stateOperations;
    std::vector<AuthorizationFlow> flows;
    std::vector<size_t> unlinkedOperationIndices;
    AuthorizationAnalysisCompleteness completeness;
};

AuthorizationAnalysisReport RunAuthorizationAnalysis(
    const AuthorizationAnalysisInput& input);

} // namespace ds
