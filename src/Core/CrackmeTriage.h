#pragma once

#include "CodeByteSignature.h"
//
// CrackmeTriage.h
// Pure, bounded, offline discovery of likely crackme server trails.  The pass
// scans file bytes (including unmapped/overlay bytes), parses endpoint and route
// literals, classifies exact networking imports, and correlates their xrefs by
// owning function.  Correlation is explicitly not argument-flow or runtime proof.
//


#include "NetworkApiCatalog.h"
#include "AuthorizationAnalysis.h"
#include "AuthorizationPatchAdvisor.h"
#include "AuthorizationTrail.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

struct XrefIndex;

enum class CrackmeTriageConfidence : uint8_t { Low = 0, Medium, High };
enum class CrackmeEndpointKind : uint8_t { Domain = 0, IPv4, IPv6 };
enum class CrackmeEndpointScope : uint8_t {
    Unknown = 0,
    Loopback,
    PrivateNetwork,
    PublicNetwork,
};
enum class CrackmeLiteralEncoding : uint8_t { Ascii = 0, Utf16Le };
enum class CrackmeLiteralLocation : uint8_t { Mapped = 0, FileOnly, Overlay };
enum class CrackmeLiteralRole : uint8_t { Url = 0, Host, Route, Evidence };

// User-facing trail stages.  They are intentionally distinct from low-level API
// stages: DNS resolution contributes to Connect, socket/HTTP writes contribute
// to Request, reads contribute to Reply, and Decision requires validation-flow
// evidence rather than merely importing a receive API.
enum class NetworkTrailStage : uint8_t {
    Endpoint = 0,
    Connect,
    Request,
    Reply,
    Decision,
    Count,
};

enum class NetworkArtifactKind : uint8_t {
    Endpoint = 0,
    Route,
    Header,
    Authentication,
    License,
    Validation,
    Success,
    Failure,
    ReplyMarker,
    Algorithm,
};

// What the bounded function annotation pass observed the caller doing with a
// network API's ABI return register.  It describes local evidence only; copied
// values and output buffers are not claimed to be followed interprocedurally.
enum class NetworkReturnUseKind : uint8_t {
    Unknown = 0,
    Ignored,
    Compared,
    Branched,
    Stored,
    Propagated,
    Consumed,
    Returned,
};

const char* CrackmeTriageConfidenceText(CrackmeTriageConfidence confidence);
const char* CrackmeEndpointKindText(CrackmeEndpointKind kind);
const char* CrackmeEndpointScopeText(CrackmeEndpointScope scope);
const char* CrackmeLiteralLocationText(CrackmeLiteralLocation location);
const char* NetworkTrailStageText(NetworkTrailStage stage);
const char* NetworkArtifactKindText(NetworkArtifactKind kind);
inline const char* NetworkReturnUseKindText(NetworkReturnUseKind kind) {
    switch (kind) {
    case NetworkReturnUseKind::Unknown:    return "unknown";
    case NetworkReturnUseKind::Ignored:    return "ignored";
    case NetworkReturnUseKind::Compared:   return "checked";
    case NetworkReturnUseKind::Branched:   return "controls branch";
    case NetworkReturnUseKind::Stored:     return "stored";
    case NetworkReturnUseKind::Propagated: return "propagated";
    case NetworkReturnUseKind::Consumed:   return "consumed";
    case NetworkReturnUseKind::Returned:   return "returned by caller";
    }
    return "unknown";
}
NetworkTrailStage NetworkTrailStageForApi(NetworkStage stage);

struct CrackmeTriageLimits {
    uint64_t maxBytes = 512ull * 1024ull * 1024ull;
    size_t maxStrings = 100000;
    size_t maxStringBytes = 512;
    size_t maxImports = 200000;
    size_t maxEndpoints = 256;
    size_t maxEndpointCandidates = 1024;
    size_t maxRoutes = 256;
    size_t maxApis = 4096;
    size_t maxCorrelations = 2048;
    size_t maxSourcesPerFinding = 64;
    size_t maxEvidenceRows = 64; // retained correlation/artifact rows per endpoint trail
    size_t maxXrefsPerTarget = 32;
    size_t maxFunctions = 256; // candidate functions eligible for CFG annotation
    size_t maxOwnershipFunctions = 200000; // bounded whole-image range ownership
    size_t maxRangesPerFunction = 64;
    size_t maxOwnershipRanges = 400000;
    size_t maxCallGraphDepth = 2;
    size_t maxCallEdges = 4096;
    size_t maxTypedCalls = 512;
    size_t maxReturnFlows = 512;
    size_t maxReturnDecisionsPerFlow = 4;
    size_t maxReturnProvenanceHops = 32;
    size_t maxReplyDecisionFlows = 1024;
    size_t maxArgumentsPerCall = 32;
    size_t maxDecisionInputs = 256;
    size_t maxAlgorithmInputs = 256;
    size_t maxReferencesPerArtifact = 32; // source references on each artifact row
    size_t maxArtifacts = 256u * 64u; // separate overflow-safe whole-report ceiling
    uint64_t cancellationCheckBytes = 4096;
};

struct CrackmeTriageImportInput {
    std::string dll;
    std::string name;
    uint64_t address = 0;       // IAT/GOT-style target when addressValid
    bool addressValid = false;
};

struct CrackmeTriageFunctionRange {
    uint64_t address = 0;
    uint64_t size = 0;
};

struct CrackmeTriageFunctionInput {
    uint64_t address = 0;
    std::string name;
    // Every owned extent, including non-contiguous chunks.  Empty falls back to
    // the single range [address,address+size) when size is nonzero.
    uint64_t size = 0;
    std::vector<CrackmeTriageFunctionRange> ranges;
};

struct CrackmeTriageCallEdgeInput {
    uint64_t caller = 0;
    uint64_t callee = 0;
};

struct CrackmeTriageApiArgumentInput {
    size_t ordinal = 0;
    std::string name;
    std::string literal;
    uint64_t address = 0;
    bool addressValid = false;
    // Typed numeric value retained independently from zero. This is used for
    // arguments such as WinHTTP/WinINet INTERNET_PORT without parsing prose.
    uint64_t immediate = 0;
    bool immediateValid = false;
    // Optional backing-file coordinate and encoding supplied by adapters which
    // can prove them. They let route/header artifacts retain exact navigation.
    uint64_t fileOffset = 0;
    bool fileOffsetValid = false;
    CrackmeLiteralEncoding encoding = CrackmeLiteralEncoding::Ascii;
    bool encodingValid = false;
};

enum class NetworkReplyDecisionKind : uint8_t {
    DirectComparison = 0,
    ComparisonCall,
};

const char* NetworkReplyDecisionKindText(NetworkReplyDecisionKind kind);

struct CrackmeTriageReplyDecisionInput {
    NetworkReplyDecisionKind kind = NetworkReplyDecisionKind::DirectComparison;
    uint32_t outputArgumentIndex = 0;
    std::string outputRole;
    std::string outputExpression;

    uint64_t comparisonAddress = 0;
    bool comparisonAddressValid = false;
    std::string comparisonInstruction;
    CodeByteSignature comparisonSignature;
    std::string comparisonSummary;
    std::string expectedValue;

    uint64_t decisionAddress = 0;
    bool decisionAddressValid = false;
    uint64_t decisionTarget = 0;
    bool decisionTargetValid = false;
    uint64_t fallthroughAddress = 0;
    bool fallthroughAddressValid = false;
    std::string decisionInstruction;
    CodeByteSignature decisionSignature;
    std::string takenPathSummary;
    std::string fallthroughPathSummary;

    uint64_t matchAddress = 0;
    bool matchAddressValid = false;
    uint64_t mismatchAddress = 0;
    bool mismatchAddressValid = false;

    std::string evidence;
    float confidence = 0.0f;
};

// Terminal comparison/branch reached from a network API's immediate ABI
// return.  This stays separate from reply-buffer content decisions: e.g. a
// failed WinHttpReadData BOOL is transport status, not license rejection.
struct CrackmeTriageReturnDecisionInput {
    uint64_t comparisonAddress = 0;
    bool comparisonAddressValid = false;
    std::string comparisonInstruction;
    CodeByteSignature comparisonSignature;
    std::string predicate;
    std::string expectedValue;
    uint64_t decisionAddress = 0;
    bool decisionAddressValid = false;
    std::string decisionInstruction;
    CodeByteSignature decisionSignature;
    uint64_t decisionTarget = 0;
    bool decisionTargetValid = false;
    uint64_t fallthroughAddress = 0;
    bool fallthroughAddressValid = false;
    NetworkReturnDisposition takenDisposition =
        NetworkReturnDisposition::Indeterminate;
    NetworkReturnDisposition fallthroughDisposition =
        NetworkReturnDisposition::Indeterminate;
    uint64_t successAddress = 0;
    bool successAddressValid = false;
    uint64_t failureAddress = 0;
    bool failureAddressValid = false;
    std::vector<ValueProvenanceHop> hops;
    std::string evidence;
    float confidence = 0.0f;
};

// Adapter-friendly typed observation.  FuncAnnotate's ApiCallObservation can be
// copied into this without making the public triage header depend on CFG types.
struct CrackmeTriageApiCallInput {
    std::string dll;
    std::string name;
    uint64_t callsite = 0;
    bool callsiteValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::string functionName;
    std::vector<CrackmeTriageApiArgumentInput> arguments;
    bool returnValueUsed = false;
    bool returnValueUseKnown = false;
    NetworkReturnUseKind returnUseKind = NetworkReturnUseKind::Unknown;
    uint64_t returnUseAddress = 0;
    bool returnUseAddressValid = false;
    std::string returnUseInstruction;
    std::string returnUseSummary;
    bool resultInfluencesDecision = false;
    uint64_t decisionAddress = 0;
    bool decisionAddressValid = false;
    uint64_t decisionTarget = 0;
    bool decisionTargetValid = false;
    std::string decisionInstruction;
    std::string returnUseEvidence;
    float returnUseConfidence = 0.0f;
    bool replyDecisionAnalysisAttempted = false;
    bool replyDecisionsComplete = true;
    std::string replyDecisionIncompleteReason;
    std::vector<CrackmeTriageReplyDecisionInput> replyDecisions;

    uint64_t continuationAddress = 0;
    bool continuationAddressValid = false;
    CodeByteSignature continuationSignature;
    uint64_t continuationFileOffset = 0;
    bool continuationFileOffsetValid = false;
    bool returnLineageAnalysisAttempted = false;
    bool returnLineageComplete = true;
    std::string returnLineageIncompleteReason;
    std::vector<CrackmeTriageReturnDecisionInput> returnDecisions;
};

struct CrackmeTriageDecisionInput {
    uint64_t address = 0;
    bool addressValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    NetworkArtifactKind kind = NetworkArtifactKind::Validation;
    std::string text;
    bool consumesNetworkReply = false;
};

struct CrackmeTriageAlgorithmInput {
    uint64_t address = 0;
    bool addressValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::string name;
    std::string category;
    std::string evidence;
    uint64_t fileOffset = 0;
    bool fileOffsetValid = false;
};

struct CrackmeTriageInput {
    const uint8_t* bytes = nullptr;
    size_t size = 0;

    // A false result means the offset is real file evidence but has no mapped VA.
    // Keeping validity separate makes a mapped VA of zero representable.
    std::function<bool(uint64_t fileOffset, uint64_t& vaOut)> offsetToVA;

    uint64_t overlayOffset = 0;
    uint64_t overlaySize = 0;
    std::vector<CrackmeTriageImportInput> imports;
    bool importsComplete = true;
    std::vector<CrackmeTriageFunctionInput> functions;
    bool functionOwnershipComplete = true;
    std::vector<CrackmeTriageCallEdgeInput> callEdges;
    bool callEdgesComplete = true;
    std::vector<CrackmeTriageApiCallInput> apiCalls;
    bool apiCallsComplete = true;
    std::vector<CrackmeTriageDecisionInput> decisions;
    bool decisionsComplete = true;
    std::vector<CrackmeTriageAlgorithmInput> algorithms;
    bool algorithmsComplete = true;
    const XrefIndex* xrefs = nullptr;

    CrackmeTriageLimits limits;
    std::function<bool()> cancelled;
};

struct CrackmeTriageLiteralSource {
    CrackmeLiteralRole role = CrackmeLiteralRole::Host;
    CrackmeLiteralEncoding encoding = CrackmeLiteralEncoding::Ascii;
    CrackmeLiteralLocation location = CrackmeLiteralLocation::FileOnly;
    std::string literal;

    uint64_t fileOffset = 0;         // start of the containing extracted string
    uint64_t literalFileOffset = 0;  // start of this literal inside that string
    uint64_t address = 0;
    uint64_t literalAddress = 0;
    bool addressValid = false;
    bool literalAddressValid = false;
    bool fileOffsetValid = true;
    bool textTruncated = false;
};

struct CrackmeTriageRoute {
    std::string path;
    std::vector<CrackmeTriageLiteralSource> sources;
};

struct NetworkArtifact {
    NetworkArtifactKind kind = NetworkArtifactKind::Validation;
    std::string value;
    std::vector<CrackmeTriageLiteralSource> sources;
    size_t endpointIndex = 0;
    bool endpointIndexValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    // All bounded owners recovered from artifact xrefs. functionAddress remains
    // the primary navigation address for compatibility; correlation considers
    // every retained owner so source ordering cannot hide validation logic.
    std::vector<uint64_t> functionAddresses;
    bool replyLinked = false;
    bool decisionEligible = true; // false for non-reply API return checks
    CrackmeTriageConfidence confidence = CrackmeTriageConfidence::Low;
    std::string confidenceLabel;
    std::string honestyLabel;
};

struct CrackmeTriageEndpoint {
    std::string display;       // normalized scheme://host[:port], or host[:port]
    std::string host;          // normalized lower-case host, brackets removed
    std::string scheme;        // lower-case; empty for a bare host literal
    uint16_t port = 0;
    bool portValid = false;
    CrackmeEndpointKind kind = CrackmeEndpointKind::Domain;
    CrackmeEndpointScope scope = CrackmeEndpointScope::Unknown;
    std::vector<std::string> paths;
    std::vector<CrackmeTriageLiteralSource> sources;
    std::vector<size_t> correlationIndices;
    NetworkStageMask stages = 0;
    CrackmeTriageConfidence confidence = CrackmeTriageConfidence::Low;
    std::string confidenceLabel;
    std::string honestyLabel;
};

struct CrackmeTriageApiEvidence {
    std::string dll;
    std::string importName;
    std::string canonicalName;
    NetworkApiFamily family = NetworkApiFamily::Winsock;
    NetworkStage stage = NetworkStage::Connect;
    uint64_t address = 0;
    bool addressValid = false;
    bool lifecycle = false;
    std::vector<uint64_t> callsites;
};

struct CrackmeTriageCorrelation {
    size_t endpointIndex = 0;
    size_t apiIndex = 0;
    NetworkStage stage = NetworkStage::Connect;
    NetworkTrailStage trailStage = NetworkTrailStage::Connect;
    // `functionAddress` is the exact API callsite owner used for navigation and
    // reply-to-decision distance.  The endpoint/literal owner is retained
    // separately so a cross-function depth remains explainable.
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::string functionName;
    uint64_t endpointFunctionAddress = 0;
    bool endpointFunctionAddressValid = false;
    std::string endpointFunctionName;
    uint64_t endpointReference = 0;
    uint64_t apiCallsite = 0;
    bool apiCallsiteValid = false;
    size_t graphDepth = 0;
    bool directArgument = false;
    bool replyToDecision = false;
    CrackmeTriageConfidence confidence = CrackmeTriageConfidence::High;
    std::string confidenceLabel;
    std::string honestyLabel;
};

struct CrackmeTriageStageEvidence {
    NetworkTrailStage stage = NetworkTrailStage::Endpoint;
    size_t apiCount = 0;
    size_t correlationCount = 0;
    CrackmeTriageConfidence confidence = CrackmeTriageConfidence::Low;
    std::string confidenceLabel;
    std::string honestyLabel;
};

// One exact network callsite plus its bounded downstream return-register use.
// Expected/documented semantics are resolved through the shared exact catalog
// using apiIndex; this record retains only binary-specific observations.
struct NetworkReturnFlow {
    size_t apiIndex = 0;
    bool apiIndexValid = false;
    uint64_t callsite = 0;
    bool callsiteValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::string functionName;
    bool returnValueUseKnown = false;
    bool returnValueUsed = false;
    NetworkReturnUseKind useKind = NetworkReturnUseKind::Unknown;
    uint64_t useAddress = 0;
    bool useAddressValid = false;
    std::string useInstruction;
    std::string useSummary;
    bool resultInfluencesDecision = false;
    uint64_t decisionAddress = 0;
    bool decisionAddressValid = false;
    uint64_t decisionTarget = 0;
    bool decisionTargetValid = false;
    std::string decisionInstruction;
    std::string evidence;
    CrackmeTriageConfidence confidence = CrackmeTriageConfidence::Low;
    std::string confidenceLabel;
    std::string honestyLabel;

    uint64_t continuationAddress = 0;
    bool continuationAddressValid = false;
    CodeByteSignature continuationSignature;
    uint64_t continuationFileOffset = 0;
    bool continuationFileOffsetValid = false;
    bool lineageAnalysisAttempted = false;
    bool lineageComplete = true;
    std::string lineageIncompleteReason;
    std::vector<CrackmeTriageReturnDecisionInput> decisions;
};

// Reply-content validation is kept distinct from API status/byte-count return
// handling.  The producer is an exact cataloged Read call and the comparison is
// reached from its declared payload/header output argument within one bounded
// function CFG.
struct NetworkReplyDecisionFlow {
    size_t apiIndex = 0;
    bool apiIndexValid = false;
    uint64_t callsite = 0;
    bool callsiteValid = false;
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::string functionName;

    NetworkReplyDecisionKind kind = NetworkReplyDecisionKind::DirectComparison;
    uint32_t outputArgumentIndex = 0;
    std::string outputRole;
    std::string outputExpression;
    uint64_t comparisonAddress = 0;
    bool comparisonAddressValid = false;
    std::string comparisonInstruction;
    CodeByteSignature comparisonSignature;
    std::string comparisonSummary;
    std::string expectedValue;

    uint64_t decisionAddress = 0;
    bool decisionAddressValid = false;
    uint64_t decisionTarget = 0;
    bool decisionTargetValid = false;
    uint64_t fallthroughAddress = 0;
    bool fallthroughAddressValid = false;
    std::string decisionInstruction;
    CodeByteSignature decisionSignature;
    std::string takenPathSummary;
    std::string fallthroughPathSummary;
    uint64_t matchAddress = 0;
    bool matchAddressValid = false;
    uint64_t mismatchAddress = 0;
    bool mismatchAddressValid = false;

    std::string evidence;
    CrackmeTriageConfidence confidence = CrackmeTriageConfidence::Low;
    std::string confidenceLabel;
    std::string honestyLabel;
};

struct CrackmeTrail {
    size_t endpointIndex = 0;
    std::vector<size_t> artifactIndices;
    std::vector<size_t> correlationIndices;
    std::vector<size_t> returnFlowIndices;
    std::vector<size_t> replyDecisionFlowIndices;
    std::array<CrackmeTriageStageEvidence,
               static_cast<size_t>(NetworkTrailStage::Count)> stages;
    CrackmeTriageConfidence confidence = CrackmeTriageConfidence::Low;
    std::string label;
    std::string confidenceLabel;
    std::string honestyLabel;
};

enum class CrackmeTriageStopReason : uint8_t {
    None = 0,
    InvalidInput,
    Cancelled,
    ByteLimit,
    StringLimit,
    EndpointLimit,
    RouteLimit,
    ApiLimit,
    CorrelationLimit,
    SourceLimit,
};

const char* CrackmeTriageStopReasonText(CrackmeTriageStopReason reason);

struct CrackmeTriageCompleteness {
    bool complete = true;
    bool cancelled = false;
    bool bytesTruncated = false;
    bool stringsTruncated = false;
    bool endpointsTruncated = false;
    bool routesTruncated = false;
    bool apisTruncated = false;
    bool correlationsTruncated = false;
    bool returnFlowsTruncated = false;
    bool returnLineageTruncated = false;
    bool replyDecisionFlowsTruncated = false;
    bool sourcesTruncated = false;
    bool candidateFunctionsTruncated = false;
    bool xrefsComplete = true;
    CrackmeTriageStopReason stopReason = CrackmeTriageStopReason::None;
    uint64_t bytesTotal = 0;
    uint64_t bytesExamined = 0;
    size_t stringsExamined = 0;
    std::string reason;
};

// Inert patch advice is kept adjacent to the ranked predicate it describes.
// No bytes are applied by the analysis worker; the UI must still route an
// explicitly selected plan through the ordinary project patch system.
struct AuthorizationPredicatePatchAdvice {
    AuthorizationLocation function;
    AuthorizationPatchAdvice advice;
};

struct CrackmeTriageReport {
    std::vector<CrackmeTriageEndpoint> endpoints;
    std::vector<CrackmeTriageRoute> routes;
    std::vector<NetworkArtifact> artifacts;
    std::vector<CrackmeTriageApiEvidence> apis;
    std::vector<CrackmeTriageCorrelation> correlations;
    std::vector<NetworkReturnFlow> returnFlows;
    std::vector<NetworkReplyDecisionFlow> replyDecisionFlows;
    std::vector<CrackmeTrail> trails;
    std::array<CrackmeTriageStageEvidence,
               static_cast<size_t>(NetworkTrailStage::Count)> stages;
    // Authorization is deliberately separate from the five transport trail
    // stages. It may contain startup-only gates even when no endpoint exists.
    AuthorizationAnalysisReport authorization;
    // Whole-program ranked authorization predicates and the evidence-backed
    // path from local input through protected operations. This stays separate
    // from transport and persistence so missing stages remain visibly unknown.
    AuthorizationTrailReport authorizationTrail;
    std::vector<AuthorizationPredicatePatchAdvice> authorizationPatchAdvice;
    std::string label;
    CrackmeTriageCompleteness completeness;
};

using CrackmeTriageResult = CrackmeTriageReport; // compatibility for early consumers

CrackmeTriageReport RunCrackmeTriage(const CrackmeTriageInput& input);

// Deterministic annotation plan used by AnalysisService.  Endpoint owners and
// exact API-callsite owners form the primary tier; semantic artifact owners are
// considered only after both.  The returned truncation flag must be reflected
// in the final report completeness after candidate-only CFG annotation.
struct CrackmeTriageCandidateSelection {
    std::vector<uint64_t> functionAddresses;
    size_t availableFunctions = 0;
    bool truncated = false;
};

CrackmeTriageCandidateSelection SelectCrackmeTriageAnnotationCandidates(
    const CrackmeTriageReport& report,
    const std::vector<CrackmeTriageFunctionInput>& functions,
    size_t maxCandidates,
    size_t maxOwnershipFunctions,
    size_t maxRangesPerFunction = 64,
    size_t maxOwnershipRanges = 400000);

} // namespace ds
