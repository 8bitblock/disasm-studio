#include "AuthorizationAnalysis.h"

#include <algorithm>
#include <cmath>
#include <deque>
#include <limits>
#include <set>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ds {
namespace {

constexpr size_t kHardMaxFunctions = 256;
constexpr size_t kHardMaxStartupDepth = 8;
constexpr size_t kHardMaxCallEdges = 4096;
constexpr size_t kHardMaxDecisions = 4096;
constexpr size_t kHardMaxOperations = 8192;
constexpr size_t kHardMaxFlows = 4096;
constexpr size_t kHardMaxEvidencePerPath = 256;
constexpr size_t kHardMaxLinksPerFlow = 256;
constexpr size_t kHardMaxProvenanceHopsPerFlow = 256;

size_t bounded(size_t requested, size_t hardMaximum) {
    return std::min(requested, hardMaximum);
}

float clamp01(float value) {
    if (!std::isfinite(value)) return 0.0f;
    return std::clamp(value, 0.0f, 1.0f);
}

void appendReason(std::string& reason, const std::string& item) {
    if (item.empty()) return;
    if (!reason.empty()) reason += "; ";
    reason += item;
}

bool cancelled(const AuthorizationAnalysisInput& input) {
    return input.cancelled && input.cancelled();
}

struct EvidenceWeight {
    float allow = 0.0f;
    float deny = 0.0f;
};

EvidenceWeight defaultWeight(AuthorizationEvidenceKind kind) {
    switch (kind) {
    case AuthorizationEvidenceKind::ProcessTermination:      return {0.0f, 0.95f};
    case AuthorizationEvidenceKind::EarlyFailureReturn:      return {0.0f, 0.80f};
    case AuthorizationEvidenceKind::FailureIndicator:        return {0.0f, 0.65f};
    case AuthorizationEvidenceKind::SuccessIndicator:        return {0.65f, 0.0f};
    case AuthorizationEvidenceKind::ApplicationContinuation: return {0.85f, 0.0f};
    // A durable write is direction-neutral without provenance for the written
    // value.  Deny paths commonly persist Licensed=0, attempt counters, or
    // revocation markers, so presence of a write must never manufacture an
    // allow verdict by itself.
    case AuthorizationEvidenceKind::PersistentStateWrite:    return {};
    case AuthorizationEvidenceKind::Unknown:                  return {};
    }
    return {};
}

std::string evidenceIdentity(const AuthorizationEvidence& evidence) {
    std::ostringstream out;
    out << static_cast<unsigned>(evidence.kind) << ':';
    if (evidence.location.addressValid) out << 'a' << evidence.location.address;
    else if (evidence.location.fileOffsetValid) out << 'f' << evidence.location.fileOffset;
    else if (evidence.location.functionAddressValid)
        out << 'n' << evidence.location.functionAddress;
    else out << 't' << evidence.text;
    return out.str();
}

AuthorizationPath scorePath(const AuthorizationPathInput& input,
                            size_t maxEvidence,
                            AuthorizationAnalysisCompleteness& completeness,
                            const std::vector<AuthorizationEvidence>& generated = {}) {
    AuthorizationPath result;
    result.entry = input.entry;
    result.complete = input.complete;
    result.evidence.reserve(std::min(maxEvidence,
        input.evidence.size() + generated.size()));
    for (const AuthorizationEvidence& evidence : input.evidence) {
        if (result.evidence.size() >= maxEvidence) break;
        result.evidence.push_back(evidence);
    }
    for (const AuthorizationEvidence& evidence : generated) {
        if (result.evidence.size() >= maxEvidence) break;
        result.evidence.push_back(evidence);
    }
    if (input.evidence.size() + generated.size() > maxEvidence) {
        result.complete = false;
        completeness.evidenceTruncated = true;
    }

    bool allowStrong = false;
    bool denyStrong = false;
    std::set<std::string> allowSources;
    std::set<std::string> denySources;
    for (const AuthorizationEvidence& evidence : result.evidence) {
        EvidenceWeight weight = defaultWeight(evidence.kind);
        if (evidence.strength > 0.0f) {
            const float requested = clamp01(evidence.strength);
            if (weight.allow > 0.0f) weight.allow = requested;
            if (weight.deny > 0.0f) weight.deny = requested;
        }
        result.allowScore = std::min(1.0f, result.allowScore + weight.allow);
        result.denyScore = std::min(1.0f, result.denyScore + weight.deny);
        const std::string source = evidenceIdentity(evidence);
        if (weight.allow > 0.0f) {
            allowSources.insert(source);
            allowStrong |= weight.allow >= 0.75f;
        }
        if (weight.deny > 0.0f) {
            denySources.insert(source);
            denyStrong |= weight.deny >= 0.75f;
        }
    }

    const bool allowQualified = allowStrong ||
        (allowSources.size() >= 2 && result.allowScore >= 1.0f);
    const bool denyQualified = denyStrong ||
        (denySources.size() >= 2 && result.denyScore >= 1.0f);
    if (result.complete && allowQualified != denyQualified) {
        result.outcome = allowQualified
            ? AuthorizationOutcome::LikelyAllow
            : AuthorizationOutcome::LikelyDeny;
    }

    if (!result.complete) {
        result.honestyLabel = input.incompleteReason.empty()
            ? "Bounded path analysis was incomplete; outcome remains unknown."
            : "Incomplete: " + input.incompleteReason;
    } else if (allowQualified && denyQualified) {
        result.honestyLabel =
            "Conflicting allow and deny effects were found; outcome remains unknown.";
    } else if (result.outcome == AuthorizationOutcome::LikelyAllow) {
        result.honestyLabel =
            "Static downstream effects suggest allow; this is not runtime proof.";
    } else if (result.outcome == AuthorizationOutcome::LikelyDeny) {
        result.honestyLabel =
            "Static downstream effects suggest deny; this is not runtime proof.";
    } else {
        result.honestyLabel =
            "No strong asymmetric allow/deny effect was proven on this bounded path.";
    }
    return result;
}

AuthorizationStageRecord pathStage(const AuthorizationPath& path) {
    AuthorizationStageRecord stage;
    stage.location = path.entry;
    stage.outcome = path.outcome;
    stage.stage = path.outcome == AuthorizationOutcome::LikelyAllow
        ? AuthorizationStage::AllowPath
        : AuthorizationStage::DenyPath;
    stage.evidence = path.honestyLabel;
    return stage;
}

void addPathStages(AuthorizationFlow& flow) {
    auto add = [&](const AuthorizationPath& path) {
        if (path.outcome == AuthorizationOutcome::Unknown) return;
        flow.stages.push_back(pathStage(path));
        for (const AuthorizationEvidence& evidence : path.evidence) {
            const EvidenceWeight weight = defaultWeight(evidence.kind);
            const bool supports = path.outcome == AuthorizationOutcome::LikelyAllow
                ? weight.allow > 0.0f : weight.deny > 0.0f;
            if (!supports) continue;
            AuthorizationStageRecord effect;
            effect.stage = path.outcome == AuthorizationOutcome::LikelyAllow
                ? AuthorizationStage::AllowPath : AuthorizationStage::DenyPath;
            effect.location = evidence.location;
            effect.outcome = path.outcome;
            effect.evidence = evidence.text.empty()
                ? AuthorizationEvidenceKindText(evidence.kind) : evidence.text;
            flow.stages.push_back(std::move(effect));
        }
    };
    add(flow.takenPath);
    add(flow.fallthroughPath);
}

bool branchLikelyAllow(const AuthorizationFlow& flow, AuthorizationBranch branch) {
    if (branch == AuthorizationBranch::Taken)
        return flow.takenPath.outcome == AuthorizationOutcome::LikelyAllow;
    if (branch == AuthorizationBranch::Fallthrough)
        return flow.fallthroughPath.outcome == AuthorizationOutcome::LikelyAllow;
    return false;
}

void setFlowHonesty(AuthorizationFlow& flow) {
    const bool takenKnown = flow.takenPath.outcome != AuthorizationOutcome::Unknown;
    const bool fallKnown = flow.fallthroughPath.outcome != AuthorizationOutcome::Unknown;
    const bool complementary =
        (flow.takenPath.outcome == AuthorizationOutcome::LikelyAllow &&
         flow.fallthroughPath.outcome == AuthorizationOutcome::LikelyDeny) ||
        (flow.takenPath.outcome == AuthorizationOutcome::LikelyDeny &&
         flow.fallthroughPath.outcome == AuthorizationOutcome::LikelyAllow);
    flow.confidence = complementary ? 0.90f : (takenKnown || fallKnown ? 0.65f : 0.0f);
    if (complementary) {
        flow.honestyLabel =
            "Bounded static effects distinguish likely allow and likely deny paths; live execution is required for observation.";
    } else if (takenKnown || fallKnown) {
        flow.honestyLabel =
            "One branch has a likely static outcome; the other branch remains unproven.";
    } else {
        flow.honestyLabel =
            "Comparison/branch found, but bounded static effects do not prove allow or deny.";
    }
}

} // namespace

const char* AuthorizationOutcomeText(AuthorizationOutcome outcome) {
    switch (outcome) {
    case AuthorizationOutcome::Unknown: return "Unknown";
    case AuthorizationOutcome::LikelyAllow: return "Likely allow";
    case AuthorizationOutcome::LikelyDeny: return "Likely deny";
    }
    return "Unknown";
}

const char* AuthorizationStageText(AuthorizationStage stage) {
    switch (stage) {
    case AuthorizationStage::ReplyCheck: return "Reply check";
    case AuthorizationStage::AllowPath: return "Allow path";
    case AuthorizationStage::DenyPath: return "Deny path";
    case AuthorizationStage::StateWrite: return "State write";
    case AuthorizationStage::StartupRead: return "Startup read";
    case AuthorizationStage::StartupGate: return "Startup gate";
    case AuthorizationStage::InputRead: return "Input read";
    case AuthorizationStage::Compare: return "Compare";
    }
    return "Unknown";
}

const char* PersistentStateKindText(PersistentStateKind kind) {
    switch (kind) {
    case PersistentStateKind::Unknown: return "Unknown/custom";
    case PersistentStateKind::Registry: return "Registry";
    case PersistentStateKind::File: return "File";
    case PersistentStateKind::Ini: return "INI";
    case PersistentStateKind::Credential: return "Credential Manager";
    case PersistentStateKind::DpapiTransform: return "DPAPI transform";
    }
    return "Unknown/custom";
}

const char* PersistentStateAccessText(PersistentStateAccess access) {
    switch (access) {
    case PersistentStateAccess::Unknown: return "Unknown";
    case PersistentStateAccess::Open: return "Open";
    case PersistentStateAccess::Read: return "Read";
    case PersistentStateAccess::Write: return "Write";
    case PersistentStateAccess::Protect: return "Protect";
    case PersistentStateAccess::Unprotect: return "Unprotect";
    }
    return "Unknown";
}

const char* AuthorizationEvidenceKindText(AuthorizationEvidenceKind kind) {
    switch (kind) {
    case AuthorizationEvidenceKind::Unknown: return "Unknown";
    case AuthorizationEvidenceKind::ProcessTermination: return "Process termination";
    case AuthorizationEvidenceKind::EarlyFailureReturn: return "Early failure return";
    case AuthorizationEvidenceKind::FailureIndicator: return "Failure indicator";
    case AuthorizationEvidenceKind::SuccessIndicator: return "Success indicator";
    case AuthorizationEvidenceKind::ApplicationContinuation: return "Application continuation";
    case AuthorizationEvidenceKind::PersistentStateWrite: return "Persistent-state write";
    }
    return "Unknown";
}

const char* ValueProvenanceHopKindText(ValueProvenanceHopKind kind) {
    switch (kind) {
    case ValueProvenanceHopKind::Origin:           return "origin";
    case ValueProvenanceHopKind::Copy:             return "copy";
    case ValueProvenanceHopKind::Store:            return "store";
    case ValueProvenanceHopKind::Reload:           return "reload";
    case ValueProvenanceHopKind::PassArgument:     return "pass argument";
    case ValueProvenanceHopKind::EnterHelper:      return "enter helper";
    case ValueProvenanceHopKind::ReturnFromHelper: return "return from helper";
    case ValueProvenanceHopKind::ReturnToCaller:   return "return to caller";
    case ValueProvenanceHopKind::Compare:          return "compare";
    case ValueProvenanceHopKind::Branch:           return "branch";
    }
    return "unknown";
}

const char* AuthorizationGateSourceText(AuthorizationGateSource source) {
    switch (source) {
    case AuthorizationGateSource::Unknown:          return "Unknown";
    case AuthorizationGateSource::ApiReturn:        return "API status/handle";
    case AuthorizationGateSource::PersistentOutput: return "Persisted output value";
    case AuthorizationGateSource::LocalInput:       return "Local input buffer";
    }
    return "Unknown";
}

const char* AuthorizationEntitlementKindText(AuthorizationEntitlementKind kind) {
    switch (kind) {
    case AuthorizationEntitlementKind::Unknown:     return "entitlement";
    case AuthorizationEntitlementKind::Pro:         return "pro";
    case AuthorizationEntitlementKind::Validated:   return "validated";
    case AuthorizationEntitlementKind::Licensed:    return "licensed";
    case AuthorizationEntitlementKind::Activated:   return "activated";
    case AuthorizationEntitlementKind::Premium:     return "premium";
    case AuthorizationEntitlementKind::BooleanTrue: return "enabled (1/true)";
    }
    return "entitlement";
}

bool PersistentStateIdentityEquivalentExact(const PersistentStateIdentity& left,
                                            const PersistentStateIdentity& right) {
    if (!left.valid || !right.valid || !left.exact || !right.exact) return false;
    if (left.kind != right.kind || left.kind == PersistentStateKind::Unknown ||
        left.kind == PersistentStateKind::DpapiTransform) return false;
    return left.canonicalScope == right.canonicalScope &&
           left.canonicalKey == right.canonicalKey &&
           left.canonicalValue == right.canonicalValue;
}

AuthorizationAnalysisReport RunAuthorizationAnalysis(
    const AuthorizationAnalysisInput& input) {
    AuthorizationAnalysisReport report;
    auto& complete = report.completeness;
    complete.startupRootsComplete = input.startupRootsComplete;
    complete.callGraphComplete = input.functionsComplete && input.callEdgesComplete;
    complete.decisionsComplete = input.decisionsComplete;
    complete.stateOperationsComplete = input.stateOperationsComplete;

    const size_t maxFunctions = bounded(input.limits.maxFunctions, kHardMaxFunctions);
    const size_t maxDepth = bounded(input.limits.maxStartupDepth, kHardMaxStartupDepth);
    const size_t maxEdges = bounded(input.limits.maxCallEdges, kHardMaxCallEdges);
    const size_t maxDecisions = bounded(input.limits.maxDecisions, kHardMaxDecisions);
    const size_t maxOperations = bounded(input.limits.maxOperations, kHardMaxOperations);
    const size_t maxFlows = bounded(input.limits.maxFlows, kHardMaxFlows);
    const size_t maxEvidence = bounded(input.limits.maxEvidencePerPath,
                                       kHardMaxEvidencePerPath);
    const size_t maxLinks = bounded(input.limits.maxLinksPerFlow,
                                    kHardMaxLinksPerFlow);
    const size_t maxProvenance = bounded(
        input.limits.maxProvenanceHopsPerFlow,
        kHardMaxProvenanceHopsPerFlow);
    const size_t decisionCount = std::min(input.decisions.size(), maxDecisions);

    if (cancelled(input)) {
        complete.cancelled = true;
        complete.complete = false;
        complete.reason = "cancelled before authorization analysis";
        return report;
    }

    const size_t operationCount = std::min(input.stateOperations.size(), maxOperations);
    report.stateOperations.reserve(operationCount);
    for (size_t i = 0; i < operationCount; ++i) {
        const PersistentStateOperationInput& source = input.stateOperations[i];
        PersistentStateOperation operation;
        operation.access = source.access;
        operation.identity = source.identity;
        operation.location = source.location;
        operation.apiDll = source.apiDll;
        operation.apiName = source.apiName;
        operation.evidence = source.evidence;
        operation.operationComplete = source.operationComplete;
        operation.controllingDecisionIndex = source.controllingDecisionIndex;
        operation.controllingDecisionIndexValid =
            source.controllingDecisionIndexValid;
        operation.controllingBranch = source.controllingBranch;
        operation.transformOperationIndex = source.transformOperationIndex;
        operation.transformOperationIndexValid = source.transformOperationIndexValid;
        operation.outputArgumentIndex = source.outputArgumentIndex;
        operation.outputArgumentIndexValid = source.outputArgumentIndexValid;
        operation.outputExpression = source.outputExpression;
        report.stateOperations.push_back(std::move(operation));
        if (!source.operationComplete) complete.stateOperationsComplete = false;
    }
    if (operationCount < input.stateOperations.size()) complete.operationsTruncated = true;

    // Build and traverse only the retained direct call graph.  Addresses at zero
    // remain valid through their explicit booleans.
    std::unordered_map<uint64_t, std::vector<uint64_t>> adjacency;
    const size_t edgeCount = std::min(input.callEdges.size(), maxEdges);
    for (size_t i = 0; i < edgeCount; ++i) {
        const AuthorizationCallEdgeInput& edge = input.callEdges[i];
        if (!edge.callerValid || !edge.calleeValid) continue;
        adjacency[edge.caller].push_back(edge.callee);
    }
    if (edgeCount < input.callEdges.size()) {
        complete.callEdgesTruncated = true;
        complete.callGraphComplete = false;
    }

    std::unordered_map<uint64_t, size_t> startupDepth;
    std::deque<std::pair<uint64_t, size_t>> queue;
    for (const AuthorizationLocation& root : input.startupRoots) {
        uint64_t address = 0;
        bool valid = false;
        if (root.functionAddressValid) {
            address = root.functionAddress;
            valid = true;
        } else if (root.addressValid) {
            address = root.address;
            valid = true;
        }
        if (!valid || startupDepth.find(address) != startupDepth.end()) continue;
        if (startupDepth.size() >= maxFunctions) {
            complete.functionsTruncated = true;
            complete.callGraphComplete = false;
            break;
        }
        startupDepth.emplace(address, 0);
        queue.emplace_back(address, 0);
    }
    while (!queue.empty() && !cancelled(input)) {
        const auto [function, depth] = queue.front();
        queue.pop_front();
        const auto found = adjacency.find(function);
        if (found == adjacency.end()) continue;
        if (depth >= maxDepth) {
            for (uint64_t callee : found->second) {
                if (startupDepth.find(callee) == startupDepth.end()) {
                    complete.startupDepthTruncated = true;
                    complete.callGraphComplete = false;
                    break;
                }
            }
            continue;
        }
        for (uint64_t callee : found->second) {
            if (startupDepth.find(callee) != startupDepth.end()) continue;
            if (startupDepth.size() >= maxFunctions) {
                complete.functionsTruncated = true;
                complete.callGraphComplete = false;
                break;
            }
            startupDepth.emplace(callee, depth + 1);
            queue.emplace_back(callee, depth + 1);
        }
    }
    complete.startupFunctionsVisited = startupDepth.size();
    if (cancelled(input)) complete.cancelled = true;

    for (PersistentStateOperation& operation : report.stateOperations) {
        if (operation.location.functionAddressValid) {
            const auto found = startupDepth.find(operation.location.functionAddress);
            if (found != startupDepth.end()) {
                operation.startupReachable = true;
                operation.startupDepth = found->second;
                operation.startupDepthValid = true;
            }
        }
        if (operation.controllingDecisionIndexValid &&
            operation.controllingDecisionIndex >= decisionCount) {
            operation.controllingDecisionIndexValid = false;
            operation.operationComplete = false;
            complete.stateOperationsComplete = false;
        }
        if (operation.transformOperationIndexValid &&
            (operation.transformOperationIndex >= report.stateOperations.size() ||
             report.stateOperations[operation.transformOperationIndex].identity.kind !=
                  PersistentStateKind::DpapiTransform)) {
            operation.transformOperationIndexValid = false;
            operation.operationComplete = false;
            complete.stateOperationsComplete = false;
        }
    }

    if (decisionCount < input.decisions.size()) complete.decisionsTruncated = true;

    // Create independently navigable reply, local-input, and startup flows.
    // State writes on a controlled branch remain visible context, but are
    // neutral unless path effects separately establish an allow outcome.
    // Successful API status alone is never authorization evidence either.
    for (size_t i = 0; i < decisionCount && !complete.cancelled; ++i) {
        if (cancelled(input)) {
            complete.cancelled = true;
            break;
        }
        const AuthorizationDecisionInput& decision = input.decisions[i];
        const auto navigable = [](const AuthorizationLocation& location) {
            return location.addressValid || location.fileOffsetValid;
        };
        const bool localLocationsComplete = !decision.localInputFlow ||
            (navigable(decision.inputLocation) &&
             navigable(decision.comparisonLocation) &&
             navigable(decision.location));
        if (!localLocationsComplete) {
            complete.decisionsComplete = false;
            complete.pathsComplete = false;
        }
        if (!decision.takenPath.complete || !decision.fallthroughPath.complete)
            complete.pathsComplete = false;
        if (!decision.provenanceComplete) complete.pathsComplete = false;
        std::vector<AuthorizationEvidence> takenGenerated;
        std::vector<AuthorizationEvidence> fallGenerated;
        if (decision.networkReplyFlowIndexValid || decision.localInputFlow) {
            for (const PersistentStateOperation& operation : report.stateOperations) {
                if (operation.access != PersistentStateAccess::Write ||
                    !operation.operationComplete ||
                    !operation.controllingDecisionIndexValid ||
                    operation.controllingDecisionIndex != i) continue;
                AuthorizationEvidence evidence;
                evidence.kind = AuthorizationEvidenceKind::PersistentStateWrite;
                evidence.location = operation.location;
                evidence.text = operation.identity.valid
                    ? "writes durable state " + operation.identity.display
                    : "writes a persistent-state candidate";
                if (operation.controllingBranch == AuthorizationBranch::Taken)
                    takenGenerated.push_back(std::move(evidence));
                else if (operation.controllingBranch == AuthorizationBranch::Fallthrough)
                    fallGenerated.push_back(std::move(evidence));
            }
        }

        const AuthorizationPath taken = scorePath(decision.takenPath, maxEvidence,
                                                  complete, takenGenerated);
        const AuthorizationPath fallthrough = scorePath(
            decision.fallthroughPath, maxEvidence, complete, fallGenerated);

        enum class FlowKind { Reply, Startup, LocalInput };
        auto emitFlow = [&](FlowKind kind, size_t stateReadIndex) {
            if (report.flows.size() >= maxFlows) {
                complete.flowsTruncated = true;
                return;
            }
            const bool reply = kind == FlowKind::Reply;
            const bool startup = kind == FlowKind::Startup;
            AuthorizationFlow flow;
            const char* prefix = reply ? "reply:"
                               : startup ? "startup:"
                                         : "local:";
            flow.id = std::string(prefix) + std::to_string(i);
            flow.decisionIndex = i;
            flow.decisionIndexValid = true;
            flow.networkReplyFlowIndex = decision.networkReplyFlowIndex;
            flow.networkReplyFlowIndexValid = reply;
            flow.localInputFlow = kind == FlowKind::LocalInput;
            flow.inputLocation = decision.inputLocation;
            flow.comparisonLocation = decision.comparisonLocation;
            flow.decisionLocation = decision.location;
            flow.takenPath = taken;
            flow.fallthroughPath = fallthrough;
            flow.gateSource = decision.gateSource;
            flow.entitlementKind = decision.entitlementKind;
            flow.entitlementLabel = decision.entitlementLabel;
            flow.originExpression = decision.originExpression;
            flow.expectedValue = decision.expectedValue;
            const size_t provenanceCount = (std::min)(
                decision.provenance.size(), maxProvenance);
            flow.provenance.assign(
                decision.provenance.begin(),
                decision.provenance.begin() +
                    static_cast<std::ptrdiff_t>(provenanceCount));
            flow.provenanceComplete = decision.provenanceComplete;
            flow.provenanceIncompleteReason =
                decision.provenanceIncompleteReason;
            if (provenanceCount < decision.provenance.size()) {
                flow.provenanceComplete = false;
                appendReason(flow.provenanceIncompleteReason,
                    "provenance hop cap retained the earliest hops");
                complete.provenanceTruncated = true;
                complete.pathsComplete = false;
            }
            if (flow.localInputFlow && !localLocationsComplete) {
                flow.provenanceComplete = false;
                appendReason(flow.provenanceIncompleteReason,
                    "local input, comparison, or decision location is not navigable");
            }
            if (reply) {
                AuthorizationStageRecord stage;
                stage.stage = AuthorizationStage::ReplyCheck;
                stage.location = decision.location;
                stage.evidence = decision.evidence.empty()
                    ? decision.comparison : decision.evidence;
                flow.stages.push_back(std::move(stage));
            } else if (startup) {
                flow.stateReadOperationIndex = stateReadIndex;
                flow.stateReadOperationIndexValid = true;
                AuthorizationStageRecord read;
                read.stage = AuthorizationStage::StartupRead;
                read.location = report.stateOperations[stateReadIndex].location;
                read.operationIndex = stateReadIndex;
                read.operationIndexValid = true;
                read.evidence = report.stateOperations[stateReadIndex].evidence;
                flow.stages.push_back(std::move(read));
                AuthorizationStageRecord gate;
                gate.stage = AuthorizationStage::StartupGate;
                gate.location = decision.location;
                gate.evidence = decision.evidence.empty()
                    ? decision.comparison : decision.evidence;
                flow.stages.push_back(std::move(gate));
            } else {
                AuthorizationStageRecord inputStage;
                inputStage.stage = AuthorizationStage::InputRead;
                inputStage.location = decision.inputLocation;
                inputStage.evidence = decision.inputEvidence.empty()
                    ? "exact cataloged input API writes the compared local buffer"
                    : decision.inputEvidence;
                flow.stages.push_back(std::move(inputStage));

                AuthorizationStageRecord compareStage;
                compareStage.stage = AuthorizationStage::Compare;
                compareStage.location = decision.comparisonLocation.addressValid ||
                                        decision.comparisonLocation.fileOffsetValid
                    ? decision.comparisonLocation : decision.location;
                compareStage.evidence = decision.comparison.empty()
                    ? decision.evidence : decision.comparison;
                flow.stages.push_back(std::move(compareStage));
            }
            addPathStages(flow);
            setFlowHonesty(flow);
            report.flows.push_back(std::move(flow));
        };

        if (decision.networkReplyFlowIndexValid)
            emitFlow(FlowKind::Reply, 0);
        if (decision.localInputFlow)
            emitFlow(FlowKind::LocalInput, 0);
        if (decision.stateReadOperationIndexValid &&
            decision.stateReadOperationIndex < report.stateOperations.size()) {
            const PersistentStateOperation& read =
                report.stateOperations[decision.stateReadOperationIndex];
            if ((read.access == PersistentStateAccess::Read ||
                 read.access == PersistentStateAccess::Open) &&
                read.startupReachable)
                emitFlow(FlowKind::Startup, decision.stateReadOperationIndex);
        }
    }

    // Link only exact durable identities.  A transform may annotate the backing
    // operation, but DPAPI descriptions are never compared as store identities.
    std::vector<bool> operationLinked(report.stateOperations.size(), false);
    for (size_t flowIndex = 0; flowIndex < report.flows.size(); ++flowIndex) {
        AuthorizationFlow& flow = report.flows[flowIndex];
        if ((!flow.networkReplyFlowIndexValid && !flow.localInputFlow) || !flow.decisionIndexValid)
            continue;

        for (size_t writeIndex = 0; writeIndex < report.stateOperations.size(); ++writeIndex) {
            const PersistentStateOperation& write = report.stateOperations[writeIndex];
            if (write.access != PersistentStateAccess::Write ||
                !write.operationComplete || !write.identity.exact ||
                !write.controllingDecisionIndexValid ||
                write.controllingDecisionIndex != flow.decisionIndex ||
                !branchLikelyAllow(flow, write.controllingBranch)) continue;
            if (flow.linkedStateWriteIndices.size() >= maxLinks) {
                complete.linksTruncated = true;
                break;
            }
            flow.linkedStateWriteIndices.push_back(writeIndex);
            AuthorizationStageRecord writeStage;
            writeStage.stage = AuthorizationStage::StateWrite;
            writeStage.location = write.location;
            writeStage.outcome = AuthorizationOutcome::LikelyAllow;
            writeStage.operationIndex = writeIndex;
            writeStage.operationIndexValid = true;
            writeStage.evidence = write.evidence;
            flow.stages.push_back(std::move(writeStage));

            for (size_t readIndex = 0; readIndex < report.stateOperations.size(); ++readIndex) {
                const PersistentStateOperation& read = report.stateOperations[readIndex];
                if ((read.access != PersistentStateAccess::Read &&
                     read.access != PersistentStateAccess::Open) ||
                    !read.operationComplete || !read.startupReachable ||
                    !PersistentStateIdentityEquivalentExact(write.identity,
                                                            read.identity)) continue;
                if (flow.linkedStartupReadIndices.size() >= maxLinks) {
                    complete.linksTruncated = true;
                    break;
                }
                if (std::find(flow.linkedStartupReadIndices.begin(),
                              flow.linkedStartupReadIndices.end(), readIndex) ==
                    flow.linkedStartupReadIndices.end()) {
                    flow.linkedStartupReadIndices.push_back(readIndex);
                    operationLinked[writeIndex] = true;
                    operationLinked[readIndex] = true;
                    if (write.transformOperationIndexValid)
                        operationLinked[write.transformOperationIndex] = true;
                    if (read.transformOperationIndexValid)
                        operationLinked[read.transformOperationIndex] = true;
                    AuthorizationStageRecord readStage;
                    readStage.stage = AuthorizationStage::StartupRead;
                    readStage.location = read.location;
                    readStage.operationIndex = readIndex;
                    readStage.operationIndexValid = true;
                    readStage.evidence = read.evidence;
                    flow.stages.push_back(std::move(readStage));
                }

                for (size_t startupFlow = 0; startupFlow < report.flows.size(); ++startupFlow) {
                    if (startupFlow == flowIndex) continue;
                    const AuthorizationFlow& candidate = report.flows[startupFlow];
                    if (!candidate.stateReadOperationIndexValid ||
                        candidate.stateReadOperationIndex != readIndex) continue;
                    if (flow.linkedStartupFlowIndices.size() >= maxLinks) {
                        complete.linksTruncated = true;
                        break;
                    }
                    if (std::find(flow.linkedStartupFlowIndices.begin(),
                                  flow.linkedStartupFlowIndices.end(), startupFlow) ==
                        flow.linkedStartupFlowIndices.end()) {
                        flow.linkedStartupFlowIndices.push_back(startupFlow);
                        for (const AuthorizationStageRecord& stage : candidate.stages) {
                            if (stage.stage == AuthorizationStage::StartupGate ||
                                stage.stage == AuthorizationStage::AllowPath ||
                                stage.stage == AuthorizationStage::DenyPath)
                                flow.stages.push_back(stage);
                        }
                    }
                }
            }
        }
        flow.rememberedAccessLinked = !flow.linkedStateWriteIndices.empty() &&
            !flow.linkedStartupReadIndices.empty() &&
            !flow.linkedStartupFlowIndices.empty();
        if (flow.rememberedAccessLinked)
            flow.honestyLabel +=
                " An exact durable write/read identity links this authorization path to a startup gate.";
    }

    for (size_t i = 0; i < report.stateOperations.size(); ++i)
        if (!operationLinked[i]) report.unlinkedOperationIndices.push_back(i);

    complete.complete = !complete.cancelled && complete.startupRootsComplete &&
        complete.callGraphComplete && complete.decisionsComplete &&
        complete.stateOperationsComplete && complete.pathsComplete &&
        !complete.functionsTruncated &&
        !complete.startupDepthTruncated &&
        !complete.callEdgesTruncated && !complete.decisionsTruncated &&
        !complete.operationsTruncated && !complete.flowsTruncated &&
        !complete.evidenceTruncated && !complete.linksTruncated &&
        !complete.provenanceTruncated;
    if (complete.cancelled) appendReason(complete.reason, "cancelled");
    if (!complete.startupRootsComplete) appendReason(complete.reason, "startup roots incomplete");
    if (!complete.callGraphComplete) appendReason(complete.reason, "call graph incomplete");
    if (!complete.decisionsComplete) appendReason(complete.reason, "decision input incomplete");
    if (!complete.stateOperationsComplete) appendReason(complete.reason, "state-operation input incomplete");
    if (!complete.pathsComplete) appendReason(complete.reason, "one or more decision paths incomplete");
    if (complete.functionsTruncated) appendReason(complete.reason, "256-function startup budget reached");
    if (complete.startupDepthTruncated) appendReason(complete.reason, "startup call-depth budget reached");
    if (complete.callEdgesTruncated) appendReason(complete.reason, "call-edge budget reached");
    if (complete.decisionsTruncated) appendReason(complete.reason, "decision budget reached");
    if (complete.operationsTruncated) appendReason(complete.reason, "state-operation budget reached");
    if (complete.flowsTruncated) appendReason(complete.reason, "authorization-flow budget reached");
    if (complete.evidenceTruncated) appendReason(complete.reason, "path-evidence budget reached");
    if (complete.linksTruncated) appendReason(complete.reason, "flow-link budget reached");
    if (complete.provenanceTruncated)
        appendReason(complete.reason, "provenance-hop budget reached");
    if (complete.reason.empty()) complete.reason = "complete";
    return report;
}

} // namespace ds
