#include "Core/AuthorizationAnalysis.h"
#include "Core/PersistentStateCatalog.h"

#include <algorithm>
#include <cstdio>
#include <string>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static AuthorizationLocation loc(uint64_t address, uint64_t function) {
    AuthorizationLocation result;
    result.address = address;
    result.addressValid = true;
    result.functionAddress = function;
    result.functionAddressValid = true;
    return result;
}

static AuthorizationEvidence effect(AuthorizationEvidenceKind kind,
                                    uint64_t address, uint64_t function,
                                    const char* text) {
    AuthorizationEvidence result;
    result.kind = kind;
    result.location = loc(address, function);
    result.text = text;
    return result;
}

static bool hasStage(const AuthorizationFlow& flow, AuthorizationStage stage) {
    return std::any_of(flow.stages.begin(), flow.stages.end(),
        [stage](const AuthorizationStageRecord& row) { return row.stage == stage; });
}

static const AuthorizationFlow* flowById(const AuthorizationAnalysisReport& report,
                                         const char* id) {
    for (const auto& flow : report.flows) if (flow.id == id) return &flow;
    return nullptr;
}

static void outcomeScoring() {
    AuthorizationAnalysisInput input;
    AuthorizationDecisionInput decision;
    decision.location = loc(0, 0); // valid VA zero must remain navigable
    decision.networkReplyFlowIndex = 7;
    decision.networkReplyFlowIndexValid = true;
    decision.comparison = "test reply marker";
    decision.takenPath.entry = loc(0x10, 0);
    decision.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ProcessTermination, 0x10, 0, "ExitProcess"));
    decision.fallthroughPath.entry = loc(0x20, 0);
    decision.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x20, 0,
        "enters the main UI loop"));
    input.decisions.push_back(decision);

    const auto report = RunAuthorizationAnalysis(input);
    CHECK(report.flows.size() == 1);
    CHECK(report.flows[0].decisionLocation.addressValid);
    CHECK(report.flows[0].decisionLocation.address == 0);
    CHECK(report.flows[0].takenPath.outcome == AuthorizationOutcome::LikelyDeny);
    CHECK(report.flows[0].fallthroughPath.outcome ==
          AuthorizationOutcome::LikelyAllow);
    CHECK(report.flows[0].confidence >= 0.89f);
    CHECK(hasStage(report.flows[0], AuthorizationStage::ReplyCheck));
    CHECK(hasStage(report.flows[0], AuthorizationStage::AllowPath));
    CHECK(hasStage(report.flows[0], AuthorizationStage::DenyPath));
    bool exactDenyEffect = false, exactAllowEffect = false;
    for (const AuthorizationStageRecord& stage : report.flows[0].stages) {
        exactDenyEffect |= stage.stage == AuthorizationStage::DenyPath &&
                           stage.location.addressValid && stage.location.address == 0x10 &&
                           stage.evidence == "ExitProcess";
        exactAllowEffect |= stage.stage == AuthorizationStage::AllowPath &&
                            stage.location.addressValid && stage.location.address == 0x20 &&
                            stage.evidence == "enters the main UI loop";
    }
    CHECK(exactDenyEffect);
    CHECK(exactAllowEffect);

    // Contradictory strong effects cannot be promoted.
    input.decisions[0].takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x11, 0,
        "also enters application code"));
    const auto contradictory = RunAuthorizationAnalysis(input);
    CHECK(contradictory.flows[0].takenPath.outcome ==
          AuthorizationOutcome::Unknown);

    // Two distinct medium indicators satisfy the corroboration rule.
    input.decisions[0].takenPath.evidence.clear();
    input.decisions[0].takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::FailureIndicator, 0x30, 0, "invalid license"));
    input.decisions[0].takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::FailureIndicator, 0x31, 0, "access denied dialog"));
    const auto corroborated = RunAuthorizationAnalysis(input);
    CHECK(corroborated.flows[0].takenPath.outcome ==
          AuthorizationOutcome::LikelyDeny);

    input.limits.maxEvidencePerPath = 1;
    const auto truncated = RunAuthorizationAnalysis(input);
    CHECK(truncated.flows[0].takenPath.outcome == AuthorizationOutcome::Unknown);
    CHECK(truncated.completeness.evidenceTruncated);
    CHECK(!truncated.completeness.complete);
}

static void fullRememberedAccessChain() {
    AuthorizationAnalysisInput input;
    input.startupRoots.push_back(loc(0, 0));
    AuthorizationCallEdgeInput edge;
    edge.caller = 0;
    edge.callerValid = true;
    edge.callee = 0x1000;
    edge.calleeValid = true;
    input.callEdges.push_back(edge);

    const PersistentStateIdentity identity = CanonicalizeRegistryIdentity(
        "HKCU", "Software\\Acme\\Crackme", "Licensed");

    PersistentStateOperationInput protect;
    protect.access = PersistentStateAccess::Protect;
    protect.identity = MakeDpapiTransformIdentity("license token");
    protect.location = loc(0x2110, 0x2000);
    protect.apiDll = "crypt32";
    protect.apiName = "CryptProtectData";
    input.stateOperations.push_back(protect); // 0

    PersistentStateOperationInput write;
    write.access = PersistentStateAccess::Write;
    write.identity = identity;
    write.location = loc(0x2120, 0x2000);
    write.apiDll = "advapi32";
    write.apiName = "RegSetValueExW";
    write.evidence = "writes the licensed marker after the reply branch";
    write.controllingDecisionIndex = 0;
    write.controllingDecisionIndexValid = true;
    write.controllingBranch = AuthorizationBranch::Taken;
    write.transformOperationIndex = 0;
    write.transformOperationIndexValid = true;
    input.stateOperations.push_back(write); // 1

    PersistentStateOperationInput unprotect;
    unprotect.access = PersistentStateAccess::Unprotect;
    unprotect.identity = MakeDpapiTransformIdentity("license token");
    unprotect.location = loc(0x1110, 0x1000);
    unprotect.apiDll = "crypt32";
    unprotect.apiName = "CryptUnprotectData";
    input.stateOperations.push_back(unprotect); // 2

    PersistentStateOperationInput read;
    read.access = PersistentStateAccess::Read;
    read.identity = identity;
    read.location = loc(0x1100, 0x1000);
    read.apiDll = "advapi32";
    read.apiName = "RegQueryValueExW";
    read.evidence = "reads the licensed marker during startup";
    read.transformOperationIndex = 2;
    read.transformOperationIndexValid = true;
    input.stateOperations.push_back(read); // 3

    AuthorizationDecisionInput reply;
    reply.location = loc(0x2050, 0x2000);
    reply.networkReplyFlowIndex = 4;
    reply.networkReplyFlowIndexValid = true;
    reply.evidence = "reply buffer compared with expected marker";
    reply.takenPath.entry = loc(0x2100, 0x2000);
    reply.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x2130, 0x2000,
        "continues into licensed application initialization"));
    reply.fallthroughPath.entry = loc(0x2200, 0x2000);
    reply.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ProcessTermination, 0x2210, 0x2000,
        "rejects and exits"));
    input.decisions.push_back(reply);

    AuthorizationDecisionInput startup;
    startup.location = loc(0x1150, 0x1000);
    startup.stateReadOperationIndex = 3;
    startup.stateReadOperationIndexValid = true;
    startup.evidence = "tests persisted licensed marker";
    startup.takenPath.entry = loc(0x1200, 0x1000);
    startup.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x1200, 0x1000,
        "continues into normal application initialization"));
    startup.fallthroughPath.entry = loc(0x1180, 0x1000);
    startup.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::EarlyFailureReturn, 0x1180, 0x1000,
        "returns launch failure"));
    input.decisions.push_back(startup);

    const auto report = RunAuthorizationAnalysis(input);
    CHECK(report.completeness.complete);
    CHECK(report.completeness.startupFunctionsVisited == 2);
    CHECK(report.stateOperations.size() == 4);
    CHECK(report.stateOperations[3].startupReachable);
    CHECK(report.stateOperations[3].startupDepthValid);
    CHECK(report.stateOperations[3].startupDepth == 1);

    const AuthorizationFlow* replyFlow = flowById(report, "reply:0");
    const AuthorizationFlow* startupFlow = flowById(report, "startup:1");
    CHECK(replyFlow != nullptr);
    CHECK(startupFlow != nullptr);
    if (replyFlow) {
        CHECK(replyFlow->takenPath.outcome == AuthorizationOutcome::LikelyAllow);
        CHECK(replyFlow->fallthroughPath.outcome == AuthorizationOutcome::LikelyDeny);
        CHECK(replyFlow->linkedStateWriteIndices.size() == 1);
        CHECK(replyFlow->linkedStateWriteIndices[0] == 1);
        CHECK(replyFlow->linkedStartupReadIndices.size() == 1);
        CHECK(replyFlow->linkedStartupReadIndices[0] == 3);
        CHECK(replyFlow->linkedStartupFlowIndices.size() == 1);
        CHECK(replyFlow->rememberedAccessLinked);
        CHECK(hasStage(*replyFlow, AuthorizationStage::StateWrite));
        CHECK(hasStage(*replyFlow, AuthorizationStage::StartupRead));
        CHECK(hasStage(*replyFlow, AuthorizationStage::StartupGate));
    }
    if (startupFlow) {
        CHECK(startupFlow->takenPath.outcome == AuthorizationOutcome::LikelyAllow);
        CHECK(startupFlow->fallthroughPath.outcome == AuthorizationOutcome::LikelyDeny);
        CHECK(startupFlow->stateReadOperationIndexValid);
        CHECK(startupFlow->stateReadOperationIndex == 3);
    }
    CHECK(report.unlinkedOperationIndices.empty());
}

static void exactIdentityAndEndpointFreeRules() {
    AuthorizationAnalysisInput input;
    input.startupRoots.push_back(loc(0x1000, 0x1000));

    PersistentStateOperationInput write;
    write.access = PersistentStateAccess::Write;
    write.identity = CanonicalizeRegistryIdentity(
        "HKCU", "Software\\Acme", "Licensed");
    write.location = loc(0x2010, 0x2000);
    write.controllingDecisionIndex = 0;
    write.controllingDecisionIndexValid = true;
    write.controllingBranch = AuthorizationBranch::Taken;
    input.stateOperations.push_back(write);

    PersistentStateOperationInput read;
    read.access = PersistentStateAccess::Read;
    read.identity = CanonicalizeRegistryIdentity(
        "HKCU", "Software\\Acme", "Trial"); // deliberately different value
    read.location = loc(0x1010, 0x1000);
    input.stateOperations.push_back(read);

    AuthorizationDecisionInput reply;
    reply.location = loc(0x2000, 0x2000);
    reply.networkReplyFlowIndex = 0;
    reply.networkReplyFlowIndexValid = true;
    reply.takenPath.entry = loc(0x2010, 0x2000);
    reply.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x2020, 0x2000,
        "continues into normal application initialization"));
    reply.fallthroughPath.entry = loc(0x2050, 0x2000);
    reply.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ProcessTermination, 0x2060, 0x2000, "exit"));
    input.decisions.push_back(reply);

    AuthorizationDecisionInput startup;
    startup.location = loc(0x1020, 0x1000);
    startup.stateReadOperationIndex = 1;
    startup.stateReadOperationIndexValid = true;
    startup.takenPath.entry = loc(0x1040, 0x1000);
    startup.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x1040, 0x1000,
        "normal startup"));
    startup.fallthroughPath.entry = loc(0x1060, 0x1000);
    startup.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::EarlyFailureReturn, 0x1060, 0x1000,
        "startup returns"));
    input.decisions.push_back(startup);

    const auto report = RunAuthorizationAnalysis(input);
    CHECK(flowById(report, "startup:1") != nullptr); // no endpoint required
    const AuthorizationFlow* replyFlow = flowById(report, "reply:0");
    CHECK(replyFlow && replyFlow->linkedStateWriteIndices.size() == 1);
    CHECK(replyFlow && replyFlow->linkedStartupReadIndices.empty());
    CHECK(replyFlow && !replyFlow->rememberedAccessLinked);
    CHECK(report.unlinkedOperationIndices.size() == 2);

    input.stateOperations[1].identity = CanonicalizeFileIdentity("license.dat");
    input.stateOperations[0].identity = CanonicalizeFileIdentity("license.dat");
    const auto relative = RunAuthorizationAnalysis(input);
    CHECK(!relative.flows[0].rememberedAccessLinked);
    CHECK(relative.unlinkedOperationIndices.size() == 2);
}

static void startupOpenGate() {
    AuthorizationAnalysisInput input;
    input.startupRoots.push_back(loc(0x1000, 0x1000));
    const auto identity = CanonicalizeFileIdentity(
        "C:\\ProgramData\\Acme\\license.dat");

    PersistentStateOperationInput write;
    write.access = PersistentStateAccess::Write;
    write.identity = identity;
    write.location = loc(0x2020, 0x2000);
    write.controllingDecisionIndex = 0;
    write.controllingDecisionIndexValid = true;
    write.controllingBranch = AuthorizationBranch::Taken;
    input.stateOperations.push_back(write);

    PersistentStateOperationInput open;
    open.access = PersistentStateAccess::Open;
    open.identity = identity;
    open.location = loc(0x1010, 0x1000);
    open.apiDll = "kernel32";
    open.apiName = "CreateFileW";
    open.evidence = "tests whether the remembered-access file exists";
    input.stateOperations.push_back(open);

    AuthorizationDecisionInput reply;
    reply.location = loc(0x2010, 0x2000);
    reply.networkReplyFlowIndex = 2;
    reply.networkReplyFlowIndexValid = true;
    reply.takenPath.entry = loc(0x2020, 0x2000);
    reply.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x2030, 0x2000,
        "continues into normal application initialization"));
    reply.fallthroughPath.entry = loc(0x2060, 0x2000);
    reply.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ProcessTermination, 0x2060, 0x2000, "exit"));
    input.decisions.push_back(reply);

    AuthorizationDecisionInput gate;
    gate.location = loc(0x1020, 0x1000);
    gate.stateReadOperationIndex = 1;
    gate.stateReadOperationIndexValid = true;
    gate.takenPath.entry = loc(0x1040, 0x1000);
    gate.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x1040, 0x1000,
        "normal startup"));
    gate.fallthroughPath.entry = loc(0x1060, 0x1000);
    gate.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::EarlyFailureReturn, 0x1060, 0x1000,
        "launch denied"));
    input.decisions.push_back(gate);

    const auto report = RunAuthorizationAnalysis(input);
    const AuthorizationFlow* replyFlow = flowById(report, "reply:0");
    const AuthorizationFlow* startupFlow = flowById(report, "startup:1");
    CHECK(startupFlow != nullptr);
    CHECK(startupFlow && startupFlow->stateReadOperationIndex == 1);
    CHECK(report.stateOperations[1].access == PersistentStateAccess::Open);
    CHECK(report.stateOperations[1].startupReachable);
    CHECK(replyFlow && replyFlow->rememberedAccessLinked);
    CHECK(replyFlow && replyFlow->linkedStartupReadIndices.size() == 1);
    CHECK(replyFlow && replyFlow->linkedStartupReadIndices[0] == 1);
}

static void boundsAndCancellation() {
    AuthorizationAnalysisInput input;
    input.startupRoots.push_back(loc(0, 0));
    for (uint64_t i = 0; i < 9; ++i) {
        AuthorizationCallEdgeInput edge;
        edge.caller = i;
        edge.callerValid = true;
        edge.callee = i + 1;
        edge.calleeValid = true;
        input.callEdges.push_back(edge);
    }
    PersistentStateOperationInput read;
    read.access = PersistentStateAccess::Read;
    read.identity = CanonicalizeRegistryIdentity("HKCU", "Software\\Acme", "Valid");
    read.location = loc(9, 9);
    input.stateOperations.push_back(read);
    AuthorizationDecisionInput gate;
    gate.location = loc(9, 9);
    gate.stateReadOperationIndex = 0;
    gate.stateReadOperationIndexValid = true;
    gate.takenPath.entry = loc(9, 9);
    gate.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 9, 9, "continue"));
    input.decisions.push_back(gate);

    const auto depth = RunAuthorizationAnalysis(input);
    CHECK(depth.completeness.startupDepthTruncated);
    CHECK(!depth.completeness.complete);
    CHECK(!depth.stateOperations[0].startupReachable);
    CHECK(depth.flows.empty());

    bool cancel = true;
    input.cancelled = [&cancel] { return cancel; };
    const auto stopped = RunAuthorizationAnalysis(input);
    CHECK(stopped.completeness.cancelled);
    CHECK(!stopped.completeness.complete);
    CHECK(stopped.flows.empty());
}

static void invalidCrossReferencesRemainIncomplete() {
    AuthorizationAnalysisInput input;
    PersistentStateOperationInput operation;
    operation.access = PersistentStateAccess::Write;
    operation.identity = CanonicalizeRegistryIdentity(
        "HKCU", "Software\\Acme", "Valid");
    operation.location = loc(0x2010, 0x2000);
    operation.controllingDecisionIndex = 99;
    operation.controllingDecisionIndexValid = true;
    operation.transformOperationIndex = 88;
    operation.transformOperationIndexValid = true;
    input.stateOperations.push_back(operation);

    const auto report = RunAuthorizationAnalysis(input);
    CHECK(!report.completeness.complete);
    CHECK(!report.completeness.stateOperationsComplete);
    CHECK(report.stateOperations.size() == 1);
    CHECK(!report.stateOperations[0].operationComplete);
    CHECK(!report.stateOperations[0].controllingDecisionIndexValid);
    CHECK(!report.stateOperations[0].transformOperationIndexValid);
}

static void incompleteOperationsNeverLink() {
    AuthorizationAnalysisInput input;
    input.startupRoots.push_back(loc(0x1000, 0x1000));
    const PersistentStateIdentity identity = CanonicalizeRegistryIdentity(
        "HKCU", "Software\\Acme", "Valid");

    PersistentStateOperationInput write;
    write.access = PersistentStateAccess::Write;
    write.identity = identity;
    write.location = loc(0x2010, 0x2000);
    write.controllingDecisionIndex = 0;
    write.controllingDecisionIndexValid = true;
    write.controllingBranch = AuthorizationBranch::Taken;
    write.operationComplete = false;
    input.stateOperations.push_back(write);

    PersistentStateOperationInput read;
    read.access = PersistentStateAccess::Read;
    read.identity = identity;
    read.location = loc(0x1010, 0x1000);
    input.stateOperations.push_back(read);

    AuthorizationDecisionInput reply;
    reply.location = loc(0x2000, 0x2000);
    reply.networkReplyFlowIndex = 0;
    reply.networkReplyFlowIndexValid = true;
    reply.takenPath.entry = loc(0x2010, 0x2000);
    reply.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x2020, 0x2000,
        "normal application initialization"));
    input.decisions.push_back(reply);

    const auto report = RunAuthorizationAnalysis(input);
    CHECK(!report.completeness.complete);
    CHECK(report.flows.size() == 1);
    CHECK(!report.flows[0].rememberedAccessLinked);
    CHECK(report.flows[0].linkedStateWriteIndices.empty());
    CHECK(report.unlinkedOperationIndices.size() == 2);

    // An incomplete write cannot become the sole strong allow effect. It stays
    // visible as unlinked evidence, but the path verdict remains Unknown.
    input.decisions[0].takenPath.evidence.clear();
    const auto incompleteOnly = RunAuthorizationAnalysis(input);
    CHECK(incompleteOnly.flows.size() == 1);
    CHECK(incompleteOnly.flows[0].takenPath.outcome ==
          AuthorizationOutcome::Unknown);
}

static void denialMarkerWriteDoesNotAuthorize() {
    AuthorizationAnalysisInput input;
    input.startupRoots.push_back(loc(0x1000, 0x1000));
    const PersistentStateIdentity identity = CanonicalizeRegistryIdentity(
        "HKCU", "Software\\Acme", "Licensed");

    PersistentStateOperationInput write;
    write.access = PersistentStateAccess::Write;
    write.identity = identity;
    write.location = loc(0x2010, 0x2000);
    write.evidence = "failure branch writes Licensed=0 denial marker";
    write.controllingDecisionIndex = 0;
    write.controllingDecisionIndexValid = true;
    write.controllingBranch = AuthorizationBranch::Taken;
    input.stateOperations.push_back(write);

    PersistentStateOperationInput read;
    read.access = PersistentStateAccess::Read;
    read.identity = identity;
    read.location = loc(0x1010, 0x1000);
    input.stateOperations.push_back(read);

    AuthorizationDecisionInput reply;
    reply.location = loc(0x2000, 0x2000);
    reply.networkReplyFlowIndex = 0;
    reply.networkReplyFlowIndexValid = true;
    reply.takenPath.entry = loc(0x2010, 0x2000);
    reply.fallthroughPath.entry = loc(0x2050, 0x2000);
    reply.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ProcessTermination, 0x2060, 0x2000,
        "other branch also terminates"));
    input.decisions.push_back(reply);

    AuthorizationDecisionInput startup;
    startup.location = loc(0x1020, 0x1000);
    startup.stateReadOperationIndex = 1;
    startup.stateReadOperationIndexValid = true;
    startup.takenPath.entry = loc(0x1040, 0x1000);
    startup.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation, 0x1040, 0x1000,
        "normal startup"));
    startup.fallthroughPath.entry = loc(0x1060, 0x1000);
    input.decisions.push_back(startup);

    const AuthorizationAnalysisReport report = RunAuthorizationAnalysis(input);
    const AuthorizationFlow* replyFlow = flowById(report, "reply:0");
    CHECK(replyFlow != nullptr);
    CHECK(replyFlow && replyFlow->takenPath.outcome ==
          AuthorizationOutcome::Unknown);
    CHECK(replyFlow && replyFlow->linkedStateWriteIndices.empty());
    CHECK(replyFlow && replyFlow->linkedStartupReadIndices.empty());
    CHECK(replyFlow && !replyFlow->rememberedAccessLinked);
}

static void provenanceBounds() {
    AuthorizationAnalysisInput input;
    input.limits.maxProvenanceHopsPerFlow = 3;
    AuthorizationDecisionInput decision;
    decision.location = loc(0x9000, 0x9000);
    decision.networkReplyFlowIndex = 1;
    decision.networkReplyFlowIndexValid = true;
    decision.gateSource = AuthorizationGateSource::PersistentOutput;
    decision.entitlementKind = AuthorizationEntitlementKind::Pro;
    decision.entitlementLabel = "pro";
    decision.originExpression = "[rbp-0x20]";
    decision.expectedValue = "\"pro\"";
    for (size_t i = 0; i < 10; ++i) {
        ValueProvenanceHop hop;
        hop.kind = i == 0 ? ValueProvenanceHopKind::Origin
                          : ValueProvenanceHopKind::Copy;
        hop.address = 0x9000 + i;
        hop.addressValid = true;
        decision.provenance.push_back(std::move(hop));
    }
    input.decisions.push_back(std::move(decision));
    const AuthorizationAnalysisReport report = RunAuthorizationAnalysis(input);
    CHECK(report.flows.size() == 1);
    CHECK(report.flows[0].provenance.size() == 3);
    CHECK(!report.flows[0].provenanceComplete);
    CHECK(report.flows[0].provenanceIncompleteReason.find("hop cap") !=
          std::string::npos);
    CHECK(report.flows[0].gateSource ==
          AuthorizationGateSource::PersistentOutput);
    CHECK(report.flows[0].entitlementKind ==
          AuthorizationEntitlementKind::Pro);
    CHECK(report.completeness.provenanceTruncated);
    CHECK(!report.completeness.complete);
    CHECK(report.completeness.reason.find("provenance-hop") !=
          std::string::npos);
}

static void localCredentialValidationFlow() {
    AuthorizationAnalysisInput input;
    input.startupRoots.push_back(loc(0x2000, 0x2000));

    const PersistentStateIdentity identity = CanonicalizeRegistryIdentity(
        "HKCU", "Software\\Acme\\Crackme", "Licensed");
    PersistentStateOperationInput write;
    write.access = PersistentStateAccess::Write;
    write.identity = identity;
    write.location = loc(0x1080, 0x1000);
    write.evidence = "stores the license marker after the local check";
    write.controllingDecisionIndex = 0;
    write.controllingDecisionIndexValid = true;
    write.controllingBranch = AuthorizationBranch::Taken;
    input.stateOperations.push_back(write);

    PersistentStateOperationInput read;
    read.access = PersistentStateAccess::Read;
    read.identity = identity;
    read.location = loc(0x2010, 0x2000);
    read.evidence = "reads the same license marker during startup";
    input.stateOperations.push_back(read);

    AuthorizationDecisionInput decision;
    decision.localInputFlow = true;
    decision.gateSource = AuthorizationGateSource::LocalInput;
    decision.inputLocation = loc(0, 0x1000); // valid VA zero is not "missing"
    decision.comparisonLocation = loc(0x1018, 0x1000);
    decision.location = loc(0x101D, 0x1000);
    decision.inputEvidence =
        "user32!GetDlgItemTextA writes the local password buffer";
    decision.comparison = "strcmp(local password, \"swordfish\")";
    decision.evidence =
        "the exact input buffer reaches an equality comparator and branch";
    decision.originExpression = "[rbp-0x80]";
    decision.expectedValue = "\"swordfish\"";
    decision.takenPath.entry = loc(0x1040, 0x1000);
    decision.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation,
        0x1040, 0x1000, "opens the protected application view"));
    decision.fallthroughPath.entry = loc(0x1060, 0x1000);
    decision.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::FailureIndicator,
        0x1060, 0x1000, "shows the invalid password dialog"));
    decision.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::EarlyFailureReturn,
        0x1068, 0x1000, "returns before protected initialization"));
    input.decisions.push_back(std::move(decision));

    AuthorizationDecisionInput startup;
    startup.location = loc(0x2030, 0x2000);
    startup.stateReadOperationIndex = 1;
    startup.stateReadOperationIndexValid = true;
    startup.evidence = "tests the remembered local license marker";
    startup.takenPath.entry = loc(0x2040, 0x2000);
    startup.takenPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::ApplicationContinuation,
        0x2040, 0x2000, "continues into the protected application"));
    startup.fallthroughPath.entry = loc(0x2060, 0x2000);
    startup.fallthroughPath.evidence.push_back(effect(
        AuthorizationEvidenceKind::EarlyFailureReturn,
        0x2060, 0x2000, "returns before protected initialization"));
    input.decisions.push_back(std::move(startup));

    const AuthorizationAnalysisReport report = RunAuthorizationAnalysis(input);
    CHECK(report.flows.size() == 2);
    const AuthorizationFlow* flow = flowById(report, "local:0");
    CHECK(flow != nullptr);
    if (!flow) return;
    CHECK(flow->localInputFlow);
    CHECK(!flow->networkReplyFlowIndexValid);
    CHECK(!flow->stateReadOperationIndexValid);
    CHECK(flow->gateSource == AuthorizationGateSource::LocalInput);
    CHECK(flow->inputLocation.addressValid && flow->inputLocation.address == 0);
    CHECK(flow->comparisonLocation.addressValid &&
          flow->comparisonLocation.address == 0x1018);
    CHECK(flow->decisionLocation.addressValid &&
          flow->decisionLocation.address == 0x101D);
    CHECK(flow->originExpression == "[rbp-0x80]");
    CHECK(flow->expectedValue == "\"swordfish\"");
    CHECK(flow->takenPath.outcome == AuthorizationOutcome::LikelyAllow);
    CHECK(flow->fallthroughPath.outcome == AuthorizationOutcome::LikelyDeny);
    CHECK(hasStage(*flow, AuthorizationStage::InputRead));
    CHECK(hasStage(*flow, AuthorizationStage::Compare));
    CHECK(hasStage(*flow, AuthorizationStage::AllowPath));
    CHECK(hasStage(*flow, AuthorizationStage::DenyPath));
    CHECK(flow->linkedStateWriteIndices.size() == 1);
    CHECK(flow->linkedStateWriteIndices[0] == 0);
    CHECK(flow->linkedStartupReadIndices.size() == 1);
    CHECK(flow->linkedStartupReadIndices[0] == 1);
    CHECK(flow->linkedStartupFlowIndices.size() == 1);
    CHECK(flow->rememberedAccessLinked);
    CHECK(hasStage(*flow, AuthorizationStage::StateWrite));
    CHECK(hasStage(*flow, AuthorizationStage::StartupRead));
    CHECK(hasStage(*flow, AuthorizationStage::StartupGate));
    CHECK(report.unlinkedOperationIndices.empty());
    CHECK(report.completeness.complete);
}

static void invalidLocalLocationsStayIncomplete() {
    AuthorizationAnalysisInput input;
    AuthorizationDecisionInput decision;
    decision.localInputFlow = true;
    decision.gateSource = AuthorizationGateSource::LocalInput;
    // Addresses default to zero, but their validity bits deliberately remain
    // false. A numeric zero alone must never masquerade as navigable evidence.
    input.decisions.push_back(std::move(decision));

    const AuthorizationAnalysisReport report = RunAuthorizationAnalysis(input);
    CHECK(report.flows.size() == 1);
    CHECK(!report.completeness.complete);
    CHECK(!report.completeness.decisionsComplete);
    CHECK(!report.completeness.pathsComplete);
    CHECK(report.completeness.reason.find("decision input incomplete") !=
          std::string::npos);
    CHECK(!report.flows[0].provenanceComplete);
    CHECK(report.flows[0].provenanceIncompleteReason.find("not navigable") !=
          std::string::npos);
}

int main() {
    CHECK(std::string(AuthorizationOutcomeText(
              AuthorizationOutcome::LikelyAllow)) == "Likely allow");
    CHECK(std::string(AuthorizationStageText(
              AuthorizationStage::StartupGate)) == "Startup gate");
    CHECK(std::string(AuthorizationStageText(
              AuthorizationStage::InputRead)) == "Input read");
    CHECK(std::string(AuthorizationGateSourceText(
              AuthorizationGateSource::LocalInput)) == "Local input buffer");
    CHECK(std::string(PersistentStateKindText(
              PersistentStateKind::Credential)) == "Credential Manager");
    outcomeScoring();
    fullRememberedAccessChain();
    exactIdentityAndEndpointFreeRules();
    startupOpenGate();
    boundsAndCancellation();
    invalidCrossReferencesRemainIncomplete();
    incompleteOperationsNeverLink();
    denialMarkerWriteDoesNotAuthorize();
    provenanceBounds();
    localCredentialValidationFlow();
    invalidLocalLocationsStayIncomplete();
    if (failures) return 1;
    std::puts("authorization analysis tests passed");
    return 0;
}
