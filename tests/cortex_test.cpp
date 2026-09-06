//
// cortex_test.cpp
// Unit test for the Cortex reasoning engine (src/Core/Cortex.cpp). Cortex is pure:
// it consumes already-computed TechScan capabilities / AlgoScan matches / discovered
// functions / strings and produces a plain-English verdict, merged behaviours,
// per-function briefs, and a deterministic Q&A (AskCortex). We build those inputs by
// hand (no BinaryFile needed — bin is null here) and assert the reasoning.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\cortex_test.cpp ^
//      src\Core\Cortex.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
//   .\cortex_test.exe
//
#include "Core/Cortex.h"
#include "Core/TechScan.h"      // Capability
#include "Core/AlgoScan.h"      // AlgoMatch, AlgoXref
#include "Core/AnalysisJobs.h"  // FuncResult, StrResult
#include "Core/BinaryFile.h"
#include "Core/CrackmeTriage.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

// A lowercase-insensitive contains.
static bool ihas(std::string s, std::string sub) {
    for (char& c : s)   c = (char)std::tolower((unsigned char)c);
    for (char& c : sub) c = (char)std::tolower((unsigned char)c);
    return s.find(sub) != std::string::npos;
}

static const CortexBehavior* behavior(const CortexReport& r, const char* cat) {
    for (const CortexBehavior& b : r.behaviors) if (b.category == cat) return &b;
    return nullptr;
}
static const CortexFuncBrief* funcAt(const CortexReport& r, uint64_t va) {
    for (const CortexFuncBrief& f : r.functions) if (f.address == va) return &f;
    return nullptr;
}

int main() {
    // ---- Build a synthetic "network + AES + packed + anti-debug" binary ----
    std::vector<Capability> caps;
    caps.push_back({ "Network I/O", "network", 0.62f, 0x401000, "Imports: connect, send, recv", "TechScan", {}, 0, true });
    caps.push_back({ "UPX packer", "packer", 0.80f, 0x402000, "Section names: UPX0, UPX1", "TechScan", {}, 0, true });
    caps.push_back({ "Anti-debugging checks", "anti-debug", 0.66f, 0x403000, "Imports: IsDebuggerPresent", "TechScan", {}, 0, true });

    std::vector<AlgoMatch> algos;
    {
        AlgoMatch a;
        a.name = "AES Rijndael S-box"; a.category = "crypto"; a.confidence = 0.9f;
        a.address = 0x410000; a.addressValid = true; a.section = ".rdata"; a.detail = "256-byte AES S-box in .rdata";
        AlgoXref x; x.funcAddress = 0x401500; x.funcAddressValid = true;
        x.funcName = "sub_401500"; x.refInsn = 0x401520; x.refInsnValid = true;
        a.referencedBy.push_back(x);
        algos.push_back(a);
    }
    {
        AlgoMatch a;
        a.name = "CRC32 table"; a.category = "checksum"; a.confidence = 0.72f;
        a.address = 0x411000; a.addressValid = true; a.section = ".rdata"; a.detail = "CRC32 lookup table";
        AlgoXref x; x.funcAddress = 0x401B00; x.funcAddressValid = true;
        x.funcName = "sub_401B00"; x.refInsn = 0x401B20; x.refInsnValid = true;
        a.referencedBy.push_back(x);
        algos.push_back(a);
    }

    std::vector<FuncResult> funcs = {
        { 0x401000, 120, "start",      false, "" },
        { 0x401500, 400, "sub_401500", false, "" },                 // crypto-referencing
        { 0x401800,  60, "read_file",  true,  "calls CreateFileW, ReadFile" },
        { 0x401900,  16, "j_send",     true,  "thunk to ws2_32.send" },
        { 0x401A00, 300, "sub_401A00", false, "" },                 // described only by annotations
        { 0x401B00, 220, "sub_401B00", false, "" },                 // checksum-referencing
        { 0x401C00,  80, "SendMessageWrapper", false, "calls user32.SendMessageW" },
        { 0x401D00,  80, "RegisterWindowClass", false, "calls user32.RegisterClassW" },
        { 0x401E00, 120, "decode_blob", false, "" },
    };

    std::vector<StrResult> strings = {
        { 0x420000, "http://c2.example.com/beacon", false },
        { 0x420100, "hello world", false },
    };

    // Per-function annotation facts (as CortexTab distils them from FuncAnnotate).
    std::vector<CortexFuncInfo> infos;
    { CortexFuncInfo fi; fi.address = 0x401A00;
      fi.summary = "reads user input and compares two strings";
      fi.patterns = { "reads user input", "string comparison" };
      fi.convention = "Microsoft x64"; infos.push_back(fi); }
    { CortexFuncInfo fi; fi.address = 0x401500;
      fi.summary = "expands the AES key schedule";
      fi.convention = "Microsoft x64"; infos.push_back(fi); }
    { CortexFuncInfo fi; fi.address = 0x401E00;
      fi.summary = "decodes a buffer";
      fi.patterns = { "XOR decode loop" }; infos.push_back(fi); }

    CrackmeTriageReport triage;
    {
        CrackmeTriageEndpoint low;
        low.display = "http://low.example/reply";
        low.host = "low.example";
        low.confidence = CrackmeTriageConfidence::Low;
        low.confidenceLabel = "Low";
        low.honestyLabel = "literal only; runtime use is unproven";
        triage.endpoints.push_back(std::move(low));

        CrackmeTriageEndpoint high;
        high.display = "https://license.example/activate";
        high.host = "license.example";
        high.confidence = CrackmeTriageConfidence::High;
        high.confidenceLabel = "High";
        high.honestyLabel = "same-function static correlation; not runtime proof";
        high.correlationIndices = { 0, 1, 2 };
        triage.endpoints.push_back(std::move(high));

        CrackmeTrail trail;
        trail.endpointIndex = 1;
        for (size_t i = 0; i < static_cast<size_t>(NetworkTrailStage::Count); ++i)
            trail.stages[i].stage = static_cast<NetworkTrailStage>(i);
        trail.stages[static_cast<size_t>(NetworkTrailStage::Connect)].apiCount = 1;
        trail.stages[static_cast<size_t>(NetworkTrailStage::Request)].correlationCount = 1;
        trail.stages[static_cast<size_t>(NetworkTrailStage::Reply)].correlationCount = 1;
        trail.stages[static_cast<size_t>(NetworkTrailStage::Decision)].correlationCount = 1;
        trail.returnFlowIndices = { 0 };
        triage.trails.push_back(std::move(trail));

        CrackmeTriageApiEvidence api;
        api.dll = "winhttp";
        api.importName = "WinHttpReadData";
        api.canonicalName = "WinHttpReadData";
        api.family = NetworkApiFamily::WinHttp;
        api.stage = NetworkStage::Read;
        triage.apis.push_back(std::move(api));

        NetworkReturnFlow flow;
        flow.apiIndex = 0; flow.apiIndexValid = true;
        flow.callsite = 0x401920; flow.callsiteValid = true;
        flow.returnValueUseKnown = true; flow.returnValueUsed = true;
        flow.useKind = NetworkReturnUseKind::Branched;
        flow.useAddress = 0x401925; flow.useAddressValid = true;
        flow.useSummary = "checked before the success/failure branch";
        flow.decisionAddress = 0x401927; flow.decisionAddressValid = true;
        triage.returnFlows.push_back(std::move(flow));

        NetworkArtifact artifact;
        artifact.kind = NetworkArtifactKind::License;
        artifact.value = "license accepted";
        artifact.endpointIndex = 1;
        artifact.endpointIndexValid = true;
        artifact.confidence = CrackmeTriageConfidence::High;
        artifact.confidenceLabel = "High";
        triage.artifacts.push_back(std::move(artifact));

        PersistentStateIdentity licenseState;
        licenseState.kind = PersistentStateKind::Registry;
        licenseState.canonicalScope = "hkcu";
        licenseState.canonicalKey = "software\\fixture";
        licenseState.canonicalValue = "licensed";
        licenseState.display = "HKCU\\Software\\Fixture / licensed";
        licenseState.valid = true;
        licenseState.exact = true;
        PersistentStateOperation stateWrite;
        stateWrite.access = PersistentStateAccess::Write;
        stateWrite.identity = licenseState;
        stateWrite.location = { 0x401960, true };
        triage.authorization.stateOperations.push_back(stateWrite);
        PersistentStateOperation startupRead;
        startupRead.access = PersistentStateAccess::Read;
        startupRead.identity = licenseState;
        startupRead.location = { 0x401110, true };
        startupRead.startupReachable = true;
        startupRead.startupDepth = 1;
        startupRead.startupDepthValid = true;
        triage.authorization.stateOperations.push_back(startupRead);

        AuthorizationFlow replyAuthorization;
        replyAuthorization.id = "reply:0";
        replyAuthorization.decisionLocation = { 0x401940, true };
        replyAuthorization.takenPath.entry = { 0x401950, true };
        replyAuthorization.takenPath.outcome = AuthorizationOutcome::LikelyAllow;
        replyAuthorization.takenPath.evidence.push_back({
            AuthorizationEvidenceKind::ApplicationContinuation,
            { 0x401970, true }, "normal application initialization", 0.9f });
        replyAuthorization.fallthroughPath.entry = { 0x401980, true };
        replyAuthorization.fallthroughPath.outcome = AuthorizationOutcome::LikelyDeny;
        replyAuthorization.fallthroughPath.evidence.push_back({
            AuthorizationEvidenceKind::ProcessTermination,
            { 0x401990, true }, "process termination", 0.95f });
        replyAuthorization.linkedStateWriteIndices = { 0 };
        replyAuthorization.linkedStartupReadIndices = { 1 };
        replyAuthorization.linkedStartupFlowIndices = { 1 };
        replyAuthorization.rememberedAccessLinked = true;
        replyAuthorization.honestyLabel = "exact registry identity; static path evidence";
        triage.authorization.flows.push_back(std::move(replyAuthorization));

        AuthorizationFlow startupAuthorization;
        startupAuthorization.id = "startup:0";
        startupAuthorization.stateReadOperationIndex = 1;
        startupAuthorization.stateReadOperationIndexValid = true;
        startupAuthorization.decisionLocation = { 0x401120, true };
        startupAuthorization.takenPath.entry = { 0x401130, true };
        startupAuthorization.takenPath.outcome = AuthorizationOutcome::LikelyAllow;
        startupAuthorization.fallthroughPath.entry = { 0x401150, true };
        startupAuthorization.fallthroughPath.outcome = AuthorizationOutcome::LikelyDeny;
        startupAuthorization.linkedStartupReadIndices = { 1 };
        startupAuthorization.honestyLabel = "startup-reachable state gate";
        triage.authorization.flows.push_back(std::move(startupAuthorization));

        AuthorizationFlow localAuthorization;
        localAuthorization.id = "local:0";
        localAuthorization.localInputFlow = true;
        localAuthorization.gateSource = AuthorizationGateSource::LocalInput;
        localAuthorization.inputLocation = { 0, true };
        localAuthorization.comparisonLocation = { 0x402018, true };
        localAuthorization.decisionLocation = { 0x40201D, true };
        localAuthorization.originExpression = "[rbp-0x80]";
        localAuthorization.expectedValue = "\"swordfish\"";
        localAuthorization.takenPath.entry = { 0x402040, true };
        localAuthorization.takenPath.outcome = AuthorizationOutcome::LikelyAllow;
        localAuthorization.fallthroughPath.entry = { 0x402060, true };
        localAuthorization.fallthroughPath.outcome =
            AuthorizationOutcome::LikelyDeny;
        localAuthorization.honestyLabel =
            "exact local input reaches a comparison and branch";
        triage.authorization.flows.push_back(std::move(localAuthorization));
    }

    CortexInput in;
    in.capabilities = &caps;
    in.algorithms   = &algos;
    in.functions    = &funcs;
    in.strings      = &strings;
    in.funcInfo     = &infos;
    in.crackmeTriage = &triage;
    in.effectiveArchitecture = "x64";

    CortexReport rep = BuildCortexReport(in);

    // ---- Behaviour merge ----
    CHECK(behavior(rep, "network")   != nullptr);
    CHECK(behavior(rep, "crypto")    != nullptr);
    CHECK(behavior(rep, "packer")    != nullptr);
    CHECK(behavior(rep, "anti-debug")!= nullptr);
    if (const CortexBehavior* c = behavior(rep, "crypto")) {
        CHECK(c->confidence >= 0.9f);
        bool aes = false; for (auto& s : c->specifics) if (has(s, "AES")) aes = true;
        CHECK(aes);                                   // algorithm name folded in as a specific
        CHECK(!c->addresses.empty());                 // referencing insn carried through
    }
    // Behaviours are sorted by descending confidence (crypto 0.9 first).
    CHECK(!rep.behaviors.empty() && rep.behaviors.front().category == "crypto");

    // ---- Headline / verdict ----
    CHECK(ihas(rep.headline, "network"));
    CHECK(ihas(rep.headline, "cryptograph") || ihas(rep.headline, "aes"));
    CHECK(ihas(rep.verdict,  "packed"));              // packer caveat present
    CHECK(ihas(rep.verdict,  "debug"));               // anti-debug note present
    CHECK(has(rep.verdict, "https://license.example/activate")); // ranked triage lead wins
    CHECK(ihas(rep.verdict, "did not contact"));

    // ---- Per-function briefs ----
    if (const CortexFuncBrief* f = funcAt(rep, 0x401000)) {
        CHECK(ihas(f->brief, "entry"));
        bool entryTag = false; for (auto& t : f->tags) if (t == "entry") entryTag = true;
        CHECK(entryTag);
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401500)) {
        CHECK(ihas(f->brief, "aes") || ihas(f->brief, "crypto"));
        bool cryptoTag = false; for (auto& t : f->tags) if (t == "crypto") cryptoTag = true;
        CHECK(cryptoTag);
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401800)) {
        CHECK(ihas(f->brief, "file"));                // canned brief for read_file
        CHECK(f->guessed);
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401900)) {
        CHECK(ihas(f->brief, "thunk"));
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401B00)) {
        CHECK(ihas(f->brief, "checksum") || ihas(f->brief, "crc32"));
        bool checksumTag = false, cryptoTag = false;
        for (auto& t : f->tags) { if (t == "checksum") checksumTag = true; if (t == "crypto") cryptoTag = true; }
        CHECK(checksumTag);
        CHECK(!cryptoTag);
    } else CHECK(false);
    // Annotation-described function: the FuncAnnotate summary becomes the brief
    // (sentence-cased), a pattern adds a tag, and the convention is carried through.
    if (const CortexFuncBrief* f = funcAt(rep, 0x401A00)) {
        CHECK(ihas(f->brief, "reads user input"));
        CHECK(f->brief.size() > 0 && f->brief[0] == 'R');       // sentence-cased
        bool inputTag = false; for (auto& t : f->tags) if (t == "input") inputTag = true;
        CHECK(inputTag);
        CHECK(f->convention == "Microsoft x64");
    } else CHECK(false);
    // Convention propagates even when the brief comes from a stronger signal (crypto).
    if (const CortexFuncBrief* f = funcAt(rep, 0x401500))
        CHECK(f->convention == "Microsoft x64");
    // Token-aware category matching: GUI APIs are not socket/registry evidence,
    // while XOR decode is encoding rather than cryptography.
    if (const CortexFuncBrief* f = funcAt(rep, 0x401C00))
        CHECK(std::find(f->tags.begin(), f->tags.end(), "network") == f->tags.end());
    else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401D00))
        CHECK(std::find(f->tags.begin(), f->tags.end(), "registry") == f->tags.end());
    else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401E00)) {
        CHECK(std::find(f->tags.begin(), f->tags.end(), "encoding") != f->tags.end());
        CHECK(std::find(f->tags.begin(), f->tags.end(), "crypto") == f->tags.end());
    } else CHECK(false);
    CHECK(ihas(rep.headline, "x64")); // effective decoder arch works without a file header

    // Highlights: entry + crypto func should rank in.
    {
        bool sawEntry = false, sawCrypto = false;
        for (const CortexFuncBrief& f : rep.highlights) {
            if (f.address == 0x401000) sawEntry = true;
            if (f.address == 0x401500) sawCrypto = true;
        }
        CHECK(sawEntry);
        CHECK(sawCrypto);
    }

    // ---- AskCortex routing ----
    CHECK(ihas(AskCortex(rep, in, "does it use crypto?"), "cryptographic"));
    CHECK(ihas(AskCortex(rep, in, "does it use crypto?"), "aes"));
    CHECK(ihas(AskCortex(rep, in, "does it use a checksum?"), "crc32"));
    const std::string endpointAnswer = AskCortex(rep, in, "which hosted reply server is used?");
    CHECK(ihas(endpointAnswer, "ranked static endpoint leads"));
    CHECK(endpointAnswer.find("license.example") < endpointAnswer.find("low.example"));
    CHECK(ihas(endpointAnswer, "not contacted"));
    CHECK(ihas(endpointAnswer, "endpoint -> connect -> request -> reply -> decision"));
    CHECK(ihas(endpointAnswer, "license accepted"));
    CHECK(ihas(endpointAnswer, "runtime proof"));
    const std::string returnAnswer = AskCortex(rep, in, "what does the server return?");
    CHECK(ihas(returnAnswer, "documented api returns"));
    CHECK(ihas(returnAnswer, "winhttpreaddata"));
    CHECK(ihas(returnAnswer, "payload buffer"));
    CHECK(ihas(returnAnswer, "branch at 0x401927"));
    CHECK(ihas(returnAnswer, "does not prove"));
    const std::string authorizationAnswer =
        AskCortex(rep, in, "where is access accepted or denied?");
    CHECK(ihas(authorizationAnswer, "authorization outcomes"));
    CHECK(ihas(authorizationAnswer, "likely allow"));
    CHECK(ihas(authorizationAnswer, "0x401940"));
    CHECK(ihas(authorizationAnswer, "candidate path entry"));
    CHECK(ihas(authorizationAnswer, "normal application initialization"));
    CHECK(ihas(authorizationAnswer, "0x401970"));
    CHECK(ihas(authorizationAnswer, "0x401990"));
    const std::string localAuthorizationAnswer =
        AskCortex(rep, in, "where is the password checked against the expected value?");
    CHECK(ihas(localAuthorizationAnswer, "local credential/input check"));
    CHECK(ihas(localAuthorizationAnswer, "input read at 0x0"));
    CHECK(ihas(localAuthorizationAnswer, "compare at 0x402018"));
    CHECK(ihas(localAuthorizationAnswer, "decision at 0x40201d"));
    CHECK(ihas(localAuthorizationAnswer, "expected value \"swordfish\""));
    CHECK(localAuthorizationAnswer.find("input read") <
              localAuthorizationAnswer.find("compare") &&
          localAuthorizationAnswer.find("compare") <
              localAuthorizationAnswer.find("decision"));
    CrackmeTriageReport noAuthorization;
    noAuthorization.authorization.completeness.complete = false;
    noAuthorization.authorization.completeness.reason =
        "decision traversal cap reached";
    CortexInput noAuthorizationInput = in;
    noAuthorizationInput.crackmeTriage = &noAuthorization;
    const std::string noAuthorizationAnswer = AskCortex(
        rep, noAuthorizationInput, "where is the password checked?");
    CHECK(ihas(noAuthorizationAnswer, "local credential/input"));
    CHECK(ihas(noAuthorizationAnswer, "partial"));
    CHECK(ihas(noAuthorizationAnswer, "decision traversal cap reached"));

    // A write alone is direction-neutral: it may be a revocation marker or an
    // attempt counter and therefore cannot be presented as the strongest
    // supporting allow effect.
    CrackmeTriageReport neutralWrite;
    AuthorizationFlow neutralWriteFlow;
    neutralWriteFlow.id = "reply:neutral-write";
    neutralWriteFlow.takenPath.entry = { 0x403000, true };
    neutralWriteFlow.takenPath.outcome = AuthorizationOutcome::LikelyAllow;
    neutralWriteFlow.takenPath.evidence.push_back({
        AuthorizationEvidenceKind::PersistentStateWrite,
        { 0x403010, true }, "writes a revocation marker / attempt counter", 1.0f });
    neutralWriteFlow.fallthroughPath.entry = { 0x403020, true };
    neutralWrite.authorization.flows.push_back(std::move(neutralWriteFlow));
    CortexInput neutralWriteInput = in;
    neutralWriteInput.crackmeTriage = &neutralWrite;
    const std::string neutralWriteAnswer = AskCortex(
        rep, neutralWriteInput, "where is access accepted or denied?");
    CHECK(ihas(neutralWriteAnswer,
               "no retained supporting downstream effect location"));
    CHECK(!ihas(neutralWriteAnswer,
                "strongest supporting downstream effect: persistent-state write"));

    // Cortex intentionally renders at most eight matching flows, but it must
    // disclose the exact omitted count instead of silently hiding the rest.
    CrackmeTriageReport manyAuthorizationFlows;
    for (size_t i = 0; i < 10; ++i) {
        AuthorizationFlow flow;
        flow.id = "local:" + std::to_string(i);
        flow.localInputFlow = true;
        flow.gateSource = AuthorizationGateSource::LocalInput;
        flow.inputLocation = { static_cast<uint64_t>(0x404000 + i * 0x10), true };
        flow.comparisonLocation = {
            static_cast<uint64_t>(0x404004 + i * 0x10), true };
        flow.decisionLocation = {
            static_cast<uint64_t>(0x404008 + i * 0x10), true };
        flow.takenPath.entry = {
            static_cast<uint64_t>(0x405000 + i * 0x10), true };
        flow.fallthroughPath.entry = {
            static_cast<uint64_t>(0x406000 + i * 0x10), true };
        manyAuthorizationFlows.authorization.flows.push_back(std::move(flow));
    }
    CortexInput manyAuthorizationInput = in;
    manyAuthorizationInput.crackmeTriage = &manyAuthorizationFlows;
    const std::string manyAuthorizationAnswer = AskCortex(
        rep, manyAuthorizationInput, "where is access accepted or denied?");
    CHECK(ihas(manyAuthorizationAnswer, "showing first 8 of 10 matching flows"));
    CHECK(ihas(manyAuthorizationAnswer, "2 flows omitted"));
    CHECK(!ihas(manyAuthorizationAnswer, "local:8 local credential"));
    const std::string rememberedAnswer =
        AskCortex(rep, in, "how is valid user access remembered for the next launch?");
    CHECK(ihas(rememberedAnswer, "remembered-access chains"));
    CHECK(ihas(rememberedAnswer, "hkcu\\software\\fixture"));
    CHECK(ihas(rememberedAnswer, "startup read"));
    CHECK(ihas(AskCortex(rep, in, "what network apis does it call?"), "network"));
    CHECK(ihas(AskCortex(rep, in, "is it packed?"), "packed"));
    CHECK(ihas(AskCortex(rep, in, "anti debugging?"), "debugger"));
    CHECK(ihas(AskCortex(rep, in, "where is the entry point"), "start"));
    CHECK(ihas(AskCortex(rep, in, "show me notable strings"), "c2.example.com"));
    CHECK(ihas(AskCortex(rep, in, "what does it do?"), "network"));    // overview -> verdict
    // Unknown intent -> fallback carries the verdict + the "Ask about" hint.
    CHECK(ihas(AskCortex(rep, in, "flibbertigibbet"), "ask about"));

    // A category that is ABSENT answers in the negative, not a fabricated yes.
    CHECK(ihas(AskCortex(rep, in, "does it touch the registry?"), "no "));

    // Per-function Q&A: by name and by explicit hex address.
    CHECK(ihas(AskCortex(rep, in, "what does sub_401A00 do?"), "sub_401a00"));
    CHECK(ihas(AskCortex(rep, in, "what does sub_401A00 do?"), "reads user input"));
    CHECK(ihas(AskCortex(rep, in, "explain 0x401a00"), "sub_401a00"));
    CHECK(ihas(AskCortex(rep, in, "explain 0x401a00"), "microsoft x64"));   // convention surfaced
    CHECK(ihas(AskCortex(rep, in, "explain this function sub_401A00"), "reads user input"));

    // Confidence is an API contract (0..1), even when an upstream source is bad.
    {
        std::vector<Capability> badCaps = {
            { "Bad confidence", "network", 4.0f, 1, "synthetic", "test", {}, 0, true }
        };
        CortexInput ci; ci.capabilities = &badCaps;
        CortexReport cr = BuildCortexReport(ci);
        CHECK(!cr.behaviors.empty() && cr.behaviors.front().confidence == 1.0f);
    }

    // A checksum-only image must not disappear from the headline or become
    // contradictory crypto evidence.
    {
        std::vector<AlgoMatch> checksumOnly(1);
        checksumOnly[0].name = "CRC32 table";
        checksumOnly[0].category = "checksum";
        checksumOnly[0].confidence = 0.8f;
        CortexInput ci; ci.algorithms = &checksumOnly;
        CortexReport cr = BuildCortexReport(ci);
        CHECK(ihas(cr.headline, "checksum") || ihas(cr.headline, "crc"));
        CHECK(ihas(AskCortex(cr, ci, "does it use crypto?"), "no "));
    }

    // ---- Clean / empty binary: no fabricated behaviours ----
    {
        CortexInput empty;
        CortexReport er = BuildCortexReport(empty);
        CHECK(er.behaviors.empty());
        CHECK(ihas(er.headline, "no notable") || ihas(er.headline, "program"));
        CHECK(!AskCortex(er, empty, "what does it do").empty());
    }

    // Address zero is a valid entry for a deliberately zero-based Raw image.  It
    // must not be mistaken for the legacy "no entry" sentinel.
    {
        const std::filesystem::path path =
            std::filesystem::temp_directory_path() / "disasmstudio_cortex_zero_entry.bin";
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            const char ret = static_cast<char>(0xC3);
            out.write(&ret, 1);
        }
        BinaryFile zero;
        CHECK(zero.loadRaw(path.string(), 0));
        CHECK(zero.setRawEntryPointVA(0));
        std::vector<FuncResult> zeroFunctions = {{ 0, 1, "sub_0", false, "" }};
        CortexInput zeroInput;
        zeroInput.bin = &zero;
        zeroInput.functions = &zeroFunctions;
        const CortexReport zeroReport = BuildCortexReport(zeroInput);
        const CortexFuncBrief* entry = funcAt(zeroReport, 0);
        CHECK(entry != nullptr);
        if (entry) {
            CHECK(ihas(entry->brief, "entry"));
            CHECK(std::find(entry->tags.begin(), entry->tags.end(), "entry") != entry->tags.end());
        }
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    // ---- Markdown render ----
    std::string md = RenderCortexMarkdown(rep);
    CHECK(has(md, "# Cortex analysis"));
    CHECK(ihas(md, "AES"));
    std::string html = RenderCortexHtml(rep);
    CHECK(has(html, "<!doctype html>"));
    CHECK(ihas(html, "AES"));
    {
        CortexReport escaped;
        escaped.headline = "<script>alert('x') & stop</script>";
        std::string safe = RenderCortexHtml(escaped);
        CHECK(has(safe, "&lt;script&gt;"));
        CHECK(has(safe, "&amp; stop"));
        CHECK(!has(safe, "<script>"));
    }

    if (g_fail == 0) std::printf("cortex_test: ALL PASSED\n");
    else             std::printf("cortex_test: %d CHEC(s) FAILED\n", g_fail);
    return g_fail != 0;
}
