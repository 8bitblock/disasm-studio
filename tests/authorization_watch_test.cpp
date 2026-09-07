#include "Core/AuthorizationWatch.h"
#include "Core/CodeByteSignatureBuilder.h"
#include "Core/NetworkObservation.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <thread>
#include <vector>

#ifdef DS_AUTHORIZATION_WATCH_LIVE_TEST
#include "Core/Debugger.h"
#include <windows.h>
#include <chrono>
#include <string>
#endif

using namespace ds;

namespace {

AuthorizationWatchSite site(uint64_t rva, uint64_t flow,
                            AuthorizationWatchOutcome outcome,
                            const char* label) {
    AuthorizationWatchSite value;
    value.moduleRva = rva;
    value.flowId = flow;
    value.stage = outcome == AuthorizationWatchOutcome::Allow ||
                          outcome == AuthorizationWatchOutcome::Deny
                      ? AuthorizationWatchStage::Outcome
                      : AuthorizationWatchStage::CandidatePath;
    value.outcome = outcome;
    value.label = label;
    value.strongOutcome = outcome == AuthorizationWatchOutcome::Allow ||
                          outcome == AuthorizationWatchOutcome::Deny;
    return value;
}

AttachedModuleIdentity image(uint64_t base, uint64_t size,
                             uint64_t loadGeneration = 1) {
    return { base, size, "fixture.exe", "C:\\fixtures\\fixture.exe",
             loadGeneration };
}

} // namespace

#ifdef DS_AUTHORIZATION_WATCH_LIVE_TEST
static volatile LONG gLiveAuthorizationHits = 0;

__declspec(noinline) static void liveAuthorizationProbe() {
    InterlockedIncrement(&gLiveAuthorizationHits);
}

__declspec(noinline) static void liveAuthorizationProbeCallsite() {
    liveAuthorizationProbe();
    (void)gLiveAuthorizationHits; // retain a real call; prevent tail-call folding
}

__declspec(noinline) static void liveAuthorizationMutationProbe() {
    InterlockedAdd(&gLiveAuthorizationHits, 3);
}

__declspec(noinline) static void liveAuthorizationMutationAlternate() {
    InterlockedAdd(&gLiveAuthorizationHits, 5);
}

__declspec(noinline) static void liveAuthorizationMutationCallsite() {
    liveAuthorizationMutationProbe();
    (void)gLiveAuthorizationHits;
}

__declspec(noinline) static void liveAuthorizationSharedMutationProbe() {
    InterlockedAdd(&gLiveAuthorizationHits, 7);
}

__declspec(noinline) static void liveAuthorizationSharedMutationAlternate() {
    InterlockedAdd(&gLiveAuthorizationHits, 11);
}

__declspec(noinline) static void liveAuthorizationSharedMutationCallsite() {
    liveAuthorizationSharedMutationProbe();
    (void)gLiveAuthorizationHits;
}

__declspec(noinline) static LONG liveAuthorizationStateApi() {
    InterlockedIncrement(&gLiveAuthorizationHits);
    return 0; // ZeroIsSuccess contract
}

__declspec(noinline) static LONG liveAuthorizationCallsite() {
    volatile LONG result = liveAuthorizationStateApi();
    return result;
}

static uint64_t findDirectCallTo(const void* caller, const void* callee) {
    const auto* code = static_cast<const uint8_t*>(caller);
    const uint64_t target = reinterpret_cast<uint64_t>(callee);
    for (size_t i = 0; i + 5 <= 128; ++i) {
        // In the launched child an Authorization Watch probe may already own the
        // first byte. Its saved E8 displacement remains readable in the tail.
        if (code[i] != 0xE8 && code[i] != 0xCC) continue;
        int32_t displacement = 0;
        std::memcpy(&displacement, code + i + 1, sizeof(displacement));
        const uint64_t continuation =
            reinterpret_cast<uint64_t>(code + i + 5);
        if (continuation + static_cast<int64_t>(displacement) == target)
            return reinterpret_cast<uint64_t>(code + i);
    }
    return 0;
}

static bool redirectDirectCallTail(const void* caller, const void* currentCallee,
                                   const void* replacementCallee) {
    const uint64_t call = findDirectCallTo(caller, currentCallee);
    if (!call) return false;
    const int64_t delta = static_cast<int64_t>(
        reinterpret_cast<uint64_t>(replacementCallee)) -
        static_cast<int64_t>(call + 5);
    if (delta < (std::numeric_limits<int32_t>::min)() ||
        delta > (std::numeric_limits<int32_t>::max)())
        return false;
    DWORD oldProtection = 0;
    auto* displacement = reinterpret_cast<void*>(call + 1);
    if (!VirtualProtect(displacement, sizeof(int32_t), PAGE_EXECUTE_READWRITE,
                        &oldProtection))
        return false;
    const int32_t encoded = static_cast<int32_t>(delta);
    std::memcpy(displacement, &encoded, sizeof(encoded));
    FlushInstructionCache(GetCurrentProcess(),
                          reinterpret_cast<const void*>(call), 5);
    DWORD ignored = 0;
    return VirtualProtect(displacement, sizeof(int32_t), oldProtection,
                          &ignored) != 0;
}

static CodeByteSignature liveExactSignature(uint64_t address, size_t length) {
    assert(address != 0 && length != 0 && length <= kCodeByteSignatureMax);
    CodeByteSignature signature;
    signature.length = static_cast<uint8_t>(length);
    std::memcpy(signature.expected.data(),
                reinterpret_cast<const void*>(address), length);
    for (size_t i = 0; i < length; ++i) signature.compareMask[i] = 0xFF;
    assert(ValidCodeByteSignature(signature));
    return signature;
}

static AttachedFileIdentity liveFileIdentity(HANDLE file) {
    AttachedFileIdentity identity;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!file || file == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(file, &info))
        return identity;
    identity.valid = true;
    identity.volumeSerial = info.dwVolumeSerialNumber;
    identity.fileIndex = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) |
                         info.nFileIndexLow;
    identity.fileSize = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) |
                        info.nFileSizeLow;
    identity.lastWriteTime =
        (static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
        info.ftLastWriteTime.dwLowDateTime;
    return identity;
}

static bool captureLiveSourceEvidence(
    const char* path, AuthorizationWatchSourceEvidence& evidence) {
    evidence = {};
    HANDLE file = CreateFileA(
        path, GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    const AttachedFileIdentity before = liveFileIdentity(file);
    if (!before.valid || !before.fileSize ||
        before.fileSize > kAuthorizationWatchSourceByteCap ||
        before.fileSize > (std::numeric_limits<size_t>::max)()) {
        CloseHandle(file);
        return false;
    }

    std::vector<uint8_t> bytes;
    try {
        bytes.resize(static_cast<size_t>(before.fileSize));
    } catch (...) {
        CloseHandle(file);
        return false;
    }
    size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD requested = static_cast<DWORD>((std::min<size_t>)(
            1024u * 1024u, bytes.size() - offset));
        DWORD got = 0;
        if (!ReadFile(file, bytes.data() + offset, requested, &got, nullptr) ||
            got != requested) {
            CloseHandle(file);
            return false;
        }
        offset += got;
    }
    const AttachedFileIdentity after = liveFileIdentity(file);
    CloseHandle(file);
    if (!SameAttachedFileIdentity(before, after)) return false;

    try {
        evidence.bytes =
            std::make_shared<std::vector<uint8_t>>(std::move(bytes));
    } catch (...) {
        evidence = {};
        return false;
    }
    evidence.fileIdentity = after;
    return CompleteAuthorizationWatchSourceEvidence(evidence);
}

static bool waitForAuthorizationEvents(Debugger& debugger, size_t count,
                                       int timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    do {
        if (debugger.authorizationWatchSnapshot().events.size() >= count) return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return debugger.authorizationWatchSnapshot().events.size() >= count;
}

static bool waitForPausedDebugger(Debugger& debugger, int timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    do {
        if (debugger.snapshot().state == DbgState::Paused) return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return debugger.snapshot().state == DbgState::Paused;
}

static bool launchOwnedWatch(Debugger& debugger, AuthorizationWatchPlan plan,
                             bool breakAtEntry, bool network, std::string& error) {
    DbgLaunchRequest request;
    request.executable = plan.imagePath;
    request.breakAtEntry = breakAtEntry;
    request.authorizationPlan = std::move(plan);
    request.prelaunchNetworkObservation = network;
    const uint64_t id = debugger.requestLaunch(request, &error);
    // Retiring the caller's plan immediately must not alter queued startup.
    request.authorizationPlan.reset();
    request.executable.clear();
    if (!id) return false;
    for (int elapsed = 0; elapsed < 35000; elapsed += 10) {
        const auto lifecycle = debugger.lifecycleSnapshot();
        if (lifecycle.requestId == id && lifecycle.completed) {
            error = lifecycle.error;
            const auto snapshot = debugger.snapshot();
            return lifecycle.succeeded && !lifecycle.cancelled &&
                DebugTargetIdentityMatches(lifecycle.target, {snapshot.pid, snapshot.sessionGeneration});
        }
        Sleep(10);
    }
    debugger.cancelLifecycle(id);
    error = "queued Authorization Watch startup timed out";
    return false;
}

static bool waitForUserBreakpointStop(Debugger& debugger, uint64_t address,
                                      uint32_t minimumHits,
                                      const std::string& condition,
                                      int timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    do {
        const DbgSnapshot snapshot = debugger.snapshot();
        const auto breakpoint = std::find_if(
            snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
            [address](const SwBreakpointInfo& value) {
                return value.address == address;
            });
        if (snapshot.state == DbgState::Paused &&
            snapshot.regs.rip == address &&
            breakpoint != snapshot.breakpoints.end() &&
            breakpoint->condition == condition &&
            breakpoint->hits >= minimumHits &&
            breakpoint->stops >= minimumHits)
            return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return false;
}

static bool waitForAuthorizationSourceRejection(Debugger& debugger,
                                                int timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() +
                               static_cast<ULONGLONG>(timeoutMs);
    do {
        const AuthorizationWatchSnapshot watch =
            debugger.authorizationWatchSnapshot();
        const DbgSnapshot debug = debugger.snapshot();
        if (watch.sourceValidationFailed && !watch.active &&
            !watch.targetBound && watch.events.empty() &&
            debug.state == DbgState::Paused &&
            debug.lastEvent.find("Authorization Watch rejected") !=
                std::string::npos)
            return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return false;
}

static bool continueToRejectedLoaderStop(Debugger& debugger, int timeoutMs) {
    debugger.cont();
    const ULONGLONG deadline = GetTickCount64() +
                               static_cast<ULONGLONG>(timeoutMs);
    do {
        const DbgSnapshot debug = debugger.snapshot();
        if (debug.state == DbgState::Terminated ||
            debug.state == DbgState::Detached)
            return false;
        // CREATE_PROCESS publishes only the main module. Observing at least one
        // LOAD_DLL before the next rejection pause proves Continue traversed the
        // startup loader path rather than re-reading the original held state.
        if (debug.state == DbgState::Paused && debug.modules.size() > 1 &&
            debug.lastEvent.find("Authorization Watch rejected") !=
                std::string::npos)
            return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return false;
}

static void runLiveDebuggerIntegration() {
    char executable[MAX_PATH]{};
    const DWORD length = GetModuleFileNameA(nullptr, executable, MAX_PATH);
    assert(length > 0 && length < MAX_PATH);
    const uint64_t imageBase = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
    const uint64_t probeCallVa = findDirectCallTo(
        reinterpret_cast<const void*>(&liveAuthorizationProbeCallsite),
        reinterpret_cast<const void*>(&liveAuthorizationProbe));
    const uint64_t callVa = findDirectCallTo(
        reinterpret_cast<const void*>(&liveAuthorizationCallsite),
        reinterpret_cast<const void*>(&liveAuthorizationStateApi));
    const uint64_t mutationCallVa = findDirectCallTo(
        reinterpret_cast<const void*>(&liveAuthorizationMutationCallsite),
        reinterpret_cast<const void*>(&liveAuthorizationMutationProbe));
    const uint64_t sharedMutationCallVa = findDirectCallTo(
        reinterpret_cast<const void*>(&liveAuthorizationSharedMutationCallsite),
        reinterpret_cast<const void*>(&liveAuthorizationSharedMutationProbe));
    assert(probeCallVa >= imageBase);
    assert(callVa >= imageBase);
    assert(mutationCallVa >= imageBase);
    assert(sharedMutationCallVa >= imageBase);

    AuthorizationWatchPlan livePlan;
    livePlan.documentIdentity = "live-self-test";
    livePlan.imagePath.assign(executable, length);
    AuthorizationWatchSite allow = site(
        probeCallVa - imageBase, 77, AuthorizationWatchOutcome::Allow,
        "synthetic observed allow");
    // Both fixture sites are known direct-call instructions, so the live test
    // carries their complete five-byte encodings now that unsigned sites are
    // rejected by production arming.
    allow.signature = liveExactSignature(probeCallVa, 5);
    livePlan.sites.push_back(std::move(allow));
    AuthorizationWatchSite stateWrite = site(
        callVa - imageBase, 78, AuthorizationWatchOutcome::None,
        "synthetic remembered-state write");
    stateWrite.stage = AuthorizationWatchStage::StateWrite;
    stateWrite.strongOutcome = false;
    stateWrite.stateApi = AuthorizationWatchStateApiContract{
        "synthetic.dll", "RememberState", "write remembered state",
        AuthorizationWatchReturnRule::ZeroIsSuccess
    };
    stateWrite.signature = liveExactSignature(callVa, 5);
    livePlan.sites.push_back(std::move(stateWrite));
    AuthorizationWatchSite changedTail = site(
        mutationCallVa - imageBase, 79, AuthorizationWatchOutcome::Allow,
        "tail-mutated authorization site");
    changedTail.signature = liveExactSignature(mutationCallVa, 5);
    livePlan.sites.push_back(std::move(changedTail));
    AuthorizationWatchSite changedSharedTail = site(
        sharedMutationCallVa - imageBase, 80, AuthorizationWatchOutcome::Allow,
        "tail-mutated authorization site shared with a user breakpoint");
    changedSharedTail.signature = liveExactSignature(sharedMutationCallVa, 5);
    livePlan.sites.push_back(std::move(changedSharedTail));
    assert(captureLiveSourceEvidence(executable, livePlan.launchSource));

    // The child takes the short probe-only path rather than recursively starting
    // another debugger. Environment inheritance lets launchAndAttach retain its
    // normal exact argv/working-directory behavior.
    char previous[16]{};
    const DWORD previousLength = GetEnvironmentVariableA(
        "DS_AUTHORIZATION_WATCH_TEST_CHILD", previous, sizeof(previous));
    assert(SetEnvironmentVariableA("DS_AUTHORIZATION_WATCH_TEST_CHILD", "1"));

    Debugger debugger;
    std::string error;

    // A complete but byte-different retained source passes API preflight and is
    // rejected only against CREATE_PROCESS::hFile. Even though launchAndAttach
    // can already have returned true, neither Authorization Watch nor its
    // optional prelaunch Server Watch may bind, arm, or publish an event.
    AuthorizationWatchPlan rejectedPlan = livePlan;
    auto differentBytes = std::make_shared<std::vector<uint8_t>>(
        *livePlan.launchSource.bytes);
    differentBytes->front() ^= 0xFF;
    rejectedPlan.launchSource.bytes = std::move(differentBytes);
    const bool rejectedLaunch = launchOwnedWatch(debugger, rejectedPlan,
        /*breakAtEntry=*/false, /*network=*/true, error);
    assert(rejectedLaunch && error.empty());
    assert(waitForAuthorizationSourceRejection(debugger, 5000));
    const AuthorizationWatchSnapshot rejected =
        debugger.authorizationWatchSnapshot();
    const NetworkObservation rejectedNetwork =
        debugger.networkObservationSnapshot();
    assert(rejected.sourceValidationFailed && !rejected.active &&
           !rejected.targetBound && rejected.events.empty() &&
           rejected.coverage.armedSites == 0 &&
           rejected.coverage.hitTotal == 0);
    assert(!debugger.netTapEnabled() &&
           !rejectedNetwork.coverage.requested &&
           !rejectedNetwork.coverage.active &&
           rejectedNetwork.coverage.probesArmed == 0 &&
           rejectedNetwork.events.empty());
    assert(continueToRejectedLoaderStop(debugger, 5000));
    assert(debugger.authorizationWatchSnapshot().events.empty());
    assert(debugger.networkObservationSnapshot().events.empty());
    debugger.detach();
    error.clear();

    const bool launched = launchOwnedWatch(debugger, livePlan,
        /*breakAtEntry=*/true, /*network=*/false, error);
    if (previousLength > 0 && previousLength < sizeof(previous))
        SetEnvironmentVariableA("DS_AUTHORIZATION_WATCH_TEST_CHILD", previous);
    else
        SetEnvironmentVariableA("DS_AUTHORIZATION_WATCH_TEST_CHILD", nullptr);
    assert(launched && error.empty());
    assert(waitForPausedDebugger(debugger, 5000));
    const AuthorizationWatchSnapshot beforeRun =
        debugger.authorizationWatchSnapshot();
    assert(beforeRun.active && beforeRun.targetBound &&
           beforeRun.sourceValidationComplete &&
           beforeRun.coverage.armedSites == 4);
    const uint64_t sharedMutationRuntimeVa = beforeRun.mainImageBase +
        (sharedMutationCallVa - imageBase);
    char conditionText[64]{};
    std::snprintf(conditionText, sizeof(conditionText), "rip == 0x%llX",
                  static_cast<unsigned long long>(sharedMutationRuntimeVa));
    const std::string sharedCondition = conditionText;
    assert(debugger.addBreakpoint(sharedMutationRuntimeVa, sharedCondition));
    debugger.cont();

    // The first shared hit rejects only stale Authorization semantics. The
    // analyst breakpoint still evaluates its condition and parks normally.
    assert(waitForUserBreakpointStop(debugger, sharedMutationRuntimeVa, 1,
                                     sharedCondition, 5000));
    AuthorizationWatchSnapshot sharedStopped =
        debugger.authorizationWatchSnapshot();
    assert(sharedStopped.events.empty());
    assert(sharedStopped.coverage.hitSignatureMismatches == 2);
    assert(sharedStopped.coverage.signatureMismatchSites == 2);
    assert(sharedStopped.coverage.skippedSites == 2);
    assert(sharedStopped.coverage.armedSites == 2);

    // Continuing single-steps the safely restored modified call and re-arms the
    // user owner. A second stop proves its hit/condition/re-arm semantics remain
    // intact after the Authorization entry metadata was retired.
    debugger.cont();
    assert(waitForUserBreakpointStop(debugger, sharedMutationRuntimeVa, 2,
                                     sharedCondition, 5000));
    sharedStopped = debugger.authorizationWatchSnapshot();
    assert(sharedStopped.events.empty());
    assert(sharedStopped.coverage.hitSignatureMismatches == 2);
    debugger.cont();

    assert(waitForAuthorizationEvents(debugger, 6, 5000));
    const AuthorizationWatchSnapshot observed =
        debugger.authorizationWatchSnapshot();
    assert(observed.events.size() == 6);
    assert(observed.coverage.hitTotal == 4);
    size_t allowHits = 0;
    size_t attempts = 0;
    size_t completions = 0;
    for (const AuthorizationWatchEvent& event : observed.events) {
        assert(event.flowId != 79 && event.flowId != 80);
        if (event.strongOutcome &&
            event.outcome == AuthorizationWatchOutcome::Allow) {
            ++allowHits;
            assert(event.runtimeVa == observed.mainImageBase +
                   livePlan.sites[0].moduleRva);
        }
        if (event.stateOperationAttempted && !event.stateOperationReturn)
            ++attempts;
        if (event.stateOperationReturn) {
            ++completions;
            assert(event.attemptId != 0);
            assert(event.stateOperationSuccessKnown);
            assert(event.stateOperationSucceeded);
            assert(event.rawResultValid && event.rawResult == 0);
            assert(event.pointerWidthBits == 64);
        }
    }
    assert(allowHits == 2 && attempts == 2 && completions == 2);
    assert(observed.coverage.hitSignatureMismatches == 2);
    assert(observed.coverage.pendingReturns == 0);
    assert(observed.coverage.pendingReturnsDropped == 0);
    debugger.detach();
}
#endif

int main() {
    // Launch evidence requires exact backing-file identity before it asks for a
    // single bounded content chunk. Content is then compared byte-for-byte; no
    // pathname or digest can authorize a different file.
    std::vector<uint8_t> sourceBytes(1024u * 1024u + 17u);
    for (size_t i = 0; i < sourceBytes.size(); ++i)
        sourceBytes[i] = static_cast<uint8_t>((i * 131u + 17u) & 0xFFu);
    AttachedFileIdentity sourceIdentity;
    sourceIdentity.valid = true;
    sourceIdentity.volumeSerial = 7;
    sourceIdentity.fileIndex = 0x1122334455667788ull;
    sourceIdentity.fileSize = sourceBytes.size();
    sourceIdentity.lastWriteTime = 0x8877665544332211ull;
    AuthorizationWatchSourceEvidence sourceEvidence;
    sourceEvidence.fileIdentity = sourceIdentity;
    sourceEvidence.bytes =
        std::make_shared<const std::vector<uint8_t>>(sourceBytes);
    size_t sourceReadCalls = 0;
    auto exactSourceReader = [&](uint64_t offset, uint8_t* out, size_t size) {
        ++sourceReadCalls;
        if (offset > sourceBytes.size() ||
            size > sourceBytes.size() - static_cast<size_t>(offset))
            return false;
        std::memcpy(out, sourceBytes.data() + static_cast<size_t>(offset),
                    size);
        return true;
    };
    assert(AuthorizationWatchSourceEvidenceMatches(
        sourceEvidence, sourceIdentity, exactSourceReader));
    assert(sourceReadCalls == 2); // the comparison remains chunk-bounded

    AttachedFileIdentity replacedSource = sourceIdentity;
    ++replacedSource.fileIndex;
    sourceReadCalls = 0;
    assert(!AuthorizationWatchSourceEvidenceMatches(
        sourceEvidence, replacedSource, exactSourceReader));
    assert(sourceReadCalls == 0); // identity rejects before reading any content

    std::vector<uint8_t> changedSource = sourceBytes;
    changedSource.back() ^= 0xFF;
    auto changedSourceReader = [&](uint64_t offset, uint8_t* out, size_t size) {
        if (offset > changedSource.size() ||
            size > changedSource.size() - static_cast<size_t>(offset))
            return false;
        std::memcpy(out,
                    changedSource.data() + static_cast<size_t>(offset), size);
        return true;
    };
    assert(!AuthorizationWatchSourceEvidenceMatches(
        sourceEvidence, sourceIdentity, changedSourceReader));
    assert(!AuthorizationWatchSourceEvidenceMatches(
        sourceEvidence, sourceIdentity,
        [](uint64_t, uint8_t*, size_t) { return false; }));

    // The plan owns its evidence until CREATE_PROCESS accepts or rejects it.
    // Binding is impossible before acceptance, and both terminal paths release
    // the potentially large immutable byte copy.
    AuthorizationWatch sourceGateWatch;
    AuthorizationWatchPlan sourceGatePlan;
    sourceGatePlan.imageSize = 0x1000;
    sourceGatePlan.sites.push_back(site(
        0x20, 1, AuthorizationWatchOutcome::Candidate, "source gate"));
    auto acceptedBytes =
        std::make_shared<const std::vector<uint8_t>>(sourceBytes);
    std::weak_ptr<const std::vector<uint8_t>> acceptedLifetime =
        acceptedBytes;
    sourceGatePlan.launchSource.fileIdentity = sourceIdentity;
    sourceGatePlan.launchSource.bytes = acceptedBytes;
    const uint64_t sourceGateGeneration =
        sourceGateWatch.prepare(sourceGatePlan);
    acceptedBytes.reset();
    sourceGatePlan.launchSource.bytes.reset();
    assert(!acceptedLifetime.expired());
    auto sourceGateSnapshot = sourceGateWatch.snapshot();
    assert(sourceGateSnapshot.active &&
           sourceGateSnapshot.sourceValidationRequired &&
           !sourceGateSnapshot.sourceValidationComplete &&
           !sourceGateSnapshot.sourceValidationFailed);
    assert(!sourceGateWatch.bindTarget(
        sourceGateGeneration, { 90, 91 }, image(0x400000, 0x1000)));
    auto retainedSource =
        sourceGateWatch.pendingSourceEvidence(sourceGateGeneration);
    assert(retainedSource && AuthorizationWatchSourceEvidenceMatches(
        *retainedSource, sourceIdentity, exactSourceReader));
    retainedSource.reset();
    assert(sourceGateWatch.acceptSourceEvidence(sourceGateGeneration));
    assert(acceptedLifetime.expired());
    sourceGateSnapshot = sourceGateWatch.snapshot();
    assert(sourceGateSnapshot.active &&
           sourceGateSnapshot.sourceValidationRequired &&
           sourceGateSnapshot.sourceValidationComplete &&
           !sourceGateSnapshot.sourceValidationFailed &&
           sourceGateSnapshot.sourceValidationError.empty());
    assert(sourceGateWatch.bindTarget(
        sourceGateGeneration, { 90, 91 }, image(0x400000, 0x1000)));

    AuthorizationWatchPlan rejectedSourcePlan;
    rejectedSourcePlan.sites.push_back(site(
        0x20, 2, AuthorizationWatchOutcome::Candidate, "rejected source"));
    auto rejectedBytes =
        std::make_shared<const std::vector<uint8_t>>(sourceBytes);
    std::weak_ptr<const std::vector<uint8_t>> rejectedLifetime =
        rejectedBytes;
    rejectedSourcePlan.launchSource.fileIdentity = sourceIdentity;
    rejectedSourcePlan.launchSource.bytes = rejectedBytes;
    const uint64_t rejectedSourceGeneration =
        sourceGateWatch.prepare(rejectedSourcePlan);
    rejectedBytes.reset();
    rejectedSourcePlan.launchSource.bytes.reset();
    assert(!rejectedLifetime.expired());
    assert(sourceGateWatch.rejectSourceEvidence(rejectedSourceGeneration));
    assert(rejectedLifetime.expired());
    sourceGateSnapshot = sourceGateWatch.snapshot();
    assert(!sourceGateSnapshot.active &&
           !sourceGateSnapshot.targetBound &&
           sourceGateSnapshot.sourceValidationRequired &&
           !sourceGateSnapshot.sourceValidationComplete &&
           sourceGateSnapshot.sourceValidationFailed &&
           sourceGateSnapshot.sourceValidationError ==
               kAuthorizationWatchSourceRejectionMessage &&
           sourceGateSnapshot.events.empty());
    assert(!sourceGateWatch.bindTarget(
        rejectedSourceGeneration, { 90, 92 }, image(0x400000, 0x1000)));
    assert(!sourceGateWatch.rejectSourceEvidence(rejectedSourceGeneration));

    // Full-instruction signatures compare every byte. A producer must exclude
    // relocation-overlapping instructions rather than wildcard executable data.
    CodeByteSignature signature;
    signature.length = 5;
    signature.expected = {0x48, 0x8B, 0x05, 0x11, 0x22};
    signature.compareMask = {0xFF, 0xFF, 0xFF, 0x00, 0x00};
    const uint8_t exact[] = {0x48, 0x8B, 0x05, 0x11, 0x22};
    const uint8_t relocated[] = {0x48, 0x8B, 0x05, 0xAA, 0xBB};
    const uint8_t modified[] = {0x90, 0x8B, 0x05, 0xAA, 0xBB};
    assert(!ValidCodeByteSignature(signature));
    signature.compareMask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    assert(ValidCodeByteSignature(signature));
    assert(CodeByteSignatureMatches(signature, exact, sizeof(exact)));
    assert(!CodeByteSignatureMatches(signature, relocated, sizeof(relocated)));
    assert(!CodeByteSignatureMatches(signature, modified, sizeof(modified)));
    CodeByteSignature allRelocated = signature;
    allRelocated.compareMask = {};
    assert(!ValidCodeByteSignature(allRelocated));
    assert(AuthorizationWatchRangeWithinImage(0xFF, 1, 0x100));
    assert(!AuthorizationWatchRangeWithinImage(0xFF, 2, 0x100));
    assert(!AuthorizationWatchRangeWithinImage(0x100, 1, 0x100));
    assert(!AuthorizationWatchRangeWithinImage(0, 1, 0));

    // Hostile public plans cannot make equality/sorting index past the bounded
    // arrays even when their claimed signature length is malformed.
    CodeByteSignature hostileA;
    hostileA.length = 0xFF;
    CodeByteSignature hostileB = hostileA;
    hostileB.expected[0] = 1;
    assert(!ValidCodeByteSignature(hostileA));
    assert(!CodeByteSignaturesEqual(hostileA, hostileA));

    const auto normalizedRelocations = NormalizeCodeByteRelocations({
        {0x30, 4}, {0x10, 2}, {0x30, 8}, {0x10, 0}, {0x30, 4}
    });
    assert(normalizedRelocations.size() == 2);
    assert(normalizedRelocations[0].address == 0x10 &&
           normalizedRelocations[0].width == 0); // unknown poisons duplicate
    assert(normalizedRelocations[1].address == 0x30 &&
           normalizedRelocations[1].width == 8); // widest known row retained

    // A site whose complete instruction changed after it was armed is retired
    // before semantic publication. The dedicated counter distinguishes this
    // live hit-time failure from a mismatch encountered during initial planting.
    AuthorizationWatch changedInstructionWatch;
    AuthorizationWatchPlan changedInstructionPlan;
    AuthorizationWatchSite changedInstruction = site(
        0x20, 91, AuthorizationWatchOutcome::Allow, "changed instruction");
    changedInstruction.signature = signature;
    changedInstructionPlan.sites.push_back(changedInstruction);
    const uint64_t changedInstructionGeneration =
        changedInstructionWatch.prepare(changedInstructionPlan);
    assert(changedInstructionWatch.bindTarget(
        changedInstructionGeneration, { 55, 66 }, image(0x500000, 0x1000)));
    changedInstructionWatch.markArmed(
        changedInstructionGeneration, 0x500020);
    changedInstructionWatch.markHitSignatureMismatch(
        changedInstructionGeneration, 0x500020);
    auto changedInstructionSnapshot = changedInstructionWatch.snapshot();
    assert(changedInstructionSnapshot.coverage.armedSites == 0);
    assert(changedInstructionSnapshot.coverage.skippedSites == 1);
    assert(changedInstructionSnapshot.coverage.signatureMismatchSites == 1);
    assert(changedInstructionSnapshot.coverage.hitSignatureMismatches == 1);
    const AuthorizationWatchHitResult rejectedChangedInstruction =
        changedInstructionWatch.recordEntryHit(
            changedInstructionGeneration, 0x500020, 7, 123);
    assert(rejectedChangedInstruction.returnRequests.empty() &&
           !rejectedChangedInstruction.pauseRequested);
    assert(changedInstructionWatch.snapshot().events.empty());
    // Duplicate/stale notifications cannot inflate the saturated hit counter.
    changedInstructionWatch.markHitSignatureMismatch(
        changedInstructionGeneration, 0x500020);
    assert(changedInstructionWatch.snapshot().coverage.hitSignatureMismatches == 1);

    AuthorizationWatch hostileWatch;
    AuthorizationWatchPlan hostilePlan;
    AuthorizationWatchSite hostileSiteA = site(
        1, 1, AuthorizationWatchOutcome::Candidate, "hostile A");
    hostileSiteA.signature = hostileA;
    AuthorizationWatchSite hostileSiteB = site(
        2, 1, AuthorizationWatchOutcome::Candidate, "hostile B");
    hostileSiteB.signature = hostileB;
    hostilePlan.sites = {hostileSiteA, hostileSiteB};
    (void)hostileWatch.prepare(hostilePlan);
    assert(hostileWatch.snapshot().coverage.retainedSites == 2);

    // Retained network events must bind to one exact module incarnation. A DLL
    // unload/reload can legally reuse its base, size, and path in one session.
    NetworkObservationEvent observed;
    observed.pid = 42;
    observed.sessionGeneration = 9;
    observed.caller = 0x180001234ull;
    observed.runtimeModuleBase = 0x180000000ull;
    observed.runtimeModuleLoadGeneration = 7;
    assert(NetworkObservationEventMatchesMapping(
        observed, 42, 9, 0x180000000ull, 0x4000, 7));
    assert(!NetworkObservationEventMatchesMapping(
        observed, 42, 9, 0x180000000ull, 0x4000, 8));
    assert(!NetworkObservationEventMatchesMapping(
        observed, 42, 10, 0x180000000ull, 0x4000, 7));
    assert(!NetworkObservationEventMatchesMapping(
        observed, 42, 9, 0x180000000ull, 0, 7));

#ifdef DS_AUTHORIZATION_WATCH_LIVE_TEST
    char child[2]{};
    if (GetEnvironmentVariableA("DS_AUTHORIZATION_WATCH_TEST_CHILD",
                                child, sizeof(child)) != 0) {
        if (!redirectDirectCallTail(
                reinterpret_cast<const void*>(&liveAuthorizationMutationCallsite),
                reinterpret_cast<const void*>(&liveAuthorizationMutationProbe),
                reinterpret_cast<const void*>(&liveAuthorizationMutationAlternate)))
            return 3;
        if (!redirectDirectCallTail(
                reinterpret_cast<const void*>(&liveAuthorizationSharedMutationCallsite),
                reinterpret_cast<const void*>(&liveAuthorizationSharedMutationProbe),
                reinterpret_cast<const void*>(&liveAuthorizationSharedMutationAlternate)))
            return 4;
        // Only the displacement tail changed. The debugger-owned leading INT3
        // still fires, exercising hit-time full-instruction revalidation.
        liveAuthorizationMutationCallsite();
        // This site is shared with a conditional analyst breakpoint. Two calls
        // prove that the user owner survives the stale Authorization retirement
        // and is re-armed after the first stop.
        liveAuthorizationSharedMutationCallsite();
        liveAuthorizationSharedMutationCallsite();
        (void)liveAuthorizationCallsite();
        (void)liveAuthorizationCallsite();
        liveAuthorizationProbeCallsite();
        liveAuthorizationProbeCallsite();
        return 0;
    }
#endif
    AuthorizationWatch watch;
    AuthorizationWatchPlan plan;
    plan.documentIdentity = "sha256:test";
    plan.documentId = 17;
    plan.documentImageGeneration = 29;
    plan.imagePath = "C:\\fixtures\\auth.exe";
    plan.imageSize = 0x5000;
    plan.sites = {
        site(0x30, 2, AuthorizationWatchOutcome::Deny, "deny path"),
        site(0x10, 1, AuthorizationWatchOutcome::Allow, "allow path"),
        site(0x10, 1, AuthorizationWatchOutcome::Candidate, "branch candidate"),
        site(0x10, 1, AuthorizationWatchOutcome::Allow, "allow path"), // duplicate
    };
    AuthorizationWatchStateApiContract stateApi;
    stateApi.dll = "advapi32.dll";
    stateApi.symbol = "RegSetValueExW";
    stateApi.operation = "write attempt counter / revocation marker";
    stateApi.returnRule = AuthorizationWatchReturnRule::ZeroIsSuccess;
    AuthorizationWatchSite write = site(
        0x20, 1, AuthorizationWatchOutcome::None, "write remembered state");
    write.stage = AuthorizationWatchStage::StateWrite;
    write.strongOutcome = false;
    write.stateApi = stateApi;
    plan.sites.push_back(write);

    const uint64_t generation = watch.prepare(plan);
    auto snapshot = watch.snapshot();
    assert(snapshot.active && !snapshot.targetBound);
    assert(snapshot.coverage.requestedSites == 5);
    assert(snapshot.coverage.retainedSites == 4); // exact duplicate removed
    assert(snapshot.coverage.plannedSites == 0);
    const AttachedModuleIdentity firstImage{
        0x140000000ull, 0x5000, "auth.exe", "C:\\fixtures\\auth.exe", 3
    };
    assert(watch.bindTarget(generation, { 4242, 7 }, firstImage));
    snapshot = watch.snapshot();
    assert(snapshot.documentId == 17 &&
           snapshot.documentImageGeneration == 29);
    assert(snapshot.boundModule.base == firstImage.base &&
           snapshot.boundModule.loadGeneration == firstImage.loadGeneration);

    auto pending = watch.pendingSites(generation);
    assert(pending.size() == 3);
    assert(pending[0].runtimeVa == 0x140000010ull);
    watch.markArmed(generation, 0x140000010ull, true);
    watch.markArmed(generation, 0x140000020ull);
    watch.markSkipped(generation, 0x140000030ull,
                      AuthorizationWatchSkipReason::SignatureMismatch);

    // One physical hit emits both semantic labels at the shared RVA. The default
    // is log-and-continue, and user-breakpoint sharing remains visible in coverage.
    assert(!watch.recordHit(generation, 0x140000010ull, 11, 100));
    snapshot = watch.snapshot();
    assert(snapshot.coverage.plannedSites == 3);
    assert(snapshot.coverage.armedSites == 2);
    assert(snapshot.coverage.sitesSharedWithUserBreakpoints == 1);
    assert(snapshot.coverage.signatureMismatchSites == 1);
    assert(snapshot.coverage.hitSites == 1 && snapshot.coverage.hitTotal == 1);
    assert(snapshot.events.size() == 2);
    assert(snapshot.events[0].target.pid == 4242);

    // A pure entry observation is explicitly an attempt, not invented API
    // success. The debugger uses recordEntryHit's request to correlate the
    // thread's real return and then publishes the completion through
    // recordStateReturn, as modeled directly below.
    assert(!watch.recordHit(generation, 0x140000020ull, 11, 101));
    snapshot = watch.snapshot();
    const auto& attempt = snapshot.events.back();
    assert(attempt.stateOperationAttempted);
    assert(!attempt.stateOperationSuccessKnown && !attempt.stateOperationSucceeded);
    assert(attempt.stage == AuthorizationWatchStage::StateWrite);
    assert(attempt.outcome == AuthorizationWatchOutcome::None);
    assert(!attempt.strongOutcome); // a write attempt is not an observed allow
    const AuthorizationWatchHitResult returnable =
        watch.recordEntryHit(generation, 0x140000020ull, 11, 102);
    assert(returnable.returnRequests.size() == 1);
    assert(watch.recordStateReturn(returnable.returnRequests.front(),
                                   0x140000025ull, 11, 103, 0, 64) == false);
    snapshot = watch.snapshot();
    assert(snapshot.events.back().stateOperationSuccessKnown);
    assert(snapshot.events.back().stateOperationSucceeded);
    assert(snapshot.events.back().stateOperationReturn);
    // Even a successful write can record denial, revocation, or an attempt
    // counter.  API success must remain direction-neutral in the event stream.
    assert(snapshot.events.back().outcome == AuthorizationWatchOutcome::None);
    assert(!snapshot.events.back().strongOutcome);
    assert(snapshot.events.back().rawResultValid &&
           snapshot.events.back().rawResult == 0);
    assert(snapshot.events.back().attemptId ==
           returnable.returnRequests.front().attemptId);

    // Exact 32-bit invalid-value contracts treat fd 0 as success and -1 as
    // failure; they must not fall through to a generic nonzero rule.
    AuthorizationWatchReturnRequest fd = returnable.returnRequests.front();
    fd.attemptId += 100;
    fd.stateApi.returnRule = AuthorizationWatchReturnRule::NotInvalidValue32;
    assert(!watch.recordStateReturn(fd, 0x140000025ull, 11, 104, 0, 64));
    assert(watch.snapshot().events.back().stateOperationSucceeded);
    fd.attemptId += 1;
    assert(!watch.recordStateReturn(fd, 0x140000025ull, 11, 105,
                                    UINT32_MAX, 64));
    assert(!watch.snapshot().events.back().stateOperationSucceeded);

    // Signed-count/status APIs remain 32-bit on Win64. EAX writes zero-extend,
    // so 0xffffffff in RAX is still signed -1 and must be reported as failure.
    AuthorizationWatchReturnRequest signedCount =
        returnable.returnRequests.front();
    signedCount.attemptId += 200;
    signedCount.stateApi.returnRule =
        AuthorizationWatchReturnRule::NonnegativeIsSuccess;
    assert(!watch.recordStateReturn(signedCount, 0x140000025ull, 11, 106,
                                    UINT32_MAX, 64));
    assert(watch.snapshot().events.back().stateOperationSuccessKnown);
    assert(!watch.snapshot().events.back().stateOperationSucceeded);
    signedCount.attemptId += 1;
    assert(!watch.recordStateReturn(signedCount, 0x140000025ull, 11, 107,
                                    UINT32_C(0x7fffffff), 64));
    assert(watch.snapshot().events.back().stateOperationSucceeded);

    // Clear retains the active plan/arming while dropping session observations.
    watch.clearEvents();
    snapshot = watch.snapshot();
    assert(snapshot.active && snapshot.events.empty());
    assert(snapshot.coverage.hitSites == 0 && snapshot.coverage.hitTotal == 0);
    assert(snapshot.coverage.armedSites == 2);

    // Pause-on-hit is opt-in and stale generations cannot mutate a replacement.
    AuthorizationWatchOptions pauseOptions;
    pauseOptions.pauseOnHit = true;
    const uint64_t replacement = watch.prepare(plan, pauseOptions);
    assert(replacement != generation);
    assert(watch.bindTarget(replacement, { 4242, 8 },
                            image(0x180000000ull, 0x5000, 4)));
    watch.markArmed(generation, 0x180000010ull);
    assert(!watch.recordHit(generation, 0x180000010ull, 1, 1));
    watch.markArmed(replacement, 0x180000010ull);
    assert(watch.recordHit(replacement, 0x180000010ull, 1, 2));
    watch.markArmed(replacement, 0x180000020ull);
    const AuthorizationWatchHitResult pausingReturn =
        watch.recordEntryHit(replacement, 0x180000020ull, 1, 3);
    assert(pausingReturn.pauseRequested &&
           pausingReturn.returnRequests.size() == 1);
    assert(watch.recordStateReturn(pausingReturn.returnRequests.front(),
                                   0x180000025ull, 1, 4, 0, 64));

    // Attached plans fail closed unless base, extent, path, and per-load
    // incarnation all still name the exact mapping stamped by the UI.
    AuthorizationWatchPlan exactPlan;
    exactPlan.documentIdentity = "sha256:exact";
    exactPlan.documentId = 41;
    exactPlan.documentImageGeneration = 73;
    exactPlan.requireExactModuleIdentity = true;
    exactPlan.expectedModule = {
        0x500000, 0x9000, "exact.exe", "C:\\fixtures\\exact.exe", 11
    };
    exactPlan.sites.push_back(site(
        0x20, 1, AuthorizationWatchOutcome::Candidate, "exact mapping"));
    const uint64_t exactGeneration = watch.prepare(exactPlan);
    AttachedModuleIdentity replaced = exactPlan.expectedModule;
    replaced.loadGeneration = 12;
    assert(!watch.bindTarget(exactGeneration, { 8, 10 }, replaced));
    replaced = exactPlan.expectedModule;
    replaced.path = "C:\\fixtures\\other.exe";
    assert(!watch.bindTarget(exactGeneration, { 8, 10 }, replaced));
    assert(watch.bindTarget(exactGeneration, { 8, 10 },
                            exactPlan.expectedModule));
    snapshot = watch.snapshot();
    assert(snapshot.targetBound && snapshot.boundModule.loadGeneration == 11);

    // A nonzero declared image extent is authoritative: the last byte is valid,
    // while an RVA exactly at SizeOfImage is skipped before any target mutation.
    AuthorizationWatchPlan imageBound;
    imageBound.imageSize = 0x100;
    imageBound.sites.push_back(site(
        0xFF, 1, AuthorizationWatchOutcome::Candidate, "inside image"));
    imageBound.sites.push_back(site(
        0x100, 2, AuthorizationWatchOutcome::Candidate, "past image"));
    const uint64_t imageBoundGeneration = watch.prepare(imageBound);
    assert(watch.bindTarget(imageBoundGeneration, { 7, 9 },
                            image(0x400000, 0x100)));
    assert(watch.pendingSites(imageBoundGeneration).size() == 1);
    assert(watch.snapshot().coverage.skippedSites == 1);

    // Static sites filtered before the cap remain visible as unavailable after
    // the target is bound; bind must not erase this limitation counter.
    AuthorizationWatchPlan filtered;
    filtered.signatureUnavailableSites = 3;
    AuthorizationWatchSite retained = site(
        0x10, 1, AuthorizationWatchOutcome::Candidate, "signed");
    retained.signature = signature;
    filtered.sites.push_back(retained);
    const uint64_t filteredGeneration = watch.prepare(filtered);
    assert(watch.bindTarget(filteredGeneration, { 6, 7 },
                            image(0x600000, 0x1000)));
    snapshot = watch.snapshot();
    assert(snapshot.coverage.requestedSites == 4);
    assert(snapshot.coverage.retainedSites == 1);
    assert(snapshot.coverage.skippedSites == 3);
    assert(snapshot.coverage.signatureUnavailableSites == 3);

    // RVA overflow is discarded at bind, and the semantic/event caps are exact.
    AuthorizationWatchPlan capped;
    for (size_t i = 0; i < kAuthorizationWatchSiteCap + 20; ++i)
        capped.sites.push_back(site(0x100 + i, i, AuthorizationWatchOutcome::Candidate,
                                    "bounded"));
    capped.sites.push_back(site((std::numeric_limits<uint64_t>::max)(), 9999,
                                AuthorizationWatchOutcome::Unknown, "overflow"));
    const uint64_t cappedGeneration = watch.prepare(capped);
    assert(watch.bindTarget(cappedGeneration, { 1, 1 },
                            image(0x1000, 0x100000)));
    snapshot = watch.snapshot();
    assert(snapshot.coverage.requestedSites == kAuthorizationWatchSiteCap + 21);
    assert(snapshot.coverage.inputSitesScanned == kAuthorizationWatchSiteCap);
    assert(snapshot.coverage.inputSitesTruncated == 21);
    assert(snapshot.coverage.retainedSites == kAuthorizationWatchSiteCap);
    assert(snapshot.coverage.plannedSites <= kAuthorizationWatchSiteCap);

    // Exact duplicates ahead of a later unique row collapse before the cap;
    // they cannot crowd the unique row out of a bounded plan.
    AuthorizationWatchPlan duplicateCrowd;
    const AuthorizationWatchSite repeated = site(
        0x20, 1, AuthorizationWatchOutcome::Candidate, "repeated");
    for (size_t i = 0; i < kAuthorizationWatchSiteCap; ++i)
        duplicateCrowd.sites.push_back(repeated);
    duplicateCrowd.sites.push_back(site(
        0x30, 2, AuthorizationWatchOutcome::Candidate, "unique after duplicates"));
    const uint64_t duplicateGeneration = watch.prepare(duplicateCrowd);
    snapshot = watch.snapshot();
    assert(snapshot.coverage.requestedSites == kAuthorizationWatchSiteCap + 1);
    assert(snapshot.coverage.retainedSites == 2);
    assert(watch.bindTarget(duplicateGeneration, { 3, 3 },
                            image(0x2000, 0x1000)));
    assert(watch.pendingSites(duplicateGeneration).size() == 2);

    // Hostile duplicate-heavy inputs have a finite scan budget. Priority is
    // retained within that prefix, and omitted rows remain visible in coverage.
    AuthorizationWatchPlan scanCapped;
    scanCapped.sites.reserve(kAuthorizationWatchInputScanCap + 1);
    for (size_t i = 0; i + 1 < kAuthorizationWatchInputScanCap; ++i)
        scanCapped.sites.push_back(repeated);
    scanCapped.sites.push_back(site(
        0x40, 3, AuthorizationWatchOutcome::Candidate, "last scanned unique"));
    scanCapped.sites.push_back(site(
        0x50, 4, AuthorizationWatchOutcome::Candidate, "truncated unique"));
    const uint64_t scanCappedGeneration = watch.prepare(scanCapped);
    snapshot = watch.snapshot();
    assert(snapshot.coverage.requestedSites ==
           kAuthorizationWatchInputScanCap + 1);
    assert(snapshot.coverage.inputSitesScanned ==
           kAuthorizationWatchInputScanCap);
    assert(snapshot.coverage.inputSitesTruncated == 1);
    assert(snapshot.coverage.retainedSites == 2);
    assert(watch.bindTarget(scanCappedGeneration, { 4, 4 },
                            image(0x3000, 0x1000)));
    assert(watch.pendingSites(scanCappedGeneration).size() == 2);

    // Local credential/input sites use an explicit live-stage label. RVA zero
    // remains valid, and repeated planner rows collapse deterministically
    // before the semantic-site cap.
    AuthorizationWatchPlan localCheckPlan;
    AuthorizationWatchSite localCheck = site(
        0, 5, AuthorizationWatchOutcome::Candidate,
        "local input read / compare / decision");
    localCheck.stage = AuthorizationWatchStage::LocalCheck;
    localCheckPlan.sites = { localCheck, localCheck };
    const uint64_t localCheckGeneration = watch.prepare(localCheckPlan);
    snapshot = watch.snapshot();
    assert(snapshot.coverage.requestedSites == 2);
    assert(snapshot.coverage.retainedSites == 1);
    assert(watch.bindTarget(localCheckGeneration, { 5, 5 },
                            image(0x4000, 0x1000)));
    const auto localPending = watch.pendingSites(localCheckGeneration);
    assert(localPending.size() == 1 && localPending[0].moduleRva == 0 &&
           localPending[0].runtimeVa == 0x4000);
    watch.markArmed(localCheckGeneration, 0x4000);
    assert(!watch.recordHit(localCheckGeneration, 0x4000, 1, 1));
    snapshot = watch.snapshot();
    assert(snapshot.events.size() == 1 &&
           snapshot.events[0].stage == AuthorizationWatchStage::LocalCheck);

    AuthorizationWatchPlan events;
    events.sites.push_back(site(1, 1, AuthorizationWatchOutcome::Allow, "repeatable"));
    const uint64_t eventGeneration = watch.prepare(events);
    assert(watch.bindTarget(eventGeneration, { 2, 2 },
                            image(0x1000, 0x100000)));
    watch.markArmed(eventGeneration, 0x1001);
    for (size_t i = 0; i < kAuthorizationWatchEventCap + 7; ++i)
        (void)watch.recordHit(eventGeneration, 0x1001, 1, i);
    snapshot = watch.snapshot();
    assert(snapshot.events.size() == kAuthorizationWatchEventCap);
    assert(snapshot.coverage.droppedEvents == 7);
    assert(snapshot.coverage.hitTotal == kAuthorizationWatchEventCap + 7);

    // Nested returns are strictly LIFO per thread, while two threads may share
    // one physical return address through refcounting.
    AuthorizationWatchReturnTracker returns;
    AuthorizationWatchPendingReturn outer;
    outer.entryAddress = 0x2000;
    outer.requests.push_back(fd);
    AuthorizationWatchPendingReturn inner = outer;
    inner.entryAddress = 0x3000;
    assert(returns.push(10, 0x5000, outer));
    assert(returns.push(10, 0x6000, inner));
    AuthorizationWatchPendingReturn popped;
    assert(!returns.pop(10, 0x5000, popped));
    assert(returns.pop(10, 0x6000, popped) && popped.entryAddress == 0x3000);
    assert(returns.pop(10, 0x5000, popped) && popped.entryAddress == 0x2000);
    assert(returns.push(11, 0x7000, outer));
    assert(returns.push(12, 0x7000, inner));
    assert(returns.references(0x7000) == 2 && returns.total() == 2);
    size_t erased = 0;
    assert(returns.eraseThread(11, &erased).empty() && erased == 1);
    assert(returns.references(0x7000) == 1);
    const auto exhausted = returns.eraseThread(12, &erased);
    assert(erased == 1 && exhausted == std::vector<uint64_t>{ 0x7000 });
    assert(returns.total() == 0);

    watch.stop();
    assert(!watch.snapshot().active);
    assert(!watch.recordHit(eventGeneration, 0x1001, 1, 999));
    watch.reset();
    snapshot = watch.snapshot();
    assert(!snapshot.active && snapshot.coverage.requestedSites == 0);

#ifdef DS_AUTHORIZATION_WATCH_LIVE_TEST
    runLiveDebuggerIntegration();
#endif

    std::cout << "authorization_watch_test: all checks passed\n";
    return 0;
}
