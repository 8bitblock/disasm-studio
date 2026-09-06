#include "Core/AuthorizationExperiment.h"

#include <cstdint>
#include <iostream>
#include <limits>

using namespace ds;

namespace {

int failures = 0;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            std::cerr << __FILE__ << ':' << __LINE__                           \
                      << ": CHECK failed: " #condition "\n";                  \
            ++failures;                                                       \
        }                                                                      \
    } while (false)

AttachedModuleIdentity module(uint64_t base = UINT64_C(0x140000000),
                              uint64_t loadGeneration = 3) {
    AttachedModuleIdentity value;
    value.base = base;
    value.size = 0x2000;
    value.name = "auth.exe";
    value.path = "C:\\fixtures\\auth.exe";
    value.loadGeneration = loadGeneration;
    return value;
}

AuthorizationExperimentRequest request(
    AuthorizationExperimentArchitecture architecture =
        AuthorizationExperimentArchitecture::X64,
    AuthorizationExperimentReturnWidth width =
        AuthorizationExperimentReturnWidth::Al) {
    AuthorizationExperimentRequest value;
    value.target = { 4242, 17 };
    value.module = module();
    value.threadId = 91;
    value.architecture = architecture;
    value.returnWidth = width;
    value.staticImageBase = 0;
    value.staticImageBaseValid = true;
    value.staticCallsite = 0;
    value.staticCallsiteValid = true;
    value.staticContinuation = 5;
    value.staticContinuationValid = true;
    return value;
}

AuthorizationExperimentPauseObservation pause(
    const AuthorizationExperimentRequest& request,
    uint64_t rip,
    uint64_t accumulator,
    bool wholeValue = true) {
    AuthorizationExperimentPauseObservation value;
    value.target = request.target;
    value.module = request.module;
    value.threadId = request.threadId;
    value.paused = true;
    value.rip = rip;
    value.ripValid = true;
    if (wholeValue) {
        value.rax = accumulator;
        value.raxValid = true;
        value.eax = static_cast<uint32_t>(accumulator);
        value.eaxValid = true;
    }
    value.al = static_cast<uint8_t>(accumulator);
    value.alValid = true;
    return value;
}

void testVaZeroAndLowBytePreservation() {
    AuthorizationExperiment experiment;
    const auto req = request();
    CHECK(experiment.request(req) == AuthorizationExperimentIssue::None);

    auto snapshot = experiment.snapshot();
    CHECK(snapshot.state == AuthorizationExperimentState::BreakRequested);
    CHECK(snapshot.breakTarget.valid);
    // Validity is separate from value: static image base and exact CALL at VA
    // zero translate to the first byte of the runtime module.
    CHECK(snapshot.breakTarget.staticCallsite == 0);
    CHECK(snapshot.breakTarget.callsiteModuleRva == 0);
    CHECK(snapshot.breakTarget.runtimeCallsite == req.module.base);
    CHECK(snapshot.breakTarget.staticContinuation == 5);
    CHECK(snapshot.breakTarget.runtimeContinuation == req.module.base + 5);

    // An unrelated debugger stop is not destructive; the requested exact
    // continuation can still be reached later.
    auto elsewhere = pause(req, req.module.base + 0x100, 7);
    CHECK(experiment.observePause(elsewhere) ==
          AuthorizationExperimentIssue::NotAtContinuation);
    CHECK(experiment.snapshot().state ==
          AuthorizationExperimentState::BreakRequested);

    constexpr uint64_t original = UINT64_C(0x11223344556677aa);
    auto observed = pause(req, req.module.base + 5, original);
    CHECK(experiment.observePause(observed) ==
          AuthorizationExperimentIssue::None);
    snapshot = experiment.snapshot();
    CHECK(snapshot.originalAccumulatorValid);
    CHECK(snapshot.originalAccumulator == original);
    CHECK(snapshot.forceAvailable);

    auto forceTrue = experiment.planForce(true);
    CHECK(forceTrue.has_value());
    CHECK(forceTrue->kind == AuthorizationExperimentWriteKind::ForceTrue);
    CHECK(forceTrue->registerName == "rax");
    CHECK(forceTrue->contractWidthBits == 8);
    CHECK(forceTrue->expectedAccumulator == original);
    CHECK(forceTrue->accumulatorCompareMask ==
          (std::numeric_limits<uint64_t>::max)());
    // Every bit unrelated to AL is preserved.
    CHECK(forceTrue->value == UINT64_C(0x1122334455667701));

    auto afterTrue = pause(req, req.module.base + 5, forceTrue->value);
    CHECK(experiment.confirmWrite(*forceTrue, afterTrue));
    snapshot = experiment.snapshot();
    CHECK(snapshot.state == AuthorizationExperimentState::Forced);
    CHECK(snapshot.originalAccumulator == original);
    CHECK(snapshot.currentAccumulator == forceTrue->value);
    CHECK(snapshot.restoreAvailable);

    // Toggling does not accumulate damage in the rest of RAX.
    auto forceFalse = experiment.planForce(false);
    CHECK(forceFalse.has_value());
    CHECK(forceFalse->value == UINT64_C(0x1122334455667700));
    auto afterFalse = pause(req, req.module.base + 5, forceFalse->value);
    CHECK(experiment.confirmWrite(*forceFalse, afterFalse));

    auto restore = experiment.planRestore();
    CHECK(restore.has_value());
    CHECK(restore->kind == AuthorizationExperimentWriteKind::Restore);
    CHECK(restore->value == original);
    auto afterRestore = pause(req, req.module.base + 5, original);
    CHECK(experiment.confirmWrite(*restore, afterRestore));
    snapshot = experiment.snapshot();
    CHECK(snapshot.state == AuthorizationExperimentState::Restored);
    CHECK(snapshot.currentAccumulator == original);
    CHECK(!snapshot.restoreAvailable);
}

void testEaxAndX86Semantics() {
    // On x64, forcing an EAX result must zero RAX[63:32].
    AuthorizationExperiment x64;
    const auto x64Request = request(
        AuthorizationExperimentArchitecture::X64,
        AuthorizationExperimentReturnWidth::Eax);
    CHECK(x64.request(x64Request) == AuthorizationExperimentIssue::None);
    constexpr uint64_t x64Original = UINT64_C(0xdeadbeef00000005);
    CHECK(x64.observePause(pause(x64Request, x64Request.module.base + 5,
                                x64Original)) ==
          AuthorizationExperimentIssue::None);
    auto x64True = x64.planForce(true);
    CHECK(x64True.has_value());
    CHECK(x64True->contractWidthBits == 32);
    CHECK(x64True->value == 1); // exact EAX zero-extension result
    CHECK(x64.confirmWrite(
        *x64True, pause(x64Request, x64Request.module.base + 5, 1)));
    auto x64Restore = x64.planRestore();
    CHECK(x64Restore.has_value() && x64Restore->value == x64Original);
    CHECK(x64.confirmWrite(
        *x64Restore,
        pause(x64Request, x64Request.module.base + 5, x64Original)));

    // An x86 snapshot may expose only the architectural EAX view.  Force and
    // restore remain bounded to 32 bits.
    AuthorizationExperiment x86;
    const auto x86Request = request(
        AuthorizationExperimentArchitecture::X86,
        AuthorizationExperimentReturnWidth::Eax);
    CHECK(x86.request(x86Request) == AuthorizationExperimentIssue::None);
    auto x86Observed = pause(x86Request, x86Request.module.base + 5,
                             UINT32_C(0xf0123456), false);
    x86Observed.eax = UINT32_C(0xf0123456);
    x86Observed.eaxValid = true;
    CHECK(x86.observePause(x86Observed) == AuthorizationExperimentIssue::None);
    auto x86False = x86.planForce(false);
    CHECK(x86False.has_value());
    CHECK(x86False->value == 0);
    CHECK(x86False->accumulatorCompareMask == UINT64_C(0xffffffff));
    auto afterX86False = pause(x86Request, x86Request.module.base + 5, 0, false);
    afterX86False.eax = 0;
    afterX86False.eaxValid = true;
    CHECK(x86.confirmWrite(*x86False, afterX86False));
    auto x86Restore = x86.planRestore();
    CHECK(x86Restore.has_value());
    CHECK(x86Restore->value == UINT32_C(0xf0123456));
    auto afterX86Restore = pause(x86Request, x86Request.module.base + 5,
                                 UINT32_C(0xf0123456), false);
    afterX86Restore.eax = UINT32_C(0xf0123456);
    afterX86Restore.eaxValid = true;
    CHECK(x86.confirmWrite(*x86Restore, afterX86Restore));

    auto impossible = x86Request;
    impossible.returnWidth = AuthorizationExperimentReturnWidth::Rax;
    CHECK(x86.request(impossible) ==
          AuthorizationExperimentIssue::UnsupportedReturnWidth);

    // Status-style predicates can prove the inverse convention (zero means
    // logical true). The UI labels logical outcomes while the pure state
    // machine writes the exact documented values.
    AuthorizationExperiment zeroIsTrue;
    auto inverse = x64Request;
    inverse.trueValue = 0;
    inverse.falseValue = 1;
    CHECK(zeroIsTrue.request(inverse) == AuthorizationExperimentIssue::None);
    CHECK(zeroIsTrue.observePause(
        pause(inverse, inverse.module.base + 5, 9)) ==
          AuthorizationExperimentIssue::None);
    auto inverseTrue = zeroIsTrue.planForce(true);
    CHECK(inverseTrue.has_value() && inverseTrue->value == 0);
    CHECK(zeroIsTrue.confirmWrite(
        *inverseTrue, pause(inverse, inverse.module.base + 5, 0)));
    auto inverseFalse = zeroIsTrue.planForce(false);
    CHECK(inverseFalse.has_value() && inverseFalse->value == 1);
}

void testValidityAndVerificationFailures() {
    AuthorizationExperiment experiment;
    auto req = request();
    CHECK(experiment.request(req) == AuthorizationExperimentIssue::None);

    // AL alone proves the displayed truth value but cannot support a preserving
    // whole-RAX edit or exact restore.
    auto partial = pause(req, req.module.base + 5, 1, false);
    CHECK(experiment.observePause(partial) ==
          AuthorizationExperimentIssue::AccumulatorUnavailable);
    CHECK(experiment.snapshot().state ==
          AuthorizationExperimentState::PausedAtContinuation);
    CHECK(!experiment.planForce(true));

    // A complete re-snapshot can recover while execution remains paused.
    auto complete = pause(req, req.module.base + 5, UINT64_C(0xaabbccdd01));
    CHECK(experiment.observePause(complete) ==
          AuthorizationExperimentIssue::None);
    auto first = experiment.planForce(false);
    CHECK(first.has_value());
    auto superseding = experiment.planForce(true);
    CHECK(superseding.has_value());
    CHECK(!experiment.confirmWrite(
        *first, pause(req, req.module.base + 5, first->value)));
    CHECK(experiment.snapshot().issue ==
          AuthorizationExperimentIssue::StaleWritePlan);

    // The current proposal remains pending until its value is actually seen.
    CHECK(!experiment.confirmWrite(
        *superseding,
        pause(req, req.module.base + 5, superseding->value ^ 1u)));
    CHECK(experiment.snapshot().issue ==
          AuthorizationExperimentIssue::WriteVerificationFailed);
    CHECK(experiment.confirmWrite(
        *superseding,
        pause(req, req.module.base + 5, superseding->value)));

    AuthorizationExperiment conflict;
    CHECK(conflict.request(req) == AuthorizationExperimentIssue::None);
    auto disagreeing = pause(req, req.module.base + 5, UINT64_C(0x100));
    disagreeing.al = 1;
    CHECK(conflict.observePause(disagreeing) ==
          AuthorizationExperimentIssue::RegisterViewsConflict);
    CHECK(!conflict.snapshot().forceAvailable);

    AuthorizationExperiment noRip;
    CHECK(noRip.request(req) == AuthorizationExperimentIssue::None);
    auto unavailableRip = pause(req, 0, 0);
    unavailableRip.ripValid = false;
    CHECK(noRip.observePause(unavailableRip) ==
          AuthorizationExperimentIssue::RipUnavailable);
    CHECK(!noRip.snapshot().forceAvailable);
}

void testNoOpForceAndLateMutationRecovery() {
    const auto req = request();

    // AL is already true, so forcing true writes the same whole RAX value. The
    // verified operation succeeds but must not strand the experiment in Forced
    // with no restore proposal capable of unlocking it.
    AuthorizationExperiment noOp;
    CHECK(noOp.request(req) == AuthorizationExperimentIssue::None);
    constexpr uint64_t alreadyTrue = UINT64_C(0x123456789abcde01);
    CHECK(noOp.observePause(
        pause(req, req.module.base + 5, alreadyTrue)) ==
          AuthorizationExperimentIssue::None);
    auto noOpTrue = noOp.planForce(true);
    CHECK(noOpTrue.has_value());
    CHECK(noOpTrue && noOpTrue->value == alreadyTrue);
    CHECK(noOpTrue && noOp.confirmWrite(
        *noOpTrue, pause(req, req.module.base + 5, alreadyTrue)));
    auto noOpSnapshot = noOp.snapshot();
    CHECK(noOpSnapshot.state == AuthorizationExperimentState::Observed);
    CHECK(!noOpSnapshot.pendingWrite.has_value());
    CHECK(!noOpSnapshot.restoreAvailable);

    auto changeFalse = noOp.planForce(false);
    CHECK(changeFalse.has_value());
    CHECK(changeFalse && noOp.confirmWrite(
        *changeFalse, pause(req, req.module.base + 5,
                            changeFalse->value)));
    auto restoreNoOp = noOp.planRestore();
    CHECK(restoreNoOp.has_value());
    CHECK(restoreNoOp && noOp.confirmWrite(
        *restoreNoOp, pause(req, req.module.base + 5, alreadyTrue)));
    auto noOpAfterRestore = noOp.planForce(true);
    CHECK(noOpAfterRestore.has_value() &&
          noOpAfterRestore->value == alreadyTrue);
    CHECK(noOpAfterRestore && noOp.confirmWrite(
        *noOpAfterRestore, pause(req, req.module.base + 5, alreadyTrue)));
    CHECK(noOp.snapshot().state == AuthorizationExperimentState::Restored);
    CHECK(!noOp.snapshot().restoreAvailable);

    // Model the debugger's rare write-verification + rollback failure: the UI
    // cancels its inert proposal, then the next coherent pause sees that the
    // target register did in fact change. The pure state must recover Forced so
    // restoring the captured original remains possible.
    AuthorizationExperiment lateMutation;
    CHECK(lateMutation.request(req) == AuthorizationExperimentIssue::None);
    constexpr uint64_t original = UINT64_C(0xfeedface00000000);
    CHECK(lateMutation.observePause(
        pause(req, req.module.base + 5, original)) ==
          AuthorizationExperimentIssue::None);
    auto attempted = lateMutation.planForce(true);
    CHECK(attempted.has_value());
    lateMutation.cancelPendingWrite();
    CHECK(lateMutation.observePause(
        pause(req, req.module.base + 5, attempted->value)) ==
          AuthorizationExperimentIssue::None);
    const auto recovered = lateMutation.snapshot();
    CHECK(recovered.state == AuthorizationExperimentState::Forced);
    CHECK(recovered.restoreAvailable);
    auto restore = lateMutation.planRestore();
    CHECK(restore.has_value() && restore->value == original);

    AuthorizationExperiment failedBreak;
    CHECK(failedBreak.request(req) == AuthorizationExperimentIssue::None);
    failedBreak.failBreakRequest(AuthorizationExperimentIssue::RunToArmFailed);
    CHECK(failedBreak.snapshot().state ==
          AuthorizationExperimentState::Invalidated);
    CHECK(failedBreak.snapshot().issue ==
          AuthorizationExperimentIssue::RunToArmFailed);
}

void testIdentityAndResumeInvalidation() {
    const auto baseRequest = request();

    // This is the Binary View frame-boundary policy: BreakRequested is exempt
    // from resume invalidation only while its exact checked one-shot is still
    // Pending/Armed.  A Hit snapshot observed after execution has already
    // resumed must not leave selection/document locks stranded.
    CHECK(AuthorizationExperimentMayRemainBreakRequestedWhileRunning(
        AuthorizationExperimentState::BreakRequested, true));
    CHECK(!AuthorizationExperimentMayRemainBreakRequestedWhileRunning(
        AuthorizationExperimentState::BreakRequested, false));
    CHECK(!AuthorizationExperimentMayRemainBreakRequestedWhileRunning(
        AuthorizationExperimentState::Observed, true));

    AuthorizationExperiment missedHitPause;
    CHECK(missedHitPause.request(baseRequest) ==
          AuthorizationExperimentIssue::None);
    if (!AuthorizationExperimentMayRemainBreakRequestedWhileRunning(
            missedHitPause.snapshot().state,
            /*exact checked RunTo is Hit, not Pending/Armed=*/false)) {
        missedHitPause.onResume(baseRequest.target, baseRequest.module);
    }
    CHECK(missedHitPause.snapshot().state ==
          AuthorizationExperimentState::Invalidated);
    CHECK(missedHitPause.snapshot().issue ==
          AuthorizationExperimentIssue::Resumed);

    auto runMismatch = [&](auto mutate,
                           AuthorizationExperimentIssue expected) {
        AuthorizationExperiment experiment;
        CHECK(experiment.request(baseRequest) ==
              AuthorizationExperimentIssue::None);
        auto observation = pause(baseRequest, baseRequest.module.base + 5, 1);
        mutate(observation);
        CHECK(experiment.observePause(observation) == expected);
        const auto snapshot = experiment.snapshot();
        CHECK(snapshot.state == AuthorizationExperimentState::Invalidated);
        CHECK(snapshot.issue == expected);
        CHECK(!snapshot.forceAvailable);
    };

    runMismatch([](auto& value) { value.target.pid += 1; },
                AuthorizationExperimentIssue::ProcessMismatch);
    runMismatch([](auto& value) { value.target.sessionGeneration += 1; },
                AuthorizationExperimentIssue::SessionMismatch);
    runMismatch([](auto& value) { value.module.loadGeneration += 1; },
                AuthorizationExperimentIssue::ModuleMismatch);
    runMismatch([](auto& value) { value.module.base += 0x10000; },
                AuthorizationExperimentIssue::ModuleMismatch);
    runMismatch([](auto& value) { value.module.path = "C:\\other\\auth.exe"; },
                AuthorizationExperimentIssue::ModuleMismatch);
    runMismatch([](auto& value) { value.threadId += 1; },
                AuthorizationExperimentIssue::ThreadMismatch);

    AuthorizationExperiment resumed;
    CHECK(resumed.request(baseRequest) == AuthorizationExperimentIssue::None);
    CHECK(resumed.observePause(
        pause(baseRequest, baseRequest.module.base + 5, UINT64_C(0x55))) ==
          AuthorizationExperimentIssue::None);
    auto force = resumed.planForce(true);
    CHECK(force.has_value());
    resumed.onResume(baseRequest.target, baseRequest.module);
    CHECK(resumed.snapshot().state == AuthorizationExperimentState::Invalidated);
    CHECK(resumed.snapshot().issue == AuthorizationExperimentIssue::Resumed);
    CHECK(!resumed.planRestore());

    // A session change discovered at the resume edge is diagnosed as identity
    // drift rather than the less specific resumed reason.
    AuthorizationExperiment replaced;
    CHECK(replaced.request(baseRequest) == AuthorizationExperimentIssue::None);
    auto newTarget = baseRequest.target;
    ++newTarget.sessionGeneration;
    replaced.onResume(newTarget, baseRequest.module);
    CHECK(replaced.snapshot().issue ==
          AuthorizationExperimentIssue::SessionMismatch);

    AuthorizationExperiment unloaded;
    CHECK(unloaded.request(baseRequest) == AuthorizationExperimentIssue::None);
    auto reloaded = baseRequest.module;
    ++reloaded.loadGeneration;
    CHECK(!unloaded.retainForIdentity(baseRequest.target, reloaded,
                                      baseRequest.threadId));
    CHECK(unloaded.snapshot().issue ==
          AuthorizationExperimentIssue::ModuleMismatch);

    // Canonically equivalent Windows path spelling is still the same exact
    // mapping when base, extent, and per-load generation match.
    AuthorizationExperiment sameMapping;
    CHECK(sameMapping.request(baseRequest) == AuthorizationExperimentIssue::None);
    auto canonical = baseRequest.module;
    canonical.path = "c:/fixtures/./AUTH.exe";
    CHECK(sameMapping.retainForIdentity(baseRequest.target, canonical,
                                        baseRequest.threadId));
}

void testRequestBoundsAndOverflow() {
    AuthorizationExperiment experiment;

    auto missingValidity = request();
    missingValidity.staticCallsite = 0;
    missingValidity.staticCallsiteValid = false;
    CHECK(experiment.request(missingValidity) ==
          AuthorizationExperimentIssue::StaticAddressValidityMissing);

    auto backwards = request();
    backwards.staticContinuation = backwards.staticCallsite;
    CHECK(experiment.request(backwards) ==
          AuthorizationExperimentIssue::InvalidCallContinuation);

    auto tooLong = request();
    tooLong.staticContinuation = 16;
    CHECK(experiment.request(tooLong) ==
          AuthorizationExperimentIssue::InvalidCallContinuation);

    auto outside = request();
    outside.staticCallsite = outside.module.size - 1;
    outside.staticContinuation = outside.module.size;
    CHECK(experiment.request(outside) ==
          AuthorizationExperimentIssue::StaticAddressOutsideImage);

    auto overflow = request();
    overflow.module = module((std::numeric_limits<uint64_t>::max)() - 2);
    overflow.staticContinuation = 5;
    CHECK(experiment.request(overflow) ==
          AuthorizationExperimentIssue::AddressTranslationOverflow);

    auto noTarget = request();
    noTarget.target = {};
    CHECK(experiment.request(noTarget) ==
          AuthorizationExperimentIssue::InvalidTargetIdentity);

    auto noModule = request();
    noModule.module.loadGeneration = 0;
    CHECK(experiment.request(noModule) ==
          AuthorizationExperimentIssue::InvalidModuleIdentity);

    auto sameTruthValues = request();
    sameTruthValues.trueValue = sameTruthValues.falseValue = 1;
    CHECK(experiment.request(sameTruthValues) ==
          AuthorizationExperimentIssue::InvalidTruthValues);

    auto oversizedTruthValue = request();
    oversizedTruthValue.trueValue = 0x100;
    CHECK(experiment.request(oversizedTruthValue) ==
          AuthorizationExperimentIssue::InvalidTruthValues);

    CHECK(AuthorizationExperimentIssueText(
              AuthorizationExperimentIssue::AddressTranslationOverflow)[0] !=
          '\0');
}

} // namespace

int main() {
    testVaZeroAndLowBytePreservation();
    testEaxAndX86Semantics();
    testValidityAndVerificationFailures();
    testNoOpForceAndLateMutationRecovery();
    testIdentityAndResumeInvalidation();
    testRequestBoundsAndOverflow();

    if (failures != 0) {
        std::cerr << "authorization_experiment_test: " << failures
                  << " check(s) failed\n";
        return 1;
    }
    std::cout << "authorization_experiment_test: all checks passed\n";
    return 0;
}
