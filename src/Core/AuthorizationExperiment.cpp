#include "AuthorizationExperiment.h"

#include <limits>

namespace ds {
namespace {

constexpr uint64_t kLowByteMask = UINT64_C(0xff);
constexpr uint64_t kLowDwordMask = UINT64_C(0xffffffff);
constexpr uint64_t kFullMask = (std::numeric_limits<uint64_t>::max)();
constexpr uint64_t kMaximumX86InstructionLength = 15;

uint8_t widthBits(AuthorizationExperimentReturnWidth width) noexcept {
    switch (width) {
    case AuthorizationExperimentReturnWidth::Al: return 8;
    case AuthorizationExperimentReturnWidth::Eax: return 32;
    case AuthorizationExperimentReturnWidth::Rax: return 64;
    case AuthorizationExperimentReturnWidth::Unknown: break;
    }
    return 0;
}

bool checkedAdd(uint64_t left, uint64_t right, uint64_t& result) noexcept {
    if (right > (std::numeric_limits<uint64_t>::max)() - left) return false;
    result = left + right;
    return true;
}

bool sameWritePlan(const AuthorizationExperimentRegisterWrite& left,
                   const AuthorizationExperimentRegisterWrite& right) {
    return left.experimentGeneration == right.experimentGeneration &&
           left.writeId == right.writeId && left.kind == right.kind &&
           DebugTargetIdentityMatches(left.target, right.target) &&
           ExactAuthorizationExperimentModuleMatch(left.module, right.module) &&
           left.threadId == right.threadId &&
           left.expectedRipValid == right.expectedRipValid &&
           left.expectedRip == right.expectedRip &&
           left.registerName == right.registerName &&
           left.contractWidthBits == right.contractWidthBits &&
           left.expectedAccumulator == right.expectedAccumulator &&
           left.accumulatorCompareMask == right.accumulatorCompareMask &&
           left.value == right.value;
}

} // namespace

const char* AuthorizationExperimentIssueText(
    AuthorizationExperimentIssue issue) noexcept {
    switch (issue) {
    case AuthorizationExperimentIssue::None:
        return "ready";
    case AuthorizationExperimentIssue::NoActiveExperiment:
        return "no live authorization experiment is active";
    case AuthorizationExperimentIssue::InvalidTargetIdentity:
        return "the debugger PID/session identity is incomplete";
    case AuthorizationExperimentIssue::InvalidModuleIdentity:
        return "the exact module base, extent, path, and load generation are required";
    case AuthorizationExperimentIssue::InvalidThreadIdentity:
        return "the call instance has no exact thread identity";
    case AuthorizationExperimentIssue::UnsupportedArchitecture:
        return "only x86 and x64 accumulator-return experiments are supported";
    case AuthorizationExperimentIssue::UnsupportedReturnWidth:
        return "the proven return view must be AL, EAX, or x64 RAX";
    case AuthorizationExperimentIssue::InvalidTruthValues:
        return "the proven true/false return values must be distinct and fit the selected accumulator view";
    case AuthorizationExperimentIssue::StaticAddressValidityMissing:
        return "the static image base, callsite, and continuation need explicit validity";
    case AuthorizationExperimentIssue::StaticAddressOutsideImage:
        return "the callsite or continuation is outside the exact module extent";
    case AuthorizationExperimentIssue::InvalidCallContinuation:
        return "the continuation is not immediately after one bounded x86/x64 instruction";
    case AuthorizationExperimentIssue::AddressTranslationOverflow:
        return "static-to-runtime address translation overflowed";
    case AuthorizationExperimentIssue::ProcessMismatch:
        return "the debugger process changed";
    case AuthorizationExperimentIssue::SessionMismatch:
        return "the debugger session generation changed";
    case AuthorizationExperimentIssue::ModuleMismatch:
        return "the module mapping or load incarnation changed";
    case AuthorizationExperimentIssue::ThreadMismatch:
        return "the paused thread is not the requested call instance";
    case AuthorizationExperimentIssue::Resumed:
        return "execution resumed; the captured return value is stale";
    case AuthorizationExperimentIssue::RipUnavailable:
        return "the paused instruction pointer is unavailable";
    case AuthorizationExperimentIssue::NotAtContinuation:
        return "the debugger is paused somewhere other than the exact call continuation";
    case AuthorizationExperimentIssue::AccumulatorUnavailable:
        return "a whole architectural accumulator is unavailable, so a preserving edit is unsafe";
    case AuthorizationExperimentIssue::RegisterViewsConflict:
        return "the supplied RAX/EAX/AL views disagree";
    case AuthorizationExperimentIssue::StaleWritePlan:
        return "the register-write proposal is stale or was superseded";
    case AuthorizationExperimentIssue::RipChangedBeforeWrite:
        return "the instruction pointer changed before the register write was verified";
    case AuthorizationExperimentIssue::WriteVerificationFailed:
        return "the requested accumulator value was not observed after the write";
    case AuthorizationExperimentIssue::RunToArmFailed:
        return "the checked break-after-call request could not be armed";
    case AuthorizationExperimentIssue::RunToCancelled:
        return "the checked break-after-call request was cancelled before it fired";
    }
    return "unknown live authorization experiment issue";
}

bool CompleteAuthorizationExperimentModuleIdentity(
    const AttachedModuleIdentity& module) noexcept {
    return module.base != 0 && module.size != 0 && !module.path.empty() &&
           module.loadGeneration != 0;
}

bool ExactAuthorizationExperimentModuleMatch(
    const AttachedModuleIdentity& expected,
    const AttachedModuleIdentity& actual) {
    return CompleteAuthorizationExperimentModuleIdentity(expected) &&
           CompleteAuthorizationExperimentModuleIdentity(actual) &&
           expected.size == actual.size &&
           expected.loadGeneration == actual.loadGeneration &&
           AttachedModuleIdentityMatches(expected, actual);
}

bool AuthorizationExperimentMayRemainBreakRequestedWhileRunning(
    AuthorizationExperimentState state,
    bool exactCheckedRunToPendingOrArmed) noexcept {
    return state == AuthorizationExperimentState::BreakRequested &&
           exactCheckedRunToPendingOrArmed;
}

void AuthorizationExperiment::invalidate(AuthorizationExperimentIssue issue) {
    state_ = AuthorizationExperimentState::Invalidated;
    issue_ = issue;
    pausedAtContinuation_ = false;
    currentAccumulatorValid_ = false;
    pendingWrite_.reset();
}

AuthorizationExperimentIssue AuthorizationExperiment::identityIssue(
    DebugTargetIdentity target,
    const AttachedModuleIdentity& module,
    uint32_t threadId,
    bool checkThread) const {
    if (!target.valid() || target.pid != request_.target.pid)
        return AuthorizationExperimentIssue::ProcessMismatch;
    if (target.sessionGeneration != request_.target.sessionGeneration)
        return AuthorizationExperimentIssue::SessionMismatch;
    if (!ExactAuthorizationExperimentModuleMatch(request_.module, module))
        return AuthorizationExperimentIssue::ModuleMismatch;
    if (checkThread && (threadId == 0 || threadId != request_.threadId))
        return AuthorizationExperimentIssue::ThreadMismatch;
    return AuthorizationExperimentIssue::None;
}

AuthorizationExperimentIssue AuthorizationExperiment::request(
    const AuthorizationExperimentRequest& request) {
    if (++generation_ == 0) ++generation_;
    state_ = AuthorizationExperimentState::Invalidated;
    issue_ = AuthorizationExperimentIssue::None;
    request_ = request;
    breakTarget_ = {};
    lastObservation_ = {};
    pausedAtContinuation_ = false;
    originalAccumulatorValid_ = false;
    originalAccumulator_ = 0;
    currentAccumulatorValid_ = false;
    currentAccumulator_ = 0;
    pendingWrite_.reset();

    auto reject = [&](AuthorizationExperimentIssue issue) {
        invalidate(issue);
        return issue;
    };

    if (!request.target.valid())
        return reject(AuthorizationExperimentIssue::InvalidTargetIdentity);
    if (!CompleteAuthorizationExperimentModuleIdentity(request.module))
        return reject(AuthorizationExperimentIssue::InvalidModuleIdentity);
    if (request.threadId == 0)
        return reject(AuthorizationExperimentIssue::InvalidThreadIdentity);
    if (request.architecture != AuthorizationExperimentArchitecture::X86 &&
        request.architecture != AuthorizationExperimentArchitecture::X64)
        return reject(AuthorizationExperimentIssue::UnsupportedArchitecture);
    if (request.returnWidth != AuthorizationExperimentReturnWidth::Al &&
        request.returnWidth != AuthorizationExperimentReturnWidth::Eax &&
        request.returnWidth != AuthorizationExperimentReturnWidth::Rax)
        return reject(AuthorizationExperimentIssue::UnsupportedReturnWidth);
    if (request.architecture == AuthorizationExperimentArchitecture::X86 &&
        request.returnWidth == AuthorizationExperimentReturnWidth::Rax)
        return reject(AuthorizationExperimentIssue::UnsupportedReturnWidth);
    const uint8_t contractBits = widthBits(request.returnWidth);
    const uint64_t contractMask = contractBits == 8
        ? kLowByteMask
        : contractBits == 32 ? kLowDwordMask : kFullMask;
    if (request.trueValue == request.falseValue ||
        (request.trueValue & ~contractMask) != 0 ||
        (request.falseValue & ~contractMask) != 0)
        return reject(AuthorizationExperimentIssue::InvalidTruthValues);
    if (!request.staticImageBaseValid || !request.staticCallsiteValid ||
        !request.staticContinuationValid)
        return reject(
            AuthorizationExperimentIssue::StaticAddressValidityMissing);
    if (request.staticCallsite < request.staticImageBase ||
        request.staticContinuation < request.staticImageBase)
        return reject(AuthorizationExperimentIssue::StaticAddressOutsideImage);
    if (request.staticContinuation <= request.staticCallsite ||
        request.staticContinuation - request.staticCallsite >
            kMaximumX86InstructionLength)
        return reject(AuthorizationExperimentIssue::InvalidCallContinuation);

    const uint64_t callsiteRva =
        request.staticCallsite - request.staticImageBase;
    const uint64_t continuationRva =
        request.staticContinuation - request.staticImageBase;
    if (callsiteRva >= request.module.size ||
        continuationRva >= request.module.size)
        return reject(AuthorizationExperimentIssue::StaticAddressOutsideImage);

    uint64_t runtimeCallsite = 0;
    uint64_t runtimeContinuation = 0;
    if (!checkedAdd(request.module.base, callsiteRva, runtimeCallsite) ||
        !checkedAdd(request.module.base, continuationRva,
                    runtimeContinuation))
        return reject(AuthorizationExperimentIssue::AddressTranslationOverflow);

    breakTarget_.valid = true;
    breakTarget_.staticCallsite = request.staticCallsite;
    breakTarget_.staticContinuation = request.staticContinuation;
    breakTarget_.callsiteModuleRva = callsiteRva;
    breakTarget_.continuationModuleRva = continuationRva;
    breakTarget_.runtimeCallsite = runtimeCallsite;
    breakTarget_.runtimeContinuation = runtimeContinuation;
    state_ = AuthorizationExperimentState::BreakRequested;
    issue_ = AuthorizationExperimentIssue::None;
    return issue_;
}

bool AuthorizationExperiment::extractAccumulator(
    const AuthorizationExperimentPauseObservation& observation,
    uint64_t& value,
    AuthorizationExperimentIssue& issue) const {
    if (observation.raxValid && observation.eaxValid &&
        static_cast<uint32_t>(observation.rax) != observation.eax) {
        issue = AuthorizationExperimentIssue::RegisterViewsConflict;
        return false;
    }
    if (observation.eaxValid && observation.alValid &&
        static_cast<uint8_t>(observation.eax) != observation.al) {
        issue = AuthorizationExperimentIssue::RegisterViewsConflict;
        return false;
    }
    if (observation.raxValid && observation.alValid &&
        static_cast<uint8_t>(observation.rax) != observation.al) {
        issue = AuthorizationExperimentIssue::RegisterViewsConflict;
        return false;
    }

    if (request_.architecture == AuthorizationExperimentArchitecture::X64) {
        // AL-only and EAX-only observations cannot preserve/restore the unseen
        // upper RAX bits.  Fail closed even when the predicate consumes AL.
        if (!observation.raxValid) {
            issue = AuthorizationExperimentIssue::AccumulatorUnavailable;
            return false;
        }
        value = observation.rax;
    } else {
        if (observation.eaxValid) {
            value = observation.eax;
        } else if (observation.raxValid && observation.rax <= kLowDwordMask) {
            value = observation.rax;
        } else {
            issue = observation.raxValid
                ? AuthorizationExperimentIssue::RegisterViewsConflict
                : AuthorizationExperimentIssue::AccumulatorUnavailable;
            return false;
        }
    }
    issue = AuthorizationExperimentIssue::None;
    return true;
}

AuthorizationExperimentIssue AuthorizationExperiment::observePause(
    const AuthorizationExperimentPauseObservation& observation) {
    if (state_ == AuthorizationExperimentState::Empty ||
        state_ == AuthorizationExperimentState::Invalidated) {
        return AuthorizationExperimentIssue::NoActiveExperiment;
    }

    const AuthorizationExperimentIssue identity = identityIssue(
        observation.target, observation.module, observation.threadId, true);
    if (identity != AuthorizationExperimentIssue::None) {
        invalidate(identity);
        return identity;
    }
    if (!observation.paused) {
        invalidate(AuthorizationExperimentIssue::Resumed);
        return issue_;
    }

    lastObservation_ = observation;
    if (!observation.ripValid) {
        pausedAtContinuation_ = false;
        issue_ = AuthorizationExperimentIssue::RipUnavailable;
        return issue_;
    }
    if (observation.rip != breakTarget_.runtimeContinuation) {
        if (pendingWrite_) {
            invalidate(AuthorizationExperimentIssue::RipChangedBeforeWrite);
            return issue_;
        }
        pausedAtContinuation_ = false;
        issue_ = AuthorizationExperimentIssue::NotAtContinuation;
        return issue_;
    }

    pausedAtContinuation_ = true;
    uint64_t accumulator = 0;
    AuthorizationExperimentIssue accumulatorIssue =
        AuthorizationExperimentIssue::None;
    if (!extractAccumulator(observation, accumulator, accumulatorIssue)) {
        currentAccumulatorValid_ = false;
        pendingWrite_.reset();
        state_ = AuthorizationExperimentState::PausedAtContinuation;
        issue_ = accumulatorIssue;
        return issue_;
    }

    const AuthorizationExperimentState previousState = state_;
    if (!originalAccumulatorValid_) {
        originalAccumulator_ = accumulator;
        originalAccumulatorValid_ = true;
    }
    currentAccumulator_ = accumulator;
    currentAccumulatorValid_ = true;
    // A debugger write can fail its readback and then also fail rollback.  The
    // adapter deliberately reports that as failure, but a later coherent pause
    // observation is still authoritative.  Preserve the one-click recovery
    // path whenever the actual whole accumulator differs from the original.
    if (accumulator != originalAccumulator_) {
        state_ = AuthorizationExperimentState::Forced;
    } else if (previousState == AuthorizationExperimentState::Forced ||
               previousState == AuthorizationExperimentState::Restored) {
        state_ = AuthorizationExperimentState::Restored;
    } else if (state_ == AuthorizationExperimentState::BreakRequested ||
               state_ == AuthorizationExperimentState::PausedAtContinuation) {
        state_ = AuthorizationExperimentState::Observed;
    }
    issue_ = AuthorizationExperimentIssue::None;
    return issue_;
}

AuthorizationExperimentRegisterWrite AuthorizationExperiment::makeWrite(
    AuthorizationExperimentWriteKind kind,
    uint64_t value) {
    if (++writeSequence_ == 0) ++writeSequence_;
    AuthorizationExperimentRegisterWrite write;
    write.experimentGeneration = generation_;
    write.writeId = writeSequence_;
    write.kind = kind;
    write.target = request_.target;
    write.module = request_.module;
    write.threadId = request_.threadId;
    write.expectedRip = breakTarget_.runtimeContinuation;
    write.expectedRipValid = breakTarget_.valid;
    write.registerName = "rax";
    write.contractWidthBits = widthBits(request_.returnWidth);
    write.expectedAccumulator = currentAccumulator_;
    write.accumulatorCompareMask =
        request_.architecture == AuthorizationExperimentArchitecture::X64
            ? kFullMask
            : kLowDwordMask;
    write.value = request_.architecture == AuthorizationExperimentArchitecture::X64
        ? value
        : value & kLowDwordMask;
    pendingWrite_ = write;
    issue_ = AuthorizationExperimentIssue::None;
    return write;
}

std::optional<AuthorizationExperimentRegisterWrite>
AuthorizationExperiment::planForce(bool value) {
    if (!pausedAtContinuation_ || !originalAccumulatorValid_ ||
        !currentAccumulatorValid_ ||
        (state_ != AuthorizationExperimentState::Observed &&
         state_ != AuthorizationExperimentState::Forced &&
         state_ != AuthorizationExperimentState::Restored)) {
        issue_ = state_ == AuthorizationExperimentState::Empty ||
                         state_ == AuthorizationExperimentState::Invalidated
            ? AuthorizationExperimentIssue::NoActiveExperiment
            : AuthorizationExperimentIssue::AccumulatorUnavailable;
        return std::nullopt;
    }

    const uint64_t logicalValue = value
        ? request_.trueValue : request_.falseValue;
    uint64_t desired = logicalValue;
    if (request_.returnWidth == AuthorizationExperimentReturnWidth::Al) {
        // Whole-register write, preserving every bit outside AL.
        desired = (currentAccumulator_ & ~kLowByteMask) |
                  (logicalValue & kLowByteMask);
    } else if (request_.returnWidth ==
               AuthorizationExperimentReturnWidth::Eax) {
        // Architectural EAX writes clear RAX[63:32] on x64. Supplying the
        // proven status/boolean value through the whole-register API models
        // that result exactly.
        desired = logicalValue & kLowDwordMask;
    }
    return makeWrite(value ? AuthorizationExperimentWriteKind::ForceTrue
                           : AuthorizationExperimentWriteKind::ForceFalse,
                     desired);
}

std::optional<AuthorizationExperimentRegisterWrite>
AuthorizationExperiment::planRestore() {
    if (!pausedAtContinuation_ || !originalAccumulatorValid_ ||
        !currentAccumulatorValid_ ||
        state_ != AuthorizationExperimentState::Forced) {
        issue_ = state_ == AuthorizationExperimentState::Empty ||
                         state_ == AuthorizationExperimentState::Invalidated
            ? AuthorizationExperimentIssue::NoActiveExperiment
            : AuthorizationExperimentIssue::AccumulatorUnavailable;
        return std::nullopt;
    }
    return makeWrite(AuthorizationExperimentWriteKind::Restore,
                     originalAccumulator_);
}

bool AuthorizationExperiment::confirmWrite(
    const AuthorizationExperimentRegisterWrite& plan,
    const AuthorizationExperimentPauseObservation& afterWrite) {
    if (state_ == AuthorizationExperimentState::Empty ||
        state_ == AuthorizationExperimentState::Invalidated ||
        !pendingWrite_ || !sameWritePlan(plan, *pendingWrite_)) {
        if (state_ != AuthorizationExperimentState::Invalidated)
            issue_ = AuthorizationExperimentIssue::StaleWritePlan;
        return false;
    }

    const AuthorizationExperimentIssue identity = identityIssue(
        afterWrite.target, afterWrite.module, afterWrite.threadId, true);
    if (identity != AuthorizationExperimentIssue::None) {
        invalidate(identity);
        return false;
    }
    if (!afterWrite.paused) {
        invalidate(AuthorizationExperimentIssue::Resumed);
        return false;
    }
    if (!afterWrite.ripValid ||
        afterWrite.rip != breakTarget_.runtimeContinuation) {
        invalidate(AuthorizationExperimentIssue::RipChangedBeforeWrite);
        return false;
    }

    uint64_t observedAccumulator = 0;
    AuthorizationExperimentIssue accumulatorIssue =
        AuthorizationExperimentIssue::None;
    if (!extractAccumulator(afterWrite, observedAccumulator,
                            accumulatorIssue)) {
        issue_ = accumulatorIssue;
        return false;
    }
    if ((observedAccumulator & plan.accumulatorCompareMask) !=
        (plan.value & plan.accumulatorCompareMask)) {
        issue_ = AuthorizationExperimentIssue::WriteVerificationFailed;
        return false;
    }

    const AuthorizationExperimentState previousState = state_;
    lastObservation_ = afterWrite;
    pausedAtContinuation_ = true;
    currentAccumulator_ = observedAccumulator;
    currentAccumulatorValid_ = true;
    if (plan.kind == AuthorizationExperimentWriteKind::Restore) {
        state_ = AuthorizationExperimentState::Restored;
    } else if (observedAccumulator == originalAccumulator_) {
        // A logical force can be an exact no-op (for example AL was already
        // true). Do not manufacture a Forced state with no possible restore.
        state_ = previousState == AuthorizationExperimentState::Forced ||
                         previousState == AuthorizationExperimentState::Restored
            ? AuthorizationExperimentState::Restored
            : AuthorizationExperimentState::Observed;
    } else {
        state_ = AuthorizationExperimentState::Forced;
    }
    pendingWrite_.reset();
    issue_ = AuthorizationExperimentIssue::None;
    return true;
}

void AuthorizationExperiment::cancelPendingWrite() {
    pendingWrite_.reset();
    if (state_ != AuthorizationExperimentState::Invalidated)
        issue_ = AuthorizationExperimentIssue::None;
}

void AuthorizationExperiment::failBreakRequest(
    AuthorizationExperimentIssue issue) {
    if (state_ != AuthorizationExperimentState::BreakRequested) return;
    if (issue != AuthorizationExperimentIssue::RunToArmFailed &&
        issue != AuthorizationExperimentIssue::RunToCancelled)
        return;
    invalidate(issue);
}

void AuthorizationExperiment::onResume(
    DebugTargetIdentity currentTarget,
    const AttachedModuleIdentity& currentModule) {
    if (state_ == AuthorizationExperimentState::Empty ||
        state_ == AuthorizationExperimentState::Invalidated)
        return;
    const AuthorizationExperimentIssue identity = identityIssue(
        currentTarget, currentModule, 0, false);
    invalidate(identity == AuthorizationExperimentIssue::None
        ? AuthorizationExperimentIssue::Resumed
        : identity);
}

bool AuthorizationExperiment::retainForIdentity(
    DebugTargetIdentity currentTarget,
    const AttachedModuleIdentity& currentModule,
    uint32_t currentThreadId) {
    if (state_ == AuthorizationExperimentState::Empty ||
        state_ == AuthorizationExperimentState::Invalidated)
        return false;
    const AuthorizationExperimentIssue identity = identityIssue(
        currentTarget, currentModule, currentThreadId, true);
    if (identity != AuthorizationExperimentIssue::None) {
        invalidate(identity);
        return false;
    }
    return true;
}

void AuthorizationExperiment::reset() {
    state_ = AuthorizationExperimentState::Empty;
    issue_ = AuthorizationExperimentIssue::None;
    request_ = {};
    breakTarget_ = {};
    lastObservation_ = {};
    pausedAtContinuation_ = false;
    originalAccumulatorValid_ = false;
    originalAccumulator_ = 0;
    currentAccumulatorValid_ = false;
    currentAccumulator_ = 0;
    pendingWrite_.reset();
}

AuthorizationExperimentSnapshot AuthorizationExperiment::snapshot() const {
    AuthorizationExperimentSnapshot result;
    result.state = state_;
    result.issue = issue_;
    result.generation = generation_;
    result.request = request_;
    result.breakTarget = breakTarget_;
    result.lastObservation = lastObservation_;
    result.pausedAtContinuation = pausedAtContinuation_;
    result.originalAccumulatorValid = originalAccumulatorValid_;
    result.originalAccumulator = originalAccumulator_;
    result.currentAccumulatorValid = currentAccumulatorValid_;
    result.currentAccumulator = currentAccumulator_;
    result.forceAvailable = pausedAtContinuation_ &&
        originalAccumulatorValid_ && currentAccumulatorValid_ &&
        state_ != AuthorizationExperimentState::Empty &&
        state_ != AuthorizationExperimentState::Invalidated;
    result.restoreAvailable = result.forceAvailable &&
        state_ == AuthorizationExperimentState::Forced &&
        currentAccumulator_ != originalAccumulator_;
    result.pendingWrite = pendingWrite_;
    return result;
}

} // namespace ds
