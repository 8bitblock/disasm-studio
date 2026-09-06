#pragma once
//
// AuthorizationExperiment.h
// Pure state for one deliberately narrow live authorization experiment:
// break at the exact instruction immediately following a proven call, inspect
// its scalar accumulator return, and (only while that same stop is current)
// propose a reversible register edit.  This module neither owns a debugger nor
// reads/writes target memory.  In particular, no byte-patch representation is
// present in this API.
//

#include "AttachImagePolicy.h"
#include "DebugTargetIdentity.h"

#include <cstdint>
#include <optional>
#include <string>

namespace ds {

enum class AuthorizationExperimentArchitecture : uint8_t {
    Unknown = 0,
    X86,
    X64,
};

// The consumer's proven view of the predicate result.  These are architectural
// accumulator aliases, not host integer widths.
enum class AuthorizationExperimentReturnWidth : uint8_t {
    Unknown = 0,
    Al = 8,
    Eax = 32,
    Rax = 64,
};

enum class AuthorizationExperimentState : uint8_t {
    Empty = 0,
    BreakRequested,
    // The exact continuation is paused, but a safe whole-accumulator value was
    // unavailable or the independently supplied aliases disagreed.
    PausedAtContinuation,
    Observed,
    Forced,
    Restored,
    Invalidated,
};

enum class AuthorizationExperimentIssue : uint8_t {
    None = 0,
    NoActiveExperiment,
    InvalidTargetIdentity,
    InvalidModuleIdentity,
    InvalidThreadIdentity,
    UnsupportedArchitecture,
    UnsupportedReturnWidth,
    InvalidTruthValues,
    StaticAddressValidityMissing,
    StaticAddressOutsideImage,
    InvalidCallContinuation,
    AddressTranslationOverflow,
    ProcessMismatch,
    SessionMismatch,
    ModuleMismatch,
    ThreadMismatch,
    Resumed,
    RipUnavailable,
    NotAtContinuation,
    AccumulatorUnavailable,
    RegisterViewsConflict,
    StaleWritePlan,
    RipChangedBeforeWrite,
    WriteVerificationFailed,
    RunToArmFailed,
    RunToCancelled,
};

const char* AuthorizationExperimentIssueText(
    AuthorizationExperimentIssue issue) noexcept;

struct AuthorizationExperimentRequest {
    DebugTargetIdentity target{};
    AttachedModuleIdentity module;
    uint32_t threadId = 0;
    AuthorizationExperimentArchitecture architecture =
        AuthorizationExperimentArchitecture::Unknown;
    AuthorizationExperimentReturnWidth returnWidth =
        AuthorizationExperimentReturnWidth::Unknown;

    // Exact values for the adapter-proven logical outcomes. Defaults model a
    // conventional C/C++ boolean; status-style predicates may instead use
    // true=0 and false=1. Values must be distinct and fit the selected view.
    uint64_t trueValue = 1;
    uint64_t falseValue = 0;

    // Validity is intentionally independent of value.  A raw/ELF analysis
    // image, call instruction, or continuation at static VA zero is legal.
    uint64_t staticImageBase = 0;
    bool staticImageBaseValid = false;
    uint64_t staticCallsite = 0;
    bool staticCallsiteValid = false;
    uint64_t staticContinuation = 0;
    bool staticContinuationValid = false;
};

struct AuthorizationExperimentBreakTarget {
    bool valid = false;
    uint64_t staticCallsite = 0;
    uint64_t staticContinuation = 0;
    uint64_t callsiteModuleRva = 0;
    uint64_t continuationModuleRva = 0;
    uint64_t runtimeCallsite = 0;
    uint64_t runtimeContinuation = 0;
};

// One debugger snapshot at a pause.  Validity bits are retained exactly so the
// UI can distinguish an observed zero from an unavailable register.  The state
// machine checks overlapping aliases for consistency when more than one was
// supplied.
struct AuthorizationExperimentPauseObservation {
    DebugTargetIdentity target{};
    AttachedModuleIdentity module;
    uint32_t threadId = 0;
    bool paused = false;

    uint64_t rip = 0;
    bool ripValid = false;
    uint64_t rax = 0;
    bool raxValid = false;
    uint32_t eax = 0;
    bool eaxValid = false;
    uint8_t al = 0;
    bool alValid = false;
};

enum class AuthorizationExperimentWriteKind : uint8_t {
    ForceFalse = 0,
    ForceTrue,
    Restore,
};

// An inert, register-only proposal.  The debugger adapter must re-check every
// identity and expected RIP before calling its atomic register setter.  `rax`
// is used because Debugger's public register editor is whole-register based.
// For an EAX contract, value is already zero-extended exactly as an x64 EAX
// write would be.  No memory address or replacement-byte field is exposed.
struct AuthorizationExperimentRegisterWrite {
    uint64_t experimentGeneration = 0;
    uint64_t writeId = 0;
    AuthorizationExperimentWriteKind kind =
        AuthorizationExperimentWriteKind::ForceFalse;
    DebugTargetIdentity target{};
    AttachedModuleIdentity module;
    uint32_t threadId = 0;
    uint64_t expectedRip = 0;
    bool expectedRipValid = false;
    std::string registerName;
    uint8_t contractWidthBits = 0;
    uint64_t expectedAccumulator = 0;
    uint64_t accumulatorCompareMask = 0;
    uint64_t value = 0;
};

struct AuthorizationExperimentSnapshot {
    AuthorizationExperimentState state = AuthorizationExperimentState::Empty;
    AuthorizationExperimentIssue issue = AuthorizationExperimentIssue::None;
    uint64_t generation = 0;
    AuthorizationExperimentRequest request;
    AuthorizationExperimentBreakTarget breakTarget;
    AuthorizationExperimentPauseObservation lastObservation;
    bool pausedAtContinuation = false;
    bool originalAccumulatorValid = false;
    uint64_t originalAccumulator = 0;
    bool currentAccumulatorValid = false;
    uint64_t currentAccumulator = 0;
    bool forceAvailable = false;
    bool restoreAvailable = false;
    std::optional<AuthorizationExperimentRegisterWrite> pendingWrite;
};

bool CompleteAuthorizationExperimentModuleIdentity(
    const AttachedModuleIdentity& module) noexcept;
bool ExactAuthorizationExperimentModuleMatch(
    const AttachedModuleIdentity& expected,
    const AttachedModuleIdentity& actual);

// Execution may remain live only while the exact checked continuation request
// is still Pending/Armed.  Once that request has Hit (or reached any other
// terminal state), a Running debugger snapshot means the return pause was
// missed and the experiment must be invalidated like every captured value.
bool AuthorizationExperimentMayRemainBreakRequestedWhileRunning(
    AuthorizationExperimentState state,
    bool exactCheckedRunToPendingOrArmed) noexcept;

class AuthorizationExperiment {
public:
    // Replaces any earlier experiment.  On success the returned issue is None
    // and breakTarget().runtimeContinuation is the only address to arm.
    AuthorizationExperimentIssue request(
        const AuthorizationExperimentRequest& request);

    // Captures the original accumulator only on the first valid observation at
    // the exact continuation.  A pause elsewhere is non-fatal because unrelated
    // user/debugger breakpoints can legitimately fire before this one.
    AuthorizationExperimentIssue observePause(
        const AuthorizationExperimentPauseObservation& observation);

    // Produces an inert proposal and records a nonce.  A newer proposal
    // supersedes an older one.  State changes only after confirmWrite observes
    // the requested value at the same exact paused context.
    std::optional<AuthorizationExperimentRegisterWrite> planForce(bool value);
    std::optional<AuthorizationExperimentRegisterWrite> planRestore();
    bool confirmWrite(
        const AuthorizationExperimentRegisterWrite& plan,
        const AuthorizationExperimentPauseObservation& afterWrite);
    void cancelPendingWrite();

    // Consume the terminal lifecycle of the exact checked RunTo request. Only
    // a pending break request can be failed/cancelled through this entrypoint.
    void failBreakRequest(AuthorizationExperimentIssue issue);

    // Any resumed execution makes the captured return stale.  Mismatched PID,
    // generation, or module incarnation takes precedence in the diagnostic.
    void onResume(DebugTargetIdentity currentTarget,
                  const AttachedModuleIdentity& currentModule);
    // Frame-boundary guard for detach/reattach and module unload/reload.  Thread
    // identity is included because the experiment is bound to one call instance.
    bool retainForIdentity(DebugTargetIdentity currentTarget,
                           const AttachedModuleIdentity& currentModule,
                           uint32_t currentThreadId);

    void reset();
    AuthorizationExperimentSnapshot snapshot() const;
    const AuthorizationExperimentBreakTarget& breakTarget() const noexcept {
        return breakTarget_;
    }

private:
    void invalidate(AuthorizationExperimentIssue issue);
    AuthorizationExperimentIssue identityIssue(
        DebugTargetIdentity target,
        const AttachedModuleIdentity& module,
        uint32_t threadId,
        bool checkThread) const;
    bool extractAccumulator(
        const AuthorizationExperimentPauseObservation& observation,
        uint64_t& value,
        AuthorizationExperimentIssue& issue) const;
    AuthorizationExperimentRegisterWrite makeWrite(
        AuthorizationExperimentWriteKind kind,
        uint64_t value);

    AuthorizationExperimentState state_ = AuthorizationExperimentState::Empty;
    AuthorizationExperimentIssue issue_ = AuthorizationExperimentIssue::None;
    uint64_t generation_ = 0;
    uint64_t writeSequence_ = 0;
    AuthorizationExperimentRequest request_;
    AuthorizationExperimentBreakTarget breakTarget_;
    AuthorizationExperimentPauseObservation lastObservation_;
    bool pausedAtContinuation_ = false;
    bool originalAccumulatorValid_ = false;
    uint64_t originalAccumulator_ = 0;
    bool currentAccumulatorValid_ = false;
    uint64_t currentAccumulator_ = 0;
    std::optional<AuthorizationExperimentRegisterWrite> pendingWrite_;
};

} // namespace ds
