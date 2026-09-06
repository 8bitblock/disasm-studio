#pragma once
//
// AuthorizationPatchAdvisor.h
// Pure, inert advice for the narrow authorization-predicate patch shape which
// DisasmStudio can describe honestly.  This module never mutates a BinaryFile,
// a project, or a live process.  Decoder-facing code must prove every safety
// fact explicitly; an omitted or incomplete fact is a refusal, not a guess.
//

#include <cstdint>
#include <string>
#include <vector>

namespace ds {

enum class AuthorizationPatchArchitecture : uint8_t {
    Unsupported = 0,
    X86,
    X64,
};

enum class AuthorizationPatchBooleanContract : uint8_t {
    Unknown = 0,
    // Every reachable return is proven to produce exactly zero or one.
    CanonicalZeroOrOne,
    // The adapter knows only that zero/nonzero differ, but not which means true.
    // This remains an ambiguity and cannot produce a byte plan.
    ZeroOrNonzero,
    // Exact truth contracts retained from the predicate/verifier analysis.
    NonzeroIsTrue,
    ZeroIsTrue,
    OneIsTrue,
};

enum class AuthorizationPatchReturnStyle : uint8_t {
    Unknown = 0,
    NearReturn,
    // x86 `ret imm16`; stackPopBytes is part of the proven ABI contract.
    NearReturnPop,
};

enum class AuthorizationPatchEffect : uint8_t {
    ForceFalse = 0,
    ForceTrue,
};

// Every value is a hard refusal.  Multiple independent refusals can be
// returned together so the UI does not imply that fixing one uncertainty makes
// an unsafe suggestion safe.
enum class AuthorizationPatchRefusal : uint8_t {
    InvalidFunctionAddress = 0,
    UnsupportedArchitecture,
    SectionExecutionUnknown,
    NonExecutableDestination,
    ReturnAnalysisIncomplete,
    AmbiguousBooleanContract,
    UnsupportedReturnWidth,
    AuthorizationLinkUnproven,
    NotCentralizedPredicate,
    EntryCoverageIncomplete,
    AlternateEntryPresent,
    ReturnStyleAnalysisIncomplete,
    UnsupportedReturnStyle,
    SideEffectAnalysisIncomplete,
    StringOrHeapCleanup,
    OtherSideEffects,
    StackCookieOrSecurityEpilogue,
    TransportWithoutAuthorizationState,
    EvidenceMissing,
    InsufficientProofConfidence,
    InsufficientBytes,
    ReplacementExtentUnproven,
    AddressRangeOverflow,
};

const char* AuthorizationPatchRefusalText(
    AuthorizationPatchRefusal refusal) noexcept;

struct AuthorizationPatchAdvisorInput {
    AuthorizationPatchArchitecture architecture =
        AuthorizationPatchArchitecture::Unsupported;

    // addressValid is deliberately separate so a mapped function at VA zero is
    // representable and can receive an inert byte plan.
    uint64_t functionAddress = 0;
    bool functionAddressValid = false;
    std::vector<uint8_t> functionBytes;

    // File availability is not function ownership: bytes after a tiny
    // predicate can belong to its neighbour.  The adapter must independently
    // prove a contiguous entry-owned span, including exact function-boundary
    // scope, before this advisor may replace any of it.
    bool replacementExtentOwned = false;
    uint64_t contiguousEntryOwnedBytes = 0;

    bool sectionExecutionKnown = false;
    bool sectionExecutable = false;

    bool returnAnalysisComplete = false;
    AuthorizationPatchBooleanContract booleanContract =
        AuthorizationPatchBooleanContract::Unknown;
    // The adapter must know whether the ABI consumes AL, EAX, or RAX.  Writing
    // EAX safely supplies all three canonical views for widths 8/32/64.
    uint8_t returnWidthBits = 0;

    // A candidate must be linked by data/control-flow evidence to authorization
    // state, and must itself be the centralized predicate rather than an HTTP
    // success check, UI string branch, or feature-local cleanup path.
    bool authorizationStateLinked = false;
    bool centralizedPredicate = false;

    // Proves that replacing the public entry controls every call while not
    // bypassing an alternate interior entry.
    bool entryCoverageComplete = false;
    bool alternateEntryPresent = false;

    bool returnStyleAnalysisComplete = false;
    AuthorizationPatchReturnStyle returnStyle =
        AuthorizationPatchReturnStyle::Unknown;
    uint16_t stackPopBytes = 0;

    bool sideEffectAnalysisComplete = false;
    bool stringOrHeapCleanupPresent = false;
    bool otherSideEffectsPresent = false;
    bool stackCookieOrSecurityEpiloguePresent = false;

    // Set for a candidate which changes only request/transport behavior.  Such
    // a patch cannot establish a server, signature, or feature authorization
    // result and is always suppressed.
    bool transportBehaviorOnly = false;

    float proofConfidence = 0.0f;
    std::string evidence;
};

struct AuthorizationPatchBytePlan {
    AuthorizationPatchEffect effect = AuthorizationPatchEffect::ForceFalse;
    uint64_t address = 0;
    bool addressValid = false;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> replacementBytes;
    float confidence = 0.0f;
    std::string evidence;
};

struct AuthorizationPatchAdvice {
    // eligible means exactly two inert plans (false and true) were emitted.
    // It does not mean that either plan was applied or persisted.
    bool eligible = false;
    std::vector<AuthorizationPatchBytePlan> suggestions;
    std::vector<AuthorizationPatchRefusal> refusals;
};

AuthorizationPatchAdvice AdviseAuthorizationPredicatePatch(
    const AuthorizationPatchAdvisorInput& input);

} // namespace ds
