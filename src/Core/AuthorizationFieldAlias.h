#pragma once
//
// AuthorizationFieldAlias.h
// Pure, bounded interprocedural correlation for FuncAnnotate's exact
// formal-parameter-rooted field observations.  A field is never identified by
// displacement alone: its stable key is (proved object root set, displacement,
// width).  Decoder-facing adapters must provide exact direct-call argument
// bindings; prose, names, and guessed argument values are deliberately absent.
//

#include "FuncAnnotate.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

// One function-local formal-parameter root.  Numeric zero is a valid function
// address when functionVAValid is true.
struct AuthorizationFieldRoot {
    uint64_t functionVA = 0;
    bool functionVAValid = false;
    uint32_t formalParameterIndex = 0;
    bool formalParameterIndexValid = false;
};

bool AuthorizationFieldRootEquivalentExact(
    const AuthorizationFieldRoot& left,
    const AuthorizationFieldRoot& right) noexcept;

// Adapter-proved binding at one exact direct call:
//
//   callerRoot  --passed as argumentIndex-->  calleeFormal
//
// directTargetVA and argumentIndex intentionally duplicate the destination
// identity.  The pure correlator checks both so stale/misaligned adapter rows
// cannot silently merge objects.
struct AuthorizationFieldRootBindingInput {
    AuthorizationFieldRoot callerRoot;
    AuthorizationFieldRoot calleeFormal;

    uint64_t callVA = 0;
    bool callVAValid = false;
    uint64_t directTargetVA = 0;
    bool directTargetVAValid = false;
    uint32_t argumentIndex = 0;
    bool argumentIndexValid = false;

    // Formal provenance can also describe an interior pointer (for example
    // lea rdx,[rcx+0x10]).  This correlator intentionally accepts only an
    // unchanged object base: otherwise every callee field displacement would
    // require a checked translation.  Adapters must publish the proved bias,
    // including a valid zero.
    int64_t callerRootBias = 0;
    bool callerRootBiasValid = false;

    bool directCallExact = false;
    bool argumentSourceExact = false;
    bool complete = true;
    float confidence = 0.0f;
    std::string evidence;
};

struct AuthorizationFieldAliasLimits {
    size_t maxAccessInputs = 32768;
    size_t maxBindingInputs = 32768;
    size_t maxRoots = 8192;
    size_t maxObjects = 8192;
    size_t maxFields = 16384;
    size_t maxAliasesPerObject = 1024;
    size_t maxAccessesPerField = 4096;
    size_t maxEvidencePerObject = 256;
    size_t maxRejectedAccesses = 4096;
    size_t maxRejectedBindings = 4096;
    size_t cancellationCheckInterval = 64;
};

struct AuthorizationFieldAliasInput {
    // Exact, per-access facts copied directly from
    // FuncAnnotations::fieldAccesses.  Inexact/widthless rows are retained as
    // explicit rejections and never enter an identity.
    std::vector<ObjectFieldAccessObservation> accesses;
    std::vector<AuthorizationFieldRootBindingInput> bindings;

    // Scope completeness is supplied by the adapter.  It is separate from
    // processing completeness: a fully executed correlator can still honestly
    // report that the caller did not enumerate every function/call binding.
    bool accessesComplete = true;
    std::string accessesIncompleteReason;
    bool bindingsComplete = true;
    std::string bindingsIncompleteReason;

    AuthorizationFieldAliasLimits limits;
    std::function<bool()> cancelled;
};

// Lossless bridge from FuncAnnotate's decoder-facing fact to this correlator's
// checked binding schema.  AppendAuthorizationFieldAliasFacts also carries the
// per-function access/binding completeness into the aggregate input.
AuthorizationFieldRootBindingInput AdaptAuthorizationFieldRootBinding(
    const DirectCallFormalBindingObservation& observation);
void AppendAuthorizationFieldAliasFacts(
    AuthorizationFieldAliasInput& destination,
    const FuncAnnotations& annotations);

enum class AuthorizationFieldBindingRejectReason : uint8_t {
    InvalidRoot = 0,
    MissingCallsite,
    InexactDirectCall,
    InexactArgumentSource,
    IncompleteFact,
    CalleeTargetMismatch,
    FormalArgumentMismatch,
    MissingRootBias,
    AdjustedRoot,
    RootLimit,
    CyclicBinding,
    ConflictingBinding,
    AmbiguousCalleeFormal,
};

enum class AuthorizationFieldAccessRejectReason : uint8_t {
    InvalidRoot = 0,
    MissingInstruction,
    MissingOperand,
    MissingDisplacement,
    MissingWidth,
    InexactObservation,
    RootLimit,
};

const char* AuthorizationFieldBindingRejectReasonText(
    AuthorizationFieldBindingRejectReason reason) noexcept;
const char* AuthorizationFieldAccessRejectReasonText(
    AuthorizationFieldAccessRejectReason reason) noexcept;

enum class AuthorizationFieldAliasEvidenceKind : uint8_t {
    ExactDirectCallBinding = 0,
    FieldRead,
    FieldWrite,
    BindingRejected,
    ScopeIncomplete,
    OutputTruncated,
};

struct AuthorizationFieldAliasEvidence {
    AuthorizationFieldAliasEvidenceKind kind =
        AuthorizationFieldAliasEvidenceKind::ExactDirectCallBinding;
    size_t inputIndex = 0;
    bool inputIndexValid = false;
    uint64_t address = 0;
    bool addressValid = false;
    std::string text;
};

struct AuthorizationRejectedFieldBinding {
    size_t inputIndex = 0;
    AuthorizationFieldRootBindingInput binding;
    AuthorizationFieldBindingRejectReason reason =
        AuthorizationFieldBindingRejectReason::InvalidRoot;
    std::string evidence;
};

struct AuthorizationRejectedFieldAccess {
    size_t inputIndex = 0;
    ObjectFieldAccessObservation access;
    AuthorizationFieldAccessRejectReason reason =
        AuthorizationFieldAccessRejectReason::InvalidRoot;
    std::string evidence;
};

struct AuthorizationAcceptedFieldBinding {
    size_t inputIndex = 0;
    AuthorizationFieldRootBindingInput binding;
    std::string evidence;
};

// One stable, report-local object identity.  canonicalRoot is the smallest
// upstream root (a zero-indegree root is preferred), and stableId is derived
// from it rather than from an allocation-order counter.
struct AuthorizationStableObjectIdentity {
    size_t index = 0;
    AuthorizationFieldRoot canonicalRoot;
    std::string stableId;
    std::vector<AuthorizationFieldRoot> aliases;
    std::vector<size_t> acceptedBindingInputIndices;
    std::vector<AuthorizationFieldAliasEvidence> evidence;
    bool complete = true;
    std::string incompleteReason;
};

struct AuthorizationStableFieldAccess {
    size_t inputIndex = 0;
    AuthorizationFieldRoot observedRoot;
    uint64_t instructionVA = 0;
    bool instructionVAValid = false;
    uint32_t operandIndex = 0;
    bool operandIndexValid = false;
    ObjectFieldAccessKind access = ObjectFieldAccessKind::Read;
    bool exact = false;
    float confidence = 0.0f;
    std::string evidence;
};

// Exact stable field key.  A ReadWrite observation appears once in each of
// reads and writes, with its inputIndex allowing de-duplication by consumers.
struct AuthorizationStableFieldIdentity {
    size_t objectIndex = 0;
    std::string stableId;
    int64_t displacement = 0;
    uint16_t widthBits = 0;
    std::vector<AuthorizationStableFieldAccess> reads;
    std::vector<AuthorizationStableFieldAccess> writes;
    std::vector<AuthorizationFieldAliasEvidence> evidence;

    // True when the same proved object+displacement was observed at another
    // exact width.  Those rows remain separate identities and are never merged.
    bool overlapsDifferentWidth = false;
    bool complete = true;
    std::string incompleteReason;
};

struct AuthorizationFieldAliasCompleteness {
    // complete means all admitted input was processed without cancellation or
    // caps.  allBindingsResolved separately reports conservative rejection of
    // cycles/conflicts/ambiguity; a complete analysis may validly reject them.
    bool complete = true;
    bool cancelled = false;
    bool accessesScopeComplete = true;
    bool bindingsScopeComplete = true;
    bool allBindingsResolved = true;

    bool accessInputsTruncated = false;
    bool bindingInputsTruncated = false;
    bool rootsTruncated = false;
    bool objectsTruncated = false;
    bool fieldsTruncated = false;
    bool aliasesTruncated = false;
    bool fieldAccessesTruncated = false;
    bool evidenceTruncated = false;
    bool rejectedAccessesTruncated = false;
    bool rejectedBindingsTruncated = false;

    size_t inputAccessCount = 0;
    size_t processedAccessCount = 0;
    size_t acceptedAccessCount = 0;
    size_t rejectedAccessCount = 0;
    size_t inputBindingCount = 0;
    size_t processedBindingCount = 0;
    size_t acceptedBindingCount = 0;
    size_t rejectedBindingCount = 0;
    std::string reason;
};

struct AuthorizationFieldAliasReport {
    std::vector<AuthorizationStableObjectIdentity> objects;
    std::vector<AuthorizationStableFieldIdentity> fields;
    std::vector<AuthorizationAcceptedFieldBinding> acceptedBindings;
    std::vector<AuthorizationRejectedFieldBinding> rejectedBindings;
    std::vector<AuthorizationRejectedFieldAccess> rejectedAccesses;
    AuthorizationFieldAliasCompleteness completeness;
};

AuthorizationFieldAliasReport CorrelateAuthorizationFieldAliases(
    const AuthorizationFieldAliasInput& input);

} // namespace ds
