#pragma once

#include "AttachImagePolicy.h"
#include "CodeByteSignature.h"
#include "DebugTargetIdentity.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ds {

inline constexpr size_t kAuthorizationWatchSiteCap = 512;
inline constexpr size_t kAuthorizationWatchInputScanCap =
    kAuthorizationWatchSiteCap * 16;
inline constexpr size_t kAuthorizationWatchEventCap = 4096;
inline constexpr size_t kAuthorizationWatchPendingReturnCap = 4096;
inline constexpr size_t kAuthorizationWatchPerThreadReturnDepth = 64;
inline constexpr size_t kAuthorizationWatchSourceByteCap =
    256u * 1024u * 1024u;
inline constexpr char kAuthorizationWatchSourceRejectionMessage[] =
    "Authorization Watch rejected: the CREATE_PROCESS backing file was absent, "
    "unreadable, or did not exactly match the analyzed file identity and bytes.";

// Immutable evidence retained only across Launch & Watch's check -> CreateProcess
// interval.  The CREATE_PROCESS_DEBUG_EVENT file handle must name this exact
// backing file and expose these exact bytes before the watch may bind or mutate
// target code.  Ordinary attached-process plans leave this empty.
struct AuthorizationWatchSourceEvidence {
    AttachedFileIdentity fileIdentity;
    std::shared_ptr<const std::vector<uint8_t>> bytes;
};

inline bool CompleteAuthorizationWatchSourceEvidence(
    const AuthorizationWatchSourceEvidence& evidence) noexcept {
    return evidence.fileIdentity.valid && evidence.bytes &&
           !evidence.bytes->empty() &&
           evidence.bytes->size() <= kAuthorizationWatchSourceByteCap &&
           evidence.fileIdentity.fileSize == evidence.bytes->size();
}

using AuthorizationWatchSourceReader =
    std::function<bool(uint64_t offset, uint8_t* out, size_t size)>;

// Exact, bounded content comparison used by the Win32 CREATE_PROCESS path and
// pure tests.  Identity equality is checked before any chunk is requested.
bool AuthorizationWatchSourceEvidenceMatches(
    const AuthorizationWatchSourceEvidence& expected,
    const AttachedFileIdentity& actual,
    const AuthorizationWatchSourceReader& read);

// These labels deliberately remain independent from the static authorization
// analyzer's enums. A saved analysis report can therefore evolve without making
// the debugger's session-only event wire format ABI-dependent on that pass.
enum class AuthorizationWatchStage : uint8_t {
    ReplyCheck,
    CandidatePath,
    StateRead,
    StateWrite,
    StartupGate,
    Outcome,
    // A local credential/input chain may contribute separate input-read,
    // comparison, and branch sites.  They intentionally share one session
    // stage: the static report remains the authority for the finer-grained
    // labels, while the live watch only claims that a local check site ran.
    LocalCheck,
};

enum class AuthorizationWatchOutcome : uint8_t {
    None,
    Candidate,
    Allow,
    Deny,
    Unknown,
};

// Exact scalar return contracts used by Debugger's per-thread return-address
// probes. Reaching a state-call entry records only an attempt. A completion is
// marked known-success/known-failure only after the matching return executes and
// its EAX/RAX value is evaluated by one of these rules. No argument, credential,
// DPAPI plaintext, file/registry value, or other target buffer is retained.
enum class AuthorizationWatchReturnRule : uint8_t {
    None,
    BooleanNonzero,
    ZeroIsSuccess,
    NonnegativeIsSuccess,
    NonNullHandle,
    NotInvalidHandle,
    NotInvalidValue32,
};

struct AuthorizationWatchStateApiContract {
    std::string dll;
    std::string symbol;
    std::string operation;
    AuthorizationWatchReturnRule returnRule = AuthorizationWatchReturnRule::None;

    bool valid() const noexcept {
        return !dll.empty() && !symbol.empty() && !operation.empty();
    }
};

struct AuthorizationWatchSite {
    uint64_t moduleRva = 0; // zero is valid; retargeted against the main image
    uint64_t flowId = 0;
    AuthorizationWatchStage stage = AuthorizationWatchStage::CandidatePath;
    AuthorizationWatchOutcome outcome = AuthorizationWatchOutcome::None;
    std::string label;
    bool strongOutcome = false;
    std::optional<AuthorizationWatchStateApiContract> stateApi;
    // Full decoded instruction bytes captured from the exact static image.
    // Any instruction overlapped by a loader relocation is excluded.
    CodeByteSignature signature;
};

struct AuthorizationWatchPlan {
    // Stable static-document identity (normally its content hash). It is retained
    // in snapshots/events for provenance; DebugTargetIdentity performs the live
    // PID/generation binding.
    std::string documentIdentity;
    // UI-owner identity.  Content hashes alone do not distinguish two open
    // document contexts or a replacement image installed into the same one.
    uint64_t documentId = 0;
    uint64_t documentImageGeneration = 0;
    std::string imagePath;
    uint64_t imageSize = 0; // optional mapped SizeOfImage guard
    // Attached starts are allowed to mutate the target only when the plan was
    // stamped from AppContext's exact FILE/LIVE session binding.  Pre-launch
    // plans leave this false; the freshly created main mapping is retained as
    // the bound module before any site is planted.
    bool requireExactModuleIdentity = false;
    AttachedModuleIdentity expectedModule;
    AuthorizationWatchSourceEvidence launchSource;
    // Sites whose complete instruction could not be captured from the exact
    // analysis image are excluded before the 512-site cap and reported here.
    size_t signatureUnavailableSites = 0;
    std::vector<AuthorizationWatchSite> sites;
};

// Stronger than the general module matcher: Authorization Watch is about to
// plant int3 bytes at document-derived RVAs, so every requested property must
// be present and equal.  Missing path/extent/incarnation evidence fails closed.
inline bool CompleteAuthorizationWatchModuleIdentity(
    const AttachedModuleIdentity& image) {
    return image.base != 0 && image.size != 0 && !image.path.empty() &&
           image.loadGeneration != 0;
}

inline bool ExactAuthorizationWatchModuleMatch(
    const AttachedModuleIdentity& expected,
    const AttachedModuleIdentity& actual) {
    return CompleteAuthorizationWatchModuleIdentity(expected) &&
           CompleteAuthorizationWatchModuleIdentity(actual) &&
           expected.size == actual.size &&
           expected.loadGeneration == actual.loadGeneration &&
           AttachedModuleIdentityMatches(expected, actual);
}

// Pure half-open range guard shared by the debugger's live-memory validation
// and unit tests.  A signature must fit wholly inside the exact main-image
// extent; validating only its first byte would allow a decoded instruction to
// straddle into another mapping.
inline bool AuthorizationWatchRangeWithinImage(uint64_t moduleRva,
                                               size_t length,
                                               uint64_t imageSize) noexcept {
    return length != 0 && imageSize != 0 && moduleRva < imageSize &&
           static_cast<uint64_t>(length) <= imageSize - moduleRva;
}

struct AuthorizationWatchOptions {
    bool pauseOnHit = false; // logging and continuing is the safe default
};

struct AuthorizationWatchEvent {
    uint64_t sequence = 0;
    uint64_t generation = 0;
    DebugTargetIdentity target{};
    uint64_t timestampTicks = 0;
    uint32_t tid = 0;
    uint64_t runtimeVa = 0;
    uint64_t moduleRva = 0;
    uint64_t flowId = 0;
    uint64_t attemptId = 0;
    AuthorizationWatchStage stage = AuthorizationWatchStage::CandidatePath;
    AuthorizationWatchOutcome outcome = AuthorizationWatchOutcome::None;
    std::string label;
    bool strongOutcome = false;

    bool stateOperationAttempted = false;
    bool stateOperationReturn = false;
    bool stateOperationSuccessKnown = false;
    bool stateOperationSucceeded = false;
    // The only raw live value retained is the scalar API status/handle returned
    // in EAX/RAX. Target arguments and pointed-to content are never captured.
    bool rawResultValid = false;
    uint64_t rawResult = 0;
    uint8_t pointerWidthBits = 0;
    std::optional<AuthorizationWatchStateApiContract> stateApi;
};

struct AuthorizationWatchReturnRequest {
    uint64_t generation = 0;
    uint64_t attemptId = 0;
    uint64_t entryRuntimeVa = 0;
    uint64_t entryModuleRva = 0;
    uint64_t flowId = 0;
    AuthorizationWatchStage stage = AuthorizationWatchStage::CandidatePath;
    AuthorizationWatchOutcome outcome = AuthorizationWatchOutcome::None;
    std::string label;
    bool strongOutcome = false;
    AuthorizationWatchStateApiContract stateApi;
};

struct AuthorizationWatchHitResult {
    bool pauseRequested = false;
    std::vector<AuthorizationWatchReturnRequest> returnRequests;
};

struct AuthorizationWatchCoverage {
    size_t requestedSites = 0; // semantic rows supplied by the analyzer
    size_t inputSitesScanned = 0; // bounded prefix inspected during prepare
    size_t inputSitesTruncated = 0; // requested rows beyond that prefix
    size_t retainedSites = 0;  // semantic rows retained under the metadata cap
    size_t plannedSites = 0;   // unique runtime addresses
    size_t armedSites = 0;
    size_t skippedSites = 0;
    size_t signatureUnavailableSites = 0;
    size_t signatureMismatchSites = 0;
    // Sites whose initially validated instruction changed while the watch was
    // running. This is kept separate from plant-time mismatches so a live
    // self-modifying/stale-code retirement is explicit in coverage.
    uint64_t hitSignatureMismatches = 0;
    size_t sitesSharedWithUserBreakpoints = 0;
    size_t hitSites = 0;
    uint64_t hitTotal = 0;
    uint64_t droppedEvents = 0;
    size_t pendingReturns = 0;
    size_t returnSitesArmed = 0;
    size_t returnSitesSharedWithUserBreakpoints = 0;
    uint64_t pendingReturnsDropped = 0;
};

struct AuthorizationWatchSnapshot {
    bool active = false;
    bool targetBound = false;
    uint64_t generation = 0;
    uint64_t revision = 0;
    DebugTargetIdentity target{};
    uint64_t mainImageBase = 0;
    uint64_t imageSize = 0;
    std::string documentIdentity;
    uint64_t documentId = 0;
    uint64_t documentImageGeneration = 0;
    std::string imagePath;
    AttachedModuleIdentity boundModule;
    bool sourceValidationRequired = false;
    bool sourceValidationComplete = false;
    bool sourceValidationFailed = false;
    std::string sourceValidationError;
    AuthorizationWatchOptions options{};
    AuthorizationWatchCoverage coverage{};
    std::vector<AuthorizationWatchEvent> events;
};

struct AuthorizationWatchRuntimeSite {
    uint64_t runtimeVa = 0;
    uint64_t moduleRva = 0;
    CodeByteSignature signature;
};

enum class AuthorizationWatchSkipReason : uint8_t {
    Other,
    SignatureUnavailable,
    SignatureMismatch,
};

// Win32-independent state/cap layer. Debugger owns target memory mutation and
// calls these generation-checked hooks only from its debug-event thread.
class AuthorizationWatch {
public:
    uint64_t prepare(const AuthorizationWatchPlan& plan,
                     const AuthorizationWatchOptions& options = {});
    bool bindTarget(uint64_t generation, DebugTargetIdentity target,
                    const AttachedModuleIdentity& mainImage);
    std::optional<AuthorizationWatchSourceEvidence> pendingSourceEvidence(
        uint64_t generation) const;
    bool acceptSourceEvidence(uint64_t generation);
    bool rejectSourceEvidence(uint64_t generation);
    void stop();
    void clearEvents();
    void reset();

    bool active() const;
    uint64_t generation() const;
    std::vector<AuthorizationWatchRuntimeSite> pendingSites(uint64_t generation) const;

    void markArmed(uint64_t generation, uint64_t runtimeVa,
                   bool sharedWithUserBreakpoint = false);
    void markSkipped(uint64_t generation, uint64_t runtimeVa,
                     AuthorizationWatchSkipReason reason =
                         AuthorizationWatchSkipReason::Other);
    void markHitSignatureMismatch(uint64_t generation, uint64_t runtimeVa);
    void markDisarmed(uint64_t generation, uint64_t runtimeVa);

    // Emits one event for every semantic label sharing the physical site. The
    // richer entry form also returns exact state-call completion requests for
    // Debugger to bind to the calling thread's return address.
    AuthorizationWatchHitResult recordEntryHit(
        uint64_t generation, uint64_t runtimeVa, uint32_t tid,
        uint64_t timestampTicks);
    // Compatibility helper for pure callers/tests. Production Debugger code
    // uses recordEntryHit followed by recordStateReturn at the correlated return.
    bool recordHit(uint64_t generation, uint64_t runtimeVa, uint32_t tid,
                   uint64_t timestampTicks, bool successKnown = false,
                   bool succeeded = false);
    bool recordStateReturn(const AuthorizationWatchReturnRequest& request,
                           uint64_t returnRuntimeVa, uint32_t tid,
                           uint64_t timestampTicks, uint64_t rawResult,
                           uint8_t pointerWidthBits);

    AuthorizationWatchSnapshot snapshot() const;

private:
    enum class SiteState : uint8_t { Pending, Armed, Skipped };
    struct RuntimeRecord {
        uint64_t moduleRva = 0;
        SiteState state = SiteState::Pending;
        bool sharedWithUserBreakpoint = false;
        AuthorizationWatchSkipReason skipReason =
            AuthorizationWatchSkipReason::Other;
        uint64_t hits = 0;
        CodeByteSignature signature;
        std::vector<AuthorizationWatchSite> semantics;
    };

    mutable std::mutex mtx_;
    bool active_ = false;
    uint64_t generation_ = 0;
    uint64_t revision_ = 0;
    uint64_t sequence_ = 0;
    uint64_t attemptSequence_ = 0;
    size_t requestedSites_ = 0;
    size_t inputSitesScanned_ = 0;
    size_t inputSitesTruncated_ = 0;
    size_t retainedSites_ = 0;
    size_t unmappedSkippedSites_ = 0;
    size_t preparedSignatureUnavailableSites_ = 0;
    uint64_t hitSignatureMismatches_ = 0;
    uint64_t droppedEvents_ = 0;
    DebugTargetIdentity target_{};
    uint64_t mainImageBase_ = 0;
    uint64_t imageSize_ = 0;
    std::string documentIdentity_;
    uint64_t documentId_ = 0;
    uint64_t documentImageGeneration_ = 0;
    std::string imagePath_;
    bool requireExactModuleIdentity_ = false;
    AttachedModuleIdentity expectedModule_;
    AttachedModuleIdentity boundModule_;
    bool sourceEvidenceRequired_ = false;
    bool sourceEvidenceValidated_ = false;
    bool sourceEvidenceFailed_ = false;
    std::string sourceEvidenceError_;
    AuthorizationWatchSourceEvidence sourceEvidence_;
    AuthorizationWatchOptions options_{};
    std::vector<AuthorizationWatchSite> preparedSites_;
    std::map<uint64_t, RuntimeRecord> runtimeSites_; // runtime VA -> record
    std::deque<AuthorizationWatchEvent> events_;
};

struct AuthorizationWatchPendingReturn {
    uint64_t returnAddress = 0;
    uint64_t entryAddress = 0;
    std::vector<AuthorizationWatchReturnRequest> requests;
};

// Pure LIFO/thread/refcount bookkeeping for nested and multi-threaded calls.
// Physical return-site ownership remains entirely in Debugger.
class AuthorizationWatchReturnTracker {
public:
    bool push(uint32_t tid, uint64_t returnAddress,
              AuthorizationWatchPendingReturn pending);
    bool pop(uint32_t tid, uint64_t returnAddress,
             AuthorizationWatchPendingReturn& pending);
    size_t references(uint64_t returnAddress) const;
    std::vector<uint64_t> eraseThread(uint32_t tid, size_t* erased = nullptr);
    size_t total() const noexcept { return total_; }
    void clear();

private:
    std::map<uint32_t, std::vector<AuthorizationWatchPendingReturn>> perThread_;
    std::map<uint64_t, size_t> references_;
    size_t total_ = 0;
};

} // namespace ds
