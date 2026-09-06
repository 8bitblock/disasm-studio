#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace ds {

enum class UnpackStrategy : uint8_t {
    Hybrid,
    StackReturn,
    WriteExecute,
    EntropySettle,
    RunFree,
    Manual
};

enum class UnpackState : uint8_t {
    Idle,
    Observing,
    CandidateReady,
    Completed,
    Failed,
    Cancelled
};

enum class UnpackConfidence : uint8_t { None, Low, Medium, High };

enum class OepEvidenceKind : uint8_t {
    InOriginalImage,
    ExecutableRegion,
    StackReturned,
    StackNearBaseline,
    WriteThenExecute,
    ProtectionBecameExecutable,
    EntropySettled,
    RunFreeStop,
    ManualSelection,
    ControlTransfer,
    RepeatedObservation
};

// Half-open address range. Overflowing ranges are rejected rather than wrapped.
struct UnpackRange {
    uint64_t base = 0;
    uint64_t size = 0;

    bool valid() const;
    bool contains(uint64_t address) const;
    bool end(uint64_t& exclusiveEnd) const;
};

// One debugger/sampler observation. changedBytes/changedPages describe work
// since the preceding sample, not cumulative process totals.
struct UnpackObservation {
    uint64_t timestampMs = 0;
    uint64_t rip = 0;
    uint64_t rsp = 0;
    double imageEntropy = 0.0; // Shannon entropy, [0, 8]
    uint64_t changedBytes = 0;
    uint32_t changedPages = 0;

    UnpackRange executionRegion;
    bool regionExecutable = false;
    bool regionPrivate = false;
    bool regionImageBacked = false;
    bool pageWasWritten = false;
    bool protectionBecameExecutable = false;
    bool returnedToOriginalImage = false;
    bool stackNearBaseline = false;
    bool controlTransfer = false;
    bool hasTransitionSource = false; // exact source for VM edge/cycle analysis
    uint64_t transitionSource = 0;
    bool exceptionHandlerEntry = false;
    bool runFreeStop = false;
    bool manualCandidate = false;
};

struct OepEvidence {
    OepEvidenceKind kind = OepEvidenceKind::ExecutableRegion;
    int score = 0;
    uint32_t occurrences = 0;
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    std::string detail;
};

struct OepCandidate {
    uint64_t va = 0;
    int score = 0; // saturated to [0, 100]
    UnpackConfidence confidence = UnpackConfidence::None;
    uint32_t observations = 0;
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    std::vector<OepEvidence> evidence;
};

struct EntropySettleReport {
    bool settled = false;
    uint64_t windowStartMs = 0;
    uint64_t windowEndMs = 0;
    size_t sampleCount = 0;
    double minimum = 0.0;
    double maximum = 0.0;
    double spread = 0.0;
    uint64_t changedBytes = 0;
    uint64_t changedPages = 0;
};

struct VmHotRip {
    uint64_t rip = 0;
    uint64_t hits = 0;
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    bool executable = false;
    bool privateRegion = false;
    bool approximate = false;
};

struct VmHandler {
    uint64_t rip = 0;
    uint64_t hits = 0;
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    uint32_t fanIn = 0;
    bool exceptionObserved = false;
    bool privateRegion = false;
    bool approximate = false;
};

struct VmLoopEdge {
    uint64_t from = 0;
    uint64_t to = 0;
    uint64_t hits = 0;
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    bool backward = false;
    bool approximate = false;
};

struct VmTraceReport {
    bool vmLike = false;
    int score = 0; // heuristic, [0, 100]
    uint64_t observedTransitions = 0;
    std::vector<VmHotRip> hotRips;
    std::vector<VmHandler> handlers;
    std::vector<VmLoopEdge> loops;
    std::vector<std::string> evidence;
};

struct UnpackConfig {
    size_t maxSamples = 4096;
    size_t maxCandidates = 128;
    size_t maxTrackedRips = 1024;
    size_t maxTrackedHandlers = 128;
    size_t maxTrackedEdges = 2048;
    size_t maxReportedHotRips = 32;
    size_t maxReportedHandlers = 16;
    size_t maxReportedLoops = 32;

    uint64_t settleWindowMs = 1500;
    size_t minSettleSamples = 4;
    double maxEntropySpread = 0.08;
    uint64_t maxChangedBytesInSettleWindow = 4096;
    uint64_t maxChangedPagesInSettleWindow = 2;
    bool requirePriorActivityForSettle = true;
    uint64_t stackTolerance = 0x1000;
    uint64_t hotRipMinimumHits = 4;
    uint64_t loopMinimumHits = 3;
};

struct UnpackStatus {
    UnpackState state = UnpackState::Idle;
    UnpackStrategy strategy = UnpackStrategy::Hybrid;
    std::string message;
    uint64_t totalSamples = 0;
    size_t retainedSamples = 0;
    uint64_t droppedSamples = 0;
    uint64_t rejectedSamples = 0;
    size_t candidateCount = 0;
    bool entropySettled = false;
    bool hasBestOep = false;
    uint64_t bestOep = 0;
    UnpackConfidence bestConfidence = UnpackConfidence::None;
};

struct UnpackReport {
    UnpackStatus status;
    std::vector<UnpackObservation> samples; // oldest to newest
    std::vector<OepCandidate> candidates;   // best score first
    EntropySettleReport entropy;
    VmTraceReport vmTrace;
};

// Pure telemetry/scoring state machine. Process control, memory reads, dumping,
// and debugger policy remain with its caller.
class UnpackEngine {
public:
    explicit UnpackEngine(UnpackConfig config = {});

    void begin(UnpackStrategy strategy, UnpackRange imageRange,
               uint64_t initialRsp = 0);
    void reset();

    // Returns false for invalid entropy/ranges or non-monotonic timestamps.
    bool observe(const UnpackObservation& observation);
    bool selectManualOep(uint64_t va, uint64_t timestampMs,
                         const std::string& detail = {});

    // Explicit escape hatch for an OEP in a separately validated mapped image
    // (for example, a private allocation containing a recovered PE). The caller
    // must supply that image's bounded allocation range. This approves only the
    // exact selected address; it does not make every address in the range an OEP.
    bool selectValidatedExternalOep(uint64_t va, UnpackRange validatedImageRange,
                                    uint64_t timestampMs,
                                    const std::string& detail = {});

    void complete(uint64_t selectedOep = 0, bool hasSelectedOep = false);
    void fail(const std::string& reason);
    void cancel();

    UnpackState state() const;
    UnpackStrategy strategy() const;
    UnpackReport report() const;

private:
    struct RipCounter {
        uint64_t rip = 0, hits = 0, error = 0;
        uint64_t firstSeenMs = 0, lastSeenMs = 0;
        bool executable = false, privateRegion = false;
    };
    struct HandlerCounter {
        uint64_t rip = 0, hits = 0, error = 0;
        uint64_t firstSeenMs = 0, lastSeenMs = 0;
        bool privateRegion = false;
    };
    struct EdgeCounter {
        uint64_t from = 0, to = 0, hits = 0, error = 0;
        uint64_t firstSeenMs = 0, lastSeenMs = 0;
    };

    void considerObservation(const UnpackObservation& observation,
                             bool entropyJustSettled);
    bool addEvidence(uint64_t va, uint64_t timestampMs,
                     OepEvidenceKind kind, int score,
                     const std::string& detail, bool beginsObservation = false);
    void updateEntropy();
    void updateTrace(const UnpackObservation& observation);
    void refreshState();
    void resetUnlocked();

    mutable std::mutex mutex_;
    UnpackConfig config_;
    UnpackState state_ = UnpackState::Idle;
    UnpackStrategy strategy_ = UnpackStrategy::Hybrid;
    UnpackRange imageRange_;
    uint64_t initialRsp_ = 0;
    bool hasInitialRsp_ = false;
    std::string message_;

    std::deque<UnpackObservation> samples_;
    std::vector<OepCandidate> candidates_;
    EntropySettleReport entropy_;
    std::vector<RipCounter> rips_;
    std::vector<HandlerCounter> handlers_;
    std::vector<EdgeCounter> edges_;
    uint64_t totalSamples_ = 0;
    uint64_t droppedSamples_ = 0;
    uint64_t rejectedSamples_ = 0;
    uint64_t transitions_ = 0;
    bool activityObserved_ = false;
    bool writeActivityObserved_ = false;
    UnpackRange approvedExternalRange_;
    uint64_t approvedExternalOep_ = 0;
    bool hasApprovedExternalOep_ = false;
    uint64_t selectedOep_ = 0;
    bool hasSelectedOep_ = false;
    UnpackConfidence selectedConfidence_ = UnpackConfidence::None;
};

const char* UnpackStrategyName(UnpackStrategy strategy);
const char* UnpackStateName(UnpackState state);
const char* UnpackConfidenceName(UnpackConfidence confidence);
const char* OepEvidenceName(OepEvidenceKind kind);

} // namespace ds
