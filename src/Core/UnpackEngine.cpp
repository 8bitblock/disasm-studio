#include "UnpackEngine.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <unordered_map>

namespace ds {

namespace {

constexpr size_t kHardMaxSamples = 65536;
constexpr size_t kHardMaxCandidates = 1024;
constexpr size_t kHardMaxCounters = 65536;

template <typename T>
T clampCount(T value, T low, T high) {
    return std::max(low, std::min(value, high));
}

uint64_t satAdd(uint64_t a, uint64_t b) {
    const uint64_t max = std::numeric_limits<uint64_t>::max();
    return max - a < b ? max : a + b;
}

uint32_t satInc(uint32_t value) {
    return value == std::numeric_limits<uint32_t>::max() ? value : value + 1;
}

uint64_t absDistance(uint64_t a, uint64_t b) {
    return a >= b ? a - b : b - a;
}

UnpackConfidence confidenceFor(int score) {
    if (score >= 75) return UnpackConfidence::High;
    if (score >= 50) return UnpackConfidence::Medium;
    if (score >= 25) return UnpackConfidence::Low;
    return UnpackConfidence::None;
}

bool terminal(UnpackState state) {
    return state == UnpackState::Completed || state == UnpackState::Failed ||
           state == UnpackState::Cancelled;
}

std::string boundedText(const std::string& text, size_t cap = 512) {
    return text.size() <= cap ? text : text.substr(0, cap);
}

} // namespace

bool UnpackRange::valid() const {
    return size != 0 && size <= std::numeric_limits<uint64_t>::max() - base;
}

bool UnpackRange::contains(uint64_t address) const {
    return valid() && address >= base && address - base < size;
}

bool UnpackRange::end(uint64_t& exclusiveEnd) const {
    if (!valid()) return false;
    exclusiveEnd = base + size;
    return true;
}

UnpackEngine::UnpackEngine(UnpackConfig config) : config_(config) {
    config_.maxSamples = clampCount(config_.maxSamples, size_t{1}, kHardMaxSamples);
    config_.maxCandidates = clampCount(config_.maxCandidates, size_t{1}, kHardMaxCandidates);
    config_.maxTrackedRips = clampCount(config_.maxTrackedRips, size_t{1}, kHardMaxCounters);
    config_.maxTrackedHandlers = clampCount(config_.maxTrackedHandlers, size_t{1}, kHardMaxCounters);
    config_.maxTrackedEdges = clampCount(config_.maxTrackedEdges, size_t{1}, kHardMaxCounters);
    config_.maxReportedHotRips = std::min(config_.maxReportedHotRips, config_.maxTrackedRips);
    config_.maxReportedHandlers = std::min(config_.maxReportedHandlers, config_.maxTrackedHandlers);
    config_.maxReportedLoops = std::min(config_.maxReportedLoops, config_.maxTrackedEdges);
    config_.minSettleSamples = clampCount(config_.minSettleSamples, size_t{2}, config_.maxSamples);
    if (!std::isfinite(config_.maxEntropySpread)) config_.maxEntropySpread = 0.08;
    config_.maxEntropySpread = std::clamp(config_.maxEntropySpread, 0.0, 8.0);
    if (config_.hotRipMinimumHits == 0) config_.hotRipMinimumHits = 1;
    if (config_.loopMinimumHits == 0) config_.loopMinimumHits = 1;
}

void UnpackEngine::begin(UnpackStrategy strategy, UnpackRange imageRange,
                         uint64_t initialRsp) {
    std::lock_guard<std::mutex> lock(mutex_);
    resetUnlocked();
    strategy_ = strategy;
    imageRange_ = imageRange;
    initialRsp_ = initialRsp;
    hasInitialRsp_ = initialRsp != 0; // callers can still provide explicit stack evidence for RSP 0
    if (!imageRange_.valid()) {
        state_ = UnpackState::Failed;
        message_ = "Image range is empty or overflows the address space";
        return;
    }
    state_ = UnpackState::Observing;
    message_ = "Collecting unpack telemetry";
}

void UnpackEngine::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    resetUnlocked();
}

void UnpackEngine::resetUnlocked() {
    state_ = UnpackState::Idle;
    strategy_ = UnpackStrategy::Hybrid;
    imageRange_ = {};
    initialRsp_ = 0;
    hasInitialRsp_ = false;
    message_.clear();
    samples_.clear();
    candidates_.clear();
    entropy_ = {};
    rips_.clear();
    handlers_.clear();
    edges_.clear();
    totalSamples_ = 0;
    droppedSamples_ = 0;
    rejectedSamples_ = 0;
    transitions_ = 0;
    activityObserved_ = false;
    writeActivityObserved_ = false;
    approvedExternalRange_ = {};
    approvedExternalOep_ = 0;
    hasApprovedExternalOep_ = false;
    selectedOep_ = 0;
    hasSelectedOep_ = false;
    selectedConfidence_ = UnpackConfidence::None;
}

bool UnpackEngine::observe(const UnpackObservation& input) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UnpackState::Idle || terminal(state_)) {
        rejectedSamples_ = satAdd(rejectedSamples_, 1);
        return false;
    }
    if (!std::isfinite(input.imageEntropy) || input.imageEntropy < 0.0 ||
        input.imageEntropy > 8.0 ||
        (input.executionRegion.size != 0 && !input.executionRegion.valid()) ||
        (!samples_.empty() && input.timestampMs < samples_.back().timestampMs)) {
        rejectedSamples_ = satAdd(rejectedSamples_, 1);
        return false;
    }

    UnpackObservation observation = input;
    if (observation.executionRegion.valid() &&
        !observation.executionRegion.contains(observation.rip)) {
        rejectedSamples_ = satAdd(rejectedSamples_, 1);
        return false;
    }
    if (hasInitialRsp_ && !observation.stackNearBaseline &&
        absDistance(observation.rsp, initialRsp_) <= config_.stackTolerance)
        observation.stackNearBaseline = true;

    activityObserved_ = activityObserved_ || observation.changedBytes != 0 ||
                        observation.changedPages != 0 || observation.pageWasWritten ||
                        (!samples_.empty() &&
                         std::abs(samples_.back().imageEntropy - observation.imageEntropy) >
                             config_.maxEntropySpread);
    writeActivityObserved_ = writeActivityObserved_ || observation.changedBytes != 0 ||
                             observation.changedPages != 0 || observation.pageWasWritten;

    const bool wasSettled = entropy_.settled;
    samples_.push_back(observation);
    totalSamples_ = satAdd(totalSamples_, 1);
    if (samples_.size() > config_.maxSamples) {
        samples_.pop_front();
        droppedSamples_ = satAdd(droppedSamples_, 1);
    }

    updateEntropy();
    updateTrace(observation);
    considerObservation(observation, entropy_.settled && !wasSettled);
    refreshState();
    return true;
}

bool UnpackEngine::selectManualOep(uint64_t va, uint64_t timestampMs,
                                   const std::string& detail) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UnpackState::Idle || terminal(state_) ||
        !imageRange_.contains(va) ||
        (!samples_.empty() && timestampMs < samples_.back().timestampMs))
        return false;
    const bool added = addEvidence(va, timestampMs, OepEvidenceKind::ManualSelection, 100,
        detail.empty() ? "Selected explicitly by the analyst" : detail, true);
    refreshState();
    return added;
}

bool UnpackEngine::selectValidatedExternalOep(
        uint64_t va, UnpackRange validatedImageRange, uint64_t timestampMs,
        const std::string& detail) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UnpackState::Idle || terminal(state_) ||
        imageRange_.contains(va) || !validatedImageRange.valid() ||
        !validatedImageRange.contains(va) ||
        (!samples_.empty() && timestampMs < samples_.back().timestampMs))
        return false;

    const bool added = addEvidence(
        va, timestampMs, OepEvidenceKind::ManualSelection, 100,
        detail.empty() ?
            "Selected explicitly in a caller-validated external image" : detail,
        true);
    if (!added) return false;

    approvedExternalRange_ = validatedImageRange;
    approvedExternalOep_ = va;
    hasApprovedExternalOep_ = true;
    refreshState();
    return true;
}

void UnpackEngine::complete(uint64_t selectedOep, bool hasSelectedOep) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UnpackState::Idle || terminal(state_)) return;
    const auto selectable = [&](uint64_t va) {
        return imageRange_.contains(va) ||
            (hasApprovedExternalOep_ && va == approvedExternalOep_ &&
             approvedExternalRange_.contains(va));
    };
    if (hasSelectedOep && selectable(selectedOep)) {
        const uint64_t when = samples_.empty() ? 0 : samples_.back().timestampMs;
        addEvidence(selectedOep, when, OepEvidenceKind::ManualSelection, 100,
                    "Chosen as the final OEP", true);
        selectedOep_ = selectedOep;
        hasSelectedOep_ = true;
        selectedConfidence_ = UnpackConfidence::High;
    } else {
        auto best = candidates_.end();
        for (auto candidate = candidates_.begin(); candidate != candidates_.end();
             ++candidate) {
            if (!selectable(candidate->va)) continue;
            if (best == candidates_.end() || candidate->score > best->score ||
                (candidate->score == best->score &&
                 candidate->lastSeenMs > best->lastSeenMs))
                best = candidate;
        }
        if (best != candidates_.end()) {
            selectedOep_ = best->va;
            hasSelectedOep_ = true;
            selectedConfidence_ = best->confidence;
        }
    }
    state_ = UnpackState::Completed;
    message_ = hasSelectedOep_ ? "Unpack observation completed with an OEP" :
                                "Unpack observation completed without an OEP";
}

void UnpackEngine::fail(const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UnpackState::Idle || terminal(state_)) return;
    state_ = UnpackState::Failed;
    message_ = reason.empty() ? "Unpack observation failed" : boundedText(reason);
}

void UnpackEngine::cancel() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UnpackState::Idle || terminal(state_)) return;
    state_ = UnpackState::Cancelled;
    message_ = "Unpack observation cancelled";
}

void UnpackEngine::updateEntropy() {
    EntropySettleReport next;
    if (samples_.empty()) {
        entropy_ = next;
        return;
    }

    const uint64_t newest = samples_.back().timestampMs;
    const uint64_t threshold = newest >= config_.settleWindowMs ?
                               newest - config_.settleWindowMs : 0;
    size_t first = samples_.size() - 1;
    while (first > 0 && samples_[first - 1].timestampMs >= threshold) --first;
    if (first > 0 && samples_[first].timestampMs > threshold)
        --first; // retain the sample bracketing the time boundary

    next.windowStartMs = samples_[first].timestampMs;
    next.windowEndMs = newest;
    next.sampleCount = samples_.size() - first;
    next.minimum = samples_[first].imageEntropy;
    next.maximum = samples_[first].imageEntropy;
    for (size_t i = first; i < samples_.size(); ++i) {
        const auto& sample = samples_[i];
        next.minimum = std::min(next.minimum, sample.imageEntropy);
        next.maximum = std::max(next.maximum, sample.imageEntropy);
        next.changedBytes = satAdd(next.changedBytes, sample.changedBytes);
        next.changedPages = satAdd(next.changedPages, sample.changedPages);
    }
    next.spread = next.maximum - next.minimum;
    const uint64_t duration = next.windowEndMs - next.windowStartMs;
    const bool boundaryCovered = first + 1 >= samples_.size() ||
        samples_[first + 1].timestampMs - samples_[first].timestampMs <=
            config_.settleWindowMs;
    next.settled = next.sampleCount >= config_.minSettleSamples &&
                   duration >= config_.settleWindowMs &&
                   boundaryCovered &&
                   next.spread <= config_.maxEntropySpread &&
                   next.changedBytes <= config_.maxChangedBytesInSettleWindow &&
                   next.changedPages <= config_.maxChangedPagesInSettleWindow &&
                   (!config_.requirePriorActivityForSettle || activityObserved_);
    entropy_ = next;
}

void UnpackEngine::considerObservation(const UnpackObservation& observation,
                                       bool entropyJustSettled) {
    const bool inImage = imageRange_.contains(observation.rip);
    const bool executable = observation.regionExecutable;
    const bool writeExecute = executable &&
        (observation.pageWasWritten || observation.protectionBecameExecutable);
    const bool stackReturn = observation.returnedToOriginalImage && inImage &&
                             observation.stackNearBaseline;
    const bool manual = observation.manualCandidate;
    const bool runFree = observation.runFreeStop;

    const bool adaptiveTransfer = observation.controlTransfer && executable &&
                                  (inImage || observation.regionPrivate) &&
                                  writeActivityObserved_;

    bool trigger = manual;
    switch (strategy_) {
        case UnpackStrategy::Hybrid:
            trigger = trigger || stackReturn || writeExecute || entropyJustSettled ||
                      runFree || adaptiveTransfer;
            break;
        case UnpackStrategy::StackReturn: trigger = trigger || stackReturn; break;
        case UnpackStrategy::WriteExecute: trigger = trigger || writeExecute; break;
        case UnpackStrategy::EntropySettle: trigger = trigger || entropyJustSettled; break;
        case UnpackStrategy::RunFree: trigger = trigger || runFree; break;
        case UnpackStrategy::Manual: break;
    }
    if (!trigger) return;

    const bool primaryWasEntropy = !manual && !writeExecute && !stackReturn &&
                                   !runFree && entropyJustSettled;
    const bool primaryWasControl = !manual && !writeExecute && !stackReturn &&
                                   !runFree && !entropyJustSettled;

    // Add the strongest trigger first so bounded candidate replacement is fair.
    if (manual)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::ManualSelection, 100,
                    "Marked manually during observation", true);
    else if (writeExecute) {
        const bool written = observation.pageWasWritten;
        addEvidence(observation.rip, observation.timestampMs,
                    written ? OepEvidenceKind::WriteThenExecute
                            : OepEvidenceKind::ProtectionBecameExecutable,
                    written ? (strategy_ == UnpackStrategy::WriteExecute ? 65 : 50)
                            : (strategy_ == UnpackStrategy::WriteExecute ? 50 : 38),
                    written ? "Execution reached a page observed being written"
                            : "Execution reached a page whose protection became executable",
                    true);
    }
    else if (stackReturn)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::StackReturned,
                    strategy_ == UnpackStrategy::StackReturn ? 60 : 45,
                    "Control returned to the original image near the initial stack", true);
    else if (runFree)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::RunFreeStop,
                    strategy_ == UnpackStrategy::RunFree ? 60 : 45,
                    "Run-free policy stopped at this address", true);
    else if (entropyJustSettled)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::EntropySettled,
                    strategy_ == UnpackStrategy::EntropySettle ? 55 : 40,
                    "Image entropy and writes settled inside the configured window", true);
    else
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::ControlTransfer, 30,
                    "Control transferred after memory-changing unpack activity", true);

    if (inImage)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::InOriginalImage, 12,
                    "Address lies in the original image");
    if (executable)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::ExecutableRegion, 8,
                    observation.regionPrivate ? "Address lies in private executable memory" :
                    observation.regionImageBacked ? "Address lies in executable image memory" :
                                                    "Address lies in executable mapped memory");
    if (observation.stackNearBaseline)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::StackNearBaseline, 8,
                    "Stack pointer is near its observation baseline");
    if (observation.controlTransfer && !primaryWasControl)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::ControlTransfer, 6,
                    "Observed at a control-transfer destination");
    if (entropy_.settled && !primaryWasEntropy)
        addEvidence(observation.rip, observation.timestampMs,
                    OepEvidenceKind::EntropySettled, 12,
                    "Image entropy is currently stable");
}

bool UnpackEngine::addEvidence(uint64_t va, uint64_t timestampMs,
                               OepEvidenceKind kind, int score,
                               const std::string& detail, bool beginsObservation) {
    score = std::clamp(score, 0, 100);
    auto candidate = std::find_if(candidates_.begin(), candidates_.end(),
        [va](const OepCandidate& item) { return item.va == va; });
    if (candidate == candidates_.end()) {
        OepCandidate proposed;
        proposed.va = va;
        proposed.firstSeenMs = proposed.lastSeenMs = timestampMs;
        proposed.observations = 1;
        proposed.evidence.push_back({ kind, score, 1, timestampMs, timestampMs,
                                      boundedText(detail) });
        proposed.score = score;
        proposed.confidence = confidenceFor(proposed.score);
        if (candidates_.size() >= config_.maxCandidates) {
            auto worst = std::min_element(candidates_.begin(), candidates_.end(),
                [](const auto& a, const auto& b) {
                    if (a.score != b.score) return a.score < b.score;
                    return a.lastSeenMs < b.lastSeenMs;
                });
            const int admissionScore = kind == OepEvidenceKind::ManualSelection ? 100 :
                std::min(100, proposed.score + (beginsObservation ? 30 : 0));
            if (worst == candidates_.end() ||
                (kind != OepEvidenceKind::ManualSelection && worst->score >= admissionScore))
                return false;
            *worst = std::move(proposed);
        } else {
            candidates_.push_back(std::move(proposed));
        }
        return true;
    }

    if (beginsObservation)
        candidate->observations = satInc(candidate->observations);
    candidate->lastSeenMs = std::max(candidate->lastSeenMs, timestampMs);
    auto evidence = std::find_if(candidate->evidence.begin(), candidate->evidence.end(),
        [kind](const OepEvidence& item) { return item.kind == kind; });
    if (evidence == candidate->evidence.end()) {
        candidate->evidence.push_back({ kind, score, 1, timestampMs, timestampMs,
                                        boundedText(detail) });
    } else {
        evidence->score = std::max(evidence->score, score);
        evidence->occurrences = satInc(evidence->occurrences);
        evidence->lastSeenMs = std::max(evidence->lastSeenMs, timestampMs);
        if (evidence->detail.empty() && !detail.empty()) evidence->detail = boundedText(detail);
    }

    if (candidate->observations > 1) {
        const uint32_t repeats = candidate->observations - 1;
        const int repeatScore = static_cast<int>(std::min<uint32_t>(repeats, 5) * 2);
        auto repeated = std::find_if(candidate->evidence.begin(), candidate->evidence.end(),
            [](const OepEvidence& item) {
                return item.kind == OepEvidenceKind::RepeatedObservation;
            });
        if (repeated == candidate->evidence.end()) {
            candidate->evidence.push_back({ OepEvidenceKind::RepeatedObservation,
                repeatScore, repeats, timestampMs, timestampMs,
                "The same OEP address was reached repeatedly" });
        } else {
            repeated->score = repeatScore;
            repeated->occurrences = repeats;
            repeated->lastSeenMs = std::max(repeated->lastSeenMs, timestampMs);
        }
    }

    int total = 0;
    for (const auto& item : candidate->evidence)
        total = std::min(100, total + item.score);
    candidate->score = total;
    candidate->confidence = confidenceFor(total);
    return true;
}

void UnpackEngine::updateTrace(const UnpackObservation& observation) {
    auto rip = std::find_if(rips_.begin(), rips_.end(),
        [&](const RipCounter& item) { return item.rip == observation.rip; });
    if (rip != rips_.end()) {
        rip->hits = satAdd(rip->hits, 1);
        rip->lastSeenMs = observation.timestampMs;
        rip->executable = rip->executable || observation.regionExecutable;
        rip->privateRegion = rip->privateRegion || observation.regionPrivate;
    } else if (rips_.size() < config_.maxTrackedRips) {
        rips_.push_back({ observation.rip, 1, 0, observation.timestampMs,
                          observation.timestampMs, observation.regionExecutable,
                          observation.regionPrivate });
    } else {
        auto least = std::min_element(rips_.begin(), rips_.end(),
            [](const auto& a, const auto& b) { return a.hits < b.hits; });
        const uint64_t error = least->hits;
        *least = { observation.rip, satAdd(error, 1), error,
                   observation.timestampMs, observation.timestampMs,
                   observation.regionExecutable, observation.regionPrivate };
    }

    if (observation.exceptionHandlerEntry) {
        auto handler = std::find_if(handlers_.begin(), handlers_.end(),
            [&](const HandlerCounter& item) { return item.rip == observation.rip; });
        if (handler != handlers_.end()) {
            handler->hits = satAdd(handler->hits, 1);
            handler->lastSeenMs = observation.timestampMs;
            handler->privateRegion = handler->privateRegion || observation.regionPrivate;
        } else if (handlers_.size() < config_.maxTrackedHandlers) {
            handlers_.push_back({ observation.rip, 1, 0, observation.timestampMs,
                                  observation.timestampMs, observation.regionPrivate });
        } else {
            auto least = std::min_element(handlers_.begin(), handlers_.end(),
                [](const auto& a, const auto& b) { return a.hits < b.hits; });
            const uint64_t error = least->hits;
            *least = { observation.rip, satAdd(error, 1), error,
                       observation.timestampMs, observation.timestampMs,
                       observation.regionPrivate };
        }
    }

    if (observation.hasTransitionSource) {
        transitions_ = satAdd(transitions_, 1);
        auto edge = std::find_if(edges_.begin(), edges_.end(), [&](const EdgeCounter& item) {
            return item.from == observation.transitionSource && item.to == observation.rip;
        });
        if (edge != edges_.end()) {
            edge->hits = satAdd(edge->hits, 1);
            edge->lastSeenMs = observation.timestampMs;
        } else if (edges_.size() < config_.maxTrackedEdges) {
            edges_.push_back({ observation.transitionSource, observation.rip, 1, 0,
                               observation.timestampMs, observation.timestampMs });
        } else {
            auto least = std::min_element(edges_.begin(), edges_.end(),
                [](const auto& a, const auto& b) { return a.hits < b.hits; });
            const uint64_t error = least->hits;
            *least = { observation.transitionSource, observation.rip, satAdd(error, 1), error,
                       observation.timestampMs, observation.timestampMs };
        }
    }
}

void UnpackEngine::refreshState() {
    if (terminal(state_) || state_ == UnpackState::Idle) return;
    if (candidates_.empty()) {
        state_ = UnpackState::Observing;
        message_ = entropy_.settled ? "Entropy settled; waiting for an OEP signal" :
                                      "Collecting unpack telemetry";
    } else {
        state_ = UnpackState::CandidateReady;
        message_ = "One or more evidence-scored OEP candidates are ready";
    }
}

UnpackState UnpackEngine::state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

UnpackStrategy UnpackEngine::strategy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return strategy_;
}

UnpackReport UnpackEngine::report() const {
    std::lock_guard<std::mutex> lock(mutex_);
    UnpackReport out;
    out.samples.assign(samples_.begin(), samples_.end());
    out.candidates = candidates_;
    std::sort(out.candidates.begin(), out.candidates.end(), [](const auto& a, const auto& b) {
        if (a.score != b.score) return a.score > b.score;
        if (a.lastSeenMs != b.lastSeenMs) return a.lastSeenMs > b.lastSeenMs;
        return a.va < b.va;
    });
    out.entropy = entropy_;

    out.status.state = state_;
    out.status.strategy = strategy_;
    out.status.message = message_;
    out.status.totalSamples = totalSamples_;
    out.status.retainedSamples = samples_.size();
    out.status.droppedSamples = droppedSamples_;
    out.status.rejectedSamples = rejectedSamples_;
    out.status.candidateCount = candidates_.size();
    out.status.entropySettled = entropy_.settled;
    if (hasSelectedOep_) {
        out.status.hasBestOep = true;
        out.status.bestOep = selectedOep_;
        out.status.bestConfidence = selectedConfidence_;
    } else if (state_ != UnpackState::Completed && !out.candidates.empty()) {
        out.status.hasBestOep = true;
        out.status.bestOep = out.candidates.front().va;
        out.status.bestConfidence = out.candidates.front().confidence;
    }

    auto& vm = out.vmTrace;
    vm.observedTransitions = transitions_;
    for (const auto& item : rips_) {
        const uint64_t hits = item.hits >= item.error ? item.hits - item.error : 0;
        if (hits < config_.hotRipMinimumHits) continue;
        vm.hotRips.push_back({ item.rip, hits, item.firstSeenMs, item.lastSeenMs,
                              item.executable, item.privateRegion, item.error != 0 });
    }
    std::sort(vm.hotRips.begin(), vm.hotRips.end(), [](const auto& a, const auto& b) {
        if (a.hits != b.hits) return a.hits > b.hits;
        return a.rip < b.rip;
    });
    if (vm.hotRips.size() > config_.maxReportedHotRips)
        vm.hotRips.resize(config_.maxReportedHotRips);

    for (const auto& item : handlers_) {
        const uint64_t hits = item.hits >= item.error ? item.hits - item.error : 0;
        vm.handlers.push_back({ item.rip, hits, item.firstSeenMs, item.lastSeenMs,
                                0, true, item.privateRegion, item.error != 0 });
    }

    // A high fan-in destination is also useful VM-handler evidence even when
    // the sampler did not observe an exception dispatch.
    std::unordered_map<uint64_t, size_t> handlerIndex;
    handlerIndex.reserve(vm.handlers.size() + edges_.size());
    for (size_t i = 0; i < vm.handlers.size(); ++i)
        handlerIndex.emplace(vm.handlers[i].rip, i);
    std::unordered_map<uint64_t, bool> privateByRip;
    privateByRip.reserve(rips_.size());
    for (const auto& rip : rips_)
        privateByRip[rip.rip] = rip.privateRegion;
    for (const auto& edge : edges_) {
        const uint64_t hits = edge.hits >= edge.error ? edge.hits - edge.error : 0;
        auto found = handlerIndex.find(edge.to);
        if (found == handlerIndex.end()) {
            const bool privateRegion = privateByRip.find(edge.to) != privateByRip.end() &&
                                       privateByRip[edge.to];
            const size_t index = vm.handlers.size();
            vm.handlers.push_back({ edge.to, hits, edge.firstSeenMs, edge.lastSeenMs,
                                    1, false, privateRegion, edge.error != 0 });
            handlerIndex.emplace(edge.to, index);
        } else {
            auto& handler = vm.handlers[found->second];
            handler.fanIn = satInc(handler.fanIn);
            handler.firstSeenMs = std::min(handler.firstSeenMs, edge.firstSeenMs);
            handler.lastSeenMs = std::max(handler.lastSeenMs, edge.lastSeenMs);
            handler.approximate = handler.approximate || edge.error != 0;
            if (!handler.exceptionObserved)
                handler.hits = satAdd(handler.hits, hits);
        }
    }
    vm.handlers.erase(std::remove_if(vm.handlers.begin(), vm.handlers.end(),
        [&](const VmHandler& item) {
            return !item.exceptionObserved &&
                   (item.fanIn < 4 || item.hits < config_.hotRipMinimumHits);
        }), vm.handlers.end());
    std::sort(vm.handlers.begin(), vm.handlers.end(), [](const auto& a, const auto& b) {
        if (a.hits != b.hits) return a.hits > b.hits;
        return a.rip < b.rip;
    });
    if (vm.handlers.size() > config_.maxReportedHandlers)
        vm.handlers.resize(config_.maxReportedHandlers);

    for (const auto& item : edges_) {
        const uint64_t hits = item.hits >= item.error ? item.hits - item.error : 0;
        if (hits < config_.loopMinimumHits || item.to >= item.from) continue;
        vm.loops.push_back({ item.from, item.to, hits, item.firstSeenMs,
                            item.lastSeenMs, true, item.error != 0 });
    }
    std::sort(vm.loops.begin(), vm.loops.end(), [](const auto& a, const auto& b) {
        if (a.hits != b.hits) return a.hits > b.hits;
        if (a.from != b.from) return a.from < b.from;
        return a.to < b.to;
    });
    if (vm.loops.size() > config_.maxReportedLoops)
        vm.loops.resize(config_.maxReportedLoops);

    if (!vm.hotRips.empty() && totalSamples_ != 0) {
        const double ratio = static_cast<double>(vm.hotRips.front().hits) /
                             static_cast<double>(totalSamples_);
        if (ratio >= 0.25) {
            vm.score += 30;
            vm.evidence.push_back("A small dispatcher-like RIP dominates the trace");
        } else if (ratio >= 0.10) {
            vm.score += 18;
            vm.evidence.push_back("The trace has a notably hot RIP");
        }
        const bool privateHot = std::any_of(vm.hotRips.begin(), vm.hotRips.end(),
            [](const VmHotRip& item) { return item.privateRegion; });
        if (privateHot) {
            vm.score += 15;
            vm.evidence.push_back("Hot execution occurs in private memory");
        }
    }
    if (!vm.loops.empty()) {
        vm.score += 30;
        vm.evidence.push_back("Repeated exact back-edges resemble a dispatch loop");
    }
    if (!vm.handlers.empty()) {
        vm.score += 20;
        vm.evidence.push_back("Exception or high-fan-in handler entries were observed");
    }
    if (vm.hotRips.size() >= 4) {
        vm.score += 10;
        vm.evidence.push_back("Several addresses remain persistently hot");
    }
    vm.score = std::min(vm.score, 100);
    vm.vmLike = vm.score >= 50;
    return out;
}

const char* UnpackStrategyName(UnpackStrategy strategy) {
    switch (strategy) {
        case UnpackStrategy::Hybrid: return "Hybrid";
        case UnpackStrategy::StackReturn: return "Stack return";
        case UnpackStrategy::WriteExecute: return "Write then execute";
        case UnpackStrategy::EntropySettle: return "Entropy settle";
        case UnpackStrategy::RunFree: return "Run free";
        case UnpackStrategy::Manual: return "Manual";
    }
    return "Unknown";
}

const char* UnpackStateName(UnpackState state) {
    switch (state) {
        case UnpackState::Idle: return "Idle";
        case UnpackState::Observing: return "Observing";
        case UnpackState::CandidateReady: return "Candidate ready";
        case UnpackState::Completed: return "Completed";
        case UnpackState::Failed: return "Failed";
        case UnpackState::Cancelled: return "Cancelled";
    }
    return "Unknown";
}

const char* UnpackConfidenceName(UnpackConfidence confidence) {
    switch (confidence) {
        case UnpackConfidence::None: return "None";
        case UnpackConfidence::Low: return "Low";
        case UnpackConfidence::Medium: return "Medium";
        case UnpackConfidence::High: return "High";
    }
    return "Unknown";
}

const char* OepEvidenceName(OepEvidenceKind kind) {
    switch (kind) {
        case OepEvidenceKind::InOriginalImage: return "In original image";
        case OepEvidenceKind::ExecutableRegion: return "Executable region";
        case OepEvidenceKind::StackReturned: return "Stack return";
        case OepEvidenceKind::StackNearBaseline: return "Stack near baseline";
        case OepEvidenceKind::WriteThenExecute: return "Write then execute";
        case OepEvidenceKind::ProtectionBecameExecutable: return "Protection became executable";
        case OepEvidenceKind::EntropySettled: return "Entropy settled";
        case OepEvidenceKind::RunFreeStop: return "Run-free stop";
        case OepEvidenceKind::ManualSelection: return "Manual selection";
        case OepEvidenceKind::ControlTransfer: return "Control transfer";
        case OepEvidenceKind::RepeatedObservation: return "Repeated observation";
    }
    return "Unknown";
}

} // namespace ds
