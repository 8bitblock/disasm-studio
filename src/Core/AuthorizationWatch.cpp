#include "AuthorizationWatch.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <tuple>

namespace ds {

namespace {

bool siteLess(const AuthorizationWatchSite& a, const AuthorizationWatchSite& b) {
    const auto primaryA = std::tie(a.moduleRva, a.flowId, a.stage, a.outcome,
                                   a.strongOutcome, a.label);
    const auto primaryB = std::tie(b.moduleRva, b.flowId, b.stage, b.outcome,
                                   b.strongOutcome, b.label);
    if (primaryA != primaryB) return primaryA < primaryB;
    if (!CodeByteSignaturesEqual(a.signature, b.signature)) {
        if (a.signature.length != b.signature.length)
            return a.signature.length < b.signature.length;
        const size_t compared = (std::min<size_t>)(
            a.signature.length, kCodeByteSignatureMax);
        for (size_t i = 0; i < compared; ++i) {
            if (a.signature.expected[i] != b.signature.expected[i])
                return a.signature.expected[i] < b.signature.expected[i];
            if (a.signature.compareMask[i] != b.signature.compareMask[i])
                return a.signature.compareMask[i] < b.signature.compareMask[i];
        }
    }
    if (a.stateApi.has_value() != b.stateApi.has_value())
        return !a.stateApi.has_value();
    if (!a.stateApi) return false;
    return std::tie(a.stateApi->dll, a.stateApi->symbol,
                    a.stateApi->operation, a.stateApi->returnRule) <
           std::tie(b.stateApi->dll, b.stateApi->symbol,
                    b.stateApi->operation, b.stateApi->returnRule);
}

bool siteEqual(const AuthorizationWatchSite& a, const AuthorizationWatchSite& b) {
    return !siteLess(a, b) && !siteLess(b, a);
}

void saturatedIncrement(uint64_t& value) {
    if (value != std::numeric_limits<uint64_t>::max()) ++value;
}

} // namespace

bool AuthorizationWatchSourceEvidenceMatches(
    const AuthorizationWatchSourceEvidence& expected,
    const AttachedFileIdentity& actual,
    const AuthorizationWatchSourceReader& read) {
    if (!CompleteAuthorizationWatchSourceEvidence(expected) || !read ||
        !SameAttachedFileIdentity(expected.fileIdentity, actual))
        return false;

    constexpr size_t kChunk = 1024u * 1024u;
    try {
        std::vector<uint8_t> buffer(
            (std::min)(kChunk, expected.bytes->size()));
        size_t offset = 0;
        while (offset < expected.bytes->size()) {
            const size_t count = (std::min)(
                buffer.size(), expected.bytes->size() - offset);
            if (!read(static_cast<uint64_t>(offset), buffer.data(), count) ||
                std::memcmp(buffer.data(), expected.bytes->data() + offset,
                            count) != 0)
                return false;
            offset += count;
        }
    } catch (...) {
        return false;
    }
    return true;
}

uint64_t AuthorizationWatch::prepare(const AuthorizationWatchPlan& plan,
                                     const AuthorizationWatchOptions& options) {
    // Analyzer order is priority order. Select the first 512 *unique* semantic
    // rows, keeping the working copy bounded while allowing duplicates ahead of
    // a later unique row to collapse rather than consume the cap.
    std::vector<AuthorizationWatchSite> sites;
    sites.reserve((std::min)(plan.sites.size(), kAuthorizationWatchSiteCap));
    const size_t scanLimit =
        (std::min)(plan.sites.size(), kAuthorizationWatchInputScanCap);
    size_t scannedSites = 0;
    for (size_t candidateIndex = 0; candidateIndex < scanLimit;
         ++candidateIndex) {
        if (sites.size() >= kAuthorizationWatchSiteCap) break;
        const AuthorizationWatchSite& candidate = plan.sites[candidateIndex];
        ++scannedSites;
        const auto at = std::lower_bound(sites.begin(), sites.end(), candidate,
                                         siteLess);
        if (at != sites.end() && siteEqual(*at, candidate)) continue;
        sites.insert(at, candidate);
    }

    std::lock_guard<std::mutex> lock(mtx_);
    ++generation_;
    if (!generation_) ++generation_;
    ++revision_;
    active_ = true;
    sequence_ = 0;
    attemptSequence_ = 0;
    requestedSites_ = plan.sites.size();
    if (requestedSites_ <= (std::numeric_limits<size_t>::max)() -
            plan.signatureUnavailableSites)
        requestedSites_ += plan.signatureUnavailableSites;
    else
        requestedSites_ = (std::numeric_limits<size_t>::max)();
    inputSitesScanned_ = scannedSites;
    inputSitesTruncated_ = plan.sites.size() - scannedSites;
    retainedSites_ = sites.size();
    unmappedSkippedSites_ = 0;
    preparedSignatureUnavailableSites_ =
        plan.signatureUnavailableSites;
    hitSignatureMismatches_ = 0;
    droppedEvents_ = 0;
    target_ = {};
    mainImageBase_ = 0;
    imageSize_ = plan.imageSize;
    documentIdentity_ = plan.documentIdentity;
    documentId_ = plan.documentId;
    documentImageGeneration_ = plan.documentImageGeneration;
    imagePath_ = plan.imagePath;
    requireExactModuleIdentity_ = plan.requireExactModuleIdentity;
    expectedModule_ = plan.expectedModule;
    boundModule_ = {};
    sourceEvidenceRequired_ = plan.launchSource.bytes ||
                              plan.launchSource.fileIdentity.valid;
    sourceEvidenceValidated_ = false;
    sourceEvidenceFailed_ = false;
    sourceEvidenceError_.clear();
    sourceEvidence_ = plan.launchSource;
    options_ = options;
    preparedSites_ = std::move(sites);
    runtimeSites_.clear();
    events_.clear();
    return generation_;
}

bool AuthorizationWatch::bindTarget(uint64_t generation,
                                    DebugTargetIdentity target,
                                    const AttachedModuleIdentity& mainImage) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_ || !target.valid() ||
        (sourceEvidenceRequired_ && !sourceEvidenceValidated_) ||
        !CompleteAuthorizationWatchModuleIdentity(mainImage) ||
        (requireExactModuleIdentity_ &&
         !ExactAuthorizationWatchModuleMatch(expectedModule_, mainImage)))
        return false;

    target_ = target;
    mainImageBase_ = mainImage.base;
    boundModule_ = mainImage;
    runtimeSites_.clear();
    unmappedSkippedSites_ = 0;
    for (const AuthorizationWatchSite& site : preparedSites_) {
        if ((imageSize_ && site.moduleRva >= imageSize_) ||
            site.moduleRva > std::numeric_limits<uint64_t>::max() - mainImage.base) {
            ++unmappedSkippedSites_;
            continue;
        }
        const uint64_t runtimeVa = mainImage.base + site.moduleRva;
        RuntimeRecord& record = runtimeSites_[runtimeVa];
        record.moduleRva = site.moduleRva;
        if (record.semantics.empty()) record.signature = site.signature;
        else if (!CodeByteSignaturesEqual(record.signature, site.signature))
            record.signature = {};
        record.semantics.push_back(site);
    }
    ++revision_;
    return true;
}

std::optional<AuthorizationWatchSourceEvidence>
AuthorizationWatch::pendingSourceEvidence(uint64_t generation) const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_ ||
        !sourceEvidenceRequired_ || sourceEvidenceValidated_ ||
        sourceEvidenceFailed_ ||
        !CompleteAuthorizationWatchSourceEvidence(sourceEvidence_))
        return std::nullopt;
    return sourceEvidence_;
}

bool AuthorizationWatch::acceptSourceEvidence(uint64_t generation) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_ ||
        !sourceEvidenceRequired_ || sourceEvidenceValidated_ ||
        sourceEvidenceFailed_ || target_.valid() || !runtimeSites_.empty() ||
        !CompleteAuthorizationWatchSourceEvidence(sourceEvidence_))
        return false;
    sourceEvidenceValidated_ = true;
    sourceEvidence_ = {};
    sourceEvidenceError_.clear();
    ++revision_;
    return true;
}

bool AuthorizationWatch::rejectSourceEvidence(uint64_t generation) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_ || !sourceEvidenceRequired_ ||
        sourceEvidenceValidated_ || sourceEvidenceFailed_)
        return false;
    active_ = false;
    sourceEvidenceValidated_ = false;
    sourceEvidenceFailed_ = true;
    sourceEvidenceError_ = kAuthorizationWatchSourceRejectionMessage;
    sourceEvidence_ = {};
    target_ = {};
    mainImageBase_ = 0;
    boundModule_ = {};
    runtimeSites_.clear();
    events_.clear();
    ++revision_;
    return true;
}

void AuthorizationWatch::stop() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_) return;
    active_ = false;
    sourceEvidence_ = {};
    for (auto& [_, site] : runtimeSites_) {
        site.state = SiteState::Pending;
        site.sharedWithUserBreakpoint = false;
    }
    ++revision_;
}

void AuthorizationWatch::clearEvents() {
    std::lock_guard<std::mutex> lock(mtx_);
    events_.clear();
    sequence_ = 0;
    droppedEvents_ = 0;
    for (auto& [_, site] : runtimeSites_) site.hits = 0;
    ++revision_;
}

void AuthorizationWatch::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    ++generation_;
    if (!generation_) ++generation_;
    ++revision_;
    active_ = false;
    sequence_ = 0;
    attemptSequence_ = 0;
    requestedSites_ = inputSitesScanned_ = inputSitesTruncated_ =
        retainedSites_ = 0;
    unmappedSkippedSites_ = 0;
    preparedSignatureUnavailableSites_ = 0;
    hitSignatureMismatches_ = 0;
    droppedEvents_ = 0;
    target_ = {};
    mainImageBase_ = 0;
    imageSize_ = 0;
    documentIdentity_.clear();
    documentId_ = 0;
    documentImageGeneration_ = 0;
    imagePath_.clear();
    requireExactModuleIdentity_ = false;
    expectedModule_ = {};
    boundModule_ = {};
    sourceEvidenceRequired_ = false;
    sourceEvidenceValidated_ = false;
    sourceEvidenceFailed_ = false;
    sourceEvidenceError_.clear();
    sourceEvidence_ = {};
    options_ = {};
    preparedSites_.clear();
    runtimeSites_.clear();
    events_.clear();
}

bool AuthorizationWatch::active() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return active_;
}

uint64_t AuthorizationWatch::generation() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return generation_;
}

std::vector<AuthorizationWatchRuntimeSite>
AuthorizationWatch::pendingSites(uint64_t generation) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<AuthorizationWatchRuntimeSite> out;
    if (!active_ || generation != generation_ || !target_.valid()) return out;
    for (const auto& [runtimeVa, site] : runtimeSites_)
        if (site.state == SiteState::Pending)
            out.push_back({ runtimeVa, site.moduleRva, site.signature });
    return out;
}

void AuthorizationWatch::markArmed(uint64_t generation, uint64_t runtimeVa,
                                   bool sharedWithUserBreakpoint) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_) return;
    auto it = runtimeSites_.find(runtimeVa);
    if (it == runtimeSites_.end()) return;
    it->second.state = SiteState::Armed;
    it->second.sharedWithUserBreakpoint = sharedWithUserBreakpoint;
    ++revision_;
}

void AuthorizationWatch::markSkipped(uint64_t generation, uint64_t runtimeVa,
                                      AuthorizationWatchSkipReason reason) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (generation != generation_) return;
    auto it = runtimeSites_.find(runtimeVa);
    if (it == runtimeSites_.end()) return;
    it->second.state = SiteState::Skipped;
    it->second.sharedWithUserBreakpoint = false;
    it->second.skipReason = reason;
    ++revision_;
}

void AuthorizationWatch::markHitSignatureMismatch(uint64_t generation,
                                                   uint64_t runtimeVa) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || generation != generation_) return;
    auto it = runtimeSites_.find(runtimeVa);
    if (it == runtimeSites_.end() || it->second.state != SiteState::Armed)
        return;
    it->second.state = SiteState::Skipped;
    it->second.sharedWithUserBreakpoint = false;
    it->second.skipReason = AuthorizationWatchSkipReason::SignatureMismatch;
    saturatedIncrement(hitSignatureMismatches_);
    ++revision_;
}

void AuthorizationWatch::markDisarmed(uint64_t generation, uint64_t runtimeVa) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (generation != generation_) return;
    auto it = runtimeSites_.find(runtimeVa);
    if (it == runtimeSites_.end()) return;
    it->second.state = SiteState::Pending;
    it->second.sharedWithUserBreakpoint = false;
    it->second.skipReason = AuthorizationWatchSkipReason::Other;
    ++revision_;
}

AuthorizationWatchHitResult AuthorizationWatch::recordEntryHit(
    uint64_t generation, uint64_t runtimeVa, uint32_t tid,
    uint64_t timestampTicks) {
    std::lock_guard<std::mutex> lock(mtx_);
    AuthorizationWatchHitResult result;
    if (!active_ || generation != generation_ || !target_.valid()) return result;
    auto found = runtimeSites_.find(runtimeVa);
    if (found == runtimeSites_.end() || found->second.state != SiteState::Armed)
        return result;

    RuntimeRecord& runtime = found->second;
    saturatedIncrement(runtime.hits);
    for (const AuthorizationWatchSite& site : runtime.semantics) {
        AuthorizationWatchEvent event;
        event.sequence = ++sequence_;
        if (!event.sequence) event.sequence = ++sequence_;
        event.generation = generation_;
        event.target = target_;
        event.timestampTicks = timestampTicks;
        event.tid = tid;
        event.runtimeVa = runtimeVa;
        event.moduleRva = runtime.moduleRva;
        event.flowId = site.flowId;
        event.stage = site.stage;
        event.outcome = site.outcome;
        event.label = site.label;
        event.strongOutcome = site.strongOutcome;
        event.stateApi = site.stateApi;
        event.stateOperationAttempted = site.stateApi && site.stateApi->valid();
        if (event.stateOperationAttempted) {
            event.attemptId = ++attemptSequence_;
            if (!event.attemptId) event.attemptId = ++attemptSequence_;
            AuthorizationWatchReturnRequest request;
            request.generation = generation_;
            request.attemptId = event.attemptId;
            request.entryRuntimeVa = runtimeVa;
            request.entryModuleRva = runtime.moduleRva;
            request.flowId = site.flowId;
            request.stage = site.stage;
            request.outcome = site.outcome;
            request.label = site.label;
            request.strongOutcome = site.strongOutcome;
            request.stateApi = *site.stateApi;
            result.returnRequests.push_back(std::move(request));
        }
        if (events_.size() == kAuthorizationWatchEventCap) {
            events_.pop_front();
            saturatedIncrement(droppedEvents_);
        }
        events_.push_back(std::move(event));
    }
    ++revision_;
    result.pauseRequested = options_.pauseOnHit;
    return result;
}

bool AuthorizationWatch::recordStateReturn(
    const AuthorizationWatchReturnRequest& request, uint64_t returnRuntimeVa,
    uint32_t tid, uint64_t timestampTicks, uint64_t rawResult,
    uint8_t pointerWidthBits) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!active_ || request.generation != generation_ || !target_.valid() ||
        !request.attemptId || !request.stateApi.valid())
        return false;

    const bool validWidth = pointerWidthBits == 32 || pointerWidthBits == 64;
    const uint64_t normalized = pointerWidthBits == 32
        ? static_cast<uint32_t>(rawResult) : rawResult;
    bool successKnown = validWidth &&
                        request.stateApi.returnRule != AuthorizationWatchReturnRule::None;
    bool succeeded = false;
    if (successKnown) {
        switch (request.stateApi.returnRule) {
            case AuthorizationWatchReturnRule::BooleanNonzero:
                succeeded = normalized != 0;
                break;
            case AuthorizationWatchReturnRule::ZeroIsSuccess:
                succeeded = normalized == 0;
                break;
            case AuthorizationWatchReturnRule::NonnegativeIsSuccess:
                // Cataloged signed-count/status APIs return a 32-bit integer on
                // both Win32 and Win64.  EAX writes zero-extend into RAX, so a
                // negative value such as 0xffffffff must be interpreted from
                // the signed low 32 bits even in a 64-bit target.
                succeeded = static_cast<int32_t>(
                    static_cast<uint32_t>(normalized)) >= 0;
                break;
            case AuthorizationWatchReturnRule::NonNullHandle:
                succeeded = normalized != 0;
                break;
            case AuthorizationWatchReturnRule::NotInvalidHandle:
                succeeded = normalized != (pointerWidthBits == 32
                    ? uint64_t{UINT32_MAX} : UINT64_MAX);
                break;
            case AuthorizationWatchReturnRule::NotInvalidValue32:
                succeeded = static_cast<uint32_t>(normalized) != UINT32_MAX;
                break;
            case AuthorizationWatchReturnRule::None:
            default:
                successKnown = false;
                break;
        }
    }

    AuthorizationWatchEvent event;
    event.sequence = ++sequence_;
    if (!event.sequence) event.sequence = ++sequence_;
    event.generation = generation_;
    event.target = target_;
    event.timestampTicks = timestampTicks;
    event.tid = tid;
    event.runtimeVa = returnRuntimeVa;
    event.moduleRva = returnRuntimeVa >= mainImageBase_
        ? returnRuntimeVa - mainImageBase_ : 0;
    event.flowId = request.flowId;
    event.attemptId = request.attemptId;
    event.stage = request.stage;
    event.outcome = request.outcome;
    event.label = request.label;
    event.strongOutcome = request.strongOutcome;
    event.stateApi = request.stateApi;
    event.stateOperationAttempted = true;
    event.stateOperationReturn = true;
    event.stateOperationSuccessKnown = successKnown;
    event.stateOperationSucceeded = successKnown && succeeded;
    event.rawResultValid = validWidth;
    event.rawResult = normalized;
    event.pointerWidthBits = validWidth ? pointerWidthBits : 0;
    if (events_.size() == kAuthorizationWatchEventCap) {
        events_.pop_front();
        saturatedIncrement(droppedEvents_);
    }
    events_.push_back(std::move(event));
    ++revision_;
    return options_.pauseOnHit;
}

bool AuthorizationWatch::recordHit(uint64_t generation, uint64_t runtimeVa,
                                   uint32_t tid, uint64_t timestampTicks,
                                   bool successKnown, bool succeeded) {
    AuthorizationWatchHitResult result =
        recordEntryHit(generation, runtimeVa, tid, timestampTicks);
    if (successKnown) {
        const uint8_t width = sizeof(void*) == 4 ? 32 : 64;
        for (const auto& request : result.returnRequests) {
            uint64_t compatibleRaw = 0;
            switch (request.stateApi.returnRule) {
                case AuthorizationWatchReturnRule::ZeroIsSuccess:
                    compatibleRaw = succeeded ? 0 : 1;
                    break;
                case AuthorizationWatchReturnRule::NonnegativeIsSuccess:
                    compatibleRaw = succeeded ? 0 : UINT64_MAX;
                    break;
                case AuthorizationWatchReturnRule::NotInvalidHandle:
                case AuthorizationWatchReturnRule::NotInvalidValue32:
                    compatibleRaw = succeeded ? 1 : UINT64_MAX;
                    break;
                case AuthorizationWatchReturnRule::BooleanNonzero:
                case AuthorizationWatchReturnRule::NonNullHandle:
                default:
                    compatibleRaw = succeeded ? 1 : 0;
                    break;
            }
            (void)recordStateReturn(request, runtimeVa, tid, timestampTicks,
                                    compatibleRaw, width);
        }
    }
    return result.pauseRequested;
}

AuthorizationWatchSnapshot AuthorizationWatch::snapshot() const {
    std::lock_guard<std::mutex> lock(mtx_);
    AuthorizationWatchSnapshot out;
    out.active = active_;
    out.targetBound = target_.valid() && mainImageBase_ != 0;
    out.generation = generation_;
    out.revision = revision_;
    out.target = target_;
    out.mainImageBase = mainImageBase_;
    out.imageSize = imageSize_;
    out.documentIdentity = documentIdentity_;
    out.documentId = documentId_;
    out.documentImageGeneration = documentImageGeneration_;
    out.imagePath = imagePath_;
    out.boundModule = boundModule_;
    out.sourceValidationRequired = sourceEvidenceRequired_;
    out.sourceValidationComplete = sourceEvidenceValidated_;
    out.sourceValidationFailed = sourceEvidenceFailed_;
    out.sourceValidationError = sourceEvidenceError_;
    out.options = options_;
    out.coverage.requestedSites = requestedSites_;
    out.coverage.inputSitesScanned = inputSitesScanned_;
    out.coverage.inputSitesTruncated = inputSitesTruncated_;
    out.coverage.retainedSites = retainedSites_;
    out.coverage.plannedSites = runtimeSites_.size();
    out.coverage.skippedSites = unmappedSkippedSites_ +
        preparedSignatureUnavailableSites_;
    out.coverage.signatureUnavailableSites =
        preparedSignatureUnavailableSites_;
    out.coverage.hitSignatureMismatches = hitSignatureMismatches_;
    out.coverage.droppedEvents = droppedEvents_;
    for (const auto& [_, site] : runtimeSites_) {
        switch (site.state) {
            case SiteState::Armed:
                ++out.coverage.armedSites;
                if (site.sharedWithUserBreakpoint)
                    ++out.coverage.sitesSharedWithUserBreakpoints;
                break;
            case SiteState::Skipped:
                ++out.coverage.skippedSites;
                if (site.skipReason ==
                    AuthorizationWatchSkipReason::SignatureUnavailable)
                    ++out.coverage.signatureUnavailableSites;
                else if (site.skipReason ==
                         AuthorizationWatchSkipReason::SignatureMismatch)
                    ++out.coverage.signatureMismatchSites;
                break;
            case SiteState::Pending: break;
        }
        if (site.hits) ++out.coverage.hitSites;
        if (std::numeric_limits<uint64_t>::max() - out.coverage.hitTotal < site.hits)
            out.coverage.hitTotal = std::numeric_limits<uint64_t>::max();
        else
            out.coverage.hitTotal += site.hits;
    }
    out.events.assign(events_.begin(), events_.end());
    return out;
}

bool AuthorizationWatchReturnTracker::push(
    uint32_t tid, uint64_t returnAddress, AuthorizationWatchPendingReturn pending) {
    if (!tid || !returnAddress || pending.requests.empty() ||
        total_ >= kAuthorizationWatchPendingReturnCap)
        return false;
    auto& stack = perThread_[tid];
    if (stack.size() >= kAuthorizationWatchPerThreadReturnDepth) return false;
    pending.returnAddress = returnAddress;
    stack.push_back(std::move(pending));
    ++references_[returnAddress];
    ++total_;
    return true;
}

bool AuthorizationWatchReturnTracker::pop(
    uint32_t tid, uint64_t returnAddress, AuthorizationWatchPendingReturn& pending) {
    auto thread = perThread_.find(tid);
    if (thread == perThread_.end() || thread->second.empty() ||
        thread->second.back().returnAddress != returnAddress)
        return false;
    pending = std::move(thread->second.back());
    thread->second.pop_back();
    if (thread->second.empty()) perThread_.erase(thread);
    auto reference = references_.find(returnAddress);
    if (reference != references_.end() && --reference->second == 0)
        references_.erase(reference);
    --total_;
    return true;
}

size_t AuthorizationWatchReturnTracker::references(uint64_t returnAddress) const {
    auto found = references_.find(returnAddress);
    return found == references_.end() ? 0 : found->second;
}

std::vector<uint64_t> AuthorizationWatchReturnTracker::eraseThread(
    uint32_t tid, size_t* erased) {
    if (erased) *erased = 0;
    std::vector<uint64_t> exhausted;
    auto thread = perThread_.find(tid);
    if (thread == perThread_.end()) return exhausted;
    for (const AuthorizationWatchPendingReturn& pending : thread->second) {
        auto reference = references_.find(pending.returnAddress);
        if (reference != references_.end() && --reference->second == 0) {
            exhausted.push_back(pending.returnAddress);
            references_.erase(reference);
        }
        --total_;
        if (erased) ++*erased;
    }
    perThread_.erase(thread);
    return exhausted;
}

void AuthorizationWatchReturnTracker::clear() {
    perThread_.clear();
    references_.clear();
    total_ = 0;
}

} // namespace ds
