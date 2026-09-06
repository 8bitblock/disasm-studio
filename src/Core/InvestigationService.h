#pragma once
//
// InvestigationService.h
// Single-owner background orchestration for InvestigationIndex rebuild/search.
// The UI boundary only exchanges small commands and immutable shared snapshots.

#include "InvestigationIndex.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ds {

struct InvestigationBuildPublication {
    uint64_t generation = 0;
    uint64_t requestId = 0;
    InvestigationBuildResult result;
};

struct InvestigationSearchPublication {
    uint64_t generation = 0;
    uint64_t requestId = 0;
    std::string query;
    InvestigationSearchResult result;
};

struct InvestigationServiceStats {
    uint64_t generation = 0;
    uint64_t requested = 0;
    uint64_t coalesced = 0;
    uint64_t dropped = 0;
    uint64_t stale = 0;
    uint64_t failed = 0;
    uint64_t completed = 0;
    size_t queued = 0; // hard-bounded to one build plus one search
    bool busy = false;
    bool hasIndex = false;
};

struct InvestigationServicePending {
    uint64_t generation = 0;
    bool buildQueued = false;
    bool searchQueued = false;
    bool building = false;
    bool searching = false;
};

// Injectable only for deterministic tests and alternate pure index backends.
// One instance is created and exclusively invoked on the service worker.
class IInvestigationServiceBackend {
public:
    virtual ~IInvestigationServiceBackend() = default;
    virtual InvestigationBuildResult build(
        const InvestigationSnapshot& snapshot,
        const InvestigationLimits& limits,
        const InvestigationCancel& cancelled) = 0;
    virtual InvestigationSearchResult search(
        const InvestigationIndex& index,
        std::string_view query,
        const InvestigationSearchOptions& options,
        const InvestigationCancel& cancelled) = 0;
};

using InvestigationServiceBackendFactory =
    std::function<std::unique_ptr<IInvestigationServiceBackend>()>;

class InvestigationService {
public:
    explicit InvestigationService(
        InvestigationServiceBackendFactory backendFactory = {});
    ~InvestigationService();
    InvestigationService(const InvestigationService&) = delete;
    InvestigationService& operator=(const InvestigationService&) = delete;

    // Starts/replaces a document session. Snapshot ownership is shared without
    // copying its potentially large vectors on the caller thread.
    uint64_t beginSession(
        uint64_t generation,
        std::shared_ptr<const InvestigationSnapshot> snapshot,
        InvestigationLimits limits = {});

    // Latest query wins within a generation. The query copy is hard-capped;
    // index traversal and result construction remain on the worker.
    uint64_t requestSearch(
        uint64_t generation,
        std::string query,
        InvestigationSearchOptions options = {});

    // Polling copies only shared_ptrs. The build publication is retained for
    // the current session; search publications may also be consumed once.
    std::shared_ptr<const InvestigationBuildPublication> currentBuild() const;
    std::shared_ptr<const InvestigationIndex> currentIndex() const;
    std::shared_ptr<const InvestigationSearchPublication> latestSearch() const;
    std::shared_ptr<const InvestigationSearchPublication> consumeLatestSearch();

    InvestigationServiceStats stats() const;
    InvestigationServicePending pending() const;

    // Cancels queued/in-flight work and invalidates publications. Worker-owned
    // operations receive cooperative cancellation; cancelAndWaitIdle joins the
    // current operation boundary without destroying the reusable worker.
    void cancel();
    void cancelAndWaitIdle();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ds
