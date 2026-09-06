#include "InvestigationService.h"

#include <atomic>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

namespace ds {
namespace {

constexpr size_t kFailureTextCap = 4096;

std::string BoundedFailure(std::string_view prefix, std::string_view detail) {
    std::string result;
    const size_t prefixBytes = (std::min)(kFailureTextCap, prefix.size());
    const size_t detailBytes = (std::min)(kFailureTextCap - prefixBytes, detail.size());
    result.reserve(prefixBytes + detailBytes);
    auto append = [&](std::string_view text) {
        if (result.size() < kFailureTextCap)
            result.append(text.substr(0, kFailureTextCap - result.size()));
    };
    append(prefix);
    append(detail);
    return result;
}

class DefaultInvestigationServiceBackend final : public IInvestigationServiceBackend {
public:
    InvestigationBuildResult build(
        const InvestigationSnapshot& snapshot,
        const InvestigationLimits& limits,
        const InvestigationCancel& cancelled) override {
        return InvestigationIndex::Build(snapshot, limits, cancelled);
    }

    InvestigationSearchResult search(
        const InvestigationIndex& index,
        std::string_view query,
        const InvestigationSearchOptions& options,
        const InvestigationCancel& cancelled) override {
        return index.search(query, options, cancelled);
    }
};

} // namespace

struct InvestigationService::Impl {
    enum class ActiveKind : uint8_t { None, Build, Search };

    struct BuildCommand {
        uint64_t generation = 0;
        uint64_t requestId = 0;
        uint64_t sessionToken = 0;
        std::shared_ptr<const InvestigationSnapshot> snapshot;
        InvestigationLimits limits;
    };

    struct SearchCommand {
        uint64_t generation = 0;
        uint64_t requestId = 0;
        uint64_t sessionToken = 0;
        uint64_t searchToken = 0;
        std::string query;
        InvestigationSearchOptions options;
        std::shared_ptr<const InvestigationIndex> index;
    };

    explicit Impl(InvestigationServiceBackendFactory backendFactory)
        : factory(std::move(backendFactory)) {
        // All queue/session fields must exist before the worker can observe them.
        worker = std::thread([this] { threadEntry(); });
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping.store(true, std::memory_order_release);
            sessionToken.fetch_add(1, std::memory_order_acq_rel);
            searchToken.fetch_add(1, std::memory_order_acq_rel);
            pendingBuild.reset();
            pendingSearch.reset();
        }
        wake.notify_all();
        if (worker.joinable()) worker.join();
    }

    uint64_t nextRequestIdLocked() noexcept {
        uint64_t id = nextRequestId++;
        if (id == 0) id = nextRequestId++;
        return id;
    }

    static InvestigationBuildResult BuildFailure(std::string_view message) {
        InvestigationBuildResult result;
        result.error = BoundedFailure("Investigation build failed: ", message);
        return result;
    }

    static InvestigationSearchResult SearchFailure(std::string_view message) {
        InvestigationSearchResult result;
        result.error = BoundedFailure("Investigation search failed: ", message);
        return result;
    }

    bool buildStaleLocked(const BuildCommand& command) const noexcept {
        return stopping.load(std::memory_order_acquire) || !sessionActive ||
               command.generation != generation ||
               command.sessionToken != sessionToken.load(std::memory_order_acquire);
    }

    bool searchStaleLocked(const SearchCommand& command) const noexcept {
        return stopping.load(std::memory_order_acquire) || !sessionActive ||
               command.generation != generation ||
               command.sessionToken != sessionToken.load(std::memory_order_acquire) ||
               command.searchToken != searchToken.load(std::memory_order_acquire);
    }

    void publishBuild(BuildCommand command, InvestigationBuildResult result) {
        std::lock_guard<std::mutex> lock(mutex);
        if (buildStaleLocked(command)) {
            ++stale;
            return;
        }
        if (result.complete && !result.index) {
            result.complete = false;
            result.error = "Investigation build failed: backend returned no index";
        }
        if (!result.complete && result.error.empty()) {
            result.error = result.cancelled
                ? "Investigation build cancelled"
                : "Investigation build failed without an error message";
        }

        auto publication = std::make_shared<InvestigationBuildPublication>();
        publication->generation = command.generation;
        publication->requestId = command.requestId;
        publication->result = std::move(result);
        if (buildPublication) ++dropped;
        buildPublication = std::move(publication);

        if (buildPublication->result.complete && buildPublication->result.index) {
            currentIndex = buildPublication->result.index;
            currentIndexGeneration = command.generation;
            ++completed;
        } else {
            currentIndex.reset();
            currentIndexGeneration = 0;
            ++failed;
        }
    }

    void publishSearch(SearchCommand command, InvestigationSearchResult result) {
        std::lock_guard<std::mutex> lock(mutex);
        if (searchStaleLocked(command)) {
            ++stale;
            return;
        }
        if (!result.complete && result.error.empty()) {
            result.error = result.cancelled
                ? "Investigation search cancelled"
                : "Investigation search failed without an error message";
        }

        auto publication = std::make_shared<InvestigationSearchPublication>();
        publication->generation = command.generation;
        publication->requestId = command.requestId;
        publication->query = std::move(command.query);
        publication->result = std::move(result);
        if (searchPublication) ++dropped;
        searchPublication = std::move(publication);
        if (searchPublication->result.complete) ++completed;
        else ++failed;
    }

    void finishCommand() {
        std::lock_guard<std::mutex> lock(mutex);
        busy = false;
        active = ActiveKind::None;
        if (!pendingBuild && !pendingSearch) idle.notify_all();
    }

    void failWorker() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex);
            stopping.store(true, std::memory_order_release);
            sessionToken.fetch_add(1, std::memory_order_acq_rel);
            searchToken.fetch_add(1, std::memory_order_acq_rel);
            pendingBuild.reset();
            pendingSearch.reset();
            currentIndex.reset();
            currentIndexGeneration = 0;
            busy = false;
            active = ActiveKind::None;
            ++failed;
        } catch (...) {
            // Keep the no-throw thread boundary intact under allocator failure.
            stopping.store(true, std::memory_order_release);
        }
        idle.notify_all();
        wake.notify_all();
    }

    void threadEntry() noexcept {
        try {
            run();
        } catch (...) {
            // Backend calls and normal publication already have finer-grained
            // diagnostics.  This is the final guard for queue/move/allocation
            // failures outside those operation boundaries.
            failWorker();
        }
    }

    void run() {
        std::unique_ptr<IInvestigationServiceBackend> backend;
        std::string backendError;
        try {
            backend = factory ? factory()
                              : std::make_unique<DefaultInvestigationServiceBackend>();
            if (!backend) backendError = "backend factory returned null";
        } catch (const std::exception& error) {
            backendError = BoundedFailure("backend creation threw: ", error.what());
        } catch (...) {
            backendError = "backend creation threw an unknown exception";
        }

        for (;;) {
            std::optional<BuildCommand> build;
            std::optional<SearchCommand> search;
            {
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait(lock, [&] {
                    return stopping.load(std::memory_order_acquire) ||
                           pendingBuild.has_value() || pendingSearch.has_value();
                });
                if (stopping.load(std::memory_order_acquire)) break;

                // A session rebuild always precedes its retained latest query.
                if (pendingBuild) {
                    build = std::move(pendingBuild);
                    pendingBuild.reset();
                    active = ActiveKind::Build;
                } else {
                    search = std::move(pendingSearch);
                    pendingSearch.reset();
                    active = ActiveKind::Search;
                    if (search && currentIndex && currentIndexGeneration == search->generation)
                        search->index = currentIndex;
                }
                busy = true;
            }

            if (build) {
                InvestigationBuildResult result;
                try {
                    if (!backend) throw std::runtime_error(
                        backendError.empty() ? "backend is unavailable" : backendError);
                    if (!build->snapshot)
                        throw std::runtime_error("session snapshot is null");
                    const uint64_t token = build->sessionToken;
                    result = backend->build(*build->snapshot, build->limits, [this, token] {
                        return stopping.load(std::memory_order_acquire) ||
                               sessionToken.load(std::memory_order_acquire) != token;
                    });
                } catch (const std::exception& error) {
                    result = BuildFailure(error.what());
                } catch (...) {
                    result = BuildFailure("unknown worker exception");
                }
                try {
                    publishBuild(std::move(*build), std::move(result));
                } catch (...) {
                    // Publication allocation is the final exception boundary.
                    std::lock_guard<std::mutex> lock(mutex);
                    ++failed;
                }
            } else if (search) {
                InvestigationSearchResult result;
                try {
                    if (!backend) throw std::runtime_error(
                        backendError.empty() ? "backend is unavailable" : backendError);
                    if (!search->index)
                        throw std::runtime_error("no completed index exists for this generation");
                    const uint64_t session = search->sessionToken;
                    const uint64_t query = search->searchToken;
                    result = backend->search(*search->index, search->query, search->options,
                        [this, session, query] {
                            return stopping.load(std::memory_order_acquire) ||
                                   sessionToken.load(std::memory_order_acquire) != session ||
                                   searchToken.load(std::memory_order_acquire) != query;
                        });
                } catch (const std::exception& error) {
                    result = SearchFailure(error.what());
                } catch (...) {
                    result = SearchFailure("unknown worker exception");
                }
                try {
                    publishSearch(std::move(*search), std::move(result));
                } catch (...) {
                    std::lock_guard<std::mutex> lock(mutex);
                    ++failed;
                }
            }
            finishCommand();
        }

        std::lock_guard<std::mutex> lock(mutex);
        busy = false;
        active = ActiveKind::None;
        idle.notify_all();
    }

    InvestigationServiceBackendFactory factory;
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::condition_variable idle;
    std::atomic<bool> stopping{false};
    std::atomic<uint64_t> sessionToken{1};
    std::atomic<uint64_t> searchToken{1};
    std::thread worker;

    uint64_t generation = 0;
    uint64_t nextRequestId = 1;
    bool sessionActive = false;
    bool busy = false;
    ActiveKind active = ActiveKind::None;
    std::optional<BuildCommand> pendingBuild;
    std::optional<SearchCommand> pendingSearch;
    std::shared_ptr<const InvestigationIndex> currentIndex;
    uint64_t currentIndexGeneration = 0;
    std::shared_ptr<const InvestigationBuildPublication> buildPublication;
    std::shared_ptr<const InvestigationSearchPublication> searchPublication;

    uint64_t requested = 0;
    uint64_t coalesced = 0;
    uint64_t dropped = 0;
    uint64_t stale = 0;
    uint64_t failed = 0;
    uint64_t completed = 0;
};

InvestigationService::InvestigationService(
    InvestigationServiceBackendFactory backendFactory)
    : impl_(std::make_unique<Impl>(std::move(backendFactory))) {}

InvestigationService::~InvestigationService() = default;

uint64_t InvestigationService::beginSession(
    uint64_t generation,
    std::shared_ptr<const InvestigationSnapshot> snapshot,
    InvestigationLimits limits) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->stopping.load(std::memory_order_acquire)) return 0;
    const uint64_t requestId = impl_->nextRequestIdLocked();
    ++impl_->requested;

    if (impl_->pendingBuild) { ++impl_->coalesced; ++impl_->dropped; }
    if (impl_->pendingSearch) { ++impl_->coalesced; ++impl_->dropped; }
    if (impl_->busy) ++impl_->coalesced;
    if (impl_->buildPublication) ++impl_->dropped;
    if (impl_->searchPublication) ++impl_->dropped;

    const uint64_t session = impl_->sessionToken.fetch_add(1,
        std::memory_order_acq_rel) + 1;
    impl_->searchToken.fetch_add(1, std::memory_order_acq_rel);
    impl_->generation = generation;
    impl_->sessionActive = true;
    impl_->pendingSearch.reset();
    impl_->currentIndex.reset();
    impl_->currentIndexGeneration = 0;
    impl_->buildPublication.reset();
    impl_->searchPublication.reset();
    impl_->pendingBuild = Impl::BuildCommand{
        generation, requestId, session, std::move(snapshot), limits };
    impl_->wake.notify_one();
    return requestId;
}

uint64_t InvestigationService::requestSearch(
    uint64_t generation,
    std::string query,
    InvestigationSearchOptions options) {
    // Retain one byte beyond the hard parser limit so the worker reports a
    // structured over-limit query instead of silently accepting a truncation.
    if (query.size() > kInvestigationHardMaxQueryBytes + 1)
        query.resize(kInvestigationHardMaxQueryBytes + 1);

    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->stopping.load(std::memory_order_acquire)) return 0;
    ++impl_->requested;
    if (!impl_->sessionActive || generation != impl_->generation) {
        ++impl_->stale;
        return 0;
    }
    const uint64_t requestId = impl_->nextRequestIdLocked();
    if (impl_->pendingSearch) { ++impl_->coalesced; ++impl_->dropped; }
    if (impl_->active == Impl::ActiveKind::Search) ++impl_->coalesced;
    if (impl_->searchPublication) { ++impl_->dropped; impl_->searchPublication.reset(); }

    const uint64_t search = impl_->searchToken.fetch_add(1,
        std::memory_order_acq_rel) + 1;
    impl_->pendingSearch = Impl::SearchCommand{
        generation, requestId,
        impl_->sessionToken.load(std::memory_order_acquire), search,
        std::move(query), options, {} };
    impl_->wake.notify_one();
    return requestId;
}

std::shared_ptr<const InvestigationBuildPublication>
InvestigationService::currentBuild() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->buildPublication;
}

std::shared_ptr<const InvestigationIndex> InvestigationService::currentIndex() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->currentIndex;
}

std::shared_ptr<const InvestigationSearchPublication>
InvestigationService::latestSearch() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->searchPublication;
}

std::shared_ptr<const InvestigationSearchPublication>
InvestigationService::consumeLatestSearch() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto publication = std::move(impl_->searchPublication);
    impl_->searchPublication.reset();
    return publication;
}

InvestigationServiceStats InvestigationService::stats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    InvestigationServiceStats result;
    result.generation = impl_->generation;
    result.requested = impl_->requested;
    result.coalesced = impl_->coalesced;
    result.dropped = impl_->dropped;
    result.stale = impl_->stale;
    result.failed = impl_->failed;
    result.completed = impl_->completed;
    result.queued = (impl_->pendingBuild ? 1u : 0u) +
                    (impl_->pendingSearch ? 1u : 0u);
    result.busy = impl_->busy;
    result.hasIndex = impl_->currentIndex != nullptr;
    return result;
}

InvestigationServicePending InvestigationService::pending() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    InvestigationServicePending result;
    result.generation = impl_->generation;
    result.buildQueued = impl_->pendingBuild.has_value();
    result.searchQueued = impl_->pendingSearch.has_value();
    result.building = impl_->active == Impl::ActiveKind::Build;
    result.searching = impl_->active == Impl::ActiveKind::Search;
    return result;
}

void InvestigationService::cancel() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->sessionToken.fetch_add(1, std::memory_order_acq_rel);
    impl_->searchToken.fetch_add(1, std::memory_order_acq_rel);
    if (impl_->pendingBuild) ++impl_->dropped;
    if (impl_->pendingSearch) ++impl_->dropped;
    if (impl_->buildPublication) ++impl_->dropped;
    if (impl_->searchPublication) ++impl_->dropped;
    impl_->pendingBuild.reset();
    impl_->pendingSearch.reset();
    impl_->buildPublication.reset();
    impl_->searchPublication.reset();
    impl_->currentIndex.reset();
    impl_->currentIndexGeneration = 0;
    impl_->sessionActive = false;
    impl_->wake.notify_all();
    if (!impl_->busy) impl_->idle.notify_all();
}

void InvestigationService::cancelAndWaitIdle() {
    cancel();
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->idle.wait(lock, [&] {
        return !impl_->busy && !impl_->pendingBuild && !impl_->pendingSearch;
    });
}

} // namespace ds
