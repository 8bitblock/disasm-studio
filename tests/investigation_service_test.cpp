#include "Core/InvestigationService.h"

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>

using namespace ds;

namespace {

struct FakeState {
    std::mutex mutex;
    std::condition_variable wake;
    bool blockedBuildEntered = false;
    bool releaseBlockedBuild = false;
    bool blockedSearchEntered = false;
    bool releaseBlockedSearch = false;
    bool cancellationBuildEntered = false;
    size_t builds = 0;
    size_t searches = 0;
    std::thread::id workerThread;
    bool oneWorker = true;
};

class FakeBackend final : public IInvestigationServiceBackend {
public:
    explicit FakeBackend(std::shared_ptr<FakeState> state) : state_(std::move(state)) {}

    InvestigationBuildResult build(
        const InvestigationSnapshot& snapshot,
        const InvestigationLimits& limits,
        const InvestigationCancel& cancelled) override {
        recordWorker(true);
        const std::string marker = snapshot.functions.empty()
                                 ? std::string{} : snapshot.functions.front().name;
        if (marker == "throw-build") throw std::runtime_error("injected build failure");
        if (marker == "blocked-build") {
            std::unique_lock<std::mutex> lock(state_->mutex);
            state_->blockedBuildEntered = true;
            state_->wake.notify_all();
            state_->wake.wait(lock, [&] { return state_->releaseBlockedBuild; });
        } else if (marker == "cancel-aware-build") {
            std::unique_lock<std::mutex> lock(state_->mutex);
            state_->cancellationBuildEntered = true;
            state_->wake.notify_all();
            while (!cancelled())
                state_->wake.wait_for(lock, std::chrono::milliseconds(1));
        }
        return InvestigationIndex::Build(snapshot, limits, cancelled);
    }

    InvestigationSearchResult search(
        const InvestigationIndex& index,
        std::string_view query,
        const InvestigationSearchOptions& options,
        const InvestigationCancel& cancelled) override {
        recordWorker(false);
        if (query == "throw-search") throw std::runtime_error("injected search failure");
        if (query == "blocked-search") {
            std::unique_lock<std::mutex> lock(state_->mutex);
            state_->blockedSearchEntered = true;
            state_->wake.notify_all();
            state_->wake.wait(lock, [&] { return state_->releaseBlockedSearch; });
        }
        return index.search(query, options, cancelled);
    }

private:
    void recordWorker(bool build) {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->workerThread == std::thread::id{})
            state_->workerThread = std::this_thread::get_id();
        else if (state_->workerThread != std::this_thread::get_id())
            state_->oneWorker = false;
        if (build) ++state_->builds;
        else ++state_->searches;
    }

    std::shared_ptr<FakeState> state_;
};

InvestigationAddress File(uint64_t address) {
    return { InvestigationIdentity::File, true, address };
}

std::shared_ptr<const InvestigationSnapshot> Snapshot(std::string marker,
                                                       uint64_t address = 0) {
    auto snapshot = std::make_shared<InvestigationSnapshot>();
    snapshot->functions.push_back({ File(address), std::move(marker), "void fixture()", "test" });
    return snapshot;
}

template <typename Predicate>
bool WaitUntil(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

bool WaitState(const std::shared_ptr<FakeState>& state, bool FakeState::*field) {
    std::unique_lock<std::mutex> lock(state->mutex);
    return state->wake.wait_for(lock, std::chrono::seconds(4), [&] {
        return state.get()->*field;
    });
}

} // namespace

int main() {
    static_assert(std::is_same_v<decltype(std::declval<const InvestigationService&>().currentIndex()),
                                 std::shared_ptr<const InvestigationIndex>>);
    static_assert(std::is_same_v<decltype(std::declval<const InvestigationService&>().latestSearch()),
                                 std::shared_ptr<const InvestigationSearchPublication>>);

    auto state = std::make_shared<FakeState>();
    const std::thread::id callerThread = std::this_thread::get_id();
    InvestigationService service([state] {
        return std::make_unique<FakeBackend>(state);
    });

    // Hold generation 1 in the backend, then replace its queued searches and
    // entire session. The late completion must be counted stale and never
    // become generation 2's current index.
    const uint64_t firstBuild = service.beginSession(1, Snapshot("blocked-build"));
    assert(firstBuild != 0);
    assert(WaitState(state, &FakeState::blockedBuildEntered));
    assert(service.requestSearch(1, "old-a") != 0);
    assert(service.requestSearch(1, "old-b") != 0);
    const uint64_t secondBuild = service.beginSession(2, Snapshot("zero-entry", 0));
    assert(secondBuild != 0);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->releaseBlockedBuild = true;
    }
    state->wake.notify_all();

    assert(WaitUntil([&] {
        auto publication = service.currentBuild();
        return publication && publication->generation == 2 &&
               publication->requestId == secondBuild && publication->result.complete;
    }));
    assert(service.stats().stale >= 1);
    assert(service.stats().coalesced >= 2);
    assert(service.stats().dropped >= 1);
    assert(service.stats().queued <= 2);

    // A search from an obsolete session is rejected before it can perturb the
    // current worker queue.
    const uint64_t staleBefore = service.stats().stale;
    assert(service.requestSearch(1, "wrong-generation") == 0);
    assert(service.stats().stale == staleBefore + 1);

    // Supersede an in-flight search and its queued replacement. Only the final
    // exact FILE VA-zero query may publish.
    assert(service.requestSearch(2, "blocked-search") != 0);
    assert(WaitState(state, &FakeState::blockedSearchEntered));
    assert(service.requestSearch(2, "zero-entry") != 0);
    const uint64_t zeroRequest = service.requestSearch(2, "file:0x0");
    assert(zeroRequest != 0);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->releaseBlockedSearch = true;
    }
    state->wake.notify_all();
    assert(WaitUntil([&] {
        auto publication = service.latestSearch();
        return publication && publication->requestId == zeroRequest;
    }));

    auto zeroPublication = service.latestSearch();
    assert(zeroPublication && zeroPublication->generation == 2);
    assert(zeroPublication->query == "file:0x0");
    assert(zeroPublication->result.complete && !zeroPublication->result.results.empty());
    const auto& direct = zeroPublication->result.results.front();
    assert(direct.category == InvestigationCategory::Address);
    assert(direct.location.valid && direct.location.value == 0);
    assert(direct.location.identity == InvestigationIdentity::File);
    assert(zeroPublication == service.consumeLatestSearch());
    assert(!service.latestSearch());

    // Exceptions from the injected worker backend are converted to immutable,
    // generation-tagged failure publications and counted.
    const uint64_t failedBefore = service.stats().failed;
    const uint64_t throwingBuild = service.beginSession(3, Snapshot("throw-build"));
    assert(WaitUntil([&] {
        auto publication = service.currentBuild();
        return publication && publication->requestId == throwingBuild;
    }));
    auto buildFailure = service.currentBuild();
    assert(buildFailure && !buildFailure->result.complete);
    assert(buildFailure->result.error.find("injected build failure") != std::string::npos);
    assert(service.stats().failed >= failedBefore + 1);

    const uint64_t healthyBuild = service.beginSession(4, Snapshot("healthy", 0));
    assert(WaitUntil([&] {
        auto publication = service.currentBuild();
        return publication && publication->requestId == healthyBuild &&
               publication->result.complete;
    }));
    const uint64_t throwingSearch = service.requestSearch(4, "throw-search");
    assert(WaitUntil([&] {
        auto publication = service.latestSearch();
        return publication && publication->requestId == throwingSearch;
    }));
    auto searchFailure = service.latestSearch();
    assert(searchFailure && !searchFailure->result.complete);
    assert(searchFailure->result.error.find("injected search failure") != std::string::npos);

    {
        std::lock_guard<std::mutex> lock(state->mutex);
        assert(state->oneWorker);
        assert(state->workerThread != callerThread);
        assert(state->builds >= 4 && state->searches >= 3);
    }

    service.cancelAndWaitIdle();
    assert(!service.stats().busy && service.stats().queued == 0);
    assert(!service.currentIndex() && !service.currentBuild() && !service.latestSearch());

    // Cooperative cancellation and the destructor both wait for the one worker
    // to leave its operation boundary; neither detaches a thread touching state.
    auto cancelState = std::make_shared<FakeState>();
    {
        InvestigationService cancelling([cancelState] {
            return std::make_unique<FakeBackend>(cancelState);
        });
        cancelling.beginSession(10, Snapshot("cancel-aware-build"));
        assert(WaitState(cancelState, &FakeState::cancellationBuildEntered));
        cancelling.cancelAndWaitIdle();
        assert(!cancelling.pending().building && !cancelling.pending().buildQueued);
    }
    auto teardownState = std::make_shared<FakeState>();
    {
        InvestigationService teardown([teardownState] {
            return std::make_unique<FakeBackend>(teardownState);
        });
        teardown.beginSession(11, Snapshot("cancel-aware-build"));
        assert(WaitState(teardownState, &FakeState::cancellationBuildEntered));
        // Scope exit sets the stop token and joins the cooperative backend.
    }
    {
        std::lock_guard<std::mutex> lock(teardownState->mutex);
        assert(teardownState->builds == 1);
    }

    // Backend construction happens on the worker.  A factory exception is a
    // per-session build failure, not an uncaught thread exception or startup
    // hang, and remains observable through the normal publication channel.
    {
        InvestigationService factoryFailure([]() -> std::unique_ptr<IInvestigationServiceBackend> {
            throw std::runtime_error("injected backend-factory failure");
        });
        const uint64_t request = factoryFailure.beginSession(12, Snapshot("factory-failure"));
        assert(request != 0);
        assert(WaitUntil([&] {
            const auto publication = factoryFailure.currentBuild();
            return publication && publication->requestId == request;
        }));
        const auto publication = factoryFailure.currentBuild();
        assert(publication && !publication->result.complete);
        assert(publication->result.error.find("injected backend-factory failure") != std::string::npos);
        factoryFailure.cancelAndWaitIdle();
    }

    return 0;
}
