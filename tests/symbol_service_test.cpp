#include "Core/SymbolService.h"

#include <windows.h>

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

using namespace ds;

namespace {

struct FakeState {
    std::mutex mutex;
    std::condition_variable wake;
    bool release = false;
    bool blockedEntered = false;
    uint64_t blockedAddress = 0;
    size_t binds = 0;
    size_t resolves = 0;
    bool bindSucceeds = true;
    uint64_t failDetailedAddress = 0;
    uint64_t hostileAddress = 0;
    bool blockModule = false;
    bool moduleEntered = false;
    bool releaseModule = false;
    size_t modulesVisited = 0;
};

class FakeBackend final : public ISymbolServiceBackend {
public:
    explicit FakeBackend(std::shared_ptr<FakeState> state) : state_(std::move(state)) {}
    void configure(const SymbolResolverOptions&) override {}
    void reset() override {}
    bool useLive(void*) override {
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->bindSucceeds;
    }
    bool useBinary(const std::string&, uint64_t) override {
        std::lock_guard<std::mutex> lock(state_->mutex);
        ++state_->binds;
        return state_->bindSucceeds;
    }
    void ensureModule(const SymbolModuleSpec&) override {
        std::unique_lock<std::mutex> lock(state_->mutex);
        ++state_->modulesVisited;
        if (state_->blockModule && state_->modulesVisited == 1) {
            state_->moduleEntered = true;
            state_->wake.notify_all();
            state_->wake.wait(lock, [&] { return state_->releaseModule; });
        }
    }
    bool resolve(uint64_t address, std::string& name, uint64_t& displacement) override {
        if (!beginResolve(address)) return false;
        name = "sym_" + std::to_string(address);
        displacement = 0;
        return true;
    }
    bool resolveDetailed(uint64_t address, SymbolRecord& result) override {
        if (!beginResolve(address)) return false;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (address == state_->failDetailedAddress) return false;
            if (address == state_->hostileAddress) {
                result.found = true;
                result.name.assign(2 * 1024 * 1024, 'N');
                result.source.file.assign(2 * 1024 * 1024, 'S');
                result.prototype.assign(2 * 1024 * 1024, 'T');
                result.locals.resize(1000);
                for (auto& local : result.locals) {
                    local.name.assign(4096, 'n');
                    local.type.assign(8192, 't');
                    local.location.assign(1024, 'l');
                }
                return true;
            }
        }
        result.queryAddress = address;
        result.found = true;
        result.symbolAddress = address;
        result.name = "sym_" + std::to_string(address);
        result.source.file = "fixture.cpp";
        result.source.line = 42;
        result.prototype = "int32_t (uint64_t)";
        result.locals.push_back({"arg", "uint64_t", "register 1", true});
        return true;
    }
    bool addressOf(const std::string& name, uint64_t& address) override {
        if (name == "zero") { address = 0; return true; }
        if (name != "known") return false;
        address = 0x4444;
        return true;
    }

private:
    bool beginResolve(uint64_t address) {
        {
            std::unique_lock<std::mutex> lock(state_->mutex);
            ++state_->resolves;
            if (address == state_->blockedAddress) {
                state_->blockedEntered = true;
                state_->wake.notify_all();
                state_->wake.wait(lock, [&] { return state_->release; });
            }
        }
        if (address & 1) return false;
        return true;
    }
    std::shared_ptr<FakeState> state_;
};

template <typename Predicate>
bool waitUntil(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

} // namespace

int main() {
    SymbolResolverOptions offline;
    offline.cacheDirectory = "C:\\symbols";
    offline.serverUrl = "https://symbols.invalid";
    const std::string offlinePath = BuildSymbolSearchPath(offline, "C:\\bin\\fixture.exe");
    assert(offlinePath.find("srv*") == std::string::npos);
    assert(offlinePath.find(offline.serverUrl) == std::string::npos);
    offline.networkEnabled = true;
    const std::string onlinePath = BuildSymbolSearchPath(offline, "C:\\bin\\fixture.exe");
    assert(onlinePath.find("srv*C:\\symbols*https://symbols.invalid") != std::string::npos);
    offline.networkEnabled = false;
    offline.cacheDirectory = "srv*C:\\symbols*https://evil.invalid";
    const std::string injectedSrv = BuildSymbolSearchPath(offline, "C:\\bin\\fixture.exe");
    assert(injectedSrv.find("srv*") == std::string::npos);
    assert(injectedSrv.find("evil.invalid") == std::string::npos);
    offline.cacheDirectory = "C:\\safe;srv*C:\\symbols*https://evil.invalid";
    assert(BuildSymbolSearchPath(offline, "C:\\bin\\fixture.exe").find("srv*") ==
           std::string::npos);
    offline.cacheDirectory = "\\\\server\\symbols";
    assert(BuildSymbolSearchPath(offline, "C:\\bin\\fixture.exe").find("server") ==
           std::string::npos);
    offline.cacheDirectory = std::string("C:\\safe\0srv*evil", 17);
    assert(BuildSymbolSearchPath(offline, "C:\\bin\\fixture.exe").find("evil") ==
           std::string::npos);

    auto shared = std::make_shared<FakeState>();
    shared->blockedAddress = 0x1000;
    SymbolServiceLimits limits;
    limits.maxPending = 4;
    limits.maxAddressCache = 2;
    limits.maxNameCache = 2;
    SymbolService service(limits, [shared] { return std::make_unique<FakeBackend>(shared); });

    assert(!service.options().networkEnabled); // network fetching is opt-in
    service.useBinary("first.exe", 0x1000);

    SymbolRecord record;
    assert(service.lookupAddress(0x1000, record) == SymbolLookupState::Pending);
    assert(service.lookupAddress(0x1000, record) == SymbolLookupState::Pending);
    assert(service.stats().coalesced >= 1);
    {
        std::lock_guard<std::mutex> lock(shared->mutex);
        shared->release = true;
    }
    shared->wake.notify_all();
    assert(waitUntil([&] { return service.stats().completed >= 1; }));
    assert(service.lookupAddress(0x1000, record) == SymbolLookupState::Found);
    assert(record.name == "sym_4096");
    assert(record.source.line == 0 && record.prototype.empty() && record.locals.empty());
    // Rich records are an explicit upgrade; ordinary listing lookups do not pay
    // for source/type/local enumeration.
    assert(service.lookupAddress(0x1000, record, true) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return service.stats().completed >= 2; }));
    assert(service.lookupAddress(0x1000, record, true) == SymbolLookupState::Found);
    assert(record.source.line == 42);
    assert(!record.prototype.empty() && record.locals.size() == 1);
    assert(service.lookupAddress(0x1000, record) == SymbolLookupState::Found);
    assert(record.source.line == 0 && record.prototype.empty() && record.locals.empty());

    assert(service.lookupAddress(0x1001, record) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return service.stats().completed >= 3; }));
    assert(service.lookupAddress(0x1001, record) == SymbolLookupState::NotFound);

    uint64_t address = 0;
    assert(service.lookupName("known", address) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return service.stats().completed >= 4; }));
    assert(service.lookupName("KNOWN", address) == SymbolLookupState::Found);
    assert(address == 0x4444);
    assert(service.lookupName("zero", address) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return service.stats().completed >= 5; }));
    assert(service.lookupName("ZERO", address) == SymbolLookupState::Found);
    assert(address == 0); // a successful reverse lookup may legitimately resolve VA zero

    // The cache is bounded. Inserting a third address evicts the oldest of two.
    assert(service.lookupAddress(0x1002, record) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return service.stats().completed >= 6; }));
    assert(service.stats().cachedAddresses == 2);
    assert(service.stats().retainedBytes <= limits.maxRetainedBytes);
    assert(service.lookupAddress(0x1000, record) == SymbolLookupState::Pending);

    // A target change invalidates queued/cache state and makes an old completion
    // stale rather than publishing it into the new binary's namespace.
    {
        std::lock_guard<std::mutex> lock(shared->mutex);
        shared->blockedAddress = 0x2000;
        shared->release = false;
        shared->blockedEntered = false;
    }
    service.useBinary("second.exe", 0x2000);
    assert(service.lookupAddress(0x2000, record) == SymbolLookupState::Pending);
    assert(waitUntil([&] {
        std::lock_guard<std::mutex> lock(shared->mutex);
        return shared->blockedEntered;
    }));
    service.useBinary("third.exe", 0x3000);
    {
        std::lock_guard<std::mutex> lock(shared->mutex);
        shared->release = true;
    }
    shared->wake.notify_all();
    assert(waitUntil([&] { return service.stats().staleResults >= 1; }));

    service.cancelAndWaitIdle();
    assert(!service.stats().busy && service.stats().queued == 0);

    // A failed rich upgrade must retain a proven basic name, while ordinary
    // consumers never copy rich vectors back onto the render thread.
    auto upgradeState = std::make_shared<FakeState>();
    upgradeState->failDetailedAddress = 0x6000;
    SymbolService upgradeService(limits, [upgradeState] {
        return std::make_unique<FakeBackend>(upgradeState);
    });
    upgradeService.useBinary("upgrade.exe", 0x6000);
    assert(upgradeService.lookupAddress(0x6000, record) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return upgradeService.stats().completed >= 1; }));
    assert(upgradeService.lookupAddress(0x6000, record) == SymbolLookupState::Found);
    assert(upgradeService.lookupAddress(0x6000, record, true) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return upgradeService.stats().completed >= 2; }));
    assert(upgradeService.lookupAddress(0x6000, record, true) == SymbolLookupState::Found);
    assert(record.name == "sym_24576");
    assert(upgradeService.lookupAddress(0x6000, record) == SymbolLookupState::Found);
    assert(record.locals.empty() && record.prototype.empty() && record.source.file.empty());

    // The service independently bounds hostile backend output and lookup input.
    auto hostileState = std::make_shared<FakeState>();
    hostileState->hostileAddress = 0x7000;
    SymbolServiceLimits hostileLimits = limits;
    hostileLimits.maxRetainedBytes = 1024 * 1024;
    SymbolService hostileService(hostileLimits, [hostileState] {
        return std::make_unique<FakeBackend>(hostileState);
    });
    hostileService.useBinary("hostile.exe", 0x7000);
    assert(hostileService.lookupAddress(0x7000, record, true) == SymbolLookupState::Pending);
    assert(waitUntil([&] { return hostileService.stats().completed >= 1; }));
    assert(hostileService.lookupAddress(0x7000, record, true) == SymbolLookupState::Found);
    assert(record.name.size() <= 4096 && record.source.file.size() <= 4096);
    assert(record.prototype.size() <= 4096 && record.locals.size() <= 256);
    for (const auto& local : record.locals) {
        assert(local.name.size() <= 1024 && local.type.size() <= 4096);
        assert(local.location.size() <= 256);
    }
    assert(hostileService.stats().retainedBytes <= hostileLimits.maxRetainedBytes);
    const uint64_t beforeOverlong = hostileService.stats().requested;
    std::string overlongName(4097, 'x');
    assert(hostileService.lookupName(overlongName, address) == SymbolLookupState::Unavailable);
    assert(hostileService.stats().requested == beforeOverlong);

    // Count and byte budgets both constrain queued/in-flight work. Large but
    // individually valid names cannot consume memory up to the count cap.
    auto queueState = std::make_shared<FakeState>();
    queueState->blockedAddress = 0xA000;
    SymbolServiceLimits queueLimits;
    queueLimits.maxPending = 64;
    queueLimits.maxQueuedBytes = 64 * 1024;
    SymbolService queueService(queueLimits, [queueState] {
        return std::make_unique<FakeBackend>(queueState);
    });
    queueService.useBinary("queue.exe", 0xA000);
    assert(queueService.lookupAddress(0xA000, record) == SymbolLookupState::Pending);
    assert(waitUntil([&] {
        std::lock_guard<std::mutex> lock(queueState->mutex);
        return queueState->blockedEntered;
    }));
    size_t queueDrops = 0;
    for (size_t i = 0; i < 32; ++i) {
        std::string candidate(4080, static_cast<char>('a' + (i % 26)));
        candidate += std::to_string(i);
        if (queueService.lookupName(candidate, address) == SymbolLookupState::Unavailable)
            ++queueDrops;
    }
    assert(queueDrops > 0 && queueService.stats().dropped >= queueDrops);
    assert(queueService.stats().pendingBytes <= queueLimits.maxQueuedBytes);
    {
        std::lock_guard<std::mutex> lock(queueState->mutex);
        queueState->release = true;
    }
    queueState->wake.notify_all();
    queueService.cancelAndWaitIdle();
    assert(queueService.stats().pendingBytes == 0);

    // A generation change interrupts a long live-module bind between bounded
    // module calls instead of walking the rest of a detached process's list.
    auto moduleState = std::make_shared<FakeState>();
    moduleState->blockModule = true;
    SymbolService moduleService(limits, [moduleState] {
        return std::make_unique<FakeBackend>(moduleState);
    });
    std::vector<SymbolModuleSpec> modules(64);
    for (size_t i = 0; i < modules.size(); ++i)
        modules[i] = {0x10000 + i * 0x1000, 0x1000, "module.dll"};
    std::string bindError;
    assert(moduleService.useLive(GetCurrentProcess(), std::move(modules), &bindError));
    assert(waitUntil([&] {
        std::lock_guard<std::mutex> lock(moduleState->mutex);
        return moduleState->moduleEntered;
    }));
    moduleService.useBinary("replacement.exe", 0x8000);
    {
        std::lock_guard<std::mutex> lock(moduleState->mutex);
        moduleState->releaseModule = true;
    }
    moduleState->wake.notify_all();
    assert(waitUntil([&] {
        std::lock_guard<std::mutex> lock(moduleState->mutex);
        return moduleState->binds >= 1;
    }));
    {
        std::lock_guard<std::mutex> lock(moduleState->mutex);
        assert(moduleState->modulesVisited == 1);
    }

    // Backend bind failures are visible and obsolete failures clear on a new
    // generation rather than lingering permanently in the UI.
    auto failureState = std::make_shared<FakeState>();
    failureState->bindSucceeds = false;
    SymbolService failureService(limits, [failureState] {
        return std::make_unique<FakeBackend>(failureState);
    });
    failureService.useBinary("failure.exe", 0x9000);
    assert(waitUntil([&] { return failureService.stats().failures >= 1; }));
    assert(!failureService.stats().lastError.empty());
    failureService.reset();
    assert(failureService.stats().lastError.empty());

    // Worker-side backend construction is guarded as well: a throwing factory
    // becomes the service's existing failure state after the first bind request.
    SymbolService factoryFailureService(limits,
        []() -> std::unique_ptr<ISymbolServiceBackend> {
            throw std::runtime_error("injected symbol-backend factory failure");
        });
    factoryFailureService.useBinary("factory-failure.exe", 0xA000);
    assert(waitUntil([&] { return factoryFailureService.stats().failures >= 1; }));
    assert(factoryFailureService.stats().lastError.find("symbol backend could not be created") !=
           std::string::npos);
    factoryFailureService.cancelAndWaitIdle();
    return 0;
}
