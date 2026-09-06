#include "SymbolService.h"

#include <windows.h>

#include <algorithm>
#include <condition_variable>
#include <cctype>
#include <cstring>
#include <deque>
#include <filesystem>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ds {

namespace {

constexpr size_t kMaxSymbolText = 4096;
constexpr size_t kMaxSymbolPath = 32767;
constexpr size_t kMaxServerText = 4096;
constexpr size_t kMaxLocalName = 1024;
constexpr size_t kMaxLocalLocation = 256;
constexpr size_t kMaxLocals = 256;
constexpr size_t kMaxSessionModuleBytes = 16ull * 1024ull * 1024ull;

class ResolverBackend final : public ISymbolServiceBackend {
public:
    void configure(const SymbolResolverOptions& options) override { resolver_.configure(options); }
    void reset() override { resolver_.reset(); }
    bool useLive(void* processHandle) override { return resolver_.useLive(processHandle); }
    bool useBinary(const std::string& path, uint64_t imageBase) override {
        return resolver_.useBinary(path, imageBase);
    }
    void ensureModule(const SymbolModuleSpec& module) override {
        resolver_.ensureModule(module.base, module.size, module.imagePath);
    }
    bool resolve(uint64_t address, std::string& name, uint64_t& displacement) override {
        return resolver_.resolve(address, name, displacement);
    }
    bool resolveDetailed(uint64_t address, SymbolRecord& result) override {
        return resolver_.resolveDetailed(address, result);
    }
    bool addressOf(const std::string& name, uint64_t& address) override {
        return resolver_.addressOf(name, address);
    }

private:
    SymbolResolver resolver_;
};

bool equalOptions(const SymbolResolverOptions& a, const SymbolResolverOptions& b) {
    return a.networkEnabled == b.networkEnabled &&
           a.cacheDirectory == b.cacheDirectory &&
           a.serverUrl == b.serverUrl &&
           a.collectSourceLines == b.collectSourceLines &&
           a.collectTypes == b.collectTypes &&
           a.collectLocals == b.collectLocals;
}

std::string lowerName(std::string value) {
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

void compactTo(std::string& value, size_t limit) {
    // Copy into fresh bounded storage rather than resize(): resize preserves a
    // hostile backend's multi-megabyte capacity and defeats the byte budget.
    std::string compact(value.data(), (std::min)(value.size(), limit));
    value.swap(compact);
}

bool containsSymbolPathSyntax(const std::string& value) {
    return value.find_first_of(";*\r\n") != std::string::npos ||
           value.find('\0') != std::string::npos;
}

bool isRemotePathText(const std::string& value) {
    return value.starts_with("\\\\") || value.starts_with("//") ||
           value.find("://") != std::string::npos;
}

void sanitizeRecord(SymbolRecord& value) {
    compactTo(value.name, kMaxSymbolText);
    compactTo(value.source.file, kMaxSymbolText);
    compactTo(value.prototype, kMaxSymbolText);
    std::vector<SymbolLocal> compactLocals;
    const size_t count = (std::min)(value.locals.size(), kMaxLocals);
    compactLocals.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        auto& local = value.locals[i];
        compactTo(local.name, kMaxLocalName);
        compactTo(local.type, kMaxSymbolText);
        compactTo(local.location, kMaxLocalLocation);
        compactLocals.push_back(std::move(local));
    }
    value.locals.swap(compactLocals);
}

size_t recordCost(const SymbolRecord& value) {
    size_t cost = sizeof(SymbolRecord) + value.name.size() + value.source.file.size() +
                  value.prototype.size();
    for (const auto& local : value.locals)
        cost += sizeof(SymbolLocal) + local.name.size() + local.type.size() +
                local.location.size();
    return cost;
}

void copyBasicRecord(const SymbolRecord& source, SymbolRecord& destination) {
    destination = {};
    destination.found = source.found;
    destination.queryAddress = source.queryAddress;
    destination.symbolAddress = source.symbolAddress;
    destination.displacement = source.displacement;
    destination.name = source.name;
}

uint64_t nextGeneration(uint64_t value) {
    ++value;
    return value ? value : 1;
}

} // namespace

struct SymbolService::Impl {
    enum class SessionKind : uint8_t { None, Binary, Live };
    struct Session {
        uint64_t generation = 0;
        SessionKind kind = SessionKind::None;
        SymbolResolverOptions options;
        std::string path;
        uint64_t imageBase = 0;
        std::shared_ptr<void> liveHandle;
        std::vector<SymbolModuleSpec> modules;
    };
    enum class RequestKind : uint8_t { Bind, Reset, Address, Name };
    struct Request {
        RequestKind kind = RequestKind::Reset;
        uint64_t generation = 0;
        std::shared_ptr<const Session> session;
        uint64_t address = 0;
        bool detailed = false;
        std::string name;
        std::string nameKey;
        size_t pendingCost = 0;
    };
    struct NameResult {
        bool found = false;
        uint64_t address = 0;
        size_t cost = 0;
    };
    struct AddressResult {
        SymbolRecord record;
        size_t cost = 0;
        bool detailed = false;
    };

    explicit Impl(SymbolServiceLimits requested,
                  SymbolServiceBackendFactory requestedFactory)
        : limits(requested), factory(std::move(requestedFactory)) {
        limits.maxPending = (std::max<size_t>)(1, (std::min<size_t>)(limits.maxPending, 65536));
        limits.maxAddressCache = (std::max<size_t>)(1, (std::min<size_t>)(limits.maxAddressCache, 262144));
        limits.maxNameCache = (std::max<size_t>)(1, (std::min<size_t>)(limits.maxNameCache, 65536));
        limits.maxModules = (std::max<size_t>)(1, (std::min<size_t>)(limits.maxModules, 16384));
        limits.maxRetainedBytes = (std::max<size_t>)(1024 * 1024,
            (std::min<size_t>)(limits.maxRetainedBytes, 1024ull * 1024ull * 1024ull));
        limits.maxQueuedBytes = (std::max<size_t>)(64 * 1024,
            (std::min<size_t>)(limits.maxQueuedBytes, 256ull * 1024ull * 1024ull));
        if (!factory) factory = [] { return std::make_unique<ResolverBackend>(); };
        worker = std::thread([this] { threadEntry(); });
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping = true;
            queue.clear();
        }
        wake.notify_all();
        if (worker.joinable()) worker.join();
    }

    void clearLookupStateLocked() {
        queue.clear();
        pendingBasicAddresses.clear();
        pendingDetailedAddresses.clear();
        pendingNames.clear();
        addresses.clear();
        addressOrder.clear();
        names.clear();
        nameOrder.clear();
        addressBytes = 0;
        nameBytes = 0;
        pendingBytes = 0;
    }

    void queueBindingLocked(const std::shared_ptr<const Session>& value) {
        Request request;
        request.kind = value ? RequestKind::Bind : RequestKind::Reset;
        request.generation = generation;
        request.session = value;
        queue.push_back(std::move(request));
        wake.notify_one();
    }

    void replaceSessionLocked(std::shared_ptr<Session> value) {
        generation = nextGeneration(generation);
        if (value) value->generation = generation;
        session = std::move(value);
        clearLookupStateLocked();
        lastError.clear();
        failedGeneration = 0;
        queueBindingLocked(session);
        ++revision;
    }

    bool generationIsCurrent(uint64_t value) const {
        std::lock_guard<std::mutex> lock(mutex);
        return !stopping && generation == value;
    }

    bool activate(ISymbolServiceBackend& backend,
                  const std::shared_ptr<const Session>& value,
                  uint64_t& activeGeneration,
                  std::shared_ptr<const Session>& activeSession) {
        if (!value || !generationIsCurrent(value->generation)) return false;
        backend.reset();
        activeGeneration = 0;
        activeSession.reset();
        if (!generationIsCurrent(value->generation)) return false;
        if (value->kind == SessionKind::None) return false;

        if (value->options.networkEnabled && !value->options.cacheDirectory.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(value->options.cacheDirectory, ec);
            if (ec) throw std::runtime_error("could not create symbol cache: " + ec.message());
        }
        backend.configure(value->options);
        if (!generationIsCurrent(value->generation)) return false;
        if (value->kind == SessionKind::Binary) {
            if (!backend.useBinary(value->path, value->imageBase))
                throw std::runtime_error("DbgHelp could not bind the binary symbol session");
            if (!generationIsCurrent(value->generation)) return false;
        } else {
            if (!backend.useLive(value->liveHandle.get()))
                throw std::runtime_error("DbgHelp could not bind the live symbol session");
            if (!generationIsCurrent(value->generation)) return false;
            for (const auto& module : value->modules) {
                backend.ensureModule(module);
                if (!generationIsCurrent(value->generation)) return false;
            }
        }
        activeGeneration = value->generation;
        activeSession = value;
        return true;
    }

    void publishCancellation(const Request& request) {
        std::lock_guard<std::mutex> lock(mutex);
        if (request.generation != generation) {
            ++staleResults;
            return;
        }
        retirePendingLocked(request);
    }

    void retirePendingLocked(const Request& request) {
        bool erased = false;
        if (request.kind == RequestKind::Address) {
            erased = request.detailed ? pendingDetailedAddresses.erase(request.address) != 0
                                      : pendingBasicAddresses.erase(request.address) != 0;
        } else if (request.kind == RequestKind::Name) {
            erased = pendingNames.erase(request.nameKey) != 0;
        }
        if (erased) pendingBytes -= (std::min)(pendingBytes, request.pendingCost);
    }

    void publishFailure(const Request& request, const char* error,
                        bool bindingFailure = false) {
        std::lock_guard<std::mutex> lock(mutex);
        if (request.generation == generation) {
            retirePendingLocked(request);
            lastError.assign(error ? error : "symbol worker failure",
                             error ? strnlen_s(error, kMaxSymbolText) : 21);
            if (bindingFailure) failedGeneration = generation;
            ++failures;
            ++revision;
        } else {
            ++staleResults;
        }
    }

    void publishAddress(const Request& request, SymbolRecord result) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (request.generation != generation) {
                ++staleResults;
                return;
            }
        }
        result.queryAddress = request.address;
        // Potentially large hostile-backend cleanup stays off the mutex used by
        // render-thread lookups and stats snapshots.
        sanitizeRecord(result);
        size_t cost = recordCost(result);
        while (cost > limits.maxRetainedBytes && !result.locals.empty()) {
            const auto& local = result.locals.back();
            const size_t localCost = sizeof(SymbolLocal) + local.name.size() +
                                     local.type.size() + local.location.size();
            cost -= (std::min)(cost, localCost);
            result.locals.pop_back();
        }

        std::lock_guard<std::mutex> lock(mutex);
        if (request.generation != generation) {
            ++staleResults;
            return;
        }
        retirePendingLocked(request);
        // A rich lookup is an upgrade of a possibly cached basic name. If the
        // optional PDB pass fails transiently, retain that already-proven name
        // and mark the upgrade complete instead of regressing the listing to a
        // negative result or retrying on every rendered frame.
        auto existing = addresses.find(request.address);
        if (request.detailed && !result.found && existing != addresses.end() &&
            existing->second.record.found) {
            SymbolRecord basic;
            copyBasicRecord(existing->second.record, basic);
            result = std::move(basic);
            cost = recordCost(result);
        }
        if (existing != addresses.end()) {
            addressBytes -= (std::min)(addressBytes, existing->second.cost);
            addresses.erase(existing);
            auto order = std::find(addressOrder.begin(), addressOrder.end(), request.address);
            if (order != addressOrder.end()) addressOrder.erase(order);
        }
        while ((addresses.size() >= limits.maxAddressCache ||
                addressBytes + nameBytes + cost > limits.maxRetainedBytes) &&
               !addressOrder.empty()) {
            const uint64_t victim = addressOrder.front();
            addressOrder.pop_front();
            auto found = addresses.find(victim);
            if (found != addresses.end()) {
                addressBytes -= (std::min)(addressBytes, found->second.cost);
                addresses.erase(found);
            }
        }
        while (addressBytes + nameBytes + cost > limits.maxRetainedBytes && !nameOrder.empty()) {
            const std::string victim = std::move(nameOrder.front());
            nameOrder.pop_front();
            auto found = names.find(victim);
            if (found != names.end()) {
                nameBytes -= (std::min)(nameBytes, found->second.cost);
                names.erase(found);
            }
        }
        addressOrder.push_back(request.address);
        addresses[request.address] = AddressResult{std::move(result), cost, request.detailed};
        addressBytes += cost;
        lastError.clear();
        ++completed;
        ++revision;
    }

    void publishName(const Request& request, bool found, uint64_t address) {
        std::lock_guard<std::mutex> lock(mutex);
        if (request.generation != generation) {
            ++staleResults;
            return;
        }
        retirePendingLocked(request);
        const size_t cost = sizeof(NameResult) + request.nameKey.size() * 2;
        auto existing = names.find(request.nameKey);
        if (existing != names.end()) {
            nameBytes -= (std::min)(nameBytes, existing->second.cost);
            names.erase(existing);
            auto order = std::find(nameOrder.begin(), nameOrder.end(), request.nameKey);
            if (order != nameOrder.end()) nameOrder.erase(order);
        }
        while ((names.size() >= limits.maxNameCache ||
                addressBytes + nameBytes + cost > limits.maxRetainedBytes) &&
               !nameOrder.empty()) {
            const std::string victim = std::move(nameOrder.front());
            nameOrder.pop_front();
            auto entry = names.find(victim);
            if (entry != names.end()) {
                nameBytes -= (std::min)(nameBytes, entry->second.cost);
                names.erase(entry);
            }
        }
        while (addressBytes + nameBytes + cost > limits.maxRetainedBytes && !addressOrder.empty()) {
            const uint64_t victim = addressOrder.front();
            addressOrder.pop_front();
            auto entry = addresses.find(victim);
            if (entry != addresses.end()) {
                addressBytes -= (std::min)(addressBytes, entry->second.cost);
                addresses.erase(entry);
            }
        }
        nameOrder.push_back(request.nameKey);
        names[request.nameKey] = NameResult{found, address, cost};
        nameBytes += cost;
        lastError.clear();
        ++completed;
        ++revision;
    }

    void publishWorkerFailure() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex);
            stopping = true;
            busy = false;
            queue.clear();
            pendingBasicAddresses.clear();
            pendingDetailedAddresses.clear();
            pendingNames.clear();
            pendingBytes = 0;
            lastError = "The symbol worker stopped after an unexpected internal exception.";
            ++failures;
            ++revision;
        } catch (...) {
            // State is updated before the diagnostic string allocation; if even
            // locking failed, avoid unsynchronized writes from the dying worker.
        }
        idle.notify_all();
        wake.notify_all();
    }

    void threadEntry() noexcept {
        try {
            run();
        } catch (...) {
            publishWorkerFailure();
        }
    }

    void run() {
        std::unique_ptr<ISymbolServiceBackend> backend;
        try {
            backend = factory();
        } catch (...) {
        }
        uint64_t activeGeneration = 0;
        std::shared_ptr<const Session> activeSession;

        for (;;) {
            Request request;
            {
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait(lock, [&] { return stopping || !queue.empty(); });
                if (stopping && queue.empty()) break;
                request = std::move(queue.front());
                queue.pop_front();
                busy = true;
            }

            try {
                bool bindingAttempt = false;
                if (!backend) throw std::runtime_error("symbol backend could not be created");
                if (request.kind == RequestKind::Reset) {
                    backend->reset();
                    activeGeneration = 0;
                    activeSession.reset();
                } else {
                    if (!request.session) throw std::runtime_error("symbol request has no session");
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        if (failedGeneration == request.session->generation) {
                            throw std::runtime_error(lastError.empty()
                                ? "symbol session binding failed" : lastError);
                        }
                    }
                    bindingAttempt = activeGeneration != request.session->generation;
                    const bool activated = generationIsCurrent(request.session->generation) &&
                        (!bindingAttempt || activate(*backend, request.session,
                                                    activeGeneration, activeSession));
                    if (!activated) {
                        publishCancellation(request);
                    } else if (request.kind == RequestKind::Address) {
                        SymbolRecord record;
                        record.queryAddress = request.address;
                        if (request.detailed) {
                            record.found = backend->resolveDetailed(request.address, record);
                        } else {
                            uint64_t displacement = 0;
                            record.found = backend->resolve(request.address, record.name,
                                                            displacement);
                            record.displacement = displacement;
                            record.symbolAddress = request.address >= displacement
                                                 ? request.address - displacement : 0;
                        }
                        publishAddress(request, std::move(record));
                    } else if (request.kind == RequestKind::Name) {
                        uint64_t address = 0;
                        const bool found = backend->addressOf(request.name, address);
                        publishName(request, found, address);
                    }
                }
            } catch (const std::exception& error) {
                const bool wasBinding = request.kind == RequestKind::Bind;
                publishFailure(request, error.what(), wasBinding);
            } catch (...) {
                publishFailure(request, "unknown symbol-worker failure",
                               request.kind == RequestKind::Bind);
            }

            {
                std::lock_guard<std::mutex> lock(mutex);
                busy = false;
            }
            idle.notify_all();
        }
        if (backend) {
            try { backend->reset(); }
            catch (...) { /* destructors must not terminate on an injected backend */ }
        }
    }

    SymbolServiceLimits limits;
    SymbolServiceBackendFactory factory;
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::condition_variable idle;
    std::thread worker;
    bool stopping = false;
    bool busy = false;

    SymbolResolverOptions options;
    uint64_t generation = 0;
    uint64_t failedGeneration = 0;
    std::shared_ptr<Session> session;
    std::deque<Request> queue;
    std::unordered_set<uint64_t> pendingBasicAddresses;
    std::unordered_set<uint64_t> pendingDetailedAddresses;
    std::unordered_set<std::string> pendingNames;
    std::unordered_map<uint64_t, AddressResult> addresses;
    std::deque<uint64_t> addressOrder;
    std::unordered_map<std::string, NameResult> names;
    std::deque<std::string> nameOrder;
    size_t addressBytes = 0;
    size_t nameBytes = 0;
    size_t pendingBytes = 0;

    uint64_t requested = 0;
    uint64_t completed = 0;
    uint64_t cacheHits = 0;
    uint64_t coalesced = 0;
    uint64_t dropped = 0;
    uint64_t staleResults = 0;
    uint64_t failures = 0;
    uint64_t revision = 0;
    std::string lastError;
};

SymbolService::SymbolService(SymbolServiceLimits limits,
                             SymbolServiceBackendFactory backendFactory)
    : impl_(std::make_unique<Impl>(limits, std::move(backendFactory))) {}

SymbolService::~SymbolService() = default;

void SymbolService::configure(SymbolResolverOptions options) {
    if (options.cacheDirectory.size() > kMaxSymbolPath ||
        containsSymbolPathSyntax(options.cacheDirectory) ||
        isRemotePathText(options.cacheDirectory))
        std::string().swap(options.cacheDirectory);
    else
        compactTo(options.cacheDirectory, kMaxSymbolPath);
    if (options.serverUrl.size() > kMaxServerText ||
        containsSymbolPathSyntax(options.serverUrl))
        std::string().swap(options.serverUrl);
    else
        compactTo(options.serverUrl, kMaxServerText);
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->stopping) return;
    if (equalOptions(impl_->options, options)) return;
    impl_->options = std::move(options);
    if (impl_->session) {
        auto replacement = std::make_shared<Impl::Session>(*impl_->session);
        replacement->options = impl_->options;
        impl_->replaceSessionLocked(std::move(replacement));
    } else {
        impl_->replaceSessionLocked(nullptr);
    }
}

SymbolResolverOptions SymbolService::options() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->options;
}

void SymbolService::useBinary(std::string path, uint64_t imageBase) {
    if (path.size() > kMaxSymbolPath || path.find('\0') != std::string::npos) {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->stopping) return;
        impl_->replaceSessionLocked(nullptr);
        impl_->lastError = "binary path exceeds the symbol-service limit";
        return;
    }
    compactTo(path, kMaxSymbolPath);
    auto replacement = std::make_shared<Impl::Session>();
    replacement->kind = Impl::SessionKind::Binary;
    replacement->path = std::move(path);
    replacement->imageBase = imageBase;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->stopping) return;
        replacement->options = impl_->options;
        impl_->replaceSessionLocked(std::move(replacement));
    }
}

bool SymbolService::useLive(void* processHandle, std::vector<SymbolModuleSpec> modules,
                            std::string* error) {
    if (error) error->clear();
    if (!processHandle) {
        if (error) *error = "the debugger process handle is not available";
        return false;
    }
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), static_cast<HANDLE>(processHandle),
                         GetCurrentProcess(), &duplicate, 0, FALSE,
                         DUPLICATE_SAME_ACCESS)) {
        if (error) *error = "the debugger process handle could not be duplicated";
        return false;
    }

    // Establish RAII immediately: allocation of the Session or its module
    // vector must not leak the freshly duplicated kernel handle.
    std::shared_ptr<void> ownedHandle(duplicate, [](void* handle) {
        if (handle) CloseHandle(static_cast<HANDLE>(handle));
    });
    auto replacement = std::make_shared<Impl::Session>();
    replacement->kind = Impl::SessionKind::Live;
    replacement->liveHandle = std::move(ownedHandle);
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->stopping) {
            if (error) *error = "the symbol worker is unavailable";
            return false;
        }
        if (modules.size() > impl_->limits.maxModules) modules.resize(impl_->limits.maxModules);
        replacement->modules.reserve(modules.size());
        size_t retainedPathBytes = 0;
        const size_t pathBudget = (std::min)(impl_->limits.maxRetainedBytes,
                                             kMaxSessionModuleBytes);
        for (auto& module : modules) {
            if (!module.base || !module.size ||
                module.size > (std::numeric_limits<uint64_t>::max)() - module.base ||
                module.imagePath.size() > kMaxSymbolPath ||
                module.imagePath.find('\0') != std::string::npos ||
                module.imagePath.size() > pathBudget - retainedPathBytes)
                continue;
            compactTo(module.imagePath, kMaxSymbolPath);
            retainedPathBytes += module.imagePath.size();
            replacement->modules.push_back(std::move(module));
        }
        replacement->options = impl_->options;
        impl_->replaceSessionLocked(std::move(replacement));
    }
    return true;
}

void SymbolService::reset() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->stopping) return;
    impl_->replaceSessionLocked(nullptr);
}

SymbolLookupState SymbolService::lookupAddress(uint64_t address, SymbolRecord& result,
                                               bool detailed) {
    result = {};
    std::unique_lock<std::mutex> lock(impl_->mutex, std::try_to_lock);
    if (!lock.owns_lock()) return SymbolLookupState::Pending;
    if (impl_->stopping) return SymbolLookupState::Unavailable;
    if (!impl_->session) return SymbolLookupState::Unavailable;
    if (impl_->failedGeneration == impl_->generation)
        return SymbolLookupState::Unavailable;
    auto cached = impl_->addresses.find(address);
    if (cached != impl_->addresses.end() && (!detailed || cached->second.detailed)) {
        if (detailed) result = cached->second.record;
        else copyBasicRecord(cached->second.record, result);
        ++impl_->cacheHits;
        return result.found ? SymbolLookupState::Found : SymbolLookupState::NotFound;
    }
    auto& requestedSet = detailed ? impl_->pendingDetailedAddresses
                                  : impl_->pendingBasicAddresses;
    if (requestedSet.find(address) != requestedSet.end() ||
        (!detailed && impl_->pendingDetailedAddresses.find(address) !=
                      impl_->pendingDetailedAddresses.end())) {
        ++impl_->coalesced;
        return SymbolLookupState::Pending;
    }
    const size_t pendingCount = impl_->pendingBasicAddresses.size() +
                                impl_->pendingDetailedAddresses.size() +
                                impl_->pendingNames.size();
    if (pendingCount >= impl_->limits.maxPending) {
        ++impl_->dropped;
        return SymbolLookupState::Unavailable;
    }
    Impl::Request request;
    request.kind = Impl::RequestKind::Address;
    request.generation = impl_->generation;
    request.session = impl_->session;
    request.address = address;
    request.detailed = detailed;
    request.pendingCost = sizeof(Impl::Request);
    if (request.pendingCost > impl_->limits.maxQueuedBytes -
                              (std::min)(impl_->pendingBytes,
                                         impl_->limits.maxQueuedBytes)) {
        ++impl_->dropped;
        return SymbolLookupState::Unavailable;
    }
    requestedSet.insert(address);
    impl_->pendingBytes += request.pendingCost;
    impl_->queue.push_back(std::move(request));
    ++impl_->requested;
    impl_->wake.notify_one();
    return SymbolLookupState::Pending;
}

SymbolLookupState SymbolService::lookupName(const std::string& name, uint64_t& address) {
    address = 0;
    if (name.empty() || name.size() > kMaxSymbolText ||
        name.find('\0') != std::string::npos)
        return SymbolLookupState::Unavailable;
    const std::string key = lowerName(name);
    std::unique_lock<std::mutex> lock(impl_->mutex, std::try_to_lock);
    if (!lock.owns_lock()) return SymbolLookupState::Pending;
    if (impl_->stopping) return SymbolLookupState::Unavailable;
    if (!impl_->session) return SymbolLookupState::Unavailable;
    if (impl_->failedGeneration == impl_->generation)
        return SymbolLookupState::Unavailable;
    auto cached = impl_->names.find(key);
    if (cached != impl_->names.end()) {
        address = cached->second.address;
        ++impl_->cacheHits;
        return cached->second.found ? SymbolLookupState::Found : SymbolLookupState::NotFound;
    }
    if (impl_->pendingNames.find(key) != impl_->pendingNames.end()) {
        ++impl_->coalesced;
        return SymbolLookupState::Pending;
    }
    if (impl_->pendingBasicAddresses.size() + impl_->pendingDetailedAddresses.size() +
        impl_->pendingNames.size() >= impl_->limits.maxPending) {
        ++impl_->dropped;
        return SymbolLookupState::Unavailable;
    }
    Impl::Request request;
    request.kind = Impl::RequestKind::Name;
    request.generation = impl_->generation;
    request.session = impl_->session;
    request.name = name;
    request.nameKey = key;
    request.pendingCost = sizeof(Impl::Request) + name.size() + key.size() * 2;
    if (request.pendingCost > impl_->limits.maxQueuedBytes -
                              (std::min)(impl_->pendingBytes,
                                         impl_->limits.maxQueuedBytes)) {
        ++impl_->dropped;
        return SymbolLookupState::Unavailable;
    }
    impl_->pendingNames.insert(key);
    impl_->pendingBytes += request.pendingCost;
    impl_->queue.push_back(std::move(request));
    ++impl_->requested;
    impl_->wake.notify_one();
    return SymbolLookupState::Pending;
}

SymbolServiceStats SymbolService::stats() const {
    SymbolServiceStats result;
    std::unique_lock<std::mutex> lock(impl_->mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        result.busy = true;
        return result;
    }
    result.generation = impl_->generation;
    result.requested = impl_->requested;
    result.completed = impl_->completed;
    result.cacheHits = impl_->cacheHits;
    result.coalesced = impl_->coalesced;
    result.dropped = impl_->dropped;
    result.staleResults = impl_->staleResults;
    result.failures = impl_->failures;
    result.revision = impl_->revision;
    result.queued = impl_->queue.size();
    result.pending = impl_->pendingBasicAddresses.size() +
                     impl_->pendingDetailedAddresses.size() + impl_->pendingNames.size();
    result.cachedAddresses = impl_->addresses.size();
    result.cachedNames = impl_->names.size();
    result.retainedBytes = impl_->addressBytes + impl_->nameBytes;
    result.pendingBytes = impl_->pendingBytes;
    result.busy = impl_->busy;
    result.lastError = impl_->lastError;
    return result;
}

void SymbolService::cancelAndWaitIdle() {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->stopping) {
            impl_->session.reset();
            impl_->clearLookupStateLocked();
            return;
        }
        impl_->replaceSessionLocked(nullptr);
    }
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->idle.wait(lock, [&] { return !impl_->busy && impl_->queue.empty(); });
}

} // namespace ds
