#pragma once
//
// SymbolService.h
// Non-blocking owner for DbgHelp/PDB work.  The render thread only submits
// bounded requests and consumes immutable completed records; PDB loading,
// optional symbol-server traffic, line/type lookup, and local enumeration stay
// on the service thread.
//
#include "SymbolResolver.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ds {

struct SymbolModuleSpec {
    uint64_t    base = 0;
    uint64_t    size = 0;
    std::string imagePath;
};

struct SymbolServiceLimits {
    size_t maxPending = 4096;
    size_t maxAddressCache = 16384;
    size_t maxNameCache = 4096;
    size_t maxModules = 4096;
    size_t maxRetainedBytes = 64ull * 1024ull * 1024ull;
    size_t maxQueuedBytes = 16ull * 1024ull * 1024ull;
};

enum class SymbolLookupState : uint8_t {
    Unavailable,
    Pending,
    Found,
    NotFound,
};

struct SymbolServiceStats {
    uint64_t generation = 0;
    uint64_t requested = 0;
    uint64_t completed = 0;
    uint64_t cacheHits = 0;
    uint64_t coalesced = 0;
    uint64_t dropped = 0;
    uint64_t staleResults = 0;
    uint64_t failures = 0;
    uint64_t revision = 0;
    size_t   queued = 0;
    size_t   pending = 0;
    size_t   cachedAddresses = 0;
    size_t   cachedNames = 0;
    size_t   retainedBytes = 0;
    size_t   pendingBytes = 0;
    bool     busy = false;
    std::string lastError;
};

// Injection seam for deterministic service tests. Production uses a private
// adapter around SymbolResolver; every method is invoked only by the worker.
class ISymbolServiceBackend {
public:
    virtual ~ISymbolServiceBackend() = default;
    virtual void configure(const SymbolResolverOptions& options) = 0;
    virtual void reset() = 0;
    virtual bool useLive(void* processHandle) = 0;
    virtual bool useBinary(const std::string& path, uint64_t imageBase) = 0;
    virtual void ensureModule(const SymbolModuleSpec& module) = 0;
    virtual bool resolve(uint64_t address, std::string& name, uint64_t& displacement) = 0;
    virtual bool resolveDetailed(uint64_t address, SymbolRecord& result) = 0;
    virtual bool addressOf(const std::string& name, uint64_t& address) = 0;
};

using SymbolServiceBackendFactory =
    std::function<std::unique_ptr<ISymbolServiceBackend>()>;

class SymbolService {
public:
    explicit SymbolService(SymbolServiceLimits limits = {},
                           SymbolServiceBackendFactory backendFactory = {});
    ~SymbolService();
    SymbolService(const SymbolService&) = delete;
    SymbolService& operator=(const SymbolService&) = delete;

    // Changing policy invalidates the current session and all cached results.
    // Network remains disabled in the default-constructed options.
    void configure(SymbolResolverOptions options);
    SymbolResolverOptions options() const;

    // Context switches are non-blocking. The live path duplicates the process
    // handle before returning so a concurrent debugger detach cannot invalidate
    // a DbgHelp call already owned by the worker.
    void useBinary(std::string path, uint64_t imageBase);
    bool useLive(void* processHandle, std::vector<SymbolModuleSpec> modules,
                 std::string* error = nullptr);
    void reset();

    // A miss queues one request and returns Pending. Pending can also mean the
    // worker is publishing under its short cache lock; callers retry next frame
    // rather than blocking the render thread. Repeated requests coalesce and a
    // completed negative lookup returns NotFound and is cached too.
    SymbolLookupState lookupAddress(uint64_t address, SymbolRecord& result,
                                    bool detailed = false);
    SymbolLookupState lookupName(const std::string& name, uint64_t& address);

    SymbolServiceStats stats() const;
    void cancelAndWaitIdle();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ds
