#pragma once
//
// ProcessMemorySession.h
//
// A non-debugger Win32 process-memory connection for scanners, viewers, and
// address lists.  Unlike Debugger, opening this session never calls
// DebugActiveProcess and never consumes debug events.  Every operation is bound
// to the exact successful open that produced its ProcessMemoryIdentity.
//
// The public header is Win32-free so the access policy and identity rules can be
// exercised by dependency-light tests.
//

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ds {

// creationTime100ns is the process creation FILETIME expressed as one 64-bit
// Windows-epoch tick count.  It protects against PID reuse; generation protects
// against closing and reopening even the same still-running process.
struct ProcessMemoryIdentity {
    uint32_t pid = 0;
    uint64_t creationTime100ns = 0;
    uint64_t generation = 0;

    constexpr bool valid() const {
        return pid != 0 && creationTime100ns != 0 && generation != 0;
    }
};

inline constexpr bool ProcessMemoryIdentityMatches(ProcessMemoryIdentity current,
                                                   ProcessMemoryIdentity expected) {
    return current.valid() && expected.valid() &&
           current.pid == expected.pid &&
           current.creationTime100ns == expected.creationTime100ns &&
           current.generation == expected.generation;
}

struct ProcessMemoryOpenOptions {
    // Ask for PROCESS_VM_WRITE/PROCESS_VM_OPERATION in addition to query/read.
    bool requestWrite = true;
    // A protected target may grant read access but reject write access.  Keeping
    // the readable connection is useful for scanning and is safer than failing
    // the whole open.  Snapshot::canWrite tells the UI which mode was obtained.
    bool allowReadOnlyFallback = true;
};

struct ProcessMemorySessionSnapshot {
    bool open = false;       // an owned process handle is installed
    bool alive = false;      // the owned handle was not signalled at snapshot time
    bool canRead = false;
    bool canWrite = false;
    bool is32 = false;
    bool bitnessKnown = false;
    ProcessMemoryIdentity identity{};
    std::string path;        // UTF-8 full image path when Windows exposes it
    std::string name;        // basename, or a bounded PID fallback
    std::string error;       // most recent failed session operation
};

// One VirtualQueryEx MEM_COMMIT span.  Raw Win32 values are retained for a rich
// region browser while portable booleans let scanners filter without windows.h.
struct ProcessMemoryRegion {
    uint64_t base = 0;
    uint64_t size = 0;
    uint64_t allocationBase = 0;
    uint32_t allocationProtect = 0;
    uint32_t protect = 0;
    uint32_t state = 0;
    uint32_t type = 0;
    bool committed = false;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool copyOnWrite = false;
    bool guarded = false;
    bool noAccess = false;
};

struct ProcessMemoryRegionResult {
    ProcessMemoryIdentity identity{};
    std::vector<ProcessMemoryRegion> regions;
    // False means a useful prefix may be present, but enumeration ended on an
    // unexpected VirtualQueryEx failure or a defensive region-count limit.
    bool complete = false;
    std::string error;
};

// Pure write-policy input and result.  The native writer evaluates every region
// touched by a request with this exact function before changing bytes or page
// protections.
struct ProcessMemoryAccess {
    bool committed = false;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool guarded = false;
    bool noAccess = false;
};

enum class ProcessMemoryWritePolicyCode : uint8_t {
    Allow,
    ExplicitAuthorizationRequired,
    Deny,
};

struct ProcessMemoryWritePolicy {
    ProcessMemoryWritePolicyCode code = ProcessMemoryWritePolicyCode::Deny;
    bool needsProtectionChange = false;
    bool touchesExecutable = false;

    constexpr bool allowed() const {
        return code == ProcessMemoryWritePolicyCode::Allow;
    }
};

// Default authority is deliberately narrow: already-writable, non-executable
// committed data.  allowProtectionChange is the explicit authority both for an
// executable page and for temporarily making a read-only page writable.  Guard
// and PAGE_NOACCESS spans stay denied because reading them would itself alter or
// violate target semantics, preventing an honest transactional rollback.
inline constexpr ProcessMemoryWritePolicy EvaluateProcessMemoryWritePolicy(
    ProcessMemoryAccess access, bool allowProtectionChange) {
    const bool denied = !access.committed || access.guarded || access.noAccess;
    if (denied) {
        return { ProcessMemoryWritePolicyCode::Deny, false, access.executable };
    }

    const bool needsProtectionChange = !access.readable || !access.writable;
    const bool needsExplicitAuthority = access.executable || needsProtectionChange;
    if (needsExplicitAuthority && !allowProtectionChange) {
        return { ProcessMemoryWritePolicyCode::ExplicitAuthorizationRequired,
                 needsProtectionChange, access.executable };
    }
    return { ProcessMemoryWritePolicyCode::Allow,
             needsProtectionChange, access.executable };
}

struct ProcessMemoryWriteOptions {
    // See EvaluateProcessMemoryWritePolicy.  This is false by default so a
    // normal address-table edit cannot silently patch code or page protection.
    bool allowProtectionChange = false;
};

enum class ProcessMemoryWriteCode : uint8_t {
    Applied,
    InvalidRequest,
    SessionClosed,
    IdentityMismatch,
    ProcessExited,
    WriteAccessUnavailable,
    RegionQueryFailed,
    RegionDenied,
    ExplicitAuthorizationRequired,
    ProtectionChangeFailed,
    ReadBeforeWriteFailed,
    WriteFailed,
    VerificationFailed,
    ProtectionRestoreFailed,
    RollbackFailed,
};

struct ProcessMemoryWriteResult {
    ProcessMemoryWriteCode code = ProcessMemoryWriteCode::InvalidRequest;
    size_t bytesWritten = 0;       // requested byte count only on Applied
    bool protectionChanged = false;
    bool rollbackAttempted = false;
    bool rollbackComplete = false;
    bool protectionsRestored = true;
    std::string error;

    bool ok() const { return code == ProcessMemoryWriteCode::Applied; }
};

inline constexpr size_t kProcessMemoryMaxTransactionalWriteBytes =
    16u * 1024u * 1024u;

class ProcessMemorySession {
public:
    ProcessMemorySession();
    ~ProcessMemorySession();

    ProcessMemorySession(const ProcessMemorySession&) = delete;
    ProcessMemorySession& operator=(const ProcessMemorySession&) = delete;
    ProcessMemorySession(ProcessMemorySession&&) = delete;
    ProcessMemorySession& operator=(ProcessMemorySession&&) = delete;

    // Transactional session replacement: a failed open leaves an existing
    // connection installed, while exposing the failure through `error` and the
    // next snapshot.  No debugger attach, suspend, or injection is performed.
    bool open(uint32_t pid, ProcessMemoryOpenOptions options = {},
              std::string* error = nullptr);
    void close();

    ProcessMemorySessionSnapshot snapshot() const;

    // The session mutex remains held from identity validation through the OS
    // call, closing the close/reopen/PID-reuse race.  Partial reads are returned
    // as a byte count and described through error/snapshot.error.
    size_t read(ProcessMemoryIdentity expected, uint64_t address,
                void* output, size_t size, std::string* error = nullptr);

    // Enumerates MEM_COMMIT regions, including guard/no-access spans so the UI
    // can describe them honestly.  Scanners should select region.readable.
    ProcessMemoryRegionResult committedRegions(ProcessMemoryIdentity expected);

    // Verified transaction: capture original bytes, write, read back, and on
    // any post-write failure attempt a verified rollback.  Original page
    // protections are restored before success is reported.  This serializes
    // DisasmStudio operations but does not suspend target threads; callers that
    // need a process-wide coherent edit must arrange an explicit pause.
    ProcessMemoryWriteResult write(ProcessMemoryIdentity expected,
                                   uint64_t address, const void* bytes, size_t size,
                                   ProcessMemoryWriteOptions options = {});

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ds
