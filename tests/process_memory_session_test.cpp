#include "Core/ProcessMemorySession.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <string>

using namespace ds;

constexpr ProcessMemoryAccess kWritableData{
    true, true, true, false, false, false
};
constexpr ProcessMemoryAccess kReadOnlyData{
    true, true, false, false, false, false
};
constexpr ProcessMemoryAccess kWritableCode{
    true, true, true, true, false, false
};
constexpr ProcessMemoryAccess kGuardedData{
    true, true, true, false, true, false
};

static_assert(EvaluateProcessMemoryWritePolicy(kWritableData, false).allowed());
static_assert(!EvaluateProcessMemoryWritePolicy(kWritableData, false).needsProtectionChange);
static_assert(EvaluateProcessMemoryWritePolicy(kReadOnlyData, false).code ==
              ProcessMemoryWritePolicyCode::ExplicitAuthorizationRequired);
static_assert(EvaluateProcessMemoryWritePolicy(kReadOnlyData, true).allowed());
static_assert(EvaluateProcessMemoryWritePolicy(kReadOnlyData, true).needsProtectionChange);
static_assert(EvaluateProcessMemoryWritePolicy(kWritableCode, false).code ==
              ProcessMemoryWritePolicyCode::ExplicitAuthorizationRequired);
static_assert(EvaluateProcessMemoryWritePolicy(kWritableCode, true).allowed());
static_assert(EvaluateProcessMemoryWritePolicy(kWritableCode, true).touchesExecutable);
static_assert(EvaluateProcessMemoryWritePolicy(kGuardedData, true).code ==
              ProcessMemoryWritePolicyCode::Deny);

constexpr ProcessMemoryIdentity kIdentity{ 42, 123456, 7 };
static_assert(kIdentity.valid());
static_assert(ProcessMemoryIdentityMatches(kIdentity, kIdentity));
static_assert(!ProcessMemoryIdentityMatches(kIdentity, { 42, 123456, 8 }));
static_assert(!ProcessMemoryIdentityMatches({}, {}));

static int failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #condition); ++failures; } } while (0)

int main() {
    ProcessMemorySession session;
    std::string error;
    CHECK(!session.open(0, {}, &error));
    CHECK(!error.empty());
    CHECK(!session.snapshot().open);

    const uint32_t pid = GetCurrentProcessId();
    CHECK(session.open(pid, {}, &error));
    CHECK(error.empty());
    ProcessMemorySessionSnapshot first = session.snapshot();
    CHECK(first.open);
    CHECK(first.alive);
    CHECK(first.canRead);
    CHECK(first.canWrite);
    CHECK(first.identity.valid());
    CHECK(first.identity.pid == pid);
    CHECK(!first.name.empty());

    volatile uint32_t target = 0x11223344u;
    const uint64_t targetAddress = reinterpret_cast<uint64_t>(
        const_cast<uint32_t*>(&target));
    uint32_t observed = 0;
    CHECK(session.read(first.identity, targetAddress, &observed, sizeof(observed),
                       &error) == sizeof(observed));
    CHECK(error.empty());
    CHECK(observed == 0x11223344u);

    const uint32_t replacement = 0x55667788u;
    ProcessMemoryWriteResult write = session.write(
        first.identity, targetAddress, &replacement, sizeof(replacement));
    CHECK(write.ok());
    CHECK(write.bytesWritten == sizeof(replacement));
    CHECK(!write.protectionChanged);
    CHECK(target == replacement);

    ProcessMemoryRegionResult regions = session.committedRegions(first.identity);
    CHECK(regions.complete);
    CHECK(regions.error.empty());
    bool foundTarget = false;
    for (const ProcessMemoryRegion& region : regions.regions) {
        if (targetAddress >= region.base &&
            targetAddress - region.base < region.size) {
            foundTarget = true;
            CHECK(region.committed);
            CHECK(region.readable);
            CHECK(region.writable);
            CHECK(!region.noAccess);
            break;
        }
    }
    CHECK(foundTarget);

    ProcessMemoryIdentity wrong = first.identity;
    ++wrong.generation;
    observed = 0xA5A5A5A5u;
    CHECK(session.read(wrong, targetAddress, &observed, sizeof(observed), &error) == 0);
    CHECK(observed == 0xA5A5A5A5u);
    CHECK(!error.empty());
    write = session.write(wrong, targetAddress, &replacement, sizeof(replacement));
    CHECK(write.code == ProcessMemoryWriteCode::IdentityMismatch);

    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    const size_t pageSize = systemInfo.dwPageSize ? systemInfo.dwPageSize : 4096;

    auto* readOnlyPage = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, pageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    CHECK(readOnlyPage != nullptr);
    if (readOnlyPage) {
        readOnlyPage[0] = 0x31;
        DWORD prior = 0;
        CHECK(VirtualProtect(readOnlyPage, pageSize, PAGE_READONLY, &prior) != FALSE);

        const uint8_t changed = 0x7A;
        write = session.write(first.identity,
                              reinterpret_cast<uint64_t>(readOnlyPage), &changed, 1);
        CHECK(write.code == ProcessMemoryWriteCode::ExplicitAuthorizationRequired);
        CHECK(readOnlyPage[0] == 0x31);

        ProcessMemoryWriteOptions authorized;
        authorized.allowProtectionChange = true;
        write = session.write(first.identity,
                              reinterpret_cast<uint64_t>(readOnlyPage), &changed, 1,
                              authorized);
        CHECK(write.ok());
        CHECK(write.protectionChanged);
        CHECK(write.protectionsRestored);
        CHECK(readOnlyPage[0] == changed);

        MEMORY_BASIC_INFORMATION info{};
        CHECK(VirtualQuery(readOnlyPage, &info, sizeof(info)) == sizeof(info));
        CHECK((info.Protect & 0xFFu) == PAGE_READONLY);
        CHECK(VirtualFree(readOnlyPage, 0, MEM_RELEASE) != FALSE);
    }

    auto* executablePage = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, pageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    CHECK(executablePage != nullptr);
    if (executablePage) {
        executablePage[0] = 0x90;
        const uint8_t changed = 0xCC;
        write = session.write(first.identity,
                              reinterpret_cast<uint64_t>(executablePage), &changed, 1);
        CHECK(write.code == ProcessMemoryWriteCode::ExplicitAuthorizationRequired);
        CHECK(executablePage[0] == 0x90);

        ProcessMemoryWriteOptions authorized;
        authorized.allowProtectionChange = true;
        write = session.write(first.identity,
                              reinterpret_cast<uint64_t>(executablePage), &changed, 1,
                              authorized);
        CHECK(write.ok());
        CHECK(!write.protectionChanged); // already writable; executable opt-in was still required
        CHECK(executablePage[0] == changed);
        CHECK(VirtualFree(executablePage, 0, MEM_RELEASE) != FALSE);
    }

    // Failed replacement is transactional: keep the currently valid session.
    CHECK(!session.open(0, {}, &error));
    ProcessMemorySessionSnapshot afterFailedOpen = session.snapshot();
    CHECK(afterFailedOpen.open);
    CHECK(ProcessMemoryIdentityMatches(afterFailedOpen.identity, first.identity));
    CHECK(!afterFailedOpen.error.empty());

    // Reopening the same process retains creation identity but advances the
    // session generation, so all records from the first open fail closed.
    CHECK(session.open(pid, {}, &error));
    ProcessMemorySessionSnapshot second = session.snapshot();
    CHECK(second.identity.creationTime100ns == first.identity.creationTime100ns);
    CHECK(second.identity.generation > first.identity.generation);
    observed = 0;
    CHECK(session.read(first.identity, targetAddress, &observed, sizeof(observed),
                       &error) == 0);
    CHECK(session.read(second.identity, targetAddress, &observed, sizeof(observed),
                       &error) == sizeof(observed));
    CHECK(observed == replacement);

    session.close();
    ProcessMemorySessionSnapshot closed = session.snapshot();
    CHECK(!closed.open);
    CHECK(!closed.alive);
    CHECK(!closed.identity.valid());
    CHECK(session.read(second.identity, targetAddress, &observed, sizeof(observed),
                       &error) == 0);

    if (!failures) std::printf("ALL PROCESS MEMORY SESSION TESTS PASSED\n");
    else std::printf("%d CHECK(S) FAILED\n", failures);
    return failures ? 1 : 0;
}
