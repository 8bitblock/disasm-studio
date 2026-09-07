// Live end-to-end check for the production x64 debugger path.  The test binary
// launches itself as the debuggee; an inherited environment marker prevents
// recursion and gives the child a deterministic, short-lived workload.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/Debugger.h"
#include "fixtures/network_http_fixture.h"

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

// The attach/stepping fixture deliberately has two threads hammering the same
// direct CALL. Its exact code addresses are recovered as image RVAs by the
// parent, so ASLR does not weaken the assertions.
static volatile LONG g_fixtureStop = 0;
static volatile LONG g_fixtureData = 0;
// Dedicated memory-write target. Worker threads intentionally mutate
// g_fixtureData, which made an immediate write/readback assertion race them.
static volatile LONG g_fixtureScratch = 0;
static volatile LONG g_fixtureHits = 0;

#pragma optimize("", off)
__declspec(noinline) static LONG fixtureLeaf(LONG input) {
    const LONG hit = InterlockedIncrement(&g_fixtureHits);
    return input + hit + 7;
}

__declspec(noinline) static LONG fixtureCaller(LONG input) {
    const LONG value = fixtureLeaf(input);
    InterlockedExchangeAdd(&g_fixtureData, value & 1);
    return value ^ 0x13579BDF;
}
#pragma optimize("", on)

static DWORD WINAPI fixtureWorker(void* parameter) {
    const LONG seed = static_cast<LONG>(reinterpret_cast<uintptr_t>(parameter));
    while (InterlockedCompareExchange(&g_fixtureStop, 0, 0) == 0) {
        (void)fixtureCaller(seed);
        SwitchToThread();
    }
    return 0;
}

static bool waitPaused(Debugger& debugger, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 10) {
        if (debugger.snapshot().state == DbgState::Paused) return true;
        Sleep(10);
    }
    return false;
}

static bool waitTerminated(Debugger& debugger, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 10) {
        const DbgState state = debugger.snapshot().state;
        if (state == DbgState::Terminated || state == DbgState::Detached) return true;
        Sleep(10);
    }
    return false;
}

static bool waitRunning(Debugger& debugger, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 5) {
        if (debugger.snapshot().state == DbgState::Running) return true;
        Sleep(5);
    }
    return false;
}

static bool waitPausedAt(Debugger& debugger, uint64_t address, int timeoutMs,
                         uint32_t ownerTid = 0) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 5) {
        const DbgSnapshot snapshot = debugger.snapshot();
        if (snapshot.state == DbgState::Paused && snapshot.regs.rip == address &&
            (!ownerTid || snapshot.activeTid == ownerTid))
            return true;
        Sleep(5);
    }
    return false;
}

static bool waitPausedEvent(Debugger& debugger, const char* eventText, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 5) {
        const DbgSnapshot snapshot = debugger.snapshot();
        if (snapshot.state == DbgState::Paused &&
            snapshot.lastEvent.find(eventText) != std::string::npos)
            return true;
        Sleep(5);
    }
    return false;
}

static bool waitSoftwareStop(Debugger& debugger, uint64_t address,
                             uint32_t minimumHits, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 5) {
        const DbgSnapshot snapshot = debugger.snapshot();
        if (snapshot.state == DbgState::Paused && snapshot.regs.rip == address) {
            for (const auto& bp : snapshot.breakpoints)
                if (bp.address == address && bp.hits >= minimumHits) return true;
        }
        Sleep(5);
    }
    return false;
}

static bool waitSecondChance(Debugger& debugger, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 10) {
        const DbgSnapshot snapshot = debugger.snapshot();
        if (snapshot.state == DbgState::Paused && snapshot.exceptionSequence &&
            !snapshot.exceptionFirstChance)
            return true;
        Sleep(10);
    }
    return false;
}

static bool liveTestRequired() {
    char value[8]{};
    return GetEnvironmentVariableA("DS_REQUIRE_LIVE_DEBUG_TESTS", value,
                                   static_cast<DWORD>(sizeof(value))) != 0 &&
           value[0] == '1';
}

static int debuggeeMain() {
    volatile unsigned value = GetCurrentProcessId();
    for (unsigned i = 0; i < 10000; ++i) value = value * 1664525u + 1013904223u;
    Sleep(3000); // leave a deterministic running window for async-mutation/detach checks
    return value == 0xFFFFFFFFu ? 1 : 0;
}

static int fixtureDebuggeeMain() {
    InterlockedExchange(&g_fixtureStop, 0);
    InterlockedExchange(&g_fixtureData, 0);
    InterlockedExchange(&g_fixtureScratch, 0);
    InterlockedExchange(&g_fixtureHits, 0);

    HANDLE workers[2] = {
        CreateThread(nullptr, 0, fixtureWorker, reinterpret_cast<void*>(1), 0, nullptr),
        CreateThread(nullptr, 0, fixtureWorker, reinterpret_cast<void*>(2), 0, nullptr),
    };
    char readyName[128]{};
    if (GetEnvironmentVariableA("DS_X64_FIXTURE_READY", readyName,
                                static_cast<DWORD>(sizeof(readyName)))) {
        HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, readyName);
        if (ready) { SetEvent(ready); CloseHandle(ready); }
    }

    const ULONGLONG deadline = GetTickCount64() + 30000;
    while (InterlockedCompareExchange(&g_fixtureStop, 0, 0) == 0 &&
           GetTickCount64() < deadline)
        Sleep(5);
    InterlockedExchange(&g_fixtureStop, 1);
    for (HANDLE worker : workers)
        if (worker) WaitForSingleObject(worker, 5000);
    for (HANDLE worker : workers)
        if (worker) CloseHandle(worker);
    return 0;
}

static int crashingDebuggeeMain() {
    volatile int* invalid = nullptr;
    *invalid = 1;
    return 0;
}

// A completely local stand-in for the sort of hosted reply service used by a
// networked crackme. Both ends live in the debuggee, so the fixture is
// deterministic and never contacts the public network, while still exercising
// name resolution, connect, send, and recv in the production debugger.
static DWORD WINAPI networkReplyWorker(void* parameter) {
    const SOCKET listener = static_cast<SOCKET>(reinterpret_cast<uintptr_t>(parameter));
    SOCKET peer = accept(listener, nullptr, nullptr);
    if (peer == INVALID_SOCKET) return 1;
    char request[64]{};
    const int received = recv(peer, request, static_cast<int>(sizeof(request)), 0);
    static constexpr char reply[] = "hosted-reply:accepted";
    if (received > 0)
        (void)send(peer, reply, static_cast<int>(sizeof(reply) - 1), 0);
    closesocket(peer);
    return received > 0 ? 0 : 2;
}

static int networkDebuggeeMain() {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 10;

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) { WSACleanup(); return 11; }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR ||
        listen(listener, 1) == SOCKET_ERROR) {
        closesocket(listener); WSACleanup(); return 12;
    }
    int localLength = sizeof(local);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&local), &localLength) == SOCKET_ERROR) {
        closesocket(listener); WSACleanup(); return 13;
    }

    HANDLE replyWorker = CreateThread(nullptr, 0, networkReplyWorker,
        reinterpret_cast<void*>(static_cast<uintptr_t>(listener)), 0, nullptr);
    if (!replyWorker) { closesocket(listener); WSACleanup(); return 14; }

    char service[16]{};
    std::snprintf(service, sizeof(service), "%u", static_cast<unsigned>(ntohs(local.sin_port)));
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* addresses = nullptr;
    const int resolved = getaddrinfo("localhost", service, &hints, &addresses);
    SOCKET client = INVALID_SOCKET;
    if (resolved == 0) {
        for (addrinfo* it = addresses; it; it = it->ai_next) {
            client = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if (client != INVALID_SOCKET &&
                connect(client, it->ai_addr, static_cast<int>(it->ai_addrlen)) == 0)
                break;
            if (client != INVALID_SOCKET) closesocket(client);
            client = INVALID_SOCKET;
        }
    }

    int replyLength = SOCKET_ERROR;
    char reply[64]{};
    static constexpr char request[] = "crackme-query:serial";
    if (client != INVALID_SOCKET &&
        send(client, request, static_cast<int>(sizeof(request) - 1), 0) > 0)
        replyLength = recv(client, reply, static_cast<int>(sizeof(reply)), 0);

    if (addresses) freeaddrinfo(addresses);
    if (client != INVALID_SOCKET) closesocket(client);
    WaitForSingleObject(replyWorker, 5000);
    DWORD workerResult = 99;
    (void)GetExitCodeThread(replyWorker, &workerResult);
    CloseHandle(replyWorker);
    closesocket(listener);
    const bool rawOk = resolved == 0 && replyLength > 0 && workerResult == 0 &&
        std::string(reply, reply + replyLength) == "hosted-reply:accepted";
    const bool failedBooleanSendsOk = ds::testfixture::RunExpectedFailedBooleanIo();
    const bool winHttpOk = ds::testfixture::RunLocalWinHttpExchange();
    const bool winInetOk = ds::testfixture::RunLocalWinInetExchange();
    WSACleanup();
    // Keep the session alive long enough for the controller to inspect coverage
    // before normal debugger cleanup resets the session's requested/active bits.
    Sleep(750);
    return rawOk && failedBooleanSendsOk && winHttpOk && winInetOk ? 0 : 15;
}

static bool launchSelf(Debugger& debugger, const char* self, std::string& error,
                       const char* mode = "1") {
    SetEnvironmentVariableA("DS_X64_DEBUGGEE", mode);
    DbgLaunchRequest request;
    request.executable = self;
    const ULONGLONG requestedAt = GetTickCount64();
    const uint64_t requestId = debugger.requestLaunch(std::move(request), &error);
    CHECK(GetTickCount64() - requestedAt < 500);
    bool launched = false;
    if (requestId) {
        for (int elapsed = 0; elapsed < 35000; elapsed += 10) {
            const auto lifecycle = debugger.lifecycleSnapshot();
            if (lifecycle.requestId == requestId && lifecycle.completed) {
                launched = lifecycle.succeeded && !lifecycle.cancelled;
                error = lifecycle.error;
                if (launched) {
                    const auto snapshot = debugger.snapshot();
                    CHECK(DebugTargetIdentityMatches(lifecycle.target,
                        {snapshot.pid, snapshot.sessionGeneration}));
                    CHECK(!snapshot.modules.empty());
                    const auto regions = debugger.queryRegionsForSession(
                        snapshot.pid, snapshot.sessionGeneration);
                    CHECK(regions.complete && regions.error.empty() && !regions.regions.empty());
                }
                break;
            }
            Sleep(10);
        }
        if (!launched && error.empty()) {
            debugger.cancelLifecycle(requestId);
            error = "queued fixture launch did not complete";
        }
    }
    SetEnvironmentVariableA("DS_X64_DEBUGGEE", nullptr);
    return launched;
}

static const uint8_t* directFixtureCall() {
    const auto* code = reinterpret_cast<const uint8_t*>(&fixtureCaller);
    const auto target = reinterpret_cast<uintptr_t>(&fixtureLeaf);
    for (size_t offset = 0; offset + 5 <= 128; ++offset) {
        if (code[offset] != 0xE8) continue;
        int32_t relative = 0;
        std::memcpy(&relative, code + offset + 1, sizeof(relative));
        const uintptr_t resolved = reinterpret_cast<uintptr_t>(code + offset + 5) + relative;
        if (resolved == target) return code + offset;
    }
    return nullptr;
}

static uint64_t remoteAddress(const DbgSnapshot& snapshot, const void* localAddress) {
    if (snapshot.modules.empty()) return 0;
    const uintptr_t localBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const uintptr_t local = reinterpret_cast<uintptr_t>(localAddress);
    if (!localBase || local < localBase) return 0;
    return snapshot.modules.front().base + static_cast<uint64_t>(local - localBase);
}

static uint64_t remoteSystemExport(const DbgSnapshot& snapshot, const char* moduleName,
                                   const char* exportName) {
    HMODULE localModule = GetModuleHandleA(moduleName);
    if (!localModule) localModule = LoadLibraryA(moduleName);
    const FARPROC localExport = localModule ? GetProcAddress(localModule, exportName) : nullptr;
    if (!localModule || !localExport) return 0;
    const uint64_t rva = reinterpret_cast<uintptr_t>(localExport) -
                         reinterpret_cast<uintptr_t>(localModule);
    for (const DbgModule& module : snapshot.modules) {
        const std::string& candidate = module.name.empty() ? module.path : module.name;
        const size_t slash = candidate.find_last_of("/\\");
        const char* base = candidate.c_str() +
            (slash == std::string::npos ? 0 : slash + 1);
        if (_stricmp(base, moduleName) == 0 && (!module.size || rva < module.size))
            return module.base + rva;
    }
    return 0;
}

static bool spawnAttachFixture(const char* self, PROCESS_INFORMATION& process,
                               HANDLE& readyEvent) {
    char readyName[128]{};
    std::snprintf(readyName, sizeof(readyName), "Local\\DS_X64_DEBUG_%lu_%llu",
                  static_cast<unsigned long>(GetCurrentProcessId()),
                  static_cast<unsigned long long>(GetTickCount64()));
    readyEvent = CreateEventA(nullptr, TRUE, FALSE, readyName);
    if (!readyEvent) return false;

    SetEnvironmentVariableA("DS_X64_DEBUGGEE", "3");
    SetEnvironmentVariableA("DS_X64_FIXTURE_READY", readyName);
    std::string commandLine = "\"" + std::string(self) + "\"";
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    const BOOL created = CreateProcessA(self, commandLine.data(), nullptr, nullptr, FALSE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    SetEnvironmentVariableA("DS_X64_FIXTURE_READY", nullptr);
    SetEnvironmentVariableA("DS_X64_DEBUGGEE", nullptr);
    if (!created) {
        CloseHandle(readyEvent);
        readyEvent = nullptr;
        return false;
    }
    CloseHandle(process.hThread);
    process.hThread = nullptr;
    if (WaitForSingleObject(readyEvent, 5000) == WAIT_OBJECT_0) return true;
    TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, 2000);
    CloseHandle(process.hProcess);
    process.hProcess = nullptr;
    CloseHandle(readyEvent);
    readyEvent = nullptr;
    return false;
}

static bool waitBreakpointCount(Debugger& debugger, size_t count, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 10) {
        if (debugger.snapshot().breakpoints.size() == count) return true;
        Sleep(10);
    }
    return false;
}

static bool waitBreakpointResult(Debugger& debugger, uint64_t address, bool armed,
                                 const char* errorContains, int timeoutMs) {
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += 5) {
        for (const auto& bp : debugger.snapshot().breakpoints) {
            if (bp.address == address && bp.armed == armed &&
                (errorContains ? bp.error.find(errorContains) != std::string::npos
                               : bp.error.empty()))
                return true;
        }
        Sleep(5);
    }
    return false;
}

// Breakpoint UI edits must complete while the same debug event remains held.
// No Continue, step, or unrelated memory write may be needed to wake the owner.
static void checkPausedBreakpointMutation(Debugger& debugger, const DbgSnapshot& before) {
    const DebugTargetIdentity target{before.pid, before.sessionGeneration};
    const uint64_t address = before.regs.rip;
    uint8_t original = 0;
    CHECK(debugger.readMemory(address, &original, 1) == 1);
    CHECK(original != 0xCC);
    bool pauseStayedOwned = true;
    auto waitForMutation = [&](bool wantArmed) {
        const ULONGLONG deadline = GetTickCount64() + 4000;
        do {
            const DbgSnapshot current = debugger.snapshot();
            pauseStayedOwned &= current.state == DbgState::Paused &&
                current.pid == before.pid &&
                current.sessionGeneration == before.sessionGeneration &&
                current.activeTid == before.activeTid && current.tid == before.tid &&
                current.regs.rip == before.regs.rip && current.is32 == before.is32;
            bool present = false, armed = false;
            for (const auto& bp : current.breakpoints) {
                if (bp.address != address) continue;
                present = true;
                armed = bp.armed && bp.error.empty();
                break;
            }
            uint8_t raw = 0, masked = 0;
            const bool bytesRead = debugger.readMemory(address, &raw, 1) == 1 &&
                debugger.readMemoryMaskedForSession(
                    target.pid, target.sessionGeneration, address, &masked, 1) == 1;
            if (bytesRead && masked == original &&
                (wantArmed ? present && armed && raw == 0xCC
                           : !present && raw == original))
                return true;
            Sleep(5);
        } while (GetTickCount64() < deadline);
        return false;
    };
    CHECK(debugger.addBreakpointForSession(target, address));
    CHECK(waitForMutation(true));
    CHECK(pauseStayedOwned);
    CHECK(debugger.removeBreakpointForSession(target, address));
    CHECK(waitForMutation(false));
    CHECK(pauseStayedOwned);
    const DbgSnapshot after = debugger.snapshot();
    CHECK(after.state == DbgState::Paused && after.pid == before.pid &&
          after.sessionGeneration == before.sessionGeneration &&
          after.activeTid == before.activeTid && after.tid == before.tid &&
          after.regs.rip == before.regs.rip && after.is32 == before.is32);
}

// Trace requests are target mutations too. Exercise the real held-event owner,
// byte masking, rejection of data/native INT3 sites, generation replacement and
// recovery from an unreadable page without issuing an execution command.
static void checkPausedTraceMutation(Debugger& debugger, const DbgSnapshot& before) {
    const DebugTargetIdentity target{before.pid, before.sessionGeneration};
    HANDLE process = static_cast<HANDLE>(debugger.duplicateProcessHandleForSession(target));
    CHECK(process != nullptr);
    if (!process) return;
    void* codePage = VirtualAllocEx(process, nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    void* dataPage = VirtualAllocEx(process, nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    CHECK(codePage != nullptr && dataPage != nullptr);
    if (codePage && dataPage) {
        const uint64_t code = reinterpret_cast<uintptr_t>(codePage);
        const uint64_t data = reinterpret_cast<uintptr_t>(dataPage);
        const uint8_t original[] = {0x90, 0xC3, 0xCC};
        SIZE_T written = 0;
        CHECK(WriteProcessMemory(process, codePage, original, sizeof(original), &written) &&
              written == sizeof(original));
        bool pauseStayedOwned = true;
        auto waitTrace = [&](auto predicate) {
            const ULONGLONG deadline = GetTickCount64() + 4000;
            do {
                const auto current = debugger.snapshot();
                pauseStayedOwned &= current.state == DbgState::Paused &&
                    current.pid == before.pid && current.sessionGeneration == before.sessionGeneration &&
                    current.activeTid == before.activeTid && current.regs.rip == before.regs.rip;
                if (predicate(debugger.traceCoverageSnapshot())) return true;
                Sleep(5);
            } while (GetTickCount64() < deadline);
            return false;
        };
        auto byteEquals = [&](uint64_t address, uint8_t rawExpected, uint8_t maskedExpected) {
            uint8_t raw = 0, masked = 0;
            return debugger.readMemory(address, &raw, 1) == 1 && raw == rawExpected &&
                debugger.readMemoryMasked(address, &masked, 1) == 1 && masked == maskedExpected;
        };
        CHECK(debugger.startTraceCoverageForSession(target,
            {code, code + 1, code + 2, data, 1, code}));
        CHECK(waitTrace([](const auto& trace) {
            return trace.active && trace.plannedSites == 5 &&
                trace.armedSites == 2 && trace.skippedSites == 3;
        }));
        CHECK(byteEquals(code, 0xCC, original[0]));
        CHECK(byteEquals(code + 1, 0xCC, original[1]));
        CHECK(byteEquals(code + 2, 0xCC, original[2]));
        CHECK(byteEquals(data, 0, 0));
        TraceCoverageSnapshot retained;
        CHECK(debugger.traceCoverageSnapshotIfChanged(retained));
        CHECK(!debugger.traceCoverageSnapshotIfChanged(retained));
        const uint64_t generation = retained.generation;
        const DebugTargetIdentity stale{target.pid, target.sessionGeneration + 1};
        CHECK(!debugger.startTraceCoverageForSession(stale, {code}));
        CHECK(!debugger.stopTraceCoverageForSession(stale));
        CHECK(!debugger.clearTraceCoverageForSession(stale));
        CHECK(debugger.traceCoverageSnapshot().generation == generation);

        // A user breakpoint takes physical ownership of a trace site. Stopping
        // the trace must preserve the user's trap and its pristine-byte mask.
        CHECK(debugger.addBreakpointForSession(target, code));
        CHECK(waitBreakpointResult(debugger, code, true, nullptr, 4000));
        CHECK(waitTrace([](const auto& trace) { return trace.armedSites == 1; }));
        CHECK(debugger.stopTraceCoverageForSession(target));
        CHECK(waitTrace([](const auto& trace) { return !trace.active && trace.armedSites == 0; }));
        CHECK(byteEquals(code, 0xCC, original[0]));
        CHECK(byteEquals(code + 1, original[1], original[1]));
        CHECK(debugger.removeBreakpointForSession(target, code));
        CHECK(waitBreakpointCount(debugger, 0, 4000));
        CHECK(byteEquals(code, original[0], original[0]));

        CHECK(debugger.startTraceCoverageForSession(target, {code}));
        CHECK(waitTrace([](const auto& trace) { return trace.active && trace.armedSites == 1; }));
        DWORD priorProtection = 0;
        const bool protectedPage = VirtualProtectEx(process, codePage, 4096,
                                                    PAGE_NOACCESS, &priorProtection) != FALSE;
        CHECK(protectedPage);
        if (protectedPage) {
            CHECK(debugger.stopTraceCoverageForSession(target));
            CHECK(waitPausedEvent(debugger, "trace restore incomplete", 4000));
            const auto failedRestore = debugger.traceCoverageSnapshot();
            CHECK(!failedRestore.active && failedRestore.armedSites == 1);
            CHECK(debugger.snapshot().traceOwnedSites == 1);
            CHECK(debugger.startTraceCoverageForSession(target, {code + 1}));
            CHECK(waitTrace([&](const auto& trace) {
                return !trace.active && trace.generation != failedRestore.generation;
            }));
            CHECK(debugger.traceCoverageSnapshot().armedSites == 0);
            CHECK(debugger.snapshot().traceOwnedSites == 1); // old generation still owns its byte
            DWORD ignoredProtection = 0;
            CHECK(VirtualProtectEx(process, codePage, 4096, priorProtection,
                                   &ignoredProtection) != FALSE);
            CHECK(byteEquals(code, 0xCC, original[0]));
        }
        CHECK(debugger.stopTraceCoverageForSession(target));
        CHECK(waitTrace([&](const auto& trace) {
            return !trace.active && trace.armedSites == 0 && debugger.snapshot().traceOwnedSites == 0;
        }));
        CHECK(byteEquals(code, original[0], original[0]));

        // Restart replaces a live generation only after restoring its bytes.
        CHECK(debugger.startTraceCoverageForSession(target, {code}));
        CHECK(waitTrace([](const auto& trace) { return trace.active && trace.armedSites == 1; }));
        const auto oldGeneration = debugger.traceCoverageSnapshot().generation;
        CHECK(debugger.startTraceCoverageForSession(target, {code + 1}));
        CHECK(waitTrace([&](const auto& trace) {
            return trace.active && trace.generation != oldGeneration && trace.armedSites == 1 &&
                trace.armed.size() == 1 && trace.armed.front() == code + 1;
        }));
        CHECK(byteEquals(code, original[0], original[0]));
        CHECK(byteEquals(code + 1, 0xCC, original[1]));
        CHECK(debugger.stopTraceCoverageForSession(target));
        CHECK(waitTrace([](const auto& trace) { return !trace.active && trace.armedSites == 0; }));
        CHECK(byteEquals(code + 1, original[1], original[1]));
        CHECK(pauseStayedOwned);
    }
    if (codePage) CHECK(VirtualFreeEx(process, codePage, 0, MEM_RELEASE) != FALSE);
    if (dataPage) CHECK(VirtualFreeEx(process, dataPage, 0, MEM_RELEASE) != FALSE);
    CloseHandle(process);
}

int main() {
    char marker[8]{};
    if (GetEnvironmentVariableA("DS_X64_DEBUGGEE", marker,
                                static_cast<DWORD>(sizeof(marker))) != 0)
        return marker[0] == '2' ? crashingDebuggeeMain()
             : marker[0] == '3' ? fixtureDebuggeeMain()
             : marker[0] == '4' ? networkDebuggeeMain()
                                : debuggeeMain();

    std::setvbuf(stdout, nullptr, _IONBF, 0); // retain useful diagnostics if a live check stalls

    using debugger_detail::ClassifyTempBreakpointCleanup;
    using debugger_detail::TempBreakpointByteState;
    using debugger_detail::TempBreakpointCleanupDisposition;
    // Never discard the sole metadata owner while an INT3 may still be live.
    CHECK(ClassifyTempBreakpointCleanup(
              false, false, TempBreakpointByteState::Int3) ==
          TempBreakpointCleanupDisposition::Retain);
    CHECK(ClassifyTempBreakpointCleanup(
              false, false, TempBreakpointByteState::Unknown) ==
          TempBreakpointCleanupDisposition::Retain);
    // A proved restore, superseding byte/unmap, or a persistent user/DLL/anti
    // owner makes releasing the temporary metadata safe.
    CHECK(ClassifyTempBreakpointCleanup(
              false, true, TempBreakpointByteState::Int3) ==
          TempBreakpointCleanupDisposition::Release);
    CHECK(ClassifyTempBreakpointCleanup(
              false, false, TempBreakpointByteState::Other) ==
          TempBreakpointCleanupDisposition::Release);
    CHECK(ClassifyTempBreakpointCleanup(
              false, false, TempBreakpointByteState::Unmapped) ==
          TempBreakpointCleanupDisposition::Release);
    CHECK(ClassifyTempBreakpointCleanup(
              true, false, TempBreakpointByteState::Unknown) ==
          TempBreakpointCleanupDisposition::Release);

    char self[MAX_PATH]{};
    const DWORD selfLength = GetModuleFileNameA(nullptr, self, MAX_PATH);
    if (!selfLength || selfLength >= MAX_PATH) {
        std::printf("x64_debug_test: %s (could not resolve test executable)\n",
                    liveTestRequired() ? "FAIL" : "SKIP");
        return liveTestRequired() ? 1 : 0;
    }

    Debugger debugger;
    std::string error;
    const bool launched = launchSelf(debugger, self, error);
    if (!launched) {
        std::printf("x64_debug_test: %s (launch failed: %s)\n",
                    liveTestRequired() ? "FAIL" : "SKIP", error.c_str());
        return liveTestRequired() ? 1 : 0;
    }

    const bool paused = waitPaused(debugger, 8000);
    CHECK(paused);
    if (paused) {
        const DbgSnapshot before = debugger.snapshot();
        CHECK(!before.is32);
        CHECK(before.pid != 0 && before.regs.rip != 0 && before.regs.rsp != 0);

        // Authorization experiments consume one coherent, identity-bound
        // register observation.  Stale sessions/threads fail closed, and the
        // verified accumulator edit checks both RIP and the prior RAX value
        // before changing anything.
        const DebugTargetIdentity beforeIdentity{
            before.pid, before.sessionGeneration
        };
        PausedRegisterSnapshot pausedRegisters;
        std::string registerError;
        CHECK(!debugger.readPausedRegistersForSession(
            { before.pid, before.sessionGeneration + 1 }, before.activeTid,
            pausedRegisters, &registerError));
        CHECK(!registerError.empty());
        CHECK(debugger.readPausedRegistersForSession(
            beforeIdentity, before.activeTid, pausedRegisters, &registerError));
        CHECK(registerError.empty());
        CHECK(pausedRegisters.target.pid == before.pid);
        CHECK(pausedRegisters.target.sessionGeneration == before.sessionGeneration);
        CHECK(pausedRegisters.tid == before.activeTid && !pausedRegisters.is32);
        CHECK(pausedRegisters.regs.rip == before.regs.rip);
        CHECK(pausedRegisters.regs.rax == before.regs.rax);
        CHECK(pausedRegisters.eax == static_cast<uint32_t>(before.regs.rax));
        CHECK(pausedRegisters.al == static_cast<uint8_t>(before.regs.rax));

        const uint64_t forcedAccumulator = before.regs.rax ^ UINT64_C(1);
        PausedRegisterSnapshot afterAccumulatorWrite;
        CHECK(!debugger.setAccumulatorForSessionVerified(
            beforeIdentity, before.activeTid, before.regs.rip + 1,
            before.regs.rax, UINT64_MAX, forcedAccumulator,
            afterAccumulatorWrite, &registerError));
        CHECK(!registerError.empty());
        CHECK(debugger.snapshot().regs.rax == before.regs.rax);
        CHECK(!debugger.setAccumulatorForSessionVerified(
            beforeIdentity, before.activeTid, before.regs.rip,
            before.regs.rax ^ UINT64_C(2), UINT64_MAX, forcedAccumulator,
            afterAccumulatorWrite, &registerError));
        CHECK(!registerError.empty());
        CHECK(debugger.snapshot().regs.rax == before.regs.rax);
        CHECK(debugger.setAccumulatorForSessionVerified(
            beforeIdentity, before.activeTid, before.regs.rip,
            before.regs.rax, UINT64_MAX, forcedAccumulator,
            afterAccumulatorWrite, &registerError));
        CHECK(registerError.empty());
        CHECK(afterAccumulatorWrite.regs.rax == forcedAccumulator);
        CHECK(debugger.setAccumulatorForSessionVerified(
            beforeIdentity, before.activeTid, before.regs.rip,
            forcedAccumulator, UINT64_MAX, before.regs.rax,
            afterAccumulatorWrite, &registerError));
        CHECK(registerError.empty());
        CHECK(afterAccumulatorWrite.regs.rax == before.regs.rax);

        // Register drawer drafts capture both the displayed thread and RIP.
        // Refuse stale drafts before modifying any register in the new context.
        const uint64_t wrongEditorRip = before.regs.rip ^ UINT64_C(1);
        CHECK(!debugger.setRegisterForSession(
            before.pid, before.sessionGeneration, "rax", forcedAccumulator,
            before.activeTid ^ 0x80000000u, &before.regs.rip));
        CHECK(!debugger.setRegisterForSession(
            before.pid, before.sessionGeneration, "rax", forcedAccumulator,
            before.activeTid, &wrongEditorRip));
        CHECK(debugger.snapshot().regs.rax == before.regs.rax);
        CHECK(debugger.setRegisterForSession(
            before.pid, before.sessionGeneration, "rax", forcedAccumulator,
            before.activeTid, &before.regs.rip));
        CHECK(debugger.snapshot().regs.rax == forcedAccumulator);
        CHECK(debugger.setRegisterForSession(
            before.pid, before.sessionGeneration, "rax", before.regs.rax,
            before.activeTid, &before.regs.rip));

        // A text register edit allocates non-executable target memory, writes a
        // NUL-terminated C string, then installs its pointer in the exact paused
        // thread. Stale session/thread identities must fail before mutation.
        const std::vector<uint8_t> registerText{
            't','h','i','s',' ','i','s',' ','s','o','m','e',' ','t','e','x','t',0
        };
        const size_t regionsBeforeRejectedEdits = debugger.regions().size();
        const uint64_t raxBeforeRejectedEdits = before.regs.rax;
        uint64_t textAddress = 123;
        std::string textError;
        CHECK(!debugger.setRegisterToBufferForSession(
            before.pid, before.sessionGeneration + 1, before.activeTid,
            "rax", registerText, textAddress, &textError));
        CHECK(textAddress == 0);
        CHECK(!textError.empty());
        CHECK(!debugger.setRegisterToBufferForSession(
            before.pid, before.sessionGeneration, before.activeTid ^ 0x80000000u,
            "rax", registerText, textAddress, &textError));
        CHECK(textAddress == 0);
        CHECK(!textError.empty());
        CHECK(debugger.snapshot().regs.rax == raxBeforeRejectedEdits);
        CHECK(!debugger.setRegisterToBufferForSession(
            before.pid, before.sessionGeneration, before.activeTid,
            "rax", registerText, textAddress, &textError, &wrongEditorRip));
        CHECK(textAddress == 0);
        CHECK(!textError.empty());
        CHECK(debugger.snapshot().regs.rax == raxBeforeRejectedEdits);
        CHECK(debugger.regions().size() == regionsBeforeRejectedEdits);
        const bool textSet = debugger.setRegisterToBufferForSession(
            before.pid, before.sessionGeneration, before.activeTid,
            "rax", registerText, textAddress, &textError, &before.regs.rip);
        CHECK(textSet);
        if (textSet) {
            CHECK(textAddress != 0);
            CHECK(debugger.snapshot().regs.rax == textAddress);
            std::vector<uint8_t> observed(registerText.size());
            CHECK(debugger.readMemory(textAddress, observed.data(), observed.size()) ==
                  observed.size());
            CHECK(observed == registerText);
            bool foundWritableNonExecutableRegion = false;
            for (const MemRegion& region : debugger.regions()) {
                if (textAddress < region.base ||
                    textAddress - region.base >= region.size)
                    continue;
                foundWritableNonExecutableRegion =
                    region.write && !region.exec &&
                    (region.protect & 0xFFu) == PAGE_READWRITE;
                break;
            }
            CHECK(foundWritableNonExecutableRegion);
            CHECK(debugger.setRegisterForSession(
                before.pid, before.sessionGeneration, "rax", before.regs.rax));
        }

        uint8_t instructionByte = 0;
        CHECK(debugger.readMemoryMasked(before.regs.rip, &instructionByte, 1) == 1);

        checkPausedBreakpointMutation(debugger, before);
        checkPausedTraceMutation(debugger, before);
        debugger.stepInto();
        bool advanced = false;
        for (int elapsed = 0; elapsed < 4000; elapsed += 10) {
            const DbgSnapshot after = debugger.snapshot();
            if (after.state == DbgState::Paused && after.regs.rip != before.regs.rip) {
                advanced = true;
                break;
            }
            Sleep(10);
        }
        CHECK(advanced);

        debugger.cont();
        CHECK(waitTerminated(debugger, 8000));
    }

    debugger.detach();
    CHECK(debugger.snapshot().state == DbgState::Detached ||
          debugger.snapshot().state == DbgState::Terminated);

    // Software breakpoint mutations are applied by the debug thread even while
    // the target is otherwise quiet. Installation/removal preserve the pristine
    // byte, and a program-authored INT3 is rejected without fabricating an orig.
    error.clear();
    CHECK(launchSelf(debugger, self, error));
    CHECK(waitPaused(debugger, 8000));
    const uint64_t generationA = debugger.snapshot().sessionGeneration;

    // Identity-bound writes must not silently broaden their authority. A
    // read-only data page is denied with the default address-table/freeze
    // policy, succeeds only when protection changes are explicitly allowed,
    // and is returned to its exact original protection after the transaction.
    const DbgSnapshot protectionOwner = debugger.snapshot();
    HANDLE protectionProcess = static_cast<HANDLE>(
        debugger.duplicateProcessHandleForSession(
            { protectionOwner.pid, protectionOwner.sessionGeneration }));
    CHECK(protectionProcess != nullptr);
    if (protectionProcess) {
        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);
        void* protectionPage = VirtualAllocEx(
            protectionProcess, nullptr, systemInfo.dwPageSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        CHECK(protectionPage != nullptr);
        if (protectionPage) {
            const uint8_t originalBytes[] = { 0x11, 0x22, 0x33, 0x44 };
            SIZE_T initializedBytes = 0;
            const bool initialized =
                WriteProcessMemory(protectionProcess, protectionPage,
                                   originalBytes, sizeof(originalBytes),
                                   &initializedBytes) != FALSE &&
                initializedBytes == sizeof(originalBytes);
            CHECK(initialized);

            DWORD writableProtection = 0;
            const bool madeReadOnly = initialized &&
                VirtualProtectEx(protectionProcess, protectionPage,
                                 systemInfo.dwPageSize, PAGE_READONLY,
                                 &writableProtection) != FALSE;
            CHECK(madeReadOnly);
            if (madeReadOnly) {
                MEMORY_BASIC_INFORMATION beforeWrite{};
                CHECK(VirtualQueryEx(protectionProcess, protectionPage,
                                     &beforeWrite, sizeof(beforeWrite)) ==
                      sizeof(beforeWrite));
                CHECK((beforeWrite.Protect & 0xFFu) == PAGE_READONLY);
                const DWORD originalProtection = beforeWrite.Protect;
                const uint64_t remotePage = static_cast<uint64_t>(
                    reinterpret_cast<uintptr_t>(protectionPage));
                const uint8_t replacementBytes[] = { 0xA1, 0xB2, 0xC3, 0xD4 };

                CHECK(debugger.writeMemoryForSession(
                          protectionOwner.pid,
                          protectionOwner.sessionGeneration,
                          remotePage, replacementBytes,
                          sizeof(replacementBytes),
                          /*allowProtectionChange=*/false) == 0);
                uint8_t observedBytes[sizeof(originalBytes)]{};
                CHECK(debugger.readMemoryForSession(
                          protectionOwner.pid,
                          protectionOwner.sessionGeneration,
                          remotePage, observedBytes,
                          sizeof(observedBytes)) == sizeof(observedBytes));
                CHECK(std::memcmp(observedBytes, originalBytes,
                                  sizeof(originalBytes)) == 0);
                MEMORY_BASIC_INFORMATION afterDeniedWrite{};
                CHECK(VirtualQueryEx(protectionProcess, protectionPage,
                                     &afterDeniedWrite,
                                     sizeof(afterDeniedWrite)) ==
                      sizeof(afterDeniedWrite));
                CHECK(afterDeniedWrite.Protect == originalProtection);

                CHECK(debugger.writeMemoryForSession(
                          protectionOwner.pid,
                          protectionOwner.sessionGeneration,
                          remotePage, replacementBytes,
                          sizeof(replacementBytes),
                          /*allowProtectionChange=*/true) ==
                      sizeof(replacementBytes));
                std::memset(observedBytes, 0, sizeof(observedBytes));
                CHECK(debugger.readMemoryForSession(
                          protectionOwner.pid,
                          protectionOwner.sessionGeneration,
                          remotePage, observedBytes,
                          sizeof(observedBytes)) == sizeof(observedBytes));
                CHECK(std::memcmp(observedBytes, replacementBytes,
                                  sizeof(replacementBytes)) == 0);
                MEMORY_BASIC_INFORMATION afterAuthorizedWrite{};
                CHECK(VirtualQueryEx(protectionProcess, protectionPage,
                                     &afterAuthorizedWrite,
                                     sizeof(afterAuthorizedWrite)) ==
                      sizeof(afterAuthorizedWrite));
                CHECK(afterAuthorizedWrite.Protect == originalProtection);
            }
            CHECK(VirtualFreeEx(protectionProcess, protectionPage, 0,
                                MEM_RELEASE) != FALSE);
        }
        CloseHandle(protectionProcess);
    }

    const uint64_t scratch = debugger.allocRemote(16);
    CHECK(scratch != 0);
    if (scratch) {
        const uint8_t pristine[2] = { 0x90, 0xCC };
        CHECK(debugger.writeMemory(scratch, pristine, sizeof(pristine)) == sizeof(pristine));
        CHECK(debugger.addBreakpoint(scratch));
        debugger.cont();
        CHECK(waitBreakpointCount(debugger, 1, 2000));
        CHECK(waitBreakpointResult(debugger, scratch, true, nullptr, 2000));
        uint8_t raw = 0, masked = 0;
        CHECK(debugger.readMemory(scratch, &raw, 1) == 1 && raw == 0xCC);
        CHECK(debugger.readMemoryMasked(scratch, &masked, 1) == 1 && masked == 0x90);

        const uint8_t patched = 0xC3;
        CHECK(debugger.writeMemory(scratch, &patched, 1) == 0); // executable writes require pause
        debugger.pause();
        CHECK(waitPaused(debugger, 2000));
        CHECK(debugger.writeMemory(scratch, &patched, 1) == 1);
        CHECK(debugger.readMemory(scratch, &raw, 1) == 1 && raw == 0xCC);
        CHECK(debugger.readMemoryMasked(scratch, &masked, 1) == 1 && masked == patched);
        const DbgSnapshot pausedMutationOwner = debugger.snapshot();
        const DebugTargetIdentity pausedMutationSession{
            pausedMutationOwner.pid, pausedMutationOwner.sessionGeneration
        };
        CHECK(debugger.removeBreakpointForSession(pausedMutationSession, scratch));
        CHECK(debugger.addBreakpointForSession(pausedMutationSession, scratch, "rax == 1"));
        CHECK(debugger.setBreakpointConditionForSession(pausedMutationSession, scratch, "rax == 9"));
        CHECK(debugger.addBreakpointForSession(pausedMutationSession, scratch, "rax == 2"));
        CHECK(debugger.addBreakpointForSession(pausedMutationSession, scratch + 2));
        CHECK(debugger.removeBreakpointForSession(pausedMutationSession, scratch + 2));
        CHECK(debugger.addBreakpointForSession(pausedMutationSession, scratch + 3, "rax == 3"));
        CHECK(debugger.setBreakpointEveryNForSession(pausedMutationSession, scratch + 3, 7));
        CHECK(debugger.removeBreakpointForSession(pausedMutationSession, scratch + 3));
        CHECK(debugger.addBreakpointForSession(pausedMutationSession, scratch + 3, "rax == 4"));
        CHECK(debugger.addBreakpointForSession(pausedMutationSession, scratch + 3, "rax == 5"));
        CHECK(debugger.addBreakpoint(scratch + 4));
        CHECK(debugger.removeBreakpoint(scratch + 4));
        CHECK(debugger.addBreakpoint(scratch + 4, "rax == 6"));
        debugger.cont();
        CHECK(waitRunning(debugger, 2000));
        CHECK(waitBreakpointCount(debugger, 3, 2000));
        CHECK(debugger.hasBreakpoint(scratch) && !debugger.hasBreakpoint(scratch + 2));
        bool finalExisting = false, finalNew = false, finalLegacy = false;
        for (const auto& bp : debugger.snapshot().breakpoints) {
            finalExisting |= bp.address == scratch && bp.armed && bp.condition == "rax == 2";
            finalNew |= bp.address == scratch + 3 && bp.armed && bp.condition == "rax == 5" && bp.everyN == 0;
            finalLegacy |= bp.address == scratch + 4 && bp.armed && bp.condition == "rax == 6";
        }
        CHECK(finalExisting && finalNew && finalLegacy);
        CHECK(debugger.removeBreakpointForSession(pausedMutationSession, scratch + 3));
        CHECK(debugger.removeBreakpoint(scratch + 4));
        CHECK(waitBreakpointCount(debugger, 1, 2000));

        CHECK(debugger.removeBreakpoint(scratch));
        CHECK(waitBreakpointCount(debugger, 0, 2000));
        CHECK(debugger.readMemory(scratch, &raw, 1) == 1 && raw == patched);

        const DbgSnapshot breakpointOwner = debugger.snapshot();
        const DebugTargetIdentity breakpointSession{
            breakpointOwner.pid, breakpointOwner.sessionGeneration
        };
        CHECK(!debugger.addBreakpointForSession(
            { breakpointOwner.pid, breakpointOwner.sessionGeneration + 1 }, scratch + 1));
        CHECK(debugger.addBreakpointForSession(breakpointSession, scratch + 1, "rax == 1"));
        CHECK(waitBreakpointResult(debugger, scratch + 1, false, "native INT3", 2000));
        CHECK(!debugger.hasBreakpoint(scratch + 1)); // diagnostic, never byte ownership
        CHECK(debugger.snapshot().breakpoints.size() == 1);
        CHECK(debugger.snapshot().breakpoints.front().condition == "rax == 1");
        CHECK(!debugger.addBreakpointForSession(
            { breakpointOwner.pid, breakpointOwner.sessionGeneration + 1 }, scratch + 1));
        CHECK(waitBreakpointResult(debugger, scratch + 1, false, "native INT3", 2000));
        CHECK(debugger.readMemory(scratch + 1, &raw, 1) == 1 && raw == 0xCC);
        CHECK(debugger.readMemoryMasked(scratch + 1, &masked, 1) == 1 && masked == 0xCC);

        // Removal retires diagnostics without restoring a fabricated displaced byte.
        CHECK(debugger.removeBreakpointForSession(breakpointSession, scratch + 1));
        CHECK(waitBreakpointCount(debugger, 0, 2000));
        CHECK(debugger.readMemory(scratch + 1, &raw, 1) == 1 && raw == 0xCC);

        // A corrected native-INT3 site can be retried normally. The successful
        // record replaces the old failure instead of duplicating/shadowing it.
        CHECK(debugger.addBreakpointForSession(breakpointSession, scratch + 1));
        CHECK(waitBreakpointResult(debugger, scratch + 1, false, "native INT3", 2000));
        debugger.pause();
        CHECK(waitPaused(debugger, 2000));
        const uint8_t corrected = 0x90;
        CHECK(debugger.writeMemory(scratch + 1, &corrected, 1) == 1);
        CHECK(debugger.addBreakpointForSession(breakpointSession, scratch + 1));
        CHECK(debugger.snapshot().breakpoints.empty()); // queued retry cannot expose the prior failure
        debugger.cont();
        CHECK(waitBreakpointResult(debugger, scratch + 1, true, nullptr, 2000));
        CHECK(debugger.snapshot().breakpoints.size() == 1);
        CHECK(debugger.hasBreakpoint(scratch + 1));
        CHECK(debugger.readMemory(scratch + 1, &raw, 1) == 1 && raw == 0xCC);
        CHECK(debugger.readMemoryMasked(scratch + 1, &masked, 1) == 1 && masked == corrected);
        CHECK(debugger.removeBreakpointForSession(breakpointSession, scratch + 1));
        CHECK(waitBreakpointCount(debugger, 0, 2000));
        CHECK(debugger.readMemory(scratch + 1, &raw, 1) == 1 && raw == corrected);

        CHECK(debugger.addBreakpointForSession(breakpointSession, 1));
        CHECK(waitBreakpointResult(debugger, 1, false, "unreadable", 2000));
        CHECK(!debugger.hasBreakpoint(1));
    } else {
        debugger.cont();
    }

    // Detach while running used to leave Cmd::Detach queued. Reusing the same
    // Debugger must start a new epoch that remains paused at its first stop.
    debugger.detach();
    error.clear();
    CHECK(launchSelf(debugger, self, error));
    CHECK(waitPaused(debugger, 8000));
    const DbgSnapshot generationB = debugger.snapshot();
    CHECK(generationB.sessionGeneration != generationA);
    CHECK(generationB.breakpoints.empty()); // old-session installation failures are retired
    const std::vector<uint8_t> detachOwnedText{
        's','u','r','v','i','v','e','s',' ','d','e','t','a','c','h',0
    };
    uint64_t detachOwnedAddress = 0;
    std::string detachOwnedError;
    const bool detachOwnedSet = debugger.setRegisterToBufferForSession(
        generationB.pid, generationB.sessionGeneration, generationB.activeTid,
        "rax", detachOwnedText, detachOwnedAddress, &detachOwnedError);
    CHECK(detachOwnedSet);
    HANDLE detachOwnedProcess = static_cast<HANDLE>(
        debugger.duplicateProcessHandleForSession(
            { generationB.pid, generationB.sessionGeneration }));
    CHECK(detachOwnedProcess != nullptr);
    if (detachOwnedSet)
        CHECK(debugger.setRegisterForSession(
            generationB.pid, generationB.sessionGeneration,
            "rax", generationB.regs.rax));
    Sleep(250);
    CHECK(debugger.snapshot().state == DbgState::Paused);
    debugger.detach();
    if (detachOwnedProcess && detachOwnedAddress) {
        std::vector<uint8_t> afterDetach(detachOwnedText.size());
        SIZE_T readAfterDetach = 0;
        CHECK(ReadProcessMemory(detachOwnedProcess,
                                reinterpret_cast<const void*>(detachOwnedAddress),
                                afterDetach.data(), afterDetach.size(),
                                &readAfterDetach) != FALSE);
        CHECK(readAfterDetach == afterDetach.size());
        CHECK(afterDetach == detachOwnedText);
    }
    if (detachOwnedProcess) CloseHandle(detachOwnedProcess);

    // Attach to an already-running, genuinely multithreaded target. Both workers
    // execute the same CALL site: Step Over and Step Out must remain owned by the
    // thread that stopped, while peer threads are held through each process-wide
    // software-breakpoint exposure/re-arm window. This session also covers HW
    // execute breakpoints and queued running-state data writes.
    PROCESS_INFORMATION fixtureProcess{};
    HANDLE fixtureReady = nullptr;
    const bool fixtureStarted = spawnAttachFixture(self, fixtureProcess, fixtureReady);
    CHECK(fixtureStarted);
    if (fixtureStarted) {
        error.clear();
        const bool attached = debugger.attach(fixtureProcess.dwProcessId, error);
        CHECK(attached);
        CHECK(attached && waitPaused(debugger, 8000));
        if (attached && debugger.snapshot().state == DbgState::Paused) {
            const DbgSnapshot initial = debugger.snapshot();
            CHECK(initial.threads.size() >= 3); // main + both hot-loop workers

            const uint8_t* localCall = directFixtureCall();
            CHECK(localCall != nullptr);
            const uint64_t callAddress = localCall ? remoteAddress(initial, localCall) : 0;
            const uint64_t callReturn = callAddress ? callAddress + 5 : 0;
            const uint64_t leafAddress = remoteAddress(initial,
                reinterpret_cast<const void*>(&fixtureLeaf));
            const uint64_t dataAddress = remoteAddress(initial,
                const_cast<const LONG*>(&g_fixtureScratch));
            const uint64_t stopAddress = remoteAddress(initial,
                const_cast<const LONG*>(&g_fixtureStop));
            CHECK(callAddress && leafAddress && dataAddress && stopAddress);

            if (callAddress && leafAddress && dataAddress && stopAddress) {
                const DebugTargetIdentity fixtureSession{ initial.pid, initial.sessionGeneration };
                CHECK(!debugger.addBreakpointForSession(
                    { initial.pid, initial.sessionGeneration + 1 }, callAddress));
                CHECK(debugger.addBreakpointForSession(fixtureSession, callAddress));
                debugger.cont();
                CHECK(waitSoftwareStop(debugger, callAddress, 1, 5000));
                const uint32_t stepOverOwner = debugger.snapshot().activeTid;
                CHECK(stepOverOwner != 0);
                const DbgSnapshot runToOwner = debugger.snapshot();
                std::string runToError;
                constexpr uint64_t checkedRunToToken = UINT64_C(0xA117);
                CHECK(!debugger.runToCursorForSession(
                    { runToOwner.pid, runToOwner.sessionGeneration + 1 },
                    stepOverOwner, callReturn, checkedRunToToken,
                    &runToError));
                CHECK(!runToError.empty());
                CHECK(!debugger.runToCursorForSession(
                    { runToOwner.pid, runToOwner.sessionGeneration },
                    stepOverOwner ^ 0x80000000u, callReturn,
                    checkedRunToToken, &runToError));
                CHECK(!runToError.empty());
                CHECK(!debugger.runToCursorForSession(
                    { runToOwner.pid, runToOwner.sessionGeneration },
                    stepOverOwner, dataAddress, checkedRunToToken,
                    &runToError));
                CHECK(!runToError.empty());
                debugger.runToCursor(1); // unmapped: debug-thread arming must fail closed
                CHECK(waitPausedEvent(debugger, "run to cursor failed", 2000));
                const DbgSnapshot failedRunTo = debugger.snapshot();
                CHECK(failedRunTo.state == DbgState::Paused);
                CHECK(failedRunTo.regs.rip == callAddress);
                CHECK(failedRunTo.activeTid == stepOverOwner);
                CHECK(failedRunTo.lastEvent.find("target remains paused") != std::string::npos);
                CHECK(debugger.runToCursorForSession(
                    { runToOwner.pid, runToOwner.sessionGeneration },
                    stepOverOwner, callReturn, checkedRunToToken,
                    &runToError));
                CHECK(runToError.empty());
                uint64_t queuedRunToRevision = 0;
                CheckedRunToState queuedRunToState =
                    CheckedRunToState::None;
                {
                    const DbgSnapshot queuedRunTo = debugger.snapshot();
                    queuedRunToRevision =
                        queuedRunTo.checkedRunTo.revision;
                    queuedRunToState = queuedRunTo.checkedRunTo.state;
                    CHECK(queuedRunTo.checkedRunTo.requestToken ==
                          checkedRunToToken);
                    CHECK(queuedRunTo.checkedRunTo.revision != 0);
                    CHECK(queuedRunTo.checkedRunTo.target.pid ==
                          runToOwner.pid);
                    CHECK(queuedRunTo.checkedRunTo.target.sessionGeneration ==
                          runToOwner.sessionGeneration);
                    CHECK(queuedRunTo.checkedRunTo.tid == stepOverOwner);
                    CHECK(queuedRunTo.checkedRunTo.address == callReturn);
                    CHECK(queuedRunTo.checkedRunTo.state ==
                              CheckedRunToState::Pending ||
                          queuedRunTo.checkedRunTo.state ==
                              CheckedRunToState::Armed ||
                          queuedRunTo.checkedRunTo.state ==
                              CheckedRunToState::Hit);
                }
                const bool checkedRunToArrived = waitPausedAt(debugger, callReturn, 5000, stepOverOwner);
                if (!checkedRunToArrived) {
                    const DbgSnapshot failed = debugger.snapshot();
                    std::printf("[diag] checked RunTo state=%u tid=%u expectedTid=%u rip=0x%llX expectedRip=0x%llX outcome=%u error=%s event=%s\n",
                        static_cast<unsigned>(failed.state), failed.activeTid, stepOverOwner,
                        static_cast<unsigned long long>(failed.regs.rip),
                        static_cast<unsigned long long>(callReturn),
                        static_cast<unsigned>(failed.checkedRunTo.state),
                        failed.checkedRunTo.error.c_str(), failed.lastEvent.c_str());
                }
                CHECK(checkedRunToArrived);
                {
                    const DbgSnapshot hitRunTo = debugger.snapshot();
                    CHECK(hitRunTo.checkedRunTo.requestToken ==
                          checkedRunToToken);
                    CHECK(hitRunTo.checkedRunTo.state ==
                          CheckedRunToState::Hit);
                    CHECK(hitRunTo.checkedRunTo.revision != 0);
                    CHECK(hitRunTo.checkedRunTo.revision >=
                          queuedRunToRevision);
                    if (queuedRunToState != CheckedRunToState::Hit)
                        CHECK(hitRunTo.checkedRunTo.revision >
                              queuedRunToRevision);
                    CHECK(hitRunTo.checkedRunTo.error.empty());
                }

                uint8_t physical = 0, logical = 0;
                CHECK(debugger.readMemory(callAddress, &physical, 1) == 1 &&
                      physical == 0xCC); // user bp re-armed after the owner returned
                CHECK(debugger.readMemoryMasked(callAddress, &logical, 1) == 1 &&
                      logical == 0xE8);

                CHECK(debugger.removeBreakpoint(callAddress));
                CHECK(debugger.addBreakpoint(leafAddress));
                debugger.cont();
                const bool leafStopped = waitSoftwareStop(debugger, leafAddress, 1, 5000);
                if (!leafStopped) {
                    DWORD exitCode = STILL_ACTIVE;
                    GetExitCodeProcess(fixtureProcess.hProcess, &exitCode);
                    const auto failed = debugger.snapshot();
                    std::printf("[diag] leaf stop state=%u rip=0x%llX leaf=0x%llX call=0x%llX return=0x%llX exit=0x%lX event=%s\n",
                        static_cast<unsigned>(failed.state), static_cast<unsigned long long>(failed.regs.rip),
                        static_cast<unsigned long long>(leafAddress), static_cast<unsigned long long>(callAddress),
                        static_cast<unsigned long long>(callReturn), static_cast<unsigned long>(exitCode),
                        failed.lastEvent.c_str());
                }
                CHECK(leafStopped);
                const uint32_t stepOutOwner = debugger.snapshot().activeTid;
                CHECK(stepOutOwner != 0);
                debugger.stepOut();
                CHECK(waitPausedAt(debugger, callReturn, 5000, stepOutOwner));

                CHECK(debugger.removeBreakpoint(leafAddress));
                CHECK(!debugger.addHardwareBreakpointForSession(
                    { initial.pid, initial.sessionGeneration + 1 }, callAddress, HwKind::Execute, 1));
                CHECK(debugger.addHardwareBreakpointForSession(
                    fixtureSession, callAddress, HwKind::Execute, 1));
                debugger.cont();
                CHECK(waitPausedAt(debugger, callAddress, 5000));
                const DbgSnapshot hardwareStop = debugger.snapshot();
                CHECK(hardwareStop.lastEvent.find("hw breakpoint") != std::string::npos);
                CHECK(hardwareStop.hwBreakpoints.size() == 1);
                if (hardwareStop.hwBreakpoints.size() == 1) {
                    CHECK(hardwareStop.hwBreakpoints.front().address == callAddress);
                    CHECK(hardwareStop.hwBreakpoints.front().kind == HwKind::Execute);
                    CHECK(hardwareStop.hwBreakpoints.front().size == 1);
                }
                CHECK(debugger.removeHardwareBreakpoint(callAddress));
                debugger.cont();
                CHECK(waitRunning(debugger, 2000));

                const LONG dataPatch = 0x2468ACE;
                CHECK(debugger.writeMemoryForSession(
                          initial.pid, initial.sessionGeneration, dataAddress,
                          &dataPatch, sizeof(dataPatch)) == sizeof(dataPatch));
                LONG dataRead = 0;
                CHECK(debugger.readMemory(dataAddress, &dataRead, sizeof(dataRead)) ==
                      sizeof(dataRead) && dataRead == dataPatch);
                CHECK(debugger.snapshot().state == DbgState::Running);

                debugger.pause();
                CHECK(waitPaused(debugger, 3000));
                const LONG stop = 1;
                CHECK(debugger.writeMemory(stopAddress, &stop, sizeof(stop)) == sizeof(stop));
                debugger.cont();
                CHECK(waitTerminated(debugger, 8000));
            }
        }
        debugger.detach();
        if (WaitForSingleObject(fixtureProcess.hProcess, 1000) == WAIT_TIMEOUT)
            TerminateProcess(fixtureProcess.hProcess, 1);
        WaitForSingleObject(fixtureProcess.hProcess, 2000);
        CloseHandle(fixtureProcess.hProcess);
        CloseHandle(fixtureReady);
    }

    // Detach may race the first trace hit while another worker has already
    // queued the same INT3. Drain those exact events before surrendering the
    // debugger, then prove both the process and its workload keep running.
    for (int attempt = 0; attempt < 3; ++attempt) {
        PROCESS_INFORMATION traceProcess{};
        HANDLE traceReady = nullptr;
        const bool traceStarted = spawnAttachFixture(self, traceProcess, traceReady);
        CHECK(traceStarted);
        if (!traceStarted) continue;
        error.clear();
        const bool attached = debugger.attach(traceProcess.dwProcessId, error);
        CHECK(attached && waitPaused(debugger, 8000));
        uint64_t stopAddress = 0;
        uint64_t hitsAddress = 0;
        if (attached && debugger.snapshot().state == DbgState::Paused) {
            const auto owner = debugger.snapshot();
            const uint8_t* localCall = directFixtureCall();
            const uint64_t call = localCall ? remoteAddress(owner, localCall) : 0;
            const uint64_t leaf = remoteAddress(owner, reinterpret_cast<const void*>(&fixtureLeaf));
            stopAddress = remoteAddress(owner, const_cast<const LONG*>(&g_fixtureStop));
            hitsAddress = remoteAddress(owner, const_cast<const LONG*>(&g_fixtureHits));
            CHECK(call && leaf && stopAddress && hitsAddress);
            if (call && leaf) {
                const DebugTargetIdentity traceSession{owner.pid, owner.sessionGeneration};
                // Start + Continue in one control epoch must arm the full plan
                // before either hot worker resumes. One-shot hits stay invisible
                // and each pristine instruction remains executable afterwards.
                for (int iteration = 0; iteration < 4; ++iteration) {
                    CHECK(debugger.startTraceCoverageForSession(traceSession,
                        {call, leaf, call + 5}));
                    debugger.cont();
                    bool traced = false;
                    for (int elapsed = 0; elapsed < 4000; elapsed += 5) {
                        const auto coverage = debugger.traceCoverageSnapshot();
                        const auto state = debugger.snapshot().state;
                        if (coverage.hitSites == 3 && coverage.armedSites == 0 &&
                            state == DbgState::Running) {
                            traced = true;
                            break;
                        }
                        if (state == DbgState::Terminated || state == DbgState::Detached) break;
                        Sleep(5);
                    }
                    if (!traced) {
                        const auto failed = debugger.snapshot();
                        const auto coverage = debugger.traceCoverageSnapshot();
                        DWORD exitCode = STILL_ACTIVE;
                        GetExitCodeProcess(traceProcess.hProcess, &exitCode);
                        std::printf("[diag] trace iteration=%d state=%u hits=%zu armed=%zu exit=0x%lX exception=0x%X at=0x%llX event=%s\n",
                            iteration, static_cast<unsigned>(failed.state), coverage.hitSites,
                            coverage.armedSites, static_cast<unsigned long>(exitCode),
                            failed.exceptionCode, static_cast<unsigned long long>(failed.exceptionAddress),
                            failed.lastEvent.c_str());
                    }
                    CHECK(traced);
                    if (!traced) break;
                    debugger.pause();
                    CHECK(waitPaused(debugger, 3000));
                    CHECK(debugger.stopTraceCoverageForSession(traceSession));
                    uint8_t actualCall = 0;
                    CHECK(debugger.readMemory(call, &actualCall, 1) == 1 && actualCall == 0xE8);
                    CHECK(debugger.traceCoverageSnapshot().blockHitTotal >= 3);
                }

                CHECK(debugger.startTraceCoverageForSession(
                    {owner.pid, owner.sessionGeneration}, {call, leaf, call + 5}));
                debugger.cont();
                const ULONGLONG deadline = GetTickCount64() + 4000;
                bool sawHit = false;
                do {
                    if (debugger.traceCoverageSnapshot().hitSites) { sawHit = true; break; }
                    SwitchToThread();
                } while (GetTickCount64() < deadline);
                CHECK(sawHit);
            }
        }
        debugger.detach();
        CHECK(debugger.snapshot().lastEvent.find("queued trace") == std::string::npos);
        CHECK(WaitForSingleObject(traceProcess.hProcess, 100) == WAIT_TIMEOUT);
        LONG beforeHits = 0, afterHits = 0;
        SIZE_T read = 0;
        CHECK(hitsAddress && ReadProcessMemory(traceProcess.hProcess, (LPCVOID)hitsAddress,
            &beforeHits, sizeof(beforeHits), &read) && read == sizeof(beforeHits));
        Sleep(50);
        CHECK(hitsAddress && ReadProcessMemory(traceProcess.hProcess, (LPCVOID)hitsAddress,
            &afterHits, sizeof(afterHits), &read) && read == sizeof(afterHits));
        CHECK(afterHits > beforeHits);
        const LONG stop = 1;
        SIZE_T wrote = 0;
        CHECK(stopAddress && WriteProcessMemory(traceProcess.hProcess, (LPVOID)stopAddress,
            &stop, sizeof(stop), &wrote) && wrote == sizeof(stop));
        const bool exited = WaitForSingleObject(traceProcess.hProcess, 5000) == WAIT_OBJECT_0;
        CHECK(exited);
        DWORD exitCode = STILL_ACTIVE;
        if (!GetExitCodeProcess(traceProcess.hProcess, &exitCode) || exitCode != 0)
            std::printf("[diag] trace detach attempt=%d exit=0x%lX event=%s beforeHits=%ld afterHits=%ld\n",
                attempt, static_cast<unsigned long>(exitCode), debugger.snapshot().lastEvent.c_str(),
                static_cast<long>(beforeHits), static_cast<long>(afterHits));
        CHECK(GetExitCodeProcess(traceProcess.hProcess, &exitCode) && exitCode == 0);
        if (!exited) {
            TerminateProcess(traceProcess.hProcess, 1);
            WaitForSingleObject(traceProcess.hProcess, 2000);
        }
        CloseHandle(traceProcess.hProcess);
        CloseHandle(traceReady);
    }

    // Removing a user breakpoint parked on a shared network-probe byte while
    // stopping Server Watch in the same resume must retire both owners cleanly.
    // The original instruction should run once with no spurious transition
    // pause and no attempt to re-arm the now-retired internal probe.
    error.clear();
    CHECK(launchSelf(debugger, self, error, "4"));
    CHECK(waitPaused(debugger, 8000));
    if (debugger.snapshot().state == DbgState::Paused) {
        const uint64_t sharedWinHttpSend = remoteSystemExport(
            debugger.snapshot(), "winhttp.dll", "WinHttpSendRequest");
        CHECK(sharedWinHttpSend != 0);
        debugger.startNetworkObservation();
        if (sharedWinHttpSend) {
            CHECK(debugger.addBreakpoint(sharedWinHttpSend));
            debugger.cont();
            const bool parked = waitSoftwareStop(
                debugger, sharedWinHttpSend, 1, 8000);
            CHECK(parked);
            if (parked) {
                CHECK(debugger.removeBreakpoint(sharedWinHttpSend));
                debugger.stopNetworkObservation();
                debugger.cont();
                const bool completedWithoutTransitionPause =
                    waitTerminated(debugger, 15000);
                if (!completedWithoutTransitionPause) {
                    const DbgSnapshot stuck = debugger.snapshot();
                    std::printf("[diag] shared-stop state=%u event=%s rip=0x%llX\n",
                                static_cast<unsigned>(stuck.state),
                                stuck.lastEvent.c_str(),
                                static_cast<unsigned long long>(stuck.regs.rip));
                }
                CHECK(completedWithoutTransitionPause);
            }
        }
    }
    debugger.detach();

    // Guided network observation must remain invisible to the analyst's normal
    // breakpoint list while collecting a complete local hosted-reply exchange.
    error.clear();
    CHECK(launchSelf(debugger, self, error, "4"));
    CHECK(waitPaused(debugger, 8000));
    char observationTemp[MAX_PATH]{};
    char observationLog[MAX_PATH]{};
    const DWORD observationTempLength = GetTempPathA(MAX_PATH, observationTemp);
    const bool observationLogReady = observationTempLength > 0 &&
        observationTempLength < MAX_PATH &&
        GetTempFileNameA(observationTemp, "dsn", 0, observationLog) != 0;
    CHECK(observationLogReady);
    if (observationLogReady)
        CHECK(debugger.setNetCaptureLogFile(observationLog, false, &error));
    if (debugger.snapshot().state == DbgState::Paused) {
        debugger.startNetworkObservation();
        debugger.cont();
        NetworkObservation observation;
        for (int elapsed = 0; elapsed < 12000; elapsed += 10) {
            observation = debugger.networkObservationSnapshot();
            bool sawQuery = false, sawReply = false, sawHttpReply = false,
                 sawInetReply = false;
            uint64_t waitSession = 0, waitConnection = 0, waitRequest = 0;
            uint64_t waitInetSession = 0, waitInetConnection = 0, waitInetRequest = 0;
            bool waitSessionClosed = false, waitConnectionClosed = false,
                 waitRequestClosed = false;
            bool waitInetSessionClosed = false, waitInetConnectionClosed = false,
                 waitInetRequestClosed = false;
            for (const NetworkObservationEvent& event : observation.events) {
                const std::string payload(event.payload.begin(), event.payload.end());
                sawQuery |= event.stage == NetworkObservationStage::Send &&
                            payload.find("crackme-query") != std::string::npos;
                sawReply |= event.stage == NetworkObservationStage::Receive &&
                            payload.find("hosted-reply") != std::string::npos;
                sawHttpReply |= event.api == NetworkProbeApi::WinHttpReadData &&
                                payload.find("hosted-http-reply") != std::string::npos;
                sawInetReply |= event.api == NetworkProbeApi::InternetReadFile &&
                                payload.find("hosted-wininet-reply") != std::string::npos;
                if (event.api == NetworkProbeApi::WinHttpOpen && event.handle && !waitSession)
                    waitSession = event.handle;
                else if (event.api == NetworkProbeApi::WinHttpConnect && event.handle &&
                         event.hostname == "127.0.0.1")
                    waitConnection = event.handle;
                else if (event.api == NetworkProbeApi::WinHttpOpenRequest && event.handle &&
                         event.object == "/serial-check")
                    waitRequest = event.handle;
                else if (event.api == NetworkProbeApi::WinHttpCloseHandle &&
                         event.stage == NetworkObservationStage::HandleClosed) {
                    waitSessionClosed |= event.handle == waitSession;
                    waitConnectionClosed |= event.handle == waitConnection;
                    waitRequestClosed |= event.handle == waitRequest;
                }
                if (event.api == NetworkProbeApi::InternetOpenW && event.handle &&
                    !waitInetSession)
                    waitInetSession = event.handle;
                else if (event.api == NetworkProbeApi::InternetConnectW && event.handle &&
                         event.hostname == "127.0.0.1")
                    waitInetConnection = event.handle;
                else if (event.api == NetworkProbeApi::HttpOpenRequestW && event.handle &&
                         event.path == "/wininet-check")
                    waitInetRequest = event.handle;
                else if (event.api == NetworkProbeApi::InternetCloseHandle &&
                         event.stage == NetworkObservationStage::HandleClosed) {
                    waitInetSessionClosed |= event.handle == waitInetSession;
                    waitInetConnectionClosed |= event.handle == waitInetConnection;
                    waitInetRequestClosed |= event.handle == waitInetRequest;
                }
            }
            if (sawQuery && sawReply && sawHttpReply && waitSessionClosed &&
                waitConnectionClosed && waitRequestClosed && sawInetReply &&
                waitInetSessionClosed && waitInetConnectionClosed &&
                waitInetRequestClosed) break;
            Sleep(10);
        }
        CHECK(observation.coverage.requested);
        CHECK(observation.coverage.active);
        CHECK(!observation.coverage.wow64);
        CHECK(observation.coverage.winsock);
        CHECK(observation.coverage.nameResolution);
        CHECK(observation.coverage.handleStatesDropped == 0);
        CHECK(debugger.snapshot().breakpoints.empty());
        bool resolved = false, resolvedStructured = false, connected = false;
        bool sent = false, received = false;
        uint64_t httpSession = 0, httpConnection = 0, httpRequest = 0;
        uint64_t openSequence = 0, connectSequence = 0, requestSequence = 0;
        uint64_t sendSequence = 0, responseSequence = 0, readSequence = 0;
        bool httpSent = false, httpResponded = false, httpRead = false;
        bool failedWinHttpSendHonest = false, failedWinInetSendHonest = false;
        bool failedWinHttpWriteHonest = false, failedWinInetWriteHonest = false;
        bool failedWinHttpReadHonest = false, failedWinInetReadHonest = false;
        bool failedWinInetReadExHonest = false;
        bool failedWinHttpQueryHonest = false, failedWinInetQueryHonest = false;
        size_t exactHttpSendCount = 0;
        bool closedRequest = false, closedConnection = false, closedSession = false;
        bool validHttpCallerMapping = false;
        uint64_t inetSession = 0, inetConnection = 0, inetRequest = 0;
        uint64_t inetOpenSequence = 0, inetConnectSequence = 0,
                 inetRequestSequence = 0, inetSendSequence = 0, inetReadSequence = 0;
        bool inetSent = false, inetRead = false;
        bool inetClosedRequest = false, inetClosedConnection = false,
             inetClosedSession = false;
        for (const NetworkObservationEvent& event : observation.events) {
            const std::string payload(event.payload.begin(), event.payload.end());
            failedWinHttpSendHonest |= event.api == NetworkProbeApi::WinHttpSendRequest &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == sizeof("failed-winhttp-inline") - 1 &&
                event.transferred == 0 && payload == "failed-winhttp-inline";
            failedWinInetSendHonest |= event.api == NetworkProbeApi::HttpSendRequestW &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == sizeof("failed-wininet-inline") - 1 &&
                event.transferred == 0 && payload == "failed-wininet-inline";
            failedWinHttpWriteHonest |= event.api == NetworkProbeApi::WinHttpWriteData &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == sizeof("failed-winhttp-write") - 1 &&
                event.transferred == 0 && payload == "failed-winhttp-write";
            failedWinInetWriteHonest |= event.api == NetworkProbeApi::InternetWriteFile &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == sizeof("failed-wininet-write") - 1 &&
                event.transferred == 0 && payload == "failed-wininet-write";
            failedWinHttpReadHonest |= event.api == NetworkProbeApi::WinHttpReadData &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == 17 && event.transferred == 0 && payload.empty();
            failedWinInetReadHonest |= event.api == NetworkProbeApi::InternetReadFile &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == 19 && event.transferred == 0 && payload.empty();
            failedWinInetReadExHonest |= event.api == NetworkProbeApi::InternetReadFileExW &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == 23 && event.transferred == 0 && payload.empty();
            failedWinHttpQueryHonest |= event.api == NetworkProbeApi::WinHttpQueryHeaders &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == 29 && event.transferred == 0 && payload.empty();
            failedWinInetQueryHonest |= event.api == NetworkProbeApi::HttpQueryInfoW &&
                event.handle == 0 && event.result == 0 &&
                event.requestedBytes == 31 && event.transferred == 0 && payload.empty();
            resolved |= event.stage == NetworkObservationStage::NameResolution &&
                        event.hostname == "localhost";
            resolvedStructured |= event.stage == NetworkObservationStage::NameResolution &&
                                  event.hostname == "localhost" && !event.ip.empty();
            connected |= event.stage == NetworkObservationStage::Connect &&
                         event.direction == NetworkDirection::Outbound && !event.endpoint.empty() &&
                         event.ip == "127.0.0.1" && event.portValid && event.port != 0;
            sent |= event.stage == NetworkObservationStage::Send &&
                    event.direction == NetworkDirection::Outbound &&
                    event.ip == "127.0.0.1" && event.portValid && event.port != 0 &&
                    payload.find("crackme-query") != std::string::npos;
            received |= event.stage == NetworkObservationStage::Receive &&
                        event.direction == NetworkDirection::Inbound &&
                        event.ip == "127.0.0.1" && event.portValid && event.port != 0 &&
                        payload.find("hosted-reply") != std::string::npos;
            if (event.api == NetworkProbeApi::WinHttpOpen && event.handle && !httpSession) {
                httpSession = event.handle;
                openSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::WinHttpConnect && event.handle &&
                       event.hostname == "127.0.0.1" && event.ip == "127.0.0.1" &&
                       event.portValid && event.port != 0 && !event.endpoint.empty()) {
                httpConnection = event.handle;
                connectSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::WinHttpOpenRequest && event.handle &&
                       event.method == "POST" && event.object == "/serial-check" &&
                       event.path == "/serial-check" &&
                       event.hostname == "127.0.0.1") {
                httpRequest = event.handle;
                requestSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::WinHttpSendRequest &&
                       event.handle == httpRequest && event.method == "POST" &&
                       event.object == "/serial-check" &&
                       event.path == "/serial-check" && event.ip == "127.0.0.1" &&
                       event.portValid && event.port != 0 &&
                       payload == "serial=crackme-query" && !event.payloadOpaque &&
                       event.requestedBytes == sizeof("serial=crackme-query") - 1 &&
                       event.transferred == 0 &&
                       !event.asyncPartial &&
                       event.detail.find("Content-Type: application/x-www-form-urlencoded") !=
                           std::string::npos) {
                httpSent = true;
                ++exactHttpSendCount;
                sendSequence = event.sequence;
                validHttpCallerMapping |= event.fileOffsetValid &&
                    event.evidenceQuality == NetworkEvidenceQuality::Observed &&
                    event.mappingEvidence.find("identity/extent not proven") !=
                        std::string::npos && !event.runtimeModule.empty();
            } else if (event.api == NetworkProbeApi::WinHttpReceiveResponse &&
                       event.handle == httpRequest && event.result != 0 &&
                       event.method == "POST" && event.object == "/serial-check") {
                httpResponded = true;
                responseSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::WinHttpReadData &&
                       event.handle == httpRequest &&
                       payload.find("hosted-http-reply:accepted") != std::string::npos &&
                       event.path == "/serial-check" && event.ip == "127.0.0.1" &&
                       event.portValid && event.port != 0 &&
                       !event.payloadOpaque && !event.asyncPartial) {
                httpRead = true;
                readSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::WinHttpCloseHandle &&
                       event.stage == NetworkObservationStage::HandleClosed && event.result != 0) {
                closedRequest |= event.handle == httpRequest && event.method == "POST" &&
                                 event.object == "/serial-check";
                closedConnection |= event.handle == httpConnection &&
                                    event.hostname == "127.0.0.1";
                closedSession |= event.handle == httpSession;
            }
            if (event.api == NetworkProbeApi::InternetOpenW && event.handle && !inetSession) {
                inetSession = event.handle;
                inetOpenSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::InternetConnectW && event.handle &&
                       event.hostname == "127.0.0.1" && event.ip == "127.0.0.1" &&
                       event.portValid && event.port != 0) {
                inetConnection = event.handle;
                inetConnectSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::HttpOpenRequestW && event.handle &&
                       event.method == "POST" && event.path == "/wininet-check" &&
                       event.ip == "127.0.0.1" && event.portValid) {
                inetRequest = event.handle;
                inetRequestSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::HttpSendRequestW &&
                       event.handle == inetRequest && event.path == "/wininet-check" &&
                       payload == "serial=wininet-query" &&
                       event.requestedBytes == sizeof("serial=wininet-query") - 1 &&
                       event.transferred == 0 && !event.asyncPartial) {
                inetSent = true;
                inetSendSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::InternetReadFile &&
                       event.handle == inetRequest && event.path == "/wininet-check" &&
                       payload.find("hosted-wininet-reply:accepted") != std::string::npos &&
                       !event.asyncPartial) {
                inetRead = true;
                inetReadSequence = event.sequence;
            } else if (event.api == NetworkProbeApi::InternetCloseHandle &&
                       event.stage == NetworkObservationStage::HandleClosed && event.result != 0) {
                inetClosedRequest |= event.handle == inetRequest &&
                                     event.path == "/wininet-check";
                inetClosedConnection |= event.handle == inetConnection &&
                                         event.hostname == "127.0.0.1";
                inetClosedSession |= event.handle == inetSession;
            }
        }
        CHECK(resolved);
        CHECK(resolvedStructured);
        CHECK(connected);
        CHECK(sent);
        CHECK(received);
        CHECK(observation.coverage.winHttp);
        CHECK(observation.coverage.winInet);
        CHECK(httpSession && httpConnection && httpRequest);
        CHECK(httpSession != httpConnection && httpConnection != httpRequest &&
              httpSession != httpRequest);
        CHECK(httpSent);
        if (!failedWinHttpSendHonest || !failedWinInetSendHonest) {
            for (const NetworkObservationEvent& event : observation.events) {
                if (event.api != NetworkProbeApi::WinHttpSendRequest &&
                    event.api != NetworkProbeApi::HttpSendRequestW) continue;
                const std::string payload(event.payload.begin(), event.payload.end());
                std::printf("[diag] failed-send api=%u handle=0x%llX result=%lld requested=%llu transferred=%u payload=%s\n",
                            static_cast<unsigned>(event.api),
                            static_cast<unsigned long long>(event.handle),
                            static_cast<long long>(event.result),
                            static_cast<unsigned long long>(event.requestedBytes),
                            event.transferred, payload.c_str());
            }
        }
        CHECK(failedWinHttpSendHonest);
        CHECK(failedWinInetSendHonest);
        CHECK(failedWinHttpWriteHonest);
        CHECK(failedWinInetWriteHonest);
        CHECK(failedWinHttpReadHonest);
        CHECK(failedWinInetReadHonest);
        CHECK(failedWinInetReadExHonest);
        CHECK(failedWinHttpQueryHonest);
        CHECK(failedWinInetQueryHonest);
        CHECK(exactHttpSendCount == 1);
        CHECK(httpResponded);
        CHECK(httpRead);
        if (!(closedRequest && closedConnection && closedSession)) {
            std::printf("[diag] WinHTTP handles session=0x%llX connection=0x%llX request=0x%llX\n",
                        static_cast<unsigned long long>(httpSession),
                        static_cast<unsigned long long>(httpConnection),
                        static_cast<unsigned long long>(httpRequest));
            for (const NetworkObservationEvent& event : observation.events) {
                if (event.api < NetworkProbeApi::WinHttpOpen ||
                    event.api > NetworkProbeApi::WinHttpCloseHandle) continue;
                std::printf("[diag] api=%u stage=%u handle=0x%llX result=%lld host=%s method=%s object=%s\n",
                            static_cast<unsigned>(event.api), static_cast<unsigned>(event.stage),
                            static_cast<unsigned long long>(event.handle),
                            static_cast<long long>(event.result), event.hostname.c_str(),
                            event.method.c_str(), event.object.c_str());
            }
        }
        CHECK(closedRequest && closedConnection && closedSession);
        CHECK(openSequence < connectSequence && connectSequence < requestSequence &&
              requestSequence < sendSequence && sendSequence < responseSequence &&
              responseSequence < readSequence);
        CHECK(validHttpCallerMapping);
        CHECK(inetSession && inetConnection && inetRequest);
        CHECK(inetSession != inetConnection && inetConnection != inetRequest &&
              inetSession != inetRequest);
        CHECK(inetSent && inetRead);
        CHECK(inetClosedRequest && inetClosedConnection && inetClosedSession);
        CHECK(inetOpenSequence < inetConnectSequence &&
              inetConnectSequence < inetRequestSequence &&
              inetRequestSequence < inetSendSequence &&
              inetSendSequence < inetReadSequence);
        CHECK(waitTerminated(debugger, 12000));
        debugger.startNetworkObservation();
        CHECK(!debugger.netTapEnabled());
        CHECK(!debugger.networkObservationSnapshot().coverage.requested);
    }
    debugger.closeNetCaptureLogFile();
    if (observationLogReady) {
        std::ifstream typedLog(observationLog, std::ios::binary);
        const std::string typedLogText((std::istreambuf_iterator<char>(typedLog)),
                                       std::istreambuf_iterator<char>());
        CHECK(typedLogText.find(
                  "stage=request direction=outbound api=WinHttpSendRequest") !=
              std::string::npos);
        CHECK(typedLogText.find("ip=127.0.0.1") != std::string::npos);
        CHECK(typedLogText.find("path=/serial-check") != std::string::npos);
        CHECK(typedLogText.find("serial=crackme-query") != std::string::npos);
        CHECK(typedLogText.find("api=HttpSendRequestW") != std::string::npos);
        CHECK(typedLogText.find("path=/wininet-check") != std::string::npos);
        CHECK(typedLogText.find("serial=wininet-query") != std::string::npos);
        typedLog.close();
        CHECK(DeleteFileA(observationLog) != FALSE);
    }
    debugger.detach();

    // A last-chance fault must remain inspectable before the default
    // DBG_EXCEPTION_NOT_HANDLED continuation terminates the target.
    error.clear();
    CHECK(launchSelf(debugger, self, error, "2"));
    CHECK(waitPaused(debugger, 8000));
    debugger.cont();
    CHECK(waitSecondChance(debugger, 4000));
    const DbgSnapshot crash = debugger.snapshot();
    CHECK(crash.exceptionCode == EXCEPTION_ACCESS_VIOLATION);
    CHECK(!crash.exceptionFirstChance);
    CHECK(crash.regs.rip != 0 && !crash.frames.empty());
    debugger.detach();

    if (g_fail) {
        std::printf("%d CHECK(s) FAILED\n", g_fail);
        return 1;
    }
    std::printf("x64_debug_test: all checks passed (launch/attach/detach + SW/HW bp + multithread step + local-loopback network observation + memory/exit cleanup)\n");
    return 0;
}
