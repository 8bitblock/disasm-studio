// Real nested x64 calls in our own short-lived child. No user process is used.
#include "Core/Backtrace.h"

#pragma optimize("", off)
__declspec(noinline) static LONG backtraceFixtureLeaf(LONG value) {
    return value + 17;
}
__declspec(noinline) static LONG backtraceFixtureCaller(LONG value) {
    const LONG result = backtraceFixtureLeaf(value);
    return result ^ 0x1234;
}
#pragma optimize("", on)

static int backtraceDebuggeeMain() {
    return backtraceFixtureCaller(5) == (22 ^ 0x1234) ? 0 : 1;
}

static void checkBacktraceLiveFixture(const char* self) {
    const int failuresBefore = g_fail;
    Debugger debugger;
    std::string error;
    const bool launched = launchSelf(debugger, self, error, "5");
    CHECK(launched);
    if (!launched) {
        std::printf("[backtrace] launch failed: %s\n", error.c_str());
        return;
    }
    CHECK(waitPaused(debugger, 8000));
    const auto initial = debugger.snapshot();
    HANDLE child = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, initial.pid);
    CHECK(child != nullptr);
    const DebugTargetIdentity owner{initial.pid, initial.sessionGeneration};
    const uint64_t leafEntry = remoteAddress(initial,
        reinterpret_cast<const void*>(&backtraceFixtureLeaf));
    CHECK(leafEntry && debugger.addBreakpointForSession(owner, leafEntry));
    CHECK(debugger.continueForSession(owner));
    DbgSnapshot stopped;
    bool nestedStop = false;
    for (int elapsed = 0; elapsed < 8000; elapsed += 10) {
        stopped = debugger.snapshot();
        if (stopped.state == DbgState::Paused &&
            stopped.stackRevision > initial.stackRevision &&
            stopped.regs.rip == leafEntry) {
            nestedStop = true;
            break;
        }
        Sleep(10);
    }
    CHECK(nestedStop);
    if (nestedStop) {
        CHECK(BacktraceUnwindCurrent(stopped));
        CHECK(stopped.frames.size() >= 3);
        const uint64_t leaf = remoteAddress(stopped,
            reinterpret_cast<const void*>(&backtraceFixtureLeaf));
        uint64_t callerContinuation = 0;
        const auto* callerCode = reinterpret_cast<const uint8_t*>(&backtraceFixtureCaller);
        for (size_t offset = 0; offset + 5 <= 128; ++offset) {
            if (callerCode[offset] != 0xE8) continue;
            int32_t displacement = 0;
            std::memcpy(&displacement, callerCode + offset + 1, sizeof(displacement));
            const auto destination = reinterpret_cast<uintptr_t>(callerCode + offset + 5) + displacement;
            if (destination == reinterpret_cast<uintptr_t>(&backtraceFixtureLeaf)) {
                callerContinuation = remoteAddress(stopped, callerCode + offset + 5);
                break;
            }
        }
        CHECK(callerContinuation != 0);
        bool sawCaller = false, sawLeaf = false;
        for (const auto& frame : stopped.frames) {
            sawCaller |= frame.pc == callerContinuation;
            sawLeaf |= frame.pc >= leaf && frame.pc - leaf < 128;
        }
        CHECK(sawCaller && sawLeaf);
        std::printf("[backtrace] %zu frames; current=0x%llX; nested leaf/caller=%d/%d\n",
            stopped.frames.size(), static_cast<unsigned long long>(stopped.regs.rip),
            sawLeaf, sawCaller);

        auto refresh = [&] {
            const auto before = debugger.snapshot();
            CHECK(debugger.refreshCallStackForSession(owner, stopped.activeTid));
            bool refreshed = false;
            for (int elapsed = 0; elapsed < 8000; elapsed += 10) {
                const auto after = debugger.snapshot();
                if (after.stackRevision > before.stackRevision) {
                    CHECK(after.state == DbgState::Paused);
                    CHECK(after.activeTid == stopped.activeTid);
                    CHECK(after.regs.rip == stopped.regs.rip);
                    CHECK(after.regs.rsp == stopped.regs.rsp);
                    CHECK(after.lastEvent == stopped.lastEvent);
                    CHECK(BacktraceUnwindCurrent(after));
                    CHECK(after.frames.size() >= 3);
                    refreshed = true;
                    break;
                }
                Sleep(10);
            }
            CHECK(refreshed);
        };
        CHECK(!debugger.refreshCallStackForSession(
            {owner.pid, owner.sessionGeneration + 1}, stopped.activeTid));
        CHECK(!debugger.refreshCallStackForSession(owner, stopped.activeTid + 1));
        refresh();

        // Returning a register to its old value must not resurrect a stale walk.
        CHECK(debugger.setRegisterForSession(owner.pid, owner.sessionGeneration,
            "rsp", stopped.regs.rsp + 8, stopped.activeTid, &stopped.regs.rip));
        CHECK(debugger.snapshot().frames.empty());
        CHECK(debugger.setRegisterForSession(owner.pid, owner.sessionGeneration,
            "rsp", stopped.regs.rsp, stopped.activeTid, &stopped.regs.rip));
        CHECK(debugger.snapshot().frames.empty());
        refresh();

        // Even an identical checked stack write retires the old observation.
        uint64_t stackWord = 0;
        CHECK(debugger.readMemoryForSession(owner.pid, owner.sessionGeneration,
            stopped.regs.rsp, &stackWord, sizeof(stackWord)) == sizeof(stackWord));
        CHECK(debugger.writeMemoryForSession(owner.pid, owner.sessionGeneration,
            stopped.regs.rsp, &stackWord, sizeof(stackWord)) == sizeof(stackWord));
        CHECK(debugger.snapshot().frames.empty());
        refresh();
    }
    // Reap only the self-launched fixture, including failure paths.
    if (child && WaitForSingleObject(child, 0) == WAIT_TIMEOUT)
        CHECK(TerminateProcess(child, 0) != FALSE);
    CHECK(debugger.detach());
    if (child) { WaitForSingleObject(child, 5000); CloseHandle(child); }
    CHECK(!debugger.refreshCallStackForSession(owner, stopped.activeTid));
    std::printf("[%s] native backtrace frames, refresh, retirement and ownership\n",
        g_fail == failuresBefore ? "pass" : "fail");
}
