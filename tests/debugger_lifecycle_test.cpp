// Target-free regression: no process is launched, attached, or modified.
// The sole Win32 attach failure uses UINT32_MAX (an invalid Windows PID).
#include "Core/Debugger.h"
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <thread>

namespace ds::debugger_detail {
struct LifecycleTestAccess {
    static auto holdOwner(Debugger& debugger) {
        return std::unique_lock<std::recursive_mutex>(debugger.lifecycleOwnerMtx_);
    }
    static void record(Debugger& debugger, const NetworkObservationEvent& event) {
        debugger.writeNetworkObservationLog(event);
    }
    static constexpr size_t byteCap() { return Debugger::kNetLogQueueBytes; }
    static void syntheticSession(Debugger& debugger, bool present) {
        std::lock_guard lock(debugger.mtx_);
        debugger.state_ = present ? DbgState::Paused : DbgState::Detached;
        debugger.pid_ = present ? 17 : 0;
        debugger.sessionGeneration_ = present ? 19 : 0;
    }
};
}

using namespace ds;
using Clock = std::chrono::steady_clock;
static void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
template<class Predicate> static void waitUntil(Predicate predicate, const char* message) {
    const auto deadline = Clock::now() + std::chrono::seconds(8);
    while (!predicate()) {
        check(Clock::now() < deadline, message);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}
static std::string read(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

static void regionCoverageChecks(Debugger& debugger) {
    using namespace ds::debugger_detail;
    auto region = [](uint64_t at, MemRegion& out) {
        out.base = at; out.size = 0x1000; out.state = 0x1000; out.read = true;
    };
    auto failure = CollectMemoryRegions(0xffff,
        [&](uint64_t at, MemRegion& out, std::string& error) {
            if (at == 0x2000) {
                error = "injected query failure";
                return RegionQueryStatus::Failed;
            }
            region(at, out); return RegionQueryStatus::Region;
        });
    check(!failure.complete && failure.regions.size() == 2 &&
          failure.coveredUntil == 0x2000 && failure.error == "injected query failure",
          "query failure must retain a labelled useful prefix");
    const auto capped = CollectMemoryRegions(0xffff,
        [&](uint64_t at, MemRegion& out, std::string&) {
            region(at, out); return RegionQueryStatus::Region;
        }, 2);
    check(!capped.complete && capped.regions.size() == 2 &&
          capped.coveredUntil == 0x2000 && !capped.error.empty(),
          "region cap must never report complete scope");
    const auto ended = CollectMemoryRegions(0xffff,
        [&](uint64_t at, MemRegion& out, std::string&) {
            if (at == 0x2000) return RegionQueryStatus::End;
            region(at, out); return RegionQueryStatus::Region;
        }, 2);
    check(ended.complete && ended.regions.size() == 2 && ended.error.empty(),
          "normal address-space end at the exact cap must remain complete");
    const auto bounded = CollectMemoryRegions(0x1fff,
        [&](uint64_t at, MemRegion& out, std::string&) {
            region(at, out); return RegionQueryStatus::Region;
        });
    check(bounded.complete && bounded.coveredUntil == 0x2000,
          "native address-space bound must complete normally");
    const auto invalid = CollectMemoryRegions(UINT64_MAX,
        [](uint64_t, MemRegion& out, std::string&) {
            out.base = UINT64_MAX - 5; out.size = 10;
            return RegionQueryStatus::Region;
        });
    check(!invalid.complete && invalid.regions.empty() && !invalid.error.empty(),
          "overflow/non-advancing ranges must not become complete scope");
    const auto stale = debugger.queryRegionsForSession(17, 19);
    check(!stale.complete && stale.regions.empty() && !stale.error.empty() &&
          DebugTargetIdentityMatches(stale.target, {17, 19}),
          "stale memory map request must retain identity and report failure");
}

int main() {
    try {
        Debugger debugger;
        regionCoverageChecks(debugger);
        check(debugger.requestAttach(0) == 0, "invalid PID must be rejected immediately");
        uint64_t cancelledRequest = 0;
        {
            // Keep the owner busy without invoking Windows: request/cancel/poll
            // must remain responsive while worker startup cannot yet proceed.
            auto owner = debugger_detail::LifecycleTestAccess::holdOwner(debugger);
            debugger_detail::LifecycleTestAccess::syntheticSession(debugger, true);
            const auto start = Clock::now();
            cancelledRequest = debugger.requestAttach(UINT32_MAX);
            check(cancelledRequest != 0, "attach request was not accepted");
            check(debugger.lifecycleSnapshot().state == DbgLifecycleState::Starting,
                  "queued attachment must expose Starting");
            check(debugger.requestAttach(UINT32_MAX) == 0, "queue must be single-flight");
            check(debugger.requestDetach() == 0, "detach must not replace an in-flight request");
            std::string error;
            check(!debugger.launchAndAttach("never-launched.exe", error),
                  "synchronous launch must fail fast behind queued lifecycle work");
            check(error == "debugger lifecycle is busy", "busy failure must explain the cause");
            check(!debugger.cancelLifecycle(cancelledRequest + 1), "stale cancellation accepted");
            check(debugger.cancelLifecycle(cancelledRequest), "cancellation rejected");
            check(debugger.lifecycleSnapshot().state == DbgLifecycleState::Stopping,
                  "cancellation must expose Stopping until cleanup finishes");
            check(Clock::now() - start < std::chrono::milliseconds(500),
                  "UI lifecycle APIs waited for the busy owner");
        }
        waitUntil([&] { return !debugger.lifecycleSnapshot().busy; }, "cancelled request did not finish");
        auto result = debugger.lifecycleSnapshot();
        check(result.requestId == cancelledRequest && result.completed && result.cancelled &&
              !result.succeeded && !result.target.valid(), "cancellation completion is not identity-safe");
        check(debugger.snapshot().state == DbgState::Paused && debugger.snapshot().pid == 17,
              "cancelling a queued attachment must preserve the previous session");
        debugger_detail::LifecycleTestAccess::syntheticSession(debugger, false);

        // Both launch variants return immediately even while the lifecycle owner
        // is unavailable. Cancellation before ownership never creates a target.
        for (const bool dll : {false, true}) {
            uint64_t launchId = 0;
            {
                auto owner = debugger_detail::LifecycleTestAccess::holdOwner(debugger);
                const auto start = Clock::now();
                std::string error;
                if (dll) {
                    DllDebugLaunchPlan plan;
                    plan.valid = true;
                    plan.executable = "never-launched-host.exe";
                    plan.commandLine = "never-launched-host.exe fixture.dll";
                    launchId = debugger.requestLaunchDll(plan, &error);
                    plan.commandLine.clear();
                } else {
                    DbgLaunchRequest request;
                    request.executable = "never-launched.exe";
                    request.containedJob = true;
                    request.prelaunchNetworkObservation = true;
                    launchId = debugger.requestLaunch(request, &error);
                    request.executable.clear();
                }
                check(launchId && error.empty(), "launch request was not admitted");
                const auto pending = debugger.lifecycleSnapshot();
                check(pending.busy && pending.state == DbgLifecycleState::Starting &&
                      pending.command == (dll ? DbgLifecycleCommand::LaunchDll : DbgLifecycleCommand::Launch),
                      "queued launch must publish its startup state");
                check(debugger.requestAttach(UINT32_MAX) == 0, "launch queue must be single-flight");
                check(!debugger.cancelLifecycle(launchId + 1), "stale launch cancellation accepted");
                check(debugger.cancelLifecycle(launchId), "queued launch cancellation rejected");
                check(Clock::now() - start < std::chrono::milliseconds(500),
                      "launch request/cancellation blocked behind owner");
            }
            waitUntil([&] { return !debugger.lifecycleSnapshot().busy; },
                      "cancelled launch did not finish");
            const auto cancelled = debugger.lifecycleSnapshot();
            check(cancelled.requestId == launchId && cancelled.cancelled &&
                  !cancelled.succeeded && !cancelled.target.valid(),
                  "cancelled launch acquired target authority");
        }
        {
            debugger_detail::LifecycleTestAccess::syntheticSession(debugger, true);
            std::string error;
            check(debugger.requestLaunch({"never-launched.exe"}, &error) == 0,
                  "async launch must not replace an existing attachment");
            check(!debugger.launchAndAttachDll({}, error), "invalid DLL plan accepted");
            check(debugger.snapshot().state == DbgState::Paused && debugger.snapshot().pid == 17,
                  "invalid DLL plan must not tear down the existing session");
            debugger_detail::LifecycleTestAccess::syntheticSession(debugger, false);
        }
        {
            std::string error;
            const auto missing = std::filesystem::temp_directory_path() /
                ("ds_missing_launch_" + std::to_string(Clock::now().time_since_epoch().count())) /
                "never.exe";
            check(!std::filesystem::exists(missing), "missing-executable fixture unexpectedly exists");
            const auto id = debugger.requestLaunch({missing.string()}, &error);
            check(id != 0, "invalid executable startup was not queued");
            waitUntil([&] { return !debugger.lifecycleSnapshot().busy; },
                      "invalid executable startup did not finish");
            const auto failed = debugger.lifecycleSnapshot();
            check(failed.requestId == id && failed.completed && !failed.succeeded &&
                  !failed.cancelled && !failed.target.valid() && !failed.error.empty(),
                  "launch failure must retain an actionable completion");
        }

        const auto failedRequest = debugger.requestAttach(UINT32_MAX);
        check(failedRequest > cancelledRequest, "request IDs must be monotone");
        waitUntil([&] { return !debugger.lifecycleSnapshot().busy; }, "invalid PID failure did not finish");
        result = debugger.lifecycleSnapshot();
        check(result.requestId == failedRequest && result.completed && !result.succeeded &&
              !result.cancelled && result.state == DbgLifecycleState::Failed && !result.error.empty(),
              "failed attachment did not retain an actionable completion");
        check(debugger.requestDetach({1, 1}) == 0, "stale target detached another session");
        const auto detachRequest = debugger.requestDetach();
        check(detachRequest != 0, "detached cleanup request not accepted");
        waitUntil([&] { return !debugger.lifecycleSnapshot().busy; }, "detach did not finish");
        check(debugger.lifecycleSnapshot().succeeded, "detach completion failed");

        const auto root = std::filesystem::temp_directory_path() /
            ("ds_lifecycle_" + std::to_string(Clock::now().time_since_epoch().count()));
        std::filesystem::create_directory(root);
        const auto first = root / "first.log";
        const auto second = root / "second.log";
        std::string error;
        check(debugger.setNetCaptureLogFile(first.string(), false, &error), "log open request rejected");
        NetworkObservationEvent a;
        a.pid = 17;
        a.api = NetworkProbeApi::Send;
        a.payload = {'F', 'I', 'R', 'S', 'T'};
        debugger_detail::LifecycleTestAccess::record(debugger, a);
        NetworkObservationEvent tooLarge;
        tooLarge.payload.resize(debugger_detail::LifecycleTestAccess::byteCap());
        debugger_detail::LifecycleTestAccess::record(debugger, tooLarge);
        check(debugger.netCaptureLogStatus().droppedRecords == 1,
              "oversized records must be dropped with explicit accounting");
        debugger.closeNetCaptureLogFile();
        check(debugger.setNetCaptureLogFile(second.string(), false, &error), "second log request rejected");
        a.payload = {'S', 'E', 'C', 'O', 'N', 'D'};
        debugger_detail::LifecycleTestAccess::record(debugger, a);
        debugger.closeNetCaptureLogFile();
        waitUntil([&] { return !debugger.netCaptureLogStatus().draining; }, "log close did not drain");
        check(!debugger.netCaptureLogEnabled(), "closed log is still enabled");
        check(debugger.netCaptureLogStatus().error.empty(), "valid log write failed");
        check(read(first).find("FIRST") != std::string::npos && read(first).find("SECOND") == std::string::npos,
              "first file lost or mixed records across file changes");
        check(read(second).find("SECOND") != std::string::npos && read(second).find("FIRST") == std::string::npos,
              "second file lost or mixed records across file changes");
        check(debugger.setNetCaptureLogFile((root / "missing" / "bad.log").string(), false, &error),
              "asynchronous file-open request should be accepted");
        waitUntil([&] { return !debugger.netCaptureLogStatus().opening; }, "file failure was not published");
        check(!debugger.netCaptureLogEnabled() && !debugger.netCaptureLogStatus().error.empty(),
              "storage failure was not surfaced to the UI");
        std::filesystem::remove(first);
        std::filesystem::remove(second);
        std::filesystem::remove(root);
        std::puts("debugger_lifecycle_test: passed (no target launched or attached)");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "debugger_lifecycle_test: %s\n", error.what());
        return 1;
    }
}
