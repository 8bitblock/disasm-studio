//
// wow64_debug_test.cpp
// Live end-to-end check that the debugger handles a 32-bit (WOW64) target: launch a
// 32-bit process under it, confirm it is detected as 32-bit, that EIP/ESP are 32-bit
// addresses, and that a single-step advances EIP. Cleans up the child afterwards.
//
// Build & run (x64 VS Dev Shell, from project root):
//   tests\run_core_tests.bat wow64_debug_test
//
#include "Core/Debugger.h"

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

static bool liveTestRequired() {
    char value[8]{};
    return GetEnvironmentVariableA("DS_REQUIRE_LIVE_DEBUG_TESTS", value,
                                   static_cast<DWORD>(sizeof(value))) != 0 &&
           value[0] == '1';
}

static bool waitPaused(Debugger& d, int ms) {
    for (int t = 0; t < ms; t += 10) {
        if (d.snapshot().state == DbgState::Paused) return true;
        Sleep(10);
    }
    return false;
}

static bool waitRunning(Debugger& d, int ms) {
    for (int t = 0; t < ms; t += 5) {
        if (d.snapshot().state == DbgState::Running) return true;
        Sleep(5);
    }
    return false;
}

static bool waitTerminated(Debugger& d, int ms) {
    for (int t = 0; t < ms; t += 10) {
        const DbgState state = d.snapshot().state;
        if (state == DbgState::Terminated || state == DbgState::Detached) return true;
        Sleep(10);
    }
    return false;
}

static bool waitPausedAt(Debugger& d, uint64_t address, int ms,
                         const char* eventContains = nullptr) {
    for (int t = 0; t < ms; t += 5) {
        const DbgSnapshot snapshot = d.snapshot();
        if (snapshot.state == DbgState::Paused && snapshot.regs.rip == address &&
            (!eventContains || snapshot.lastEvent.find(eventContains) != std::string::npos))
            return true;
        Sleep(5);
    }
    return false;
}

static bool waitSoftwareStop(Debugger& d, uint64_t address, int ms) {
    for (int t = 0; t < ms; t += 5) {
        const DbgSnapshot snapshot = d.snapshot();
        if (snapshot.state == DbgState::Paused && snapshot.regs.rip == address) {
            for (const auto& bp : snapshot.breakpoints)
                if (bp.address == address && bp.hits) return true;
        }
        Sleep(5);
    }
    return false;
}

static bool createSuspendedTarget(const std::string& path, PROCESS_INFORMATION& process) {
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    std::string commandLine = "\"" + path + "\"";
    return CreateProcessA(path.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                          CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr,
                          &startup, &process) != FALSE;
}

// The live controller is built x64, so produce a disposable x86 debuggee with
// the same installed Visual Studio toolchain. Keeping this in the live fixture
// avoids checking a generated executable into the repository.
static bool buildX86NetworkFixture(std::string& executable, std::string& object,
                                   std::string& error) {
    error.clear(); executable.clear(); object.clear();
    char current[MAX_PATH]{};
    char temporary[MAX_PATH]{};
    char vsRoot[MAX_PATH]{};
    if (!GetCurrentDirectoryA(MAX_PATH, current) || !GetTempPathA(MAX_PATH, temporary)) {
        error = "could not resolve working/temp directory";
        return false;
    }
    DWORD rootLength = GetEnvironmentVariableA("VSINSTALLDIR", vsRoot, MAX_PATH);
    std::string vcvars;
    if (rootLength && rootLength < MAX_PATH) {
        vcvars = std::string(vsRoot) + "VC\\Auxiliary\\Build\\vcvarsall.bat";
    } else {
        rootLength = GetEnvironmentVariableA("VCINSTALLDIR", vsRoot, MAX_PATH);
        if (rootLength && rootLength < MAX_PATH)
            vcvars = std::string(vsRoot) + "Auxiliary\\Build\\vcvarsall.bat";
    }
    if (vcvars.empty() || GetFileAttributesA(vcvars.c_str()) == INVALID_FILE_ATTRIBUTES) {
        error = "Visual Studio x86 environment script was not found";
        return false;
    }

    const std::string source = std::string(current) + "\\tests\\fixtures\\network_loopback_fixture.cpp";
    if (GetFileAttributesA(source.c_str()) == INVALID_FILE_ATTRIBUTES) {
        error = "tests\\fixtures\\network_loopback_fixture.cpp was not found from the test root";
        return false;
    }
    const std::string stem = std::string(temporary) + "ds_net_x86_" +
        std::to_string(GetCurrentProcessId()) + "_" + std::to_string(GetTickCount64());
    executable = stem + ".exe";
    object = stem + ".obj";

    // cmd's /s /c contract needs the outer quote pair in addition to quotes
    // around each path. vcvarsall supplies the matching x86 INCLUDE/LIB paths.
    std::string command = "cmd.exe /d /s /c \"\"" + vcvars +
        "\" x86 >nul && cl.exe /nologo /std:c++20 /EHsc /MT /W4 \"" + source +
        "\" /Fo\"" + object + "\" /Fe\"" + executable +
        "\" /link ws2_32.lib winhttp.lib wininet.lib\"";
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION compiler{};
    if (!CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, current, &startup, &compiler)) {
        error = "could not launch the x86 compiler environment";
        return false;
    }
    CloseHandle(compiler.hThread);
    const DWORD waited = WaitForSingleObject(compiler.hProcess, 120000);
    DWORD exitCode = 1;
    (void)GetExitCodeProcess(compiler.hProcess, &exitCode);
    CloseHandle(compiler.hProcess);
    if (waited != WAIT_OBJECT_0 || exitCode != 0 ||
        GetFileAttributesA(executable.c_str()) == INVALID_FILE_ATTRIBUTES) {
        error = "x86 loopback fixture compilation failed";
        DeleteFileA(executable.c_str());
        DeleteFileA(object.c_str());
        executable.clear(); object.clear();
        return false;
    }
    return true;
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

int main(int argc, char** argv) {
    std::string target = (argc > 1) ? argv[1] : "C:\\Windows\\SysWOW64\\cmd.exe";
    if (GetFileAttributesA(target.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::printf("wow64_debug_test: %s (no 32-bit target at %s)\n",
                    liveTestRequired() ? "FAIL" : "SKIP", target.c_str());
        return liveTestRequired() ? 1 : 0;
    }

    Debugger d;
    std::string err;
    if (!d.launchAndAttach(target, err, /*breakAtEntry=*/true)) {
        std::printf("wow64_debug_test: %s (launch failed: %s)\n",
                    liveTestRequired() ? "FAIL" : "SKIP", err.c_str());
        return liveTestRequired() ? 1 : 0;
    }

    bool gotPaused = waitPaused(d, 8000);
    { DbgSnapshot s = d.snapshot();
      std::printf("[diag] paused=%d state=%d is32=%d pid=%u rip=0x%llX lastEvent=%s\n",
                  (int)gotPaused, (int)s.state, (int)s.is32, s.pid,
                  (unsigned long long)s.regs.rip, s.lastEvent.c_str()); }
    uint32_t pid = 0;
    bool exitedUnderDebugger = false;
    if (gotPaused) {
        DbgSnapshot s = d.snapshot();
        pid = s.pid;
        CHECK(s.is32);                                  // detected as a 32-bit (WOW64) target
        CHECK(s.regs.rip != 0);
        CHECK(s.regs.rip < 0x100000000ull);             // 32-bit EIP
        CHECK(s.regs.rsp != 0 && s.regs.rsp < 0x100000000ull);
        CHECK(!s.modules.empty());
        if (!s.modules.empty()) {
            const DbgModule& mainModule = s.modules.front();
            IMAGE_DOS_HEADER dos{};
            CHECK(d.readMemory(mainModule.base, &dos, sizeof(dos)) == sizeof(dos));
            CHECK(dos.e_magic == IMAGE_DOS_SIGNATURE);
            CHECK(dos.e_lfanew > 0 && static_cast<uint64_t>(dos.e_lfanew) < mainModule.size);
            if (dos.e_lfanew > 0 && static_cast<uint64_t>(dos.e_lfanew) < mainModule.size) {
                IMAGE_NT_HEADERS32 nt{};
                CHECK(d.readMemory(mainModule.base + dos.e_lfanew, &nt, sizeof(nt)) == sizeof(nt));
                CHECK(nt.Signature == IMAGE_NT_SIGNATURE);
                CHECK(nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
                // Entry stops are translated from image RVA to the actual loaded
                // module base, even when ASLR chose a different preferred base.
                CHECK(s.regs.rip == mainModule.base + nt.OptionalHeader.AddressOfEntryPoint);
            }
        }
        const uint64_t originalEax = s.regs.rax;

        const DebugTargetIdentity session{ s.pid, s.sessionGeneration };
        PausedRegisterSnapshot pausedRegisters;
        std::string accumulatorError;
        CHECK(d.readPausedRegistersForSession(
            session, s.activeTid, pausedRegisters, &accumulatorError));
        CHECK(accumulatorError.empty());
        CHECK(pausedRegisters.is32 && pausedRegisters.tid == s.activeTid);
        CHECK(pausedRegisters.regs.rip == s.regs.rip);
        CHECK(pausedRegisters.regs.rax == originalEax);
        CHECK(pausedRegisters.eax == static_cast<uint32_t>(originalEax));
        CHECK(pausedRegisters.al == static_cast<uint8_t>(originalEax));

        const uint64_t forcedEax = static_cast<uint32_t>(originalEax ^ 1u);
        PausedRegisterSnapshot afterAccumulatorWrite;
        CHECK(d.setAccumulatorForSessionVerified(
            session, s.activeTid, s.regs.rip, originalEax,
            UINT64_C(0xffffffff), forcedEax, afterAccumulatorWrite,
            &accumulatorError));
        CHECK(accumulatorError.empty());
        CHECK(afterAccumulatorWrite.regs.rax == forcedEax);
        CHECK((afterAccumulatorWrite.regs.rax >> 32) == 0);
        CHECK(d.setAccumulatorForSessionVerified(
            session, s.activeTid, s.regs.rip, forcedEax,
            UINT64_C(0xffffffff), originalEax, afterAccumulatorWrite,
            &accumulatorError));
        CHECK(accumulatorError.empty());
        CHECK(afterAccumulatorWrite.regs.rax == originalEax);
        CHECK(!d.setAccumulatorForSessionVerified(
            session, s.activeTid, s.regs.rip, originalEax,
            UINT64_C(0xffffffff), UINT64_C(0x100000000),
            afterAccumulatorWrite, &accumulatorError));
        CHECK(!accumulatorError.empty());

        CHECK(!d.setRegisterForSession(
            s.pid, s.sessionGeneration, "rax",
            static_cast<uint64_t>(UINT32_MAX) + 1));
        CHECK(d.snapshot().regs.rax == originalEax);     // reject, never truncate
        CHECK(!d.setRegisterForSession(
            s.pid, s.sessionGeneration, "r8", 1));    // no x64-only GPRs in WOW64
        CHECK(d.snapshot().regs.rax == originalEax);

        const uint64_t wrongEditorRip = s.regs.rip ^ UINT64_C(1);
        CHECK(!d.setRegisterForSession(
            s.pid, s.sessionGeneration, "rax", forcedEax,
            s.activeTid ^ 0x80000000u, &s.regs.rip));
        CHECK(!d.setRegisterForSession(
            s.pid, s.sessionGeneration, "rax", forcedEax,
            s.activeTid, &wrongEditorRip));
        CHECK(d.snapshot().regs.rax == originalEax);
        CHECK(d.setRegisterForSession(
            s.pid, s.sessionGeneration, "rax", forcedEax,
            s.activeTid, &s.regs.rip));
        CHECK(d.snapshot().regs.rax == forcedEax);
        CHECK(d.setRegisterForSession(
            s.pid, s.sessionGeneration, "rax", originalEax,
            s.activeTid, &s.regs.rip));

        const std::vector<uint8_t> registerText{
            't','h','i','s',' ','i','s',' ','s','o','m','e',' ','t','e','x','t',0
        };
        uint64_t textAddress = 0;
        std::string textError;
        const size_t regionsBeforeRejectedEdit = d.regions().size();
        CHECK(!d.setRegisterToBufferForSession(
            s.pid, s.sessionGeneration, s.activeTid,
            "rax", registerText, textAddress, &textError, &wrongEditorRip));
        CHECK(textAddress == 0);
        CHECK(!textError.empty());
        CHECK(d.snapshot().regs.rax == originalEax);
        CHECK(d.regions().size() == regionsBeforeRejectedEdit);
        const bool textSet = d.setRegisterToBufferForSession(
            s.pid, s.sessionGeneration, s.activeTid,
            "rax", registerText, textAddress, &textError, &s.regs.rip);
        CHECK(textSet);
        if (textSet) {
            CHECK(textAddress != 0 && textAddress <= UINT32_MAX);
            const DbgSnapshot edited = d.snapshot();
            CHECK(edited.regs.rax == textAddress);
            CHECK((edited.regs.rax >> 32) == 0);         // real EAX, not a stale host high half
            std::vector<uint8_t> observed(registerText.size());
            CHECK(d.readMemory(textAddress, observed.data(), observed.size()) ==
                  observed.size());
            CHECK(observed == registerText);
            bool foundWritableNonExecutableRegion = false;
            for (const MemRegion& region : d.regions()) {
                if (textAddress < region.base ||
                    textAddress - region.base >= region.size)
                    continue;
                foundWritableNonExecutableRegion =
                    region.write && !region.exec &&
                    (region.protect & 0xFFu) == PAGE_READWRITE;
                break;
            }
            CHECK(foundWritableNonExecutableRegion);
            CHECK(d.setRegisterForSession(
                s.pid, s.sessionGeneration, "rax", s.regs.rax));
        }

        checkPausedBreakpointMutation(d, s);
        uint64_t rip0 = s.regs.rip;
        d.stepInto();
        bool advanced = false;
        for (int t = 0; t < 4000; t += 20) {
            DbgSnapshot s2 = d.snapshot();
            if (s2.state == DbgState::Paused && s2.regs.rip != rip0) {
                CHECK(s2.is32);
                CHECK(s2.regs.rip < 0x100000000ull);    // still a 32-bit EIP after stepping
                advanced = true;
                break;
            }
            Sleep(20);
        }
        CHECK(advanced);                                // single-step moved EIP

        // Exercise the production SW/HW breakpoint and Step Over/Out paths with
        // a tiny deterministic x86 function graph in debugger-owned memory:
        //   call leaf; nop; loop     leaf: mov eax,imm; ret
        if (advanced && d.snapshot().state == DbgState::Paused) {
            const uint64_t scratch = d.allocRemote(64);
            CHECK(scratch != 0 && scratch < 0x100000000ull);
            if (scratch) {
                uint8_t code[64];
                std::memset(code, 0x90, sizeof(code));
                code[0] = 0xE8;
                const int32_t leafRelative = 16 - 5;
                std::memcpy(code + 1, &leafRelative, sizeof(leafRelative));
                code[5] = 0x90;
                code[6] = 0xEB; code[7] = 0xFE;
                code[16] = 0xB8;
                const uint32_t resultValue = 0x12345678;
                std::memcpy(code + 17, &resultValue, sizeof(resultValue));
                code[21] = 0xC3;
                code[32] = 0x90;
                code[33] = 0xEB; code[34] = 0xFE;
                code[48] = 0xCC; // native trap: failure diagnostic must never own or mask this byte
                CHECK(d.writeMemory(scratch, code, sizeof(code)) == sizeof(code));

                Registers jump = d.snapshot().regs;
                jump.rip = scratch;
                CHECK(d.setRegisters(jump));
                CHECK(!d.addBreakpointForSession(
                    { session.pid, session.sessionGeneration + 1 }, scratch));
                CHECK(d.addBreakpointForSession(session, scratch));
                CHECK(d.addBreakpointForSession(session, scratch + 48));
                CHECK(d.setBreakpointEveryNForSession(session, scratch + 48, 3));
                CHECK(d.addBreakpointForSession(session, 1));
                d.cont();
                CHECK(waitSoftwareStop(d, scratch, 4000));
                const DbgSnapshot initialStop = d.snapshot();
                bool nativeFailure = false, unreadableFailure = false;
                for (const auto& bp : initialStop.breakpoints) {
                    nativeFailure |= bp.address == scratch + 48 && !bp.armed &&
                                     bp.error.find("native INT3") != std::string::npos && bp.everyN == 3;
                    unreadableFailure |= bp.address == 1 && !bp.armed &&
                                         bp.error.find("unreadable") != std::string::npos;
                }
                CHECK(nativeFailure && unreadableFailure);
                CHECK(!d.hasBreakpoint(scratch + 48) && !d.hasBreakpoint(1));
                uint8_t untouchedTrap = 0;
                CHECK(d.readMemoryMasked(scratch + 48, &untouchedTrap, 1) == 1 &&
                      untouchedTrap == 0xCC);
                CHECK(d.removeBreakpointForSession(session, scratch + 48));
                CHECK(d.removeBreakpointForSession(session, 1));
                const uint32_t stepOwner = d.snapshot().activeTid;
                d.stepOver();
                CHECK(waitPausedAt(d, scratch + 5, 4000));
                const DbgSnapshot afterOver = d.snapshot();
                CHECK(afterOver.activeTid == stepOwner);
                CHECK(static_cast<uint32_t>(afterOver.regs.rax) == resultValue);
                CHECK(afterOver.breakpoints.size() == 1);
                if (afterOver.breakpoints.size() == 1) {
                    CHECK(afterOver.breakpoints.front().address == scratch);
                    CHECK(afterOver.breakpoints.front().armed);
                    CHECK(afterOver.breakpoints.front().error.empty());
                }
                uint8_t physical = 0, logical = 0;
                CHECK(d.readMemory(scratch, &physical, 1) == 1 && physical == 0xCC);
                CHECK(d.readMemoryMasked(scratch, &logical, 1) == 1 && logical == 0xE8);

                CHECK(d.removeBreakpoint(scratch));
                Registers leaf = d.snapshot().regs;
                leaf.rip = scratch + 16;
                CHECK(d.setRegisters(leaf));
                d.stepOut();
                bool steppedOut = false;
                for (int t = 0; t < 4000; t += 5) {
                    const DbgSnapshot out = d.snapshot();
                    if (out.state == DbgState::Paused && out.regs.rip != scratch + 16 &&
                        out.lastEvent.find("step out") != std::string::npos) {
                        steppedOut = true;
                        break;
                    }
                    Sleep(5);
                }
                CHECK(steppedOut);

                Registers hardware = d.snapshot().regs;
                hardware.rip = scratch + 32;
                CHECK(d.setRegisters(hardware));
                CHECK(!d.addHardwareBreakpointForSession(
                    { session.pid, session.sessionGeneration + 1 }, scratch + 32, HwKind::Execute, 1));
                CHECK(d.addHardwareBreakpointForSession(session, scratch + 32, HwKind::Execute, 1));
                d.cont();
                CHECK(waitPausedAt(d, scratch + 32, 4000, "hw breakpoint"));
                CHECK(d.snapshot().hwBreakpoints.size() == 1);
                if (d.snapshot().hwBreakpoints.size() == 1) {
                    const HwBreakpointInfo installed = d.snapshot().hwBreakpoints.front();
                    CHECK(installed.address == scratch + 32);
                    CHECK(installed.kind == HwKind::Execute && installed.size == 1);
                }
                CHECK(d.removeHardwareBreakpoint(scratch + 32));

                // Record the actual WOW64 CALL/RET path, including the callee,
                // and stop at the user's return-site breakpoint. The retained
                // contexts must use 32-bit EIP/ESP and preserve execution order.
                Registers historyStart = d.snapshot().regs;
                historyStart.rip = scratch;
                historyStart.rax = 0;
                CHECK(d.setRegisters(historyStart));
                CHECK(d.addBreakpointForSession(session, scratch));
                CHECK(d.addBreakpointForSession(session, scratch + 5));
                CHECK(d.continueForSession(session));
                const bool historyAtStart = waitSoftwareStop(d, scratch, 4000);
                CHECK(historyAtStart);
                if (historyAtStart) {
                    const uint32_t historyTid = d.snapshot().activeTid;
                    ExecutionHistorySnapshot history;
                    d.executionHistorySnapshotIfChanged(history);
                    const uint64_t previousGeneration = history.generation;
                    CHECK(d.recordExecutionPathForSession(session, historyTid));
                    bool recorded = false;
                    for (int elapsed = 0; elapsed < 5000; elapsed += 5) {
                        d.executionHistorySnapshotIfChanged(history);
                        if (history.generation != previousGeneration && !history.recording &&
                            d.snapshot().state == DbgState::Paused) {
                            recorded = true;
                            break;
                        }
                        Sleep(5);
                    }
                    if (!recorded || history.entries.size() != 4)
                        std::printf("[diag] WOW64 history count=%zu status=%s event=%s\n",
                            history.entries.size(), history.status.c_str(), d.snapshot().lastEvent.c_str());
                    CHECK(recorded && history.entries.size() == 4);
                    CHECK(history.is32 && history.tid == historyTid);
                    CHECK(DebugTargetIdentityMatches(history.target, session));
                    static constexpr uint64_t expectedOffsets[] = {0, 16, 21, 5};
                    for (size_t i = 0; i < history.entries.size(); ++i) {
                        const auto& entry = history.entries[i];
                        if (i < 4) CHECK(entry.regs.rip == scratch + expectedOffsets[i]);
                        CHECK(entry.regs.rip < 0x100000000ull && entry.regs.rsp < 0x100000000ull);
                        CHECK(entry.byteCount > 0 && entry.byteCount <= entry.bytes.size());
                        if (entry.regs.rip >= scratch && entry.regs.rip < scratch + sizeof(code))
                            CHECK(entry.bytes[0] == code[entry.regs.rip - scratch]);
                        if (i) CHECK(entry.sequence == history.entries[i - 1].sequence + 1);
                    }
                    if (history.entries.size() == 4) {
                        CHECK(history.entries[1].regs.rsp + 4 == history.entries.front().regs.rsp);
                        CHECK(history.entries.back().regs.rsp == history.entries.front().regs.rsp);
                        CHECK(history.entries.front().regs.rax == 0);
                        CHECK(history.entries.back().regs.rax == resultValue);
                        CHECK(history.entries.front().byteCount >= 6 && history.entries.front().bytes[5] == 0x90);
                    }
                    CHECK(d.snapshot().activeTid == historyTid && d.snapshot().regs.rip == scratch + 5);
                    CHECK(d.snapshot().regs.rax == resultValue);
                    CHECK(!d.executionHistorySnapshotIfChanged(history));
                    CHECK(d.snapshot().regs.rip == scratch + 5);
                }
                CHECK(d.removeBreakpointForSession(session, scratch));
                CHECK(d.removeBreakpointForSession(session, scratch + 5));

                const DbgSnapshot owner = d.snapshot();
                HANDLE process = static_cast<HANDLE>(d.duplicateProcessHandleForSession(
                    { owner.pid, owner.sessionGeneration }));
                CHECK(process != nullptr);
                if (process) {
                    CHECK(TerminateProcess(process, 0) != FALSE);
                    CloseHandle(process);
                    d.cont();
                    exitedUnderDebugger = waitTerminated(d, 5000);
                    CHECK(exitedUnderDebugger);
                }
            }
        }
    } else {
        CHECK(false && "never paused at entry");
        pid = d.snapshot().pid;
    }

    d.detach();
    if (pid && !exitedUnderDebugger) {   // failure cleanup for the launched child
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
    }

    // Attach-by-PID uses a separately created suspended WOW64 process. Continue
    // releases the debugger's initial break while the external main-thread
    // suspend count keeps the fixture deterministic; running detach must not
    // terminate it or leak a stale Detach command into the next session.
    PROCESS_INFORMATION attachTarget{};
    const bool targetCreated = createSuspendedTarget(target, attachTarget);
    CHECK(targetCreated);
    if (targetCreated) {
        err.clear();
        const bool attached = d.attach(attachTarget.dwProcessId, err);
        CHECK(attached);
        CHECK(attached && waitPaused(d, 8000));
        if (attached && d.snapshot().state == DbgState::Paused) {
            CHECK(d.snapshot().is32);
            d.cont();
            CHECK(waitRunning(d, 2000));
            d.detach();
            DWORD exitCode = 0;
            CHECK(GetExitCodeProcess(attachTarget.hProcess, &exitCode) &&
                  exitCode == STILL_ACTIVE);
        } else {
            d.detach();
        }
        ResumeThread(attachTarget.hThread);
        TerminateProcess(attachTarget.hProcess, 0);
        WaitForSingleObject(attachTarget.hProcess, 2000);
        CloseHandle(attachTarget.hThread);
        CloseHandle(attachTarget.hProcess);
    }

    // Exercise the exact WOW64 stack ABI used by internal network entry/return
    // probes against a deterministic local hosted-reply exchange.
    std::string networkTarget, networkObject, fixtureError;
    const bool fixtureBuilt = buildX86NetworkFixture(networkTarget, networkObject, fixtureError);
    if (!fixtureBuilt)
        std::printf("[diag] WOW64 network fixture: %s\n", fixtureError.c_str());
    CHECK(fixtureBuilt);
    if (fixtureBuilt) {
        err.clear();
        const bool networkLaunched = d.launchAndAttach(networkTarget, err, /*breakAtEntry=*/true);
        CHECK(networkLaunched);
        CHECK(networkLaunched && waitPaused(d, 8000));
        if (networkLaunched && d.snapshot().state == DbgState::Paused) {
            CHECK(d.snapshot().is32);
            d.startNetworkObservation();
            d.cont();
            NetworkObservation observation;
            for (int elapsed = 0; elapsed < 12000; elapsed += 10) {
                observation = d.networkObservationSnapshot();
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
            CHECK(observation.coverage.wow64);
            CHECK(observation.coverage.winsock);
            CHECK(observation.coverage.nameResolution);
            CHECK(observation.coverage.handleStatesDropped == 0);
            CHECK(d.snapshot().breakpoints.empty());
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
                failedWinHttpSendHonest |=
                    event.api == NetworkProbeApi::WinHttpSendRequest &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == sizeof("failed-winhttp-inline") - 1 &&
                    event.transferred == 0 && payload == "failed-winhttp-inline";
                failedWinInetSendHonest |=
                    event.api == NetworkProbeApi::HttpSendRequestW &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == sizeof("failed-wininet-inline") - 1 &&
                    event.transferred == 0 && payload == "failed-wininet-inline";
                failedWinHttpWriteHonest |=
                    event.api == NetworkProbeApi::WinHttpWriteData &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == sizeof("failed-winhttp-write") - 1 &&
                    event.transferred == 0 && payload == "failed-winhttp-write";
                failedWinInetWriteHonest |=
                    event.api == NetworkProbeApi::InternetWriteFile &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == sizeof("failed-wininet-write") - 1 &&
                    event.transferred == 0 && payload == "failed-wininet-write";
                failedWinHttpReadHonest |=
                    event.api == NetworkProbeApi::WinHttpReadData &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == 17 && event.transferred == 0 && payload.empty();
                failedWinInetReadHonest |=
                    event.api == NetworkProbeApi::InternetReadFile &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == 19 && event.transferred == 0 && payload.empty();
                failedWinInetReadExHonest |=
                    event.api == NetworkProbeApi::InternetReadFileExW &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == 23 && event.transferred == 0 && payload.empty();
                failedWinHttpQueryHonest |=
                    event.api == NetworkProbeApi::WinHttpQueryHeaders &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == 29 && event.transferred == 0 && payload.empty();
                failedWinInetQueryHonest |=
                    event.api == NetworkProbeApi::HttpQueryInfoW &&
                    event.handle == 0 && event.result == 0 &&
                    event.requestedBytes == 31 && event.transferred == 0 && payload.empty();
                resolved |= event.stage == NetworkObservationStage::NameResolution &&
                            event.hostname == "localhost";
                resolvedStructured |= event.stage == NetworkObservationStage::NameResolution &&
                                      event.hostname == "localhost" && !event.ip.empty();
                connected |= event.stage == NetworkObservationStage::Connect &&
                             event.direction == NetworkDirection::Outbound &&
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
            CHECK(failedWinHttpSendHonest);
            CHECK(failedWinInetSendHonest);
            CHECK(failedWinHttpWriteHonest);
            CHECK(failedWinInetWriteHonest);
            CHECK(failedWinHttpReadHonest);
            CHECK(failedWinInetReadHonest);
            CHECK(failedWinInetReadExHonest);
            CHECK(failedWinHttpQueryHonest);
            CHECK(failedWinInetQueryHonest);
            CHECK(httpResponded);
            CHECK(httpRead);
            CHECK(closedRequest && closedConnection && closedSession);
            if (!(openSequence < connectSequence && connectSequence < requestSequence &&
                  requestSequence < sendSequence && sendSequence < responseSequence &&
                  responseSequence < readSequence)) {
                std::printf("[diag] WOW64 WinHTTP sequence open=%llu connect=%llu request=%llu send=%llu response=%llu read=%llu\n",
                            static_cast<unsigned long long>(openSequence),
                            static_cast<unsigned long long>(connectSequence),
                            static_cast<unsigned long long>(requestSequence),
                            static_cast<unsigned long long>(sendSequence),
                            static_cast<unsigned long long>(responseSequence),
                            static_cast<unsigned long long>(readSequence));
                for (const NetworkObservationEvent& event : observation.events) {
                    if (event.api < NetworkProbeApi::WinHttpOpen ||
                        event.api > NetworkProbeApi::WinHttpCloseHandle) continue;
                    std::printf("[diag] seq=%llu api=%u stage=%u handle=0x%llX result=%lld host=%s method=%s object=%s bytes=%u\n",
                                static_cast<unsigned long long>(event.sequence),
                                static_cast<unsigned>(event.api), static_cast<unsigned>(event.stage),
                                static_cast<unsigned long long>(event.handle),
                                static_cast<long long>(event.result), event.hostname.c_str(),
                                event.method.c_str(), event.object.c_str(), event.transferred);
                }
            }
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
            CHECK(waitTerminated(d, 12000));
        }
        d.detach();
        DeleteFileA(networkTarget.c_str());
        DeleteFileA(networkObject.c_str());
    }

    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("wow64_debug_test: all checks passed (launch/attach/detach + SW/HW bp + step/memory/exit cleanup + x86 local-loopback network observation)\n");
    return 0;
}
