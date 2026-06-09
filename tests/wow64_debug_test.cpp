//
// wow64_debug_test.cpp
// Live end-to-end check that the debugger handles a 32-bit (WOW64) target: launch a
// 32-bit process under it, confirm it is detected as 32-bit, that EIP/ESP are 32-bit
// addresses, and that a single-step advances EIP. Cleans up the child afterwards.
//
// Build & run (x64 VS Dev Shell, from project root):
//   set V=vcpkg_installed\x64-windows-static\x64-windows-static
//   cl /nologo /std:c++20 /EHsc /MT /I src /I %V%\include tests\wow64_debug_test.cpp ^
//      src\Core\Debugger.cpp src\Core\Cond.cpp src\Disasm\ZydisDisassembler.cpp ^
//      %V%\lib\Zydis.lib %V%\lib\Zycore.lib
//   .\wow64_debug_test.exe [path-to-32bit-exe]
//
#include "Core/Debugger.h"

#include <windows.h>
#include <cstdio>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

static bool waitPaused(Debugger& d, int ms) {
    for (int t = 0; t < ms; t += 10) {
        if (d.snapshot().state == DbgState::Paused) return true;
        Sleep(10);
    }
    return false;
}

int main(int argc, char** argv) {
    std::string target = (argc > 1) ? argv[1] : "C:\\Windows\\SysWOW64\\cmd.exe";
    if (GetFileAttributesA(target.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::printf("wow64_debug_test: SKIP (no 32-bit target at %s)\n", target.c_str());
        return 0;
    }

    Debugger d;
    std::string err;
    if (!d.launchAndAttach(target, err, /*breakAtEntry=*/true)) {
        std::printf("wow64_debug_test: SKIP (launch failed: %s)\n", err.c_str());
        return 0;
    }

    bool gotPaused = waitPaused(d, 8000);
    { DbgSnapshot s = d.snapshot();
      std::printf("[diag] paused=%d state=%d is32=%d pid=%u rip=0x%llX lastEvent=%s\n",
                  (int)gotPaused, (int)s.state, (int)s.is32, s.pid,
                  (unsigned long long)s.regs.rip, s.lastEvent.c_str()); }
    uint32_t pid = 0;
    if (gotPaused) {
        DbgSnapshot s = d.snapshot();
        pid = s.pid;
        CHECK(s.is32);                                  // detected as a 32-bit (WOW64) target
        CHECK(s.regs.rip != 0);
        CHECK(s.regs.rip < 0x100000000ull);             // 32-bit EIP
        CHECK(s.regs.rsp != 0 && s.regs.rsp < 0x100000000ull);

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
    } else {
        CHECK(false && "never paused at entry");
        pid = d.snapshot().pid;
    }

    d.detach();
    if (pid) {   // the child was paused at entry; terminate it rather than let it run on
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
    }

    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("wow64_debug_test: all checks passed (WOW64 launch + 32-bit regs + single-step)\n");
    return 0;
}
