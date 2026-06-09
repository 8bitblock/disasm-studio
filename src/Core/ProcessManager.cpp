#include "ProcessManager.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

namespace ds {

static std::string narrow(const wchar_t* w) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

ProcessManager::~ProcessManager() { detach(); }

void ProcessManager::close() {
    if (hProcess_) { CloseHandle((HANDLE)hProcess_); hProcess_ = nullptr; }
}

std::vector<ProcessInfo> ProcessManager::enumerate() const {
    std::vector<ProcessInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo p;
            p.pid  = pe.th32ProcessID;
            p.ppid = pe.th32ParentProcessID;
            p.name = narrow(pe.szExeFile);

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
            if (h) {
                p.canOpen = true;
                BOOL wow64 = FALSE;
                if (IsWow64Process(h, &wow64)) p.is64 = !wow64;
                CloseHandle(h);
            }
            out.push_back(std::move(p));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

std::vector<ModuleInfo> ProcessManager::modules(uint32_t pid) const {
    std::vector<ModuleInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return out;

    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            ModuleInfo m;
            m.name = narrow(me.szModule);
            m.path = narrow(me.szExePath);
            m.base = (uint64_t)me.modBaseAddr;
            m.size = me.modBaseSize;
            out.push_back(std::move(m));
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return out;
}

bool ProcessManager::attach(uint32_t pid) {
    detach();
    if (!DebugActiveProcess(pid)) {
        lastError_ = "DebugActiveProcess failed (err " + std::to_string(GetLastError()) +
                     ") - try running as Administrator.";
        return false;
    }
    // Don't kill the debuggee when we detach/exit.
    DebugSetProcessKillOnExit(FALSE);

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) {
        lastError_ = "OpenProcess failed (err " + std::to_string(GetLastError()) + ").";
        DebugActiveProcessStop(pid);
        return false;
    }
    hProcess_   = h;
    attachedPid_ = pid;
    lastError_.clear();
    return true;
}

void ProcessManager::detach() {
    if (attachedPid_) {
        DebugActiveProcessStop(attachedPid_);
        attachedPid_ = 0;
    }
    close();
}

size_t ProcessManager::readMemory(uint64_t address, void* out, size_t size) const {
    if (!hProcess_) return 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory((HANDLE)hProcess_, (LPCVOID)address, out, size, &read))
        return (size_t)read;
    return (size_t)read;
}

bool ProcessManager::readMemory(uint64_t address, std::vector<uint8_t>& out, size_t size) const {
    out.assign(size, 0);
    size_t n = readMemory(address, out.data(), size);
    out.resize(n);
    return n > 0;
}

bool ProcessManager::pumpDebugEvent(std::string& eventDesc) {
    if (!attachedPid_) return false;
    DEBUG_EVENT ev{};
    if (!WaitForDebugEvent(&ev, 0)) return false;

    switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            eventDesc = "process created";
            // This passive pump keeps none of the handles the debug API hands us, so
            // close them here — otherwise a process/thread/file kernel handle leaks per
            // create-process event (our own ReadProcessMemory handle is separate).
            if (ev.u.CreateProcessInfo.hFile)    CloseHandle(ev.u.CreateProcessInfo.hFile);
            if (ev.u.CreateProcessInfo.hThread)  CloseHandle(ev.u.CreateProcessInfo.hThread);
            if (ev.u.CreateProcessInfo.hProcess) CloseHandle(ev.u.CreateProcessInfo.hProcess);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:   eventDesc = "process exited";  break;
        case CREATE_THREAD_DEBUG_EVENT:
            eventDesc = "thread created";
            if (ev.u.CreateThread.hThread) CloseHandle(ev.u.CreateThread.hThread);   // leaked per thread create otherwise
            break;
        case EXIT_THREAD_DEBUG_EVENT:    eventDesc = "thread exited";   break;
        case LOAD_DLL_DEBUG_EVENT:
            eventDesc = "dll loaded";
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);   // leaked per DLL load otherwise
            break;
        case UNLOAD_DLL_DEBUG_EVENT:     eventDesc = "dll unloaded";    break;
        case OUTPUT_DEBUG_STRING_EVENT:  eventDesc = "debug string";    break;
        case EXCEPTION_DEBUG_EVENT: {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            eventDesc = (code == EXCEPTION_BREAKPOINT)      ? "breakpoint"
                      : (code == EXCEPTION_SINGLE_STEP)     ? "single step"
                      : ("exception 0x" + [](DWORD c){ char b[16]; sprintf_s(b,"%08X",c); return std::string(b); }(code));
            break;
        }
        default: eventDesc = "event"; break;
    }
    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    return true;
}

} // namespace ds
