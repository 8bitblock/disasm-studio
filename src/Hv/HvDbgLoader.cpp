#include "HvDbgLoader.h"

#include <windows.h>
#include <winsvc.h>
#include <string>

namespace ds {

namespace {

// RAII wrapper for an SC_HANDLE (SCManager or service handle).
struct ScHandle {
    SC_HANDLE h = nullptr;
    ScHandle() = default;
    explicit ScHandle(SC_HANDLE x) : h(x) {}
    ~ScHandle() { if (h) CloseServiceHandle(h); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    explicit operator bool() const { return h != nullptr; }
    operator SC_HANDLE() const { return h; }
};

// Map a Win32 error from the SCM into a short, actionable message.
std::string describe(const char* what, DWORD e) {
    std::string m = what;
    switch (e) {
    case ERROR_ACCESS_DENIED:
        m += ": access denied - run DisasmStudio as Administrator."; break;
    case ERROR_SERVICE_DOES_NOT_EXIST:
        m += ": the HvDbg service is not installed."; break;
    case ERROR_PATH_NOT_FOUND:
    case ERROR_FILE_NOT_FOUND:
        m += ": HvDbg.sys was not found next to the exe."; break;
    case ERROR_INVALID_IMAGE_HASH:
        m += ": the driver image is not signed (enable test-signing or sign HvDbg.sys)."; break;
    case ERROR_BAD_DRIVER:
        m += ": the driver image is invalid (malformed HvDbg.sys)."; break;
    case ERROR_DRIVER_BLOCKED:
        m += ": the driver is blocked by Windows code-integrity / blocklist policy."; break;
    case ERROR_DRIVER_FAILED_PRIOR_UNLOAD:
        m += ": the previous HvDbg instance has not finished unloading - wait a moment, then retry."; break;
    case ERROR_SERVICE_MARKED_FOR_DELETE:
        m += ": service is being deleted - wait a moment and retry (or reboot)."; break;
    default:
        m += " (error " + std::to_string((unsigned)e) + ")."; break;
    }
    return m;
}

// Poll the service until it reaches SERVICE_STOPPED or the timeout elapses.
// ControlService(STOP) only *dispatches* the stop; for a kernel driver the
// DriverUnload + image dereference complete asynchronously, so unload() must
// drain to STOPPED before DeleteService - otherwise the record lingers
// marked-for-delete and the next CreateService fails. Returns the last observed
// state (SERVICE_STOPPED on success, 0 if the status query itself fails).
DWORD waitForStopped(SC_HANDLE svc, DWORD timeoutMs) {
    SERVICE_STATUS st{};
    DWORD waited = 0;
    const DWORD slice = 100;
    for (;;) {
        if (!QueryServiceStatus(svc, &st)) return 0;
        if (st.dwCurrentState == SERVICE_STOPPED) return SERVICE_STOPPED;
        if (waited >= timeoutMs) return st.dwCurrentState;
        Sleep(slice);
        waited += slice;
    }
}

} // namespace

HvDbgLoader::~HvDbgLoader() = default;

void HvDbgLoader::setError(const char* what, unsigned long winErr) {
    lastError_ = describe(what, (DWORD)winErr);
}

bool HvDbgLoader::isElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD got = 0;
    bool elevated = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &got)
                    && elev.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

std::wstring HvDbgLoader::defaultSysPath() {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"HvDbg.sys";
    std::wstring path(buf, n);
    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) path.resize(slash + 1);
    else path.clear();
    path += L"HvDbg.sys";
    return path;
}

HvDbgLoader::State HvDbgLoader::state() const {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return State::Unknown;
    ScHandle svc(OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS));
    if (!svc) {
        return (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
               ? State::NotInstalled : State::Unknown;
    }
    SERVICE_STATUS st{};
    if (!QueryServiceStatus(svc, &st)) return State::Unknown;
    return (st.dwCurrentState == SERVICE_STOPPED || st.dwCurrentState == SERVICE_STOP_PENDING)
           ? State::Stopped : State::Running;
}

bool HvDbgLoader::load(const std::wstring& sysPathIn) {
    clearError();
    if (!isElevated()) { lastError_ = "Loading a kernel driver requires Administrator rights."; return false; }

    std::wstring sysPath = sysPathIn.empty() ? defaultSysPath() : sysPathIn;
    if (GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        setError("HvDbg.sys not found", ERROR_FILE_NOT_FOUND);
        return false;
    }

    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!scm) { setError("OpenSCManager", GetLastError()); return false; }

    // Create-or-open the kernel-driver service entry pointing at HvDbg.sys.
    // Two recoverable states are handled: ERROR_SERVICE_EXISTS means a live
    // registration (open it, keeping its image path), while
    // ERROR_SERVICE_MARKED_FOR_DELETE is the residual window right after an
    // unload() whose kernel teardown hasn't fully settled - retry briefly until
    // the old record drops (opening a marked record would only push the failure
    // into StartService, so we must wait for a fresh CreateService to succeed).
    const DWORD access = SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE;
    ScHandle svc;
    bool created = false;
    const DWORD createDeadline = 3000;
    for (DWORD waited = 0;;) {
        svc.h = CreateServiceW(scm, kServiceName, kDisplayName, access,
                               SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                               sysPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (svc) { created = true; break; }
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) {
            svc.h = OpenServiceW(scm, kServiceName, access);
            if (!svc) { setError("OpenService", GetLastError()); return false; }
            break;
        }
        if (e == ERROR_SERVICE_MARKED_FOR_DELETE && waited < createDeadline) {
            Sleep(100); waited += 100; continue;
        }
        setError("CreateService", e);
        return false;
    }

    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            setError("StartService", e);
            // Don't leave a dead registration behind if we just created it (e.g.
            // an unsigned image fails the start). A pre-existing service is left
            // alone so the user can retry without re-registering.
            if (created) DeleteService(svc);
            return false;
        }
    }
    return true;
}

bool HvDbgLoader::start() {
    clearError();
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { setError("OpenSCManager", GetLastError()); return false; }
    ScHandle svc(OpenServiceW(scm, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS));
    if (!svc) { setError("OpenService", GetLastError()); return false; }
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) { setError("StartService", e); return false; }
    }
    return true;
}

bool HvDbgLoader::stop() {
    clearError();
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { setError("OpenSCManager", GetLastError()); return false; }
    ScHandle svc(OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!svc) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) return true; // nothing to stop
        setError("OpenService", e); return false;
    }
    SERVICE_STATUS st{};
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        waitForStopped(svc, 5000);   // drain to STOPPED so the device is gone on return
    } else {
        DWORD e = GetLastError();
        // Already stopped / never started is success for our purposes.
        if (e != ERROR_SERVICE_NOT_ACTIVE) { setError("ControlService(STOP)", e); return false; }
    }
    return true;
}

bool HvDbgLoader::unload() {
    clearError();
    if (!isElevated()) { lastError_ = "Unloading a kernel driver requires Administrator rights."; return false; }

    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { setError("OpenSCManager", GetLastError()); return false; }
    ScHandle svc(OpenServiceW(scm, kServiceName,
                              SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!svc) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) return true; // already gone
        setError("OpenService", e); return false;
    }

    // Stop first (DriverUnload tears the hypervisor down), then deregister. The
    // stop is asynchronous, so drain to SERVICE_STOPPED before DeleteService -
    // otherwise the kernel image is still referenced and the record only gets
    // marked-for-delete, which would block the next load(). A not-active service
    // is already stopped, so skip the wait in that case.
    SERVICE_STATUS st{};
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        waitForStopped(svc, 5000);
    } else {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_NOT_ACTIVE) { setError("ControlService(STOP)", e); return false; }
    }

    if (!DeleteService(svc)) {
        DWORD e = GetLastError();
        // MARKED_FOR_DELETE means a prior handle is still open; it will go on the
        // last close - treat as success.
        if (e != ERROR_SERVICE_MARKED_FOR_DELETE) { setError("DeleteService", e); return false; }
    }
    return true;
}

} // namespace ds
