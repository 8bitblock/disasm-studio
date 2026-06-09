#include "HvDbgClient.h"

#include <windows.h>
#include <string>

namespace ds {

HvDbgClient::~HvDbgClient() { disconnect(); }

bool HvDbgClient::connect() {
    if (handle_) return true;
    HANDLE h = CreateFileW(HVDBG_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            lastError_ = "HvDbg driver not loaded (\\\\.\\HvDbg is not present).";
        else if (e == ERROR_ACCESS_DENIED)
            lastError_ = "Access denied opening \\\\.\\HvDbg - run DisasmStudio as Administrator.";
        else
            lastError_ = "CreateFile(\\\\.\\HvDbg) failed (error " + std::to_string((unsigned)e) + ").";
        handle_ = nullptr;
        return false;
    }
    handle_ = h;
    lastError_.clear();
    return true;
}

void HvDbgClient::disconnect() {
    if (handle_) { CloseHandle((HANDLE)handle_); handle_ = nullptr; }
}

bool HvDbgClient::ioctl(unsigned long code, void* in, unsigned long inLen,
                        void* out, unsigned long outLen, unsigned long* returned) {
    if (!handle_) { lastError_ = "Not connected to \\\\.\\HvDbg."; return false; }
    DWORD ret = 0;
    BOOL ok = DeviceIoControl((HANDLE)handle_, code, in, inLen, out, outLen, &ret, nullptr);
    if (returned) *returned = ret;
    if (!ok) {
        lastError_ = "DeviceIoControl failed (error " + std::to_string((unsigned)GetLastError()) + ").";
        return false;
    }
    return true;
}

bool HvDbgClient::ping(HVDBG_INFO& out) {
    out = HVDBG_INFO{};
    unsigned long ret = 0;
    if (!ioctl(IOCTL_HVDBG_PING, nullptr, 0, &out, sizeof(out), &ret)) return false;
    if (ret < sizeof(out) || out.magic != HVDBG_PROTOCOL_MAGIC) {
        lastError_ = "Bad handshake from \\\\.\\HvDbg (not an HvDbg driver?).";
        return false;
    }
    if (out.abiVersion != HVDBG_ABI_VERSION)
        lastError_ = "HvDbg driver ABI " + std::to_string(out.abiVersion) +
                     " != client ABI " + std::to_string((unsigned)HVDBG_ABI_VERSION) + " (rebuild driver).";
    return true;
}

bool HvDbgClient::getState(HVDBG_INFO& out) {
    out = HVDBG_INFO{};
    unsigned long ret = 0;
    if (!ioctl(IOCTL_HVDBG_GET_STATE, nullptr, 0, &out, sizeof(out), &ret)) return false;
    return ret >= sizeof(out) && out.magic == HVDBG_PROTOCOL_MAGIC;
}

bool HvDbgClient::virtualize()   { return ioctl(IOCTL_HVDBG_VIRTUALIZE,   nullptr, 0, nullptr, 0, nullptr); }
bool HvDbgClient::devirtualize() { return ioctl(IOCTL_HVDBG_DEVIRTUALIZE, nullptr, 0, nullptr, 0, nullptr); }

} // namespace ds
