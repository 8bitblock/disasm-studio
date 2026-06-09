#pragma once
//
// HvDbgClient.h
// Thin user-mode client for the AMD-V (SVM) debugging driver. Opens \\.\HvDbg
// and drives the IOCTL protocol in HvDbgProtocol.h. All methods are no-throw and
// report failure via return value + lastError(); connect() simply fails (rather
// than asserting) when the driver isn't loaded, so the UI degrades gracefully.
//
#include "HvDbgProtocol.h"   // HVDBG_INFO + IOCTL codes (pulls <windows.h> on the user side)
#include <string>

namespace ds {

class HvDbgClient {
public:
    HvDbgClient() = default;
    ~HvDbgClient();
    HvDbgClient(const HvDbgClient&) = delete;
    HvDbgClient& operator=(const HvDbgClient&) = delete;

    bool connect();                       // open \\.\HvDbg; false if not present / no rights
    void disconnect();
    bool connected() const { return handle_ != nullptr; }

    bool ping(HVDBG_INFO& out);           // IOCTL_HVDBG_PING     (handshake + capabilities)
    bool getState(HVDBG_INFO& out);       // IOCTL_HVDBG_GET_STATE (no side effects)
    bool virtualize();                    // IOCTL_HVDBG_VIRTUALIZE
    bool devirtualize();                  // IOCTL_HVDBG_DEVIRTUALIZE

    const std::string& lastError() const { return lastError_; }

private:
    bool ioctl(unsigned long code, void* in, unsigned long inLen,
               void* out, unsigned long outLen, unsigned long* returned);

    void*       handle_ = nullptr;        // HANDLE (void* to keep <windows.h> out of callers that don't need it)
    std::string lastError_;
};

} // namespace ds
