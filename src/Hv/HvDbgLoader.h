#pragma once
//
// HvDbgLoader.h
// User-mode loader for the AMD-V (SVM) kernel driver (driver/HvDbg.sys). Drives
// the Service Control Manager to register a SERVICE_KERNEL_DRIVER entry pointing
// at HvDbg.sys, start it (which runs DriverEntry and creates \\.\HvDbg), and on
// teardown stop + delete the service. Once loaded, HvDbgClient can open the
// device.
//
// All methods are no-throw and report failure via return value + lastError().
// Loading a kernel driver requires (a) an elevated process and (b) the driver to
// be signed or the machine to be in test-signing mode - the loader reports those
// conditions through lastError() rather than asserting, so the UI degrades
// gracefully.
//
#include <string>

namespace ds {

class HvDbgLoader {
public:
    // Live state of the HvDbg kernel service, as seen through the SCM.
    enum class State { NotInstalled, Stopped, Running, Unknown };

    HvDbgLoader() = default;
    ~HvDbgLoader();
    HvDbgLoader(const HvDbgLoader&) = delete;
    HvDbgLoader& operator=(const HvDbgLoader&) = delete;

    // Full bring-up: create the kernel service (if not already present) pointing
    // at sysPath, then start it. Idempotent - succeeds when already running.
    // Pass an empty sysPath to use defaultSysPath() (HvDbg.sys next to the exe).
    bool load(const std::wstring& sysPath = std::wstring());

    // Stop the driver (if running) and delete its service entry. Idempotent -
    // succeeds when the service is already gone.
    bool unload();

    // Start / stop an already-installed service without touching its registration.
    bool start();
    bool stop();

    State state() const;            // queries the SCM live; never caches
    bool  installed() const { return state() != State::NotInstalled; }
    bool  running()   const { return state() == State::Running; }

    // Whether the current process is elevated (a precondition for load/unload).
    static bool isElevated();

    // Default driver image path: HvDbg.sys in the same directory as this exe.
    static std::wstring defaultSysPath();

    const std::string& lastError() const { return lastError_; }

private:
    // The kernel-driver service name (and \\.\HvDbg matches the device, not this).
    static constexpr const wchar_t* kServiceName = L"HvDbg";
    static constexpr const wchar_t* kDisplayName = L"DisasmStudio AMD-V (SVM) Debug Driver";

    void setError(const char* what, unsigned long winErr);
    void clearError() { lastError_.clear(); }

    std::string lastError_;
};

} // namespace ds
