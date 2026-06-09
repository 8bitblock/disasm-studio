#pragma once
//
// ProcessManager.h
// Real Win32 process enumeration, attach/detach (debug API), and memory reads.
// This is the native-process backend for the Communications + Memory tabs.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

struct ProcessInfo {
    uint32_t    pid    = 0;
    uint32_t    ppid   = 0;
    std::string name;
    bool        is64   = true;   // best-effort; WOW64 => 32-bit
    bool        canOpen = false; // had rights to open for query
};

struct ModuleInfo {
    std::string name;
    uint64_t    base = 0;
    uint64_t    size = 0;
    std::string path;
};

// Enumerates and attaches to live processes. Attach uses the Win32 debug API
// (DebugActiveProcess); memory reads use ReadProcessMemory. A real debug-event
// pump would build on pumpDebugEvent() to deliver breakpoints/single-steps.
class ProcessManager {
public:
    ~ProcessManager();

    // Snapshot all processes (Toolhelp32). Cheap enough to call on demand.
    std::vector<ProcessInfo> enumerate() const;

    // List loaded modules for a pid (Toolhelp32 module snapshot).
    std::vector<ModuleInfo> modules(uint32_t pid) const;

    // Attach the debugger to a pid. Returns false on failure (sets lastError()).
    bool attach(uint32_t pid);
    void detach();
    bool attached() const { return attachedPid_ != 0; }
    uint32_t attachedPid() const { return attachedPid_; }

    // Read process memory into out (resized to size). Returns bytes read.
    size_t readMemory(uint64_t address, void* out, size_t size) const;
    bool   readMemory(uint64_t address, std::vector<uint8_t>& out, size_t size) const;

    // Pump one debug event (non-blocking-ish; uses a 0ms wait). Returns true if
    // an event was processed. Continues the debuggee automatically.
    bool pumpDebugEvent(std::string& eventDesc);

    const std::string& lastError() const { return lastError_; }

private:
    void   close();

    uint32_t   attachedPid_ = 0;
    void*      hProcess_    = nullptr; // HANDLE
    std::string lastError_;
};

} // namespace ds
