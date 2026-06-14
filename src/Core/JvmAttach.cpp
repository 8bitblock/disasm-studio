#include "JvmAttach.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ds {

// ---- target inspection --------------------------------------------------------

static bool processIs64(HANDLE proc) {
    // Prefer IsWow64Process2 (Win10+, also correct on ARM64): a non-UNKNOWN
    // process machine means the process runs emulated under WOW64 -> 32-bit.
    // The classic IsWow64Process is the fallback.
    using PFN_IWP2 = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    static PFN_IWP2 pIsWow64Process2 = (PFN_IWP2)::GetProcAddress(
        ::GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (pIsWow64Process2) {
        USHORT procMach = 0, nativeMach = 0;
        if (pIsWow64Process2(proc, &procMach, &nativeMach))
            return procMach == IMAGE_FILE_MACHINE_UNKNOWN;   // UNKNOWN = native (64-bit on an x64 host)
    }
    BOOL wow = FALSE;
    if (!::IsWow64Process(proc, &wow)) return true;
    return !wow;
}

// Lowercased base name of a module entry.
static bool isModuleNamed(const char* name, const char* want) {
    std::string b;
    for (const char* p = name; *p; ++p) b.push_back((char)std::tolower((unsigned char)*p));
    return b == want;
}

JvmInfo InspectJvm(uint32_t pid) {
    JvmInfo info;
    if (!pid) return info;

    if (HANDLE proc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)) {
        info.is64 = processIs64(proc);
        ::CloseHandle(proc);
    }

    // Toolhelp module snapshot (include 32-bit modules so a WOW64 JVM is still seen).
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return info;
    bool haveJvm = false, haveJ9 = false;
    std::string jvmPath, j9Path;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (::Module32FirstW(snap, &me)) {
        do {
            char name[MAX_PATH];
            if (::WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, name, sizeof(name), nullptr, nullptr) <= 0)
                continue;
            char full[MAX_PATH] = {0};
            ::WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, full, sizeof(full), nullptr, nullptr);
            // OpenJ9 ships BOTH jvm.dll (a JNI shim) and j9vm.dll; the j9vm.dll
            // presence is what distinguishes it from HotSpot. Check it first.
            if (isModuleNamed(name, "j9vm.dll")) { haveJ9 = true; j9Path = full; }
            else if (isModuleNamed(name, "jvm.dll")) { haveJvm = true; jvmPath = full; }
        } while (::Module32NextW(snap, &me));
    }
    ::CloseHandle(snap);

    if (haveJ9)       { info.flavor = JvmFlavor::OpenJ9;  info.vmPath = j9Path.empty() ? jvmPath : j9Path; }
    else if (haveJvm) { info.flavor = JvmFlavor::HotSpot; info.vmPath = jvmPath; }
    return info;
}

bool ProcessHostsJvm(uint32_t pid, std::string& jvmPath, bool& is64) {
    JvmInfo info = InspectJvm(pid);
    jvmPath = info.vmPath;
    is64    = info.is64;
    return info.hosts();
}

// ---- the injected stub --------------------------------------------------------
//
// Position-independent x64 thread routine. RCX = &DataBlock on entry. It resolves
// jvm.dll!JVM_EnqueueOperation in the TARGET (GetModuleHandleA + GetProcAddress)
// and calls it with (cmd, arg0, arg1, arg2, pipename). All operands are
// rbx-relative, so the stub needs no relocation once written into the target.
//
// CRITICAL: both resolutions are null-checked. A VM whose jvm.dll lacks
// JVM_EnqueueOperation (OpenJ9, or any non-HotSpot VM) would otherwise have the
// injected thread CALL address 0 and crash the target process. On a null result
// the stub returns 0xFFFFFFFF instead, which LoadJdwpAgent reports as "not a
// HotSpot VM" — the debuggee is left untouched.
//
// The exact bytes are emitted by Keystone from this asm (tests/jvm_stub_gen.cpp);
// re-run it to regenerate if the asm changes — do NOT hand-edit the jz/jmp rels.
//   push  rbx
//   sub   rsp, 0x30                ; 0x20 shadow + 5th-arg slot, 16-aligned
//   mov   rbx, rcx                 ; rbx = &DataBlock
//   lea   rcx, [rbx+0x10]          ; jvmLib "jvm"
//   call  qword ptr [rbx]          ; GetModuleHandleA
//   test  rax, rax
//   jz    fail                     ; jvm.dll not present
//   mov   rcx, rax
//   lea   rdx, [rbx+0x30]          ; func "JVM_EnqueueOperation"
//   call  qword ptr [rbx+8]        ; GetProcAddress
//   test  rax, rax
//   jz    fail                     ; export absent -> never call NULL
//   lea   rcx, [rbx+0x70]          ; cmd
//   lea   rdx, [rbx+0x180]         ; arg0
//   lea   r8,  [rbx+0x580]         ; arg1
//   lea   r9,  [rbx+0x980]         ; arg2
//   lea   r10, [rbx+0x80]          ; pipename
//   mov   [rsp+0x20], r10          ; 5th arg
//   call  rax                      ; JVM_EnqueueOperation(...)
//   jmp   done
// fail:
//   mov   eax, 0xFFFFFFFF          ; sentinel: resolution failed
// done:
//   add   rsp, 0x30
//   pop   rbx
//   ret
static const uint8_t kStub[] = {
    0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89, 0xCB,
    0x48, 0x8D, 0x4B, 0x10, 0xFF, 0x13, 0x48, 0x85,
    0xC0, 0x74, 0x38, 0x48, 0x89, 0xC1, 0x48, 0x8D,
    0x53, 0x30, 0xFF, 0x53, 0x08, 0x48, 0x85, 0xC0,
    0x74, 0x29, 0x48, 0x8D, 0x4B, 0x70, 0x48, 0x8D,
    0x93, 0x80, 0x01, 0x00, 0x00, 0x4C, 0x8D, 0x83,
    0x80, 0x05, 0x00, 0x00, 0x4C, 0x8D, 0x8B, 0x80,
    0x09, 0x00, 0x00, 0x4C, 0x8D, 0x93, 0x80, 0x00,
    0x00, 0x00, 0x4C, 0x89, 0x54, 0x24, 0x20, 0xFF,
    0xD0, 0xEB, 0x05, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
    0x48, 0x83, 0xC4, 0x30, 0x5B, 0xC3,
};
// The stub returns this when it could not resolve JVM_EnqueueOperation (so it
// safely did NOT call into the VM). Matches `mov eax, 0xFFFFFFFF` above.
static constexpr DWORD kStubResolveFailed = 0xFFFFFFFFu;

// DataBlock layout (offsets must match the lea displacements above).
namespace {
constexpr size_t kOffGetModuleHandle = 0x00;
constexpr size_t kOffGetProcAddress  = 0x08;
constexpr size_t kOffJvmLib          = 0x10;   // 32 bytes
constexpr size_t kOffFunc            = 0x30;   // 64 bytes
constexpr size_t kOffCmd             = 0x70;   // 16 bytes
constexpr size_t kOffPipe            = 0x80;   // 256 bytes
constexpr size_t kOffArg0            = 0x180;  // 1024 bytes
constexpr size_t kOffArg1            = 0x580;  // 1024 bytes
constexpr size_t kOffArg2            = 0x980;  // 1024 bytes
constexpr size_t kDataBlockSize      = 0xD80;  // 0x980 + 0x400

void putPtr(std::vector<uint8_t>& b, size_t off, const void* p) {
    uint64_t v = (uint64_t)p;
    std::memcpy(b.data() + off, &v, 8);
}
void putStr(std::vector<uint8_t>& b, size_t off, size_t cap, const char* s) {
    size_t n = std::strlen(s);
    if (n >= cap) n = cap - 1;
    std::memcpy(b.data() + off, s, n);   // remainder already zero
}
} // namespace

// ---- named-pipe result readback (overlapped, with a deadline) ------------------

// Waits for the VM to connect to `pipe` and writes everything it sends into
// `out`, bounded by `deadline`. Returns false on timeout / error.
static bool readPipeResult(HANDLE pipe, std::string& out, DWORD timeoutMs) {
    HANDLE ev = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ev) return false;
    OVERLAPPED ov{};
    ov.hEvent = ev;

    bool connected = false;
    if (::ConnectNamedPipe(pipe, &ov)) {
        connected = true;
    } else {
        DWORD e = ::GetLastError();
        if (e == ERROR_PIPE_CONNECTED) connected = true;
        else if (e == ERROR_IO_PENDING) {
            if (::WaitForSingleObject(ev, timeoutMs) == WAIT_OBJECT_0) {
                DWORD got = 0;
                connected = ::GetOverlappedResult(pipe, &ov, &got, FALSE) != 0;
            } else {
                ::CancelIo(pipe);
            }
        }
    }
    if (!connected) { ::CloseHandle(ev); return false; }

    char buf[1024];
    bool any = false;
    for (;;) {
        ::ResetEvent(ev);
        OVERLAPPED rov{};
        rov.hEvent = ev;
        DWORD got = 0;
        BOOL rc = ::ReadFile(pipe, buf, sizeof(buf), &got, &rov);
        if (!rc) {
            DWORD e = ::GetLastError();
            if (e == ERROR_IO_PENDING) {
                if (::WaitForSingleObject(ev, timeoutMs) != WAIT_OBJECT_0) { ::CancelIo(pipe); break; }
                if (!::GetOverlappedResult(pipe, &rov, &got, FALSE)) break;   // BROKEN_PIPE = VM done
            } else {
                break;   // ERROR_BROKEN_PIPE etc.: the VM closed its end
            }
        }
        if (got == 0) break;
        out.append(buf, got);
        any = true;
        if (out.size() > 64 * 1024) break;   // sanity cap
    }
    ::CloseHandle(ev);
    return any;
}

// First line "N\n" is the completion code; returns it (or -1 if unparseable).
static int parseCompletion(const std::string& s) {
    if (s.empty()) return -1;
    size_t nl = s.find('\n');
    std::string head = (nl == std::string::npos) ? s : s.substr(0, nl);
    try { return std::stoi(head); } catch (...) { return -1; }
}

// ---- the attach itself ---------------------------------------------------------

JvmAttachResult LoadJdwpAgent(uint32_t pid, uint16_t port, int timeoutMs) {
    JvmAttachResult res;
    res.port = port;

    JvmInfo jvm = InspectJvm(pid);
    if (!jvm.hosts()) {
        res.error = "the selected process does not host a Java VM (no jvm.dll / j9vm.dll loaded)";
        return res;
    }
    if (jvm.flavor == JvmFlavor::OpenJ9) {
        // OpenJ9's jvm.dll does not export JVM_EnqueueOperation; its attach uses a
        // separate file-based protocol this build doesn't implement. Reject up front
        // (the stub's null-guard would also catch it, but a clear message is better).
        res.error = "this is an OpenJ9 VM (j9vm.dll); dynamic JDWP attach here supports HotSpot only. "
                    "Relaunch the app with -agentlib:jdwp=...,server=y,address=*:" + std::to_string(port) +
                    " and use the host:port connect, or debug it natively.";
        return res;
    }
#ifdef _WIN64
    if (!jvm.is64) {
        res.error = "target is a 32-bit JVM; this build can only inject into a 64-bit JVM "
                    "(debug it natively via Attach, or connect a -agentlib:jdwp agent by host:port)";
        return res;
    }
#else
    res.error = "the disassembler must be 64-bit to inject into a 64-bit JVM";
    return res;
#endif

    // GetModuleHandleA / GetProcAddress live in kernel32, mapped at the same base in
    // every process of the session, so their local addresses are valid in the target.
    HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
    void* pGetModuleHandle = k32 ? (void*)::GetProcAddress(k32, "GetModuleHandleA") : nullptr;
    void* pGetProcAddress  = k32 ? (void*)::GetProcAddress(k32, "GetProcAddress")  : nullptr;
    if (!pGetModuleHandle || !pGetProcAddress) {
        res.error = "could not resolve kernel32 thunks";
        return res;
    }

    HANDLE proc = ::OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                FALSE, pid);
    if (!proc) {
        res.error = "OpenProcess failed (try running the disassembler as Administrator)";
        return res;
    }

    // A unique pipe name; the VM connects back to it with the completion result.
    char pipeName[128];
    std::snprintf(pipeName, sizeof(pipeName), "\\\\.\\pipe\\javatool%u_%lu",
                  pid, (unsigned long)::GetTickCount());
    HANDLE pipe = ::CreateNamedPipeA(pipeName, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 8192, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        ::CloseHandle(proc);
        res.error = "CreateNamedPipe failed";
        return res;
    }

    // Build the data block.
    std::vector<uint8_t> data(kDataBlockSize, 0);
    putPtr(data, kOffGetModuleHandle, pGetModuleHandle);
    putPtr(data, kOffGetProcAddress,  pGetProcAddress);
    putStr(data, kOffJvmLib, 32, "jvm");
    putStr(data, kOffFunc,   64, "JVM_EnqueueOperation");
    putStr(data, kOffCmd,    16, "load");
    putStr(data, kOffPipe,  256, pipeName);
    putStr(data, kOffArg0, 1024, "jdwp");
    putStr(data, kOffArg1, 1024, "false");
    char opts[160];
    std::snprintf(opts, sizeof(opts),
                  "transport=dt_socket,server=y,suspend=n,address=127.0.0.1:%u", (unsigned)port);
    putStr(data, kOffArg2, 1024, opts);

    auto fail = [&](const char* why, LPVOID rData, LPVOID rStub) {
        if (rData) ::VirtualFreeEx(proc, rData, 0, MEM_RELEASE);
        if (rStub) ::VirtualFreeEx(proc, rStub, 0, MEM_RELEASE);
        ::CloseHandle(pipe);
        ::CloseHandle(proc);
        res.error = why;
        return res;
    };

    // Remote allocations: data (RW) + stub (RX).
    LPVOID rData = ::VirtualAllocEx(proc, nullptr, data.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rData) return fail("VirtualAllocEx (data) failed", nullptr, nullptr);
    LPVOID rStub = ::VirtualAllocEx(proc, nullptr, sizeof(kStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!rStub) return fail("VirtualAllocEx (stub) failed", rData, nullptr);

    SIZE_T wrote = 0;
    if (!::WriteProcessMemory(proc, rData, data.data(), data.size(), &wrote) || wrote != data.size())
        return fail("WriteProcessMemory (data) failed", rData, rStub);
    // The stub region is PAGE_EXECUTE_READ; WriteProcessMemory flips it writable
    // for the copy and restores protection itself.
    if (!::WriteProcessMemory(proc, rStub, kStub, sizeof(kStub), &wrote) || wrote != sizeof(kStub))
        return fail("WriteProcessMemory (stub) failed", rData, rStub);
    ::FlushInstructionCache(proc, rStub, sizeof(kStub));

    HANDLE thread = ::CreateRemoteThread(proc, nullptr, 0,
                                         (LPTHREAD_START_ROUTINE)rStub, rData, 0, nullptr);
    if (!thread) return fail("CreateRemoteThread failed", rData, rStub);

    // The enqueue thread returns quickly; the operation completes on the VM's
    // attach-listener thread, which connects to our pipe with the result.
    ::WaitForSingleObject(thread, (DWORD)timeoutMs);
    DWORD enqueueRc = 0;
    ::GetExitCodeThread(thread, &enqueueRc);
    ::CloseHandle(thread);

    // The stub returns the sentinel when it safely declined to call a missing
    // JVM_EnqueueOperation (so the target was NOT touched). No pipe reply will come.
    if (enqueueRc == kStubResolveFailed) {
        ::VirtualFreeEx(proc, rData, 0, MEM_RELEASE);
        ::VirtualFreeEx(proc, rStub, 0, MEM_RELEASE);
        ::CloseHandle(pipe);
        ::CloseHandle(proc);
        res.error = "jvm.dll does not export JVM_EnqueueOperation \xE2\x80\x94 not a HotSpot VM "
                    "(the target was left untouched)";
        return res;
    }

    // enqueueRc == 0 means JVM_EnqueueOperation accepted the load request; the
    // operation then runs on the VM's attach-listener thread.
    res.enqueued = (enqueueRc == 0);

    std::string reply;
    const bool gotReply = readPipeResult(pipe, reply, (DWORD)timeoutMs);

    ::VirtualFreeEx(proc, rData, 0, MEM_RELEASE);
    ::VirtualFreeEx(proc, rStub, 0, MEM_RELEASE);
    ::CloseHandle(pipe);
    ::CloseHandle(proc);

    res.agentOutput = reply;
    if (!gotReply) {
        // No status came back over the pipe. If the request was accepted, the
        // agent is most likely already listening (server=y) — report enqueued so
        // the caller still tries to connect, rather than treating this as fatal.
        res.error = res.enqueued
            ? "the VM accepted the load request but didn't confirm over the result pipe; "
              "the JDWP agent is probably listening \xE2\x80\x94 connecting anyway"
            : "JVM_EnqueueOperation did not accept the request (attach may be disabled with -XX:+DisableAttachMechanism)";
        return res;
    }
    int completion = parseCompletion(reply);
    if (completion != 0) {
        // A definitive refusal from the VM (agent already loaded, jdwp.dll missing,
        // bad options, port in use, ...). NOT a connect-anyway case — clear enqueued
        // so the caller surfaces this real reason instead of a generic connect error.
        res.enqueued = false;
        // The text after the "N\n" completion line is the agent's own message.
        std::string detail = reply;
        if (size_t nl = detail.find('\n'); nl != std::string::npos) detail = detail.substr(nl + 1);
        while (!detail.empty() && (detail.back() == '\n' || detail.back() == '\r' || detail.back() == ' '))
            detail.pop_back();
        std::string hint;
        std::string low = detail;
        for (char& c : low) c = (char)std::tolower((unsigned char)c);
        if (low.find("agent_onattach") != std::string::npos || low.find("not available") != std::string::npos) {
            // jdwp loaded but its attach entry wasn't found. Usual causes: a JRE /
            // jlink runtime that omits the JDWP agent, or a bitness mismatch.
            hint = "  [the JVM's jdwp library has no attach entry \xE2\x80\x94 it's likely a JRE or a "
                   "jlink/jpackage runtime built without the jdk.jdwp.agent module, or a 32-bit VM. "
                   "Use a full JDK, or relaunch with -agentlib:jdwp=transport=dt_socket,server=y,address=*:" +
                   std::to_string(port) + " and use the host:port Connect.]";
        } else if (low.find("already") != std::string::npos) {
            hint = "  [a prior attempt is still bound to port " + std::to_string(port) +
                   " \xE2\x80\x94 just click Connect, or restart the JVM]";
        }
        res.error = "the VM refused to load the JDWP agent (code " + std::to_string(completion) + ")" +
                    (detail.empty() ? "" : ": " + detail) + hint;
        return res;
    }
    res.ok = true;
    return res;
}

} // namespace ds
