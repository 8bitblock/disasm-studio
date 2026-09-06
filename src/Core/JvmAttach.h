#pragma once
//
// JvmAttach.h
// Windows HotSpot *dynamic attach*: load the JDWP agent into an ALREADY-RUNNING
// JVM, with no `-agentlib:jdwp` prelaunch flag. This is the mechanism `jcmd` /
// IntelliJ "attach to process" use — it is what makes "debug any running Java
// process" possible (the JDWP socket protocol in Jdwp.* still does the actual
// debugging once the agent is listening).
//
// How it works (the OpenJDK Windows attach path):
//   1. Find jvm.dll in the target and confirm it's a 64-bit HotSpot/OpenJ9 VM.
//   2. Resolve jvm.dll!JVM_EnqueueOperation from the target's mapped PE export
//      table, then CreateRemoteThread a tiny position-independent x64 stub that
//      calls that validated target address with: cmd="load", arg0="jdwp", arg1="false",
//      arg2="transport=dt_socket,server=y,suspend=n,address=127.0.0.1:<port>".
//   3. The VM's attach listener loads the JDWP agent (which starts listening on
//      the port) and writes the completion code back over a named pipe.
//   4. The caller then connects to 127.0.0.1:<port> with JdwpClient.
//
// The live injection is Win32 integration code. Its remote-memory cleanup rule
// is kept as a pure policy below so timeout/failure handling is unit-testable.
//
#include <cstdint>
#include <string>

namespace ds {

// Which VM is hosted. Only HotSpot exports JVM_EnqueueOperation, so only HotSpot
// supports the CreateRemoteThread dynamic-attach path here. OpenJ9 uses a
// different (file-based) attach protocol that this build does not implement.
enum class JvmFlavor { None, HotSpot, OpenJ9 };

struct JvmInfo {
    JvmFlavor   flavor = JvmFlavor::None;
    bool        is64   = true;
    std::string vmPath;       // path of the VM module (when resolvable)
    uint64_t    vmBase = 0;   // target-process mapping base of jvm.dll / j9vm.dll
    uint64_t    vmSize = 0;   // target-process SizeOfImage reported by Toolhelp
    bool        hosts() const { return flavor != JvmFlavor::None; }
};

// Remote allocations are releasable only after the remote thread is proven to
// have exited. WAIT_TIMEOUT and WAIT_FAILED both mean it may still be fetching
// instructions or arguments from those allocations.
enum class JvmRemoteThreadCompletion { ConfirmedExited, MayStillRun };
constexpr bool CanReleaseJvmAttachRemoteMemory(JvmRemoteThreadCompletion state) {
    return state == JvmRemoteThreadCompletion::ConfirmedExited;
}

struct JvmAttachResult {
    bool        ok = false;       // VM confirmed the agent loaded (completion 0 over the pipe)
    bool        enqueued = false; // the load request was accepted by the VM (remote thread returned 0).
                                  // With server=y the agent is then very likely listening even if the
                                  // pipe result didn't arrive — the caller should try connecting anyway.
    std::string error;        // human-readable failure reason when !ok
    std::string agentOutput;  // text the VM wrote back (carries the reason on failure)
    uint16_t    port = 0;     // the port the JDWP agent is now listening on
};

// Inspect the modules of `pid` for a hosted Java VM (HotSpot jvm.dll, OpenJ9
// j9vm.dll), reporting the flavor, bitness, and VM module path. flavor == None
// for a non-Java process.
JvmInfo InspectJvm(uint32_t pid);

// Back-compat convenience: true if `pid` hosts any Java VM. Fills `jvmPath`/`is64`.
bool ProcessHostsJvm(uint32_t pid, std::string& jvmPath, bool& is64);

// Load the JDWP agent into the running JVM `pid`, making it listen on
// 127.0.0.1:`port`. Requires an x64 target (and an x64 host). On success the
// caller connects with JdwpClient::attach("127.0.0.1", port). `timeoutMs`
// bounds the remote-thread + pipe-readback wait.
JvmAttachResult LoadJdwpAgent(uint32_t pid, uint16_t port, int timeoutMs = 8000);

} // namespace ds
