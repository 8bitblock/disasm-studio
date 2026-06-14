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
//   2. CreateRemoteThread a tiny position-independent x64 stub that, inside the
//      target, resolves jvm.dll!JVM_EnqueueOperation (via GetModuleHandleA /
//      GetProcAddress, whose addresses are identical across the session) and
//      calls it with: cmd="load", arg0="jdwp", arg1="false",
//      arg2="transport=dt_socket,server=y,suspend=n,address=127.0.0.1:<port>".
//   3. The VM's attach listener loads the JDWP agent (which starts listening on
//      the port) and writes the completion code back over a named pipe.
//   4. The caller then connects to 127.0.0.1:<port> with JdwpClient.
//
// Win32 + a live JVM, so this is review-verified, not unit-tested.
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
    bool        hosts() const { return flavor != JvmFlavor::None; }
};

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
