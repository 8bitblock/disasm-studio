#pragma once
//
// JdwpClient.h
// A live JVM (Java) debugger over JDWP. Connects to a JVM started with
//   -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
// and drives it at the BYTECODE level: suspend/resume, breakpoints at
// (class, method, bci), single-step into/over/out, thread + frame inspection,
// and Method::Bytecodes / ReferenceType::ConstantPool fetches so the UI can
// disassemble live bytecode with the same JvmDisassembler used for .class
// files. Mirrors the Debugger pattern: one reader thread owns the socket, the
// UI posts requests and reads a mutex-guarded snapshot.
//
// Threading contract:
//   - attach()/detach() and every public request run on the caller (UI) thread;
//     RPCs block on the reply with a short timeout (localhost JDWP is sub-ms).
//   - the reader thread pumps incoming packets, parks replies for waiting
//     callers, and handles events (stop bookkeeping + follow-up RPCs through
//     its own nested pump, never through the caller-side wait path).
// All wire encode/decode lives in Core/Jdwp.{h,cpp} (pure, unit-tested);
// this file is the socket + session-state shell (review-verified, Winsock).
//
#include "Jdwp.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ds {

enum class JdwpState { Detached, Running, Suspended, Dead };

struct JdwpThreadRow {
    uint64_t    id = 0;
    std::string name;
    int32_t     status = 0;        // JDWP_TS_*
};
struct JdwpClassRow {
    uint64_t    typeID = 0;
    std::string name;              // "com/foo/Bar"
    std::string signature;         // "Lcom/foo/Bar;"
};
struct JdwpMethodRow {
    uint64_t    methodID = 0;
    std::string name, signature;
    uint32_t    modBits = 0;
};
struct JdwpBpRow {
    int32_t      requestID = 0;
    JdwpLocation loc;
    std::string  label;            // "Bar.main bci=5"
    uint32_t     hits = 0;
};
struct JdwpFrameRow {
    uint64_t     frameID = 0;
    JdwpLocation loc;
    std::string  label;            // "Bar.main bci=5" (best-effort names)
};

struct JdwpSnapshot {
    JdwpState    state = JdwpState::Detached;
    std::string  host;
    uint16_t     port = 0;
    std::string  vmName, vmVersion;
    std::string  lastEvent = "idle";
    JdwpIdSizes  idSizes;
    uint64_t     stopThread = 0;   // thread of the last stop (0 = none)
    JdwpLocation stopLoc;          // classID == 0 means "no location" (VM-wide suspend)
    std::vector<JdwpThreadRow>  threads;
    std::vector<JdwpFrameRow>   frames;      // of stopThread, top first
    std::vector<JdwpBpRow>      breakpoints;
    std::vector<std::string>    events;      // bounded session log, newest last
    // Loaded classes, shared (large): replaced wholesale on refresh, so a
    // per-frame snapshot() is one pointer copy, not a 10k-row vector copy.
    std::shared_ptr<const std::vector<JdwpClassRow>> classes;
    bool attached() const { return state == JdwpState::Running || state == JdwpState::Suspended; }
};

class JdwpClient {
public:
    JdwpClient() = default;
    ~JdwpClient();
    JdwpClient(const JdwpClient&) = delete;
    JdwpClient& operator=(const JdwpClient&) = delete;

    // Connect + handshake + IDSizes/Version + AllClasses, then start the
    // reader thread. Synchronous (3 s connect timeout); false + err on failure.
    bool attach(const std::string& host, uint16_t port, std::string& err);
    void detach();                          // best-effort VM_Dispose + close + join

    JdwpSnapshot snapshot();

    // Execution control. Steps act on the stopped thread.
    void suspendAll();
    void resumeAll();
    void stepInto();
    void stepOver();
    void stepOut();

    // Breakpoints at (class, method, bci).
    bool setBreakpoint(const JdwpLocation& loc, const std::string& label, std::string& err);
    void clearBreakpoint(int32_t requestID);

    // Browsing (blocking RPCs on the caller thread, short timeout).
    void refreshClasses();
    bool methodsOf(uint64_t typeID, std::vector<JdwpMethodRow>& out);
    bool bytecodesOf(uint64_t typeID, uint64_t methodID, std::vector<uint8_t>& out);
    bool constantPoolOf(uint64_t typeID, uint32_t& cpCount, std::vector<uint8_t>& cpBytes);
    bool lineTableOf(uint64_t typeID, uint64_t methodID,
                     std::vector<std::pair<uint64_t, uint32_t>>& out);

private:
    // ---- RPC plumbing ----
    uint32_t sendCommand(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload);
    // Caller-side RPC: send + wait for the reader thread to park the reply.
    bool request(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                 JdwpPacket& reply, int timeoutMs = 1500);
    // Reader-side RPC: send + pump the socket inline until the reply arrives
    // (events seen meanwhile are queued, not recursed into).
    bool readerRequest(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                       JdwpPacket& reply, int timeoutMs = 1500);
    bool pumpSocket(int timeoutMs);         // select+recv+frame; parks replies, queues events
    void readerMain();
    void handleEvent(const JdwpEventSet& es);
    void onStopped(const JdwpEvent& e, const char* kind);
    void stepCommon(uint32_t depth, const char* what);
    // Reader-thread refreshers (attach() uses them too, before the thread starts).
    void refreshClassesViaReader();
    void refreshThreadsViaReader();
    std::string locationLabel(const JdwpLocation& loc);   // reader thread only
    void closeSocket();
    void pushEvent(const std::string& line);

    // ---- session state (guarded by mtx_ unless noted) ----
    std::mutex                     mtx_;
    std::condition_variable        replyCv_;
    std::map<uint32_t, JdwpPacket> replies_;       // parked replies by packet id
    std::atomic<uint32_t>          nextId_{1};
    std::atomic<bool>              quit_{false};

    uintptr_t                      sock_ = ~(uintptr_t)0;   // INVALID_SOCKET
    std::mutex                     sendMtx_;                // serializes send()
    std::thread                    reader_;
    std::vector<uint8_t>           rxBuf_;                  // reader thread only
    std::deque<JdwpEventSet>       pendingEvents_;          // reader thread only (nested pumps)
    int                            pumpDepth_ = 0;          // reader thread only

    JdwpState                      state_ = JdwpState::Detached;
    std::string                    host_;
    uint16_t                       port_ = 0;
    std::string                    vmName_, vmVersion_;
    std::string                    lastEvent_ = "idle";
    JdwpIdSizes                    sizes_;
    uint64_t                       stopThread_ = 0;
    JdwpLocation                   stopLoc_;
    std::vector<JdwpThreadRow>     threads_;
    std::vector<JdwpFrameRow>      frames_;
    std::vector<JdwpBpRow>         bps_;
    std::deque<std::string>        events_;                 // capped ring
    std::shared_ptr<const std::vector<JdwpClassRow>> classes_;
    int32_t                        activeStepReq_ = -1;     // outstanding SINGLE_STEP request
    // method-name cache for frame/stop labels: classID -> (methodID -> name)
    std::map<uint64_t, std::map<uint64_t, std::string>> methodNameCache_;
};

} // namespace ds
