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
//   - one connection thread exclusively owns the SOCKET for its complete
//     lifetime: resolution/connect/handshake, send/recv, shutdown, and close.
//   - attach()/detach() and every public RPC submit bounded commands and wait
//     only on command completion; caller/UI threads never perform socket I/O.
//   - event-triggered follow-up RPCs execute directly on the connection thread
//     through a nested pump, avoiding a command-queue self-deadlock.
// All wire encode/decode lives in Core/Jdwp.{h,cpp} (pure, unit-tested);
// this file is the socket + session-state shell (review-verified, Winsock).
//
#include "Jdwp.h"

#include <atomic>
#include <chrono>
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

    // Starts the connection thread and asks it to connect, handshake, and
    // bootstrap IDSizes/Version/classes/threads. The public API remains
    // synchronous for compatibility, but the wait is bounded and the caller
    // never touches Winsock or the socket.
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

    // Browsing (bounded waits for connection-thread RPC commands).
    void refreshClasses();
    bool methodsOf(uint64_t typeID, std::vector<JdwpMethodRow>& out);
    bool bytecodesOf(uint64_t typeID, uint64_t methodID, std::vector<uint8_t>& out);
    bool constantPoolOf(uint64_t typeID, uint32_t& cpCount, std::vector<uint8_t>& cpBytes);
    bool lineTableOf(uint64_t typeID, uint64_t methodID,
                     std::vector<std::pair<uint64_t, uint32_t>>& out);

#if defined(DS_JDWP_TEST_HOOKS)
    // Deterministically exercises the connection-thread exception boundary.
    // This declaration and its storage do not exist in production builds.
    void injectReaderFailureForTest();
#endif

private:
    // ---- RPC plumbing ----
    using Deadline = std::chrono::steady_clock::time_point;
    struct Command {
        enum class Kind { Connect, Request, Disconnect } kind = Kind::Request;
        std::string host;
        uint16_t port = 0;
        uint8_t set = 0, cmd = 0;
        std::vector<uint8_t> payload;
        Deadline deadline{};
        std::atomic<bool> cancelled{false};

        std::mutex doneMtx;
        std::condition_variable doneCv;
        bool done = false;
        bool ok = false;
        std::string error;
        JdwpPacket reply;
    };

    bool submitAndWait(const std::shared_ptr<Command>& command,
                       JdwpPacket* reply = nullptr, std::string* error = nullptr);
    bool enqueue(const std::shared_ptr<Command>& command, bool front = false);
    static void complete(const std::shared_ptr<Command>& command, bool ok,
                         JdwpPacket reply = {}, std::string error = {});
    static void failCommandNoThrow(const std::shared_ptr<Command>& command,
                                   const char* reason) noexcept;
    void failQueuedCommands(const char* reason) noexcept;

    // Caller-side RPC: enqueue + bounded wait for connection-thread completion.
    bool request(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                 JdwpPacket& reply, int timeoutMs = 1500);
    // Connection-thread RPC: send + pump the owned socket until the reply arrives
    // (events seen meanwhile are queued, not recursed into).
    bool readerRequest(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                       JdwpPacket& reply, int timeoutMs = 1500,
                       const std::atomic<bool>* cancelled = nullptr);
    bool readerRequestUntil(uint8_t set, uint8_t cmd,
                            const std::vector<uint8_t>& payload,
                            JdwpPacket& reply, Deadline deadline,
                            const std::atomic<bool>* cancelled = nullptr);
    uint32_t sendCommandOwned(uint8_t set, uint8_t cmd,
                              const std::vector<uint8_t>& payload,
                              Deadline deadline,
                              const std::atomic<bool>* cancelled = nullptr);
    bool sendAllOwned(const uint8_t* data, size_t size, Deadline deadline,
                      const std::atomic<bool>* cancelled = nullptr);
    bool pumpSocket(int timeoutMs);         // select+recv+frame; parks replies, queues events
    bool connectOwned(const std::string& host, uint16_t port, Deadline deadline,
                      const std::atomic<bool>* cancelled, std::string& err);
    bool bootstrapOwned(const std::string& host, uint16_t port, Deadline deadline,
                        const std::atomic<bool>* cancelled, std::string& err);
    void readerMain() noexcept;
    void readerLoop(std::shared_ptr<Command>& activeCommand);
    void finishReader(const std::shared_ptr<Command>& activeCommand,
                      const char* reason, bool failed) noexcept;
    void handleEvent(const JdwpEventSet& es);
    void onStopped(const JdwpEvent& e, const char* kind);
    void stepCommon(uint32_t depth, const char* what);
    // Connection-thread refreshers. Optional cancellation is used by attach.
    void refreshClassesViaReader(int timeoutMs = 5000,
                                 const std::atomic<bool>* cancelled = nullptr);
    void refreshThreadsViaReader(int timeoutMs = 2500,
                                 const std::atomic<bool>* cancelled = nullptr);
    std::string locationLabel(const JdwpLocation& loc);   // reader thread only
    void closeSocketOwned();
    void pushEvent(const std::string& line);

    // ---- session state (guarded by mtx_ unless noted) ----
    std::mutex                     mtx_;
    std::map<uint32_t, JdwpPacket> replies_;       // parked replies by packet id
    std::atomic<uint32_t>          nextId_{1};
    std::atomic<bool>              disconnectRequested_{false};

    // Command queue state. sock_, rxBuf_, pendingEvents_, and pumpDepth_ are
    // accessed only by reader_ after it starts and until it exits.
    std::mutex                     commandMtx_;
    std::condition_variable        commandCv_;
    std::deque<std::shared_ptr<Command>> commands_;
    bool                           acceptingCommands_ = false;
    bool                           workerRunning_ = false;
    std::thread                    reader_;
    uintptr_t                      sock_ = ~(uintptr_t)0;   // connection thread only
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
#if defined(DS_JDWP_TEST_HOOKS)
    std::atomic<bool>              injectReaderFailure_{false};
#endif
    // method-name cache for frame/stop labels: classID -> (methodID -> name)
    std::map<uint64_t, std::map<uint64_t, std::string>> methodNameCache_;
};

} // namespace ds
