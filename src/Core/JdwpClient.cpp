#include "JdwpClient.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>

#pragma comment(lib, "ws2_32.lib")

namespace ds {

using Clock = std::chrono::steady_clock;

static const uintptr_t kInvalidSock = ~(uintptr_t)0;
static_assert(sizeof(uintptr_t) >= sizeof(SOCKET), "SOCKET must fit uintptr_t");

static void ensureWinsock() {
    static bool done = [] {
        WSADATA wd;
        return ::WSAStartup(MAKEWORD(2, 2), &wd) == 0;
    }();
    (void)done;   // never cleaned up: process-lifetime
}

static std::string shortClass(const std::string& internalName) {
    const size_t s = internalName.find_last_of('/');
    return s == std::string::npos ? internalName : internalName.substr(s + 1);
}

// ---- lifecycle ----------------------------------------------------------------

JdwpClient::~JdwpClient() { detach(); }

bool JdwpClient::attach(const std::string& host, uint16_t port, std::string& err) {
    detach();                              // drop any previous session first
    err.clear();

    auto command = std::make_shared<Command>();
    command->kind = Command::Kind::Connect;
    command->host = host;
    command->port = port;
    // Connect + handshake are each capped internally. The larger aggregate
    // budget also covers ID negotiation and the initial bounded snapshots.
    command->deadline = Clock::now() + std::chrono::seconds(15);

    disconnectRequested_.store(false);
    {
        std::lock_guard<std::mutex> lk(commandMtx_);
        commands_.clear();
        acceptingCommands_ = true;
        workerRunning_ = true;
    }
    try {
        reader_ = std::thread(&JdwpClient::readerMain, this);
    } catch (...) {
        std::lock_guard<std::mutex> lk(commandMtx_);
        acceptingCommands_ = false;
        workerRunning_ = false;
        err = "could not start the JDWP connection thread";
        return false;
    }

    if (!submitAndWait(command, nullptr, &err)) {
        if (err.empty()) err = "JDWP attach timed out";
        detach();
        return false;
    }
    return true;
}

void JdwpClient::detach() {
    bool hadSession = reader_.joinable();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        hadSession = hadSession || state_ != JdwpState::Detached;
    }

    disconnectRequested_.store(true);
    auto command = std::make_shared<Command>();
    command->kind = Command::Kind::Disconnect;
    command->deadline = Clock::now() + std::chrono::seconds(3);
    std::deque<std::shared_ptr<Command>> cancelled;
    bool queuedDisconnect = false;
    {
        std::lock_guard<std::mutex> lk(commandMtx_);
        acceptingCommands_ = false;
        cancelled.swap(commands_);
        if (workerRunning_) {
            commands_.push_front(command);
            queuedDisconnect = true;
        }
    }
    for (auto& pending : cancelled) {
        pending->cancelled.store(true);
        complete(pending, false, {}, "JDWP session is detaching");
    }
    commandCv_.notify_all();

    if (queuedDisconnect) {
        std::unique_lock<std::mutex> lk(command->doneMtx);
        command->doneCv.wait_until(lk, command->deadline + std::chrono::milliseconds(250),
                                   [&] { return command->done; });
    }
    if (reader_.joinable()) reader_.join();

    {
        std::lock_guard<std::mutex> lk(mtx_);
        state_ = JdwpState::Detached;
        threads_.clear();
        frames_.clear();
        bps_.clear();                       // event requests die with the connection
        replies_.clear();
        methodNameCache_.clear();
        classes_.reset();
        stopThread_ = 0;
        stopLoc_ = JdwpLocation{};
        activeStepReq_ = -1;
        // Preserve an unexpected worker-failure diagnostic across the
        // attach-failure path's automatic detach. A later successful attach
        // replaces it with the normal "attached" event.
        if (hadSession && lastEvent_.rfind("JDWP worker failed", 0) != 0)
            lastEvent_ = "detached";
    }
}

JdwpSnapshot JdwpClient::snapshot() {
    std::lock_guard<std::mutex> lk(mtx_);
    JdwpSnapshot s;
    s.state       = state_;
    s.host        = host_;
    s.port        = port_;
    s.vmName      = vmName_;
    s.vmVersion   = vmVersion_;
    s.lastEvent   = lastEvent_;
    s.idSizes     = sizes_;
    s.stopThread  = stopThread_;
    s.stopLoc     = stopLoc_;
    s.threads     = threads_;
    s.frames      = frames_;
    s.breakpoints = bps_;
    s.classes     = classes_;
    s.events.assign(events_.begin(), events_.end());
    return s;
}

void JdwpClient::pushEvent(const std::string& line) {
    std::lock_guard<std::mutex> lk(mtx_);
    events_.push_back(line);
    while (events_.size() > 300) events_.pop_front();
    // A caller released by the reader's exception cleanup may publish a
    // secondary "request failed" message. Keep the root worker failure as the
    // public terminal event until detach/re-attach establishes a new session.
    if (state_ != JdwpState::Dead || lastEvent_.rfind("JDWP worker failed", 0) != 0)
        lastEvent_ = line;
}

// ---- RPC plumbing ---------------------------------------------------------------

void JdwpClient::complete(const std::shared_ptr<Command>& command, bool ok,
                          JdwpPacket reply, std::string error) {
    {
        std::lock_guard<std::mutex> lk(command->doneMtx);
        if (command->done) return;
        command->ok = ok;
        command->reply = std::move(reply);
        command->error = std::move(error);
        command->done = true;
    }
    command->doneCv.notify_all();
}

void JdwpClient::failCommandNoThrow(const std::shared_ptr<Command>& command,
                                    const char* reason) noexcept {
    if (!command) return;
    command->cancelled.store(true);
    try {
        complete(command, false, {}, reason);
        return;
    } catch (...) {
        // If even copying the diagnostic fails, still release the bounded
        // waiter. The snapshot retains the root worker failure separately.
    }
    try {
        std::lock_guard<std::mutex> lk(command->doneMtx);
        if (!command->done) {
            command->ok = false;
            command->error.clear();
            command->done = true;
        }
    } catch (...) {}
    command->doneCv.notify_all();
}

bool JdwpClient::enqueue(const std::shared_ptr<Command>& command, bool front) {
    {
        std::lock_guard<std::mutex> lk(commandMtx_);
        if (!workerRunning_ ||
            (!acceptingCommands_ && command->kind != Command::Kind::Disconnect) ||
            commands_.size() >= 128)
            return false;
        if (front) commands_.push_front(command);
        else commands_.push_back(command);
    }
    commandCv_.notify_one();
    return true;
}

bool JdwpClient::submitAndWait(const std::shared_ptr<Command>& command,
                               JdwpPacket* reply, std::string* error) {
    if (!enqueue(command)) {
        if (error) *error = "JDWP connection is not accepting requests";
        return false;
    }
    std::unique_lock<std::mutex> lk(command->doneMtx);
    if (!command->doneCv.wait_until(lk, command->deadline + std::chrono::milliseconds(250),
                                    [&] { return command->done; })) {
        command->cancelled.store(true);
        commandCv_.notify_all();
        if (error) *error = "JDWP request timed out";
        return false;
    }
    if (reply) *reply = std::move(command->reply);
    if (error) *error = command->error;
    return command->ok;
}

void JdwpClient::failQueuedCommands(const char* reason) noexcept {
    std::deque<std::shared_ptr<Command>> pending;
    try {
        std::lock_guard<std::mutex> lk(commandMtx_);
        pending.swap(commands_);
    } catch (...) { return; }
    for (auto& command : pending) failCommandNoThrow(command, reason);
}

bool JdwpClient::request(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                         JdwpPacket& reply, int timeoutMs) {
    auto command = std::make_shared<Command>();
    command->kind = Command::Kind::Request;
    command->set = set;
    command->cmd = cmd;
    command->payload = payload;
    command->deadline = Clock::now() + std::chrono::milliseconds(std::max(timeoutMs, 1));
    return submitAndWait(command, &reply);
}

bool JdwpClient::readerRequest(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                               JdwpPacket& reply, int timeoutMs,
                               const std::atomic<bool>* cancelled) {
    return readerRequestUntil(set, cmd, payload, reply,
                              Clock::now() + std::chrono::milliseconds(std::max(timeoutMs, 1)),
                              cancelled);
}

bool JdwpClient::readerRequestUntil(uint8_t set, uint8_t cmd,
                                    const std::vector<uint8_t>& payload,
                                    JdwpPacket& reply, Deadline deadline,
                                    const std::atomic<bool>* cancelled) {
    if (disconnectRequested_.load() || (cancelled && cancelled->load()) ||
        Clock::now() >= deadline)
        return false;
    const uint32_t id = sendCommandOwned(set, cmd, payload, deadline, cancelled);
    if (!id) return false;
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = replies_.find(id);
            if (it != replies_.end()) {
                reply = std::move(it->second);
                replies_.erase(it);
                return true;
            }
        }
        if (disconnectRequested_.load() ||
            (cancelled && cancelled->load()) || Clock::now() >= deadline)
            return false;
        ++pumpDepth_;
        const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        const bool ok = pumpSocket((int)std::max<int64_t>(1, std::min<int64_t>(50, remain)));
        --pumpDepth_;
        if (!ok) return false;
    }
}

bool JdwpClient::sendAllOwned(const uint8_t* data, size_t size, Deadline deadline,
                              const std::atomic<bool>* cancelled) {
    if (sock_ == kInvalidSock) return false;
    const SOCKET s = (SOCKET)sock_;
    while (size) {
        if ((cancelled && cancelled->load()) || Clock::now() >= deadline)
            return false;
        const int chunk = (int)std::min<size_t>(size, INT_MAX);
        const int sent = ::send(s, reinterpret_cast<const char*>(data), chunk, 0);
        if (sent > 0) {
            data += sent;
            size -= (size_t)sent;
            continue;
        }
        const int error = ::WSAGetLastError();
        if (sent == SOCKET_ERROR && (error == WSAEWOULDBLOCK || error == WSAEINTR)) {
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            timeval tv{0, 50 * 1000};
            const int rc = ::select(0, nullptr, &wf, nullptr, &tv);
            if (rc >= 0) continue;
        }
        return false;
    }
    return true;
}

uint32_t JdwpClient::sendCommandOwned(uint8_t set, uint8_t cmd,
                                      const std::vector<uint8_t>& payload,
                                      Deadline deadline,
                                      const std::atomic<bool>* cancelled) {
    if (sock_ == kInvalidSock) return 0;
    const uint32_t id = nextId_.fetch_add(1);
    const auto bytes = JdwpEncodeCommand(id, set, cmd, payload);
    return sendAllOwned(bytes.data(), bytes.size(), deadline, cancelled) ? id : 0;
}

bool JdwpClient::connectOwned(const std::string& host, uint16_t port, Deadline deadline,
                              const std::atomic<bool>* cancelled, std::string& err) {
    ensureWinsock();
    if ((cancelled && cancelled->load()) || disconnectRequested_.load()) {
        err = "attach cancelled";
        return false;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char portStr[16];
    std::snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), portStr, &hints, &res) != 0 || !res) {
        err = "cannot resolve host '" + host + "'";
        return false;
    }

    bool connected = false;
    const Deadline connectDeadline = std::min(deadline, Clock::now() + std::chrono::seconds(3));
    for (addrinfo* ai = res; ai && !connected; ai = ai->ai_next) {
        if ((cancelled && cancelled->load()) || disconnectRequested_.load() ||
            Clock::now() >= connectDeadline)
            break;
        const SOCKET s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        sock_ = (uintptr_t)s;
        u_long nonBlocking = 1;
        if (::ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
            closeSocketOwned();
            continue;
        }
        const int rc = ::connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc == 0) {
            connected = true;
            break;
        }
        const int connectError = ::WSAGetLastError();
        if (connectError != WSAEWOULDBLOCK && connectError != WSAEINPROGRESS) {
            closeSocketOwned();
            continue;
        }
        while (!(cancelled && cancelled->load()) && !disconnectRequested_.load() &&
               Clock::now() < connectDeadline) {
            fd_set wf, ef;
            FD_ZERO(&wf); FD_SET(s, &wf);
            FD_ZERO(&ef); FD_SET(s, &ef);
            timeval tv{0, 50 * 1000};
            const int selected = ::select(0, nullptr, &wf, &ef, &tv);
            if (selected < 0) break;
            if (selected == 0) continue;
            int soError = 0;
            int soErrorSize = sizeof(soError);
            if (::getsockopt(s, SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&soError), &soErrorSize) == 0 && soError == 0)
                connected = true;
            break;
        }
        if (!connected) closeSocketOwned();
    }
    ::freeaddrinfo(res);

    if (!connected) {
        if ((cancelled && cancelled->load()) || disconnectRequested_.load())
            err = "attach cancelled";
        else if (Clock::now() >= connectDeadline)
            err = "connection timed out (is the JVM listening for JDWP on port " +
                  std::string(portStr) + "?)";
        else
            err = "connection refused";
        return false;
    }

    BOOL noDelay = TRUE;
    ::setsockopt((SOCKET)sock_, IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));

    const Deadline handshakeDeadline = std::min(deadline, Clock::now() + std::chrono::seconds(3));
    if (!sendAllOwned(reinterpret_cast<const uint8_t*>(JdwpHandshake()),
                      kJdwpHandshakeLen, handshakeDeadline, cancelled)) {
        err = "handshake send failed";
        closeSocketOwned();
        return false;
    }
    char got[kJdwpHandshakeLen]{};
    size_t have = 0;
    while (have < kJdwpHandshakeLen && Clock::now() < handshakeDeadline &&
           !(cancelled && cancelled->load()) && !disconnectRequested_.load()) {
        const SOCKET s = (SOCKET)sock_;
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(s, &rf);
        timeval tv{0, 50 * 1000};
        const int selected = ::select(0, &rf, nullptr, nullptr, &tv);
        if (selected < 0) break;
        if (selected == 0) continue;
        const int received = ::recv(s, got + have, (int)(kJdwpHandshakeLen - have), 0);
        if (received > 0) have += (size_t)received;
        else if (received == 0 || ::WSAGetLastError() != WSAEWOULDBLOCK) break;
    }
    if (have != kJdwpHandshakeLen ||
        std::memcmp(got, JdwpHandshake(), kJdwpHandshakeLen) != 0) {
        err = "JDWP handshake failed (not a JDWP endpoint?)";
        closeSocketOwned();
        return false;
    }
    return true;
}

bool JdwpClient::bootstrapOwned(const std::string& host, uint16_t port, Deadline deadline,
                                const std::atomic<bool>* cancelled, std::string& err) {
    if (!connectOwned(host, port, deadline, cancelled, err)) return false;
    rxBuf_.clear();
    pendingEvents_.clear();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        replies_.clear();
    }

    JdwpPacket rep;
    JdwpIdSizes negotiated;
    const Deadline idsDeadline = std::min(deadline, Clock::now() + std::chrono::seconds(3));
    if (!readerRequestUntil(JDWP_SET_VirtualMachine, JDWP_VM_IDSizes, {}, rep,
                            idsDeadline, cancelled) || rep.errorCode != 0 ||
        !JdwpParseIdSizes(rep.payload, negotiated)) {
        err = "IDSizes exchange failed";
        closeSocketOwned();
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        sizes_ = negotiated;
        state_ = JdwpState::Running;
        host_ = host;
        port_ = port;
        vmName_.clear();
        vmVersion_.clear();
    }

    const Deadline versionDeadline = std::min(deadline, Clock::now() + std::chrono::milliseconds(1500));
    if (readerRequestUntil(JDWP_SET_VirtualMachine, JDWP_VM_Version, {}, rep,
                           versionDeadline, cancelled) && rep.errorCode == 0) {
        JdwpVersionInfo version;
        if (JdwpParseVersion(rep.payload, version)) {
            std::lock_guard<std::mutex> lk(mtx_);
            vmName_ = std::move(version.vmName);
            vmVersion_ = std::move(version.vmVersion);
        }
    }

    auto remainingMs = [&]() -> int {
        return (int)std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now()).count());
    };
    if (remainingMs() > 0)
        refreshClassesViaReader(std::min(5000, remainingMs()), cancelled);
    if (remainingMs() > 0)
        refreshThreadsViaReader(std::min(2500, remainingMs()), cancelled);

    if ((cancelled && cancelled->load()) || disconnectRequested_.load()) {
        err = "attach cancelled";
        closeSocketOwned();
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == JdwpState::Dead) {
            err = "connection lost during JDWP initialization";
            closeSocketOwned();
            return false;
        }
    }

    std::string name, version;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        name = vmName_;
        version = vmVersion_;
    }
    char portStr[16];
    std::snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);
    pushEvent("attached: " + (name.empty() ? host + ":" + portStr : name) +
              (version.empty() ? "" : " (Java " + version + ")"));
    return true;
}

bool JdwpClient::pumpSocket(int timeoutMs) {
#if defined(DS_JDWP_TEST_HOOKS)
    if (injectReaderFailure_.exchange(false))
        throw std::runtime_error("injected reader failure");
#endif
    char buf[65536];
    int got = 0;
    bool dead = false;
    const SOCKET s = (SOCKET)sock_;
    if (s == INVALID_SOCKET || sock_ == kInvalidSock) return false;

    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(s, &rf);
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    const int rc = ::select(0, &rf, nullptr, nullptr, &tv);
    if (rc == 0) return true;           // idle tick, connection still fine
    dead = rc < 0;
    if (!dead) {
        got = ::recv(s, buf, sizeof(buf), 0);
        if (got == SOCKET_ERROR && ::WSAGetLastError() == WSAEWOULDBLOCK) return true;
        if (got <= 0) dead = true;
    }
    if (got > 0) rxBuf_.insert(rxBuf_.end(), buf, buf + got);

    size_t off = 0;
    while (!dead) {
        JdwpPacket p;
        size_t used = 0;
        if (!JdwpDecodePacket(rxBuf_.data() + off, rxBuf_.size() - off, p, used)) {
            if (used == SIZE_MAX) dead = true;   // hostile length: drop the connection
            break;
        }
        off += used;
        if (p.isReply()) {
            std::lock_guard<std::mutex> lk(mtx_);
            replies_[p.id] = std::move(p);
            if (replies_.size() > 256) replies_.erase(replies_.begin());   // abandoned-waiter backstop
        } else if (p.cmdSet == JDWP_SET_Event && p.cmd == JDWP_E_Composite) {
            JdwpEventSet es;
            if (JdwpParseEventComposite(p.payload, sizes_, es))
                pendingEvents_.push_back(std::move(es));
        }
        // Other VM->debugger commands (none in our subset) are ignored.
    }
    if (off) rxBuf_.erase(rxBuf_.begin(), rxBuf_.begin() + off);

    if (dead) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (state_ != JdwpState::Detached) {
                state_ = JdwpState::Dead;
                lastEvent_ = "connection lost";
            }
        }
        return false;
    }
    return true;
}

void JdwpClient::closeSocketOwned() {
    if (sock_ == kInvalidSock) return;
    const SOCKET s = (SOCKET)sock_;
    ::shutdown(s, SD_BOTH);
    ::closesocket(s);
    sock_ = kInvalidSock;
}

void JdwpClient::readerLoop(std::shared_ptr<Command>& activeCommand) {
    bool stop = false;
    while (!stop) {
        {
            std::unique_lock<std::mutex> lk(commandMtx_);
            if (commands_.empty() && sock_ == kInvalidSock)
                commandCv_.wait(lk, [&] { return !commands_.empty(); });
            if (!commands_.empty()) {
                activeCommand = std::move(commands_.front());
                commands_.pop_front();
            }
        }

        if (activeCommand) {
            if (activeCommand->kind == Command::Kind::Disconnect) {
                if (sock_ != kInvalidSock) {
                    const Deadline disposeDeadline = Clock::now() + std::chrono::milliseconds(200);
                    (void)sendCommandOwned(JDWP_SET_VirtualMachine, JDWP_VM_Dispose, {},
                                           disposeDeadline, nullptr);
                }
                closeSocketOwned();
                complete(activeCommand, true);
                activeCommand.reset();
                stop = true;
                continue;
            }
            if (activeCommand->cancelled.load() || Clock::now() >= activeCommand->deadline) {
                complete(activeCommand, false, {}, "JDWP request timed out");
                activeCommand.reset();
                continue;
            }
            if (activeCommand->kind == Command::Kind::Connect) {
                std::string error;
                const bool ok = bootstrapOwned(activeCommand->host, activeCommand->port,
                                               activeCommand->deadline,
                                               &activeCommand->cancelled, error);
                complete(activeCommand, ok, {}, std::move(error));
            } else {
                JdwpPacket reply;
                const bool ok = readerRequestUntil(activeCommand->set, activeCommand->cmd,
                                                   activeCommand->payload, reply,
                                                   activeCommand->deadline,
                                                   &activeCommand->cancelled);
                complete(activeCommand, ok, std::move(reply),
                         ok ? std::string() : "no reply from the VM");
            }
            activeCommand.reset();
        } else if (sock_ != kInvalidSock && !pumpSocket(50)) {
            stop = true;
        }

        while (!pendingEvents_.empty() && !disconnectRequested_.load() && !stop) {
            JdwpEventSet es = std::move(pendingEvents_.front());
            pendingEvents_.pop_front();
            handleEvent(es);
        }
    }
}

void JdwpClient::finishReader(const std::shared_ptr<Command>& activeCommand,
                              const char* reason, bool failed) noexcept {
    // Every reader exit, normal or exceptional, converges here. Keep each
    // cleanup step independently guarded: cleanup itself must never escape the
    // std::thread entry point and call std::terminate.
    if (failed) {
        try {
            std::lock_guard<std::mutex> lk(mtx_);
            state_ = JdwpState::Dead;
            stopThread_ = 0;
            stopLoc_ = JdwpLocation{};
            frames_.clear();
            lastEvent_ = reason;
            events_.push_back(reason);
            while (events_.size() > 300) events_.pop_front();
        } catch (...) {
            // State is assigned before diagnostic storage above, so even an
            // allocation failure leaves the session non-authoritative.
        }
        // Publish the terminal state before releasing any caller. That caller
        // can immediately snapshot or emit a secondary request-failure event.
        failCommandNoThrow(activeCommand, reason);
    }

    try { closeSocketOwned(); } catch (...) {}
    try { rxBuf_.clear(); } catch (...) {}
    try { pendingEvents_.clear(); } catch (...) {}
    pumpDepth_ = 0;
    try {
        std::lock_guard<std::mutex> lk(mtx_);
        replies_.clear();
    } catch (...) {}
    try {
        std::lock_guard<std::mutex> lk(commandMtx_);
        acceptingCommands_ = false;
        workerRunning_ = false;
    } catch (...) {}
    failQueuedCommands(reason);
    commandCv_.notify_all();
}

void JdwpClient::readerMain() noexcept {
    std::shared_ptr<Command> activeCommand;
    std::string failureReason;
    bool failed = false;
    try {
        readerLoop(activeCommand);
    } catch (const std::exception& e) {
        failed = true;
        try {
            failureReason = "JDWP worker failed: ";
            failureReason += e.what();
        } catch (...) {}
    } catch (...) {
        failed = true;
        try { failureReason = "JDWP worker failed: unknown exception"; }
        catch (...) {}
    }

    const char* reason = failed
        ? (failureReason.empty() ? "JDWP worker failed" : failureReason.c_str())
        : "JDWP connection closed";
    finishReader(activeCommand, reason, failed);
}

#if defined(DS_JDWP_TEST_HOOKS)
void JdwpClient::injectReaderFailureForTest() {
    injectReaderFailure_.store(true);
    commandCv_.notify_all();
}
#endif

// ---- events -----------------------------------------------------------------------

void JdwpClient::handleEvent(const JdwpEventSet& es) {
    for (const auto& e : es.events) {
        switch (e.eventKind) {
            case JDWP_EK_BREAKPOINT: {
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    for (auto& b : bps_)
                        if (b.requestID == e.requestID) { ++b.hits; break; }
                }
                onStopped(e, "Breakpoint hit");
                break;
            }
            case JDWP_EK_SINGLE_STEP: {
                int32_t sr = -1;
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    sr = activeStepReq_;
                    activeStepReq_ = -1;
                }
                if (sr >= 0) {
                    // The count-1 modifier already exhausted the request; Clear
                    // just frees the VM-side slot. Best-effort.
                    JdwpPacket rep;
                    readerRequest(JDWP_SET_EventRequest, JDWP_ER_Clear,
                                  JdwpBuildClearRequest(JDWP_EK_SINGLE_STEP, sr), rep, 500);
                }
                onStopped(e, "Stepped");
                break;
            }
            case JDWP_EK_VM_START:
                if (es.suspendPolicy == JDWP_SP_ALL) {
                    std::lock_guard<std::mutex> lk(mtx_);
                    state_ = JdwpState::Suspended;
                }
                pushEvent("VM started");
                break;
            case JDWP_EK_VM_DEATH: {
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    state_ = JdwpState::Dead;
                    stopThread_ = 0;
                    frames_.clear();
                }
                pushEvent("VM exited");
                break;
            }
            case JDWP_EK_THREAD_START: pushEvent("thread started"); break;
            case JDWP_EK_THREAD_DEATH: pushEvent("thread exited");  break;
            case JDWP_EK_CLASS_PREPARE:
                pushEvent("class prepared: " + JdwpSignatureToClassName(e.signature));
                break;
            default: break;                 // unknown kinds: already logged shape-blind
        }
    }
}

void JdwpClient::onStopped(const JdwpEvent& e, const char* kind) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        state_      = JdwpState::Suspended;
        stopThread_ = e.threadID;
        stopLoc_    = e.loc;
    }
    const std::string where = locationLabel(e.loc);

    // Call stack of the stopped thread (top 20 frames).
    std::vector<JdwpFrameRow> rows;
    {
        JdwpWriter w;
        w.id(e.threadID, sizes_.objectID);
        w.u4(0);
        w.u4(20);
        JdwpPacket rep;
        if (readerRequest(JDWP_SET_ThreadReference, JDWP_TR_Frames, w.bytes(), rep) &&
            rep.errorCode == 0) {
            std::vector<JdwpFrameInfo> fs;
            if (JdwpParseFrames(rep.payload, sizes_, fs))
                for (const auto& f : fs)
                    rows.push_back({f.frameID, f.loc, locationLabel(f.loc)});
        }
    }
    refreshThreadsViaReader();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        frames_ = std::move(rows);
    }
    pushEvent(std::string(kind) + " at " + where);
}

std::string JdwpClient::locationLabel(const JdwpLocation& loc) {
    if (!loc.classID) return "(no location)";

    std::shared_ptr<const std::vector<JdwpClassRow>> cls;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        cls = classes_;
    }
    std::string cn;
    if (cls)
        for (const auto& c : *cls)
            if (c.typeID == loc.classID) { cn = shortClass(c.name); break; }
    if (cn.empty()) {
        char b[32];
        std::snprintf(b, sizeof(b), "class_%llX", (unsigned long long)loc.classID);
        cn = b;
    }

    std::string mn;
    bool haveCache = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto ci = methodNameCache_.find(loc.classID);
        if (ci != methodNameCache_.end()) {
            haveCache = true;
            auto mi = ci->second.find(loc.methodID);
            if (mi != ci->second.end()) mn = mi->second;
        }
    }
    if (mn.empty() && !haveCache) {
        JdwpWriter w;
        w.id(loc.classID, sizes_.referenceTypeID);
        JdwpPacket rep;
        if (readerRequest(JDWP_SET_ReferenceType, JDWP_RT_Methods, w.bytes(), rep) &&
            rep.errorCode == 0) {
            std::vector<JdwpMethodInfo> ms;
            if (JdwpParseMethods(rep.payload, sizes_, ms)) {
                std::lock_guard<std::mutex> lk(mtx_);
                auto& mc = methodNameCache_[loc.classID];
                for (const auto& m : ms) {
                    mc[m.methodID] = m.name;
                    if (m.methodID == loc.methodID) mn = m.name;
                }
            }
        }
    }
    if (mn.empty()) {
        char b[32];
        std::snprintf(b, sizeof(b), "method_%llX", (unsigned long long)loc.methodID);
        mn = b;
    }
    return cn + "." + mn + " bci=" + std::to_string((long long)loc.index);
}

void JdwpClient::refreshClassesViaReader(int timeoutMs,
                                         const std::atomic<bool>* cancelled) {
    JdwpPacket rep;
    if (!readerRequest(JDWP_SET_VirtualMachine, JDWP_VM_AllClasses, {}, rep,
                       timeoutMs, cancelled) ||
        rep.errorCode != 0)
        return;
    std::vector<JdwpClassInfo> cs;
    if (!JdwpParseAllClasses(rep.payload, sizes_, cs)) return;
    auto rows = std::make_shared<std::vector<JdwpClassRow>>();
    rows->reserve(cs.size());
    for (auto& c : cs) {
        if (c.refTypeTag == 3) continue;    // arrays have no bytecode to browse
        JdwpClassRow r;
        r.typeID    = c.typeID;
        r.name      = JdwpSignatureToClassName(c.signature);
        r.signature = std::move(c.signature);
        rows->push_back(std::move(r));
    }
    std::sort(rows->begin(), rows->end(),
              [](const JdwpClassRow& a, const JdwpClassRow& b) { return a.name < b.name; });
    std::lock_guard<std::mutex> lk(mtx_);
    classes_ = std::move(rows);
}

void JdwpClient::refreshThreadsViaReader(int timeoutMs,
                                         const std::atomic<bool>* cancelled) {
    const Deadline deadline = Clock::now() + std::chrono::milliseconds(std::max(timeoutMs, 1));
    auto remainingMs = [&]() -> int {
        return (int)std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now()).count());
    };
    JdwpPacket rep;
    if (!readerRequestUntil(JDWP_SET_VirtualMachine, JDWP_VM_AllThreads, {}, rep,
                            deadline, cancelled) ||
        rep.errorCode != 0)
        return;
    std::vector<uint64_t> ids;
    if (!JdwpParseAllThreads(rep.payload, sizes_, ids)) return;
    std::vector<JdwpThreadRow> rows;
    rows.reserve(ids.size());
    for (size_t i = 0; i < ids.size() && i < 64; ++i) {   // name/status RPCs: cap the fan-out
        if (remainingMs() <= 0 || (cancelled && cancelled->load()) ||
            disconnectRequested_.load())
            break;
        JdwpThreadRow t;
        t.id = ids[i];
        JdwpWriter w;
        w.id(t.id, sizes_.objectID);
        Deadline oneDeadline = std::min(deadline, Clock::now() + std::chrono::milliseconds(500));
        if (readerRequestUntil(JDWP_SET_ThreadReference, JDWP_TR_Name, w.bytes(), rep,
                               oneDeadline, cancelled) &&
            rep.errorCode == 0) {
            JdwpReader r(rep.payload.data(), rep.payload.size());
            t.name = r.str();
        }
        oneDeadline = std::min(deadline, Clock::now() + std::chrono::milliseconds(500));
        if (Clock::now() < oneDeadline &&
            readerRequestUntil(JDWP_SET_ThreadReference, JDWP_TR_Status, w.bytes(), rep,
                               oneDeadline, cancelled) &&
            rep.errorCode == 0) {
            int32_t st = 0, su = 0;
            if (JdwpParseThreadStatus(rep.payload, st, su)) t.status = st;
        }
        rows.push_back(std::move(t));
    }
    std::lock_guard<std::mutex> lk(mtx_);
    threads_ = std::move(rows);
}

// ---- execution control (UI thread) ---------------------------------------------------

void JdwpClient::suspendAll() {
    JdwpPacket rep;
    if (!request(JDWP_SET_VirtualMachine, JDWP_VM_Suspend, {}, rep) || rep.errorCode) {
        pushEvent("suspend failed");
        return;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        state_ = JdwpState::Suspended;
        stopThread_ = threads_.empty() ? 0 : threads_.front().id;
        stopLoc_ = JdwpLocation{};          // VM-wide suspend: no single location
        frames_.clear();
    }
    pushEvent("suspended (all threads)");
}

void JdwpClient::resumeAll() {
    JdwpPacket rep;
    if (!request(JDWP_SET_VirtualMachine, JDWP_VM_Resume, {}, rep) || rep.errorCode) {
        pushEvent("resume failed");
        return;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        state_ = JdwpState::Running;
        stopThread_ = 0;
        stopLoc_ = JdwpLocation{};
        frames_.clear();
    }
    pushEvent("resumed");
}

void JdwpClient::stepInto() { stepCommon(JDWP_STEP_INTO, "step into"); }
void JdwpClient::stepOver() { stepCommon(JDWP_STEP_OVER, "step over"); }
void JdwpClient::stepOut()  { stepCommon(JDWP_STEP_OUT,  "step out"); }

void JdwpClient::stepCommon(uint32_t depth, const char* what) {
    uint64_t th = 0;
    JdwpIdSizes sz;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ != JdwpState::Suspended || !stopThread_) return;
        th = stopThread_;
        sz = sizes_;
    }
    JdwpPacket rep;
    if (!request(JDWP_SET_EventRequest, JDWP_ER_Set,
                 JdwpBuildStepRequest(th, depth, sz), rep) || rep.errorCode) {
        pushEvent(std::string(what) + " failed");
        return;
    }
    {
        JdwpReader r(rep.payload.data(), rep.payload.size());
        const int32_t rid = (int32_t)r.u4();
        std::lock_guard<std::mutex> lk(mtx_);
        activeStepReq_ = rid;
    }
    if (request(JDWP_SET_VirtualMachine, JDWP_VM_Resume, {}, rep) && !rep.errorCode) {
        std::lock_guard<std::mutex> lk(mtx_);
        state_ = JdwpState::Running;
        frames_.clear();
    }
    pushEvent(what);
}

// ---- breakpoints (UI thread) ----------------------------------------------------------

bool JdwpClient::setBreakpoint(const JdwpLocation& loc, const std::string& label,
                               std::string& err) {
    JdwpIdSizes sz;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == JdwpState::Detached || state_ == JdwpState::Dead) {
            err = "not attached";
            return false;
        }
        sz = sizes_;
    }
    JdwpPacket rep;
    if (!request(JDWP_SET_EventRequest, JDWP_ER_Set,
                 JdwpBuildBreakpointRequest(loc, sz), rep)) {
        err = "no reply from the VM";
        return false;
    }
    if (rep.errorCode != 0) {
        err = "JDWP error " + std::to_string(rep.errorCode) +
              " (is the bci on an instruction boundary?)";
        return false;
    }
    JdwpReader r(rep.payload.data(), rep.payload.size());
    const int32_t rid = (int32_t)r.u4();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        bps_.push_back({rid, loc, label, 0});
    }
    pushEvent("breakpoint set: " + label);
    return true;
}

void JdwpClient::clearBreakpoint(int32_t requestID) {
    JdwpPacket rep;
    request(JDWP_SET_EventRequest, JDWP_ER_Clear,
            JdwpBuildClearRequest(JDWP_EK_BREAKPOINT, requestID), rep, 800);
    std::lock_guard<std::mutex> lk(mtx_);
    for (size_t i = 0; i < bps_.size(); ++i)
        if (bps_[i].requestID == requestID) { bps_.erase(bps_.begin() + i); break; }
}

// ---- browsing (UI thread) ---------------------------------------------------------------

void JdwpClient::refreshClasses() {
    JdwpPacket rep;
    if (!request(JDWP_SET_VirtualMachine, JDWP_VM_AllClasses, {}, rep, 5000) ||
        rep.errorCode != 0)
        return;
    std::vector<JdwpClassInfo> cs;
    if (!JdwpParseAllClasses(rep.payload, sizes_, cs)) return;
    auto rows = std::make_shared<std::vector<JdwpClassRow>>();
    rows->reserve(cs.size());
    for (auto& c : cs) {
        if (c.refTypeTag == 3) continue;
        JdwpClassRow r;
        r.typeID    = c.typeID;
        r.name      = JdwpSignatureToClassName(c.signature);
        r.signature = std::move(c.signature);
        rows->push_back(std::move(r));
    }
    std::sort(rows->begin(), rows->end(),
              [](const JdwpClassRow& a, const JdwpClassRow& b) { return a.name < b.name; });
    std::lock_guard<std::mutex> lk(mtx_);
    classes_ = std::move(rows);
}

bool JdwpClient::methodsOf(uint64_t typeID, std::vector<JdwpMethodRow>& out) {
    out.clear();
    JdwpWriter w;
    w.id(typeID, sizes_.referenceTypeID);
    JdwpPacket rep;
    if (!request(JDWP_SET_ReferenceType, JDWP_RT_Methods, w.bytes(), rep) || rep.errorCode)
        return false;
    std::vector<JdwpMethodInfo> ms;
    if (!JdwpParseMethods(rep.payload, sizes_, ms)) return false;
    out.reserve(ms.size());
    std::lock_guard<std::mutex> lk(mtx_);
    auto& mc = methodNameCache_[typeID];
    for (auto& m : ms) {
        mc[m.methodID] = m.name;
        out.push_back({m.methodID, std::move(m.name), std::move(m.signature), m.modBits});
    }
    return true;
}

bool JdwpClient::bytecodesOf(uint64_t typeID, uint64_t methodID, std::vector<uint8_t>& out) {
    out.clear();
    JdwpWriter w;
    w.id(typeID, sizes_.referenceTypeID);
    w.id(methodID, sizes_.methodID);
    JdwpPacket rep;
    if (!request(JDWP_SET_Method, JDWP_M_Bytecodes, w.bytes(), rep) || rep.errorCode)
        return false;
    return JdwpParseBytecodes(rep.payload, out);
}

bool JdwpClient::constantPoolOf(uint64_t typeID, uint32_t& cpCount,
                                std::vector<uint8_t>& cpBytes) {
    JdwpWriter w;
    w.id(typeID, sizes_.referenceTypeID);
    JdwpPacket rep;
    if (!request(JDWP_SET_ReferenceType, JDWP_RT_ConstantPool, w.bytes(), rep) || rep.errorCode)
        return false;
    return JdwpParseConstantPool(rep.payload, cpCount, cpBytes);
}

bool JdwpClient::lineTableOf(uint64_t typeID, uint64_t methodID,
                             std::vector<std::pair<uint64_t, uint32_t>>& out) {
    out.clear();
    JdwpWriter w;
    w.id(typeID, sizes_.referenceTypeID);
    w.id(methodID, sizes_.methodID);
    JdwpPacket rep;
    if (!request(JDWP_SET_Method, JDWP_M_LineTable, w.bytes(), rep) || rep.errorCode)
        return false;
    return JdwpParseLineTable(rep.payload, out);
}

} // namespace ds
