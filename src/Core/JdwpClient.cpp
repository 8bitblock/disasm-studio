#include "JdwpClient.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

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
    ensureWinsock();

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char portStr[16];
    std::snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), portStr, &hints, &res) != 0 || !res) {
        err = "cannot resolve host '" + host + "'";
        return false;
    }

    SOCKET s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { ::freeaddrinfo(res); err = "socket() failed"; return false; }

    // Non-blocking connect with a 3 s timeout so a wrong port can't hang the UI.
    u_long nb = 1;
    ::ioctlsocket(s, FIONBIO, &nb);
    int rc = ::connect(s, res->ai_addr, (int)res->ai_addrlen);
    ::freeaddrinfo(res);
    if (rc == SOCKET_ERROR && ::WSAGetLastError() != WSAEWOULDBLOCK) {
        ::closesocket(s); err = "connect() failed"; return false;
    }
    {
        fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
        timeval tv{3, 0};
        if (::select(0, nullptr, &wf, nullptr, &tv) != 1) {
            ::closesocket(s);
            err = "connection timed out (is the JVM running with -agentlib:jdwp=transport=dt_socket,server=y,address=*:" + std::string(portStr) + " ?)";
            return false;
        }
        int soerr = 0, len = sizeof(soerr);
        ::getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &len);
        if (soerr != 0) { ::closesocket(s); err = "connection refused"; return false; }
    }
    nb = 0;
    ::ioctlsocket(s, FIONBIO, &nb);
    {
        BOOL nd = TRUE;
        ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
    }

    // Handshake: send the 14 ASCII bytes, expect the same 14 back.
    if (::send(s, JdwpHandshake(), (int)kJdwpHandshakeLen, 0) != (int)kJdwpHandshakeLen) {
        ::closesocket(s); err = "handshake send failed"; return false;
    }
    {
        char got[kJdwpHandshakeLen];
        size_t have = 0;
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        while (have < kJdwpHandshakeLen) {
            fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
            timeval tv{0, 200 * 1000};
            if (::select(0, &rf, nullptr, nullptr, &tv) == 1) {
                int n = ::recv(s, got + have, (int)(kJdwpHandshakeLen - have), 0);
                if (n <= 0) break;
                have += (size_t)n;
            }
            if (Clock::now() > deadline) break;
        }
        if (have != kJdwpHandshakeLen ||
            std::memcmp(got, JdwpHandshake(), kJdwpHandshakeLen) != 0) {
            ::closesocket(s);
            err = "JDWP handshake failed (not a JDWP endpoint?)";
            return false;
        }
    }

    // Session up. The attach thread acts as the reader until the thread starts
    // (rxBuf_/pendingEvents_ are reader-only; nothing else touches them yet).
    quit_.store(false);
    sock_ = (uintptr_t)s;

    JdwpPacket rep;
    if (!readerRequest(JDWP_SET_VirtualMachine, JDWP_VM_IDSizes, {}, rep, 3000) ||
        rep.errorCode != 0 || !JdwpParseIdSizes(rep.payload, sizes_)) {
        closeSocket();
        err = "IDSizes exchange failed";
        return false;
    }
    if (readerRequest(JDWP_SET_VirtualMachine, JDWP_VM_Version, {}, rep, 3000) &&
        rep.errorCode == 0) {
        JdwpVersionInfo v;
        if (JdwpParseVersion(rep.payload, v)) { vmName_ = v.vmName; vmVersion_ = v.vmVersion; }
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        state_ = JdwpState::Running;
        host_  = host;
        port_  = port;
    }
    refreshClassesViaReader();
    refreshThreadsViaReader();
    reader_ = std::thread(&JdwpClient::readerMain, this);
    pushEvent("attached: " + (vmName_.empty() ? host + ":" + portStr : vmName_) +
              (vmVersion_.empty() ? "" : " (Java " + vmVersion_ + ")"));
    return true;
}

void JdwpClient::detach() {
    const bool hadSession = sock_ != kInvalidSock || reader_.joinable();
    quit_.store(true);
    if (sock_ != kInvalidSock)
        sendCommand(JDWP_SET_VirtualMachine, JDWP_VM_Dispose, {});   // best effort, no wait
    closeSocket();                          // unblocks the reader's select
    if (reader_.joinable()) reader_.join();
    rxBuf_.clear();
    pendingEvents_.clear();
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
        if (hadSession) lastEvent_ = "detached";
    }
    replyCv_.notify_all();
}

void JdwpClient::closeSocket() {
    std::lock_guard<std::mutex> lk(sendMtx_);
    if (sock_ != kInvalidSock) {
        ::closesocket((SOCKET)sock_);
        sock_ = kInvalidSock;
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
    lastEvent_ = line;
}

// ---- RPC plumbing ---------------------------------------------------------------

uint32_t JdwpClient::sendCommand(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lk(sendMtx_);
    if (sock_ == kInvalidSock) return 0;
    const uint32_t id = nextId_.fetch_add(1);
    auto bytes = JdwpEncodeCommand(id, set, cmd, payload);
    const char* p = (const char*)bytes.data();
    size_t left = bytes.size();
    while (left) {
        int w = ::send((SOCKET)sock_, p, (int)left, 0);
        if (w <= 0) return 0;
        p += w;
        left -= (size_t)w;
    }
    return id;
}

bool JdwpClient::request(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                         JdwpPacket& reply, int timeoutMs) {
    const uint32_t id = sendCommand(set, cmd, payload);
    if (!id) return false;
    std::unique_lock<std::mutex> lk(mtx_);
    const bool got = replyCv_.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&] {
        return replies_.count(id) != 0 ||
               state_ == JdwpState::Dead || state_ == JdwpState::Detached;
    });
    auto it = replies_.find(id);
    if (!got || it == replies_.end()) return false;
    reply = std::move(it->second);
    replies_.erase(it);
    return true;
}

bool JdwpClient::readerRequest(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload,
                               JdwpPacket& reply, int timeoutMs) {
    const uint32_t id = sendCommand(set, cmd, payload);
    if (!id) return false;
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
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
        if (Clock::now() > deadline) return false;
        ++pumpDepth_;
        const bool ok = pumpSocket(50);
        --pumpDepth_;
        if (!ok) return false;
    }
}

bool JdwpClient::pumpSocket(int timeoutMs) {
    const SOCKET s = (SOCKET)sock_;
    if (s == INVALID_SOCKET || sock_ == kInvalidSock) return false;

    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(s, &rf);
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    const int rc = ::select(0, &rf, nullptr, nullptr, &tv);
    if (rc == 0) return true;              // idle tick, connection still fine
    bool dead = rc < 0;

    if (!dead) {
        char buf[65536];
        const int got = ::recv(s, buf, sizeof(buf), 0);
        if (got <= 0) dead = true;
        else rxBuf_.insert(rxBuf_.end(), buf, buf + got);
    }

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
            replyCv_.notify_all();
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
        replyCv_.notify_all();
        return false;
    }
    return true;
}

void JdwpClient::readerMain() {
    while (!quit_.load()) {
        if (!pumpSocket(100)) break;
        while (!pendingEvents_.empty() && !quit_.load()) {
            JdwpEventSet es = std::move(pendingEvents_.front());
            pendingEvents_.pop_front();
            handleEvent(es);
        }
    }
    replyCv_.notify_all();
}

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

void JdwpClient::refreshClassesViaReader() {
    JdwpPacket rep;
    if (!readerRequest(JDWP_SET_VirtualMachine, JDWP_VM_AllClasses, {}, rep, 5000) ||
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

void JdwpClient::refreshThreadsViaReader() {
    JdwpPacket rep;
    if (!readerRequest(JDWP_SET_VirtualMachine, JDWP_VM_AllThreads, {}, rep) ||
        rep.errorCode != 0)
        return;
    std::vector<uint64_t> ids;
    if (!JdwpParseAllThreads(rep.payload, sizes_, ids)) return;
    std::vector<JdwpThreadRow> rows;
    rows.reserve(ids.size());
    for (size_t i = 0; i < ids.size() && i < 64; ++i) {   // name/status RPCs: cap the fan-out
        JdwpThreadRow t;
        t.id = ids[i];
        JdwpWriter w;
        w.id(t.id, sizes_.objectID);
        if (readerRequest(JDWP_SET_ThreadReference, JDWP_TR_Name, w.bytes(), rep, 500) &&
            rep.errorCode == 0) {
            JdwpReader r(rep.payload.data(), rep.payload.size());
            t.name = r.str();
        }
        if (readerRequest(JDWP_SET_ThreadReference, JDWP_TR_Status, w.bytes(), rep, 500) &&
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
