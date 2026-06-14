#include "Debugger.h"
#include "Cond.h"
#include "DbgHelpLock.h"      // serialize DbgHelp against the UI thread's SymbolResolver
#include "ExcName.h"          // semantic exception-code names for lastEvent_
#include "JvmAware.h"         // JVM module detection / JNI_CreateJavaVM resolution
#include "StepLogic.h"
#include "../Disasm/IDisassembler.h"
#include "../Disasm/ZydisDisassembler.h"

#include <windows.h>
#include <dbghelp.h>          // StackWalk64 + Sym* callbacks for real call-stack unwinding

#include <algorithm>          // std::sort / std::lower_bound (breakpoint-address cache)
#include <cctype>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "dbghelp.lib")

namespace ds {

static constexpr uint32_t TRAP_FLAG = 0x100;
static constexpr size_t   kStepOutCap = 500000; // safety cap for depth stepping
static constexpr size_t   kMaxDbgModules = 2048;   // live-module list bound
static constexpr size_t   kDbgOutputCap  = 1000;   // OutputDebugString ring bound
static constexpr size_t   kDbgOutputLine = 8192;   // per-message read cap (bytes)

static std::wstring widenUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

static void writePrintablePayload(std::FILE* f, const std::vector<uint8_t>& bytes) {
    for (uint8_t b : bytes) {
        if (b == '\r' || b == '\n' || b == '\t') std::fputc((int)b, f);
        else if (b >= 0x20 && b < 0x7F)          std::fputc((int)b, f);
        else                                     std::fputc('.', f);
    }
    if (bytes.empty() || bytes.back() != '\n') std::fputc('\n', f);
}

static void writeHexPayload(std::FILE* f, const std::vector<uint8_t>& bytes) {
    for (size_t off = 0; off < bytes.size(); off += 16) {
        std::fprintf(f, "%08zX  ", off);
        char ascii[17] = {};
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < bytes.size()) {
                uint8_t b = bytes[off + i];
                std::fprintf(f, "%02X ", b);
                ascii[i] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            } else {
                std::fputs("   ", f);
                ascii[i] = ' ';
            }
            if (i == 7) std::fputc(' ', f);
        }
        ascii[16] = '\0';
        std::fprintf(f, " %s\n", ascii);
    }
}

// In a 32-bit (WOW64) target, int3 / single-step in the 32-bit code are reported as
// these WX86 status codes, not the usual EXCEPTION_BREAKPOINT / EXCEPTION_SINGLE_STEP.
static constexpr uint32_t kStatusWx86Breakpoint = 0x4000001FUL;
static constexpr uint32_t kStatusWx86SingleStep = 0x4000001EUL;

// The debugger handles both native 64-bit and 32-bit (WOW64) targets: it reads the
// x64 CONTEXT or the WOW64_CONTEXT as appropriate (see isWow64_ / the ctx* helpers).
// Two private step decoders measure instruction lengths and spot calls - x64 for
// native targets, x86 for WOW64 - independent of whichever engine the UI is showing.
Debugger::Debugger()
    : ownDis_(std::make_unique<ZydisDisassembler>(Arch::X64)),
      ownDis32_(std::make_unique<ZydisDisassembler>(Arch::X86)) {}
Debugger::~Debugger() { detach(); }

// ---- UI-thread API ----------------------------------------------------------

bool Debugger::attach(uint32_t pid, std::string& err) {
    detach();
    quit_ = false;
    startupOk_ = false;
    startupDone_ = false;
    breakRequested_ = false;   // a Pause that never landed must not leak into the new session
    thread_ = std::thread([this, pid] { threadMain(pid, /*launch=*/false, std::wstring(), /*breakAtEntry=*/false); });

    std::unique_lock<std::mutex> lk(mtx_);
    cmdCv_.wait(lk, [this] { return startupDone_.load(); });
    if (!startupOk_) { err = startupErr_; lk.unlock(); if (thread_.joinable()) thread_.join(); return false; }
    return true;
}

bool Debugger::launchAndAttach(const std::string& exePath, std::string& err, bool breakAtEntry) {
    detach();
    quit_ = false;
    startupOk_ = false;
    startupDone_ = false;
    breakRequested_ = false;
    // UTF-8 path -> UTF-16 for CreateProcessW.
    std::wstring wpath;
    if (!exePath.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, exePath.c_str(), (int)exePath.size(), nullptr, 0);
        wpath.resize(n > 0 ? n : 0);
        if (n > 0) MultiByteToWideChar(CP_UTF8, 0, exePath.c_str(), (int)exePath.size(), wpath.data(), n);
    }
    if (wpath.empty()) { err = "no binary path to launch"; return false; }
    thread_ = std::thread([this, wpath, breakAtEntry] {
        threadMain(0, /*launch=*/true, wpath, breakAtEntry);
    });

    std::unique_lock<std::mutex> lk(mtx_);
    cmdCv_.wait(lk, [this] { return startupDone_.load(); });
    if (!startupOk_) { err = startupErr_; lk.unlock(); if (thread_.joinable()) thread_.join(); return false; }
    return true;
}

void Debugger::detach() {
    if (!thread_.joinable()) { closeNetCaptureLogFile(); return; }
    freeAllRemote();                 // release F2 detour allocations while the handle is valid
    quit_ = true;
    postCommand(Cmd::Detach);
    thread_.join();
    closeNetCaptureLogFile();
    std::lock_guard<std::mutex> lk(mtx_);
    state_ = DbgState::Detached;
    bps_.clear();
    bpAddrs_.clear();
    pendingBpAdds_.clear();
    pendingBpRems_.clear();
    pendingBpConds_.clear();
    threadList_.clear();
    threadHandles_.clear();
    frames_.clear();
    suspended_.clear();
    dbgModules_.clear();
    dbgOutput_.clear();
    jvmLoaded_ = false;
    jvmPath_.clear();
    jvmExceptionsPassed_ = 0;
    activeTid_ = 0;
    hProcessShared_ = nullptr;
    isWow64_.store(false);
}

void Debugger::postCommand(Cmd c) {
    { std::lock_guard<std::mutex> lk(mtx_); pending_ = c; }
    cmdCv_.notify_all();
}

void Debugger::cont()     { postCommand(Cmd::Continue);  }
void Debugger::stepInto() { postCommand(Cmd::StepInto);  }
void Debugger::stepOver() { postCommand(Cmd::StepOver);  }
void Debugger::stepOut()  { postCommand(Cmd::StepOut);   }

void Debugger::runToCursor(uint64_t va) {
    { std::lock_guard<std::mutex> lk(mtx_); cmdArg_ = va; pending_ = Cmd::RunTo; }
    cmdCv_.notify_all();
}

void Debugger::setActiveThread(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (state_ != DbgState::Paused) return;            // thread contexts are only stable at a stop
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    if (!h) return;
    Registers r;
    if (!ctxReadFull(h, r)) return;
    activeTid_ = tid;
    regs_ = r;
    // frames_ was unwound for the thread the debugger stopped on. Switching to a
    // different displayed thread invalidates it; clear it (this is the UI thread, so
    // we can't safely re-run StackWalk64 here, which touches debug-thread-local
    // state) so the call-stack view falls back to the heuristic walk of the new
    // thread's RSP until the next stop re-unwinds.
    if (tid != tid_) frames_.clear();
}

bool Debugger::setRegisters(const Registers& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (state_ != DbgState::Paused) return false;      // contexts are only stable at a stop
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == activeTid_) { h = kv.second; break; }
    if (!h) return false;
    if (!ctxWriteFull(h, r)) return false;             // get-modify-set (preserves seg/FP/debug)
    regs_ = r;                                          // reflect immediately in the next snapshot
    return true;
}

bool Debugger::setRegister(const std::string& name, uint64_t value) {
    Registers r;
    { std::lock_guard<std::mutex> lk(mtx_); r = regs_; }   // start from the current values
    uint64_t Registers::* f = nullptr;
    if      (name == "rip") f = &Registers::rip; else if (name == "rsp") f = &Registers::rsp;
    else if (name == "rbp") f = &Registers::rbp; else if (name == "rflags") f = &Registers::rflags;
    else if (name == "rax") f = &Registers::rax; else if (name == "rbx") f = &Registers::rbx;
    else if (name == "rcx") f = &Registers::rcx; else if (name == "rdx") f = &Registers::rdx;
    else if (name == "rsi") f = &Registers::rsi; else if (name == "rdi") f = &Registers::rdi;
    else if (name == "r8")  f = &Registers::r8;  else if (name == "r9")  f = &Registers::r9;
    else if (name == "r10") f = &Registers::r10; else if (name == "r11") f = &Registers::r11;
    else if (name == "r12") f = &Registers::r12; else if (name == "r13") f = &Registers::r13;
    else if (name == "r14") f = &Registers::r14; else if (name == "r15") f = &Registers::r15;
    if (!f) return false;
    r.*f = value;
    return setRegisters(r);
}

void Debugger::suspendThread(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (suspended_.count(tid)) return;                 // keep our suspend count at exactly +1
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    if (!h) return;
    if (SuspendThread((HANDLE)h) != (DWORD)-1) suspended_.insert(tid);
}

void Debugger::resumeThread(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!suspended_.count(tid)) return;
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    // Only forget the thread once it is actually un-suspended (or its handle is
    // already gone). If ResumeThread fails on a live handle, keep the entry so a
    // retry can still thaw it - symmetric with suspendThread's success check.
    if (!h || ResumeThread((HANDLE)h) != (DWORD)-1) suspended_.erase(tid);
}

bool Debugger::isThreadSuspended(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    return suspended_.count(tid) != 0;
}

void Debugger::pause() {
    std::lock_guard<std::mutex> lk(hProcMtx_);   // serialize with the debug thread closing the handle
    void* h = hProcessShared_.load();
    if (h) {
        breakRequested_ = true;               // tell the loop the next stray int3 is our pause
        DebugBreakProcess((HANDLE)h);          // injects an int3 in a helper thread
    }
}

bool Debugger::addBreakpoint(uint64_t va, const std::string& condition) {
    std::lock_guard<std::mutex> lk(mtx_);
    pendingBpAdds_.push_back({ va, condition });
    return true;
}
bool Debugger::removeBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    pendingBpRems_.push_back(va);
    return true;
}
bool Debugger::hasBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    return bps_.count(va) != 0;
}
void Debugger::setBreakpointCondition(uint64_t va, const std::string& condition) {
    std::lock_guard<std::mutex> lk(mtx_);
    pendingBpConds_.push_back({ va, condition });
}

void Debugger::setBreakpointEveryN(uint64_t va, uint32_t n) {
    std::lock_guard<std::mutex> lk(mtx_);
    pendingBpEveryN_.push_back({ va, n });
}

void Debugger::addFirstChanceCode(uint32_t code) {
    std::lock_guard<std::mutex> lk(mtx_);
    fcWhitelist_.insert(code);
}
void Debugger::removeFirstChanceCode(uint32_t code) {
    std::lock_guard<std::mutex> lk(mtx_);
    fcWhitelist_.erase(code);
}
std::vector<uint32_t> Debugger::firstChanceCodes() {
    std::lock_guard<std::mutex> lk(mtx_);
    return std::vector<uint32_t>(fcWhitelist_.begin(), fcWhitelist_.end());
}

void Debugger::clearDebugOutput() {
    std::lock_guard<std::mutex> lk(mtx_);
    dbgOutput_.clear();
}

// Defined further down (the RPM byte helpers); forward-declared so the net-tap
// methods above their definitions can use them.
static bool readByteRPM(HANDLE h, uint64_t va, uint8_t& b);
static bool writeByteRPM(HANDLE h, uint64_t va, uint8_t b);

// ---- network data tap (public, thread-safe) -----------------------------------
// enableNetTap only sets intent; the debug thread arms/disarms in its loop (it owns
// the breakpoint bytes). This keeps all 0xCC writes on the one thread that services
// debug events, matching the rest of the engine.
void Debugger::enableNetTap(bool on) { netTapWant_.store(on); }

bool Debugger::setNetCaptureLogFile(const std::string& utf8Path, bool append, std::string* err) {
    if (err) err->clear();
    if (utf8Path.empty()) {
        if (err) *err = "empty log path";
        return false;
    }

    std::wstring wpath = widenUtf8(utf8Path);
    if (wpath.empty()) {
        if (err) *err = "could not convert log path";
        return false;
    }

    std::FILE* f = nullptr;
    if (_wfopen_s(&f, wpath.c_str(), append ? L"ab" : L"wb") != 0 || !f) {
        if (err) *err = "could not open log file";
        return false;
    }

    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::fprintf(f,
                 "# DisasmStudio network payload log\n"
                 "# started %04u-%02u-%02u %02u:%02u:%02u.%03u local\n"
                 "# each record: API direction, pid/tid, SOCKET handle, API byte count, captured byte count\n\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::fflush(f);

    std::lock_guard<std::mutex> lk(netLogMtx_);
    if (netLogFile_) std::fclose(netLogFile_);
    netLogFile_ = f;
    netLogPath_ = utf8Path;
    return true;
}

void Debugger::closeNetCaptureLogFile() {
    std::lock_guard<std::mutex> lk(netLogMtx_);
    if (netLogFile_) {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        std::fprintf(netLogFile_, "\n# stopped %04u-%02u-%02u %02u:%02u:%02u.%03u local\n",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        std::fclose(netLogFile_);
        netLogFile_ = nullptr;
    }
    netLogPath_.clear();
}

bool Debugger::netCaptureLogEnabled() {
    std::lock_guard<std::mutex> lk(netLogMtx_);
    return netLogFile_ != nullptr;
}

std::string Debugger::netCaptureLogPath() {
    std::lock_guard<std::mutex> lk(netLogMtx_);
    return netLogPath_;
}

std::vector<NetCapture> Debugger::netCaptures() {
    std::lock_guard<std::mutex> lk(mtx_);
    const size_t n = netCaps_.size(), keep = 300, start = n > keep ? n - keep : 0;
    return std::vector<NetCapture>(netCaps_.begin() + start, netCaps_.end());
}
size_t Debugger::netCaptureCount() {
    std::lock_guard<std::mutex> lk(mtx_);
    return netCapSeq_;
}
void Debugger::clearNetCaptures() {
    std::lock_guard<std::mutex> lk(mtx_);
    netCaps_.clear();
    netCapSeq_ = 0;
}
void Debugger::pushNetCapture(NetCapture&& c) {
    if (!c.pid) c.pid = pid_;
    writeNetCaptureLog(c);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        netCaps_.push_back(std::move(c));
        ++netCapSeq_;
        while (netCaps_.size() > 1000) netCaps_.pop_front();
    }
}

void Debugger::writeNetCaptureLog(const NetCapture& c) {
    std::lock_guard<std::mutex> lk(netLogMtx_);
    if (!netLogFile_) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);
    const char* dir = c.dir == 0 ? "SEND" : "RECV";
    const char* api = c.api == TAP_send    ? "send"
                    : c.api == TAP_recv    ? "recv"
                    : c.api == TAP_WSASend ? "WSASend"
                    : c.api == TAP_WSARecv ? "WSARecv"
                                            : "socket";
    std::fprintf(netLogFile_,
                 "=== %04u-%02u-%02u %02u:%02u:%02u.%03u %s api=%s pid=%u tid=%u sock=0x%llX total=%u captured=%zu%s ===\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 dir, api, c.pid, c.tid, (unsigned long long)c.sock, c.total, c.bytes.size(),
                 c.bytes.size() < c.total ? " truncated" : "");
    std::fputs("TEXT:\n", netLogFile_);
    writePrintablePayload(netLogFile_, c.bytes);
    std::fputs("HEX:\n", netLogFile_);
    writeHexPayload(netLogFile_, c.bytes);
    std::fputc('\n', netLogFile_);
    std::fflush(netLogFile_);
}

// Resolve ws2_32 send/recv/WSASend/WSARecv and plant 0xCC hooks (as tap-flagged
// bps_ entries, so the existing step-over/re-arm machinery services them). The
// export addresses are valid in the debuggee because ws2_32 is a system DLL mapped
// at the same base session-wide (the same basis as the JDWP-injection thunks).
void Debugger::armNetTap() {
    if (netTapArmed_ || !hProcess_) return;
    if (isWow64_.load()) { std::lock_guard<std::mutex> lk(mtx_); lastEvent_ = "net tap: 64-bit targets only"; return; }
    HMODULE ws = ::GetModuleHandleW(L"ws2_32.dll");
    if (!ws) { std::lock_guard<std::mutex> lk(mtx_); lastEvent_ = "net tap: ws2_32 not present"; return; }
    const struct { const char* n; uint8_t api; } fns[] = {
        {"send", TAP_send}, {"recv", TAP_recv}, {"WSASend", TAP_WSASend}, {"WSARecv", TAP_WSARecv} };
    int armed = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto& f : fns) {
            uint64_t addr = (uint64_t)::GetProcAddress(ws, f.n);
            if (!addr || bps_.count(addr)) continue;     // missing, or a user bp owns this addr
            uint8_t orig = 0;
            if (!readByteRPM((HANDLE)hProcess_, addr, orig)) continue;
            if (orig == 0xCC) continue;                  // already hooked (e.g. another debugger)
            if (!writeByteRPM((HANDLE)hProcess_, addr, 0xCC)) continue;
            SwBp b; b.orig = orig; b.tapApi = f.api;
            bps_[addr] = b;
            ++armed;
        }
        rebuildBpAddrs_();
        lastEvent_ = armed ? "net data tap armed (ws2_32 send/recv)" : "net tap: no ws2_32 hooks installed";
    }
    netTapArmed_ = armed > 0;
}

void Debugger::disarmNetTap() {
    if (hProcess_) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto it = bps_.begin(); it != bps_.end(); ) {
            if (it->second.tapApi) { writeByteRPM((HANDLE)hProcess_, it->first, it->second.orig); it = bps_.erase(it); }
            else ++it;
        }
        for (auto& [addr, orig] : recvRetBytes_) writeByteRPM((HANDLE)hProcess_, addr, orig);
        recvRetBytes_.clear();
        pendingRecv_.clear();
        rebuildBpAddrs_();
        lastEvent_ = "net data tap off";
    }
    netTapArmed_ = false;
}

// Entry hit on a hooked send/recv/WSASend/WSARecv (x64 arg registers). send/WSASend
// data is present now; recv/WSARecv data isn't filled until the call returns, so we
// stash the buffer info and plant a one-shot return hook.
void Debugger::netTapCapture(uint64_t /*addr*/, uint32_t tid, uint8_t api) {
    auto th = threads_.find(tid);
    if (th == threads_.end()) return;
    Registers r;
    if (!ctxReadFull(th->second, r)) return;
    HANDLE hp = (HANDLE)hProcess_;
    const uint32_t now = ::GetTickCount();

    auto grab = [&](uint64_t buf, uint32_t len, uint8_t dir, uint8_t apiId, uint64_t sock) {
        if (!buf || !len) return;
        size_t take = len < kNetCaptureByteCap ? len : kNetCaptureByteCap;
        NetCapture c; c.tickMs = now; c.pid = pid_; c.tid = tid; c.dir = dir; c.api = apiId; c.sock = sock; c.total = len;
        c.bytes.resize(take);
        SIZE_T got = 0;
        if (::ReadProcessMemory(hp, (LPCVOID)buf, c.bytes.data(), take, &got) && got) {
            c.bytes.resize((size_t)got);
            pushNetCapture(std::move(c));
        }
    };

    if (api == TAP_send) {
        grab(r.rdx, (uint32_t)r.r8, 0, api, r.rcx);              // send(s=rcx, buf=rdx, len=r8)
    } else if (api == TAP_WSASend) {
        uint32_t count = (uint32_t)r.r8; if (count > 16) count = 16;   // WSASend(s, lpBuffers=rdx, count=r8)
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t wb[16];                                     // WSABUF{ULONG len; char* buf;} x64 stride 16
            if (!::ReadProcessMemory(hp, (LPCVOID)(r.rdx + (uint64_t)i * 16), wb, 16, nullptr)) break;
            uint32_t blen; std::memcpy(&blen, wb, 4);
            uint64_t bptr; std::memcpy(&bptr, wb + 8, 8);
            grab(bptr, blen, 0, api, r.rcx);
        }
    } else { // recv / WSARecv: capture on return
        uint64_t retAddr = 0;
        if (!::ReadProcessMemory(hp, (LPCVOID)r.rsp, &retAddr, 8, nullptr) || !retAddr) return;
        PendingRecv pr;
        pr.retAddr = retAddr; pr.sock = r.rcx; pr.wsa = (api == TAP_WSARecv);
        pr.buf = r.rdx; pr.len = (uint32_t)r.r8;                // recv: len; WSARecv: buffer count
        if (api == TAP_WSARecv) pr.numBytesPtr = r.r9;          // WSARecv(s, lpBuffers=rdx, count=r8, recvd=r9)
        pendingRecv_[tid] = pr;
        if (!recvRetBytes_.count(retAddr)) {
            uint8_t orig = 0;
            if (readByteRPM(hp, retAddr, orig) && orig != 0xCC && writeByteRPM(hp, retAddr, 0xCC))
                recvRetBytes_[retAddr] = orig;
        }
    }
}

// One-shot recv/WSARecv return hook: the buffer is filled now. Restore the byte,
// back RIP onto the return instruction, then capture what was received.
void Debugger::netTapOnReturn(uint64_t addr, uint32_t tid) {
    HANDLE hp = (HANDLE)hProcess_;
    if (auto rb = recvRetBytes_.find(addr); rb != recvRetBytes_.end()) {
        writeByteRPM(hp, addr, rb->second);
        recvRetBytes_.erase(rb);
    }
    auto th = threads_.find(tid);
    if (th != threads_.end()) ctxSetRip(th->second, addr);     // re-execute the real instruction

    auto pit = pendingRecv_.find(tid);
    if (pit == pendingRecv_.end() || th == threads_.end()) return;   // not our pending
    PendingRecv pr = pit->second;
    pendingRecv_.erase(pit);

    Registers r;
    if (!ctxReadFull(th->second, r)) return;
    const uint32_t now = ::GetTickCount();
    auto grab = [&](uint64_t buf, uint32_t len, uint8_t apiId, uint64_t sock) {
        if (!buf || !len) return;
        size_t take = len < kNetCaptureByteCap ? len : kNetCaptureByteCap;
        NetCapture c; c.tickMs = now; c.pid = pid_; c.tid = tid; c.dir = 1; c.api = apiId; c.sock = sock; c.total = len;
        c.bytes.resize(take);
        SIZE_T got = 0;
        if (::ReadProcessMemory(hp, (LPCVOID)buf, c.bytes.data(), take, &got) && got) {
            c.bytes.resize((size_t)got); pushNetCapture(std::move(c));
        }
    };
    if (!pr.wsa) {
        int32_t n = (int32_t)(uint32_t)r.rax;                  // recv() returns bytes received
        if (n > 0) grab(pr.buf, ((uint32_t)n < pr.len) ? (uint32_t)n : pr.len, TAP_recv, pr.sock);
    } else {
        uint32_t nbytes = 0;                                   // WSARecv: *lpNumberOfBytesRecvd
        if (pr.numBytesPtr) ::ReadProcessMemory(hp, (LPCVOID)pr.numBytesPtr, &nbytes, 4, nullptr);
        if (nbytes) {
            uint8_t wb[16];
            if (::ReadProcessMemory(hp, (LPCVOID)pr.buf, wb, 16, nullptr)) {
                uint64_t bptr; std::memcpy(&bptr, wb + 8, 8);
                grab(bptr, nbytes, TAP_WSARecv, pr.sock);
            }
        }
    }
}

bool Debugger::addHardwareBreakpoint(uint64_t va, HwKind kind, uint8_t size) {
    std::lock_guard<std::mutex> lk(mtx_);
    // Reject if already present or all four slots are spoken for (incl. pending).
    int inUse = 0;
    for (auto& s : hwSlots_) if (s.used) { if (s.addr == va) return true; ++inUse; }
    inUse += (int)pendingHwAdds_.size();
    if (inUse >= 4) return false;
    HwSlot s; s.used = true; s.addr = va; s.kind = kind; s.size = size;
    pendingHwAdds_.push_back(s);
    return true;
}
bool Debugger::removeHardwareBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    pendingHwRems_.push_back(va);
    return true;
}
bool Debugger::hasHardwareBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& s : hwSlots_) if (s.used && s.addr == va) return true;
    return false;
}

size_t Debugger::readMemory(uint64_t va, void* out, size_t n) {
    std::lock_guard<std::mutex> lk(hProcMtx_);   // serialize handle use vs the debug thread's close
    void* h = hProcessShared_.load();
    if (!h) return 0;
    SIZE_T got = 0;
    ReadProcessMemory((HANDLE)h, (LPCVOID)va, out, n, &got);
    return (size_t)got;
}

// Refill the sorted breakpoint-address cache from bps_. Caller holds mtx_.
void Debugger::rebuildBpAddrs_() {
    bpAddrs_.clear();
    bpAddrs_.reserve(bps_.size());
    for (auto& kv : bps_) bpAddrs_.push_back(kv.first);
    std::sort(bpAddrs_.begin(), bpAddrs_.end());
}

size_t Debugger::readMemoryMasked(uint64_t va, void* out, size_t n) {
    size_t got = readMemory(va, out, n);            // takes hProcMtx_ internally, then releases
    if (!got) return got;
    uint8_t* p = static_cast<uint8_t*>(out);
    std::lock_guard<std::mutex> lk(mtx_);           // bps_ / bpAddrs_ are guarded by mtx_
    if (bpAddrs_.empty()) return got;               // no breakpoints -> nothing to fix up
    // Binary-search the maintained sorted address list for only the breakpoints that
    // fall inside [va, va+got): the read range, not the whole bp table, drives the
    // work, so a read with no in-range breakpoints does O(log n) and stops.
    auto lo = std::lower_bound(bpAddrs_.begin(), bpAddrs_.end(), va);
    uint64_t end = va + (uint64_t)got;              // got <= n, no overflow vs a real read
    for (auto it = lo; it != bpAddrs_.end() && *it < end; ++it) {
        auto b = bps_.find(*it);
        if (b != bps_.end()) p[(size_t)(*it - va)] = b->second.orig;
    }
    return got;
}

size_t Debugger::writeMemory(uint64_t va, const void* in, size_t n) {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (!h) return 0;
    DWORD oldProt = 0;
    BOOL prot = VirtualProtectEx((HANDLE)h, (LPVOID)va, n, PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T put = 0;
    WriteProcessMemory((HANDLE)h, (LPVOID)va, in, n, &put);
    if (prot) VirtualProtectEx((HANDLE)h, (LPVOID)va, n, oldProt, &oldProt);
    FlushInstructionCache((HANDLE)h, (LPCVOID)va, n);
    return (size_t)put;
}

std::vector<MemRegion> Debugger::regions() {
    std::vector<MemRegion> out;
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (!h) return out;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = 0;
    while (VirtualQueryEx((HANDLE)h, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
            MemRegion r;
            r.base = (uint64_t)mbi.BaseAddress;
            r.size = (uint64_t)mbi.RegionSize;
            r.protect = mbi.Protect; r.state = mbi.State; r.type = mbi.Type;
            DWORD p = mbi.Protect & 0xFF;
            r.read  = p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
            r.write = p & (PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
            r.exec  = p & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
            out.push_back(r);
        }
        uint64_t next = (uint64_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
        if (out.size() > 100000) break;
    }
    return out;
}

uint64_t Debugger::allocRemote(size_t n) {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (!h || n == 0) return 0;
    void* p = VirtualAllocEx((HANDLE)h, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) return 0;
    remoteAllocs_.push_back((uint64_t)p);
    return (uint64_t)p;
}

void Debugger::freeRemote(uint64_t addr) {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (h && addr) VirtualFreeEx((HANDLE)h, (LPVOID)addr, 0, MEM_RELEASE);
    for (size_t i = 0; i < remoteAllocs_.size(); ++i)
        if (remoteAllocs_[i] == addr) { remoteAllocs_.erase(remoteAllocs_.begin() + i); break; }
}

void Debugger::freeAllRemote() {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (h) for (uint64_t a : remoteAllocs_) VirtualFreeEx((HANDLE)h, (LPVOID)a, 0, MEM_RELEASE);
    remoteAllocs_.clear();
}

bool Debugger::takeSnapshot(MemSnapshot& out, size_t perRegionCap) {
    DbgSnapshot s = snapshot();          // delegates lock; do NOT hold hProcMtx_ here
    if (!s.attached()) return false;
    out.regs = s.regs;
    out.blocks.clear();
    for (const auto& r : regions()) {    // committed, non-guard regions
        if (!r.read || r.size == 0) continue;
        const size_t len = (r.size < (uint64_t)perRegionCap) ? (size_t)r.size : perRegionCap;
        MemSnapshot::Block b; b.base = r.base; b.bytes.resize(len);
        const size_t got = readMemory(r.base, b.bytes.data(), len);
        if (got) { b.bytes.resize(got); out.blocks.push_back(std::move(b)); }
    }
    return true;
}

bool Debugger::restoreSnapshot(const MemSnapshot& snap) {
    if (snapshot().state != DbgState::Paused) return false;   // only safe while stopped
    for (const auto& b : snap.blocks)
        if (!b.bytes.empty()) writeMemory(b.base, b.bytes.data(), b.bytes.size());
    return setRegisters(snap.regs);
}

DbgSnapshot Debugger::snapshot() {
    std::lock_guard<std::mutex> lk(mtx_);
    DbgSnapshot s;
    s.state = state_;
    s.pid = pid_; s.tid = tid_;
    s.regs = regs_;
    s.lastEvent = lastEvent_;
    s.breakpoints.reserve(bps_.size());
    for (auto& kv : bps_) s.breakpoints.push_back({ kv.first, kv.second.cond, kv.second.hits, kv.second.stops, kv.second.everyN });
    for (auto& hs : hwSlots_) if (hs.used) s.hwBreakpoints.push_back({ hs.addr, hs.kind, hs.size });
    s.threads = threadList_;
    for (auto& t : s.threads) t.suspended = suspended_.count(t.tid) != 0;
    s.frames = frames_;
    s.modules = dbgModules_;
    s.debugOutput.assign(dbgOutput_.begin(), dbgOutput_.end());
    s.activeTid = activeTid_;
    s.is32 = isWow64_.load();
    s.jvmLoaded = jvmLoaded_;
    s.jvmPath = jvmPath_;
    s.jvmExceptionsPassed = jvmExceptionsPassed_;
    return s;
}

Debugger::Cmd Debugger::waitForCommand() {
    std::unique_lock<std::mutex> lk(mtx_);
    cmdCv_.wait(lk, [this] { return pending_ != Cmd::None || quit_; });
    Cmd c = quit_ ? Cmd::Detach : pending_;
    pending_ = Cmd::None;
    return c;
}

// ---- debug-thread helpers ---------------------------------------------------

static bool readByteRPM(HANDLE h, uint64_t va, uint8_t& b) {
    SIZE_T got = 0; return ReadProcessMemory(h, (LPCVOID)va, &b, 1, &got) && got == 1;
}
static bool writeByteRPM(HANDLE h, uint64_t va, uint8_t b) {
    SIZE_T put = 0;
    DWORD oldProt = 0;
    BOOL prot = VirtualProtectEx(h, (LPVOID)va, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    bool ok = WriteProcessMemory(h, (LPVOID)va, &b, 1, &put) && put == 1;
    if (prot) VirtualProtectEx(h, (LPVOID)va, 1, oldProt, &oldProt);
    FlushInstructionCache(h, (LPCVOID)va, 1);
    return ok;
}

// ---- arch-aware thread-context access ---------------------------------------
// A 32-bit (WOW64) target's registers live in a WOW64_CONTEXT reached via
// Wow64Get/SetThreadContext; a native 64-bit target uses the normal CONTEXT.
// 32-bit values are zero-extended into the 64-bit Registers fields so the rest of
// the engine (stepping, conditions, UI) is arch-agnostic.

bool Debugger::ctxReadFull(void* hThread, Registers& out) {
    out = Registers{};
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext((HANDLE)hThread, &c)) return false;
        out.rip = c.Eip; out.rsp = c.Esp; out.rbp = c.Ebp; out.rflags = c.EFlags;
        out.rax = c.Eax; out.rbx = c.Ebx; out.rcx = c.Ecx; out.rdx = c.Edx;
        out.rsi = c.Esi; out.rdi = c.Edi;   // r8-r15 don't exist in 32-bit mode
        return true;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext((HANDLE)hThread, &c)) return false;
    out.rip = c.Rip; out.rsp = c.Rsp; out.rbp = c.Rbp; out.rflags = c.EFlags;
    out.rax = c.Rax; out.rbx = c.Rbx; out.rcx = c.Rcx; out.rdx = c.Rdx;
    out.rsi = c.Rsi; out.rdi = c.Rdi;
    out.r8  = c.R8;  out.r9  = c.R9;  out.r10 = c.R10; out.r11 = c.R11;
    out.r12 = c.R12; out.r13 = c.R13; out.r14 = c.R14; out.r15 = c.R15;
    return true;
}

bool Debugger::ctxWriteFull(void* hThread, const Registers& r) {
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext((HANDLE)hThread, &c)) return false;   // preserve seg/FP/debug
        c.Eip = (DWORD)r.rip; c.Esp = (DWORD)r.rsp; c.Ebp = (DWORD)r.rbp; c.EFlags = (DWORD)r.rflags;
        c.Eax = (DWORD)r.rax; c.Ebx = (DWORD)r.rbx; c.Ecx = (DWORD)r.rcx; c.Edx = (DWORD)r.rdx;
        c.Esi = (DWORD)r.rsi; c.Edi = (DWORD)r.rdi;
        c.ContextFlags = WOW64_CONTEXT_FULL;
        return Wow64SetThreadContext((HANDLE)hThread, &c) != 0;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext((HANDLE)hThread, &c)) return false;
    c.Rip = r.rip; c.Rsp = r.rsp; c.Rbp = r.rbp; c.EFlags = (DWORD)r.rflags;
    c.Rax = r.rax; c.Rbx = r.rbx; c.Rcx = r.rcx; c.Rdx = r.rdx; c.Rsi = r.rsi; c.Rdi = r.rdi;
    c.R8  = r.r8;  c.R9  = r.r9;  c.R10 = r.r10; c.R11 = r.r11;
    c.R12 = r.r12; c.R13 = r.r13; c.R14 = r.r14; c.R15 = r.r15;
    c.ContextFlags = CONTEXT_FULL;
    return SetThreadContext((HANDLE)hThread, &c) != 0;
}

uint64_t Debugger::ctxReadRip(void* hThread) {
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        return Wow64GetThreadContext((HANDLE)hThread, &c) ? (uint64_t)c.Eip : 0;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    return GetThreadContext((HANDLE)hThread, &c) ? (uint64_t)c.Rip : 0;
}

void Debugger::ctxSetRip(void* hThread, uint64_t rip) {
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (Wow64GetThreadContext((HANDLE)hThread, &c)) {
            c.Eip = (DWORD)rip; c.ContextFlags = WOW64_CONTEXT_CONTROL;
            Wow64SetThreadContext((HANDLE)hThread, &c);
        }
        return;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext((HANDLE)hThread, &c)) { c.Rip = rip; SetThreadContext((HANDLE)hThread, &c); }
}

void Debugger::armBreakpoint(uint64_t va) {
    auto it = bps_.find(va);
    if (it == bps_.end()) return;
    writeByteRPM((HANDLE)hProcess_, va, 0xCC);
}
void Debugger::disarmBreakpoint(uint64_t va) {
    auto it = bps_.find(va);
    if (it == bps_.end()) return;
    writeByteRPM((HANDLE)hProcess_, va, it->second.orig); // restore original byte
}

// Rebuild the UI-visible thread list (debug thread; debuggee is stopped here).
void Debugger::refreshThreadList() {
    std::vector<ThreadInfo> list;
    std::vector<std::pair<uint32_t, void*>> handles;
    for (auto& kv : threads_) {
        ThreadInfo ti; ti.tid = kv.first;
        ti.rip = ctxReadRip(kv.second);
        list.push_back(ti);
        handles.emplace_back(kv.first, kv.second);
    }
    std::lock_guard<std::mutex> lk(mtx_);
    threadList_.swap(list);
    threadHandles_.swap(handles);
}

// Real call-stack unwind of the stopped debuggee (debug thread only; the target is
// frozen at an event here, so its memory/contexts are stable). Uses DbgHelp's
// StackWalk64, driven by:
//   - ReadProcessMemory       -> read the debuggee's frames/return addresses
//   - SymFunctionTableAccess64 -> the .pdata unwind tables (function table access)
//   - SymGetModuleBase64       -> the image base covering a given address
// The DbgHelp symbol session is the one the UI's SymbolResolver opened on this same
// process HANDLE (SymInitialize keys on the handle), so the function-table-access /
// module-base callbacks resolve against the modules it has registered. We pass the
// debuggee process HANDLE as hProcess so the stock Sym* callbacks operate on it.
//
// WOW64-aware: a 32-bit target is walked as IMAGE_FILE_MACHINE_I386 over its
// WOW64_CONTEXT (same field layout as a 32-bit CONTEXT); a native target as
// IMAGE_FILE_MACHINE_AMD64 over the x64 CONTEXT. Names are filled best-effort here
// (SymFromAddr); the UI may re-resolve through its own heuristic namer.
void Debugger::unwindStack(uint32_t tid) {
    std::vector<CallStackFrame> frames;
    auto it = threads_.find(tid);
    HANDLE hProc = (HANDLE)hProcess_;
    if (it == threads_.end() || !hProc) {
        std::lock_guard<std::mutex> lk(mtx_); frames_.swap(frames); return;
    }
    HANDLE hThread = (HANDLE)it->second;

    // The frame/stack/instruction seeds come from the thread's live context.
    STACKFRAME64 sf{};
    DWORD machine;
    // The CONTEXT StackWalk64 reads+updates. For WOW64 we keep a WOW64_CONTEXT and
    // hand its address in (StackWalk64 treats the pointer opaquely per `machine`).
    CONTEXT       ctx64{};
    WOW64_CONTEXT ctx32{};
    void* ctxPtr = nullptr;

    if (isWow64_.load()) {
        machine = IMAGE_FILE_MACHINE_I386;
        ctx32.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext(hThread, &ctx32)) {
            std::lock_guard<std::mutex> lk(mtx_); frames_.swap(frames); return;
        }
        sf.AddrPC.Offset    = ctx32.Eip;  sf.AddrPC.Mode    = AddrModeFlat;
        sf.AddrFrame.Offset = ctx32.Ebp;  sf.AddrFrame.Mode = AddrModeFlat;
        sf.AddrStack.Offset = ctx32.Esp;  sf.AddrStack.Mode = AddrModeFlat;
        ctxPtr = &ctx32;
    } else {
        machine = IMAGE_FILE_MACHINE_AMD64;
        ctx64.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx64)) {
            std::lock_guard<std::mutex> lk(mtx_); frames_.swap(frames); return;
        }
        sf.AddrPC.Offset    = ctx64.Rip; sf.AddrPC.Mode    = AddrModeFlat;
        sf.AddrFrame.Offset = ctx64.Rbp; sf.AddrFrame.Mode = AddrModeFlat;  // ignored by x64 walk, seeded anyway
        sf.AddrStack.Offset = ctx64.Rsp; sf.AddrStack.Mode = AddrModeFlat;
        ctxPtr = &ctx64;
    }

    const size_t kMaxFrames = 256;
    {
        // DbgHelp's Sym*/StackWalk64 are process-global single-threaded: serialize the
        // whole walk against the UI thread's SymbolResolver (see DbgHelpLock.h). Refresh
        // the module list first so .pdata unwind tables for every loaded module are
        // present -- the UI registers modules lazily, which would otherwise leave x64
        // unwinding without the tables it needs and degrade to frame-pointer guesses.
        std::lock_guard<std::recursive_mutex> dhlk(DbgHelpMutex());
        SymRefreshModuleList(hProc);
    for (size_t n = 0; n < kMaxFrames; ++n) {
        if (!StackWalk64(machine, hProc, hThread, &sf, ctxPtr,
                         /*ReadMemoryRoutine*/        nullptr,  // null -> StackWalk64 uses ReadProcessMemory(hProc)
                         /*FunctionTableAccess*/      SymFunctionTableAccess64,
                         /*GetModuleBase*/            SymGetModuleBase64,
                         /*TranslateAddress*/         nullptr))
            break;
        uint64_t pc = sf.AddrPC.Offset;
        if (!pc) break;   // unwound off the top of the stack

        CallStackFrame f;
        f.pc       = pc;
        f.frameSp  = sf.AddrFrame.Offset;
        f.stackPtr = sf.AddrStack.Offset;
        // Best-effort symbol (the UI re-resolves through its own namer anyway).
        ULONG64 buf[(sizeof(SYMBOL_INFO) + 256 + sizeof(ULONG64) - 1) / sizeof(ULONG64)] = {0};
        SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buf);
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen   = 255;
        DWORD64 disp = 0;
        if (SymFromAddr(hProc, pc, &disp, si) && si->NameLen)
            f.name.assign(si->Name, si->NameLen < si->MaxNameLen ? si->NameLen : si->MaxNameLen);
        frames.push_back(std::move(f));

        // A self-referential frame (AddrPC unchanged with zero frame movement) means
        // the walk stalled; stop rather than spin to the cap.
        if (n > 0 && sf.AddrReturn.Offset == sf.AddrPC.Offset && !sf.AddrFrame.Offset) break;
    }
    }   // release DbgHelpMutex before taking mtx_

    std::lock_guard<std::mutex> lk(mtx_);
    frames_.swap(frames);
}

// Evaluate a breakpoint's condition for the stopped thread (debug thread).
bool Debugger::evalConditionFor(uint64_t addr, uint32_t tid) {
    // Use the condition compiled once when the breakpoint was set/changed, instead
    // of re-parsing the string on every hit. An empty (unconditional) program is
    // {valid,empty} -> always true.
    CondProgram prog;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = bps_.find(addr); if (it != bps_.end()) prog = it->second.prog; }
    if (prog.empty) return true;

    auto th = threads_.find(tid);
    if (th == threads_.end()) return true;
    Registers rg;
    if (!ctxReadFull(th->second, rg)) return true;   // 32-bit values map into the low halves

    CondContext cc;
    cc.reg = [&rg](const std::string& n, uint64_t& out) -> bool {
        // Accept both 64-bit and 32-bit register names (eax/eip/esp/... alias rax/rip/rsp).
        if      (n == "rax" || n == "eax") out = rg.rax; else if (n == "rbx" || n == "ebx") out = rg.rbx;
        else if (n == "rcx" || n == "ecx") out = rg.rcx; else if (n == "rdx" || n == "edx") out = rg.rdx;
        else if (n == "rsi" || n == "esi") out = rg.rsi; else if (n == "rdi" || n == "edi") out = rg.rdi;
        else if (n == "rbp" || n == "ebp") out = rg.rbp; else if (n == "rsp" || n == "esp") out = rg.rsp;
        else if (n == "rip" || n == "eip") out = rg.rip;
        else if (n == "r8")  out = rg.r8;  else if (n == "r9")  out = rg.r9;
        else if (n == "r10") out = rg.r10; else if (n == "r11") out = rg.r11;
        else if (n == "r12") out = rg.r12; else if (n == "r13") out = rg.r13;
        else if (n == "r14") out = rg.r14; else if (n == "r15") out = rg.r15;
        else return false;
        return true;
    };
    // Read pointer-width: a 32-bit (WOW64) target's [addr] must not pull 4 adjacent bytes into the high dword.
    cc.mem = [this](uint64_t a) -> uint64_t { uint64_t v = 0; readMemory(a, &v, isWow64_.load() ? 4 : 8); return v; };
    return EvalCompiled(prog, cc, /*onError*/ true);   // evaluate the pre-compiled form
}

void Debugger::setTrapFlag(uint32_t tid, bool on) {
    auto it = threads_.find(tid);
    if (it == threads_.end()) return;
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!Wow64GetThreadContext((HANDLE)it->second, &c)) return;
        if (on) c.EFlags |= TRAP_FLAG; else c.EFlags &= ~TRAP_FLAG;
        c.ContextFlags = WOW64_CONTEXT_CONTROL;
        Wow64SetThreadContext((HANDLE)it->second, &c);
        return;
    }
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext((HANDLE)it->second, &ctx)) return;
    if (on) ctx.EFlags |= TRAP_FLAG; else ctx.EFlags &= ~TRAP_FLAG;
    SetThreadContext((HANDLE)it->second, &ctx);
}

// Set EFLAGS.RF (resume flag). A fault-class #DB from a hardware *execute*
// breakpoint (or a trap-flag step that lands on one) leaves RIP on the trapping
// instruction; RF makes the CPU run that one instruction without re-raising the
// breakpoint, then the CPU clears RF automatically so the bp stays armed.
void Debugger::setResumeFlag(uint32_t tid) {
    auto it = threads_.find(tid);
    if (it == threads_.end()) return;
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!Wow64GetThreadContext((HANDLE)it->second, &c)) return;
        c.EFlags |= 0x10000; // RF
        c.ContextFlags = WOW64_CONTEXT_CONTROL;
        Wow64SetThreadContext((HANDLE)it->second, &c);
        return;
    }
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext((HANDLE)it->second, &ctx)) return;
    ctx.EFlags |= 0x10000; // RF
    SetThreadContext((HANDLE)it->second, &ctx);
}

// Program DR0-DR3 + DR7 on one thread from the current hwSlots_ table.
void Debugger::applyHwToThread(void* hThread) {
    DWORD64 dr7 = 0;
    DWORD64 addrs[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        if (!hwSlots_[i].used) continue;
        addrs[i] = hwSlots_[i].addr;
        dr7 |= (DWORD64)1 << (i * 2);              // Ln: local enable for slot i

        // RWn condition: 00=execute, 01=write, 11=read/write.
        DWORD64 rw = 0;
        switch (hwSlots_[i].kind) {
            case HwKind::Execute:   rw = 0b00; break;
            case HwKind::Write:     rw = 0b01; break;
            case HwKind::ReadWrite: rw = 0b11; break;
        }
        // LENn: 00=1, 01=2, 11=4, 10=8 bytes. Execute must be length 1 (00).
        DWORD64 len = 0b00;
        if (hwSlots_[i].kind != HwKind::Execute) {
            switch (hwSlots_[i].size) { case 2: len = 0b01; break; case 4: len = 0b11; break;
                                         case 8: len = 0b10; break; default: len = 0b00; break; }
        }
        dr7 |= (rw  << (16 + i * 4));
        dr7 |= (len << (18 + i * 4));
    }
    // DR0-DR7 are shared physical registers and the DR7 layout is identical for x86/x64.
    // Program them via the NATIVE 64-bit CONTEXT even for a WOW64 thread: debug registers
    // set through the 32-bit WOW64_CONTEXT are not reliably armed by the kernel, so a
    // WOW64 hardware breakpoint set that way often never fires. 32-bit DR addresses
    // zero-extend into the DWORD64 fields, and CONTEXT_DEBUG_REGISTERS touches only the DRs.
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext((HANDLE)hThread, &ctx)) return;
    ctx.Dr0 = addrs[0]; ctx.Dr1 = addrs[1]; ctx.Dr2 = addrs[2]; ctx.Dr3 = addrs[3];
    ctx.Dr7 = dr7;
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext((HANDLE)hThread, &ctx);
}

void Debugger::applyHwAllThreads() {
    for (auto& kv : threads_) applyHwToThread(kv.second);
}

// Read DR6 for a thread and clear it (so the next hit is distinguishable).
bool Debugger::readDr6Clear(uint32_t tid, uint64_t& dr6) {
    dr6 = 0;
    auto it = threads_.find(tid);
    if (it == threads_.end()) return false;
    // Read/clear DR6 via the native CONTEXT for both x86 and x64 (see applyHwToThread:
    // the WOW64 debug-register view is unreliable). DR6 is the same physical register.
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext((HANDLE)it->second, &ctx)) return false;
    dr6 = ctx.Dr6;
    if (ctx.Dr6 & 0xF) { ctx.Dr6 = 0; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                         SetThreadContext((HANDLE)it->second, &ctx); }
    return true;
}

void Debugger::captureContext(uint32_t tid) {
    auto it = threads_.find(tid);
    if (it == threads_.end()) return;
    Registers r;
    if (!ctxReadFull(it->second, r)) return;   // arch-aware (native CONTEXT or WOW64_CONTEXT)
    std::lock_guard<std::mutex> lk(mtx_);
    regs_ = r;
}

Debugger::StepDecode Debugger::decodeAt(uint64_t va) {
    StepDecode d;
    // 32-bit (WOW64) code must be measured/classified with an x86 decoder.
    IDisassembler* dis = isWow64_.load() ? ownDis32_.get() : ownDis_.get();
    if (!dis) return d;
    uint8_t buf[16] = {0};
    size_t n = readMemory(va, buf, sizeof(buf));
    if (!n) return d;
    // The live bytes may contain our own 0xCC software breakpoints; substitute the
    // saved originals so we classify the real instruction, not an int3.
    for (size_t i = 0; i < n; ++i) {
        auto it = bps_.find(va + i);
        if (it != bps_.end()) buf[i] = it->second.orig;
    }
    Instruction in;
    if (dis->decodeOne(buf, n, va, in)) {
        d.length      = in.length ? in.length : 1;
        d.isCall      = in.isCall;
        d.isRet       = in.isRet;
        d.isRepString = in.isRepString;
    }
    return d;
}

// ---- debug-thread main loop -------------------------------------------------

void Debugger::threadMain(uint32_t pid, bool launch, std::wstring launchPath, bool breakAtEntry) {
    if (launch) {
        // The thread that creates a DEBUG-flagged process must be the same one that
        // pumps WaitForDebugEvent, so the process is created here on the debug thread.
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        // CreateProcessW may write to the command-line buffer, so pass a mutable copy.
        std::vector<wchar_t> cmd(launchPath.begin(), launchPath.end());
        cmd.push_back(L'\0');
        BOOL ok = CreateProcessW(launchPath.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                                 DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                                 nullptr, nullptr, &si, &pi);
        if (!ok) {
            std::lock_guard<std::mutex> lk(mtx_);
            startupErr_ = "CreateProcess failed (err " + std::to_string(GetLastError()) +
                          ") - check the path / bitness, or run as Administrator.";
            startupOk_ = false; startupDone_ = true; cmdCv_.notify_all();
            return;
        }
        pid = pi.dwProcessId;
        // We receive our own process/thread handles via the debug events; the ones
        // CreateProcess returned are redundant.
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else if (!DebugActiveProcess(pid)) {
        std::lock_guard<std::mutex> lk(mtx_);
        startupErr_ = "DebugActiveProcess failed (err " + std::to_string(GetLastError()) +
                      ") - run as Administrator / match bitness.";
        startupOk_ = false; startupDone_ = true; cmdCv_.notify_all();
        return;
    }
    DebugSetProcessKillOnExit(FALSE);
    { std::lock_guard<std::mutex> lk(mtx_); pid_ = pid; state_ = DbgState::Running;
      lastEvent_ = launch ? "launched" : "attached";
      // The startup flags MUST be published under mtx_. The waiter in attach()/
      // launchAndAttach() evaluates `startupDone_` while holding mtx_ and then blocks
      // on cmdCv_; setting the flag + notifying outside the lock races with that
      // check-then-wait and can drop the wakeup, hanging the UI forever on attach.
      startupOk_ = true; startupDone_ = true; }
    cmdCv_.notify_all();

    // Launch + break-at-entry: don't stop on the loader breakpoint; instead arm a
    // one-shot breakpoint at the program entry and continue, landing the user on
    // the first instruction of their code. Captured on CREATE_PROCESS_DEBUG_EVENT.
    bool     wantEntryBreak = launch && breakAtEntry;
    uint64_t entryAddr      = 0;

    // --- parked on a user breakpoint (byte restored, RIP backed up) ---
    bool        pausedOnBp = false; uint64_t pausedOnBpAddr = 0;

    // --- single-step then re-arm a user breakpoint we stepped off of ---
    uint64_t    reArmAddr = 0;                       // 0 = none pending
    AfterReArm  reArmAfter = AfterReArm::FreeRun;    // what to do once it is re-armed
    const char* reArmLabel = "step";                 // UI label for AfterReArm::Pause

    bool   stepPause = false;                  // pause on the next single-step
    uint32_t stepTid = 0;                      // thread a single-instruction step is armed on; binds
                                               // the trap-flag #DB so another thread's stray single-step
                                               // can't consume our pending step state

    // --- step out ---
    bool     steppingOut = false; size_t stepOutIters = 0;
    bool     stepOutFinishing = false;         // ret is executing; pause on next step
    uint64_t stepOutAnchorRsp = 0;             // RSP when step-out began: a ret only leaves
                                               // the frame when RSP rises above this anchor

    // --- one-shot temporary breakpoint (run-to / step-over return / step-out skip) ---
    TempKind tempKind = TempKind::None;
    bool   tempBpSet = false; uint64_t tempBpAddr = 0; uint8_t tempBpOrig = 0;
    uint64_t tempReArm = 0;                     // re-arm this user bp when the temp bp fires

    bool   firstBreakpoint = true;
    // A WOW64 (32-bit) target raises MORE than one loader breakpoint during startup
    // (the x64 ntdll one, then the 32-bit wow64 ntdll one). They must be swallowed,
    // not passed back as unhandled (which terminates the process). loaderPhase stays
    // true until the first user-visible stop.
    bool   loaderPhase = true;
    uint32_t mainTid = 0;   // the process main thread (shown when the user hits Pause)

    // --- JVM awareness (Java EXEs) ---
    // The VM module's mapped range, captured from its LOAD_DLL event; bounds
    // IsJvmInternalException so HotSpot's intentional AVs (null checks, safepoint
    // polls) pass through without pausing or spamming events.
    uint64_t jvmBase = 0, jvmSize = 0;
    // JNI_CreateJavaVM one-shot waiting for the single temp-bp slot to free up
    // (a step's temp bp may be in flight when jvm.dll loads).
    uint64_t pendingJvmInitVA = 0;

    auto applyPendingBps = [&]() {
        std::vector<PendingBp> adds, conds;
        std::vector<uint64_t>  rems;
        { std::lock_guard<std::mutex> lk(mtx_);
          adds.swap(pendingBpAdds_); rems.swap(pendingBpRems_); conds.swap(pendingBpConds_); }
        bool bpSetChanged = false;   // adds/removes that change the bpAddrs_ key set
        for (auto& add : adds) {
            if (bps_.count(add.va)) {   // re-add of an existing bp only updates its condition
                std::lock_guard<std::mutex> lk(mtx_);
                bps_[add.va].cond = add.cond; bps_[add.va].prog = CompileCondition(add.cond);
                continue;
            }
            uint8_t orig = 0x90;
            readByteRPM((HANDLE)hProcess_, add.va, orig);
            if (orig == 0xCC) {
                // The live byte is already an int3. If it is our own in-flight temp bp,
                // recover the real original; otherwise it is a genuine int3 in the program
                // (or another debugger's), so PRESERVE 0xCC. Never fabricate 0x90 here —
                // writing a NOP back when the breakpoint is removed would corrupt the code.
                if (tempBpSet && add.va == tempBpAddr) orig = tempBpOrig;
                else orig = 0xCC;
            }
            { std::lock_guard<std::mutex> lk(mtx_); SwBp b; b.orig = orig; b.cond = add.cond;
              b.prog = CompileCondition(add.cond); bps_[add.va] = b; bpSetChanged = true; }
            writeByteRPM((HANDLE)hProcess_, add.va, 0xCC);
        }
        for (auto& cset : conds) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = bps_.find(cset.va);
            if (it != bps_.end()) { it->second.cond = cset.cond; it->second.prog = CompileCondition(cset.cond); }
        }
        {   // every-Nth-hit updates (applied after adds so a fresh bp can be tuned).
            std::vector<std::pair<uint64_t, uint32_t>> everyNs;
            { std::lock_guard<std::mutex> lk(mtx_); everyNs.swap(pendingBpEveryN_); }
            for (auto& [va, n] : everyNs) {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = bps_.find(va);
                if (it != bps_.end()) it->second.everyN = n;
            }
        }
        for (uint64_t va : rems) {
            auto it = bps_.find(va);
            if (it == bps_.end()) continue;
            writeByteRPM((HANDLE)hProcess_, va, it->second.orig);
            { std::lock_guard<std::mutex> lk(mtx_); bps_.erase(va); bpSetChanged = true; }
        }
        // Keep the sorted breakpoint-address cache in sync with the key set, so
        // readMemoryMasked stays O(log n) per read (see rebuildBpAddrs_).
        if (bpSetChanged) { std::lock_guard<std::mutex> lk(mtx_); rebuildBpAddrs_(); }

        // Hardware breakpoints: fold pending changes into slots, reprogram threads.
        std::vector<HwSlot> hwAdds; std::vector<uint64_t> hwRems;
        { std::lock_guard<std::mutex> lk(mtx_); hwAdds.swap(pendingHwAdds_); hwRems.swap(pendingHwRems_); }
        bool hwChanged = false;
        for (uint64_t va : hwRems) {
            for (auto& s : hwSlots_)
                if (s.used && s.addr == va) { std::lock_guard<std::mutex> lk(mtx_); s = HwSlot{}; hwChanged = true; }
        }
        for (auto& add : hwAdds) {
            bool placed = false;
            for (auto& s : hwSlots_) if (s.used && s.addr == add.addr) { placed = true; break; }
            if (placed) continue;
            for (auto& s : hwSlots_) if (!s.used) { std::lock_guard<std::mutex> lk(mtx_); s = add; hwChanged = true; placed = true; break; }
        }
        if (hwChanged) applyHwAllThreads();

        // Network data tap: install / remove the ws2_32 hooks to match the request.
        if (netTapWant_.load() && !netTapArmed_)      armNetTap();
        else if (!netTapWant_.load() && netTapArmed_) disarmNetTap();
    };

    // Publish a one-line status for the UI (locks mtx_; never called while held).
    auto setEvent = [&](const char* s) { std::lock_guard<std::mutex> lk(mtx_); lastEvent_ = s; };

    auto ripOf = [&](uint32_t tid) -> uint64_t {
        auto it = threads_.find(tid); if (it == threads_.end()) return 0;
        return ctxReadRip(it->second);   // arch-aware (RIP or EIP)
    };
    auto rspOf = [&](uint32_t tid) -> uint64_t {
        auto it = threads_.find(tid); if (it == threads_.end()) return 0;
        Registers r; return ctxReadFull(it->second, r) ? r.rsp : 0;   // arch-aware (RSP or ESP)
    };
    // Arm a one-shot temp breakpoint at `addr`, remembering what it stands for.
    auto setTempBp = [&](uint64_t addr, TempKind kind) {
        tempBpAddr = addr; tempBpOrig = 0x90;
        readByteRPM((HANDLE)hProcess_, addr, tempBpOrig);
        // If the 0xCC can't actually be written (unwritable page / bad addr), don't
        // record a temp bp that was never set: it would later restore a stale byte and
        // make us wait for a stop that can never fire.
        if (!writeByteRPM((HANDLE)hProcess_, addr, 0xCC)) { tempBpSet = false; tempKind = TempKind::None; return; }
        tempBpSet = true; tempKind = kind;
    };
    // Tear down any outstanding temp breakpoint and honor a deferred user-bp re-arm.
    // Called whenever an in-progress step is abandoned (a different bp/HW bp fires),
    // so we never leak a 0xCC into the target or strand a disarmed user breakpoint.
    auto clearTempBp = [&]() {
        if (tempBpSet) { writeByteRPM((HANDLE)hProcess_, tempBpAddr, tempBpOrig); tempBpSet = false; }
        tempKind = TempKind::None;
        if (tempReArm) { armBreakpoint(tempReArm); tempReArm = 0; }
    };
    // Handle a hit on the user software breakpoint at `a`: cancel any step, restore
    // the original byte, back RIP over the int3, then either park on it (condition
    // holds) or silently step+re-arm+run (condition false). Returns true to pause.
    auto handleUserBp = [&](uint64_t a, uint32_t tid) -> bool {
        clearTempBp();
        steppingOut = false; stepPause = false; stepOutFinishing = false;
        disarmBreakpoint(a);
        // find(), not operator[]: an unknown tid must not insert a null HANDLE
        // into threads_ (it would linger and get CloseHandle(nullptr)'d at cleanup).
        if (auto th = threads_.find(tid); th != threads_.end()) ctxSetRip(th->second, a);
        // Network data tap: this bp is a ws2_32 hook, not a user stop. Capture the
        // buffer (or, for recv, arm a one-shot return bp), then take the same
        // step-over + re-arm + free-run path as a condition-false hit. Never pauses.
        if (auto bt = bps_.find(a); bt != bps_.end() && bt->second.tapApi) {
            netTapCapture(a, tid, bt->second.tapApi);
            reArmAddr = a; reArmAfter = AfterReArm::FreeRun;
            stepTid = tid;
            setTrapFlag(tid, true);
            return false;
        }
        bool stop = evalConditionFor(a, tid);
        {   // Hit accounting (under mtx_: snapshot() reads bps_ concurrently). The
            // every-Nth gate composes with the condition: the bp parks only when the
            // condition holds AND this is the Nth raw hit (hits counts every fire).
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto it = bps_.find(a); it != bps_.end()) {
                ++it->second.hits;
                if (stop && it->second.everyN > 1 && (it->second.hits % it->second.everyN) != 0)
                    stop = false;
                if (stop) ++it->second.stops;
            }
        }
        if (stop) {
            // Park on it; how we step off + re-arm is decided by the next command.
            pausedOnBp = true; pausedOnBpAddr = a;
            setEvent("breakpoint");
            return true;
        }
        // Condition false: single-step the original instruction, re-arm, keep running.
        reArmAddr = a; reArmAfter = AfterReArm::FreeRun;
        stepTid = tid;
        setTrapFlag(tid, true);
        return false;
    };
    // One decision tick of a step-out, evaluated against the instruction at the
    // current RIP. Sets the trap flag or a temp breakpoint as needed. Returns true
    // only when the caller should pause immediately (the iteration cap tripped).
    auto stepOutStep = [&](uint32_t tid) -> bool {
        stepTid = tid;
        if (++stepOutIters > kStepOutCap) { steppingOut = false; setEvent("step out (capped)"); return true; }
        uint64_t rip = ripOf(tid);
        StepDecode d = decodeAt(rip);
        switch (DecideStepOut(ClassifyInsn(d.isCall, d.isRet, d.isRepString))) {
            case StepOutAction::StepOverUnit:
                // Skip the call/rep entirely: break at the return point and continue.
                setTempBp(rip + d.length, TempKind::StepOutSkip);
                setTrapFlag(tid, false);
                return false;
            case StepOutAction::FinishAfterRet:
                // Let the ret execute; the following single-step lands in the caller.
                steppingOut = false; stepOutFinishing = true;
                setTrapFlag(tid, true);
                return false;
            case StepOutAction::SingleStep:
            default:
                setTrapFlag(tid, true);
                return false;
        }
    };

    DEBUG_EVENT ev{};
    bool alive = true;
    while (alive && !quit_) {
        if (!WaitForDebugEvent(&ev, 100)) continue; // timeout: re-check quit_
        DWORD contStatus = DBG_CONTINUE;
        bool  pause = false;
        bool  needResumeFlag = false;   // set when stopped on a fault-class hw execute bp
        uint32_t breakDisplayTid = 0;   // !=0 => a Pause break; show/step this thread, not the helper

        switch (ev.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                hProcess_ = ev.u.CreateProcessInfo.hProcess;
                hProcessShared_ = hProcess_;
                // A 32-bit (WOW64) target needs the WOW64_CONTEXT register set and an
                // x86 step decoder. Detect it once, before any context access below.
                { BOOL w = FALSE; if (IsWow64Process((HANDLE)hProcess_, &w)) isWow64_.store(w != 0); }
                mainTid = ev.dwThreadId;
                threads_[ev.dwThreadId] = ev.u.CreateProcessInfo.hThread;
                // Program entry for break-at-entry. lpStartAddress is unreliable for
                // packed/managed images, so prefer the PE AddressOfEntryPoint read from
                // the mapped image (AddressOfEntryPoint sits at e_lfanew+24+16 in both
                // PE32 and PE32+); fall back to lpStartAddress.
                entryAddr = (uint64_t)ev.u.CreateProcessInfo.lpStartAddress;
                {
                    uint64_t imgBase = (uint64_t)ev.u.CreateProcessInfo.lpBaseOfImage;
                    IMAGE_DOS_HEADER dos{}; DWORD sig = 0, aoe = 0;
                    if (imgBase && readMemory(imgBase, &dos, sizeof(dos)) == sizeof(dos) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE &&
                        readMemory(imgBase + dos.e_lfanew, &sig, 4) == 4 && sig == IMAGE_NT_SIGNATURE &&
                        readMemory(imgBase + dos.e_lfanew + 24 + 16, &aoe, 4) == 4 && aoe)
                        entryAddr = imgBase + aoe;
                }
                if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                threads_[ev.dwThreadId] = ev.u.CreateThread.hThread;
                applyHwToThread(ev.u.CreateThread.hThread); // inherit active DR breakpoints
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                if (auto it = threads_.find(ev.dwThreadId); it != threads_.end()) {
                    {   // Drop the UI-visible copy under mtx_ BEFORE closing the handle, so a
                        // concurrent setActiveThread() on the UI thread can never resolve a
                        // now-closed (possibly recycled) handle.
                        std::lock_guard<std::mutex> lk(mtx_);
                        for (size_t i = 0; i < threadHandles_.size(); )
                            if (threadHandles_[i].first == ev.dwThreadId) threadHandles_.erase(threadHandles_.begin() + i);
                            else ++i;
                        for (size_t i = 0; i < threadList_.size(); )
                            if (threadList_[i].tid == ev.dwThreadId) threadList_.erase(threadList_.begin() + i);
                            else ++i;
                        suspended_.erase(ev.dwThreadId);   // a frozen thread that exits is no longer frozen
                    }
                    CloseHandle((HANDLE)it->second);   // we own thread handles from the debug API
                    threads_.erase(it);
                }
                break;
            case LOAD_DLL_DEBUG_EVENT: {
                DbgModule m;
                m.base = (uint64_t)(uintptr_t)ev.u.LoadDll.lpBaseOfDll;
                // Resolve the path from the file handle Windows hands us (most
                // reliable); fall back to the debuggee-side lpImageName pointer.
                if (ev.u.LoadDll.hFile) {
                    wchar_t wpath[1024];
                    DWORD n = GetFinalPathNameByHandleW(ev.u.LoadDll.hFile, wpath,
                                                        (DWORD)(sizeof(wpath) / sizeof(wpath[0])), FILE_NAME_NORMALIZED);
                    if (n > 0 && n < sizeof(wpath) / sizeof(wpath[0])) {
                        const wchar_t* p = wpath;
                        if (wcsncmp(p, L"\\\\?\\", 4) == 0) p += 4;   // strip the NT prefix
                        char buf[2048] = {0};
                        if (WideCharToMultiByte(CP_UTF8, 0, p, -1, buf, sizeof(buf), nullptr, nullptr) > 0)
                            m.path = buf;
                    }
                    CloseHandle(ev.u.LoadDll.hFile);
                }
                if (m.path.empty() && ev.u.LoadDll.lpImageName) {
                    // lpImageName points (in DEBUGGEE memory) to a pointer to the name.
                    uint64_t namePtr = 0;
                    const size_t psz = isWow64_.load() ? 4 : 8;
                    if (readMemory((uint64_t)(uintptr_t)ev.u.LoadDll.lpImageName, &namePtr, psz) == psz && namePtr) {
                        if (ev.u.LoadDll.fUnicode) {
                            wchar_t wbuf[512] = {0};
                            readMemory(namePtr, wbuf, sizeof(wbuf) - sizeof(wchar_t));
                            char buf[2048] = {0};
                            if (wbuf[0] && WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, sizeof(buf), nullptr, nullptr) > 0)
                                m.path = buf;
                        } else {
                            char abuf[1024] = {0};
                            readMemory(namePtr, abuf, sizeof(abuf) - 1);
                            m.path = abuf;
                        }
                    }
                }
                {   // File name from the path; a nameless module is labelled by base.
                    size_t s = m.path.find_last_of("/\\");
                    m.name = m.path.empty() ? std::string()
                           : (s == std::string::npos ? m.path : m.path.substr(s + 1));
                    if (m.name.empty()) {
                        char b[32]; std::snprintf(b, sizeof(b), "<0x%llX>", (unsigned long long)m.base);
                        m.name = b;
                    }
                }
                {   // SizeOfImage from the mapped PE header (same slot in PE32/PE32+).
                    IMAGE_DOS_HEADER dos{}; DWORD soi = 0;
                    if (m.base && readMemory(m.base, &dos, sizeof(dos)) == sizeof(dos) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE &&
                        readMemory(m.base + dos.e_lfanew + 24 + 56, &soi, 4) == 4)
                        m.size = soi;
                }
                // JVM awareness: capture the VM module's range and (when armed) plant
                // the one-shot JNI_CreateJavaVM breakpoint. jli.dll lights the badge
                // but doesn't bound exceptions (IsJvmVmModuleName excludes it).
                if (IsJvmVmModuleName(m.name)) {
                    jvmBase = m.base;
                    jvmSize = m.size ? m.size : (32ull << 20);   // header unreadable: generous bound
                    { std::lock_guard<std::mutex> lk(mtx_);
                      jvmLoaded_ = true; jvmPath_ = m.path.empty() ? m.name : m.path; }
                    if (breakOnJvmInit_.load()) {
                        RemoteReader rr = [this](uint64_t va, void* out, size_t n) {
                            return readMemory(va, out, n) == n;
                        };
                        if (uint32_t rva = FindExportRVA(rr, m.base, "JNI_CreateJavaVM")) {
                            // Only one temp-bp slot exists; if a step's temp bp is in
                            // flight, defer arming until the slot frees (see the
                            // armDeferredJvmInit ticks after applyPendingBps below).
                            if (!tempBpSet) setTempBp(m.base + rva, TempKind::JvmInit);
                            else            pendingJvmInitVA = m.base + rva;
                        }
                    }
                } else if (IsJvmModuleName(m.name)) {
                    std::lock_guard<std::mutex> lk(mtx_);
                    jvmLoaded_ = true;
                    if (jvmPath_.empty()) jvmPath_ = m.path.empty() ? m.name : m.path;
                }
                {   // Publish to the UI-visible list (bounded against load/unload churn).
                    std::lock_guard<std::mutex> lk(mtx_);
                    if (dbgModules_.size() < kMaxDbgModules) dbgModules_.push_back(std::move(m));
                }
                break;
            }
            case UNLOAD_DLL_DEBUG_EVENT: {
                const uint64_t b = (uint64_t)(uintptr_t)ev.u.UnloadDll.lpBaseOfDll;
                if (b && b == jvmBase) { jvmBase = 0; jvmSize = 0; }
                std::lock_guard<std::mutex> lk(mtx_);
                for (size_t i = 0; i < dbgModules_.size(); )
                    if (dbgModules_[i].base == b) dbgModules_.erase(dbgModules_.begin() + i);
                    else ++i;
                break;
            }
            case OUTPUT_DEBUG_STRING_EVENT: {
                const OUTPUT_DEBUG_STRING_INFO& od = ev.u.DebugString;
                if (od.lpDebugStringData && od.nDebugStringLength) {
                    std::string text;
                    if (od.fUnicode) {
                        size_t chars = od.nDebugStringLength;        // length in WCHARs
                        if (chars * 2 > kDbgOutputLine) chars = kDbgOutputLine / 2;
                        std::vector<wchar_t> wb(chars + 1, 0);
                        size_t got = readMemory((uint64_t)(uintptr_t)od.lpDebugStringData, wb.data(), chars * 2);
                        int wn = (int)(got / 2);
                        while (wn > 0 && wb[wn - 1] == 0) --wn;
                        if (wn > 0) {
                            int k = WideCharToMultiByte(CP_UTF8, 0, wb.data(), wn, nullptr, 0, nullptr, nullptr);
                            if (k > 0) {
                                text.resize(k);
                                WideCharToMultiByte(CP_UTF8, 0, wb.data(), wn, text.data(), k, nullptr, nullptr);
                            }
                        }
                    } else {
                        size_t len = od.nDebugStringLength;          // length in bytes
                        if (len > kDbgOutputLine) len = kDbgOutputLine;
                        text.resize(len);
                        text.resize(readMemory((uint64_t)(uintptr_t)od.lpDebugStringData, text.data(), len));
                        while (!text.empty() && text.back() == '\0') text.pop_back();
                    }
                    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
                    if (!text.empty()) {
                        std::lock_guard<std::mutex> lk(mtx_);
                        dbgOutput_.push_back(std::move(text));
                        while (dbgOutput_.size() > kDbgOutputCap) dbgOutput_.pop_front();
                    }
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT:
                { std::lock_guard<std::mutex> lk(mtx_); state_ = DbgState::Terminated; lastEvent_ = "process exited"; }
                alive = false;
                break;

            case EXCEPTION_DEBUG_EVENT: {
                const EXCEPTION_RECORD& er = ev.u.Exception.ExceptionRecord;
                const uint64_t addr = (uint64_t)er.ExceptionAddress;
                // WOW64 reports 32-bit int3/single-step under WX86 status codes.
                const bool isBpExc = er.ExceptionCode == EXCEPTION_BREAKPOINT ||
                                     er.ExceptionCode == kStatusWx86Breakpoint;
                const bool isSsExc = er.ExceptionCode == EXCEPTION_SINGLE_STEP ||
                                     er.ExceptionCode == kStatusWx86SingleStep;

                if (isBpExc) {
                    if (wantEntryBreak && entryAddr && !tempBpSet) {
                        // Arm a one-shot bp at the program entry and continue, landing the
                        // user on their first instruction. Done independently of the
                        // positional `firstBreakpoint` so a stray early int3 (TLS callback /
                        // static initializer) can't consume the chance to arm it.
                        firstBreakpoint = false;
                        wantEntryBreak = false;
                        setTempBp(entryAddr, TempKind::EntryPoint);
                        setEvent("launching");
                    } else if (firstBreakpoint) {
                        firstBreakpoint = false; // initial system breakpoint (loader)
                        pause = true;
                        setEvent("initial break");
                    } else if (tempBpSet && addr == tempBpAddr) {
                        // A temp breakpoint fired (run-to-cursor, step-over return, or a
                        // call/rep skipped during step-out). Remove it and back RIP onto
                        // the target instruction.
                        writeByteRPM((HANDLE)hProcess_, tempBpAddr, tempBpOrig);
                        if (auto th = threads_.find(ev.dwThreadId); th != threads_.end())
                            ctxSetRip(th->second, tempBpAddr);
                        tempBpSet = false;
                        TempKind tk = tempKind; tempKind = TempKind::None;
                        // If this temp bp also stood in for a user bp we stepped off of,
                        // re-arm that user bp now (its 0xCC was withheld during the run).
                        if (tempReArm) { armBreakpoint(tempReArm); tempReArm = 0; }
                        if (bps_.count(tempBpAddr)) {
                            // A real user breakpoint also lives at this address: it takes
                            // priority over the step (don't silently skip past it).
                            if (handleUserBp(tempBpAddr, ev.dwThreadId)) pause = true;
                        } else if (tk == TempKind::StepOutSkip) {
                            if (stepOutStep(ev.dwThreadId)) pause = true; // keep stepping out
                        } else {
                            pause = true;
                            setEvent(tk == TempKind::RunTo      ? "run to cursor"
                                   : tk == TempKind::EntryPoint ? "entry point"
                                   : tk == TempKind::JvmInit    ? "JVM init (JNI_CreateJavaVM)"
                                                                : "step over");
                        }
                    } else if (bps_.count(addr)) {
                        if (handleUserBp(addr, ev.dwThreadId)) pause = true;
                    } else if (recvRetBytes_.count(addr)) {
                        // A one-shot recv/WSARecv return hook: the buffer is now filled.
                        netTapOnReturn(addr, ev.dwThreadId);   // captures, restores byte, no pause
                    } else if (breakRequested_.exchange(false)) {
                        // User pressed Pause: DebugBreakProcess put this int3 in a helper
                        // thread (ntdll!DbgBreakPoint). Consume it and show/step a real user
                        // thread (the main thread) so you stop on the code it's executing.
                        pause = true;
                        breakDisplayTid = (mainTid && threads_.count(mainTid)) ? mainTid : ev.dwThreadId;
                        setEvent("paused");
                    } else if (isWow64_.load() && loaderPhase) {
                        // An extra WOW64 loader breakpoint (e.g. wow64 ntdll init) before
                        // the program is running: swallow it so the process isn't killed.
                        contStatus = DBG_CONTINUE;
                    } else {
                        contStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }
                } else if (isSsExc) {
                    // A single-step exception is raised both by the trap flag (DR6.BS)
                    // and by a hardware breakpoint hit (DR6 bits 0-3). Read + clear DR6.
                    uint64_t dr6 = 0; readDr6Clear(ev.dwThreadId, dr6);
                    const bool hwHit = (dr6 & 0xF) != 0;

                    // Thread binding: we only ever set the trap flag on `stepTid`, so a NON-hw-bp
                    // single-step from any other thread is a stray (ContinueDebugEvent resumes the
                    // whole process). Don't let it consume the stepped thread's pending state — clear
                    // that thread's trap flag and continue; the stepped thread's own #DB still arrives
                    // and is handled. Nothing is suspended, so (unlike "freeze other threads") this
                    // can't deadlock a thread blocked on a peer's lock/syscall.
                    if (!hwHit && stepTid && ev.dwThreadId != stepTid &&
                        (reArmAddr || stepPause || steppingOut || stepOutFinishing)) {
                        setTrapFlag(ev.dwThreadId, false);
                    } else if (reArmAddr) {
                        // We just single-stepped the original instruction of a user
                        // breakpoint; re-arm its 0xCC, then realize the pending command
                        // from the new RIP (this is what makes Step Over / Step Out /
                        // Continue work correctly even when issued while parked on a bp).
                        armBreakpoint(reArmAddr);
                        AfterReArm after = reArmAfter;
                        reArmAddr = 0; reArmAfter = AfterReArm::FreeRun;
                        if (hwHit) {
                            steppingOut = false; stepOutFinishing = false;
                            for (int i = 0; i < 4; ++i)
                                if (((dr6 >> i) & 1) && hwSlots_[i].used && hwSlots_[i].kind == HwKind::Execute) needResumeFlag = true;
                            pause = true; setEvent("hw breakpoint");
                        } else switch (after) {
                            case AfterReArm::Pause:
                                pause = true; setEvent(reArmLabel);
                                break;
                            case AfterReArm::BeginStepOut:
                                steppingOut = true; stepOutIters = 0; stepOutFinishing = false;
                                stepOutAnchorRsp = rspOf(ev.dwThreadId);
                                if (stepOutStep(ev.dwThreadId)) pause = true;
                                break;
                            case AfterReArm::ContinueStepOut: // only reached via the temp-bp path
                            case AfterReArm::FreeRun:
                            default:
                                setTrapFlag(ev.dwThreadId, false);
                                break;
                        }
                    } else if (hwHit) {
                        clearTempBp(); // abandon any outstanding step-over/step-out temp bp
                        steppingOut = false; stepPause = false; stepOutFinishing = false;
                        for (int i = 0; i < 4; ++i)
                            if (((dr6 >> i) & 1) && hwSlots_[i].used && hwSlots_[i].kind == HwKind::Execute) needResumeFlag = true;
                        pause = true; setEvent("hw breakpoint");
                    } else if (stepOutFinishing) {
                        // A ret just executed. Only stop if RSP actually rose above the
                        // step-out anchor (we truly left the frame); a stack-neutral
                        // ret-trick (push/ret) or a deeper recursion level leaves RSP at
                        // or below the anchor, so keep stepping out in that case.
                        stepOutFinishing = false;
                        if (rspOf(ev.dwThreadId) > stepOutAnchorRsp) { pause = true; setEvent("step out"); }
                        else { steppingOut = true; if (stepOutStep(ev.dwThreadId)) pause = true; }
                    } else if (steppingOut) {
                        if (stepOutStep(ev.dwThreadId)) pause = true;
                    } else if (stepPause) {
                        stepPause = false; pause = true; setEvent("step");
                    }
                } else {
                    // A real exception. Always passed back to the app (we never
                    // swallow it), but three policies decide what the USER sees:
                    //   1. JVM-internal faults (HotSpot null checks / safepoint polls
                    //      inside jvm.dll) are counted and passed through silently.
                    //   2. A whitelisted code, or break-on-first-chance, pauses on
                    //      the first chance with a semantic label.
                    //   3. Otherwise only a last-chance (unhandled) exception updates
                    //      the status line - no pause, no per-event spam.
                    const uint32_t code = er.ExceptionCode;
                    bool whitelisted = false;
                    { std::lock_guard<std::mutex> lk(mtx_); whitelisted = fcWhitelist_.count(code) != 0; }
                    if (IsJvmInternalException(code, addr, jvmBase, jvmSize) && !whitelisted) {
                        std::lock_guard<std::mutex> lk(mtx_);
                        ++jvmExceptionsPassed_;
                    } else if (ev.u.Exception.dwFirstChance &&
                               (breakOnFirstChance_.load() || whitelisted)) {
                        char lbl[128];
                        std::snprintf(lbl, sizeof(lbl), "first-chance %s at 0x%llX",
                                      ExceptionCodeLabel(code).c_str(), (unsigned long long)addr);
                        setEvent(lbl);
                        pause = true;
                    } else if (!ev.u.Exception.dwFirstChance) {
                        char lbl[128];
                        std::snprintf(lbl, sizeof(lbl), "unhandled %s at 0x%llX",
                                      ExceptionCodeLabel(code).c_str(), (unsigned long long)addr);
                        setEvent(lbl);
                    }
                    contStatus = DBG_EXCEPTION_NOT_HANDLED; // real exception -> let app handle
                }
                break;
            }
            default: break;
        }

        // We are stopped at an event here, so it's safe to touch debuggee memory.
        applyPendingBps();
        // A JNI_CreateJavaVM one-shot that was deferred because the single temp-bp
        // slot was busy: arm it as soon as the slot is free.
        if (pendingJvmInitVA && !tempBpSet) {
            setTempBp(pendingJvmInitVA, TempKind::JvmInit);
            pendingJvmInitVA = 0;
        }

        if (pause && alive) {
            loaderPhase = false;   // a user-visible stop ends startup; later int3s are real
            // On a Pause break, present a user thread (not the DebugBreak helper).
            uint32_t showTid = breakDisplayTid ? breakDisplayTid : ev.dwThreadId;
            captureContext(showTid);
            refreshThreadList();
            unwindStack(showTid);   // real DbgHelp StackWalk64 of the stopped thread
            { std::lock_guard<std::mutex> lk(mtx_); state_ = DbgState::Paused; tid_ = showTid; activeTid_ = showTid; }

            Cmd c = waitForCommand();
            if (c == Cmd::Detach || quit_) { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE); break; }
            applyPendingBps();
            if (pendingJvmInitVA && !tempBpSet) {   // deferred JVM-init one-shot (see above)
                setTempBp(pendingJvmInitVA, TempKind::JvmInit);
                pendingJvmInitVA = 0;
            }
            { std::lock_guard<std::mutex> lk(mtx_); state_ = DbgState::Running; }

            // Step/continue commands act on the displayed thread; ContinueDebugEvent still
            // resumes via the event's own thread (the helper just returns and exits).
            const uint32_t tid = showTid;

            // Run-to-cursor: arm a one-shot temp breakpoint at the target, then resume
            // exactly like Continue (which also steps off / re-arms a bp we are parked
            // on). Skip if the target is the very breakpoint we are sitting on.
            if (c == Cmd::RunTo) {
                uint64_t target = 0; { std::lock_guard<std::mutex> lk(mtx_); target = cmdArg_; }
                if (target && !tempBpSet && !(pausedOnBp && target == pausedOnBpAddr))
                    setTempBp(target, TempKind::RunTo);
                c = Cmd::Continue;
            }

            if (pausedOnBp) {
                // Parked on a user breakpoint (original byte restored, RIP backed up).
                // Decide how to step off it, re-arm it, and then realize the command.
                uint64_t   A  = pausedOnBpAddr; pausedOnBp = false;
                StepDecode od = decodeAt(A);
                InsnKind   k  = ClassifyInsn(od.isCall, od.isRet, od.isRepString);
                StepCmd    sc = (c == Cmd::StepInto) ? StepCmd::StepInto
                              : (c == Cmd::StepOver) ? StepCmd::StepOver
                              : (c == Cmd::StepOut)  ? StepCmd::StepOut
                                                     : StepCmd::Continue;
                reArmLabel = (sc == StepCmd::StepInto) ? "step into"
                           : (sc == StepCmd::StepOver) ? "step over"
                           : (sc == StepCmd::StepOut)  ? "step out" : "step";
                OnBpResume plan = DecideOnBpResume(sc, k);
                if (plan.method == ReArmMethod::SingleStep) {
                    reArmAddr = A; reArmAfter = plan.after;
                    stepTid = tid;
                    setTrapFlag(tid, true);   // step the original insn; re-arm + resume on #DB
                } else {
                    // TempBpAfter: a call/rep sits directly on the breakpoint. Run over it
                    // and re-arm the user bp once the temp bp at its return point fires.
                    uint32_t L = od.length ? od.length : 1;
                    if (plan.after == AfterReArm::ContinueStepOut) {
                        steppingOut = true; stepOutIters = 0; stepOutFinishing = false;
                        stepOutAnchorRsp = rspOf(tid);
                        setTempBp(A + L, TempKind::StepOutSkip);
                    } else {
                        setTempBp(A + L, TempKind::StepOver);
                    }
                    if (tempBpSet) {
                        tempReArm = A;            // re-armed when the temp bp at the return point fires
                    } else {
                        // The temp bp couldn't be written: don't strand the user bp at A (it was
                        // disarmed when we parked on it). Re-arm it now and fall back to a plain
                        // continue with the breakpoint live, rather than free-running past it.
                        armBreakpoint(A);
                        steppingOut = false; stepOutFinishing = false;
                    }
                    setTrapFlag(tid, false);
                }
            } else {
                switch (c) {
                    case Cmd::StepInto:
                        stepTid = tid; setTrapFlag(tid, true); stepPause = true; break;
                    case Cmd::StepOver: {
                        StepDecode d = decodeAt(ripOf(tid));
                        if (DecideStepOver(ClassifyInsn(d.isCall, d.isRet, d.isRepString))
                                == StepOverAction::StepOverUnit) {
                            setTempBp(ripOf(tid) + d.length, TempKind::StepOver); // over the call/rep
                            setTrapFlag(tid, false); // run to the return point, don't single-step
                        } else { stepTid = tid; setTrapFlag(tid, true); stepPause = true; }
                        break;
                    }
                    case Cmd::StepOut:
                        steppingOut = true; stepOutIters = 0; stepOutFinishing = false;
                        stepOutAnchorRsp = rspOf(tid);
                        // The first tick cannot trip the iteration cap, so its pause hint
                        // (too late to act on here anyway) is intentionally not checked.
                        stepOutStep(tid);   // inspect the current instruction and act
                        break;
                    case Cmd::Continue:
                    default:
                        setTrapFlag(tid, false); break;
                }
            }

            // We were parked on a fault-class hardware execute breakpoint: RIP is
            // still on the trapping instruction and the DR slot is still armed, so
            // any forward resume would immediately re-trap. Set RF so this one
            // instruction runs; the CPU clears RF afterward, keeping the bp live.
            if (needResumeFlag) setResumeFlag(tid);
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, contStatus);
    }

    // Cleanup: restore all breakpoint bytes, clear DR registers, stop debugging.
    {   // Drop the UI-visible handle FIRST: a pause() (DebugBreakProcess) landing after
        // DebugActiveProcessStop would inject an int3 into a process that no longer has
        // a debugger and kill it. Nulling under hProcMtx_ makes the UI see "gone" before
        // we stop debugging; the restores below use hProcess_ directly so they still work.
        std::lock_guard<std::mutex> lk(hProcMtx_);
        hProcessShared_ = nullptr;
    }
    breakRequested_ = false;   // a pause that raced the teardown must not leak into a reattach
    for (auto& kv : bps_) writeByteRPM((HANDLE)hProcess_, kv.first, kv.second.orig);
    if (tempBpSet) writeByteRPM((HANDLE)hProcess_, tempBpAddr, tempBpOrig);
    // Net-tap one-shot recv-return hooks aren't in bps_; restore them too.
    for (auto& [addr, orig] : recvRetBytes_) writeByteRPM((HANDLE)hProcess_, addr, orig);
    recvRetBytes_.clear(); pendingRecv_.clear(); netTapArmed_ = false;
    for (auto& s : hwSlots_) s = HwSlot{};
    applyHwAllThreads();                       // walks threads_, so close handles after it
    {   // Thaw any user-frozen threads so the process isn't left with suspended
        // threads after we detach (SuspendThread's count persists past detach).
        std::vector<uint32_t> toResume;
        { std::lock_guard<std::mutex> lk(mtx_); toResume.assign(suspended_.begin(), suspended_.end()); suspended_.clear(); }
        for (uint32_t tid : toResume) { auto it = threads_.find(tid); if (it != threads_.end()) ResumeThread((HANDLE)it->second); }
    }
    for (auto& kv : threads_) CloseHandle((HANDLE)kv.second);
    threads_.clear();
    DebugActiveProcessStop(pid);
    {   // Close the process handle under hProcMtx_ so a UI-thread pause/readMemory/
        // writeMemory/regions can't be mid-call on a handle we are about to close.
        std::lock_guard<std::mutex> lk(hProcMtx_);
        if (hProcess_) { CloseHandle((HANDLE)hProcess_); hProcess_ = nullptr; }
        hProcessShared_ = nullptr;
    }
    { std::lock_guard<std::mutex> lk(mtx_);
      if (state_ != DbgState::Terminated) state_ = DbgState::Detached; }
}

} // namespace ds
