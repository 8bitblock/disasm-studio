// Reversible native mouse-ball experiment for the verified 32-bit Peggle build.
// Opening this controller does not modify the game. Arm is the explicit opt-in.
// Native mouse capture owns the reference. The only ball write is its checked
// one-byte stationary flag; no input injection, remote calls, or refcount writes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include "Core/ProcessMemorySession.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <exception>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr uint32_t kAppGlobal = 0x6873AC;
constexpr uint32_t kAppVtable = 0x5D7CBC;
constexpr uint32_t kBoardVtable = 0x5D76F4;
constexpr uint32_t kDebugVtable = 0x5DD3F0;
constexpr uint32_t kBallVtable = 0x5F19B4;
constexpr UINT kTimer = 1;
constexpr int kArm = 101, kRelease = 102, kClose = 103;
int systemDpi = 96;
int pixels(int logical) { return MulDiv(logical, systemDpi, 96); }

struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { reset(); value = std::exchange(other.value, nullptr); }
        return *this;
    }
    explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
    void reset(HANDLE h = nullptr) { if (*this) CloseHandle(value); value = h; }
};

std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring result(n > 0 ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), n);
    return result;
}

std::string winError(const char* action) {
    return std::string(action) + " (Windows error " + std::to_string(GetLastError()) + ").";
}

bool pointer(uint32_t p) { return p >= 0x10000 && p <= 0xFFF00000 && (p & 3) == 0; }

struct SuspendedThread { Handle handle; DWORD tid = 0; };

bool resumeThreads(std::vector<SuspendedThread>& threads, std::string& error) {
    // Keep failed handles so the next timer or Release can retry OUR one suspend.
    for (size_t i = threads.size(); i-- > 0;) {
        auto& thread = threads[i];
        if (WaitForSingleObject(thread.handle.value, 0) == WAIT_OBJECT_0 ||
            ResumeThread(thread.handle.value) != static_cast<DWORD>(-1)) {
            threads.erase(threads.begin() + static_cast<ptrdiff_t>(i));
        }
    }
    if (threads.empty()) return true;
    error = "Could not resume " + std::to_string(threads.size()) +
        " game thread(s). Retrying; keep this controller open.";
    return false;
}

bool threadIds(DWORD pid, std::vector<DWORD>& ids, std::string& error) {
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snap) { error = winError("Cannot enumerate game threads"); return false; }
    THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
    if (!Thread32First(snap.value, &entry)) {
        error = winError("Cannot read game thread list"); return false;
    }
    do {
        if (entry.th32OwnerProcessID == pid) ids.push_back(entry.th32ThreadID);
    } while (Thread32Next(snap.value, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) {
        error = winError("Game thread enumeration was incomplete"); return false;
    }
    if (ids.empty() || ids.size() > 256) {
        error = "Game thread count is empty or outside the supported bound."; return false;
    }
    std::sort(ids.begin(), ids.end());
    return true;
}

class PauseGuard {
public:
    PauseGuard(ds::ProcessMemorySession& memory, ds::ProcessMemoryIdentity identity,
               std::vector<SuspendedThread>& suspended, std::string& error)
        : memory_(memory), identity_(identity), suspended_(suspended), error_(error) {}
    ~PauseGuard() { if (!finished_) resumeThreads(suspended_, error_); }
    bool begin() {
        if (!suspended_.empty()) { error_ = "A previous thread resume still needs recovery."; return false; }
        const ULONGLONG start = GetTickCount64();
        std::vector<DWORD> ids;
        if (!sameProcess() || !threadIds(identity_.pid, ids, error_)) return false;
        suspended_.reserve(ids.size());
        for (DWORD tid : ids) {
            Handle thread(OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                     THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, tid));
            if (!thread || GetProcessIdOfThread(thread.value) != identity_.pid) {
                error_ = "A game thread changed or could not be opened; no edit was started."; return false;
            }
            if (SuspendThread(thread.value) == static_cast<DWORD>(-1)) {
                error_ = winError("Cannot suspend every game thread"); return false;
            }
            suspended_.push_back({std::move(thread), tid});
            WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (!Wow64GetThreadContext(suspended_.back().handle.value, &context)) {
                error_ = winError("Cannot verify the paused x86 instruction pointer"); return false;
            }
            // Include nearby branch instructions, not just the two patch bytes.
            if ((context.Eip >= 0x4400C1 && context.Eip < 0x4400D4) ||
                (context.Eip >= 0x43E520 && context.Eip < 0x43E538)) {
                error_ = "A game thread is inside a temporary patch area. Retry Release or Arm."; return false;
            }
            if (GetTickCount64() - start > 250) {
                error_ = "Pausing exceeded the short edit budget; no edit was started."; return false;
            }
        }
        std::vector<DWORD> finalIds;
        if (!sameProcess() || !threadIds(identity_.pid, finalIds, error_)) return false;
        if (ids != finalIds) {
            error_ = "Game threads changed during the pause; no edit was started."; return false;
        }
        return true;
    }
    bool finish() {
        finished_ = true;
        return resumeThreads(suspended_, error_);
    }
private:
    bool sameProcess() {
        const auto current = memory_.snapshot();
        if (current.alive && ds::ProcessMemoryIdentityMatches(current.identity, identity_)) return true;
        error_ = "The exact game process is no longer available."; return false;
    }
    ds::ProcessMemorySession& memory_;
    ds::ProcessMemoryIdentity identity_;
    std::vector<SuspendedThread>& suspended_;
    std::string& error_;
    bool finished_ = false;
};

struct Scene { uint32_t app = 0, board = 0, debug = 0; };
bool operator==(const Scene& a, const Scene& b) {
    return a.app == b.app && a.board == b.board && a.debug == b.debug;
}

struct Patch {
    uint32_t address;
    std::array<uint8_t, 2> original;
    std::array<uint8_t, 2> replacement;
    bool owned = false;
};

enum class Mode { Idle, WaitingBall, WaitingClick, Following, Releasing, Recovery };

class Controller {
public:
    explicit Controller(DWORD requestedPid, bool autoArm) : requestedPid_(requestedPid), autoArm_(autoArm) {}
    ~Controller() {
        std::string ignored;
        resumeThreads(suspended_, ignored);
        if (mutexOwned_) ReleaseMutex(mutex_.value);
        if (font_) DeleteObject(font_);
    }
    void create(HWND window) {
        window_ = window;
        font_ = CreateFontW(-pixels(17), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            DEFAULT_PITCH, L"Segoe UI");
        control(L"STATIC", L"Peggle: ball follows cursor", SS_LEFT, 18, 14, 484, 26, 0);
        control(L"STATIC", L"1. Open a level and click Arm.\r\n2. Shoot a ball, then click anywhere in the playfield.\r\n3. Release here, then click once in the game to let go.",
                SS_LEFT, 18, 47, 484, 76, 0);
        status_ = control(L"EDIT", L"Ready. No game changes have been made.",
                          ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                          18, 132, 484, 100, 0);
        target_ = control(L"STATIC", L"Only the verified popcapgame1.exe build is supported.", SS_LEFT,
                          18, 240, 484, 44, 0);
        control(L"STATIC", L"Collisions stay active. Release before menus / quit.",
                SS_LEFT, 18, 288, 484, 20, 0);
        arm_ = control(L"BUTTON", L"Arm", BS_PUSHBUTTON | WS_TABSTOP, 18, 312, 140, 34, kArm);
        release_ = control(L"BUTTON", L"Release / Cancel", BS_PUSHBUTTON | WS_TABSTOP,
                           174, 312, 160, 34, kRelease);
        control(L"BUTTON", L"Close", BS_PUSHBUTTON | WS_TABSTOP, 350, 312, 152, 34, kClose);
        SetTimer(window_, kTimer, 50, nullptr);
        updateButtons();
        if (autoArm_) PostMessageW(window_, WM_COMMAND, kArm, 0);
    }
    void command(int id) {
        if (id == kArm) arm();
        else if (id == kRelease) release(false);
        else if (id == kClose) close();
    }
    void close() {
        if (clean()) { DestroyWindow(window_); return; }
        closeRequested_ = true;
        release(true);
    }
    bool clean() const {
        return !retained_ && !patches_[0].owned && !patches_[1].owned &&
            capturedBall_ == 0 && !ballFlagOwned_ && !unresolvedWrite_ && suspended_.empty();
    }
    void fault(const std::string& error) {
        if (clean()) {
            mode_ = Mode::Idle;
            setStatus("Operation stopped: " + error + "\r\nNo active experiment remains. Arm can be retried.");
            return;
        }
        mode_ = Mode::Recovery;
        setStatus("Recovery needed: " + error + "\r\nUse Release to retry cleanup. Keep this controller open.");
    }
    void tick() {
        if (!suspended_.empty()) {
            std::string error;
            if (!resumeThreads(suspended_, error)) { fault(error); return; }
            fault("Game threads have resumed. Use Release to finish cleanup.");
        }
        if (!identity_.valid()) return;
        const auto snapshot = memory_.snapshot();
        if (!snapshot.alive || !ds::ProcessMemoryIdentityMatches(snapshot.identity, identity_)) {
            // An exited process owns no surviving code, data, or intrusive references.
            patches_[0].owned = patches_[1].owned = false;
            retained_ = unresolvedWrite_ = false;
            clearCaptureOwnership();
            mode_ = Mode::Idle;
            setStatus("The game exited. This session is retired; no stale addresses will be written.");
            if (closeRequested_ && suspended_.empty()) DestroyWindow(window_);
            return;
        }
        if (mode_ == Mode::Idle || mode_ == Mode::Recovery) return;
        std::string error;
        Scene scene;
        if (!readScene(scene, error) || !(scene == scene_)) {
            release(false, "The level or game scene changed."); return;
        }
        uint32_t held = 0;
        if (!read(scene_.debug + 8, held, error)) { release(false, error); return; }
        if (mode_ == Mode::WaitingBall || mode_ == Mode::WaitingClick) {
            if (held) {
                if (mode_ == Mode::WaitingClick) finishCapture();
                else release(false, "A native mouse ball appeared before capture was armed.");
                return;
            }
            if (GetTickCount64() >= deadline_) { release(false, "Arming timed out after 60 seconds."); return; }
            if (mode_ == Mode::WaitingBall) {
                bool active = false;
                if (!activeBall(scene, active, error)) { release(false, error); return; }
                if (active) prepareCapture();
            } else {
                bool active = false;
                if (!activeBall(scene, active, error)) { release(false, error); return; }
                if (!active) waitForNextBall();
            }
        } else if (mode_ == Mode::Following || mode_ == Mode::Releasing) {
            if (!held) { release(false, "The game released the ball."); return; }
            if (!capturedBall_ || held != capturedBall_) {
                release(false, "The native mouse-ball pointer changed. Another ball will not be modified."); return;
            }
            const uint8_t expected = mode_ == Mode::Following ? 0 : 1;
            if (!validBallState(held, expected, error)) { release(false, error); return; }
            if (mode_ == Mode::Following) {
                bool unusedActive = false;
                if (!activeBall(scene, unusedActive, error, held, 0)) {
                    // The debug manager's native reference still owns this object,
                    // so release uses its identity even after list removal.
                    release(false, error);
                }
            }
        }
    }

private:
    HWND control(const wchar_t* kind, const wchar_t* text, DWORD style,
                 int x, int y, int width, int height, int id) {
        HWND child = CreateWindowExW(0, kind, text, WS_CHILD | WS_VISIBLE | style,
            pixels(x), pixels(y), pixels(width), pixels(height), window_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            GetModuleHandleW(nullptr), nullptr);
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
        return child;
    }
    void setStatus(const std::string& value) {
        const auto text = wide(value);
        SetWindowTextW(status_, text.c_str());
        updateButtons();
    }
    void updateButtons() {
        EnableWindow(arm_, clean() && mode_ == Mode::Idle);
        EnableWindow(release_, !clean());
    }
    template<class T> bool read(uint32_t address, T& value, std::string& error) {
        return memory_.read(identity_, address, &value, sizeof(value), &error) == sizeof(value);
    }
    template<class T> bool write(uint32_t address, const T& value, std::string& error) {
        const auto result = memory_.write(identity_, address, &value, sizeof(value));
        if (result.ok()) return true;
        if (!result.protectionsRestored || result.code == ds::ProcessMemoryWriteCode::RollbackFailed)
            unresolvedWrite_ = true;
        error = result.error.empty() ? "A checked data write failed." : result.error;
        return false;
    }
    bool readScene(Scene& scene, std::string& error) {
        uint32_t vt = 0, backlink = 0;
        if (!read(kAppGlobal, scene.app, error) || !pointer(scene.app) ||
            !read(scene.app, vt, error) || vt != kAppVtable ||
            !read(scene.app + 0x7B8, scene.board, error) || !pointer(scene.board) ||
            !read(scene.board, vt, error) || vt != kBoardVtable ||
            !read(scene.board + 0x140, scene.debug, error) || !pointer(scene.debug) ||
            !read(scene.debug, vt, error) || vt != kDebugVtable ||
            !read(scene.debug + 0x24, backlink, error) || backlink != scene.board) {
            if (error.empty()) error = "No supported live level/debug-manager identity was found.";
            return false;
        }
        return true;
    }
    bool currentScene(std::string& error) {
        Scene current;
        if (!readScene(current, error) || !(current == scene_)) {
            if (error.empty()) error = "The retained level identity no longer matches.";
            return false;
        }
        return true;
    }
    void clearCaptureOwnership() {
        capturedBall_ = 0;
        ballFlagOwned_ = false;
        nativeCaptureExpected_ = false;
    }
    bool validBallIdentity(uint32_t ball, std::string& error) {
        uint32_t vt = 0, type = 0;
        if (!pointer(ball) || !read(ball, vt, error) || vt != kBallVtable ||
            !read(ball + 0x10, type, error) || type != 2) {
            error = "The native mouse-ball identity could not be verified."; return false;
        }
        return true;
    }
    bool validBallState(uint32_t ball, uint8_t expected, std::string& error) {
        uint8_t flag = 0;
        if (!validBallIdentity(ball, error) || !read(ball + 0x140, flag, error) || flag != expected) {
            error = "The owned ball's stationary state changed unexpectedly."; return false;
        }
        return true;
    }
    bool writeCapturedFlag(uint8_t desired, std::string& error) {
        // Caller holds PauseGuard. Revalidate native ownership before touching the
        // one per-ball byte, including rollback/release after a failed write.
        uint32_t nativeBall = 0;
        uint8_t current = 0;
        if (!capturedBall_ || !currentScene(error) ||
            !read(scene_.debug + 8, nativeBall, error) || nativeBall != capturedBall_ ||
            !validBallIdentity(capturedBall_, error) ||
            !read(capturedBall_ + 0x140, current, error) || current > 1) {
            error = "The exact native-owned ball could not be verified; its flag was not changed."; return false;
        }
        if (desired == 0) {
            if (current != 1 || ballFlagOwned_) {
                error = "The captured ball was not in its original native-held state."; return false;
            }
            ballFlagOwned_ = true; // Keep restoration responsibility on uncertainty.
        }
        if (current != desired && !write(capturedBall_ + 0x140, desired, error)) return false;
        if (desired == 1) ballFlagOwned_ = false;
        return true;
    }
    bool activeBall(const Scene& scene, bool& found, std::string& error,
                    uint32_t requiredBall = 0, uint8_t requiredFlag = 1) {
        uint32_t sentinel = 0, count = 0;
        if (!read(scene.board + 0x1A0, sentinel, error) || !pointer(sentinel) ||
            !read(scene.board + 0x1A4, count, error) || count > 64) {
            error = "The level's ball list is not a supported bounded list."; return false;
        }
        struct Node { uint32_t next, previous, ball; };
        std::array<uint32_t, 2> ends{};
        if (!read(sentinel, ends, error)) return false;
        uint32_t node = ends[0], previous = sentinel;
        bool requiredFound = requiredBall == 0;
        std::vector<uint32_t> visited;
        for (uint32_t i = 0; i < count; ++i) {
            if (!pointer(node) || node == sentinel ||
                std::find(visited.begin(), visited.end(), node) != visited.end()) {
                error = "The ball list changed or contains an invalid cycle."; return false;
            }
            visited.push_back(node);
            Node entry{};
            if (!read(node, entry, error) || entry.previous != previous || !pointer(entry.next)) {
                error = "The ball list links could not be verified."; return false;
            }
            uint32_t nextPrevious = 0;
            if (!read(entry.next + 4, nextPrevious, error) || nextPrevious != node) {
                error = "The ball list's reverse links changed."; return false;
            }
            if (entry.ball) {
                uint32_t vt = 0, type = 0;
                uint8_t stationary = 1, inert = 1;
                if (!pointer(entry.ball) || !read(entry.ball, vt, error) || vt != kBallVtable ||
                    !read(entry.ball + 0x10, type, error) || type != 2 ||
                    !read(entry.ball + 0x140, stationary, error) ||
                    !read(entry.ball + 0x18C, inert, error)) {
                    error = "A ball-list object did not match the verified ball type."; return false;
                }
                if (stationary == 0 && inert == 0) found = true;
                if (entry.ball == requiredBall && stationary == requiredFlag && inert == 0) requiredFound = true;
            }
            previous = node; node = entry.next;
        }
        if (node != sentinel || previous != ends[1]) {
            error = "The ball list count and circular links disagree."; return false;
        }
        if (!requiredFound) {
            error = "The captured object is not an eligible ball in this level's owned list."; return false;
        }
        return true;
    }
    bool signatures(std::string& error) {
        const auto check = [&](uint32_t address, const auto& expected) {
            std::vector<uint8_t> actual(expected.size());
            if (memory_.read(identity_, address, actual.data(), actual.size(), &error) != actual.size()) return false;
            for (const auto& patch : patches_) {
                if (patch.address < address || patch.address + 2 > address + actual.size()) continue;
                const auto offset = patch.address - address;
                const bool original = std::equal(patch.original.begin(), patch.original.end(), actual.begin() + offset);
                const bool ours = patch.owned && std::equal(patch.replacement.begin(), patch.replacement.end(), actual.begin() + offset);
                if (!original && !ours) { error = "A patch site contains unknown bytes; refusing to overwrite them."; return false; }
                std::copy(patch.original.begin(), patch.original.end(), actual.begin() + offset);
            }
            if (!std::equal(expected.begin(), expected.end(), actual.begin())) {
                error = "The game code does not match the supported build (or another tool changed it)."; return false;
            }
            return true;
        };
        constexpr std::array<uint8_t, 24> mouseUp = {
            0x80,0x79,0x04,0x00,0x74,0x0C,0x6A,0x00,0xE8,0xB3,0xFF,0xFF,
            0xFF,0xB0,0x01,0xC2,0x0C,0x00,0x32,0xC0,0xC2,0x0C,0x00,0xCC};
        constexpr std::array<uint8_t, 19> selection = {
            0xD8,0xD9,0xDF,0xE0,0xF6,0xC4,0x01,0x75,0x08,0xD9,0x5D,0xFC,
            0x89,0x75,0xF8,0xEB,0x02,0xDD,0xD8};
        constexpr std::array<uint8_t, 48> setter = {
            0x55,0x8B,0xEC,0x8B,0x41,0x08,0x85,0xC0,0x56,0x8D,0x71,0x08,
            0x74,0x07,0xC6,0x80,0x40,0x01,0x00,0x00,0x00,0x8B,0x45,0x08,
            0x50,0x8B,0xCE,0xE8,0x70,0x8A,0x03,0x00,0x8B,0x36,0x85,0xF6,
            0x74,0x07,0xC6,0x86,0x40,0x01,0x00,0x00,0x01,0x5E,0x5D,0xC2};
        constexpr std::array<uint8_t, 12> updater = {
            0x55,0x8B,0xEC,0x83,0xEC,0x20,0x56,0x8B,0xF1,0x83,0x7E,0x08};
        return check(0x43E520, mouseUp) && check(0x4400C1, selection) &&
               check(0x43E4E0, setter) && check(0x439AB0, updater);
    }
    bool changePatch(Patch& patch, bool install, std::string& error) {
        if (!install && !patch.owned) return true;
        std::array<uint8_t, 2> bytes{};
        if (!read(patch.address, bytes, error)) return false;
        if (install) {
            if (bytes != patch.original || patch.owned) {
                error = "Temporary patch installation did not start from original bytes."; return false;
            }
            patch.owned = true; // Retain cleanup responsibility even for an uncertain write.
        } else {
            if (bytes == patch.original) { patch.owned = false; return true; }
            if (bytes != patch.replacement) {
                error = "An owned patch now contains unknown bytes; cleanup needs review."; return false;
            }
        }
        const auto& desired = install ? patch.replacement : patch.original;
        const auto result = memory_.write(identity_, patch.address, desired.data(), desired.size(), {true});
        if (!result.ok()) {
            if (!result.protectionsRestored || result.code == ds::ProcessMemoryWriteCode::RollbackFailed)
                unresolvedWrite_ = true;
            error = result.error.empty() ? "A checked code write failed." : result.error;
            return false;
        }
        patch.owned = install;
        return true;
    }
    bool restorePatches(std::string& error) {
        // Restore each owned site independently even if a different site is damaged.
        bool ok = true;
        std::string combined;
        for (auto& patch : patches_) {
            std::string part;
            if (!changePatch(patch, false, part)) {
                ok = false;
                if (!combined.empty()) combined += " ";
                combined += part;
            }
        }
        if (!ok) error = combined;
        return ok;
    }
    bool connect(std::string& error) {
        const auto existing = memory_.snapshot();
        if (connected_ && mutexOwned_ && existing.alive &&
            ds::ProcessMemoryIdentityMatches(existing.identity, identity_)) return signatures(error);
        if (!clean()) { error = "The previous session still owns cleanup work."; return false; }
        if (mutexOwned_) { ReleaseMutex(mutex_.value); mutexOwned_ = false; }
        mutex_.reset();
        memory_.close(); identity_ = {}; connected_ = false;
        std::vector<DWORD> candidates;
        Handle processes(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
        if (!processes || !Process32FirstW(processes.value, &entry)) {
            error = winError("Cannot enumerate Peggle processes"); return false;
        }
        do {
            if (_wcsicmp(entry.szExeFile, L"popcapgame1.exe") == 0 &&
                (!requestedPid_ || requestedPid_ == entry.th32ProcessID)) candidates.push_back(entry.th32ProcessID);
        } while (Process32NextW(processes.value, &entry));
        if (GetLastError() != ERROR_NO_MORE_FILES || candidates.size() != 1) {
            error = candidates.empty() ? "The actual game process popcapgame1.exe is not running." :
                "More than one game process is running. Start this controller with --pid NUMBER.";
            return false;
        }
        if (!memory_.open(candidates.front(), {true, false}, &error)) return false;
        const auto snapshot = memory_.snapshot();
        if (!snapshot.alive || !snapshot.canWrite || !snapshot.bitnessKnown || !snapshot.is32 ||
            _stricmp(snapshot.name.c_str(), "popcapgame1.exe") != 0 || snapshot.path.empty()) {
            error = "The writable, 32-bit game process identity could not be verified."; memory_.close(); return false;
        }
        identity_ = snapshot.identity;
        const std::wstring mutexName = L"Local\\DisasmStudio.PeggleCursor." +
            std::to_wstring(identity_.pid) + L"." + std::to_wstring(identity_.creationTime100ns);
        mutex_.reset(CreateMutexW(nullptr, FALSE, mutexName.c_str()));
        if (!mutex_) { error = winError("Cannot create the per-game controller lock"); return false; }
        const DWORD wait = WaitForSingleObject(mutex_.value, 0);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
            error = "Another cursor controller already owns this game session."; return false;
        }
        mutexOwned_ = true;
        Handle modules(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, identity_.pid));
        MODULEENTRY32W module{}; module.dwSize = sizeof(module);
        bool matched = false;
        if (modules && Module32FirstW(modules.value, &module)) {
            do {
                if (_wcsicmp(module.szModule, L"popcapgame1.exe") == 0 &&
                    reinterpret_cast<uintptr_t>(module.modBaseAddr) == 0x400000 &&
                    module.modBaseSize > kAppGlobal - 0x400000 &&
                    _wcsicmp(module.szExePath, wide(snapshot.path).c_str()) == 0) matched = true;
            } while (Module32NextW(modules.value, &module));
        }
        if (!matched) { error = "The exact supported game module/path/base could not be verified."; return false; }
        uint16_t mz = 0;
        if (!read(0x400000, mz, error) || mz != 0x5A4D || !signatures(error)) return false;
        const auto target = wide("PID " + std::to_string(identity_.pid) + " | " + snapshot.path);
        SetWindowTextW(target_, target.c_str());
        connected_ = true;
        return true;
    }
    void arm() {
        if (!clean() || mode_ != Mode::Idle) return;
        closeRequested_ = false;
        std::string error;
        if (!connect(error)) { setStatus("Cannot arm: " + error); return; }
        PauseGuard pause(memory_, identity_, suspended_, error);
        bool ok = pause.begin();
        if (ok) ok = signatures(error) && readScene(scene_, error);
        uint32_t held = 0;
        uint8_t priorFlag = 0;
        if (ok) ok = read(scene_.debug + 4, priorFlag, error) &&
            read(scene_.debug + 8, held, error) && read(scene_.debug + 0xC, originalOffsets_, error);
        if (ok && held != 0) {
            error = "A native mouse ball is already held. Click once in the uncovered playfield to release it, then Arm again."; ok = false;
        }
        if (ok && priorFlag > 1) {
            error = "The native mouse-mode flag is outside its verified boolean range."; ok = false;
        }
        if (ok) {
            // Native MouseUp releases its ball but leaves the input-mode byte set.
            // An explicit Arm with no native-owned ball resets that idle mode.
            // Retain cleanup responsibility BEFORE the checked normalization write;
            // the requested normal-input baseline is zero even after a rollback.
            retained_ = true;
            clearCaptureOwnership();
            originalFlag_ = 0;
            if (priorFlag == 1) ok = write(scene_.debug + 4, originalFlag_, error);
            if (ok) {
                deadline_ = GetTickCount64() + 60000;
                mode_ = Mode::WaitingBall;
            }
        }
        if (!pause.finish()) { fault(error); return; }
        if (!ok) {
            if (retained_) release(false, "Arming stopped: " + error);
            else setStatus("Cannot arm: " + error);
            return;
        }
        setStatus((priorFlag == 1 ? std::string("Cleared the leftover idle mouse mode.\r\n") : std::string{}) +
            "Armed for 60 seconds. Shoot a ball normally.\r\nWhen it is moving, click anywhere in the playfield to attach it.");
    }
    void prepareCapture() {
        std::string error;
        PauseGuard pause(memory_, identity_, suspended_, error);
        const bool paused = pause.begin();
        bool ok = paused;
        bool active = false;
        uint32_t held = 0;
        uint8_t flag = 0;
        if (ok) ok = signatures(error) && currentScene(error) &&
            read(scene_.debug + 8, held, error) && read(scene_.debug + 4, flag, error) &&
            activeBall(scene_, active, error);
        if (ok && (held != 0 || flag != originalFlag_)) {
            error = "The game's native mouse state changed before capture."; ok = false;
        }
        // The ball may disappear between the polling read and this coherent pause.
        if (ok && active) {
            ok = changePatch(patches_[0], true, error) && changePatch(patches_[1], true, error);
            const uint8_t enabled = 1;
            if (ok) {
                nativeCaptureExpected_ = true;
                ok = write(scene_.debug + 4, enabled, error);
            }
            if (ok) mode_ = Mode::WaitingClick;
        }
        if (!ok && paused) {
            const std::string problem = error;
            std::string cleanup;
            if (!restorePatches(cleanup)) error = problem + " Cleanup: " + cleanup;
        }
        if (!pause.finish()) { fault(error); return; }
        if (!ok) { release(false, error); return; }
        if (active) setStatus("Click anywhere in the playfield to attach the moving ball.\r\nThe game's own mouse-ball handler will take ownership.");
    }
    void waitForNextBall() {
        std::string error;
        PauseGuard pause(memory_, identity_, suspended_, error);
        bool ok = pause.begin();
        uint32_t held = 0;
        if (ok) ok = currentScene(error) && read(scene_.debug + 8, held, error);
        if (ok && !held) {
            // Restore shooting immediately if the moving ball drained before a click.
            ok = restorePatches(error) && write(scene_.debug + 4, originalFlag_, error);
            if (ok) { nativeCaptureExpected_ = false; mode_ = Mode::WaitingBall; }
        }
        if (!pause.finish()) { fault(error); return; }
        if (!ok) { release(false, error); return; }
        if (held) finishCapture();
        else setStatus("The ball left play before capture. Shoot another ball, then click again.\r\nNormal shooting and original code are restored while waiting.");
    }
    void finishCapture() {
        std::string error;
        PauseGuard pause(memory_, identity_, suspended_, error);
        bool ok = pause.begin();
        uint32_t ball = 0;
        bool unusedActive = false;
        if (ok) ok = signatures(error) && currentScene(error) &&
            read(scene_.debug + 8, ball, error) && ball != 0 && nativeCaptureExpected_ &&
            capturedBall_ == 0 && validBallState(ball, 1, error) &&
            activeBall(scene_, unusedActive, error, ball);
        if (ok) {
            capturedBall_ = ball;
            const std::array<uint32_t, 2> centered{0, 0};
            const uint8_t disabled = 0;
            ok = write(scene_.debug + 4, disabled, error) &&
                 write(scene_.debug + 0xC, centered, error) &&
                 writeCapturedFlag(0, error);
        }
        if (ok) ok = restorePatches(error);
        if (!pause.finish()) { fault(error); return; }
        if (!ok) { release(false, error); return; }
        mode_ = Mode::Following;
        setStatus("The ball follows the cursor with collisions active.\r\nCapture code patches are restored. Release here, then click once in the game, to let go.");
    }
    void release(bool closing, const std::string& reason = {}) {
        closeRequested_ = closeRequested_ || closing;
        if (clean()) {
            mode_ = Mode::Idle;
            setStatus(reason.empty() ? "Released. Ready to arm again." : reason);
            if (closeRequested_) DestroyWindow(window_);
            return;
        }
        std::string error;
        if (!suspended_.empty() && !resumeThreads(suspended_, error)) { fault(error); return; }
        const auto snapshot = memory_.snapshot();
        if (!snapshot.alive || !ds::ProcessMemoryIdentityMatches(snapshot.identity, identity_)) {
            patches_[0].owned = patches_[1].owned = false;
            retained_ = unresolvedWrite_ = false;
            clearCaptureOwnership();
            mode_ = Mode::Idle;
            setStatus("The game exited; no process changes survive.");
            if (closeRequested_) DestroyWindow(window_);
            return;
        }
        PauseGuard pause(memory_, identity_, suspended_, error);
        bool ok = pause.begin();
        bool needsClick = false;
        bool sceneRetired = false;
        if (ok) ok = restorePatches(error);
        if (ok && retained_) {
            std::string sceneError;
            if (!currentScene(sceneError)) {
                // Never write a recycled board/debug pointer after a scene change.
                uint32_t vt = 0, backlink = 0, ball = 1;
                const bool confirmedNull = read(scene_.board, vt, sceneError) && vt == kBoardVtable &&
                    read(scene_.debug, vt, sceneError) && vt == kDebugVtable &&
                    read(scene_.debug + 0x24, backlink, sceneError) && backlink == scene_.board &&
                    read(scene_.debug + 8, ball, sceneError) && ball == 0;
                if (confirmedNull) {
                    retained_ = false;
                    clearCaptureOwnership();
                    sceneRetired = true;
                }
                else {
                    error = "The scene changed. Code patches are restored, but old ball ownership cannot be confirmed. "
                        "Exit Peggle to retire this session safely; no old scene data will be written.";
                    ok = false;
                }
            } else {
                uint32_t ball = 0;
                ok = read(scene_.debug + 8, ball, error);
                if (ok && ball) {
                    if (capturedBall_ && ball != capturedBall_) {
                        error = "Another ball now owns native mouse capture. Its flag and mouse settings were not changed.";
                        ok = false;
                    } else if (!capturedBall_) {
                        if (!nativeCaptureExpected_ || !validBallState(ball, 1, error)) {
                            error = "Native mouse capture was not acquired by this experiment. Its state was not changed.";
                            ok = false;
                        } else capturedBall_ = ball;
                    }
                    const uint8_t enabled = 1;
                    // Re-establish the native held state before enabling selection:
                    // GetBallAt must skip this ball so the release click lets go.
                    if (ok) ok = signatures(error) && writeCapturedFlag(1, error) &&
                                 write(scene_.debug + 4, enabled, error);
                    needsClick = ok;
                } else if (ok) {
                    // Native MouseUp/SetMouseBall have already released the reference.
                    // It also clears the old ball's stationary byte; that pointer
                    // may now be freed and must not be read or written again.
                    clearCaptureOwnership();
                    ok = write(scene_.debug + 0xC, originalOffsets_, error) &&
                         write(scene_.debug + 4, originalFlag_, error);
                    if (ok) retained_ = false;
                }
            }
        }
        if (!pause.finish()) { fault(error); return; }
        if (!ok) { fault(error); return; }
        if (unresolvedWrite_ && !needsClick) {
            fault("A previous write could not confirm its rollback or original page protections. "
                  "Exit Peggle before closing this controller; cleanup is not being reported as complete.");
            return;
        }
        if (needsClick) {
            mode_ = Mode::Releasing;
            setStatus((reason.empty() ? std::string{} : reason + "\r\n") +
                "Click once in Peggle's playfield to release the ball. Original code is restored. "
                "This controller will stay open until the game releases ownership.");
        } else {
            mode_ = Mode::Idle;
            setStatus((reason.empty() ? std::string{} : reason + "\r\n") +
                (sceneRetired ? "Original code is restored and the old scene has no mouse ball. Old scene data was not written." :
                    "Released. Original code and retained mouse settings are restored."));
            if (closeRequested_) DestroyWindow(window_);
        }
    }

    DWORD requestedPid_ = 0;
    bool autoArm_ = false;
    HWND window_ = nullptr, status_ = nullptr, target_ = nullptr, arm_ = nullptr, release_ = nullptr;
    HFONT font_ = nullptr;
    ds::ProcessMemorySession memory_;
    ds::ProcessMemoryIdentity identity_{};
    Handle mutex_;
    bool mutexOwned_ = false, connected_ = false, unresolvedWrite_ = false;
    std::vector<SuspendedThread> suspended_;
    std::array<Patch, 2> patches_{{
        {0x4400C8, {0x75, 0x08}, {0x66, 0x90}, false},
        {0x43E524, {0x74, 0x0C}, {0xEB, 0x0C}, false}
    }};
    Scene scene_{};
    uint8_t originalFlag_ = 0;
    std::array<uint32_t, 2> originalOffsets_{};
    bool retained_ = false, closeRequested_ = false;
    uint32_t capturedBall_ = 0;
    bool ballFlagOwned_ = false, nativeCaptureExpected_ = false;
    ULONGLONG deadline_ = 0;
    Mode mode_ = Mode::Idle;
};

LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* controller = reinterpret_cast<Controller*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        controller = static_cast<Controller*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(controller));
    }
    try {
        switch (message) {
        case WM_CREATE: controller->create(window); return 0;
        case WM_COMMAND: if (controller) controller->command(LOWORD(wparam)); return 0;
        case WM_TIMER: if (controller && wparam == kTimer) controller->tick(); return 0;
        case WM_CLOSE: if (controller) controller->close(); return 0;
        case WM_QUERYENDSESSION: return !controller || controller->clean();
        case WM_DESTROY: KillTimer(window, kTimer); PostQuitMessage(0); return 0;
        }
    } catch (const std::exception& ex) {
        if (controller) controller->fault(std::string("Controller operation failed: ") + ex.what());
        return 0;
    } catch (...) {
        if (controller) controller->fault("Controller operation failed unexpectedly.");
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    DWORD requestedPid = 0;
    bool autoArm = false;
    bool validArgs = argv != nullptr;
    for (int i = 1; validArgs && i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--arm") == 0 && !autoArm) {
            autoArm = true;
        } else if (std::wcscmp(argv[i], L"--pid") == 0 && !requestedPid && i + 1 < argc) {
            wchar_t* end = nullptr;
            const wchar_t* value = argv[++i];
            const unsigned long long parsed = std::wcstoull(value, &end, 10);
            validArgs = end && *end == 0 && end != value && parsed > 0 &&
                        parsed <= std::numeric_limits<DWORD>::max();
            if (validArgs) requestedPid = static_cast<DWORD>(parsed);
        } else validArgs = false;
    }
    if (argv) LocalFree(argv);
    if (!validArgs) {
        MessageBoxW(nullptr, L"Usage: PeggleCursor.exe [--pid NUMBER] [--arm]", L"Peggle cursor", MB_OK | MB_ICONERROR);
        return 2;
    }
    SetProcessDPIAware();
    HDC screen = GetDC(nullptr);
    if (screen) { systemDpi = GetDeviceCaps(screen, LOGPIXELSY); ReleaseDC(nullptr, screen); }
    Controller controller(requestedPid, autoArm);
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = windowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = L"DisasmStudio.PeggleCursor";
    if (!RegisterClassW(&windowClass)) return 1;
    RECT bounds{0, 0, pixels(520), pixels(364)};
    const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    AdjustWindowRect(&bounds, style, FALSE);
    HWND window = CreateWindowExW(0, windowClass.lpszClassName, L"Peggle cursor experiment", style,
        CW_USEDEFAULT, CW_USEDEFAULT, bounds.right - bounds.left, bounds.bottom - bounds.top,
        nullptr, nullptr, instance, &controller);
    if (!window) return 1;
    ShowWindow(window, show);
    UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    return static_cast<int>(message.wParam);
}
