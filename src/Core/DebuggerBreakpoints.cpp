#include "Debugger.h"
#include "DebuggerInternal.h"
#include "NetworkApiCatalog.h"
#include "DbgHelpLock.h"
#include "StepLogic.h"
#include "DebuggerExecutionPolicy.h"
#include "../Disasm/IDisassembler.h"
#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <limits>

namespace ds {
bool Debugger::addBreakpoint(uint64_t va, const std::string& condition) {
    if (!ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        if (gameMakerOwnsRangeLocked(va,1)) return false;
        // The debug thread drains command kinds separately. Coalesce this
        // address while still queued so remove/re-add preserves the last intent.
        // Keep adds/removals sorted: large ascending listing selections append
        // after logarithmic lookup instead of scanning every prior request.
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal != pendingBpRems_.end() && *removal == va) pendingBpRems_.erase(removal);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) addition->cond = condition;
        else pendingBpAdds_.insert(addition, { va, condition });
        clearBreakpointInstallFailureLocked(va); // a fresh request is queued, not the old failure
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::addBreakpointForSession(DebugTargetIdentity expected, uint64_t va,
                                       const std::string& condition) {
    if (!expected.valid() || !ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || (state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        if (gameMakerOwnsRangeLocked(va,1)) return false;
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal != pendingBpRems_.end() && *removal == va) pendingBpRems_.erase(removal);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) addition->cond = condition;
        else pendingBpAdds_.insert(addition, { va, condition });
        clearBreakpointInstallFailureLocked(va);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::removeBreakpoint(uint64_t va) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) pendingBpAdds_.erase(addition);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        std::erase_if(pendingBpEveryN_, [va](const auto& pending) { return pending.first == va; });
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal == pendingBpRems_.end() || *removal != va) pendingBpRems_.insert(removal, va);
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::removeBreakpointForSession(DebugTargetIdentity expected, uint64_t va) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || (state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) pendingBpAdds_.erase(addition);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        std::erase_if(pendingBpEveryN_, [va](const auto& pending) { return pending.first == va; });
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal == pendingBpRems_.end() || *removal != va) pendingBpRems_.insert(removal, va);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::hasBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    return bps_.count(va) != 0;
}
bool Debugger::setBreakpointCondition(uint64_t va, const std::string& condition) {
    if (!ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        pendingBpConds_.push_back({ va, condition });
    }
    requestTraceSyncBreak();
    return true;
}

bool Debugger::setBreakpointConditionForSession(DebugTargetIdentity expected,
                                                uint64_t va,
                                                const std::string& condition) {
    if (!expected.valid() || !ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || (state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        pendingBpConds_.push_back({ va, condition });
    }
    requestTraceSyncBreak(expected);
    return true;
}

void Debugger::setBreakpointEveryN(uint64_t va, uint32_t n) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || state_ == DbgState::Detached || state_ == DbgState::Terminated) return;
        pendingBpEveryN_.push_back({ va, n });
    }
    requestTraceSyncBreak();
}

bool Debugger::setBreakpointEveryNForSession(DebugTargetIdentity expected,
                                             uint64_t va, uint32_t n) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || (state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        pendingBpEveryN_.push_back({ va, n });
    }
    requestTraceSyncBreak(expected);
    return true;
}

bool Debugger::addHardwareBreakpoint(uint64_t va, HwKind kind, uint8_t size) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        if (!debugger_detail::ValidHardwareBreakpoint(va, kind == HwKind::Execute, size, isWow64_.load()))
            return false;
        if (kind == HwKind::Execute) size = 1;
        if (gameMakerOwnsRangeLocked(va,kind==HwKind::Execute ? 1 : size)) return false;
        // A remove followed by an add at the same address is a type/size
        // replacement. The debug thread applies removals before additions, so do
        // not mistake the soon-to-be-freed slot for an already-satisfied add.
        const bool replacing = std::find(pendingHwRems_.begin(), pendingHwRems_.end(), va) !=
                               pendingHwRems_.end();
        for (auto& pending : pendingHwAdds_) {
            if (pending.addr != va) continue;
            pending.kind = kind;
            pending.size = size;
            return true;
        }
        int inUse = 0;
        for (auto& s : hwSlots_) {
            if (!s.used) continue;
            if (s.addr == va) {
                if (!replacing) return true;
                continue;
            }
            ++inUse;
        }
        inUse += (int)pendingHwAdds_.size();
        if (inUse >= 4) return false;
        HwSlot s; s.used = true; s.addr = va; s.kind = kind; s.size = size;
        pendingHwAdds_.push_back(s);
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::addHardwareBreakpointForSession(DebugTargetIdentity expected,
                                               uint64_t va, HwKind kind,
                                               uint8_t size) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || (state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        if (!debugger_detail::ValidHardwareBreakpoint(va, kind == HwKind::Execute, size, isWow64_.load()))
            return false;
        if (kind == HwKind::Execute) size = 1;
        if (gameMakerOwnsRangeLocked(va,kind==HwKind::Execute ? 1 : size)) return false;
        const bool replacing = std::find(pendingHwRems_.begin(), pendingHwRems_.end(), va) !=
                               pendingHwRems_.end();
        for (auto& pending : pendingHwAdds_) {
            if (pending.addr != va) continue;
            pending.kind = kind;
            pending.size = size;
            return true;
        }
        int inUse = 0;
        for (auto& s : hwSlots_) {
            if (!s.used) continue;
            if (s.addr == va) {
                if (!replacing) return true;
                continue;
            }
            ++inUse;
        }
        inUse += (int)pendingHwAdds_.size();
        if (inUse >= 4) return false;
        HwSlot s; s.used = true; s.addr = va; s.kind = kind; s.size = size;
        pendingHwAdds_.push_back(s);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::removeHardwareBreakpoint(uint64_t va) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        std::erase_if(pendingHwAdds_, [va](const HwSlot& pending) { return pending.addr == va; });
        if (std::find(pendingHwRems_.begin(), pendingHwRems_.end(), va) == pendingHwRems_.end())
            pendingHwRems_.push_back(va);
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::removeHardwareBreakpointForSession(DebugTargetIdentity expected,
                                                  uint64_t va) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_ || (state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        std::erase_if(pendingHwAdds_, [va](const HwSlot& pending) { return pending.addr == va; });
        if (std::find(pendingHwRems_.begin(), pendingHwRems_.end(), va) == pendingHwRems_.end())
            pendingHwRems_.push_back(va);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::hasHardwareBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& s : hwSlots_) if (s.used && s.addr == va) return true;
    return false;
}

void Debugger::clearBreakpointInstallFailureLocked(uint64_t va) {
    std::erase_if(failedBpInstalls_, [va](const SwBreakpointInfo& failed) {
        return failed.address == va;
    });
}

bool Debugger::armBreakpoint(uint64_t va) {
    uint8_t orig = 0;
    bool ownsByte = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (gameMakerOwnsRangeLocked(va,1)) return false;
        auto it = bps_.find(va);
        if (it == bps_.end()) return false;
        orig = it->second.orig;
        ownsByte = it->second.ownsByte;
        if (!ownsByte) {
            it->second.armed = true;
            it->second.error.clear();
            return true;
        }
    }
    const bool ok = orig != 0xCC &&
        replaceByteIfEqual((HANDLE)hProcess_, va, orig, 0xCC);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = bps_.find(va); it != bps_.end()) {
            it->second.armed = ok;
            it->second.error = ok ? std::string{} : "could not re-arm owned breakpoint byte";
        }
    }
    return ok;
}
bool Debugger::disarmBreakpoint(uint64_t va) {
    uint8_t orig = 0;
    bool ownsByte = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = bps_.find(va);
        if (it == bps_.end()) return false;
        orig = it->second.orig;
        ownsByte = it->second.ownsByte;
        if (!ownsByte) return true; // the shared anti-debug hook mediates the byte
    }
    uint8_t current = 0;
    const bool ok = readByteRPM((HANDLE)hProcess_, va, current) &&
        (current == orig || replaceByteIfEqual((HANDLE)hProcess_, va, 0xCC, orig));
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = bps_.find(va); it != bps_.end()) {
            it->second.armed = false;
            it->second.error = ok ? std::string{} : "could not restore owned breakpoint byte";
        }
    }
    return ok;
}

bool Debugger::disarmAuthorizationBreakpoint(uint64_t va) {
    AuthorizationBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationBps_.find(va);
        if (it == authorizationBps_.end()) return false;
        site = it->second;
        it->second.armed = false;
        if (auto completion = authorizationReturnBps_.find(va);
            completion != authorizationReturnBps_.end())
            completion->second.armed = false;
    }
    return !site.ownsByte ||
           replaceByteIfEqual((HANDLE)hProcess_, va, 0xCC, site.orig);
}

bool Debugger::rearmAuthorizationBreakpoint(uint64_t va) {
    AuthorizationBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationBps_.find(va);
        if (it == authorizationBps_.end()) return false;
        site = it->second;
    }
    const bool ok = !site.ownsByte ||
                    replaceByteIfEqual((HANDLE)hProcess_, va, site.orig, 0xCC);
    if (ok) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = authorizationBps_.find(va); it != authorizationBps_.end())
            it->second.armed = true;
        if (auto it = authorizationReturnBps_.find(va);
            it != authorizationReturnBps_.end())
            it->second.armed = true;
    }
    return ok;
}

bool Debugger::disarmAuthorizationReturn(uint64_t va) {
    AuthorizationReturnBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationReturnBps_.find(va);
        if (it == authorizationReturnBps_.end()) return false;
        site = it->second;
        it->second.armed = false;
    }
    return !site.ownsByte ||
           replaceByteIfEqual((HANDLE)hProcess_, va, 0xCC, site.orig);
}

bool Debugger::rearmAuthorizationReturn(uint64_t va) {
    AuthorizationReturnBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationReturnBps_.find(va);
        if (it == authorizationReturnBps_.end()) return false;
        site = it->second;
    }
    const bool ok = !site.ownsByte ||
                    replaceByteIfEqual((HANDLE)hProcess_, va, site.orig, 0xCC);
    if (ok) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = authorizationReturnBps_.find(va);
            it != authorizationReturnBps_.end())
            it->second.armed = true;
    }
    return ok;
}

// Rebuild the UI-visible thread list (debug thread; debuggee is stopped here).
bool Debugger::evalConditionFor(uint64_t addr, uint32_t tid) {
    // Use the condition compiled once when the breakpoint was set/changed, instead
    // of re-parsing the string on every hit. An empty (unconditional) program is
    // {valid,empty} -> always true.
    CondProgram prog;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = bps_.find(addr); if (it != bps_.end()) prog = it->second.prog; }
    // Invalid programs are never supposed to enter bps_ (the public command
    // boundary rejects them). Fail closed here as defense in depth: malformed
    // legacy/corrupt state must not become an unconditional breakpoint.
    if (!prog.valid) return false;
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
        else if (n == "rflags" || n == "eflags") out = rg.rflags;
        else if (n == "r8")  out = rg.r8;  else if (n == "r9")  out = rg.r9;
        else if (n == "r10") out = rg.r10; else if (n == "r11") out = rg.r11;
        else if (n == "r12") out = rg.r12; else if (n == "r13") out = rg.r13;
        else if (n == "r14") out = rg.r14; else if (n == "r15") out = rg.r15;
        else return false;
        return true;
    };
    // Read pointer-width: a 32-bit (WOW64) target's [addr] must not pull 4 adjacent bytes into the high dword.
    cc.mem = [this](uint64_t a) -> uint64_t { uint64_t v = 0; readMemory(a, &v, isWow64_.load() ? 4 : 8); return v; };
    return EvalCompiled(prog, cc, /*onError*/ false);  // unknown runtime state fails closed
}


void Debugger::applyPendingHardwareBreakpoints() {
    std::vector<HwSlot> additions;
    std::vector<uint64_t> removals;
    HwSlot before[4];
    bool changed = false;
    {
        std::lock_guard lock(mtx_);
        additions.swap(pendingHwAdds_);
        removals.swap(pendingHwRems_);
        std::copy(std::begin(hwSlots_), std::end(hwSlots_), std::begin(before));
        for (uint64_t address : removals)
            for (auto& slot : hwSlots_)
                if (slot.used && slot.addr == address) { slot = {}; changed = true; }
        for (const auto& addition : additions) {
            if (!debugger_detail::ValidHardwareBreakpoint(addition.addr,
                    addition.kind == HwKind::Execute, addition.size, isWow64_.load()) ||
                gameMakerOwnsRangeLocked(addition.addr, addition.size)) continue;
            const auto existing = std::find_if(std::begin(hwSlots_), std::end(hwSlots_),
                [&](const auto& slot) { return slot.used && slot.addr == addition.addr; });
            if (existing != std::end(hwSlots_)) continue;
            const auto free = std::find_if(std::begin(hwSlots_), std::end(hwSlots_),
                [](const auto& slot) { return !slot.used; });
            if (free != std::end(hwSlots_)) { *free = addition; changed = true; }
        }
    }
    if (changed && !applyHwAllThreads()) {
        { std::lock_guard lock(mtx_);
          std::copy(std::begin(before), std::end(before), std::begin(hwSlots_)); }
        recordExecutionFailure("hardware breakpoint transaction failed; previous slots retained and target remains paused");
    }
}

} // namespace ds
