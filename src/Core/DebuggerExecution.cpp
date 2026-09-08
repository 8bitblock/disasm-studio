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
namespace {
bool nativeThreadHasExited(void* raw) {
    const HANDLE handle = static_cast<HANDLE>(raw);
    if (!handle) return false;
    if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0) return true;
    DWORD status = STILL_ACTIVE;
    return GetExitCodeThread(handle, &status) && status != STILL_ACTIVE;
}
}

static constexpr uint32_t TRAP_FLAG = 0x100;
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

bool Debugger::ctxSetRip(void* hThread, uint64_t rip) {
    uint32_t ownerTid = 0;
    for (const auto& [tid, handle] : threads_) if (handle == hThread) { ownerTid = tid; break; }
    if (ownerTid) {
        std::lock_guard lock(mtx_);
        pendingInstructionRewinds_[ownerTid] = {hThread, rip}; // allocate before native mutation
    }
    const auto fail = [&]() {
        recordExecutionFailure("instruction-pointer rewind could not be verified; target remains paused and rewind is retained");
        return false;
    };
    if (isWow64_.load()) {
        if (rip > UINT32_MAX) return fail();
        WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!Wow64GetThreadContext((HANDLE)hThread, &context)) return fail();
        context.Eip = static_cast<DWORD>(rip);
        if (!Wow64SetThreadContext((HANDLE)hThread, &context)) return fail();
        WOW64_CONTEXT verify{}; verify.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!Wow64GetThreadContext((HANDLE)hThread, &verify) || verify.Eip != rip) return fail();
    } else {
        CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext((HANDLE)hThread, &context)) return fail();
        context.Rip = rip;
        if (!SetThreadContext((HANDLE)hThread, &context)) return fail();
        CONTEXT verify{}; verify.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext((HANDLE)hThread, &verify) || verify.Rip != rip) return fail();
    }
    if (ownerTid) { std::lock_guard lock(mtx_); pendingInstructionRewinds_.erase(ownerTid); }
    return true;
}

bool Debugger::retryPendingInstructionRewinds() {
    std::vector<std::pair<uint32_t, InstructionRewind>> pending;
    { std::lock_guard lock(mtx_);
      pending.assign(pendingInstructionRewinds_.begin(), pendingInstructionRewinds_.end()); }
    bool complete = true;
    for (const auto& [tid, rewind] : pending) {
        const auto owner = threads_.find(tid);
        if (owner == threads_.end() || owner->second != rewind.thread || nativeThreadHasExited(rewind.thread)) {
            // An exited thread's old handle/address grants no authority over a
            // replacement thread or a recycled native handle.
            std::lock_guard lock(mtx_);
            pendingInstructionRewinds_.erase(tid);
            continue;
        }
        complete = ctxSetRip(rewind.thread, rewind.address) && complete;
    }
    return complete;
}

void Debugger::recordExecutionFailure(std::string error) {
    if (executionFailure_.empty()) executionFailure_ = std::move(error);
    std::lock_guard lock(mtx_);
    mutationError_ = executionFailure_;
    lastEvent_ = executionFailure_;
    ++mutationErrorRevision_;
    // The queued command was authorized before this failure was visible. It
    // must not silently become permission to resume a failed mutation. Detach
    // keeps its lifecycle priority; a new explicit command can retry afterward.
    if (pendingCommand_.command != Cmd::None && pendingCommand_.command != Cmd::Detach) {
        if (pendingCommand_.checkedRunToToken &&
            checkedRunTo_.requestToken == pendingCommand_.checkedRunToToken &&
            checkedRunTo_.state == CheckedRunToState::Pending)
            transitionCheckedRunToLocked(CheckedRunToState::Failed, executionFailure_);
        pendingCommand_ = {};
    }
}

bool Debugger::updateControlFlag(uint32_t tid, uint32_t mask, bool on, const char* operation) {
    const auto thread = threads_.find(tid);
    if (thread == threads_.end()) {
        recordExecutionFailure(std::string(operation) + ": thread no longer exists; target remains paused");
        return false;
    }
    const HANDLE handle = static_cast<HANDLE>(thread->second);
    if (nativeThreadHasExited(thread->second)) {
        pendingControlFlagRepairs_.erase((uint64_t{tid} << 32) | mask);
        return true;
    }
    const bool wow64 = isWow64_.load();
    const auto read = [&](uint32_t& flags) {
        if (wow64) {
            WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (!Wow64GetThreadContext(handle, &context)) return false;
            flags = context.EFlags;
        } else {
            CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
            if (!GetThreadContext(handle, &context)) return false;
            flags = context.EFlags;
        }
        return true;
    };
    const auto write = [&](uint32_t flags) {
        if (wow64) {
            WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (!Wow64GetThreadContext(handle, &context)) return false;
            context.EFlags = flags;
            return Wow64SetThreadContext(handle, &context) != FALSE;
        }
        CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(handle, &context)) return false;
        context.EFlags = flags;
        return SetThreadContext(handle, &context) != FALSE;
    };
    const uint64_t repairKey = (uint64_t{tid} << 32) | mask;
    // Publish an exact-handle repair record before any native write. Allocation
    // failure cannot strand an unrecorded TF/RF mutation on an unselected thread.
    pendingControlFlagRepairs_[repairKey] = {thread->second, tid, mask, on};
    const auto result = debugger_detail::UpdateControlBits(mask, on, read, write);
    if (result == debugger_detail::ControlMutationResult::Applied) {
        pendingControlFlagRepairs_.erase(repairKey);
        return true;
    }
    if (nativeThreadHasExited(thread->second)) {
        pendingControlFlagRepairs_.erase(repairKey);
        return true;
    }
    const char* reason = result == debugger_detail::ControlMutationResult::ReadFailed ? "context read failed"
        : result == debugger_detail::ControlMutationResult::WriteFailed ? "context write failed (restored)"
        : result == debugger_detail::ControlMutationResult::VerifyFailed ? "context verification failed (restored)"
        : "context mutation and rollback could not be verified";
    recordExecutionFailure(std::string(operation) + ": " + reason + "; target remains paused");
    return false;
}

bool Debugger::retryPendingControlFlags() {
    std::vector<ControlFlagRepair> repairs;
    repairs.reserve(pendingControlFlagRepairs_.size());
    for (const auto& [key, repair] : pendingControlFlagRepairs_) repairs.push_back(repair);
    bool complete = true;
    for (const auto& repair : repairs) {
        const auto owner = threads_.find(repair.tid);
        if (owner == threads_.end() || owner->second != repair.thread ||
            nativeThreadHasExited(repair.thread)) {
            pendingControlFlagRepairs_.erase((uint64_t{repair.tid} << 32) | repair.mask);
            continue;
        }
        complete = updateControlFlag(repair.tid, repair.mask, repair.on,
            "repair retained control flags") && complete;
    }
    return complete;
}

bool Debugger::setTrapFlag(uint32_t tid, bool on) {
    return updateControlFlag(tid, TRAP_FLAG, on, on ? "enable single step" : "disable single step");
}

bool Debugger::setResumeFlag(uint32_t tid) {
    return updateControlFlag(tid, 0x10000, true, "resume hardware execution breakpoint");
}

// Program DR0-DR3 + DR7 on one thread from the current hwSlots_ table.
bool Debugger::applyHwToThread(void* hThread) {
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
    if (!GetThreadContext((HANDLE)hThread, &ctx)) return false;
    ctx.Dr0 = addrs[0]; ctx.Dr1 = addrs[1]; ctx.Dr2 = addrs[2]; ctx.Dr3 = addrs[3];
    ctx.Dr7 = dr7;
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext((HANDLE)hThread, &ctx)) return false;
    CONTEXT verify{}; verify.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return GetThreadContext((HANDLE)hThread, &verify) && verify.Dr0 == addrs[0] &&
        verify.Dr1 == addrs[1] && verify.Dr2 == addrs[2] && verify.Dr3 == addrs[3] &&
        (verify.Dr7 & 0xffff00ff) == (dr7 & 0xffff00ff);
}

bool Debugger::applyHwAllThreads() {
    // Capture every thread before writing any of them. A partial installation
    // must roll back the exact native DR state, including pre-existing slots.
    std::vector<std::pair<HANDLE, CONTEXT>> before;
    before.reserve(threads_.size());
    for (const auto& [tid, raw] : threads_) {
        (void)tid;
        if (nativeThreadHasExited(raw)) continue;
        CONTEXT context{}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext((HANDLE)raw, &context)) {
            if (nativeThreadHasExited(raw)) continue;
            return false;
        }
        before.emplace_back((HANDLE)raw, context);
    }
    for (size_t index = 0; index < before.size(); ++index) {
        if (applyHwToThread(before[index].first)) continue;
        bool restored = true;
        for (size_t rollback = 0; rollback <= index; ++rollback) {
            auto& [handle, context] = before[rollback];
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!SetThreadContext(handle, &context)) { restored = false; continue; }
            CONTEXT verify{}; verify.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(handle, &verify) || verify.Dr0 != context.Dr0 ||
                verify.Dr1 != context.Dr1 || verify.Dr2 != context.Dr2 ||
                verify.Dr3 != context.Dr3 || (verify.Dr7 & 0xffff00ff) != (context.Dr7 & 0xffff00ff))
                restored = false;
        }
        if (!restored) {
            hardwareReconciliationRequired_ = true;
            recordExecutionFailure("hardware breakpoint rollback could not be verified; target remains paused");
        }
        return false;
    }
    hardwareReconciliationRequired_ = false;
    return true;
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
    if (ctx.Dr6 & 0xF) {
        ctx.Dr6 = 0;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!SetThreadContext((HANDLE)it->second, &ctx)) return false;
    }
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
    size_t n = readMemoryMasked(va, buf, sizeof(buf));
    if (!n) return d;
    Instruction in;
    if (dis->decodeOne(buf, n, va, in) && in.length && in.length <= n && in.length <= 15) {
        d.valid       = true;
        d.length      = in.length;
        d.isCall      = in.isCall;
        d.isRet       = in.isRet;
        d.isRepString = in.isRepString;
    }
    return d;
}


} // namespace ds
