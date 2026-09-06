#include "AntiDebug.h"

#include <algorithm>
#include <limits>

namespace ds {

namespace {
constexpr uint32_t kStatusSuccess = 0x00000000u;
constexpr uint32_t kStatusInvalidHandle = 0xC0000008u;
constexpr uint32_t kStatusPortNotSet = 0xC0000353u;

uint64_t saturatingAdd(uint64_t a, uint64_t b) {
    if (b > std::numeric_limits<uint64_t>::max() - a)
        return std::numeric_limits<uint64_t>::max();
    return a + b;
}

} // namespace

bool AntiDebugPolicy::enabled() const {
    return normalizePeb || normalizeProcessHeap || hideProcessDebugQueries ||
           hideKernelDebuggerQuery || acceptThreadHideRequests ||
           neutralizeInvalidHandleClose || maskDebugRegisters || syntheticClock ||
           rdtsc != RdtscInterception::Off;
}

bool AntiDebugPolicy::requiresNtdllHooks() const {
    return hideProcessDebugQueries || hideKernelDebuggerQuery ||
           acceptThreadHideRequests || neutralizeInvalidHandleClose ||
           maskDebugRegisters || syntheticClock;
}

AntiDebugDecision DecideAntiDebugCall(const AntiDebugPolicy& p,
                                      AntiDebugCall call,
                                      uint32_t infoClass,
                                      size_t outputLength,
                                      bool invalidHandle,
                                      size_t pointerSize,
                                      bool sameTargetHandle,
                                      bool informationBufferPresent) {
    AntiDebugDecision d;
    pointerSize = pointerSize == 4 ? 4 : 8;
    switch (call) {
        case AntiDebugCall::NtQueryInformationProcess:
            if (!p.hideProcessDebugQueries || !sameTargetHandle || !informationBufferPresent) break;
            if (infoClass == 7 && outputLength == pointerSize) { // ProcessDebugPort
                d = { true, kStatusSuccess, AntiDebugOutput::ZeroPointer, pointerSize,
                      "ProcessDebugPort concealed" };
            } else if (infoClass == 30 && outputLength == pointerSize) { // ProcessDebugObjectHandle
                d = { true, kStatusPortNotSet, AntiDebugOutput::ZeroPointer, pointerSize,
                      "ProcessDebugObjectHandle concealed" };
            } else if (infoClass == 31 && outputLength == 4) { // ProcessDebugFlags
                d = { true, kStatusSuccess, AntiDebugOutput::OneU32, 4,
                      "ProcessDebugFlags reports no debugger" };
            }
            break;
        case AntiDebugCall::NtQuerySystemInformation:
            if (p.hideKernelDebuggerQuery && infoClass == 35 && outputLength == 2 &&
                informationBufferPresent) {
                d = { true, kStatusSuccess, AntiDebugOutput::KernelDebuggerInfo, 2,
                      "kernel debugger reported absent" };
            }
            break;
        case AntiDebugCall::NtQueryInformationThread:
            if (p.acceptThreadHideRequests && sameTargetHandle && infoClass == 17 &&
                outputLength == 1 && informationBufferPresent) {
                d = { true, kStatusSuccess, AntiDebugOutput::FalseByte, 1,
                      "ThreadHideFromDebugger reported clear" };
            }
            break;
        case AntiDebugCall::NtSetInformationThread:
            if (p.acceptThreadHideRequests && sameTargetHandle && infoClass == 17 &&
                outputLength == 0 && !informationBufferPresent) {
                d = { true, kStatusSuccess, AntiDebugOutput::None, 0,
                      "ThreadHideFromDebugger accepted without hiding events" };
            }
            break;
        case AntiDebugCall::NtClose:
            if (p.neutralizeInvalidHandleClose && invalidHandle) {
                d = { true, kStatusInvalidHandle, AntiDebugOutput::None, 0,
                      "invalid NtClose returned status without debugger exception" };
            }
            break;
        case AntiDebugCall::NtGetContextThread:
        case AntiDebugCall::NtSetContextThread:
            if (p.maskDebugRegisters && sameTargetHandle) {
                d = { true, kStatusSuccess, AntiDebugOutput::None, 0,
                      "thread context mediated with owned DR state hidden" };
            }
            break;
        case AntiDebugCall::NtQueryPerformanceCounter:
        case AntiDebugCall::NtQuerySystemTime:
            if (p.syntheticClock) {
                d = { true, kStatusSuccess, AntiDebugOutput::None, 0,
                      "synthetic monotonic clock" };
            }
            break;
    }
    return d;
}

size_t AntiDebugX86StackArgumentBytes(AntiDebugCall call) {
    switch (call) {
        case AntiDebugCall::NtQueryInformationProcess:
        case AntiDebugCall::NtQueryInformationThread:
            return 20;
        case AntiDebugCall::NtQuerySystemInformation:
        case AntiDebugCall::NtSetInformationThread:
            return 16;
        case AntiDebugCall::NtGetContextThread:
        case AntiDebugCall::NtSetContextThread:
        case AntiDebugCall::NtQueryPerformanceCounter:
            return 8;
        case AntiDebugCall::NtClose:
        case AntiDebugCall::NtQuerySystemTime:
            return 4;
    }
    return 0;
}

uint32_t NormalizeNtGlobalFlag(uint32_t value) {
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
    // FLG_HEAP_VALIDATE_PARAMETERS
    return value & ~uint32_t{0x70};
}

uint32_t NormalizeHeapFlags(uint32_t value) {
    // Keep all application heap policy, remove only the three debugger-induced
    // validation bits, and preserve/force HEAP_GROWABLE as ordinary process heaps do.
    constexpr uint32_t kDebugHeapBits = 0x40000060u;
    constexpr uint32_t kHeapGrowable = 0x00000002u;
    return (value & ~kDebugHeapBits) | kHeapGrowable;
}

uint32_t NormalizeHeapForceFlags(uint32_t value) {
    // ForceFlags is a policy mask, not a boolean. Preserve target-selected heap
    // behavior and remove only the debugger-induced validation bits.
    constexpr uint32_t kDebugHeapBits = 0x40000060u;
    return value & ~kDebugHeapBits;
}

bool PristinePatchSet::remember(uint64_t address,
                                const std::vector<uint8_t>& original,
                                const std::vector<uint8_t>& concealed,
                                std::string_view label) noexcept {
    constexpr size_t kPatchCap = 64;
    if (!address || original.empty() || original.size() != concealed.size()) return false;
    if (find(address) || patches_.size() >= kPatchCap) return false;
    try {
        patches_.push_back({ address, original, concealed, std::string(label) });
        return true;
    } catch (...) {
        return false;
    }
}

bool PristinePatchSet::forget(uint64_t address) noexcept {
    auto it = std::find_if(patches_.begin(), patches_.end(),
                           [address](const PristineMemoryPatch& patch) {
                               return patch.address == address;
                           });
    if (it == patches_.end()) return false;
    patches_.erase(it);
    return true;
}

const PristineMemoryPatch* PristinePatchSet::find(uint64_t address) const {
    auto it = std::find_if(patches_.begin(), patches_.end(),
                           [address](const PristineMemoryPatch& p) { return p.address == address; });
    return it == patches_.end() ? nullptr : &*it;
}

bool PristinePatchSet::shouldRestore(const PristineMemoryPatch& patch,
                                     const std::vector<uint8_t>& current) {
    // Do not overwrite a value the target legitimately changed after concealment.
    return current == patch.concealed;
}

DebugRegisterState MaskDebugRegisters(const DebugRegisterState& /*in*/) {
    return {};
}

bool CanMediateSetContext(bool targetsCurrentEventThread, uint32_t contextFlags) {
    // The low 16 bits are CONTEXT group selections on both i386 and AMD64;
    // 0x10 is CONTEXT_DEBUG_REGISTERS. Synthesizing the function return writes
    // the event thread's control/integer state, so only debug-only self updates
    // can be mediated without undoing requested non-DR groups.
    constexpr uint32_t kDebugRegistersGroup = 0x10u;
    const uint32_t groups = contextFlags & 0xFFFFu;
    return !targetsCurrentEventThread || (groups & ~kDebugRegistersGroup) == 0;
}

bool AntiDebugTrapRangeValid(uint64_t ownerImageBase, uint64_t ownerImageSize,
                             uint64_t address, size_t instructionLength) {
    if (!ownerImageBase || !ownerImageSize || !instructionLength ||
        ownerImageSize > std::numeric_limits<uint64_t>::max() - ownerImageBase)
        return false;
    const uint64_t ownerEnd = ownerImageBase + ownerImageSize;
    if (address < ownerImageBase || address >= ownerEnd ||
        instructionLength > std::numeric_limits<uint64_t>::max() - address)
        return false;
    return address + instructionLength <= ownerEnd;
}

bool AntiDebugRearmState::begin(uint32_t tid, uint64_t address,
                                uint64_t ownerImageBase) noexcept {
    constexpr size_t kPendingThreadCap = 4096;
    if (!tid || !address || find(tid) || pending_.size() >= kPendingThreadCap) return false;
    try {
        pending_.push_back({ tid, address, ownerImageBase });
        return true;
    } catch (...) {
        return false;
    }
}

const PendingAntiDebugRearm* AntiDebugRearmState::find(uint32_t tid) const noexcept {
    auto it = std::find_if(pending_.begin(), pending_.end(),
                           [tid](const PendingAntiDebugRearm& pending) {
                               return pending.tid == tid;
                           });
    return it == pending_.end() ? nullptr : &*it;
}

bool AntiDebugRearmState::hasAddress(uint64_t address) const noexcept {
    return std::any_of(pending_.begin(), pending_.end(),
                       [address](const PendingAntiDebugRearm& pending) {
                           return pending.address == address;
                       });
}

std::optional<PendingAntiDebugRearm> AntiDebugRearmState::take(uint32_t tid) noexcept {
    auto it = std::find_if(pending_.begin(), pending_.end(),
                           [tid](const PendingAntiDebugRearm& pending) {
                               return pending.tid == tid;
                           });
    if (it == pending_.end()) return std::nullopt;
    PendingAntiDebugRearm result = *it;
    pending_.erase(it);
    return result;
}

std::optional<PendingAntiDebugRearm> AntiDebugRearmState::takeOwner(
    uint64_t ownerImageBase) noexcept {
    if (!ownerImageBase) return std::nullopt;
    auto it = std::find_if(pending_.begin(), pending_.end(),
                           [ownerImageBase](const PendingAntiDebugRearm& pending) {
                               return pending.ownerImageBase == ownerImageBase;
                           });
    if (it == pending_.end()) return std::nullopt;
    PendingAntiDebugRearm result = *it;
    pending_.erase(it);
    return result;
}

std::optional<PendingAntiDebugRearm> AntiDebugRearmState::takeAny() noexcept {
    if (pending_.empty()) return std::nullopt;
    PendingAntiDebugRearm result = pending_.back();
    pending_.pop_back();
    return result;
}

SyntheticClock::SyntheticClock(SyntheticClockConfig config) { reset(config); }

void SyntheticClock::reset(SyntheticClockConfig config) {
    if (!config.qpcFrequency) config.qpcFrequency = 10'000'000;
    if (!config.qpcQuantum) config.qpcQuantum = 1;
    if (!config.tscQuantum) config.tscQuantum = 1;
    config_ = config;
    elapsedQpcTicks_ = 0;
}

void SyntheticClock::advanceRunningQpcTicks(uint64_t ticks) {
    elapsedQpcTicks_ = saturatingAdd(elapsedQpcTicks_, ticks);
}

void SyntheticClock::advanceQueryQuantum() {
    elapsedQpcTicks_ = saturatingAdd(elapsedQpcTicks_, config_.qpcQuantum);
}

uint64_t SyntheticClock::nextQpc() {
    const uint64_t result = saturatingAdd(config_.qpcStart, elapsedQpcTicks_);
    advanceQueryQuantum();
    return result;
}

uint64_t SyntheticClock::nextSystemTime100ns() {
    // All time sources sample one shared virtual elapsed timeline. Thus an RDTSC
    // query advances subsequent QPC/system-time results rather than maintaining
    // three independently detectable counters.
    const uint64_t elapsed = elapsedQpcTicks_;
    uint64_t delta100ns = 0;
    if (config_.qpcFrequency) {
        const uint64_t whole = elapsed / config_.qpcFrequency;
        const uint64_t rem = elapsed % config_.qpcFrequency;
        const uint64_t wholePart = whole > std::numeric_limits<uint64_t>::max() / 10'000'000ULL
                                 ? std::numeric_limits<uint64_t>::max()
                                 : whole * 10'000'000ULL;
        const uint64_t remScaled = rem > std::numeric_limits<uint64_t>::max() / 10'000'000ULL
                                 ? std::numeric_limits<uint64_t>::max()
                                 : rem * 10'000'000ULL;
        delta100ns = saturatingAdd(wholePart, remScaled / config_.qpcFrequency);
    }
    const uint64_t result = saturatingAdd(config_.systemTimeStart100ns, delta100ns);
    advanceQueryQuantum();
    return result;
}

RdtscValue SyntheticClock::nextTsc(bool rdtscp) {
    uint64_t tscDelta = 0;
    if (elapsedQpcTicks_ &&
        config_.tscQuantum <= std::numeric_limits<uint64_t>::max() / elapsedQpcTicks_) {
        tscDelta = (elapsedQpcTicks_ * config_.tscQuantum) / config_.qpcQuantum;
    } else if (elapsedQpcTicks_) {
        // The production values stay on the exact integer path for many days.
        // Keep hostile/test configurations bounded instead of overflowing.
        const long double scaled = static_cast<long double>(elapsedQpcTicks_) *
                                   static_cast<long double>(config_.tscQuantum) /
                                   static_cast<long double>(config_.qpcQuantum);
        tscDelta = scaled >= static_cast<long double>(std::numeric_limits<uint64_t>::max())
                 ? std::numeric_limits<uint64_t>::max()
                 : static_cast<uint64_t>(scaled);
    }
    const uint64_t value = saturatingAdd(config_.tscStart, tscDelta);
    advanceQueryQuantum();
    RdtscValue out;
    out.eax = static_cast<uint32_t>(value);
    out.edx = static_cast<uint32_t>(value >> 32);
    out.ecx = rdtscp ? config_.rdtscpAux : 0;
    return out;
}

AntiDebugCapabilityReport BuildAntiDebugCapabilityReport(const AntiDebugPolicy& p) {
    AntiDebugCapabilityReport r;
    if (!p.enabled()) {
        r.userModeCoverage.push_back("concealment is off (default)");
    } else {
        if (p.normalizePeb) r.userModeCoverage.push_back("reversible PEB debug-field normalization");
        if (p.normalizeProcessHeap) r.userModeCoverage.push_back("reversible process-heap debug-flag normalization");
        if (p.hideProcessDebugQueries || p.hideKernelDebuggerQuery || p.acceptThreadHideRequests ||
            p.neutralizeInvalidHandleClose)
            r.userModeCoverage.push_back("breakpoint-mediated selected ntdll anti-debug calls");
        if (p.maskDebugRegisters)
            r.userModeCoverage.push_back("NtGet/SetContextThread debug-register mediation with owned DR re-arm");
        if (p.syntheticClock)
            r.userModeCoverage.push_back(
                "session-seeded, target-run-time-accounted QPC/system-time virtualization");
        if (p.rdtsc != RdtscInterception::Off)
            r.userModeCoverage.push_back(
                "software traps only at recursively reachable, loader-proven RDTSC/RDTSCP instruction starts");
    }

    // Be explicit: these guarantees cannot truthfully be made by a Win32 debugger
    // and are out of scope for this tool.
    r.beyondUserMode = {
        "trap every RDTSC/RDTSCP, including generated/self-modifying code, without patching target bytes",
        "virtualize KUSER_SHARED_DATA time reads and direct syscalls that bypass patched ntdll entries",
        "eliminate the one-instruction restore/single-step/re-arm window used for ntdll pass-through calls",
        "hide kernel debug objects, debug ports, process instrumentation and debugger event side effects",
        "make debug-register state invisible to kernel-mode code and cross-process/kernel inspections",
        "provide instruction-perfect time across every core/thread and every timing source",
    };
    return r;
}

bool AddAntiDebugWarning(AntiDebugSessionStats& stats, std::string warning, size_t cap) {
    // The caller may be inspecting hostile module metadata. Keep both cardinality
    // and per-message storage bounded before the snapshot is copied to the UI.
    cap = std::min(cap, kAntiDebugWarningCap);
    constexpr size_t kMessageCap = 256;
    if (warning.size() > kMessageCap) {
        warning.resize(kMessageCap - 3);
        warning += "...";
    }
    if (std::find(stats.warnings.begin(), stats.warnings.end(), warning) != stats.warnings.end()) {
        ++stats.warningsDeduplicated;
        return false;
    }
    if (!cap || stats.warnings.size() >= cap) {
        ++stats.warningsDropped;
        return false;
    }
    stats.warnings.push_back(std::move(warning));
    return true;
}

} // namespace ds
