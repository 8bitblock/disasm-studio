#pragma once
//
// AntiDebug.h
// Pure policy and state for the opt-in "Hide Debugger" layer.  This file has no
// Win32 dependency: the debugger event loop supplies the actual memory/context
// operations, while this module owns conservative decisions, pristine-byte
// bookkeeping, and deterministic virtual time.
//
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

enum class RdtscInterception : uint8_t {
    Off,
    MainExecutable,
    AllExecutableImages,
};

// Every switch is deliberately false/off by default.  The policy is captured at
// attach/launch time so a session cannot become half-concealed while it is running.
struct AntiDebugPolicy {
    bool normalizePeb = false;               // PEB BeingDebugged + NtGlobalFlag
    bool normalizeProcessHeap = false;       // process-heap Flags + ForceFlags
    bool hideProcessDebugQueries = false;    // NtQueryInformationProcess debug classes
    bool hideKernelDebuggerQuery = false;    // NtQuerySystemInformation class 35
    bool acceptThreadHideRequests = false;    // Nt[Query/Set]InformationThread class 17
    bool neutralizeInvalidHandleClose = false;// NtClose invalid-handle probe
    bool maskDebugRegisters = false;          // NtGet/SetContextThread mediation
    bool syntheticClock = false;              // NtQueryPerformanceCounter/SystemTime
    RdtscInterception rdtsc = RdtscInterception::Off;

    bool enabled() const;
    bool requiresNtdllHooks() const;
};

enum class AntiDebugCall : uint8_t {
    NtQueryInformationProcess,
    NtQuerySystemInformation,
    NtQueryInformationThread,
    NtSetInformationThread,
    NtClose,
    NtGetContextThread,
    NtSetContextThread,
    NtQueryPerformanceCounter,
    NtQuerySystemTime,
};

enum class AntiDebugOutput : uint8_t {
    None,
    ZeroPointer,
    OneU32,
    KernelDebuggerInfo, // {DebuggerEnabled=FALSE, DebuggerNotPresent=TRUE}
    FalseByte,
};

struct AntiDebugDecision {
    bool intercept = false;
    uint32_t status = 0;              // NTSTATUS bit pattern
    AntiDebugOutput output = AntiDebugOutput::None;
    size_t requiredOutputBytes = 0;
    const char* reason = "pass through";
};

// infoClass/outputLength are ignored for calls that do not use them.  `invalidHandle`
// must come from a real handle-table probe; the pure policy never guesses validity.
AntiDebugDecision DecideAntiDebugCall(const AntiDebugPolicy& policy,
                                      AntiDebugCall call,
                                      uint32_t infoClass = 0,
                                      size_t outputLength = 0,
                                      bool invalidHandle = false,
                                      size_t pointerSize = sizeof(uint64_t),
                                      bool sameTargetHandle = true,
                                      bool informationBufferPresent = true);

// Bytes removed by the callee's `ret N` for 32-bit NTAPI/stdcall exports.
// x64 uses caller-owned shadow space and therefore never uses this value.
size_t AntiDebugX86StackArgumentBytes(AntiDebugCall call);

// Stable normalizers used by the Win32 adapter after it has read the pristine fields.
uint32_t NormalizeNtGlobalFlag(uint32_t value);
uint32_t NormalizeHeapFlags(uint32_t value);
uint32_t NormalizeHeapForceFlags(uint32_t value);

struct PristineMemoryPatch {
    uint64_t address = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> concealed;
    std::string label;
};

// First observation wins.  This prevents a repeated normalization tick from
// accidentally treating its own concealed bytes as the pristine detach value.
class PristinePatchSet {
public:
    bool remember(uint64_t address,
                  const std::vector<uint8_t>& original,
                  const std::vector<uint8_t>& concealed,
                  std::string_view label) noexcept;
    bool forget(uint64_t address) noexcept;
    const std::vector<PristineMemoryPatch>& patches() const { return patches_; }
    const PristineMemoryPatch* find(uint64_t address) const;
    static bool shouldRestore(const PristineMemoryPatch& patch,
                              const std::vector<uint8_t>& current);
    void clear() { patches_.clear(); }

private:
    std::vector<PristineMemoryPatch> patches_;
};

struct DebugRegisterState {
    std::array<uint64_t, 4> address{};
    uint64_t dr6 = 0;
    uint64_t dr7 = 0;
};

DebugRegisterState MaskDebugRegisters(const DebugRegisterState& in);
bool CanMediateSetContext(bool targetsCurrentEventThread, uint32_t contextFlags);
bool AntiDebugTrapRangeValid(uint64_t ownerImageBase, uint64_t ownerImageSize,
                             uint64_t address, size_t instructionLength);

struct PendingAntiDebugRearm {
    uint32_t tid = 0;
    uint64_t address = 0;
    uint64_t ownerImageBase = 0;
};

// Debug events resume every thread, so several threads can simultaneously be
// trap-stepping different restored hook entries. Keep one non-overwritable
// pending re-arm per thread and consume it only on that thread's #DB.
class AntiDebugRearmState {
public:
    bool begin(uint32_t tid, uint64_t address, uint64_t ownerImageBase) noexcept;
    const PendingAntiDebugRearm* find(uint32_t tid) const noexcept;
    bool hasAddress(uint64_t address) const noexcept;
    std::optional<PendingAntiDebugRearm> take(uint32_t tid) noexcept;
    std::optional<PendingAntiDebugRearm> takeOwner(uint64_t ownerImageBase) noexcept;
    std::optional<PendingAntiDebugRearm> takeAny() noexcept;
    size_t size() const { return pending_.size(); }

private:
    std::vector<PendingAntiDebugRearm> pending_;
};

struct SyntheticClockConfig {
    uint64_t qpcStart = 10'000'000;
    uint64_t qpcFrequency = 10'000'000;       // 10 MHz
    uint64_t qpcQuantum = 1'000;              // 100 microseconds/query
    uint64_t systemTimeStart100ns = 132'000'000'000'000'000ULL;
    uint64_t tscStart = 3'000'000'000ULL;
    uint64_t tscQuantum = 300'000;             // ~100 microseconds at 3 GHz
    uint32_t rdtscpAux = 0;
};

struct RdtscValue {
    uint32_t eax = 0;
    uint32_t edx = 0;
    uint32_t ecx = 0;
};

// One correlated virtual timeline. The debugger advances it by the time for which
// the target was actually resumed, while each intercepted query adds a small
// monotonic call-cost quantum. Time spent stopped in a debug event is excluded.
class SyntheticClock {
public:
    explicit SyntheticClock(SyntheticClockConfig config = {});
    void reset(SyntheticClockConfig config = {});
    void advanceRunningQpcTicks(uint64_t ticks);
    uint64_t nextQpc();
    uint64_t qpcFrequency() const { return config_.qpcFrequency; }
    uint64_t nextSystemTime100ns();
    RdtscValue nextTsc(bool rdtscp);

private:
    void advanceQueryQuantum();
    SyntheticClockConfig config_{};
    uint64_t elapsedQpcTicks_ = 0;
};

struct AntiDebugCapabilityReport {
    std::vector<std::string> userModeCoverage;
    std::vector<std::string> beyondUserMode;
};

AntiDebugCapabilityReport BuildAntiDebugCapabilityReport(const AntiDebugPolicy& policy);

struct AntiDebugSessionStats {
    bool active = false;
    AntiDebugPolicy policy{};
    uint64_t memoryFieldsNormalized = 0;
    uint64_t memoryFieldsRestored = 0;
    uint64_t memoryFieldNormalizeFailures = 0;
    uint64_t memoryFieldRestoreFailures = 0;
    uint64_t antiTrapRestoreFailures = 0;
    uint64_t ntdllHooksArmed = 0;
    uint64_t queryCallsConcealed = 0;
    uint64_t contextCallsMediated = 0;
    uint64_t clockCallsSynthesized = 0;
    uint64_t clockRunIntervals = 0;
    uint64_t clockRunningQpcTicks = 0;
    uint64_t clockRunIntervalsClamped = 0;
    uint64_t clockQpcFrequency = 0;
    uint64_t rdtscSitesArmed = 0;
    uint64_t rdtscInstructionsEmulated = 0;
    uint64_t rdtscDiscoveryInstructions = 0;
    uint64_t rdtscDiscoveryImagesCapped = 0;
    bool rdtscDiscoveryBudgetExhausted = false;
    uint64_t rdtscDiscoveryBudgetTotal = 0;
    uint64_t rdtscDiscoveryBudgetRemaining = 0;
    std::vector<std::string> warnings;
    uint64_t warningsDropped = 0;       // distinct warnings rejected by the cap
    uint64_t warningsDeduplicated = 0;  // repeated warning occurrences suppressed
};

inline constexpr size_t kAntiDebugWarningCap = 32;
bool AddAntiDebugWarning(AntiDebugSessionStats& stats, std::string warning,
                         size_t cap = kAntiDebugWarningCap);

} // namespace ds
