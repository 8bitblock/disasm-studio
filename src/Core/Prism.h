#pragma once
//
// Prism.h
// The "explanatory profiler" core for DisasmStudio (additions.md idea #5). A sampling
// profiler answers *where* time goes; Prism's job is to also answer *why* — is the
// program actually computing, or is it blocked waiting, fighting over a lock, churning
// the allocator, or stuck in I/O? — and to say it in plain English.
//
// This header is the PURE aggregation + explanation layer: it takes a batch of
// symbolized stack samples (leaf frame first) and produces the flat hot-function
// table (self + inclusive), a thread-state breakdown, the hottest call paths, and a
// plain-language verdict ("62% of samples were blocked in a critical section — this
// is lock contention, not CPU work"). The actual sampling — suspend a thread,
// StackWalk64 it, resolve symbols, resume — is a thin Win32 layer (the Prism tab)
// that feeds PrismSamples in here; keeping the reasoning pure makes it unit-testable
// exactly like TechScan / FuncAnnotate / Cortex (tests/prism_test.cpp).
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// One stack frame in a sample. `symbol` is the resolved "module!function" name (or a
// raw hex string when unresolved); `address` is the frame's instruction pointer.
struct PrismFrame {
    std::string symbol;
    uint64_t    address = 0;
};

// One profiler sample: the call stack of one thread at one instant, LEAF FRAME FIRST
// (frames[0] is where the thread currently is; the last frame is the outermost caller).
// `timeMs` is a millisecond timestamp (any monotonic clock; the sampler uses
// GetTickCount64). 0 means "unknown" — the over-time timeline is only built when
// samples carry timestamps.
struct PrismSample {
    uint32_t                threadId = 0;
    uint64_t                timeMs   = 0;
    std::vector<PrismFrame> frames;
    // QueryThreadCycleTime delta since this thread's previous observation. This
    // weights CPU attribution without confusing the number of sleeping threads
    // with process CPU usage. Zero means unavailable/no measured CPU progress.
    uint64_t                cpuCycles = 0;
};

// What a thread was doing when sampled — inferred from the top few frames.
enum class ThreadState : uint8_t {
    Running,         // executing user/CPU code (not in a recognized wait/io/alloc frame)
    Waiting,         // blocked on a wait/sleep/message-pump (idle, not CPU work)
    LockContention,  // blocked entering a critical section / SRW lock (serialized on a lock)
    Allocation,      // inside the heap allocator (alloc/free churn)
    IO,              // in file/socket I/O
    Gpu,             // at a GPU present/swap boundary (waiting on the GPU / vsync)
    Unknown
};
const char* ThreadStateName(ThreadState s);

// Classify one sample by scanning its top frames. Deterministic; exposed for testing.
ThreadState ClassifySample(const std::vector<PrismFrame>& frames);

// Flat per-function statistics.
struct PrismFuncStat {
    std::string symbol;
    uint64_t    address = 0;      // representative IP (first sample this symbol was seen at)
    int         self = 0;         // samples where this was the LEAF frame (on-CPU here)
    int         inclusive = 0;    // samples where this appeared ANYWHERE in the stack
    float       selfPct = 0.0f;
    float       inclusivePct = 0.0f;
    uint64_t    selfCycles = 0;
    uint64_t    inclusiveCycles = 0;
    float       cpuSelfPct = 0.0f;
    float       cpuInclusivePct = 0.0f;
};

// Aggregate for one thread-state bucket.
struct PrismStateStat {
    ThreadState state = ThreadState::Unknown;
    int         samples = 0;
    float       pct = 0.0f;
};

// One hot call path (a distinct stack), with how often it was sampled.
struct PrismHotPath {
    std::vector<std::string> frames;  // leaf..root symbols (bounded depth)
    int   samples = 0;
    float pct = 0.0f;
};

// Per-thread breakdown (which thread is doing what — "threads fighting over locks").
struct PrismThreadStat {
    uint32_t    threadId = 0;
    int         samples = 0;
    float       pct = 0.0f;
    ThreadState dominant = ThreadState::Unknown;  // its most common state
    float       dominantPct = 0.0f;
    std::string topSymbol;                        // its hottest leaf frame
    uint64_t    cpuCycles = 0;
    float       cpuPct = 0.0f;
};

// Per-module self-time attribution (where the leaf frames live).
struct PrismModuleStat {
    std::string module;      // "ntdll", "app", "(unknown)"
    int         self = 0;    // samples whose LEAF frame is in this module
    float       selfPct = 0.0f;
    uint64_t    cpuCycles = 0;
    float       cpuPct = 0.0f;
};

// One time bucket of the run (only produced when samples carry timestamps).
struct PrismTimeSlice {
    uint64_t    startMs = 0;              // window start, relative to the first sample
    int         samples = 0;
    int         state[7] = { 0 };         // per-ThreadState counts (index == enum value)
    ThreadState dominant = ThreadState::Unknown;
};

struct PrismReport {
    int                          totalSamples = 0;
    int                          threadCount  = 0;
    uint64_t                     spanMs       = 0;   // last - first sample timestamp (0 if untimed)
    uint64_t                     totalCpuCycles = 0; // sum of QueryThreadCycleTime deltas
    std::vector<PrismFuncStat>   functions;   // CPU cycles first when available, then samples
    std::vector<PrismStateStat>  states;      // sorted by samples desc
    std::vector<PrismThreadStat> threads;     // per-thread, sorted by observation count
    std::vector<PrismModuleStat> modules;     // CPU cycles first when available, then leaf samples
    std::vector<PrismHotPath>    hotPaths;    // top distinct stacks by frequency
    std::vector<PrismTimeSlice>  timeline;    // over-time buckets (empty if untimed)
    std::string                  headline;    // one line: dominant state + hottest function
    std::string                  verdict;     // plain-English where-time-goes + what-to-fix
    const char*                  analyzer = "Prism";
};

// Aggregate + explain a batch of samples. Returns a benign empty report (no fabricated
// numbers) when `samples` is empty.
PrismReport BuildPrismReport(const std::vector<PrismSample>& samples);

} // namespace ds
