#include "Prism.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>

namespace ds {

namespace {

constexpr int    kTopFramesForClass = 4;    // how deep to look when classifying a sample
constexpr size_t kHotPathDepth      = 12;   // frames retained per hot-path key
constexpr size_t kMaxHotPaths       = 12;
constexpr size_t kMaxFuncRows       = 200;

std::string lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}
bool anyOf(const std::string& low, std::initializer_list<const char*> subs) {
    for (const char* s : subs) if (low.find(s) != std::string::npos) return true;
    return false;
}

bool symbolToken(const std::string& low, const char* token) {
    const size_t bang = low.find('!');
    if (bang == std::string::npos) return false;
    const size_t n = std::char_traits<char>::length(token);
    size_t at = bang + 1;
    while ((at = low.find(token, at)) != std::string::npos) {
        const bool left = at == bang + 1 ||
                          (!std::isalnum((unsigned char)low[at - 1]) && low[at - 1] != '_');
        const size_t end = at + n;
        const bool right = end == low.size() ||
                           (!std::isalnum((unsigned char)low[end]) && low[end] != '_');
        if (left && right) return true;
        ++at;
    }
    return false;
}

bool moduleToken(const std::string& low, const char* module, const char* token) {
    const size_t bang = low.find('!');
    return bang != std::string::npos && low.compare(0, bang, module) == 0 &&
           symbolToken(low, token);
}

// Symbol keyword sets (matched case-insensitively against "module!function").
// Separate ordinary lock acquisition from actual blocking helpers: merely entering
// an uncontended critical section is not lock contention.
bool isLockWaitFrame(const std::string& low) {
    return anyOf(low, { "rtlpwaitoncriticalsection", "rtlpwaitonsrwlock",
                        "rtlwaitoncriticalsection", "rtlwaitonsrwlock" });
}
bool isLockAcquireFrame(const std::string& low) {
    return anyOf(low, { "!entercriticalsection", "!rtlentercriticalsection",
                        "!acquiresrwlock", "!rtlacquiresrwlock" });
}
bool isLockFrame(const std::string& low) {
    return isLockWaitFrame(low) || isLockAcquireFrame(low);
}
bool isIoFrame(const std::string& low) {
    return anyOf(low, { "ntdll!ntreadfile", "ntdll!ntwritefile", "ntdll!ntdeviceiocontrol",
                        "ntdll!ntfscontrolfile", "kernel32!readfile", "kernelbase!readfile",
                        "kernel32!writefile", "kernelbase!writefile", "ws2_32!wsarecv",
                        "ws2_32!wsasend", "ws2_32!recv", "ws2_32!send",
                        "!getoverlappedresult", "!ntremoveiocompletion",
                        "!getqueuedcompletionstatus" });
}
bool isAllocFrame(const std::string& low) {
    return anyOf(low, { "ntdll!rtlallocateheap", "ntdll!rtlfreeheap", "ntdll!rtlpallocateheap",
                        "kernel32!heapalloc", "kernelbase!heapalloc", "kernel32!heapfree",
                        "kernelbase!heapfree" }) ||
           symbolToken(low, "operator new") || symbolToken(low, "operator delete") ||
           symbolToken(low, "malloc") || symbolToken(low, "free") ||
           symbolToken(low, "calloc") || symbolToken(low, "realloc") ||
           symbolToken(low, "virtualalloc");
}
bool isWaitFrame(const std::string& low) {
    return anyOf(low, { "ntdll!ntwaitforsingleobject", "ntdll!ntwaitformultipleobjects",
                        "kernel32!waitforsingleobject", "kernelbase!waitforsingleobject",
                        "kernel32!waitformultipleobjects", "kernelbase!waitformultipleobjects",
                        "ntdll!ntdelayexecution", "kernel32!sleep", "kernelbase!sleep",
                        "user32!getmessage", "!msgwaitformultiple", "!ntwaitforalertbythreadid",
                        "!zwwaitfor", "!cowaitfor", "!waitonaddress" });
}
bool isGpuFrame(const std::string& low) {
    return moduleToken(low, "dxgi", "present") || moduleToken(low, "dxgi", "present1") ||
           moduleToken(low, "dxgi", "presentmultiplaneoverlay") ||
           moduleToken(low, "d3d9", "present") ||
           moduleToken(low, "opengl32", "swapbuffers") || moduleToken(low, "gdi32", "swapbuffers") ||
           moduleToken(low, "vulkan-1", "vkqueuepresent") || moduleToken(low, "vulkan-1", "vkqueuepresentkhr");
}

// Module part of a "module!function" symbol ("(unknown)" when there is no module).
std::string leafModule(const std::string& sym) {
    size_t bang = sym.find('!');
    return bang == std::string::npos ? std::string("(unknown)") : sym.substr(0, bang);
}

} // namespace

const char* ThreadStateName(ThreadState s) {
    switch (s) {
        case ThreadState::Running:        return "Running / executing";
        case ThreadState::Waiting:        return "Waiting / idle";
        case ThreadState::LockContention: return "Lock contention";
        case ThreadState::Allocation:     return "Allocating";
        case ThreadState::IO:             return "I/O";
        case ThreadState::Gpu:            return "GPU / present";
        default:                          return "Unknown";
    }
}

ThreadState ClassifySample(const std::vector<PrismFrame>& frames) {
    if (frames.empty()) return ThreadState::Unknown;
    int depth = (int)std::min((size_t)kTopFramesForClass, frames.size());

    // Every predicate below expects lowercase text. Lower each of the few frames
    // once instead of allocating a fresh lowercase copy for every category pass
    // (lock, I/O, allocation, GPU, wait).
    std::string lowered[kTopFramesForClass];
    for (int i = 0; i < depth; ++i) lowered[i] = lower(frames[i].symbol);

    // Lock contention requires a blocking lock helper, or a generic wait plus an
    // acquisition frame in the sampled stack. A lone EnterCriticalSection may be fast.
    bool sawWait = false, sawAcquire = false;
    for (int i = 0; i < depth; ++i) {
        const std::string& f = lowered[i];
        if (isLockWaitFrame(f)) return ThreadState::LockContention;
        sawWait = sawWait || isWaitFrame(f);
        sawAcquire = sawAcquire || isLockAcquireFrame(f);
    }
    if (sawWait && sawAcquire) return ThreadState::LockContention;

    // I/O, allocation and GPU-present are more specific than a generic wait. A
    // Present stack commonly has NtWait* at its leaf, so classify GPU before wait.
    for (int i = 0; i < depth; ++i) if (isIoFrame(lowered[i]))    return ThreadState::IO;
    for (int i = 0; i < depth; ++i) if (isAllocFrame(lowered[i])) return ThreadState::Allocation;
    for (int i = 0; i < depth; ++i) if (isGpuFrame(lowered[i]))   return ThreadState::Gpu;
    for (int i = 0; i < depth; ++i) if (isWaitFrame(lowered[i]))  return ThreadState::Waiting;

    // Nothing recognized in the top frames: the thread is executing code — CPU work.
    return ThreadState::Running;
}

namespace {

std::string pctStr(float p) {
    char b[16];
    std::snprintf(b, sizeof(b), "%.0f%%", p);
    return b;
}

} // namespace

PrismReport BuildPrismReport(const std::vector<PrismSample>& samples) {
    PrismReport rep;
    rep.totalSamples = (int)samples.size();
    if (samples.empty()) {
        rep.headline = "No samples collected.";
        rep.verdict  = "Nothing was sampled yet — start the profiler while the target is doing work.";
        return rep;
    }
    const float inv = 100.0f / (float)samples.size();

    // ---- Flat function table (self = leaf; inclusive = anywhere in the stack) ----
    std::unordered_map<std::string, PrismFuncStat> funcs;
    std::unordered_set<uint32_t> threads;
    std::unordered_map<std::string, PrismHotPath> paths;
    std::unordered_map<int, int> stateCount;   // ThreadState -> samples

    // Per-thread / per-module / over-time accumulators.
    struct ThreadAcc {
        int count = 0;
        int st[7] = { 0 };
        uint64_t cycles = 0;
        std::unordered_map<std::string, int> leaf;
        std::unordered_map<std::string, uint64_t> leafCycles;
    };
    std::unordered_map<uint32_t, ThreadAcc> threadAcc;
    std::unordered_map<std::string, int>    moduleSelf;
    std::unordered_map<std::string, uint64_t> moduleCycles;
    std::vector<std::pair<uint64_t, int>>   timeState;  // (timeMs, stateIdx) for timed samples
    // Report refreshes aggregate a rolling window repeatedly. Reserve from the
    // known sample count so common profiles do not rehash/grow these containers
    // over and over on the UI refresh path.
    const size_t expectedSymbols = std::min<size_t>(samples.size() * 2, kMaxFuncRows * 8);
    funcs.reserve(expectedSymbols);
    paths.reserve(std::min<size_t>(samples.size(), 2048));
    threadAcc.reserve(std::min<size_t>(samples.size(), 256));
    moduleSelf.reserve(64);
    moduleCycles.reserve(64);
    timeState.reserve(samples.size());
    uint64_t minMs = 0, maxMs = 0;
    bool     anyTime = false;

    for (const PrismSample& s : samples) {
        rep.totalCpuCycles += s.cpuCycles;
        threads.insert(s.threadId);
        ThreadState ts = ClassifySample(s.frames);   // Unknown for empty frames
        stateCount[(int)ts]++;

        ThreadAcc& ta = threadAcc[s.threadId];
        ta.count++;
        ta.st[(int)ts]++;
        ta.cycles += s.cpuCycles;

        if (s.timeMs) {
            timeState.emplace_back(s.timeMs, (int)ts);
            if (!anyTime) { minMs = maxMs = s.timeMs; anyTime = true; }
            else { if (s.timeMs < minMs) minMs = s.timeMs; if (s.timeMs > maxMs) maxMs = s.timeMs; }
        }

        if (s.frames.empty()) continue;
        const PrismFrame& leaf = s.frames.front();

        // self: leaf frame.
        {
            PrismFuncStat& fs = funcs[leaf.symbol];
            if (fs.symbol.empty()) { fs.symbol = leaf.symbol; fs.address = leaf.address; }
            fs.self++;
            fs.selfCycles += s.cpuCycles;
        }
        ta.leaf[leaf.symbol]++;
        ta.leafCycles[leaf.symbol] += s.cpuCycles;
        std::string module = leafModule(leaf.symbol);
        moduleSelf[module]++;
        moduleCycles[module] += s.cpuCycles;

        // inclusive: each UNIQUE symbol in this stack (recursion counts once per sample).
        {
            std::unordered_set<std::string> seen;
            for (const PrismFrame& f : s.frames)
                if (seen.insert(f.symbol).second) {
                    PrismFuncStat& fs = funcs[f.symbol];
                    if (fs.symbol.empty()) { fs.symbol = f.symbol; fs.address = f.address; }
                    fs.inclusive++;
                    fs.inclusiveCycles += s.cpuCycles;
                }
        }
        // hot path key: the top kHotPathDepth symbols joined.
        {
            std::string key;
            size_t n = std::min(kHotPathDepth, s.frames.size());
            size_t keyBytes = n;
            for (size_t i = 0; i < n; ++i) keyBytes += s.frames[i].symbol.size();
            key.reserve(keyBytes);
            for (size_t i = 0; i < n; ++i) { key += s.frames[i].symbol; key += ";"; }
            auto [it, inserted] = paths.try_emplace(std::move(key));
            PrismHotPath& hp = it->second;
            if (inserted) {
                hp.frames.reserve(n);
                for (size_t i = 0; i < n; ++i) hp.frames.push_back(s.frames[i].symbol);
            }
            ++hp.samples;
        }
    }
    rep.threadCount = (int)threads.size();
    if (anyTime) rep.spanMs = maxMs - minMs;
    const double invCycles = rep.totalCpuCycles
                           ? 100.0 / (double)rep.totalCpuCycles : 0.0;

    for (auto& kv : funcs) {
        PrismFuncStat fs = kv.second;
        fs.selfPct      = fs.self * inv;
        fs.inclusivePct = fs.inclusive * inv;
        fs.cpuSelfPct      = (float)((double)fs.selfCycles * invCycles);
        fs.cpuInclusivePct = (float)((double)fs.inclusiveCycles * invCycles);
        rep.functions.push_back(std::move(fs));
    }
    std::sort(rep.functions.begin(), rep.functions.end(),
              [](const PrismFuncStat& a, const PrismFuncStat& b) {
                  if (a.selfCycles != b.selfCycles) return a.selfCycles > b.selfCycles;
                  if (a.self != b.self) return a.self > b.self;
                  return a.inclusive > b.inclusive;
              });
    if (rep.functions.size() > kMaxFuncRows) rep.functions.resize(kMaxFuncRows);

    for (auto& kv : stateCount) {
        PrismStateStat ss;
        ss.state = (ThreadState)kv.first;
        ss.samples = kv.second;
        ss.pct = kv.second * inv;
        rep.states.push_back(ss);
    }
    std::sort(rep.states.begin(), rep.states.end(),
              [](const PrismStateStat& a, const PrismStateStat& b) { return a.samples > b.samples; });

    for (auto& kv : paths) {
        PrismHotPath hp = kv.second;
        hp.pct = hp.samples * inv;
        rep.hotPaths.push_back(std::move(hp));
    }
    std::sort(rep.hotPaths.begin(), rep.hotPaths.end(),
              [](const PrismHotPath& a, const PrismHotPath& b) { return a.samples > b.samples; });
    if (rep.hotPaths.size() > kMaxHotPaths) rep.hotPaths.resize(kMaxHotPaths);

    // ---- Per-thread breakdown ----
    for (auto& kv : threadAcc) {
        const ThreadAcc& ta = kv.second;
        PrismThreadStat t;
        t.threadId = kv.first;
        t.samples  = ta.count;
        t.pct      = ta.count * inv;
        t.cpuCycles = ta.cycles;
        t.cpuPct = (float)((double)ta.cycles * invCycles);
        int best = 0, bestC = -1;
        for (int i = 0; i < 7; ++i) if (ta.st[i] > bestC) { bestC = ta.st[i]; best = i; }
        t.dominant    = (ThreadState)best;
        t.dominantPct = ta.count ? (float)bestC * 100.0f / (float)ta.count : 0.0f;
        if (rep.totalCpuCycles) {
            uint64_t bestCycles = 0;
            for (const auto& l : ta.leafCycles)
                if (l.second > bestCycles) { bestCycles = l.second; t.topSymbol = l.first; }
        }
        if (t.topSymbol.empty()) {
            int lc = -1;
            for (const auto& l : ta.leaf) if (l.second > lc) { lc = l.second; t.topSymbol = l.first; }
        }
        rep.threads.push_back(std::move(t));
    }
    std::sort(rep.threads.begin(), rep.threads.end(),
              [](const PrismThreadStat& a, const PrismThreadStat& b) { return a.samples > b.samples; });

    // ---- Per-module self-time ----
    for (auto& kv : moduleSelf) {
        PrismModuleStat m;
        m.module  = kv.first;
        m.self    = kv.second;
        m.selfPct = kv.second * inv;
        m.cpuCycles = moduleCycles[kv.first];
        m.cpuPct = (float)((double)m.cpuCycles * invCycles);
        rep.modules.push_back(std::move(m));
    }
    std::sort(rep.modules.begin(), rep.modules.end(),
              [](const PrismModuleStat& a, const PrismModuleStat& b) {
                  if (a.cpuCycles != b.cpuCycles) return a.cpuCycles > b.cpuCycles;
                  return a.self > b.self;
              });

    // ---- Over-time timeline (only when samples are timestamped) ----
    if (anyTime && maxMs > minMs) {
        const int N = 30;
        const uint64_t span = maxMs - minMs;
        rep.timeline.resize(N);
        for (int i = 0; i < N; ++i) rep.timeline[i].startMs = span * (uint64_t)i / (uint64_t)N;
        for (const auto& ps : timeState) {
            uint64_t rel = ps.first - minMs;
            int idx = (int)(rel * (uint64_t)N / (span + 1));
            if (idx < 0) idx = 0;
            if (idx >= N) idx = N - 1;
            rep.timeline[idx].samples++;
            rep.timeline[idx].state[ps.second]++;
        }
        for (PrismTimeSlice& sl : rep.timeline) {
            int best = 0, bestC = -1;
            for (int i = 0; i < 7; ++i) if (sl.state[i] > bestC) { bestC = sl.state[i]; best = i; }
            sl.dominant = bestC > 0 ? (ThreadState)best : ThreadState::Unknown;
        }
    }

    // ---- Headline + verdict ----
    // State percentages are a census of sampled THREADS, not CPU time: sampling
    // every thread once per sweep would otherwise let many idle threads hide one
    // saturated worker. QueryThreadCycleTime deltas provide the separate CPU weight.
    const PrismStateStat& dom = rep.states.front();
    const bool haveCycles = rep.totalCpuCycles != 0;
    const PrismFuncStat* hot = nullptr;
    for (const PrismFuncStat& fs : rep.functions) {
        std::string ls = lower(fs.symbol);
        const bool hasWeight = haveCycles ? fs.selfCycles != 0 : fs.self != 0;
        if (hasWeight && !isWaitFrame(ls) && !isLockFrame(ls) && !isIoFrame(ls) &&
            !isAllocFrame(ls) && !isGpuFrame(ls)) { hot = &fs; break; }
    }

    {
        std::string h = std::to_string(rep.totalSamples) + " thread observations across " +
                        std::to_string(rep.threadCount) + " thread(s): " +
                        pctStr(dom.pct) + " " + ThreadStateName(dom.state);
        if (hot) {
            const float pct = haveCycles ? hot->cpuSelfPct : hot->selfPct;
            h += haveCycles ? "; estimated CPU hotspot " : "; most frequent running leaf ";
            h += hot->symbol + " (" + pctStr(pct) + ")";
        }
        rep.headline = h;
    }

    std::string v;
    switch (dom.state) {
        case ThreadState::Running:
            v = "Thread-state census: " + pctStr(dom.pct) +
                " of observations were executing code rather than in a recognized wait.";
            break;
        case ThreadState::Waiting:
            v = "Thread occupancy is mostly blocked/idle: " + pctStr(dom.pct) +
                " of observations were waiting. This describes how many sampled threads were idle, "
                "not the process's CPU utilization; inspect the cycle-weighted hotspot separately.";
            break;
        case ThreadState::LockContention:
            v = "Possible lock contention: " + pctStr(dom.pct) +
                " of observations contained a blocking critical-section/SRW-lock path. "
                "Confirm the shared lock before shrinking or sharding the critical section.";
            break;
        case ThreadState::Allocation:
            v = "Allocation activity: " + pctStr(dom.pct) +
                " of thread observations were inside a heap allocator. If the same functions also "
                "dominate measured cycles, reduce churn by pooling or reserving storage.";
            break;
        case ThreadState::IO:
            v = "I/O activity: " + pctStr(dom.pct) +
                " of observations were in qualified file/socket I/O or completion paths. "
                "Consider batching, buffering, or overlapped I/O if cycle/path evidence agrees.";
            break;
        case ThreadState::Gpu:
            v = "Present activity: " + pctStr(dom.pct) +
                " of observations included a qualified graphics present/swap function, which can "
                "indicate GPU/vsync waiting but is not proof of a GPU bottleneck.";
            break;
        default:
            v = pctStr(dom.pct) + " of thread observations could not be classified (missing symbols?).";
            break;
    }

    if (hot) {
        if (haveCycles) {
            v += " Estimated CPU-cycle attribution is concentrated in " + hot->symbol + " (" +
                 pctStr(hot->cpuSelfPct) + " leaf, " + pctStr(hot->cpuInclusivePct) +
                 " inclusive). Cycle deltas are weighting evidence, not wall-clock CPU utilization.";
        } else {
            v += " Cycle weighting was unavailable; the most frequent running leaf was " + hot->symbol +
                 " (" + pctStr(hot->selfPct) + " of observations).";
        }
    }

    if (rep.functions.size() > 1) {
        std::vector<std::string> more;
        for (const PrismFuncStat& f : rep.functions) {
            if (more.size() >= 3) break;
            const float pct = haveCycles ? f.cpuSelfPct : f.selfPct;
            if ((haveCycles ? f.selfCycles != 0 : f.self != 0))
                more.push_back(f.symbol + " " + pctStr(pct));
        }
        if (more.size() > 1) {
            v += haveCycles ? " Top estimated CPU leaf functions: " : " Top sampled leaf functions: ";
            for (size_t i = 0; i < more.size(); ++i) { if (i) v += ", "; v += more[i]; }
            v += ".";
        }
    }

    if (rep.threads.size() > 1) {
        int onCpu = 0, blocked = 0;
        for (const PrismThreadStat& t : rep.threads) {
            if (t.dominant == ThreadState::Running) ++onCpu;
            else if (t.dominant == ThreadState::Waiting || t.dominant == ThreadState::LockContention ||
                     t.dominant == ThreadState::IO) ++blocked;
        }
        v += " Across " + std::to_string(rep.threads.size()) + " sampled threads, " +
             std::to_string(onCpu) + " were mostly executing and " + std::to_string(blocked) +
             " mostly blocked/idle.";
    }

    rep.verdict = v;

    return rep;
}

} // namespace ds
