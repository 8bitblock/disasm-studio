//
// prism_test.cpp
// Unit test for the Prism explanatory-profiler core (src/Core/Prism.cpp). We hand it
// synthetic symbolized stacks (leaf frame first) and assert the self/inclusive
// aggregation, the thread-state classification, and the plain-English verdict.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\prism_test.cpp src\Core\Prism.cpp
//   .\prism_test.exe
//
#include "Core/Prism.h"

#include <cstdio>
#include <stop_token>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static bool ihas(std::string s, std::string sub) {
    for (char& c : s)   c = (char)std::tolower((unsigned char)c);
    for (char& c : sub) c = (char)std::tolower((unsigned char)c);
    return s.find(sub) != std::string::npos;
}

// Build a sample from leaf..root symbol names.
static PrismSample sample(uint32_t tid, std::initializer_list<const char*> syms) {
    PrismSample s; s.threadId = tid;
    uint64_t a = 0x140001000;
    for (const char* sym : syms) { s.frames.push_back({ sym, a }); a += 0x40; }
    return s;
}

static const PrismFuncStat* fn(const PrismReport& r, const char* sym) {
    for (const PrismFuncStat& f : r.functions) if (f.symbol == sym) return &f;
    return nullptr;
}

static const PrismFlameNode* flame(const PrismReport& r, const char* sym) {
    for (const PrismFlameNode& node : r.flame) if (node.symbol == sym) return &node;
    return nullptr;
}

int main() {
    // ---- ClassifySample: each category ----
    CHECK(ClassifySample({ { "ntdll!NtWaitForSingleObject", 1 }, { "app!main", 2 } }) == ThreadState::Waiting);
    CHECK(ClassifySample({ { "ntdll!RtlpWaitOnCriticalSection", 1 }, { "ntdll!RtlEnterCriticalSection", 2 }, { "app!work", 3 } }) == ThreadState::LockContention);
    CHECK(ClassifySample({ { "ntdll!RtlAllocateHeap", 1 }, { "app!make", 2 } }) == ThreadState::Allocation);
    CHECK(ClassifySample({ { "ntdll!NtReadFile", 1 }, { "app!load", 2 } }) == ThreadState::IO);
    CHECK(ClassifySample({ { "ntdll!NtWaitForSingleObject", 1 }, { "dxgi!Present", 2 },
                           { "app!render", 3 } }) == ThreadState::Gpu);
    CHECK(ClassifySample({ { "app!EnterCriticalSectionWrapper", 1 }, { "app!work", 2 } }) == ThreadState::Running);
    CHECK(ClassifySample({ { "app!SendMessage", 1 }, { "app!ui", 2 } }) == ThreadState::Running);
    CHECK(ClassifySample({ { "app!dxgi_helper", 1 }, { "app!work", 2 } }) == ThreadState::Running);
    CHECK(ClassifySample({ { "kernel32!FreeLibrary", 1 }, { "app!unload", 2 } }) == ThreadState::Running);
    CHECK(ClassifySample({ { "dxgi!PresentationHelper", 1 }, { "app!work", 2 } }) == ThreadState::Running);
    CHECK(ClassifySample({ { "dxgi!SwapChain::Present", 1 }, { "app!render", 2 } }) == ThreadState::Gpu);
    CHECK(ClassifySample({ { "app!crunch_pixels", 1 }, { "app!render", 2 } }) == ThreadState::Running);
    CHECK(ClassifySample({}) == ThreadState::Unknown);

    // ---- A waiting-dominant profile: 7 blocked, 3 crunching. Common root app!main. ----
    std::vector<PrismSample> samples;
    for (int i = 0; i < 7; ++i)
        samples.push_back(sample(100, { "ntdll!NtWaitForSingleObject", "kernel32!WaitForSingleObjectEx", "app!wait_for_job", "app!main" }));
    for (int i = 0; i < 3; ++i)
        samples.push_back(sample(101, { "app!crunch_pixels", "app!render", "app!main" }));
    // Timestamp the samples so the over-time timeline is produced (1000..1090 ms).
    for (size_t i = 0; i < samples.size(); ++i) samples[i].timeMs = 1000 + i * 10;
    for (size_t i = 7; i < samples.size(); ++i) samples[i].cpuCycles = 100;

    PrismReport rep = BuildPrismReport(samples);
    CHECK(rep.totalSamples == 10);
    CHECK(rep.threadCount == 2);

    // States: Waiting dominant (70%).
    CHECK(!rep.states.empty() && rep.states.front().state == ThreadState::Waiting);
    CHECK(rep.states.front().samples == 7);
    CHECK(rep.states.front().pct >= 69.0f && rep.states.front().pct <= 71.0f);

    // Self counts.
    CHECK(fn(rep, "ntdll!NtWaitForSingleObject") && fn(rep, "ntdll!NtWaitForSingleObject")->self == 7);
    CHECK(fn(rep, "app!crunch_pixels") && fn(rep, "app!crunch_pixels")->self == 3);
    CHECK(rep.totalCpuCycles == 300);
    CHECK(fn(rep, "app!crunch_pixels") && fn(rep, "app!crunch_pixels")->cpuSelfPct > 99.0f);
    // Inclusive: app!main is the root of every sample -> inclusive 10 (100%).
    CHECK(fn(rep, "app!main") && fn(rep, "app!main")->inclusive == 10);
    CHECK(fn(rep, "app!main")->self == 0);   // never the leaf

    // Verdict: "not CPU work" framing, and the hottest CPU is the crunch fn (not the wait leaf).
    CHECK(ihas(rep.verdict, "wait") || ihas(rep.verdict, "blocked"));
    CHECK(ihas(rep.verdict, "not the process's cpu") || ihas(rep.verdict, "occupancy"));
    CHECK(ihas(rep.verdict, "crunch_pixels"));       // hottest CPU work named
    CHECK(ihas(rep.headline, "crunch_pixels"));       // headline names the hottest CPU (not the wait frame)
    CHECK(!ihas(rep.headline, "ntwaitforsingleobject") || ihas(rep.headline, "70%")); // wait shown as state, not "hottest CPU"

    // Hot paths: the 7 identical wait stacks collapse into one hot path with 7 samples.
    CHECK(!rep.hotPaths.empty() && rep.hotPaths.front().samples == 7);

    // ---- Per-thread breakdown ----
    CHECK(rep.threads.size() == 2);
    const PrismThreadStat* t100 = nullptr; const PrismThreadStat* t101 = nullptr;
    for (const auto& t : rep.threads) { if (t.threadId == 100) t100 = &t; if (t.threadId == 101) t101 = &t; }
    CHECK(t100 && t100->samples == 7 && t100->dominant == ThreadState::Waiting);
    CHECK(t101 && t101->samples == 3 && t101->dominant == ThreadState::Running);
    CHECK(t101 && t101->cpuPct > 99.0f);
    CHECK(t100 && ihas(t100->topSymbol, "ntwaitforsingleobject"));
    CHECK(rep.threads.front().threadId == 100);   // sorted by samples desc

    // ---- Per-module self-time (leaf module) ----
    const PrismModuleStat* mnt = nullptr; const PrismModuleStat* mapp = nullptr;
    for (const auto& m : rep.modules) { if (m.module == "ntdll") mnt = &m; if (m.module == "app") mapp = &m; }
    CHECK(mnt && mnt->self == 7);
    CHECK(mapp && mapp->self == 3);
    CHECK(mapp && mapp->cpuPct > 99.0f);
    CHECK(!rep.modules.empty() && rep.modules.front().module == "app"); // CPU-weighted when cycles exist

    // ---- Over-time timeline ----
    CHECK(rep.spanMs == 90);                 // 1090 - 1000
    CHECK(rep.firstTimestampMs == 1000);
    CHECK(rep.lastTimestampMs == 1090);
    CHECK(rep.timeline.size() == 30);
    { int tl = 0; for (const auto& sl : rep.timeline) tl += sl.samples; CHECK(tl == 10); }  // every sample bucketed

    // ---- Verdict per-thread context ----
    CHECK(ihas(rep.verdict, "threads"));

    // ---- Deterministic flame layout (root -> leaf, bounded normalized spans) ----
    CHECK(!rep.flame.empty());
    CHECK(rep.flame.front().symbol == "(all samples)");
    CHECK(rep.flame.front().samples == 10);
    const PrismFlameNode* mainFlame = flame(rep, "app!main");
    const PrismFlameNode* crunchFlame = flame(rep, "app!crunch_pixels");
    CHECK(mainFlame && mainFlame->samples == 10);
    CHECK(crunchFlame && crunchFlame->samples == 3 && crunchFlame->selfSamples == 3);
    CHECK(mainFlame && mainFlame->x0 >= 0.0f && mainFlame->x1 <= 1.0f &&
          mainFlame->x1 > mainFlame->x0);
    CHECK(crunchFlame && mainFlame && crunchFlame->x0 >= mainFlame->x0 &&
          crunchFlame->x1 <= mainFlame->x1);
    PrismReport repeat = BuildPrismReport(samples);
    CHECK(repeat.flame.size() == rep.flame.size());
    if (repeat.flame.size() == rep.flame.size()) {
        for (size_t i = 0; i < rep.flame.size(); ++i) {
            CHECK(repeat.flame[i].symbol == rep.flame[i].symbol);
            CHECK(repeat.flame[i].x0 == rep.flame[i].x0);
            CHECK(repeat.flame[i].x1 == rep.flame[i].x1);
        }
    }

    // ---- Normalized ETW event/quality evidence ----
    {
        PrismCollectionQuality starting;
        starting.collector = PrismCollectorKind::Etw;
        CHECK(!FinalizePrismQuality(std::move(starting)).degraded);

        PrismCollectionQuality q;
        q.collector = PrismCollectorKind::Etw;
        q.stackTracingConfigured = true;
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::SampledProfile, 4, 3);
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::SampledProfile, 1, 0);
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::Image);
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::Thread);
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::ContextSwitch);
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::Wait);
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::IO);
        q.lostEvents = 2;
        q.lostBuffers = 1;
        q = FinalizePrismQuality(std::move(q));
        CHECK(q.sampledEvents == 2 && q.samplesWithStacks == 1);
        CHECK(q.totalFrames == 5 && q.resolvedFrames == 3);
        CHECK(q.stackCoveragePct > 49.0f && q.stackCoveragePct < 51.0f);
        CHECK(q.frameResolutionPct > 59.0f && q.frameResolutionPct < 61.0f);
        CHECK(q.imageEvents == 1 && q.threadEvents == 1 && q.contextSwitchEvents == 1);
        CHECK(q.waitEvents == 1 && q.ioEvents == 1);
        CHECK(q.degraded);
        CHECK(ihas(q.summary, "lost") && ihas(q.summary, "degraded"));

        PrismReport withQuality = BuildPrismReport(samples, q);
        CHECK(withQuality.quality.collector == PrismCollectorKind::Etw);
        CHECK(withQuality.quality.lostEvents == 2);
    }

    // Fallback labels WOW64 honestly and does not claim ETW evidence.
    {
        PrismCollectionQuality q;
        q.collector = PrismCollectorKind::SuspendWalk;
        q.wow64Target = true;
        q.stackTracingConfigured = true;
        AccumulatePrismTraceEvent(q, PrismTraceEventKind::SampledProfile, 3, 2);
        q = FinalizePrismQuality(std::move(q));
        CHECK(ihas(PrismCollectorName(q.collector), "fallback"));
        CHECK(ihas(q.summary, "wow64"));
        CHECK(!q.degraded);
    }

    // Cancellation is explicit and never publishes a partially authoritative report.
    {
        std::stop_source source;
        source.request_stop();
        PrismReport cancelled = BuildPrismReport(samples, {}, source.get_token());
        CHECK(cancelled.cancelled);
    }

    // ---- CPU-bound profile ----
    {
        std::vector<PrismSample> s;
        for (int i = 0; i < 9; ++i) {
            auto x = sample(1, { "app!inner_loop", "app!compute", "app!main" });
            x.cpuCycles = 10; s.push_back(std::move(x));
        }
        s.push_back(sample(1, { "ntdll!NtWaitForSingleObject", "app!main" }));
        PrismReport r = BuildPrismReport(s);
        CHECK(r.states.front().state == ThreadState::Running);
        CHECK(ihas(r.verdict, "thread-state census"));
        CHECK(ihas(r.verdict, "cpu-cycle"));
        CHECK(ihas(r.verdict, "inner_loop"));
    }

    // ---- Lock-contention profile ----
    {
        std::vector<PrismSample> s;
        for (int i = 0; i < 8; ++i) s.push_back(sample(1, { "ntdll!RtlpWaitOnCriticalSection", "ntdll!RtlEnterCriticalSection", "app!take_lock", "app!worker" }));
        for (int i = 0; i < 2; ++i) s.push_back(sample(2, { "app!worker", "app!main" }));
        PrismReport r = BuildPrismReport(s);
        CHECK(r.states.front().state == ThreadState::LockContention);
        CHECK(ihas(r.verdict, "lock contention") || ihas(r.verdict, "critical section"));
    }

    // ---- Allocation-bound profile ----
    {
        std::vector<PrismSample> s;
        for (int i = 0; i < 6; ++i) s.push_back(sample(1, { "ntdll!RtlAllocateHeap", "ucrtbase!malloc", "app!build_node", "app!main" }));
        PrismReport r = BuildPrismReport(s);
        CHECK(r.states.front().state == ThreadState::Allocation);
        CHECK(ihas(r.verdict, "allocator"));
    }

    // ---- Empty profile: benign, no fabricated numbers ----
    {
        PrismReport r = BuildPrismReport({});
        CHECK(r.totalSamples == 0);
        CHECK(r.functions.empty());
        CHECK(ihas(r.headline, "no samples"));
        CHECK(!r.verdict.empty());
    }

    if (g_fail == 0) std::printf("prism_test: ALL PASSED\n");
    else             std::printf("prism_test: %d CHECK(s) FAILED\n", g_fail);
    return g_fail != 0;
}
