//
// livescan_service_test.cpp
// Unit-tests LiveScanService: worker-pool mechanics plus Strings, Pattern, Xref,
// and ReadImage jobs driven by a STUB memory reader and a STUB decoder, so
// none of Windows / a real Debugger / Zydis is needed.
//
// Compile + run (MSVC dev shell), from the repo root:
//   cl /nologo /std:c++20 /EHsc /D_CRT_SECURE_NO_WARNINGS /I src ^
//      tests\livescan_service_test.cpp src\Core\LiveScanService.cpp src\Core\AnalysisJobs.cpp ^
//      src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp ^
//      src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp
//
#include "Core/LiveScanService.h"
#include "Core/SigMatch.h"
#include "Disasm/IDisassembler.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

// Decoder stub: 0xE8 => a 5-byte "call" with a FIXED branchTarget; anything else a
// 1-byte nop. Lets us plant a known cross-reference for the Xref job.
static const uint64_t kCallTarget = 0xCAFEBABEull;
struct StubDisasm : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "stub"; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || size == 0) return false;
        out = Instruction{};
        out.address = va;
        if (data[0] == 0xE8 && size >= 5) { out.length = 5; out.mnemonic = "call"; out.branchTarget = kCallTarget; }
        else                              { out.length = 1; out.mnemonic = "nop"; }
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t*, size_t, uint64_t, size_t) override { return {}; }
};

struct FailedDisasm final : StubDisasm {
    bool ready() const override { return false; }
    std::string_view errorMessage() const override { return "configured decoder unavailable"; }
};

int main() {
    const uint64_t imgBase = 0x140000000ull;
    // Fake debuggee image: nops, an ASCII string at +0x10, a 0xE8 "call" at +0x40.
    std::vector<uint8_t> mem(0x100, 0x90);
    const char* str = "HelloLiveWorld";
    std::memcpy(mem.data() + 0x10, str, std::strlen(str));
    mem[0x10 + (int)std::strlen(str)] = 0x00;     // terminate the run
    mem[0x40] = 0xE8; mem[0x41] = mem[0x42] = mem[0x43] = mem[0x44] = 0x00;
    const char* str2 = "SecondLiveString";
    std::memcpy(mem.data() + 0x70, str2, std::strlen(str2));
    mem[0x70 + (int)std::strlen(str2)] = 0x00;

    // Stub MemReader over the fake image.
    MemReader reader = [imgBase, &mem](uint64_t va, void* out, size_t n) -> size_t {
        if (va < imgBase) return 0;
        size_t off = (size_t)(va - imgBase);
        if (off >= mem.size()) return 0;
        size_t k = std::min(n, mem.size() - off);
        std::memcpy(out, mem.data() + off, k);
        return k;
    };

    DecoderConfig observedConfig;
    LiveScanService svc([&](const DecoderConfig& config) -> std::unique_ptr<IDisassembler> {
        observedConfig = config;
        if (config.features.armV8) return std::make_unique<FailedDisasm>();
        return std::make_unique<StubDisasm>();
    });

    auto collect = [&](int ms, uint64_t token, LiveScanResult& got) -> bool {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            LiveScanResult tmp;
            while (svc.tryTake(tmp)) {
                if (tmp.token == token && tmp.epoch == svc.epoch()) { got = std::move(tmp); return true; }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    };

    // ---- Strings ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        uint64_t tok = svc.requestStrings(ranges, reader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "strings job produced a result");
        bool found = false;
        for (auto& s : got.strings) if (s.text == "HelloLiveWorld" && s.address == imgBase + 0x10) found = true;
        CHECK(found, "live string scan found the planted ASCII string at the right VA");
    }

    // Exactly filling the cap is complete, while a real omitted result is surfaced.
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        uint64_t tok = svc.requestStrings(ranges, reader, svc.epoch(), 2);
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "exact-cap strings job produced a result");
        CHECK(got.strings.size() == 2 && !got.truncated,
              "exactly filling the live string cap is not falsely marked truncated");

        tok = svc.requestStrings(ranges, reader, svc.epoch(), 1);
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "over-cap strings job produced a result");
        CHECK(got.strings.size() == 1 && got.truncated,
              "live string result reports a genuinely omitted match");

        tok = svc.requestStrings(ranges, reader, svc.epoch(), 100, 0x60);
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "byte-capped strings job produced a result");
        CHECK(got.truncated, "a partial final range reports byte-cap truncation");
    }

    // ---- Masked byte patterns ----
    // Exercise the live worker rather than SigMatch in isolation: the match
    // crosses the worker's read boundary and its wildcard byte is deliberately
    // different from the pattern's placeholder value.  Overlap bytes must make
    // the match visible exactly once, never once per adjacent read.
    {
        constexpr size_t kReadBoundary = 1u << 20;
        const uint64_t patternBase = imgBase + 0x200000;
        std::vector<uint8_t> patternMemory(kReadBoundary + 64, 0x31);
        const size_t matchOffset = kReadBoundary - 2;
        patternMemory[matchOffset + 0] = 0xDE;
        patternMemory[matchOffset + 1] = 0xAD;
        patternMemory[matchOffset + 2] = 0x7F;
        patternMemory[matchOffset + 3] = 0xEF;
        std::atomic<size_t> reads{0};
        MemReader patternReader = [patternBase, &patternMemory, &reads](
                                      uint64_t va, void* out, size_t n) -> size_t {
            ++reads;
            if (va < patternBase) return 0;
            const uint64_t relative = va - patternBase;
            if (relative >= patternMemory.size()) return 0;
            const size_t offset = static_cast<size_t>(relative);
            const size_t count = std::min(n, patternMemory.size() - offset);
            std::memcpy(out, patternMemory.data() + offset, count);
            return count;
        };
        SigPattern pattern;
        CHECK(ParseSignature("DE AD ?? EF", pattern),
              "masked live pattern parses through the shared signature grammar");
        const uint64_t tok = svc.requestPattern(
            {{patternBase, patternMemory.size()}}, pattern, patternReader,
            svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "masked pattern job produced a result");
        CHECK(got.complete && got.error.empty(),
              "masked pattern job completed normally");
        CHECK(got.hits == std::vector<uint64_t>{patternBase + matchOffset},
              "wildcard match crossing a read boundary is returned exactly once");
        CHECK(reads.load() > 1,
              "boundary fixture was split across more than one target-memory read");
        CHECK(!got.truncated &&
              got.scannedBytes == patternMemory.size() &&
              got.attemptedBytes == patternMemory.size() &&
              got.unreadableChunks == 0 && got.partialChunks == 0,
              "an uncapped complete pattern search is not marked truncated");
    }

    // Pattern completions are token-addressable because several Binary View
    // documents share this one service. A document asking for another token
    // must not consume the result, and the generic live-scan drain must be able
    // to take a later non-pattern result without stealing the queued pattern.
    {
        SigPattern pattern;
        CHECK(ParseSignature("E8", pattern), "routed live pattern parses");
        const uint64_t patternToken = svc.requestPattern(
            {{imgBase, mem.size()}}, pattern, reader, svc.epoch());
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
        while (svc.busy() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(!svc.busy(), "routed pattern result reached the completed queue");

        LiveScanResult got;
        CHECK(!svc.tryTakePattern(patternToken + 1000000, got),
              "wrong document token cannot consume a pattern result");

        const uint64_t stringToken = svc.requestStrings(
            {{imgBase, mem.size()}}, reader, svc.epoch());
        deadline = std::chrono::steady_clock::now() +
                   std::chrono::seconds(3);
        while (svc.busy() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(!svc.busy(), "non-pattern result reached the completed queue");
        CHECK(svc.tryTakeNonPattern(got) &&
              got.kind == LiveKind::Strings && got.token == stringToken,
              "non-pattern drain skips a queued document-owned pattern result");

        got = LiveScanResult{};
        CHECK(svc.tryTakePattern(patternToken, got) &&
              got.kind == LiveKind::Pattern && got.token == patternToken &&
              got.hits == std::vector<uint64_t>{imgBase + 0x40},
              "matching document token receives its retained pattern result");
    }

    // Pattern results are retained for their exact token owner even if enough
    // ordinary shared completions arrive to exercise the 256-result eviction
    // bound. The ordinary queue remains bounded independently.
    {
        LiveScanService retentionSvc(LiveScanService::DecoderFactory{});
        SigPattern pattern;
        CHECK(ParseSignature("90", pattern),
              "retained live pattern parses");
        const uint64_t patternToken = retentionSvc.requestPattern(
            {{imgBase, 1}}, pattern, reader, retentionSvc.epoch());
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
        while (retentionSvc.busy() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(!retentionSvc.busy(),
              "retained Pattern completion reached the result queue");

        constexpr size_t kOrdinaryCompletions = 300;
        for (size_t index = 0; index < kOrdinaryCompletions; ++index) {
            retentionSvc.requestStrings(
                {{imgBase, 1}}, reader, retentionSvc.epoch());
        }
        deadline = std::chrono::steady_clock::now() +
                   std::chrono::seconds(3);
        while (retentionSvc.busy() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(!retentionSvc.busy(),
              "ordinary completion pressure returned to idle");

        LiveScanResult got;
        CHECK(retentionSvc.tryTakePattern(patternToken, got) && got.complete &&
              got.hits == std::vector<uint64_t>{imgBase},
              "ordinary result eviction cannot discard a token-owned Pattern completion");
        size_t ordinaryRetained = 0;
        while (retentionSvc.tryTakeNonPattern(got)) ++ordinaryRetained;
        CHECK(ordinaryRetained == 256,
              "ordinary result retention remains independently capped at 256");
    }

    // Per-token cancellation removes queued and already-completed work without
    // advancing the shared epoch or disturbing another document's Pattern job.
    {
        LiveScanService cancelSvc(LiveScanService::DecoderFactory{});
        SigPattern pattern;
        CHECK(ParseSignature("90", pattern), "cancelable live pattern parses");

        // Eight held jobs saturate the service's bounded 1..8 worker pool. The
        // following target is therefore guaranteed to remain queued until it is
        // canceled, regardless of hardware_concurrency().
        std::atomic<bool> releaseBlockers{false};
        MemReader blocker = [&releaseBlockers](uint64_t, void* out,
                                                size_t n) -> size_t {
            while (!releaseBlockers.load(std::memory_order_acquire))
                std::this_thread::yield();
            if (n) static_cast<uint8_t*>(out)[0] = 0x90;
            return std::min<size_t>(n, 1);
        };
        std::vector<uint64_t> blockerTokens;
        for (size_t index = 0; index < 8; ++index)
            blockerTokens.push_back(cancelSvc.requestPattern(
                {{imgBase + index, 1}}, pattern, blocker, cancelSvc.epoch()));
        const uint64_t queuedToken = cancelSvc.requestPattern(
            {{imgBase + 0x80, 1}}, pattern, reader, cancelSvc.epoch());
        cancelSvc.cancelPattern(queuedToken);
        releaseBlockers.store(true, std::memory_order_release);
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
        while (cancelSvc.busy() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(!cancelSvc.busy(), "queued-cancel fixture returned to idle");
        LiveScanResult got;
        CHECK(!cancelSvc.tryTakePattern(queuedToken, got),
              "canceling a queued Pattern prevents its publication");
        size_t blockerResults = 0;
        for (const uint64_t token : blockerTokens) {
            got = LiveScanResult{};
            if (cancelSvc.tryTakePattern(token, got) && got.complete)
                ++blockerResults;
        }
        CHECK(blockerResults == blockerTokens.size(),
              "queued cancellation leaves preceding sibling Pattern jobs intact");

        // Once a result is already queued for adoption, cancelPattern removes
        // only that token and retains a completed sibling result.
        const uint64_t completedToken = cancelSvc.requestPattern(
            {{imgBase, mem.size()}}, pattern, reader, cancelSvc.epoch());
        const uint64_t completedSibling = cancelSvc.requestPattern(
            {{imgBase, mem.size()}}, pattern, reader, cancelSvc.epoch());
        deadline = std::chrono::steady_clock::now() +
                   std::chrono::seconds(3);
        while (cancelSvc.busy() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(!cancelSvc.busy(), "completed-cancel fixture reached idle");
        cancelSvc.cancelPattern(completedToken);
        CHECK(!cancelSvc.tryTakePattern(completedToken, got),
              "canceling a completed Pattern removes its queued result");
        got = LiveScanResult{};
        CHECK(cancelSvc.tryTakePattern(completedSibling, got) && got.complete,
              "completed cancellation retains a sibling Pattern result");
    }

    // Cancellation observed while the target reader is in flight suppresses
    // publication after that reader returns. A sibling request remains eligible
    // and completes under the unchanged service epoch.
    {
        LiveScanService cancelSvc(LiveScanService::DecoderFactory{});
        SigPattern canceledPattern;
        SigPattern siblingPattern;
        CHECK(ParseSignature("90", canceledPattern),
              "in-flight canceled pattern parses");
        CHECK(ParseSignature("E8", siblingPattern),
              "in-flight sibling pattern parses");
        std::atomic<bool> entered{false};
        std::atomic<bool> release{false};
        MemReader heldReader = [&entered, &release](uint64_t, void* out,
                                                    size_t n) -> size_t {
            entered.store(true, std::memory_order_release);
            while (!release.load(std::memory_order_acquire))
                std::this_thread::yield();
            if (n) static_cast<uint8_t*>(out)[0] = 0x90;
            return std::min<size_t>(n, 1);
        };
        const uint64_t canceledToken = cancelSvc.requestPattern(
            {{imgBase, 1}}, canceledPattern, heldReader, cancelSvc.epoch());
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
        while (!entered.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(entered.load(std::memory_order_acquire),
              "canceled Pattern reached its held target-memory reader");

        const uint64_t siblingToken = cancelSvc.requestPattern(
            {{imgBase, mem.size()}}, siblingPattern, reader,
            cancelSvc.epoch());
        cancelSvc.cancelPattern(canceledToken);
        release.store(true, std::memory_order_release);
        deadline = std::chrono::steady_clock::now() +
                   std::chrono::seconds(3);
        while (cancelSvc.busy() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(!cancelSvc.busy(), "in-flight cancellation fixture returned to idle");

        LiveScanResult got;
        CHECK(!cancelSvc.tryTakePattern(canceledToken, got),
              "in-flight canceled Pattern publishes no result");
        CHECK(cancelSvc.tryTakePattern(siblingToken, got) && got.complete &&
              got.hits == std::vector<uint64_t>{imgBase + 0x40},
              "in-flight cancellation leaves sibling Pattern completion intact");
    }

    // Destruction cancels already-running uncapped Pattern work rather than
    // waiting for the remainder of its address range. Saturate every possible
    // worker with a held first read and keep a marker job queued; destruction
    // releases that marker before join, proving its cancellation state is set
    // before the held reads return.
    {
        auto shutdownSvc = std::make_unique<LiveScanService>(
            LiveScanService::DecoderFactory{});
        SigPattern pattern;
        CHECK(ParseSignature("90", pattern),
              "shutdown-cancel live pattern parses");

        unsigned workerCount = std::thread::hardware_concurrency();
        workerCount = workerCount > 3 ? workerCount - 2 : 1;
        workerCount = (std::min)(workerCount, 8u);
        std::atomic<unsigned> reads{0};
        std::atomic<bool> releaseReads{false};
        MemReader heldReader = [&reads, &releaseReads](
                                   uint64_t, void* out, size_t n) -> size_t {
            reads.fetch_add(1, std::memory_order_acq_rel);
            while (!releaseReads.load(std::memory_order_acquire))
                std::this_thread::yield();
            if (n) static_cast<uint8_t*>(out)[0] = 0x90;
            return (std::min)(n, size_t{1});
        };
        constexpr unsigned kMaxWorkers = 8;
        for (unsigned index = 0; index < kMaxWorkers; ++index) {
            shutdownSvc->requestPattern(
                {{imgBase + index * 0x10, 2}}, pattern, heldReader,
                shutdownSvc->epoch(), 0, 0, 1);
        }
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
        while (reads.load(std::memory_order_acquire) < workerCount &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(reads.load(std::memory_order_acquire) == workerCount,
              "shutdown fixture held every live-scan worker in its first read");

        auto queuedMarker = std::make_shared<int>(1);
        std::weak_ptr<int> queuedMarkerLifetime = queuedMarker;
        MemReader queuedReader = [queuedMarker](uint64_t, void* out,
                                                size_t n) -> size_t {
            if (n) static_cast<uint8_t*>(out)[0] = 0x90;
            return (std::min)(n, size_t{1});
        };
        shutdownSvc->requestPattern(
            {{imgBase + 0x1000, 1}}, pattern, std::move(queuedReader),
            shutdownSvc->epoch(), 0, 0, 1);
        queuedReader = {};
        queuedMarker.reset();
        CHECK(!queuedMarkerLifetime.expired(),
              "shutdown marker remains owned by a queued Pattern job");

        std::atomic<bool> destroyed{false};
        std::thread destroyer(
            [service = std::move(shutdownSvc), &destroyed]() mutable {
                service.reset();
                destroyed.store(true, std::memory_order_release);
            });
        deadline = std::chrono::steady_clock::now() +
                   std::chrono::seconds(1);
        while (!queuedMarkerLifetime.expired() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(queuedMarkerLifetime.expired(),
              "destruction drops queued Pattern jobs before waiting for workers");

        const unsigned readsAtCancellation =
            reads.load(std::memory_order_acquire);
        releaseReads.store(true, std::memory_order_release);
        destroyer.join();
        CHECK(destroyed.load(std::memory_order_acquire),
              "LiveScanService destruction completed after the held read returned");
        CHECK(reads.load(std::memory_order_acquire) == readsAtCancellation,
              "shutdown cancellation prevents another uncapped Pattern chunk read");
    }

    // A result cap reports real omission, while byteCap == 0 means uncapped.
    // The explicit byte cap is measured over unique target bytes, not overlap
    // reads, and therefore excludes the second planted match predictably.
    {
        const uint64_t patternBase = imgBase + 0x400000;
        const std::vector<uint8_t> patternMemory = {
            0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00,
            0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00,
        };
        MemReader patternReader = [patternBase, &patternMemory](
                                      uint64_t va, void* out, size_t n) -> size_t {
            if (va < patternBase) return 0;
            const uint64_t relative = va - patternBase;
            if (relative >= patternMemory.size()) return 0;
            const size_t offset = static_cast<size_t>(relative);
            const size_t count = std::min(n, patternMemory.size() - offset);
            std::memcpy(out, patternMemory.data() + offset, count);
            return count;
        };
        SigPattern pattern;
        CHECK(ParseSignature("AA BB CC DD", pattern),
              "concrete live pattern parses");

        uint64_t tok = svc.requestPattern(
            {{patternBase, patternMemory.size()}}, pattern, patternReader,
            svc.epoch(), 1, 0);
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "hit-capped pattern job produced a result");
        CHECK(got.hits == std::vector<uint64_t>{patternBase + 2} && got.truncated,
              "pattern hit cap retains the first hit and reports omitted hits");

        tok = svc.requestPattern(
            {{patternBase, patternMemory.size()}}, pattern, patternReader,
            svc.epoch(), 16, 8);
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "byte-capped pattern job produced a result");
        CHECK(got.hits == std::vector<uint64_t>{patternBase + 2} &&
              got.truncated && got.scannedBytes == 8 && got.attemptedBytes == 8,
              "explicit byte cap keeps in-budget matches and reports a partial scan");

        tok = svc.requestPattern(
            {{patternBase, patternMemory.size()}}, pattern, patternReader,
            svc.epoch(), 16, 0);
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "uncapped pattern job produced a result");
        CHECK((got.hits == std::vector<uint64_t>{patternBase + 2,
                                                 patternBase + 10} &&
               !got.truncated &&
               got.scannedBytes == patternMemory.size() &&
               got.attemptedBytes == patternMemory.size()),
              "zero byte cap scans the complete range without the legacy cutoff");
    }

    // Short and zero target-memory reads are successful partial scans: bytes
    // actually returned can still match, but the result must not claim complete
    // coverage of the requested address range.
    {
        const uint64_t patternBase = imgBase + 0x500000;
        const std::vector<uint8_t> patternMemory = {
            0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40,
        };
        SigPattern pattern;
        CHECK(ParseSignature("DE AD BE EF", pattern),
              "partial-read live pattern parses");
        MemReader shortReader = [patternBase, &patternMemory](
                                    uint64_t va, void* out, size_t n) -> size_t {
            if (va != patternBase || !n) return 0;
            const size_t count = std::min<size_t>({n, patternMemory.size(), 4});
            std::memcpy(out, patternMemory.data(), count);
            return count;
        };
        uint64_t tok = svc.requestPattern(
            {{patternBase, 32}}, pattern, shortReader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "short-read pattern job produced a result");
        CHECK(got.hits == std::vector<uint64_t>{patternBase},
              "bytes returned by a short read are still searched");
        CHECK(got.complete && !got.truncated &&
              got.scannedBytes == 4 && got.attemptedBytes == 32 &&
              got.partialChunks == 1 && got.unreadableChunks == 0,
              "short read is a completed scan with explicit partial coverage");

        MemReader zeroReader = [](uint64_t, void*, size_t) -> size_t { return 0; };
        tok = svc.requestPattern(
            {{patternBase, 32}}, pattern, zeroReader, svc.epoch());
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "zero-read pattern job produced a result");
        CHECK(got.complete && got.hits.empty() && !got.truncated &&
              got.scannedBytes == 0 && got.attemptedBytes == 32 &&
              got.partialChunks == 0 && got.unreadableChunks == 1,
              "unreadable live range has explicit zero-read coverage diagnostics");
    }

    // Pattern results carry the same epoch ownership as the other live jobs.
    // Hold the reader until the caller supersedes the request so this cannot
    // pass merely because a tiny job happened to finish before bumpEpoch().
    {
        SigPattern pattern;
        CHECK(ParseSignature("90", pattern), "epoch-gated live pattern parses");
        std::atomic<bool> entered{false};
        std::atomic<bool> release{false};
        MemReader heldReader = [&entered, &release](uint64_t, void* out,
                                                    size_t n) -> size_t {
            entered.store(true, std::memory_order_release);
            while (!release.load(std::memory_order_acquire))
                std::this_thread::yield();
            if (n) static_cast<uint8_t*>(out)[0] = 0x90;
            return std::min<size_t>(n, 1);
        };
        const uint64_t oldEpoch = svc.epoch();
        const uint64_t tok = svc.requestPattern(
            {{imgBase, 1}}, pattern, heldReader, oldEpoch);
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(3);
        while (!entered.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(entered.load(std::memory_order_acquire),
              "held pattern job reached the identity-bound reader");
        svc.bumpEpoch();
        release.store(true, std::memory_order_release);
        const auto idleDeadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(3);
        while (svc.busy() && std::chrono::steady_clock::now() < idleDeadline)
            std::this_thread::yield();
        CHECK(!svc.busy(), "superseded pattern job returned from its reader");
        LiveScanResult stale;
        bool published = false;
        while (svc.tryTake(stale))
            if (stale.token == tok) published = true;
        CHECK(!published,
              "superseded pattern result is not published for a new live owner");
    }

    // ---- Xref ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        uint64_t tok = svc.requestXref(ranges, kCallTarget, Engine::Zydis, Arch::X64, reader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "xref job produced a result");
        bool hit = false;
        for (uint64_t a : got.hits) if (a == imgBase + 0x40) hit = true;
        CHECK(hit, "live xref found the call referencing the target at +0x40");
        CHECK(got.target == kCallTarget, "xref result echoes the target");
        CHECK(got.complete && got.error.empty(), "successful xref is explicitly complete");
    }

    // Full decoder configuration reaches the private worker decoder, and a
    // decoder initialization failure is a result rather than an empty success.
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        DecoderConfig config;
        config.engine = Engine::Capstone;
        config.arch = Arch::PPC64;
        config.byteOrder = ByteOrder::Big;
        config.features.riscvCompressed = false;
        uint64_t tok = svc.requestXref(ranges, kCallTarget, config, reader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "configured xref job produced a result");
        CHECK(observedConfig == config, "live xref preserved byte order and feature bits");
        CHECK(got.complete && got.error.empty(), "configured decoder completed normally");

        config.features.armV8 = true; // fixture's explicit failure switch
        tok = svc.requestXref(ranges, kCallTarget, config, reader, svc.epoch());
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "failed-decoder xref published a result");
        CHECK(!got.complete && !got.error.empty() && got.hits.empty(),
              "failed decoder is not reported as an empty successful xref");
        CHECK(got.error.find("configured decoder unavailable") != std::string::npos,
              "failed decoder reason is preserved");
    }

    // ---- ReadImage ----
    {
        uint64_t tok = svc.requestReadImage(imgBase, 0x80, /*moduleBase=*/imgBase, reader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "read-image job produced a result");
        CHECK(got.image.size() == 0x80, "read-image returned the requested span");
        CHECK(got.moduleBase == imgBase, "read-image echoes the module base");
        CHECK(!got.image.empty() && got.image[0x10] == (uint8_t)'H', "read-image bytes match the source");
    }

    // An exception from a target-memory reader is reported as a failed job and
    // does not escape the worker thread or poison the pool.
    {
        MemReader throwingReader = [](uint64_t, void*, size_t) -> size_t {
            throw std::runtime_error("fixture read failure");
        };
        uint64_t tok = svc.requestReadImage(imgBase, 0x20, imgBase,
                                            throwingReader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "throwing reader produced a failure result");
        CHECK(!got.complete && got.error.find("fixture read failure") != std::string::npos,
              "worker exception text is preserved");

        tok = svc.requestReadImage(imgBase, 0x20, imgBase, reader, svc.epoch());
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "pool accepted a job after worker exception");
        CHECK(got.complete && got.image.size() == 0x20,
              "post-exception worker result completed normally");
    }

    // ---- Epoch gating: a bumped epoch means no result is accepted as current ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        svc.requestStrings(ranges, reader, svc.epoch());
        svc.bumpEpoch();
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
        while (std::chrono::steady_clock::now() < deadline) {
            LiveScanResult got;
            if (svc.tryTake(got)) CHECK(got.epoch != svc.epoch(), "superseded live result not current-epoch");
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // ---- cancelAndWaitIdle leaves the pool idle ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        svc.requestStrings(ranges, reader, svc.epoch());
        svc.cancelAndWaitIdle();
        CHECK(!svc.busy(), "not busy after cancelAndWaitIdle");
    }

    // The historical two-argument factory remains source compatible.
    {
        LiveScanService legacy([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<StubDisasm>();
        });
        legacy.cancelAndWaitIdle();
    }

    if (g_fail == 0) std::printf("livescan_service_test: all checks passed\n");
    else             std::printf("livescan_service_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
