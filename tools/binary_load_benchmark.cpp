// Headless production load/analysis benchmark. Targets are read, never executed.
// Build/run with tools/run_binary_load_benchmark.ps1; timing excludes UI adoption,
// visible-page decoding, project sidecars, and symbol-server work.
#include "Core/AnalysisService.h"
#include "Core/BinaryFile.h"
#include "Disasm/DisassemblerFactory.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <windows.h>

namespace {
using Clock = std::chrono::steady_clock;
double runCpuStart = 0;
double processCpuMs() {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return -1;
    const auto ticks = [](FILETIME value) {
        return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    };
    return static_cast<double>(ticks(kernel) + ticks(user)) / 10000.0;
}
double elapsed(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}
uint64_t addHash(uint64_t hash, uint64_t value) {
    for (unsigned i = 0; i != 8; ++i) {
        hash ^= static_cast<uint8_t>(value >> (8 * i));
        hash *= 1099511628211ull;
    }
    return hash;
}
uint64_t addText(uint64_t hash, const std::string& text) {
    hash = addHash(hash, text.size());
    for (unsigned char c : text) { hash ^= c; hash *= 1099511628211ull; }
    return hash;
}
constexpr uint64_t hashSeed = 14695981039346656037ull;
constexpr uint32_t fullKinds = ds::K_Funcs | ds::K_Strings | ds::K_Listing |
    ds::K_Xref | ds::K_Intent | ds::K_CallGraph | ds::K_CrackmeTriage;
// BinaryView requests these; AnalysisService adds K_CallGraph for triage.
constexpr uint32_t requestedKinds = fullKinds & ~ds::K_CallGraph;

void row(unsigned run, const char* phase, double cumulativeMs, uint64_t count,
         uint64_t digest = 0, const char* detail = "") {
    const double cpu = processCpuMs();
    std::printf("%u\t%s\t%.3f\t%.3f\t%llu\t%016llx\t%s\n", run, phase,
                cumulativeMs, cpu >= 0 && runCpuStart >= 0 ? cpu - runCpuStart : -1,
                static_cast<unsigned long long>(count),
                static_cast<unsigned long long>(digest), detail);
    std::fflush(stdout);
}
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 5) {
        std::fprintf(stderr, "Usage: binary_load_benchmark <binary> [runs=3] [warm=0] [timeout-seconds=300]\n");
        return 2;
    }
    unsigned runs = argc > 2 ? static_cast<unsigned>(std::atoi(argv[2])) : 3;
    const bool warm = argc > 3 && std::atoi(argv[3]) != 0;
    const unsigned timeoutSeconds = argc > 4 ? static_cast<unsigned>(std::atoi(argv[4])) : 300;
    if (!runs || runs > 100 || !timeoutSeconds || timeoutSeconds > 3600) return 2;
    std::printf("# Target: %s\n# Derived cache: %s\n# Times: milliseconds since the start of each run; OS file cache is uncontrolled.\n",
                argv[1], warm ? "retained after first run" : "empty on every run");
    std::puts("run\tphase\tcumulative_ms\tprocess_cpu_ms\tcount\tdigest\tdetail");
    ds::BinaryFile binary; // Outlives all service reads; explicitly join before replacement.
    std::unique_ptr<ds::AnalysisService> service;
    for (unsigned run = 1; run <= runs; ++run) {
        if (service) service->cancelAndWaitIdle();
        if (!warm) service.reset();
        const auto start = Clock::now();
        runCpuStart = processCpuMs();
        if (!binary.load(argv[1])) {
            std::fprintf(stderr, "Load failed: %s\n", binary.loadErrorText().c_str());
            return 1;
        }
        row(run, "parsed", elapsed(start), binary.bytes().size());
        const uint64_t contentHash = binary.contentHash();
        row(run, "hashed", elapsed(start), binary.bytes().size(), contentHash);
        if (!service) {
            // A single bulk request executes in one worker in the app as well.
            service = std::make_unique<ds::AnalysisService>(
                ds::AnalysisService::DecoderFactory([](const ds::DecoderConfig& config) {
                    return ds::MakeDisassembler(config);
                }), 1);
        }
        const auto config = ds::DecoderConfigForImage(binary, {});
        const auto epoch = service->bumpEpoch();
        const auto before = service->progress();
        service->requestBulk(&binary, config, requestedKinds, true, epoch);
        uint32_t completed = 0;
        bool failed = false;
        auto drain = [&] {
            ds::AnalysisResult result;
            while (service->tryTakeBulk(result)) {
                if (result.epoch != epoch) continue;
                const double ms = elapsed(start);
                if (result.failureValid) {
                    row(run, "failure", ms, 0, 0, result.failure.c_str());
                    failed = true;
                }
                if (result.stringsValid) {
                    uint64_t hash = hashSeed;
                    for (const auto& value : result.strings) {
                        hash = addText(addHash(addHash(hash, value.address), value.wide), value.text);
                    }
                    row(run, "strings", ms, result.strings.size(), hash,
                        result.stringsTruncated ? "truncated" : "complete");
                    completed |= ds::K_Strings;
                }
                if (result.funcsValid) {
                    uint64_t hash = hashSeed;
                    for (const auto& value : result.functions)
                        hash = addText(addHash(addHash(hash, value.address), value.size), value.name);
                    row(run, "functions", ms, result.functions.size(), hash);
                    completed |= ds::K_Funcs;
                }
                if (result.listingValid) {
                    row(run, "listing", ms, result.listRows.size(), result.listingCodePages);
                    completed |= ds::K_Listing;
                }
                if (result.callGraphValid) {
                    uint64_t hash = hashSeed;
                    for (const auto& edge : result.callEdges)
                        hash = addHash(addHash(hash, edge.from), edge.to);
                    row(run, "call_graph", ms, result.callEdges.size(), hash);
                    completed |= ds::K_CallGraph;
                }
                if (result.xref) {
                    // Order-independent target/edge digest; unordered_map iteration order
                    // is not part of the public xref result contract.
                    uint64_t hash = 0, edges = 0;
                    for (const auto& [target, sources] : result.xref->toTarget) {
                        uint64_t targetHash = addHash(hashSeed, target);
                        for (uint64_t source : sources) targetHash = addHash(targetHash, source);
                        hash ^= targetHash;
                        edges += sources.size();
                    }
                    row(run, "xrefs", ms, edges, hash,
                        result.xref->complete ? "complete" : ds::XrefStopReasonText(result.xref->stopReason));
                    completed |= ds::K_Xref;
                }
                if (result.algosValid) {
                    row(run, "algorithms", ms, result.algos.size());
                    completed |= ds::K_Intent;
                }
                if (result.crackmeTriageValid) {
                    row(run, "triage", ms, result.crackmeTriage.artifacts.size());
                    completed |= ds::K_CrackmeTriage;
                }
                result = {};
            }
        };
        while (service->bulkPending()) {
            drain();
            if (failed || elapsed(start) > timeoutSeconds * 1000.0) {
                service->cancelAndWaitIdle();
                std::fprintf(stderr, "%s\n", failed ? "Analysis failed." : "Analysis timed out.");
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        drain();
        const auto progress = service->progress();
        row(run, "complete", elapsed(start), completed);
        row(run, "cache_hits", elapsed(start), progress.cacheHits - before.cacheHits);
        row(run, "cache_misses", elapsed(start), progress.cacheMisses - before.cacheMisses);
        if (failed || completed != fullKinds || progress.resultsDropped || progress.jobsFailed) {
            service->cancelAndWaitIdle();
            std::fprintf(stderr, "Missing, failed, or dropped analysis results.\n");
            return 1;
        }
    }
    service->cancelAndWaitIdle();
    return 0;
}
