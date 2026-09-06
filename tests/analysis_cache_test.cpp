#include "Core/AnalysisCache.h"
#include "Core/Project.h"

#include <cstdio>
#include <memory>
#include <vector>

using namespace ds;

namespace {
int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++failures; } } while (0)
}

int main() {
    CHECK(kAnalysisSchemaVersion == 6,
          "classification-aware references and typed address semantics use analysis schema version 6");
    // Patch history order is semantic: later overlapping writes win. The digest
    // must distinguish the same records in the opposite application order.
    PjPatch first{ 0x1000, { 0x10, 0x11 }, { 0xA0, 0xA1 } };
    PjPatch second{ 0x1001, { 0x11, 0x12 }, { 0xB0, 0xB1 } };
    const std::vector<PjPatch> forward{ first, second };
    const std::vector<PjPatch> reverse{ second, first };
    CHECK(DigestOrderedPatches({}) == 0, "empty patch history has canonical digest zero");
    CHECK(DigestOrderedPatches(forward) != DigestOrderedPatches(reverse),
          "ordered patch digest changes when overlapping application order changes");

    ProjectAnalysisOverrides overrides;
    overrides.functions.push_back({ 0, PjFunctionAction::Define, true, 8,
                                    PjOverrideBool::True, "__stdcall",
                                    "void root(void)", PjFunctionMode::Thumb });
    overrides.data.push_back({ 0x20, 16, PjDataKind::JumpTable, "uint32_t[4]" });
    const uint64_t overrideA = DigestAnalysisOverrides(&overrides);
    overrides.functions[0].noreturn = PjOverrideBool::False;
    const uint64_t overrideB = DigestAnalysisOverrides(&overrides);
    CHECK(overrideA && overrideB && overrideA != overrideB,
          "every authoritative override field invalidates the digest");
    const ProjectAnalysisOverrides emptyOverrides;
    CHECK(DigestAnalysisOverrides(nullptr) == 0 &&
          DigestAnalysisOverrides(&emptyOverrides) == 0,
          "null and empty override snapshots share the canonical digest");

    const uint64_t patchDigest = DigestOrderedPatches(forward);
    const AnalysisCacheKey zydis = MakeAnalysisCacheKey(
        0x1234, patchDigest, Arch::X64, Engine::Zydis, true, overrideA,
        AnalysisCachePass::Functions, 0x55);
    const AnalysisCacheKey capstone = MakeAnalysisCacheKey(
        0x1234, patchDigest, Arch::X64, Engine::Capstone, true, overrideA,
        AnalysisCachePass::Functions, 0x55);
    const AnalysisCacheKey newerSchema = MakeAnalysisCacheKey(
        0x1234, patchDigest, Arch::X64, Engine::Zydis, true, overrideA,
        AnalysisCachePass::Functions, 0x55, kAnalysisSchemaVersion + 1);
    const AnalysisCacheKey changedOverride = MakeAnalysisCacheKey(
        0x1234, patchDigest, Arch::X64, Engine::Zydis, true, overrideB,
        AnalysisCachePass::Functions, 0x55);
    CHECK(!(zydis == capstone), "x86 decoder backend participates in the key");
    CHECK(!(zydis == newerSchema), "analysis schema version participates in the key");
    CHECK(!(zydis == changedOverride), "analyst override digest participates in the key");
    const AnalysisCacheKey triageKey = MakeAnalysisCacheKey(
        0x1234, patchDigest, Arch::X64, Engine::Zydis, true, overrideA,
        AnalysisCachePass::CrackmeTriage, 0x55);
    CHECK(!(zydis == triageKey), "crackme triage has a distinct derived-pass identity");

    const AnalysisCacheKey armRequestedZydis = MakeAnalysisCacheKey(
        0x1234, 0, Arch::ARM64, Engine::Zydis, false, 0,
        AnalysisCachePass::Xref);
    const AnalysisCacheKey armRequestedCapstone = MakeAnalysisCacheKey(
        0x1234, 0, Arch::ARM64, Engine::Capstone, false, 0,
        AnalysisCachePass::Xref);
    CHECK(armRequestedZydis == armRequestedCapstone,
          "non-x86 cosmetic backend choices normalize to the effective decoder");

    DecoderConfig riscv;
    riscv.engine = Engine::Capstone;
    riscv.arch = Arch::RISCV64;
    const AnalysisCacheKey riscvDefault = MakeAnalysisCacheKey(
        0x1234, 0, riscv, false, 0, AnalysisCachePass::Listing);
    riscv.features.riscvCompressed = false;
    const AnalysisCacheKey riscvNoCompressed = MakeAnalysisCacheKey(
        0x1234, 0, riscv, false, 0, AnalysisCachePass::Listing);
    riscv.byteOrder = ByteOrder::Big;
    const AnalysisCacheKey riscvBigEndian = MakeAnalysisCacheKey(
        0x1234, 0, riscv, false, 0, AnalysisCachePass::Listing);
    CHECK(!(riscvDefault == riscvNoCompressed),
          "decoder feature bits participate in the cache identity");
    CHECK(!(riscvNoCompressed == riscvBigEndian),
          "decoder byte order participates in the cache identity");

    AnalysisCache cache(/*maxEntries=*/2, /*maxBytes=*/1024);
    cache.put<int>(zydis, std::make_shared<const int>(11), sizeof(int));
    CHECK(cache.find<int>(zydis) && *cache.find<int>(zydis) == 11,
          "cache returns a typed immutable payload");
    CHECK(!cache.find<int>(capstone), "decoder mismatch is a cache miss");
    CHECK(!cache.find<int>(newerSchema), "schema mismatch is a cache miss");
    CHECK(!cache.find<int>(changedOverride), "override mismatch is a cache miss");

    // Fill the second slot, touch the first, then insert a third: true LRU must
    // evict the untouched second entry rather than insertion-order FIFO.
    AnalysisCacheKey secondKey = zydis;
    secondKey.pristineHash = 2;
    AnalysisCacheKey thirdKey = zydis;
    thirdKey.pristineHash = 3;
    cache.put<int>(secondKey, std::make_shared<const int>(22), sizeof(int));
    CHECK(cache.find<int>(zydis) != nullptr, "LRU touch succeeds");
    cache.put<int>(thirdKey, std::make_shared<const int>(33), sizeof(int));
    CHECK(cache.find<int>(zydis) != nullptr, "recently used entry survives eviction");
    CHECK(!cache.find<int>(secondKey), "least recently used entry is evicted");
    CHECK(cache.find<int>(thirdKey) && *cache.find<int>(thirdKey) == 33,
          "new entry is retained after eviction");

    const AnalysisCacheStats stats = cache.stats();
    CHECK(stats.entries == 2 && stats.evictions == 1,
          "bounded cache reports entry and eviction counters");
    CHECK(stats.hits > 0 && stats.misses > 0 && stats.inserts == 3,
          "cache reports deterministic hit/miss/insert counters");

    if (!failures) std::printf("analysis_cache_test: all checks passed\n");
    return failures ? 1 : 0;
}
