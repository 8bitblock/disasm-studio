// Pure tests for bounded pointer backlink discovery and chain resolution.
#include "Core/MemoryPointer.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <stdexcept>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void putLe(std::vector<uint8_t>& bytes, uint64_t blockBase,
                  uint64_t address, uint64_t value, uint8_t width) {
    const size_t offset = static_cast<size_t>(address - blockBase);
    for (uint8_t i = 0; i < width; ++i)
        bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

static const MemoryPointerChain* findChain(
    const MemoryPointerSearchResult& result, uint64_t root, uint64_t target,
    std::initializer_list<uint64_t> offsets) {
    for (const auto& chain : result.chains) {
        if (chain.rootAddress == root && chain.targetAddress == target &&
            chain.offsets == std::vector<uint64_t>(offsets))
            return &chain;
    }
    return nullptr;
}

static MemoryPointerReader mapReader(const std::map<uint64_t, uint64_t>& values,
                                     uint8_t width) {
    return [&values, width](uint64_t address, void* output, size_t size) -> size_t {
        auto it = values.find(address);
        if (it == values.end() || size != width) return 0;
        auto* out = static_cast<uint8_t*>(output);
        for (uint8_t i = 0; i < width; ++i)
            out[i] = static_cast<uint8_t>(it->second >> (i * 8));
        return width;
    };
}

int main() {
    CHECK(MemoryPointerAddressCanonical(0, 4));
    CHECK(MemoryPointerAddressCanonical(UINT32_MAX, 4));
    CHECK(!MemoryPointerAddressCanonical(uint64_t{UINT32_MAX} + 1, 4));
    CHECK(MemoryPointerAddressCanonical(0x00007FFFFFFFFFFFull, 8));
    CHECK(!MemoryPointerAddressCanonical(0x0000800000000000ull, 8));
    CHECK(MemoryPointerAddressCanonical(0xFFFF800000000000ull, 8));
    CHECK(!MemoryPointerAddressCanonical(0xFFFF000000000000ull, 8));
    CHECK(!MemoryPointerAddressCanonical(0, 2));

    // One-level x64 backlinks use inclusive, non-negative offsets. A pointer
    // above the target (negative offset), one just outside the bound, and null
    // filler must not become chains.
    std::vector<uint8_t> basicBytes(0x80, 0);
    putLe(basicBytes, 0x1000, 0x1010, 0x4FF0, 8);
    putLe(basicBytes, 0x1000, 0x1020, 0x5000, 8);
    putLe(basicBytes, 0x1000, 0x1030, 0x5001, 8);
    putLe(basicBytes, 0x1000, 0x1040, 0x4FDF, 8);
    const MemoryPointerBlock basicBlock{ 0x1000, basicBytes };
    const uint64_t basicTarget = 0x5000;
    MemoryPointerSearchOptions options;
    options.pointerWidth = 8;
    options.maxDepth = 1;
    options.maxOffset = 0x20;
    auto basic = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&basicBlock, 1),
        std::span<const uint64_t>(&basicTarget, 1), options);
    CHECK(basic.status == MemoryPointerSearchStatus::Complete);
    CHECK(basic.chains.size() == 2);
    CHECK(findChain(basic, 0x1010, 0x5000, { 0x10 }));
    CHECK(findChain(basic, 0x1020, 0x5000, { 0 }));
    CHECK(basic.stats.depthsCompleted == 1);

    // A single stored pointer can backlink to multiple frontier targets.
    std::vector<uint8_t> multiBytes(16, 0);
    putLe(multiBytes, 0x1800, 0x1800, 0x6000, 8);
    const MemoryPointerBlock multiBlock{ 0x1800, multiBytes };
    const uint64_t multiTargets[] = { 0x6020, 0x6010, 0x6010 };
    options.maxDepth = 1;
    options.maxOffset = 0x20;
    auto multi = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&multiBlock, 1), multiTargets, options);
    CHECK(multi.status == MemoryPointerSearchStatus::Complete);
    CHECK(multi.chains.size() == 2);
    CHECK(findChain(multi, 0x1800, 0x6010, { 0x10 }));
    CHECK(findChain(multi, 0x1800, 0x6020, { 0x20 }));
    CHECK(multi.chains[0].targetAddress < multi.chains[1].targetAddress);

    // Build and resolve a two-level chain:
    //   [0x1010] = 0x1FF0; +0x10 -> 0x2000
    //   [0x2000] = 0x2FE0; +0x20 -> 0x3000
    std::vector<uint8_t> deepBytes(0x1100, 0);
    putLe(deepBytes, 0x1000, 0x1010, 0x1FF0, 8);
    putLe(deepBytes, 0x1000, 0x2000, 0x2FE0, 8);
    const MemoryPointerBlock deepBlock{ 0x1000, deepBytes };
    const uint64_t deepTarget = 0x3000;
    options.maxDepth = 2;
    options.maxOffset = 0x20;
    auto deep = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&deepBlock, 1),
        std::span<const uint64_t>(&deepTarget, 1), options);
    CHECK(deep.status == MemoryPointerSearchStatus::Complete);
    CHECK(findChain(deep, 0x2000, 0x3000, { 0x20 }));
    const auto* deepChain = findChain(deep, 0x1010, 0x3000, { 0x10, 0x20 });
    CHECK(deepChain != nullptr);
    CHECK(deep.stats.depthsCompleted == 2);

    const std::map<uint64_t, uint64_t> deepMemory = {
        { 0x1010, 0x1FF0 }, { 0x2000, 0x2FE0 }
    };
    const uint64_t deepOffsets[] = { 0x10, 0x20 };
    auto resolved = ResolveMemoryPointerChain(mapReader(deepMemory, 8), 8, 0x1010,
                                              deepOffsets);
    CHECK(resolved.resolved());
    CHECK(resolved.address == 0x3000 && resolved.stepsResolved == 2);
    CHECK((resolved.addresses == std::vector<uint64_t>{ 0x1010, 0x2000, 0x3000 }));
    CHECK((resolved.pointerValues == std::vector<uint64_t>{ 0x1FF0, 0x2FE0 }));

    // A reverse edge back into an existing path is a cycle, not a deeper chain.
    std::vector<uint8_t> cycleBytes(0x1010, 0);
    putLe(cycleBytes, 0x1000, 0x1000, 0x2000, 8);
    putLe(cycleBytes, 0x1000, 0x2000, 0x1000, 8);
    const MemoryPointerBlock cycleBlock{ 0x1000, cycleBytes };
    const uint64_t cycleTarget = 0x2000;
    options.maxDepth = 4;
    options.maxOffset = 0;
    auto cycle = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&cycleBlock, 1),
        std::span<const uint64_t>(&cycleTarget, 1), options);
    CHECK(cycle.status == MemoryPointerSearchStatus::Complete);
    CHECK(cycle.chains.size() == 1);
    CHECK(findChain(cycle, 0x1000, 0x2000, { 0 }));
    CHECK(cycle.stats.rejectedCycles >= 1);

    // Alignment is based on the absolute storage VA, not the block's offset.
    std::vector<uint8_t> unalignedBytes(32, 0);
    putLe(unalignedBytes, 0x1001, 0x1002, 0x6FF8, 8);
    const MemoryPointerBlock unalignedBlock{ 0x1001, unalignedBytes };
    const uint64_t unalignedTarget = 0x7000;
    options.maxDepth = 1;
    options.maxOffset = 8;
    options.allowUnaligned = false;
    auto alignedOnly = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&unalignedBlock, 1),
        std::span<const uint64_t>(&unalignedTarget, 1), options);
    CHECK(!findChain(alignedOnly, 0x1002, 0x7000, { 8 }));
    options.allowUnaligned = true;
    auto withUnaligned = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&unalignedBlock, 1),
        std::span<const uint64_t>(&unalignedTarget, 1), options);
    CHECK(findChain(withUnaligned, 0x1002, 0x7000, { 8 }));

    std::vector<uint8_t> shiftedBytes(24, 0);
    putLe(shiftedBytes, 0x1001, 0x1008, 0x6FF8, 8);
    const MemoryPointerBlock shiftedBlock{ 0x1001, shiftedBytes };
    options.allowUnaligned = false;
    auto shifted = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&shiftedBlock, 1),
        std::span<const uint64_t>(&unalignedTarget, 1), options);
    CHECK(findChain(shifted, 0x1008, 0x7000, { 8 }));

    // Pointer width belongs to the target. A 32-bit scan reads only four bytes
    // even though this test executable and the bytes beside it are 64-bit.
    std::vector<uint8_t> wowBytes(16, 0xAA);
    putLe(wowBytes, 0x4000, 0x4000, 0x7FF0, 4);
    const MemoryPointerBlock wowBlock{ 0x4000, wowBytes };
    const uint64_t wowTarget = 0x8000;
    options.pointerWidth = 4;
    options.maxDepth = 1;
    options.maxOffset = 0x10;
    auto wow = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&wowBlock, 1),
        std::span<const uint64_t>(&wowTarget, 1), options);
    CHECK(findChain(wow, 0x4000, 0x8000, { 0x10 }));
    const uint64_t tooHigh32 = 0x100000000ull;
    auto impossibleWow = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&wowBlock, 1),
        std::span<const uint64_t>(&tooHigh32, 1), options);
    CHECK(impossibleWow.chains.empty());

    const std::map<uint64_t, uint64_t> wowMemory = { { 0x4000, 0x7FF0 } };
    const uint64_t wowOffset = 0x10;
    auto wowResolved = ResolveMemoryPointerChain(mapReader(wowMemory, 4), 4,
                                                 0x4000,
                                                 std::span<const uint64_t>(&wowOffset, 1));
    CHECK(wowResolved.resolved() && wowResolved.address == 0x8000);

    // Overlapping input blocks and duplicate targets do not duplicate output.
    const MemoryPointerBlock duplicateBlocks[] = { basicBlock, basicBlock };
    const uint64_t duplicateTargets[] = { basicTarget, basicTarget };
    options.pointerWidth = 8;
    options.maxDepth = 1;
    options.maxOffset = 0x20;
    auto deduped = FindMemoryPointerChains(duplicateBlocks, duplicateTargets, options);
    CHECK(deduped.status == MemoryPointerSearchStatus::Complete);
    CHECK(deduped.chains.size() == 2);

    // Invalid/non-canonical values and an overflowing block extent are skipped.
    std::vector<uint8_t> unsafeBytes(16, 0);
    putLe(unsafeBytes, 0x8000, 0x8000, 0x0000800000000000ull, 8);
    const MemoryPointerBlock unsafeBlocks[] = {
        { 0x8000, unsafeBytes },
        { UINT64_MAX - 3, std::span<const uint8_t>(unsafeBytes.data(), 8) }
    };
    const uint64_t unsafeTarget = 0x9000;
    options.requireCanonical = true;
    auto unsafe = FindMemoryPointerChains(unsafeBlocks,
        std::span<const uint64_t>(&unsafeTarget, 1), options);
    CHECK(unsafe.chains.empty());
    CHECK(unsafe.stats.skippedInvalidBlocks == 1);

    // Exact limit occupancy is complete; discovering one more unique result is
    // explicitly truncated. Candidate and frontier work limits are likewise
    // surfaced rather than returning a misleading complete result.
    options.requireCanonical = true;
    options.maxResults = 2;
    auto exactCap = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&basicBlock, 1),
        std::span<const uint64_t>(&basicTarget, 1), options);
    CHECK(exactCap.status == MemoryPointerSearchStatus::Complete);
    CHECK(exactCap.chains.size() == 2);
    options.maxResults = 1;
    auto overCap = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&basicBlock, 1),
        std::span<const uint64_t>(&basicTarget, 1), options);
    CHECK(overCap.status == MemoryPointerSearchStatus::Truncated);
    CHECK(overCap.chains.size() == 1);
    // The second hit is at offset 0x20. Once it exceeds the result budget,
    // no later pointer-sized slot in this block may be read.
    CHECK(overCap.stats.candidateReads == 5);

    options.maxResults = 100;
    options.maxCandidateReads = 1;
    auto candidateCap = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&basicBlock, 1),
        std::span<const uint64_t>(&basicTarget, 1), options);
    CHECK(candidateCap.status == MemoryPointerSearchStatus::Truncated);
    CHECK(candidateCap.stats.candidateReads == 1);

    options.maxCandidateReads = 1000;
    options.maxComparisons = 1;
    auto comparisonCap = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&multiBlock, 1), multiTargets, options);
    CHECK(comparisonCap.status == MemoryPointerSearchStatus::Truncated);
    CHECK(comparisonCap.stats.comparisons == 1);
    CHECK(comparisonCap.stats.candidateReads == 1);
    options.maxComparisons = 1000;

    // A frontier overflow must stop the current block as well as later
    // blocks/depths. Sparse trailing data can otherwise consume millions of
    // candidate reads after the search has already decided to stop.
    auto frontierOptions = options;
    frontierOptions.maxDepth = 2;
    frontierOptions.maxFrontier = 1;
    auto frontierCap = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&basicBlock, 1),
        std::span<const uint64_t>(&basicTarget, 1), frontierOptions);
    CHECK(frontierCap.status == MemoryPointerSearchStatus::Truncated);
    CHECK(frontierCap.stats.candidateReads == 5);
    CHECK(frontierCap.stats.depthsCompleted == 0);

    options.maxSeedTargets = 1;
    auto targetAdmissionCap = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&multiBlock, 1), multiTargets, options);
    CHECK(targetAdmissionCap.status == MemoryPointerSearchStatus::Truncated);
    CHECK(targetAdmissionCap.stats.seedTargetsExamined == 1);
    CHECK(targetAdmissionCap.chains.size() == 1);
    CHECK(targetAdmissionCap.chains[0].targetAddress == 0x6020); // admitted prefix
    options.maxSeedTargets = 100;

    options.maxBlockVisits = 1;
    auto blockAdmissionCap = FindMemoryPointerChains(duplicateBlocks, duplicateTargets, options);
    CHECK(blockAdmissionCap.status == MemoryPointerSearchStatus::Truncated);
    CHECK(blockAdmissionCap.stats.blockVisits == 1);
    options.maxBlockVisits = 100;

    options.maxFrontier = 1;
    auto seedCap = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&multiBlock, 1), multiTargets, options);
    CHECK(seedCap.status == MemoryPointerSearchStatus::Truncated);
    CHECK(seedCap.chains.size() == 1);
    CHECK(seedCap.chains[0].targetAddress == 0x6010); // deterministic smallest seed

    // Cooperative cancellation is observed before scanning bytes.
    options.maxFrontier = 100;
    options.cancelled = [] { return true; };
    auto cancelled = FindMemoryPointerChains(
        std::span<const MemoryPointerBlock>(&basicBlock, 1),
        std::span<const uint64_t>(&basicTarget, 1), options);
    CHECK(cancelled.status == MemoryPointerSearchStatus::Cancelled);
    CHECK(cancelled.stats.candidateReads == 0);
    options.cancelled = {};

    // Invalid option values cannot silently fall back to host pointer width or
    // unbounded work.
    auto invalidOptions = options;
    invalidOptions.pointerWidth = 2;
    CHECK(FindMemoryPointerChains(
              std::span<const MemoryPointerBlock>(&basicBlock, 1),
              std::span<const uint64_t>(&basicTarget, 1), invalidOptions).status ==
          MemoryPointerSearchStatus::InvalidOptions);
    invalidOptions = options;
    invalidOptions.maxDepth = kMemoryPointerHardMaxDepth + 1;
    CHECK(FindMemoryPointerChains(
              std::span<const MemoryPointerBlock>(&basicBlock, 1),
              std::span<const uint64_t>(&basicTarget, 1), invalidOptions).status ==
          MemoryPointerSearchStatus::InvalidOptions);

    // Resolver failures preserve the last successfully resolved address and do
    // not coerce partial reads, nulls, exceptions, or bad arithmetic to success.
    const uint64_t oneOffset = 1;
    auto partial = ResolveMemoryPointerChain(
        [](uint64_t, void*, size_t size) { return size - 1; },
        8, 0x1000, std::span<const uint64_t>(&oneOffset, 1));
    CHECK(partial.status == MemoryPointerResolveStatus::ReadFailure);
    CHECK(partial.address == 0x1000 && partial.stepsResolved == 0);

    auto throwing = ResolveMemoryPointerChain(
        [](uint64_t, void*, size_t) -> size_t { throw std::runtime_error("reader"); },
        8, 0x1000, std::span<const uint64_t>(&oneOffset, 1));
    CHECK(throwing.status == MemoryPointerResolveStatus::ReaderException);

    const std::map<uint64_t, uint64_t> nullMemory = { { 0x1000, 0 } };
    auto nullResult = ResolveMemoryPointerChain(mapReader(nullMemory, 8), 8,
        0x1000, std::span<const uint64_t>(&oneOffset, 1));
    CHECK(nullResult.status == MemoryPointerResolveStatus::NullPointer);

    const std::map<uint64_t, uint64_t> noncanonicalMemory = {
        { 0x1000, 0x0000800000000000ull }
    };
    auto noncanonical = ResolveMemoryPointerChain(mapReader(noncanonicalMemory, 8), 8,
        0x1000, std::span<const uint64_t>(&oneOffset, 1));
    CHECK(noncanonical.status == MemoryPointerResolveStatus::NonCanonicalPointer);

    const std::map<uint64_t, uint64_t> overflowMemory = { { 0x1000, UINT64_MAX - 3 } };
    const uint64_t ten = 10;
    auto overflow = ResolveMemoryPointerChain(mapReader(overflowMemory, 8), 8,
        0x1000, std::span<const uint64_t>(&ten, 1), false);
    CHECK(overflow.status == MemoryPointerResolveStatus::ArithmeticOverflow);

    const std::map<uint64_t, uint64_t> overflow32Memory = { { 0x1000, 0xFFFFFFF8u } };
    auto overflow32 = ResolveMemoryPointerChain(mapReader(overflow32Memory, 4), 4,
        0x1000, std::span<const uint64_t>(&ten, 1));
    CHECK(overflow32.status == MemoryPointerResolveStatus::ArithmeticOverflow);

    const std::map<uint64_t, uint64_t> canonicalEdge = {
        { 0x1000, 0x00007FFFFFFFFFFFull }
    };
    auto canonicalHole = ResolveMemoryPointerChain(mapReader(canonicalEdge, 8), 8,
        0x1000, std::span<const uint64_t>(&oneOffset, 1), true);
    CHECK(canonicalHole.status == MemoryPointerResolveStatus::NonCanonicalAddress);

    bool overflowReaderCalled = false;
    auto readSpanOverflow = ResolveMemoryPointerChain(
        [&overflowReaderCalled](uint64_t, void*, size_t) {
            overflowReaderCalled = true;
            return size_t{0};
        }, 8, UINT64_MAX, std::span<const uint64_t>(&oneOffset, 1), true);
    CHECK(readSpanOverflow.status == MemoryPointerResolveStatus::ArithmeticOverflow);
    CHECK(!overflowReaderCalled);

    bool canonicalHoleReaderCalled = false;
    auto readSpanCanonicalHole = ResolveMemoryPointerChain(
        [&canonicalHoleReaderCalled](uint64_t, void*, size_t) {
            canonicalHoleReaderCalled = true;
            return size_t{0};
        }, 8, 0x00007FFFFFFFFFFFull,
        std::span<const uint64_t>(&oneOffset, 1), true);
    CHECK(readSpanCanonicalHole.status == MemoryPointerResolveStatus::NonCanonicalAddress);
    CHECK(!canonicalHoleReaderCalled);

    std::vector<uint64_t> tooDeep(kMemoryPointerHardMaxDepth + 1, 0);
    auto depthLimit = ResolveMemoryPointerChain(mapReader(deepMemory, 8), 8,
                                                0x1010, tooDeep);
    CHECK(depthLimit.status == MemoryPointerResolveStatus::DepthLimit);
    CHECK(ResolveMemoryPointerChain(mapReader(deepMemory, 8), 3,
              0x1010, {}).status == MemoryPointerResolveStatus::InvalidPointerWidth);

    auto empty = ResolveMemoryPointerChain(mapReader(deepMemory, 8), 8, 0x1010, {});
    CHECK(empty.resolved() && empty.address == 0x1010 && empty.stepsResolved == 0);
    CHECK((empty.addresses == std::vector<uint64_t>{ 0x1010 }));

    if (g_fail == 0) std::printf("memory_pointer_test: all checks passed\n");
    else std::printf("memory_pointer_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
