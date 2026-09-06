#pragma once

// Pure, bounded pointer-chain discovery for Memory Tools.  This module owns no
// process handles and has no Win32 or ImGui dependency: callers provide stable
// byte blocks for backlink discovery and a reader callback for chain
// resolution.  Offsets are stored in root-to-target order, so a discovered
// chain is evaluated as:
//
//     cursor = rootAddress;
//     for (offset : offsets) cursor = read_pointer(cursor) + offset;

// Only non-negative offsets are considered by the backlink search.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace ds {

struct MemoryPointerBlock {
    uint64_t base = 0;
    std::span<const uint8_t> bytes;
};

struct MemoryPointerChain {
    uint64_t rootAddress = 0;   // address containing the first pointer
    uint64_t targetAddress = 0; // final target used to seed the search
    std::vector<uint64_t> offsets; // root-to-target, all non-negative
};

enum class MemoryPointerSearchStatus : uint8_t {
    Complete,
    Truncated,
    Cancelled,
    InvalidOptions,
    ResourceFailure,
};

struct MemoryPointerSearchOptions {
    uint8_t pointerWidth = 8;       // exactly 4 (WOW64) or 8 (native x64)
    uint32_t maxDepth = 3;          // number of pointer dereferences
    uint64_t maxOffset = 4096;      // inclusive positive offset bound
    bool allowUnaligned = false;    // false aligns storage VAs to pointerWidth
    bool requireCanonical = true;   // reject non-canonical pointer/storage VAs

    // Work and output bounds.  A limit is an admission bound, not a hint.
    size_t maxResults = 100'000;
    size_t maxFrontier = 100'000;
    size_t maxSeedTargets = 500'000;
    size_t maxBlockVisits = 100'000;
    uint64_t maxCandidateReads = 25'000'000;
    uint64_t maxComparisons = 50'000'000;

    // Optional cooperative cancellation. Returning true stops without
    // publishing a misleading complete result.
    std::function<bool()> cancelled;
};

struct MemoryPointerSearchStats {
    uint64_t candidateReads = 0;
    uint64_t comparisons = 0;
    uint64_t bytesExamined = 0;
    size_t seedTargetsExamined = 0;
    size_t blockVisits = 0;
    uint32_t depthsCompleted = 0;
    size_t skippedInvalidBlocks = 0;
    size_t rejectedCycles = 0;
};

struct MemoryPointerSearchResult {
    MemoryPointerSearchStatus status = MemoryPointerSearchStatus::Complete;
    std::vector<MemoryPointerChain> chains;
    MemoryPointerSearchStats stats;
};

// Absolute hard ceilings keep hostile or accidentally-unbounded callers from
// turning a UI request into unbounded CPU or allocation work.
inline constexpr uint32_t kMemoryPointerHardMaxDepth = 16;
inline constexpr size_t kMemoryPointerHardMaxResults = 500'000;
inline constexpr size_t kMemoryPointerHardMaxFrontier = 500'000;
inline constexpr size_t kMemoryPointerHardMaxSeedTargets = 5'000'000;
inline constexpr size_t kMemoryPointerHardMaxBlockVisits = 1'000'000;
inline constexpr uint64_t kMemoryPointerHardMaxCandidateReads = 250'000'000;
inline constexpr uint64_t kMemoryPointerHardMaxComparisons = 500'000'000;

// For width 4 this is the 32-bit address range. For width 8 this implements
// the x86-64 canonical-address rule (bits 63..48 repeat bit 47), accepting both
// low and high canonical halves. Invalid widths always return false.
bool MemoryPointerAddressCanonical(uint64_t address, uint8_t pointerWidth) noexcept;

// Discover every unique chain of depths 1..maxDepth that resolves to any seed
// target. Byte blocks may overlap and targets may repeat; output is still
// unique and deterministically sorted. Pointer bytes are little-endian.
MemoryPointerSearchResult FindMemoryPointerChains(
    std::span<const MemoryPointerBlock> blocks,
    std::span<const uint64_t> targetAddresses,
    const MemoryPointerSearchOptions& options = {});

using MemoryPointerReader =
    std::function<size_t(uint64_t address, void* output, size_t size)>;

enum class MemoryPointerResolveStatus : uint8_t {
    Resolved,
    InvalidPointerWidth,
    DepthLimit,
    NonCanonicalAddress,
    ReadFailure,
    NullPointer,
    NonCanonicalPointer,
    ArithmeticOverflow,
    ReaderException,
};

struct MemoryPointerResolveResult {
    MemoryPointerResolveStatus status = MemoryPointerResolveStatus::ReadFailure;
    uint64_t address = 0;       // last successfully resolved address
    size_t stepsResolved = 0;
    std::vector<uint64_t> pointerValues; // raw values read at each completed step
    std::vector<uint64_t> addresses;     // root, then each completed next address

    bool resolved() const noexcept {
        return status == MemoryPointerResolveStatus::Resolved;
    }
};

// Resolve one root-to-target chain through an exact-size supplied reader. The
// reader can bind Debugger::readMemoryForSession so target identity remains an
// authority check outside this platform-neutral module.
MemoryPointerResolveResult ResolveMemoryPointerChain(
    const MemoryPointerReader& reader,
    uint8_t pointerWidth,
    uint64_t rootAddress,
    std::span<const uint64_t> offsets,
    bool requireCanonical = true);

} // namespace ds
