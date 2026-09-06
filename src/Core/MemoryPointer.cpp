#include "MemoryPointer.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

namespace ds {
namespace {

bool validWidth(uint8_t width) noexcept {
    return width == 4 || width == 8;
}

uint64_t readLittleEndian(const uint8_t* bytes, uint8_t width) noexcept {
    uint64_t value = 0;
    for (uint8_t i = 0; i < width; ++i)
        value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    return value;
}

bool validAddress(uint64_t address, uint8_t width, bool requireCanonical) noexcept {
    if (!validWidth(width)) return false;
    if (width == 4) return address <= UINT32_MAX;
    return !requireCanonical || MemoryPointerAddressCanonical(address, width);
}

struct ChainLess {
    bool operator()(const MemoryPointerChain& a,
                    const MemoryPointerChain& b) const noexcept {
        if (a.targetAddress != b.targetAddress)
            return a.targetAddress < b.targetAddress;
        if (a.offsets.size() != b.offsets.size())
            return a.offsets.size() < b.offsets.size();
        if (a.rootAddress != b.rootAddress)
            return a.rootAddress < b.rootAddress;
        return std::lexicographical_compare(a.offsets.begin(), a.offsets.end(),
                                            b.offsets.begin(), b.offsets.end());
    }
};

struct FrontierPath {
    uint64_t address = 0;
    uint64_t targetAddress = 0;
    std::vector<uint64_t> offsets;
    // Storage addresses already present downstream, plus the final target.
    // This is at most maxDepth+1 entries and rejects self/cyclic chains.
    std::vector<uint64_t> visited;
};

struct FrontierLess {
    bool operator()(const FrontierPath& a, const FrontierPath& b) const noexcept {
        if (a.address != b.address) return a.address < b.address;
        if (a.targetAddress != b.targetAddress)
            return a.targetAddress < b.targetAddress;
        return std::lexicographical_compare(a.offsets.begin(), a.offsets.end(),
                                            b.offsets.begin(), b.offsets.end());
    }
};

bool optionsValid(const MemoryPointerSearchOptions& o) noexcept {
    return validWidth(o.pointerWidth) && o.maxDepth != 0 &&
           o.maxDepth <= kMemoryPointerHardMaxDepth &&
           o.maxResults != 0 && o.maxResults <= kMemoryPointerHardMaxResults &&
           o.maxFrontier != 0 && o.maxFrontier <= kMemoryPointerHardMaxFrontier &&
           o.maxSeedTargets != 0 &&
           o.maxSeedTargets <= kMemoryPointerHardMaxSeedTargets &&
           o.maxBlockVisits != 0 &&
           o.maxBlockVisits <= kMemoryPointerHardMaxBlockVisits &&
           o.maxCandidateReads != 0 &&
           o.maxCandidateReads <= kMemoryPointerHardMaxCandidateReads &&
           o.maxComparisons != 0 &&
           o.maxComparisons <= kMemoryPointerHardMaxComparisons;
}

bool cancelled(const MemoryPointerSearchOptions& options) {
    return options.cancelled && options.cancelled();
}

void saturatingAdd(uint64_t& value, uint64_t amount) noexcept {
    value = value > UINT64_MAX - amount ? UINT64_MAX : value + amount;
}

} // namespace

bool MemoryPointerAddressCanonical(uint64_t address, uint8_t pointerWidth) noexcept {
    if (pointerWidth == 4) return address <= UINT32_MAX;
    if (pointerWidth != 8) return false;
    const uint64_t upper = address >> 48;
    const bool sign = ((address >> 47) & 1u) != 0;
    return sign ? upper == 0xFFFFu : upper == 0;
}

MemoryPointerSearchResult FindMemoryPointerChains(
    std::span<const MemoryPointerBlock> blocks,
    std::span<const uint64_t> targetAddresses,
    const MemoryPointerSearchOptions& options) {
    MemoryPointerSearchResult result;
    if (!optionsValid(options)) {
        result.status = MemoryPointerSearchStatus::InvalidOptions;
        return result;
    }

    try {
        // Keep seed admission bounded even if a hostile caller supplies a huge
        // target span. Retaining the smallest values makes truncation
        // deterministic regardless of input ordering.
        std::set<uint64_t> boundedSeeds;
        const size_t admittedTargets =
            std::min(targetAddresses.size(), options.maxSeedTargets);
        if (targetAddresses.size() > admittedTargets)
            result.status = MemoryPointerSearchStatus::Truncated;
        for (size_t targetIndex = 0; targetIndex < admittedTargets; ++targetIndex) {
            const uint64_t target = targetAddresses[targetIndex];
            ++result.stats.seedTargetsExamined;
            if (!validAddress(target, options.pointerWidth,
                              options.requireCanonical))
                continue;
            boundedSeeds.insert(target);
            if (boundedSeeds.size() > options.maxFrontier) {
                boundedSeeds.erase(std::prev(boundedSeeds.end()));
                result.status = MemoryPointerSearchStatus::Truncated;
            }
        }
        std::vector<uint64_t> seeds(boundedSeeds.begin(), boundedSeeds.end());

        std::vector<FrontierPath> frontier;
        frontier.reserve(seeds.size());
        for (uint64_t target : seeds)
            frontier.push_back({ target, target, {}, { target } });

        std::set<MemoryPointerChain, ChainLess> uniqueResults;
        bool stop = false;
        for (uint32_t depth = 1; depth <= options.maxDepth && !frontier.empty(); ++depth) {
            if (cancelled(options)) {
                result.status = MemoryPointerSearchStatus::Cancelled;
                break;
            }

            std::sort(frontier.begin(), frontier.end(), FrontierLess{});
            std::vector<FrontierPath> next;
            next.reserve(std::min(options.maxFrontier, frontier.size() * 2));
            std::set<MemoryPointerChain, ChainLess> nextKeys;

            for (const MemoryPointerBlock& block : blocks) {
                if (stop) break;
                if (cancelled(options)) {
                    result.status = MemoryPointerSearchStatus::Cancelled;
                    stop = true;
                    break;
                }
                if (result.stats.blockVisits >= options.maxBlockVisits) {
                    result.status = MemoryPointerSearchStatus::Truncated;
                    stop = true;
                    break;
                }
                ++result.stats.blockVisits;
                const uint64_t blockSize = static_cast<uint64_t>(block.bytes.size());
                if (blockSize < options.pointerWidth ||
                    block.base > UINT64_MAX - (blockSize - 1) ||
                    !validAddress(block.base, options.pointerWidth,
                                  options.requireCanonical) ||
                    !validAddress(block.base + blockSize - 1,
                                  options.pointerWidth,
                                  options.requireCanonical)) {
                    ++result.stats.skippedInvalidBlocks;
                    continue;
                }

                uint64_t first = 0;
                const uint64_t stride = options.allowUnaligned ? 1 : options.pointerWidth;
                if (!options.allowUnaligned) {
                    const uint64_t remainder = block.base % options.pointerWidth;
                    first = remainder ? options.pointerWidth - remainder : 0;
                }
                if (first > blockSize - options.pointerWidth) continue;

                for (uint64_t offsetInBlock = first;
                     offsetInBlock <= blockSize - options.pointerWidth;
                     offsetInBlock += stride) {
                    if (cancelled(options)) {
                        result.status = MemoryPointerSearchStatus::Cancelled;
                        stop = true;
                        break;
                    }
                    if (result.stats.candidateReads >= options.maxCandidateReads) {
                        result.status = MemoryPointerSearchStatus::Truncated;
                        stop = true;
                        break;
                    }
                    ++result.stats.candidateReads;
                    saturatingAdd(result.stats.bytesExamined, options.pointerWidth);

                    const uint64_t storageAddress = block.base + offsetInBlock;
                    if (!validAddress(storageAddress, options.pointerWidth,
                                      options.requireCanonical))
                        continue;
                    const uint64_t pointerValue = readLittleEndian(
                        block.bytes.data() + static_cast<size_t>(offsetInBlock),
                        options.pointerWidth);
                    // A null base plus a small offset is not a useful pointer and
                    // would create a large cluster of false backlink results.
                    if (pointerValue == 0 ||
                        !validAddress(pointerValue, options.pointerWidth,
                                      options.requireCanonical))
                        continue;

                    const uint64_t upper = pointerValue > UINT64_MAX - options.maxOffset
                        ? UINT64_MAX : pointerValue + options.maxOffset;
                    auto it = std::lower_bound(
                        frontier.begin(), frontier.end(), pointerValue,
                        [](const FrontierPath& item, uint64_t address) {
                            return item.address < address;
                        });
                    for (; it != frontier.end() && it->address <= upper; ++it) {
                        if (result.stats.comparisons >= options.maxComparisons) {
                            result.status = MemoryPointerSearchStatus::Truncated;
                            stop = true;
                            break;
                        }
                        ++result.stats.comparisons;
                        if (std::find(it->visited.begin(), it->visited.end(),
                                      storageAddress) != it->visited.end()) {
                            ++result.stats.rejectedCycles;
                            continue;
                        }

                        const uint64_t positiveOffset = it->address - pointerValue;
                        MemoryPointerChain chain;
                        chain.rootAddress = storageAddress;
                        chain.targetAddress = it->targetAddress;
                        chain.offsets.reserve(it->offsets.size() + 1);
                        chain.offsets.push_back(positiveOffset);
                        chain.offsets.insert(chain.offsets.end(),
                                             it->offsets.begin(), it->offsets.end());

                        const auto [resultIt, inserted] = uniqueResults.insert(chain);
                        (void)resultIt;
                        if (inserted && uniqueResults.size() > options.maxResults) {
                            uniqueResults.erase(std::prev(uniqueResults.end()));
                            result.status = MemoryPointerSearchStatus::Truncated;
                            stop = true;
                            break;
                        }

                        if (depth < options.maxDepth) {
                            const auto [keyIt, frontierInserted] = nextKeys.insert(chain);
                            (void)keyIt;
                            if (!frontierInserted) continue;
                            if (next.size() >= options.maxFrontier) {
                                result.status = MemoryPointerSearchStatus::Truncated;
                                stop = true;
                                break;
                            }
                            FrontierPath path;
                            path.address = storageAddress;
                            path.targetAddress = it->targetAddress;
                            path.offsets = chain.offsets;
                            path.visited.reserve(it->visited.size() + 1);
                            path.visited.push_back(storageAddress);
                            path.visited.insert(path.visited.end(),
                                                it->visited.begin(), it->visited.end());
                            next.push_back(std::move(path));
                        }
                    }

                    // Result/frontier/comparison limits are detected in the
                    // inner frontier loop. Propagate that stop immediately;
                    // otherwise the remainder of this block is still scanned.
                    if (stop) break;

                    // Avoid unsigned wrap in the loop increment even though a
                    // valid block normally makes this unreachable.
                    if (offsetInBlock > UINT64_MAX - stride) break;
                }
            }

            if (stop) break;
            result.stats.depthsCompleted = depth;
            frontier = std::move(next);
        }

        result.chains.assign(uniqueResults.begin(), uniqueResults.end());
    } catch (...) {
        result.status = MemoryPointerSearchStatus::ResourceFailure;
        result.chains.clear();
    }
    return result;
}

MemoryPointerResolveResult ResolveMemoryPointerChain(
    const MemoryPointerReader& reader,
    uint8_t pointerWidth,
    uint64_t rootAddress,
    std::span<const uint64_t> offsets,
    bool requireCanonical) {
    MemoryPointerResolveResult result;
    result.address = rootAddress;
    if (!validWidth(pointerWidth)) {
        result.status = MemoryPointerResolveStatus::InvalidPointerWidth;
        return result;
    }
    if (offsets.size() > kMemoryPointerHardMaxDepth) {
        result.status = MemoryPointerResolveStatus::DepthLimit;
        return result;
    }
    if (!validAddress(rootAddress, pointerWidth, requireCanonical)) {
        result.status = MemoryPointerResolveStatus::NonCanonicalAddress;
        return result;
    }

    result.addresses.reserve(offsets.size() + 1);
    result.pointerValues.reserve(offsets.size());
    result.addresses.push_back(rootAddress);
    uint64_t cursor = rootAddress;
    for (uint64_t offset : offsets) {
        const uint64_t widthLimit = pointerWidth == 4 ? UINT32_MAX : UINT64_MAX;
        if (cursor > widthLimit - (pointerWidth - 1)) {
            result.status = MemoryPointerResolveStatus::ArithmeticOverflow;
            return result;
        }
        if (requireCanonical &&
            !validAddress(cursor + pointerWidth - 1, pointerWidth, true)) {
            result.status = MemoryPointerResolveStatus::NonCanonicalAddress;
            return result;
        }
        uint8_t bytes[8]{};
        size_t got = 0;
        try {
            if (!reader) {
                result.status = MemoryPointerResolveStatus::ReadFailure;
                return result;
            }
            got = reader(cursor, bytes, pointerWidth);
        } catch (...) {
            result.status = MemoryPointerResolveStatus::ReaderException;
            return result;
        }
        if (got != pointerWidth) {
            result.status = MemoryPointerResolveStatus::ReadFailure;
            return result;
        }

        const uint64_t pointerValue = readLittleEndian(bytes, pointerWidth);
        if (pointerValue == 0) {
            result.status = MemoryPointerResolveStatus::NullPointer;
            return result;
        }
        if (!validAddress(pointerValue, pointerWidth, requireCanonical)) {
            result.status = MemoryPointerResolveStatus::NonCanonicalPointer;
            return result;
        }
        if (pointerValue > UINT64_MAX - offset) {
            result.status = MemoryPointerResolveStatus::ArithmeticOverflow;
            return result;
        }
        const uint64_t next = pointerValue + offset;
        if (!validAddress(next, pointerWidth, requireCanonical)) {
            // In a 32-bit target this is width overflow. In a 64-bit target it
            // is a transition into the non-canonical address hole.
            result.status = pointerWidth == 4
                ? MemoryPointerResolveStatus::ArithmeticOverflow
                : MemoryPointerResolveStatus::NonCanonicalAddress;
            return result;
        }

        result.pointerValues.push_back(pointerValue);
        cursor = next;
        result.address = cursor;
        result.addresses.push_back(cursor);
        ++result.stepsResolved;
    }
    result.status = MemoryPointerResolveStatus::Resolved;
    return result;
}

} // namespace ds
