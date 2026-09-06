#include "SemanticDiff.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cctype>
#include <cmath>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>

namespace ds {
namespace {

constexpr uint64_t kFnvOffset = 1469598103934665603ull;
constexpr uint64_t kFnvPrime = 1099511628211ull;
constexpr size_t kMaxTokenText = 160;
constexpr size_t kMaxMetadataText = 4096;
constexpr size_t kHardMaxFunctions = 100000;
constexpr size_t kHardMaxInstructionsPerFunction = 100000;
constexpr size_t kHardMaxTotalInstructions = 5000000;
constexpr size_t kHardMaxBlocksPerFunction = 100000;
constexpr size_t kHardMaxEdgesPerFunction = 1000000;
constexpr size_t kHardMaxCallsPerFunction = 100000;
constexpr size_t kHardMaxOperandsPerInstruction = 64;
constexpr size_t kHardMaxEditCells = 4000000;
constexpr size_t kHardMaxHunks = 200000;
constexpr size_t kHardMaxTransferProposals = 200000;
constexpr size_t kHardMaxBuildBytes = size_t{2} * 1024u * 1024u * 1024u;
constexpr uint32_t kHardMaxNeighborhoodRounds = 8;

void mixByte(uint64_t& hash, uint8_t value) {
    hash ^= value;
    hash *= kFnvPrime;
}

template <typename T>
void mixIntegral(uint64_t& hash, T value) {
    using U = std::make_unsigned_t<T>;
    U bits = static_cast<U>(value);
    for (size_t i = 0; i < sizeof(U); ++i) {
        mixByte(hash, static_cast<uint8_t>(bits & 0xFFu));
        bits >>= 8;
    }
}

void mixText(uint64_t& hash, const std::string& text, bool lower = true) {
    const size_t count = (std::min)(text.size(), kMaxTokenText);
    mixIntegral(hash, count);
    for (size_t i = 0; i < count; ++i) {
        unsigned char ch = static_cast<unsigned char>(text[i]);
        if (lower && ch >= 'A' && ch <= 'Z') ch = static_cast<unsigned char>(ch + ('a' - 'A'));
        mixByte(hash, ch);
    }
    // A bounded token still distinguishes an overlong hostile string from an
    // ordinary spelling without hashing the unbounded tail.
    mixByte(hash, text.size() > count ? 1u : 0u);
}

std::string boundedMetadata(const std::string& text) {
    return text.substr(0, (std::min)(text.size(), kMaxMetadataText));
}

bool cancellationRequested(const SemanticDiffCancel& cancelled) {
    if (!cancelled) return false;
    try { return cancelled(); }
    catch (...) { return true; }
}

void publishProgress(const SemanticDiffProgressCallback& callback,
                     SemanticDiffPhase phase, uint64_t completed, uint64_t total) {
    if (!callback) return;
    try { callback({phase, completed, total}); }
    catch (...) { /* progress observers cannot fail the analysis */ }
}

uint64_t instructionHash(const SemanticInstruction& instruction,
                         size_t operandCap, bool structuralOnly) {
    uint64_t hash = kFnvOffset;
    mixIntegral(hash, static_cast<uint8_t>(instruction.flow.kind));
    mixIntegral(hash, instruction.flow.delaySlots);
    if (structuralOnly) return hash;

    mixText(hash, instruction.mnemonic);
    const size_t prefixCount = (std::min)(instruction.prefixes.size(), size_t{16});
    mixIntegral(hash, prefixCount);
    for (size_t i = 0; i < prefixCount; ++i)
        mixIntegral(hash, static_cast<uint8_t>(instruction.prefixes[i]));
    mixByte(hash, instruction.prefixes.size() > prefixCount ? 1u : 0u);
    mixIntegral(hash, instruction.flagsRead);
    mixIntegral(hash, instruction.flagsWritten);

    auto mixRegisterSet = [&](const std::vector<std::string>& registers) {
        std::vector<uint64_t> names;
        names.reserve((std::min)(registers.size(), size_t{64}));
        for (size_t i = 0; i < registers.size() && i < 64; ++i) {
            uint64_t nameHash = kFnvOffset;
            mixText(nameHash, registers[i]);
            names.push_back(nameHash);
        }
        std::sort(names.begin(), names.end());
        mixIntegral(hash, names.size());
        for (uint64_t nameHash : names) mixIntegral(hash, nameHash);
        mixByte(hash, registers.size() > names.size() ? 1u : 0u);
    };
    mixRegisterSet(instruction.registersRead);
    mixRegisterSet(instruction.registersWritten);

    const size_t count = (std::min)(instruction.operands.size(), operandCap);
    mixIntegral(hash, count);
    for (size_t i = 0; i < count; ++i) {
        const SemanticOperand& operand = instruction.operands[i];
        mixIntegral(hash, static_cast<uint8_t>(operand.kind));
        mixIntegral(hash, static_cast<uint8_t>(operand.access));
        mixIntegral(hash, operand.widthBits);
        mixText(hash, operand.registerName);
        mixText(hash, operand.segmentRegister);
        mixText(hash, operand.baseRegister);
        mixText(hash, operand.indexRegister);
        mixIntegral(hash, operand.scale);
        mixByte(hash, operand.pcRelative ? 1u : 0u);
        mixByte(hash, operand.valueIsRelocation ? 1u : 0u);

        if (operand.kind == OperandKind::Immediate || operand.kind == OperandKind::Pointer) {
            mixByte(hash, operand.immediateSigned ? 1u : 0u);
            if (!operand.valueIsRelocation) mixIntegral(hash, operand.immediate);
        }
        if (operand.kind == OperandKind::Memory) {
            mixByte(hash, operand.displacementValid ? 1u : 0u);
            if (operand.displacementValid && !operand.valueIsRelocation)
                mixIntegral(hash, operand.displacement);
        }
    }
    mixByte(hash, instruction.operands.size() > count ? 1u : 0u);
    return hash;
}

uint64_t opcodeHash(const SemanticInstruction& instruction) {
    uint64_t hash = kFnvOffset;
    mixText(hash, instruction.mnemonic);
    const size_t prefixCount = (std::min)(instruction.prefixes.size(), size_t{16});
    mixIntegral(hash, prefixCount);
    for (size_t i = 0; i < prefixCount; ++i)
        mixIntegral(hash, static_cast<uint8_t>(instruction.prefixes[i]));
    mixByte(hash, instruction.prefixes.size() > prefixCount ? 1u : 0u);
    mixIntegral(hash, static_cast<uint8_t>(instruction.flow.kind));
    return hash;
}

struct FeatureBlock {
    uint64_t address = 0;
    bool entry = false;
    bool synthetic = false;
    std::vector<uint32_t> instructions;
    std::vector<size_t> successors;
};

struct FunctionFeature {
    const SemanticFunction* function = nullptr;
    size_t sourceIndex = 0;
    uint64_t semanticHash = 0;
    uint64_t cfgHash = 0;
    size_t edgeCount = 0;
    std::vector<uint64_t> exactTokens;
    std::vector<uint64_t> opcodeTokens;
    std::vector<uint64_t> calls;
};

struct ImageFeatures {
    std::vector<FunctionFeature> functions;
    std::unordered_map<uint64_t, size_t> functionByAddress;
    std::vector<std::vector<size_t>> outgoing;
    std::vector<std::vector<size_t>> incoming;
    bool truncated = false;
    bool cancelled = false;
};

std::vector<uint64_t> refineBlockLabels(const std::vector<FeatureBlock>& blocks,
                                        std::vector<uint64_t> labels) {
    // A fixed number of Weisfeiler-Lehman rounds is deterministic and bounded.
    // Four rounds distinguish the local topology needed by this lightweight
    // matcher without risking non-termination on cyclic hostile graphs.
    for (unsigned round = 0; round < 4; ++round) {
        std::vector<uint64_t> next(labels.size(), kFnvOffset);
        for (size_t i = 0; i < blocks.size(); ++i) {
            uint64_t hash = kFnvOffset;
            mixIntegral(hash, labels[i]);
            std::vector<uint64_t> successorLabels;
            successorLabels.reserve(blocks[i].successors.size());
            for (size_t successor : blocks[i].successors)
                if (successor < labels.size()) successorLabels.push_back(labels[successor]);
            std::sort(successorLabels.begin(), successorLabels.end());
            mixIntegral(hash, successorLabels.size());
            for (uint64_t label : successorLabels) mixIntegral(hash, label);
            next[i] = hash;
        }
        labels.swap(next);
    }
    return labels;
}

FunctionFeature buildFunctionFeature(const SemanticFunction& function,
                                     size_t sourceIndex,
                                     const SemanticDiffLimits& limits,
                                     size_t& totalInstructions,
                                     bool& truncated) {
    FunctionFeature feature;
    feature.function = &function;
    feature.sourceIndex = sourceIndex;

    size_t instructionCount = (std::min)(function.instructions.size(),
                                          limits.maxInstructionsPerFunction);
    if (instructionCount > limits.maxTotalInstructions -
                               (std::min)(totalInstructions, limits.maxTotalInstructions)) {
        instructionCount = limits.maxTotalInstructions -
                           (std::min)(totalInstructions, limits.maxTotalInstructions);
    }
    if (instructionCount < function.instructions.size()) truncated = true;
    totalInstructions += instructionCount;
    feature.exactTokens.reserve(instructionCount);
    feature.opcodeTokens.reserve(instructionCount);
    for (size_t i = 0; i < instructionCount; ++i) {
        feature.exactTokens.push_back(
            instructionHash(function.instructions[i], limits.maxOperandsPerInstruction, false));
        feature.opcodeTokens.push_back(opcodeHash(function.instructions[i]));
    }

    std::vector<FeatureBlock> blocks;
    const size_t blockCount = function.blocks.empty()
                            ? (instructionCount ? 1u : 0u)
                            : (std::min)(function.blocks.size(), limits.maxBlocksPerFunction);
    if (blockCount < function.blocks.size()) truncated = true;
    blocks.reserve(blockCount);

    if (function.blocks.empty() && instructionCount) {
        FeatureBlock block;
        block.address = function.address;
        block.entry = true;
        block.instructions.reserve(instructionCount);
        for (size_t i = 0; i < instructionCount; ++i)
            block.instructions.push_back(static_cast<uint32_t>(i));
        blocks.push_back(std::move(block));
    } else {
        for (size_t i = 0; i < blockCount; ++i) {
            FeatureBlock block;
            block.address = function.blocks[i].address;
            block.entry = block.address == function.address;
            block.instructions.reserve((std::min)(function.blocks[i].instructionIndices.size(),
                                                   instructionCount));
            for (uint32_t instructionIndex : function.blocks[i].instructionIndices) {
                if (instructionIndex < instructionCount)
                    block.instructions.push_back(instructionIndex);
            }
            blocks.push_back(std::move(block));
        }
    }

    // Malformed/precomputed input can omit instructions from every declared
    // block. Keep those semantics in a synthetic disconnected block rather
    // than allowing an exact match to ignore them.
    std::vector<bool> covered(instructionCount, false);
    for (const FeatureBlock& block : blocks)
        for (uint32_t instructionIndex : block.instructions)
            if (instructionIndex < covered.size()) covered[instructionIndex] = true;
    FeatureBlock orphaned;
    orphaned.synthetic = true;
    for (size_t i = 0; i < covered.size(); ++i)
        if (!covered[i]) orphaned.instructions.push_back(static_cast<uint32_t>(i));
    if (!orphaned.instructions.empty()) blocks.push_back(std::move(orphaned));

    std::unordered_map<uint64_t, size_t> blockByAddress;
    blockByAddress.reserve(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i)
        if (!blocks[i].synthetic) blockByAddress.emplace(blocks[i].address, i);

    size_t edgeBudget = limits.maxEdgesPerFunction;
    for (size_t i = 0; i < blocks.size() && i < function.blocks.size(); ++i) {
        for (uint64_t successorAddress : function.blocks[i].successors) {
            if (!edgeBudget) { truncated = true; break; }
            auto successor = blockByAddress.find(successorAddress);
            if (successor != blockByAddress.end()) {
                blocks[i].successors.push_back(successor->second);
                --edgeBudget;
            }
        }
        std::sort(blocks[i].successors.begin(), blocks[i].successors.end());
        blocks[i].successors.erase(std::unique(blocks[i].successors.begin(),
                                               blocks[i].successors.end()),
                                   blocks[i].successors.end());
        feature.edgeCount += blocks[i].successors.size();
    }

    std::vector<uint64_t> exactLabels(blocks.size(), kFnvOffset);
    std::vector<uint64_t> shapeLabels(blocks.size(), kFnvOffset);
    for (size_t i = 0; i < blocks.size(); ++i) {
        uint64_t exact = kFnvOffset;
        uint64_t shape = kFnvOffset;
        const bool entry = blocks[i].entry;
        mixByte(exact, entry ? 1u : 0u);
        mixByte(shape, entry ? 1u : 0u);
        mixIntegral(exact, blocks[i].instructions.size());
        mixIntegral(shape, blocks[i].instructions.size());
        for (uint32_t instructionIndex : blocks[i].instructions) {
            if (instructionIndex >= instructionCount) continue;
            mixIntegral(exact, feature.exactTokens[instructionIndex]);
            mixIntegral(shape, instructionHash(function.instructions[instructionIndex],
                                                 limits.maxOperandsPerInstruction, true));
        }
        mixIntegral(exact, blocks[i].successors.size());
        mixIntegral(shape, blocks[i].successors.size());
        exactLabels[i] = exact;
        shapeLabels[i] = shape;
    }
    exactLabels = refineBlockLabels(blocks, std::move(exactLabels));
    shapeLabels = refineBlockLabels(blocks, std::move(shapeLabels));

    auto finishFunctionHash = [&](std::vector<uint64_t> labels, bool exact) {
        uint64_t entryLabel = 0;
        bool entryFound = false;
        for (size_t i = 0; i < blocks.size(); ++i) {
            if (blocks[i].entry) {
                entryLabel = labels[i];
                entryFound = true;
                break;
            }
        }
        std::sort(labels.begin(), labels.end());
        uint64_t hash = kFnvOffset;
        mixIntegral(hash, labels.size());
        mixIntegral(hash, feature.edgeCount);
        mixIntegral(hash, instructionCount);
        mixByte(hash, entryFound ? 1u : 0u);
        if (entryFound) mixIntegral(hash, entryLabel);
        for (uint64_t label : labels) mixIntegral(hash, label);
        // Empty functions still need a stable exact spelling discriminator only
        // at the name tier; semantic/CFG matching intentionally treats stubs alike.
        (void)exact;
        return hash;
    };
    feature.semanticHash = finishFunctionHash(std::move(exactLabels), true);
    feature.cfgHash = finishFunctionHash(std::move(shapeLabels), false);

    feature.calls.reserve((std::min)(function.callTargets.size(), limits.maxCallsPerFunction));
    for (size_t i = 0; i < function.callTargets.size() &&
                       feature.calls.size() < limits.maxCallsPerFunction; ++i)
        feature.calls.push_back(function.callTargets[i]);
    for (size_t i = 0; i < instructionCount &&
                       feature.calls.size() < limits.maxCallsPerFunction; ++i) {
        const SemanticInstruction& instruction = function.instructions[i];
        if (instruction.flow.kind == FlowKind::DirectCall &&
            instruction.flow.directTargetValid)
            feature.calls.push_back(instruction.flow.directTarget);
    }
    if (function.callTargets.size() > limits.maxCallsPerFunction) truncated = true;
    std::sort(feature.calls.begin(), feature.calls.end());
    feature.calls.erase(std::unique(feature.calls.begin(), feature.calls.end()),
                        feature.calls.end());
    return feature;
}

ImageFeatures buildImageFeatures(const SemanticImage& image,
                                 const SemanticDiffLimits& limits,
                                 const SemanticDiffCancel& cancelled,
                                 const SemanticDiffProgressCallback& progress,
                                 uint64_t progressBase, uint64_t progressTotal) {
    ImageFeatures result;
    const size_t count = (std::min)(image.functions.size(), limits.maxFunctions);
    result.truncated = count < image.functions.size();

    std::vector<size_t> indices(count);
    for (size_t i = 0; i < count; ++i) indices[i] = i;
    std::stable_sort(indices.begin(), indices.end(), [&](size_t a, size_t b) {
        if (image.functions[a].address != image.functions[b].address)
            return image.functions[a].address < image.functions[b].address;
        if (image.functions[a].name != image.functions[b].name)
            return image.functions[a].name < image.functions[b].name;
        return a < b;
    });

    result.functions.reserve(count);
    size_t totalInstructions = 0;
    for (size_t ordinal = 0; ordinal < indices.size(); ++ordinal) {
        if ((ordinal & 31u) == 0u && cancellationRequested(cancelled)) {
            result.cancelled = true;
            break;
        }
        result.functions.push_back(buildFunctionFeature(image.functions[indices[ordinal]],
                                                        indices[ordinal], limits,
                                                        totalInstructions, result.truncated));
        publishProgress(progress, SemanticDiffPhase::Indexing,
                        progressBase + ordinal + 1, progressTotal);
    }

    result.outgoing.resize(result.functions.size());
    result.incoming.resize(result.functions.size());
    result.functionByAddress.reserve(result.functions.size());
    for (size_t i = 0; i < result.functions.size(); ++i)
        result.functionByAddress.emplace(result.functions[i].function->address, i);
    for (size_t caller = 0; caller < result.functions.size(); ++caller) {
        for (uint64_t targetAddress : result.functions[caller].calls) {
            auto target = result.functionByAddress.find(targetAddress);
            if (target == result.functionByAddress.end()) continue;
            result.outgoing[caller].push_back(target->second);
            result.incoming[target->second].push_back(caller);
        }
    }
    for (auto& edges : result.outgoing) {
        std::sort(edges.begin(), edges.end());
        edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
    }
    for (auto& edges : result.incoming) {
        std::sort(edges.begin(), edges.end());
        edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
    }
    return result;
}

double multisetSimilarity(std::vector<uint64_t> a, std::vector<uint64_t> b) {
    if (a.empty() && b.empty()) return 1.0;
    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());
    size_t i = 0, j = 0, intersection = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] == b[j]) { ++intersection; ++i; ++j; }
        else if (a[i] < b[j]) ++i;
        else ++j;
    }
    const size_t denominator = (std::max)(a.size(), b.size());
    return denominator ? static_cast<double>(intersection) / denominator : 1.0;
}

struct MatchMeta {
    SemanticMatchBasis basis = SemanticMatchBasis::SemanticHash;
    float confidence = 0.0f;
    std::string evidence;
};

void recordMatch(size_t left, size_t right, MatchMeta meta,
                 std::vector<int64_t>& leftToRight,
                 std::vector<int64_t>& rightToLeft,
                 std::vector<std::optional<MatchMeta>>& metadata) {
    if (left >= leftToRight.size() || right >= rightToLeft.size()) return;
    if (leftToRight[left] >= 0 || rightToLeft[right] >= 0) return;
    leftToRight[left] = static_cast<int64_t>(right);
    rightToLeft[right] = static_cast<int64_t>(left);
    metadata[left] = std::move(meta);
}

template <typename Key, typename KeyFn, typename MetaFn>
void matchUniqueGroups(const ImageFeatures& left, const ImageFeatures& right,
                       std::vector<int64_t>& leftToRight,
                       std::vector<int64_t>& rightToLeft,
                       std::vector<std::optional<MatchMeta>>& metadata,
                       KeyFn keyOf, MetaFn metaOf) {
    std::map<Key, std::vector<size_t>> leftGroups;
    std::map<Key, std::vector<size_t>> rightGroups;
    for (size_t i = 0; i < left.functions.size(); ++i)
        if (leftToRight[i] < 0) {
            auto key = keyOf(left.functions[i]);
            if (key) leftGroups[*key].push_back(i);
        }
    for (size_t i = 0; i < right.functions.size(); ++i)
        if (rightToLeft[i] < 0) {
            auto key = keyOf(right.functions[i]);
            if (key) rightGroups[*key].push_back(i);
        }
    for (const auto& [key, leftIndices] : leftGroups) {
        auto rightIt = rightGroups.find(key);
        if (rightIt == rightGroups.end()) continue;
        if (leftIndices.size() == 1 && rightIt->second.size() == 1) {
            const size_t li = leftIndices.front();
            const size_t ri = rightIt->second.front();
            recordMatch(li, ri, metaOf(left.functions[li], right.functions[ri]),
                        leftToRight, rightToLeft, metadata);
        }
    }
}

struct NeighborhoodScore {
    double similarity = 0.0;
    size_t evidenceSets = 0;
};

double setJaccard(const std::set<size_t>& a, const std::set<size_t>& b) {
    size_t intersection = 0;
    auto ai = a.begin();
    auto bi = b.begin();
    while (ai != a.end() && bi != b.end()) {
        if (*ai == *bi) { ++intersection; ++ai; ++bi; }
        else if (*ai < *bi) ++ai;
        else ++bi;
    }
    const size_t unionCount = a.size() + b.size() - intersection;
    return unionCount ? static_cast<double>(intersection) / unionCount : 1.0;
}

NeighborhoodScore neighborhoodSimilarity(size_t li, size_t ri,
                                         const ImageFeatures& left,
                                         const ImageFeatures& right,
                                         const std::vector<int64_t>& leftToRight) {
    NeighborhoodScore result;
    auto compare = [&](const std::vector<size_t>& leftEdges,
                       const std::vector<size_t>& rightEdges) {
        std::set<size_t> mappedLeft;
        for (size_t target : leftEdges)
            if (target < leftToRight.size() && leftToRight[target] >= 0)
                mappedLeft.insert(static_cast<size_t>(leftToRight[target]));
        if (mappedLeft.empty()) return;
        std::set<size_t> rightSet(rightEdges.begin(), rightEdges.end());
        result.similarity += setJaccard(mappedLeft, rightSet);
        ++result.evidenceSets;
    };
    compare(left.outgoing[li], right.outgoing[ri]);
    compare(left.incoming[li], right.incoming[ri]);
    if (result.evidenceSets) result.similarity /= result.evidenceSets;
    return result;
}

struct EditBuild {
    std::vector<InstructionEditHunk> hunks;
    std::vector<int64_t> leftToRight;
    std::vector<int64_t> rightToLeft;
    bool truncated = false;
};

InstructionEditHunk makeHunk(const FunctionFeature& left,
                             const FunctionFeature& right,
                             size_t leftBegin, size_t leftCount,
                             size_t rightBegin, size_t rightCount) {
    InstructionEditHunk hunk;
    hunk.leftBegin = static_cast<uint32_t>((std::min)(leftBegin, size_t{0xFFFFFFFFu}));
    hunk.leftCount = static_cast<uint32_t>((std::min)(leftCount, size_t{0xFFFFFFFFu}));
    hunk.rightBegin = static_cast<uint32_t>((std::min)(rightBegin, size_t{0xFFFFFFFFu}));
    hunk.rightCount = static_cast<uint32_t>((std::min)(rightCount, size_t{0xFFFFFFFFu}));
    hunk.kind = leftCount && rightCount ? InstructionEditKind::Replace
              : leftCount ? InstructionEditKind::Delete
                          : InstructionEditKind::Insert;
    if (leftBegin < left.function->instructions.size()) {
        hunk.leftAddressValid = true;
        hunk.leftAddress = left.function->instructions[leftBegin].address;
    }
    if (rightBegin < right.function->instructions.size()) {
        hunk.rightAddressValid = true;
        hunk.rightAddress = right.function->instructions[rightBegin].address;
    }
    return hunk;
}

EditBuild buildEdits(const FunctionFeature& left, const FunctionFeature& right,
                     size_t maxCells, size_t hunkBudget) {
    EditBuild result;
    const size_t n = left.exactTokens.size();
    const size_t m = right.exactTokens.size();
    result.leftToRight.assign(n, -1);
    result.rightToLeft.assign(m, -1);

    auto addGap = [&](size_t lb, size_t le, size_t rb, size_t re) {
        if (lb == le && rb == re) return;
        if (result.hunks.size() >= hunkBudget) { result.truncated = true; return; }
        result.hunks.push_back(makeHunk(left, right, lb, le - lb, rb, re - rb));
    };

    const bool cellOverflow = n == (std::numeric_limits<size_t>::max)() ||
                              m == (std::numeric_limits<size_t>::max)() ||
                              (n + 1) > (maxCells / (m + 1));
    if (!maxCells || cellOverflow) {
        size_t prefix = 0;
        while (prefix < n && prefix < m && left.exactTokens[prefix] == right.exactTokens[prefix]) {
            result.leftToRight[prefix] = static_cast<int64_t>(prefix);
            result.rightToLeft[prefix] = static_cast<int64_t>(prefix);
            ++prefix;
        }
        size_t suffix = 0;
        while (suffix < n - prefix && suffix < m - prefix &&
               left.exactTokens[n - suffix - 1] == right.exactTokens[m - suffix - 1]) {
            result.leftToRight[n - suffix - 1] = static_cast<int64_t>(m - suffix - 1);
            result.rightToLeft[m - suffix - 1] = static_cast<int64_t>(n - suffix - 1);
            ++suffix;
        }
        addGap(prefix, n - suffix, prefix, m - suffix);
        result.truncated = true;
        return result;
    }

    const size_t columns = m + 1;
    std::vector<uint32_t> lcs((n + 1) * columns, 0);
    for (size_t ii = n; ii-- > 0;) {
        for (size_t jj = m; jj-- > 0;) {
            const size_t at = ii * columns + jj;
            if (left.exactTokens[ii] == right.exactTokens[jj])
                lcs[at] = 1u + lcs[(ii + 1) * columns + jj + 1];
            else
                lcs[at] = (std::max)(lcs[(ii + 1) * columns + jj],
                                     lcs[ii * columns + jj + 1]);
        }
    }

    std::vector<std::pair<size_t, size_t>> equalPairs;
    size_t i = 0, j = 0;
    while (i < n && j < m) {
        if (left.exactTokens[i] == right.exactTokens[j]) {
            equalPairs.emplace_back(i, j);
            result.leftToRight[i] = static_cast<int64_t>(j);
            result.rightToLeft[j] = static_cast<int64_t>(i);
            ++i; ++j;
        } else if (lcs[(i + 1) * columns + j] >= lcs[i * columns + j + 1]) {
            ++i;
        } else {
            ++j;
        }
    }
    equalPairs.emplace_back(n, m); // sentinel closes the final edit gap

    size_t leftCursor = 0, rightCursor = 0;
    for (const auto& [equalLeft, equalRight] : equalPairs) {
        addGap(leftCursor, equalLeft, rightCursor, equalRight);
        if (equalLeft == n && equalRight == m) break;
        leftCursor = equalLeft + 1;
        rightCursor = equalRight + 1;
    }
    return result;
}

bool hasComment(const SemanticFunction& function, uint32_t index, const std::string& text) {
    for (const SemanticComment& comment : function.comments)
        if (comment.instructionIndex == index && comment.text == text) return true;
    return false;
}

void appendProposal(std::vector<MetadataTransferProposal>& proposals,
                    const SemanticDiffLimits& limits, bool& truncated,
                    MetadataTransferProposal proposal) {
    if (proposals.size() >= limits.maxTransferProposals) {
        truncated = true;
        return;
    }
    proposal.value = boundedMetadata(proposal.value);
    proposal.requiresExplicitSelection = true;
    proposals.push_back(std::move(proposal));
}

void appendMetadataProposals(const FunctionFeature& left,
                             const FunctionFeature& right,
                             const EditBuild& edits,
                             const SemanticDiffLimits& limits,
                             SemanticDiffResult& result) {
    const SemanticFunction& lf = *left.function;
    const SemanticFunction& rf = *right.function;
    auto functionProposal = [&](MetadataTransferKind kind,
                                MetadataTransferDirection direction,
                                const std::string& value) {
        MetadataTransferProposal proposal;
        proposal.kind = kind;
        proposal.direction = direction;
        proposal.sourceFunction = direction == MetadataTransferDirection::LeftToRight
                                ? lf.address : rf.address;
        proposal.targetFunction = direction == MetadataTransferDirection::LeftToRight
                                ? rf.address : lf.address;
        proposal.value = value;
        appendProposal(result.transferProposals, limits, result.truncated, std::move(proposal));
    };

    if (lf.name != rf.name) {
        if (lf.nameTransferable && !lf.name.empty()) functionProposal(MetadataTransferKind::Name,
                                               MetadataTransferDirection::LeftToRight, lf.name);
        if (rf.nameTransferable && !rf.name.empty()) functionProposal(MetadataTransferKind::Name,
                                               MetadataTransferDirection::RightToLeft, rf.name);
    }
    if (lf.prototype != rf.prototype) {
        if (!lf.prototype.empty()) functionProposal(MetadataTransferKind::Prototype,
                                                    MetadataTransferDirection::LeftToRight,
                                                    lf.prototype);
        if (!rf.prototype.empty()) functionProposal(MetadataTransferKind::Prototype,
                                                    MetadataTransferDirection::RightToLeft,
                                                    rf.prototype);
    }

    auto comments = [&](const SemanticFunction& source, const SemanticFunction& target,
                        const std::vector<int64_t>& mapping,
                        MetadataTransferDirection direction) {
        for (const SemanticComment& comment : source.comments) {
            if (comment.text.empty()) continue;
            MetadataTransferProposal proposal;
            proposal.kind = MetadataTransferKind::Comment;
            proposal.direction = direction;
            proposal.sourceFunction = source.address;
            proposal.targetFunction = target.address;
            proposal.sourceInstructionValid = comment.instructionIndex < source.instructions.size();
            proposal.sourceInstructionIndex = comment.instructionIndex;
            if (comment.instructionIndex < mapping.size() && mapping[comment.instructionIndex] >= 0) {
                proposal.targetInstructionValid = true;
                proposal.targetInstructionIndex = static_cast<uint32_t>(mapping[comment.instructionIndex]);
                if (hasComment(target, proposal.targetInstructionIndex, comment.text)) continue;
            }
            proposal.value = comment.text;
            appendProposal(result.transferProposals, limits, result.truncated, std::move(proposal));
        }
    };
    comments(lf, rf, edits.leftToRight, MetadataTransferDirection::LeftToRight);
    comments(rf, lf, edits.rightToLeft, MetadataTransferDirection::RightToLeft);

    auto bookmarks = [&](const SemanticFunction& source, const SemanticFunction& target,
                         const std::vector<int64_t>& mapping,
                         MetadataTransferDirection direction) {
        std::set<uint32_t> targetBookmarks(target.bookmarkInstructions.begin(),
                                           target.bookmarkInstructions.end());
        for (uint32_t sourceIndex : source.bookmarkInstructions) {
            MetadataTransferProposal proposal;
            proposal.kind = MetadataTransferKind::Bookmark;
            proposal.direction = direction;
            proposal.sourceFunction = source.address;
            proposal.targetFunction = target.address;
            proposal.sourceInstructionValid = sourceIndex < source.instructions.size();
            proposal.sourceInstructionIndex = sourceIndex;
            if (sourceIndex < mapping.size() && mapping[sourceIndex] >= 0) {
                proposal.targetInstructionValid = true;
                proposal.targetInstructionIndex = static_cast<uint32_t>(mapping[sourceIndex]);
                if (targetBookmarks.count(proposal.targetInstructionIndex)) continue;
            }
            appendProposal(result.transferProposals, limits, result.truncated, std::move(proposal));
        }
    };
    bookmarks(lf, rf, edits.leftToRight, MetadataTransferDirection::LeftToRight);
    bookmarks(rf, lf, edits.rightToLeft, MetadataTransferDirection::RightToLeft);
}

} // namespace

SemanticDiffLimits BoundSemanticDiffLimits(const SemanticDiffLimits& requested) noexcept {
    SemanticDiffLimits bounded = requested;
    bounded.maxFunctions = (std::min)(bounded.maxFunctions, kHardMaxFunctions);
    bounded.maxInstructionsPerFunction = (std::min)(bounded.maxInstructionsPerFunction,
                                                     kHardMaxInstructionsPerFunction);
    bounded.maxTotalInstructions = (std::min)(bounded.maxTotalInstructions,
                                              kHardMaxTotalInstructions);
    bounded.maxBlocksPerFunction = (std::min)(bounded.maxBlocksPerFunction,
                                              kHardMaxBlocksPerFunction);
    bounded.maxEdgesPerFunction = (std::min)(bounded.maxEdgesPerFunction,
                                             kHardMaxEdgesPerFunction);
    bounded.maxCallsPerFunction = (std::min)(bounded.maxCallsPerFunction,
                                             kHardMaxCallsPerFunction);
    bounded.maxOperandsPerInstruction = (std::min)(bounded.maxOperandsPerInstruction,
                                                    kHardMaxOperandsPerInstruction);
    bounded.maxEditCellsPerFunction = (std::min)(bounded.maxEditCellsPerFunction,
                                                 kHardMaxEditCells);
    bounded.maxHunks = (std::min)(bounded.maxHunks, kHardMaxHunks);
    bounded.maxTransferProposals = (std::min)(bounded.maxTransferProposals,
                                              kHardMaxTransferProposals);
    bounded.maxBuildBytes = (std::min)(bounded.maxBuildBytes, kHardMaxBuildBytes);
    bounded.maxNeighborhoodRounds = (std::min)(bounded.maxNeighborhoodRounds,
                                                kHardMaxNeighborhoodRounds);
    return bounded;
}

SemanticInstruction MakeSemanticInstruction(const Instruction& instruction) {
    SemanticInstruction result;
    result.address = instruction.address;
    result.length = instruction.length;
    result.mnemonic = instruction.mnemonic;
    result.display = InstructionText(instruction);
    result.prefixes = instruction.prefixes;
    result.flow = instruction.flow;
    if (result.flow.kind == FlowKind::None) {
        if (instruction.isRet) result.flow.kind = FlowKind::Return;
        else if (instruction.isCall)
            result.flow.kind = HasBranchTarget(instruction)
                             ? FlowKind::DirectCall : FlowKind::IndirectCall;
        else if (instruction.isBranch)
            result.flow.kind = HasBranchTarget(instruction)
                             ? FlowKind::ConditionalBranch : FlowKind::IndirectBranch;
    }
    uint64_t directTarget = 0;
    if (!result.flow.directTargetValid && TryGetDirectTarget(instruction, directTarget)) {
        result.flow.directTargetValid = true;
        result.flow.directTarget = directTarget;
    }
    result.registersRead = instruction.registersRead;
    result.registersWritten = instruction.registersWritten;
    result.flagsRead = instruction.flagsRead;
    result.flagsWritten = instruction.flagsWritten;

    // A control-flow instruction can carry semantic immediates in addition to
    // its destination (AArch64 TBZ/TBNZ are the canonical examples: bit number,
    // then branch target).  Only the operand that actually denotes the resolved
    // destination is relocation-insensitive; otherwise changing the tested bit
    // would incorrectly leave the instruction hash unchanged.
    size_t directFlowOperand = instruction.typedOperands.size();
    if (result.flow.directTargetValid) {
        for (size_t i = instruction.typedOperands.size(); i-- > 0;) {
            const TypedOperand& candidate = instruction.typedOperands[i];
            if ((candidate.kind == OperandKind::Immediate ||
                 candidate.kind == OperandKind::Pointer) && candidate.pcRelative) {
                directFlowOperand = i;
                break;
            }
        }
        if (directFlowOperand == instruction.typedOperands.size()) {
            for (size_t i = instruction.typedOperands.size(); i-- > 0;) {
                const TypedOperand& candidate = instruction.typedOperands[i];
                if ((candidate.kind == OperandKind::Immediate ||
                     candidate.kind == OperandKind::Pointer) &&
                    candidate.immediate == result.flow.directTarget) {
                    directFlowOperand = i;
                    break;
                }
            }
        }
        if (directFlowOperand == instruction.typedOperands.size()) {
            size_t onlyCandidate = instruction.typedOperands.size();
            for (size_t i = 0; i < instruction.typedOperands.size(); ++i) {
                const OperandKind kind = instruction.typedOperands[i].kind;
                if (kind != OperandKind::Immediate && kind != OperandKind::Pointer) continue;
                if (onlyCandidate != instruction.typedOperands.size()) {
                    onlyCandidate = instruction.typedOperands.size();
                    break;
                }
                onlyCandidate = i;
            }
            directFlowOperand = onlyCandidate;
        }
    }
    result.operands.reserve(instruction.typedOperands.size());
    for (size_t inputIndex = 0; inputIndex < instruction.typedOperands.size(); ++inputIndex) {
        const TypedOperand& input = instruction.typedOperands[inputIndex];
        SemanticOperand operand;
        operand.kind = input.kind;
        operand.access = input.access;
        operand.widthBits = input.widthBits;
        operand.registerName = input.registerName;
        operand.segmentRegister = input.segmentRegister;
        operand.baseRegister = input.baseRegister;
        operand.indexRegister = input.indexRegister;
        operand.scale = input.scale;
        operand.immediate = input.immediate;
        operand.immediateSigned = input.immediateSigned;
        operand.displacement = input.displacement;
        operand.displacementValid = input.displacementValid;
        operand.pcRelative = input.pcRelative;
        const bool directFlowValue = inputIndex == directFlowOperand;
        const bool absoluteMemory = input.kind == OperandKind::Memory &&
                                    input.baseRegister.empty() && input.indexRegister.empty();
        operand.valueIsRelocation = input.pcRelative || directFlowValue ||
                                    absoluteMemory || input.kind == OperandKind::Pointer;
        result.operands.push_back(std::move(operand));
    }
    return result;
}

SemanticDiffResult ComputeSemanticDiff(const SemanticImage& leftImage,
                                       const SemanticImage& rightImage,
                                       const SemanticDiffLimits& requestedLimits,
                                       const SemanticDiffCancel& cancelled,
                                       const SemanticDiffProgressCallback& progress) noexcept {
    try {
        SemanticDiffResult result;
        const SemanticDiffLimits limits = BoundSemanticDiffLimits(requestedLimits);
        if (!limits.maxFunctions || !limits.maxInstructionsPerFunction ||
            !limits.maxTotalInstructions || !limits.maxBlocksPerFunction) {
            result.error = "semantic diff limits must be non-zero";
            publishProgress(progress, SemanticDiffPhase::Failed, 0, 0);
            return result;
        }
        if (leftImage.arch != rightImage.arch) {
            result.error = "semantic diff requires matching architectures";
            publishProgress(progress, SemanticDiffPhase::Failed, 0, 0);
            return result;
        }
        const uint64_t indexTotal = static_cast<uint64_t>((std::min)(leftImage.functions.size(),
                                                                     limits.maxFunctions)) +
                                    static_cast<uint64_t>((std::min)(rightImage.functions.size(),
                                                                     limits.maxFunctions));
        publishProgress(progress, SemanticDiffPhase::Indexing, 0, indexTotal);
        ImageFeatures left = buildImageFeatures(leftImage, limits, cancelled, progress, 0, indexTotal);
        if (left.cancelled || cancellationRequested(cancelled)) {
            result.cancelled = true;
            publishProgress(progress, SemanticDiffPhase::Cancelled, 0, 0);
            return result;
        }
        ImageFeatures right = buildImageFeatures(rightImage, limits, cancelled, progress,
                                                 left.functions.size(), indexTotal);
        if (right.cancelled || cancellationRequested(cancelled)) {
            result.cancelled = true;
            publishProgress(progress, SemanticDiffPhase::Cancelled, 0, 0);
            return result;
        }
        result.truncated = left.truncated || right.truncated;

        std::vector<int64_t> leftToRight(left.functions.size(), -1);
        std::vector<int64_t> rightToLeft(right.functions.size(), -1);
        std::vector<std::optional<MatchMeta>> metadata(left.functions.size());

        publishProgress(progress, SemanticDiffPhase::AuthoritativeNames, 0,
                        left.functions.size());
        matchUniqueGroups<std::string>(
            left, right, leftToRight, rightToLeft, metadata,
            [](const FunctionFeature& feature) -> std::optional<std::string> {
                if (!feature.function->authoritativeName || feature.function->name.empty())
                    return std::nullopt;
                return feature.function->name;
            },
            [](const FunctionFeature&, const FunctionFeature&) {
                return MatchMeta{SemanticMatchBasis::AuthoritativeName, 1.0f,
                                 "unique authoritative symbol/name"};
            });
        if (cancellationRequested(cancelled)) {
            result.cancelled = true;
            publishProgress(progress, SemanticDiffPhase::Cancelled, 0, 0);
            return result;
        }

        using HashKey = std::tuple<uint64_t, size_t, size_t>;
        publishProgress(progress, SemanticDiffPhase::SemanticHashes, 0,
                        left.functions.size());
        matchUniqueGroups<HashKey>(
            left, right, leftToRight, rightToLeft, metadata,
            [](const FunctionFeature& feature) -> std::optional<HashKey> {
                return HashKey{feature.semanticHash, feature.exactTokens.size(), feature.edgeCount};
            },
            [](const FunctionFeature&, const FunctionFeature&) {
                return MatchMeta{SemanticMatchBasis::SemanticHash, 0.94f,
                                 "unique normalized semantic hash (absolute relocations excluded)"};
            });
        if (cancellationRequested(cancelled)) {
            result.cancelled = true;
            publishProgress(progress, SemanticDiffPhase::Cancelled, 0, 0);
            return result;
        }

        publishProgress(progress, SemanticDiffPhase::CfgStructure, 0,
                        left.functions.size());
        matchUniqueGroups<HashKey>(
            left, right, leftToRight, rightToLeft, metadata,
            [](const FunctionFeature& feature) -> std::optional<HashKey> {
                return HashKey{feature.cfgHash, feature.exactTokens.size(), feature.edgeCount};
            },
            [](const FunctionFeature& leftFeature, const FunctionFeature& rightFeature) {
                const double opcode = multisetSimilarity(leftFeature.opcodeTokens,
                                                         rightFeature.opcodeTokens);
                const float confidence = static_cast<float>(0.70 + 0.18 * opcode);
                return MatchMeta{SemanticMatchBasis::CfgStructure, confidence,
                                 "unique canonical CFG shape; opcode similarity " +
                                 std::to_string(static_cast<unsigned>(std::lround(opcode * 100.0))) + "%"};
            });
        if (cancellationRequested(cancelled)) {
            result.cancelled = true;
            publishProgress(progress, SemanticDiffPhase::Cancelled, 0, 0);
            return result;
        }

        // Ambiguous same-shape/same-hash groups are not paired by address.  Use
        // only already-matched call neighbors as evidence, iterating because one
        // resolved wrapper can anchor another.
        struct Candidate { size_t li = 0, ri = 0; double score = 0.0; double neighborhood = 0.0; };
        for (uint32_t round = 0; round < limits.maxNeighborhoodRounds; ++round) {
            publishProgress(progress, SemanticDiffPhase::CallNeighborhood, round,
                            limits.maxNeighborhoodRounds);
            std::vector<Candidate> candidates;
            for (size_t li = 0; li < left.functions.size(); ++li) {
                if (leftToRight[li] >= 0) continue;
                if ((li & 31u) == 0u && cancellationRequested(cancelled)) {
                    result.cancelled = true;
                    publishProgress(progress, SemanticDiffPhase::Cancelled, 0, 0);
                    return result;
                }
                for (size_t ri = 0; ri < right.functions.size(); ++ri) {
                    if (rightToLeft[ri] >= 0) continue;
                    NeighborhoodScore neighborhood = neighborhoodSimilarity(
                        li, ri, left, right, leftToRight);
                    if (!neighborhood.evidenceSets) continue;
                    const double opcode = multisetSimilarity(left.functions[li].opcodeTokens,
                                                             right.functions[ri].opcodeTokens);
                    const double cfg = left.functions[li].cfgHash == right.functions[ri].cfgHash
                                     ? 1.0 : 0.0;
                    const double score = 0.60 * neighborhood.similarity +
                                         0.25 * opcode + 0.15 * cfg;
                    if (score >= 0.62)
                        candidates.push_back({li, ri, score, neighborhood.similarity});
                }
            }
            if (candidates.empty()) break;
            std::sort(candidates.begin(), candidates.end(), [&](const Candidate& a,
                                                                 const Candidate& b) {
                if (a.score != b.score) return a.score > b.score;
                const uint64_t ala = left.functions[a.li].function->address;
                const uint64_t bla = left.functions[b.li].function->address;
                if (ala != bla) return ala < bla;
                return right.functions[a.ri].function->address <
                       right.functions[b.ri].function->address;
            });

            std::vector<double> bestLeft(left.functions.size(), -1.0);
            std::vector<double> secondLeft(left.functions.size(), -1.0);
            std::vector<size_t> bestLeftRight(left.functions.size(), size_t(-1));
            std::vector<double> bestRight(right.functions.size(), -1.0);
            std::vector<double> secondRight(right.functions.size(), -1.0);
            std::vector<size_t> bestRightLeft(right.functions.size(), size_t(-1));
            for (const Candidate& candidate : candidates) {
                if (candidate.score > bestLeft[candidate.li]) {
                    secondLeft[candidate.li] = bestLeft[candidate.li];
                    bestLeft[candidate.li] = candidate.score;
                    bestLeftRight[candidate.li] = candidate.ri;
                } else if (candidate.score > secondLeft[candidate.li]) {
                    secondLeft[candidate.li] = candidate.score;
                }
                if (candidate.score > bestRight[candidate.ri]) {
                    secondRight[candidate.ri] = bestRight[candidate.ri];
                    bestRight[candidate.ri] = candidate.score;
                    bestRightLeft[candidate.ri] = candidate.li;
                } else if (candidate.score > secondRight[candidate.ri]) {
                    secondRight[candidate.ri] = candidate.score;
                }
            }

            size_t matchesThisRound = 0;
            for (const Candidate& candidate : candidates) {
                if (leftToRight[candidate.li] >= 0 || rightToLeft[candidate.ri] >= 0) continue;
                if (bestLeftRight[candidate.li] != candidate.ri ||
                    bestRightLeft[candidate.ri] != candidate.li) continue;
                const bool leftUnique = secondLeft[candidate.li] < 0.0 ||
                                        bestLeft[candidate.li] - secondLeft[candidate.li] >= 0.05;
                const bool rightUnique = secondRight[candidate.ri] < 0.0 ||
                                         bestRight[candidate.ri] - secondRight[candidate.ri] >= 0.05;
                if (!leftUnique || !rightUnique) continue;
                const float confidence = static_cast<float>((std::min)(0.91,
                    0.54 + 0.37 * candidate.score));
                recordMatch(candidate.li, candidate.ri,
                            {SemanticMatchBasis::CallNeighborhood, confidence,
                             "mutually unique matched call-neighborhood; similarity " +
                             std::to_string(static_cast<unsigned>(
                                 std::lround(candidate.neighborhood * 100.0))) + "%"},
                            leftToRight, rightToLeft, metadata);
                ++matchesThisRound;
            }
            if (!matchesThisRound) break;
        }

        publishProgress(progress, SemanticDiffPhase::InstructionEdits, 0,
                        left.functions.size());
        size_t remainingHunks = limits.maxHunks;
        for (size_t li = 0; li < left.functions.size(); ++li) {
            if ((li & 15u) == 0u && cancellationRequested(cancelled)) {
                result = {};
                result.cancelled = true;
                publishProgress(progress, SemanticDiffPhase::Cancelled, 0, 0);
                return result;
            }
            if (leftToRight[li] < 0) continue;
            const size_t ri = static_cast<size_t>(leftToRight[li]);
            EditBuild edits = buildEdits(left.functions[li], right.functions[ri],
                                         limits.maxEditCellsPerFunction, remainingHunks);
            if (edits.hunks.size() <= remainingHunks) remainingHunks -= edits.hunks.size();
            else remainingHunks = 0;

            SemanticFunctionMatch match;
            match.leftIndex = left.functions[li].sourceIndex;
            match.rightIndex = right.functions[ri].sourceIndex;
            match.leftAddress = left.functions[li].function->address;
            match.rightAddress = right.functions[ri].function->address;
            match.basis = metadata[li]->basis;
            match.confidence = metadata[li]->confidence;
            match.evidence = metadata[li]->evidence;
            match.leftSemanticHash = left.functions[li].semanticHash;
            match.rightSemanticHash = right.functions[ri].semanticHash;
            match.leftCfgHash = left.functions[li].cfgHash;
            match.rightCfgHash = right.functions[ri].cfgHash;
            match.hunks = edits.hunks;
            match.hunksTruncated = edits.truncated;
            if (edits.truncated) result.truncated = true;
            appendMetadataProposals(left.functions[li], right.functions[ri], edits,
                                    limits, result);
            result.matched.push_back(std::move(match));
            publishProgress(progress, SemanticDiffPhase::InstructionEdits,
                            li + 1, left.functions.size());
        }

        for (size_t li = 0; li < left.functions.size(); ++li) {
            if (leftToRight[li] >= 0) continue;
            result.removed.push_back({left.functions[li].sourceIndex,
                                      left.functions[li].function->address,
                                      boundedMetadata(left.functions[li].function->name)});
        }
        for (size_t ri = 0; ri < right.functions.size(); ++ri) {
            if (rightToLeft[ri] >= 0) continue;
            result.added.push_back({right.functions[ri].sourceIndex,
                                    right.functions[ri].function->address,
                                    boundedMetadata(right.functions[ri].function->name)});
        }
        std::sort(result.matched.begin(), result.matched.end(),
                  [](const SemanticFunctionMatch& a, const SemanticFunctionMatch& b) {
            if (a.leftAddress != b.leftAddress) return a.leftAddress < b.leftAddress;
            return a.rightAddress < b.rightAddress;
        });
        std::sort(result.removed.begin(), result.removed.end(),
                  [](const SemanticUnmatchedFunction& a, const SemanticUnmatchedFunction& b) {
            if (a.address != b.address) return a.address < b.address;
            return a.index < b.index;
        });
        std::sort(result.added.begin(), result.added.end(),
                  [](const SemanticUnmatchedFunction& a, const SemanticUnmatchedFunction& b) {
            if (a.address != b.address) return a.address < b.address;
            return a.index < b.index;
        });
        result.complete = true;
        publishProgress(progress, SemanticDiffPhase::Complete,
                        result.matched.size(), result.matched.size());
        return result;
    } catch (const std::exception& exception) {
        SemanticDiffResult result;
        result.error = std::string("semantic diff failed: ") + exception.what();
        publishProgress(progress, SemanticDiffPhase::Failed, 0, 0);
        return result;
    } catch (...) {
        SemanticDiffResult result;
        result.error = "semantic diff failed: unknown exception";
        publishProgress(progress, SemanticDiffPhase::Failed, 0, 0);
        return result;
    }
}

struct SemanticDiffService::Impl {
    struct Job {
        uint64_t id = 0;
        std::shared_ptr<const SemanticImage> left;
        std::shared_ptr<const SemanticImage> right;
        SemanticDiffLimits limits;
    };

    mutable std::mutex mutex;
    std::condition_variable wake;
    std::condition_variable idle;
    std::optional<Job> pending;
    std::optional<SemanticDiffServiceResult> result;
    SemanticDiffProgress currentProgress;
    SemanticDiffServiceStats currentStats;
    std::thread worker;
    std::atomic<uint64_t> desiredId{0};
    std::atomic<bool> stopping{false};
    uint64_t nextId = 1;
    bool running = false;

    Impl() {
        // Start after every atomic/queue field has completed construction.
        worker = std::thread([this] { threadEntry(); });
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping.store(true, std::memory_order_release);
            desiredId.store(0, std::memory_order_release);
            pending.reset();
        }
        wake.notify_all();
        if (worker.joinable()) worker.join();
    }

    void publishWorkerFailure() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex);
            const uint64_t id = desiredId.load(std::memory_order_acquire);
            currentProgress = {SemanticDiffPhase::Failed, 0, 0};
            ++currentStats.jobsFailed;
            pending.reset();
            running = false;
            stopping.store(true, std::memory_order_release);
            SemanticDiffResult failure;
            failure.error = "semantic diff worker stopped after an unexpected internal exception";
            if (id) result = SemanticDiffServiceResult{id, std::move(failure)};
        } catch (...) {
            stopping.store(true, std::memory_order_release);
        }
        idle.notify_all();
        wake.notify_all();
    }

    void threadEntry() noexcept {
        try {
            run();
        } catch (...) {
            publishWorkerFailure();
        }
    }

    void run() {
        for (;;) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait(lock, [&] { return stopping.load(std::memory_order_acquire) || pending; });
                if (stopping.load(std::memory_order_acquire)) break;
                job = std::move(*pending);
                pending.reset();
                running = true;
                currentProgress = {SemanticDiffPhase::Indexing, 0, 0};
            }

            SemanticDiffResult diff = ComputeSemanticDiff(
                *job.left, *job.right, job.limits,
                [this, id = job.id] {
                    return stopping.load(std::memory_order_acquire) ||
                           desiredId.load(std::memory_order_acquire) != id;
                },
                [this, id = job.id](const SemanticDiffProgress& progressValue) {
                    if (desiredId.load(std::memory_order_acquire) != id) return;
                    std::lock_guard<std::mutex> lock(mutex);
                    currentProgress = progressValue;
                });

            {
                std::lock_guard<std::mutex> lock(mutex);
                running = false;
                const bool current = desiredId.load(std::memory_order_acquire) == job.id;
                if (current && !stopping.load(std::memory_order_acquire)) {
                    if (diff.error.size()) ++currentStats.jobsFailed;
                    if (result) ++currentStats.resultsDropped;
                    result = SemanticDiffServiceResult{job.id, std::move(diff)};
                } else if (!stopping.load(std::memory_order_acquire)) {
                    // A newer request/cancel made this result stale while the
                    // pure matcher was unwinding its cancellation boundary.
                    ++currentStats.resultsDropped;
                }
                if (!pending && !running) idle.notify_all();
            }
        }
        std::lock_guard<std::mutex> lock(mutex);
        running = false;
        idle.notify_all();
    }
};

SemanticDiffService::SemanticDiffService() : impl_(std::make_unique<Impl>()) {}
SemanticDiffService::~SemanticDiffService() = default;

uint64_t SemanticDiffService::request(std::shared_ptr<const SemanticImage> left,
                                      std::shared_ptr<const SemanticImage> right,
                                      SemanticDiffLimits limits) {
    if (!left || !right) return 0;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->stopping.load(std::memory_order_acquire)) return 0;
    uint64_t id = impl_->nextId++;
    if (!id) id = impl_->nextId++;
    ++impl_->currentStats.requests;
    // Replacing a queued request and superseding an active comparison are both
    // latest-wins coalescing events. The active job observes desiredId without
    // waiting for the next phase boundary.
    if (impl_->pending || impl_->running) ++impl_->currentStats.requestsCoalesced;
    if (impl_->result) {
        impl_->result.reset();
        ++impl_->currentStats.resultsDropped;
    }
    impl_->desiredId.store(id, std::memory_order_release);
    impl_->pending = Impl::Job{id, std::move(left), std::move(right), limits};
    impl_->currentProgress = {SemanticDiffPhase::Indexing, 0, 0};
    impl_->wake.notify_one();
    return id;
}

void SemanticDiffService::cancel() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    uint64_t cancellationId = impl_->nextId++;
    if (!cancellationId) cancellationId = impl_->nextId++;
    impl_->desiredId.store(cancellationId, std::memory_order_release);
    if (impl_->pending || impl_->running) ++impl_->currentStats.requestsCoalesced;
    impl_->pending.reset();
    if (impl_->result) {
        impl_->result.reset();
        ++impl_->currentStats.resultsDropped;
    }
    impl_->currentProgress = {SemanticDiffPhase::Cancelled, 0, 0};
    impl_->wake.notify_all();
    if (!impl_->running) impl_->idle.notify_all();
}

void SemanticDiffService::cancelAndWaitIdle() {
    cancel();
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->idle.wait(lock, [&] { return !impl_->running && !impl_->pending; });
}

bool SemanticDiffService::tryTakeResult(SemanticDiffServiceResult& resultValue) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->result) return false;
    resultValue = std::move(*impl_->result);
    impl_->result.reset();
    return true;
}

SemanticDiffProgress SemanticDiffService::progress() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->currentProgress;
}

SemanticDiffServiceStats SemanticDiffService::stats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->currentStats;
}

} // namespace ds
