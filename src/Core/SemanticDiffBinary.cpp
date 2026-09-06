#include "SemanticDiffBinary.h"

#include "BinaryFile.h"
#include "CFG.h"

#include <algorithm>
#include <exception>
#include <limits>
#include <unordered_map>

namespace ds {
namespace {

bool requestedCancel(const SemanticDiffCancel& cancelled) {
    if (!cancelled) return false;
    try { return cancelled(); }
    catch (...) { return true; }
}

} // namespace

SemanticImageBuildResult BuildSemanticImage(
    const BinaryFile& binary,
    const DecoderConfig& decoderConfig,
    const SemanticDecoderFactory& decoderFactory,
    const SemanticDiffLimits& requestedLimits,
    const SemanticDiffCancel& cancelled,
    const std::vector<DiscoveredFunction>* discoveredFunctions) noexcept {
    try {
        SemanticImageBuildResult result;
        const SemanticDiffLimits limits = BoundSemanticDiffLimits(requestedLimits);
        result.image.contentIdentity = binary.contentHash();
        if (!binary.loaded()) {
            result.image.arch = decoderConfig.arch;
            result.error = "semantic image source is not loaded";
            return result;
        }
        const DecoderConfig effectiveDecoder =
            DecoderConfigForImage(binary, decoderConfig);
        result.image.arch = effectiveDecoder.arch;
        if (!decoderFactory) {
            result.error = "semantic image decoder factory is empty";
            return result;
        }
        if (!limits.maxFunctions || !limits.maxInstructionsPerFunction ||
            !limits.maxTotalInstructions || !limits.maxBuildBytes) {
            result.error = "semantic image limits must be non-zero";
            return result;
        }
        bool cancellationSeen = false;
        auto isCancelled = [&] {
            if (!cancellationSeen) cancellationSeen = requestedCancel(cancelled);
            return cancellationSeen;
        };

        std::unique_ptr<IDisassembler> decoder = decoderFactory(effectiveDecoder);
        if (!decoder) {
            result.error = "semantic image decoder factory returned null";
            return result;
        }
        if (!decoder->ready()) {
            result.error = "semantic image decoder initialization failed";
            if (!decoder->errorMessage().empty()) {
                result.error += ": ";
                result.error.append(decoder->errorMessage());
            }
            return result;
        }

        std::vector<DiscoveredFunction> discoveredStorage;
        if (!discoveredFunctions) {
            FunctionAnalyzer analyzer;
            discoveredStorage = analyzer.analyze(binary, *decoder, effectiveDecoder.arch,
                                                 limits.maxFunctions,
                                                 limits.maxInstructionsPerFunction,
                                                 isCancelled);
            discoveredFunctions = &discoveredStorage;
            if (isCancelled()) {
                result.cancelled = true;
                return result;
            }
            // Discovery may leave decoder-specific state; semantic extraction
            // receives a fresh independent decoder from the same factory.
            decoder = decoderFactory(effectiveDecoder);
            if (!decoder) {
                result.error = "semantic image decoder factory returned null after discovery";
                return result;
            }
            if (!decoder->ready()) {
                result.error = "semantic image decoder initialization failed after discovery";
                if (!decoder->errorMessage().empty()) {
                    result.error += ": ";
                    result.error.append(decoder->errorMessage());
                }
                return result;
            }
        }

        const size_t functionCount = (std::min)(discoveredFunctions->size(), limits.maxFunctions);
        result.truncated = functionCount < discoveredFunctions->size();
        result.image.functions.reserve(functionCount);
        size_t totalInstructions = 0;
        size_t totalBytes = 0;

        for (size_t functionIndex = 0; functionIndex < functionCount; ++functionIndex) {
            if ((functionIndex & 15u) == 0u && isCancelled()) {
                result.image.functions.clear();
                result.cancelled = true;
                return result;
            }
            const DiscoveredFunction& discovered = (*discoveredFunctions)[functionIndex];
            SemanticFunction function;
            function.address = discovered.address;
            function.size = discovered.size;
            function.name = discovered.name;
            function.authoritativeName = discovered.isExport;
            function.nameTransferable = discovered.isExport;

            std::vector<FunctionChunk> chunks = discovered.chunks;
            if (chunks.empty() && discovered.size)
                chunks.push_back({discovered.address, discovered.size});
            std::sort(chunks.begin(), chunks.end(), [](const FunctionChunk& a,
                                                       const FunctionChunk& b) {
                if (a.address != b.address) return a.address < b.address;
                return a.size < b.size;
            });

            std::vector<CFGCodeChunk> cfgChunks;
            cfgChunks.reserve(chunks.size());
            for (const FunctionChunk& chunk : chunks) {
                if (!chunk.size) continue;
                if (totalBytes >= limits.maxBuildBytes) {
                    result.truncated = true;
                    continue;
                }
                size_t available = 0;
                const uint8_t* bytes = binary.ptrFromVA(chunk.address, available);
                if (!bytes || !available) {
                    result.truncated = true;
                    continue;
                }
                size_t byteCount = (std::min)(available, static_cast<size_t>(chunk.size));
                byteCount = (std::min)(byteCount, limits.maxBuildBytes - totalBytes);
                if (!byteCount) { result.truncated = true; continue; }
                cfgChunks.push_back({bytes, byteCount, chunk.address});
                totalBytes += byteCount;
                if (byteCount < static_cast<size_t>(chunk.size)) result.truncated = true;
            }

            if (!cfgChunks.empty() &&
                totalInstructions < limits.maxTotalInstructions &&
                function.instructions.size() < limits.maxInstructionsPerFunction) {
                const size_t instructionBudget = (std::min)(
                    limits.maxInstructionsPerFunction - function.instructions.size(),
                    limits.maxTotalInstructions - totalInstructions);
                // Decode all owned chunks as one logical function. Fallthrough
                // remains chunk-local, while explicit transfers can now retain
                // edges into a nonadjacent chunk.
                ControlFlowGraph cfg = BuildCFG(
                    cfgChunks, *decoder, instructionBudget, {}, {},
                    [&binary](const Instruction& instruction, uint64_t& target) {
                        return binary.resolveInstructionTarget(instruction, target);
                    });
                if (!cfg.complete) result.truncated = true;

                // CFG owns each decoded instruction once.  Preserve block-local
                // order while allowing the vector of blocks itself to be
                // canonicalized independently by the matcher.
                for (const BasicBlock& sourceBlock : cfg.blocks) {
                    if (function.blocks.size() >= limits.maxBlocksPerFunction) {
                        result.truncated = true;
                        break;
                    }
                    SemanticBasicBlock block;
                    block.address = sourceBlock.start;
                    for (const Instruction& instruction : sourceBlock.insns) {
                        if (function.instructions.size() >= limits.maxInstructionsPerFunction ||
                            totalInstructions >= limits.maxTotalInstructions) {
                            result.truncated = true;
                            break;
                        }
                        const uint32_t newIndex = static_cast<uint32_t>(function.instructions.size());
                        block.instructionIndices.push_back(newIndex);
                        SemanticInstruction semantic = MakeSemanticInstruction(instruction);
                        if (semantic.flow.kind == FlowKind::DirectCall &&
                            semantic.flow.directTargetValid)
                            function.callTargets.push_back(semantic.flow.directTarget);
                        function.instructions.push_back(std::move(semantic));
                        ++totalInstructions;
                    }
                    for (size_t successor : sourceBlock.succ)
                        if (successor < cfg.blocks.size())
                            block.successors.push_back(cfg.blocks[successor].start);
                    function.blocks.push_back(std::move(block));
                }
            } else if (!cfgChunks.empty()) {
                result.truncated = true;
            }
            std::sort(function.callTargets.begin(), function.callTargets.end());
            function.callTargets.erase(std::unique(function.callTargets.begin(),
                                                    function.callTargets.end()),
                                       function.callTargets.end());
            if (function.callTargets.size() > limits.maxCallsPerFunction) {
                function.callTargets.resize(limits.maxCallsPerFunction);
                result.truncated = true;
            }
            result.image.functions.push_back(std::move(function));
        }
        result.complete = true;
        return result;
    } catch (const std::exception& exception) {
        SemanticImageBuildResult result;
        result.image.arch = decoderConfig.arch;
        result.error = std::string("semantic image build failed: ") + exception.what();
        return result;
    } catch (...) {
        SemanticImageBuildResult result;
        result.image.arch = decoderConfig.arch;
        result.error = "semantic image build failed: unknown exception";
        return result;
    }
}

SemanticImageBuildResult BuildSemanticImage(
    const BinaryFile& binary,
    Arch arch,
    const LegacySemanticDecoderFactory& decoderFactory,
    const SemanticDiffLimits& limits,
    const SemanticDiffCancel& cancelled,
    const std::vector<DiscoveredFunction>* discoveredFunctions) noexcept {
    DecoderConfig config;
    config.arch = arch;
    SemanticDecoderFactory adapted;
    if (decoderFactory) {
        adapted = [decoderFactory](const DecoderConfig& requested) {
            return LegacyDecoderFactoryCanRepresent(requested)
                 ? decoderFactory(requested.arch) : nullptr;
        };
    }
    return BuildSemanticImage(binary, config, adapted, limits, cancelled,
                              discoveredFunctions);
}

} // namespace ds
