#pragma once
// BinaryFile/decoder adapter for the pure SemanticDiff model.

#include "FunctionAnalyzer.h"
#include "SemanticDiff.h"

#include <functional>
#include <memory>
#include <vector>

namespace ds {

class BinaryFile;

using SemanticDecoderFactory =
    std::function<std::unique_ptr<IDisassembler>(const DecoderConfig&)>;
using LegacySemanticDecoderFactory =
    std::function<std::unique_ptr<IDisassembler>(Arch)>;

struct SemanticImageBuildResult {
    SemanticImage image;
    bool complete = false;
    bool cancelled = false;
    bool truncated = false;
    std::string error;
};

// Builds immutable semantic facts without retaining BinaryFile storage or a
// decoder.  If discoveredFunctions is null, bounded FunctionAnalyzer discovery
// runs first with its own decoder.  Supplying a snapshot lets an existing
// analysis pipeline avoid duplicate discovery.
SemanticImageBuildResult BuildSemanticImage(
    const BinaryFile& binary,
    const DecoderConfig& decoder,
    const SemanticDecoderFactory& decoderFactory,
    const SemanticDiffLimits& limits = {},
    const SemanticDiffCancel& cancelled = {},
    const std::vector<DiscoveredFunction>* discoveredFunctions = nullptr) noexcept;

// Source-compatible adapter for callers that have not yet acquired loader
// byte-order / feature metadata.  New analysis paths must use DecoderConfig.
SemanticImageBuildResult BuildSemanticImage(
    const BinaryFile& binary,
    Arch arch,
    const LegacySemanticDecoderFactory& decoderFactory,
    const SemanticDiffLimits& limits = {},
    const SemanticDiffCancel& cancelled = {},
    const std::vector<DiscoveredFunction>* discoveredFunctions = nullptr) noexcept;

} // namespace ds
