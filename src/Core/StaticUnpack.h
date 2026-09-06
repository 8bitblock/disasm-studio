#pragma once
//
// StaticUnpack.h
// Bounded, dependency-light static recovery of packed PE payloads.  The
// primary strategy recognises the VMProtect-style PACKER_INFO layout used by
// its loader: one {SrcRVA,DstRVA} LZMA-properties record followed by one
// record for each virtual-only non-BSS destination section.  A conservative
// LZMA-alone fallback and explicit/manual stored blocks are also supported.
//
// The pure probe/decode functions perform no UI, filesystem, or process access.
// Heavy work can run through StaticUnpackService, which owns either supplied
// bytes or a path it reads on the worker and publishes a lock-protected progress
// snapshot without blocking the render thread.

#include "PeUnpack.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ds {

enum class StaticUnpackSeverity : uint8_t { Info = 0, Warning, Error };

enum class StaticUnpackStrategy : uint8_t {
    Auto = 0,
    VmprotectPackerInfo,
    EmbeddedLzmaAlone,
    ManualBlocks
};

enum class StaticUnpackCodec : uint8_t { Lzma1 = 0, Stored };

enum class StaticUnpackPhase : uint8_t {
    Idle = 0,
    Probing,
    MappingImage,
    Decompressing,
    ReconstructingPe,
    Complete,
    Failed,
    Cancelled
};

const char* StaticUnpackStrategyName(StaticUnpackStrategy strategy);
const char* StaticUnpackCodecName(StaticUnpackCodec codec);
const char* StaticUnpackPhaseName(StaticUnpackPhase phase);

struct StaticUnpackIssue {
    StaticUnpackSeverity severity = StaticUnpackSeverity::Info;
    std::string code;
    std::string message;
};

struct StaticUnpackEvidence {
    std::string code;
    std::string detail;
    uint64_t fileOffset = 0;
    float confidence = 0.0f;
};

// A recovered or analyst-supplied block.  For auto-recovered PE blocks,
// sourceRVA/destinationRVA are authoritative and sourceOffset is the validated
// file mapping of sourceRVA.  Manual blocks use sourceOffset directly.
struct StaticUnpackBlock {
    uint64_t descriptorOffset = 0;
    uint32_t sourceRVA = 0;
    uint32_t destinationRVA = 0;
    uint64_t sourceOffset = 0;
    uint64_t compressedSize = 0;   // hard input bound; zero is never "to EOF"
    uint64_t outputLimit = 0;      // hard destination bound
    uint64_t outputSize = 0;       // populated after a successful decode/copy
    StaticUnpackCodec codec = StaticUnpackCodec::Lzma1;
    std::array<uint8_t, 5> lzmaProperties{};
    bool hasLzmaProperties = false;
    bool complete = false;
    float confidence = 0.0f;
    std::string evidence;
    std::string status;
};

struct StaticUnpackProbe {
    bool recognized = false;
    bool likelyVmProtect = false;
    float confidence = 0.0f;
    StaticUnpackStrategy recommended = StaticUnpackStrategy::Auto;
    uint64_t packerInfoOffset = 0;
    uint64_t lzmaPropertiesOffset = 0;
    std::vector<StaticUnpackBlock> blocks;
    std::vector<StaticUnpackEvidence> evidence;
    std::vector<StaticUnpackIssue> issues;
    std::string summary;
};

struct StaticUnpackOptions {
    StaticUnpackStrategy strategy = StaticUnpackStrategy::Auto;
    size_t maxInputBytes = 512u * 1024u * 1024u;
    size_t maxOutputBytes = 512u * 1024u * 1024u;
    size_t maxDictionaryBytes = 64u * 1024u * 1024u;
    size_t maxBlocks = 256;
    size_t maxLzmaCandidates = 16;
    bool rebuildDiskPe = true;
    // Packer sections are currently always retained. Safe removal requires
    // directory/reference reachability analysis and is deliberately not
    // claimed by this implementation; false produces an explicit warning.
    bool retainPackedSections = true;

    // ManualBlocks is deliberately explicit.  Each stored block must provide
    // exact compressedSize == outputLimit; each LZMA block must provide valid
    // properties and finite input/output bounds.  No manual block reads to EOF.
    std::vector<StaticUnpackBlock> manualBlocks;

    // Forwarded to mapped-PE reconstruction after decompression.
    uint64_t runtimeImageBase = 0;
    uint64_t oepVA = 0;
    // For mapped-section recovery, oepVA is interpreted against runtimeImageBase.
    // If a complete standalone PE is decoded, its own preferred image base is
    // authoritative instead; the outer packed image base is never reused.
    bool hasOep = false;
};

struct StaticUnpackProgress {
    StaticUnpackPhase phase = StaticUnpackPhase::Idle;
    uint64_t current = 0;
    uint64_t total = 0;
    uint64_t outputBytes = 0;
    uint32_t blockIndex = 0;
    uint32_t blockCount = 0;
};

struct StaticUnpackResult {
    bool success = false;          // requested final artifact is ready
    bool decoded = false;          // every selected block was recovered
    bool diskImageReady = false;   // image is a validated disk-layout PE
    bool cancelled = false;
    bool oepTrusted = false;       // safe to label as a runnable/clean entry
    uint32_t entryRVA = 0;
    std::string oepAssessment;
    StaticUnpackStrategy strategy = StaticUnpackStrategy::Auto;
    float confidence = 0.0f;
    StaticUnpackProbe probe;
    std::vector<StaticUnpackBlock> blocks;
    std::vector<uint8_t> mappedImage;
    std::vector<uint8_t> image;
    // Retains the original packed input only when recovery fails before a
    // decoded mapping exists.  After decoding, mappedImage is the failure
    // artifact; successful complete disk payloads live in image.  This avoids
    // keeping two identical image-sized vectors in a successful result.
    std::vector<uint8_t> rawArtifact;
    PeUnpackRepairs repairs;
    std::vector<StaticUnpackIssue> issues;
    std::string report;
};

using StaticUnpackCancelFn = std::function<bool()>;
using StaticUnpackProgressFn = std::function<void(const StaticUnpackProgress&)>;

// Probe only; does no decompression.  All searches and result vectors obey the
// supplied caps.  The cancellation callback is checked during large scans.
StaticUnpackProbe ProbeStaticPackedPe(const std::vector<uint8_t>& input,
                                      const StaticUnpackOptions& options = {},
                                      const StaticUnpackCancelFn& cancelled = {},
                                      const StaticUnpackProgressFn& progress = {});

// Decode and optionally reconstruct a normal disk PE.  Input is immutable.
StaticUnpackResult StaticUnpackPe(const std::vector<uint8_t>& input,
                                  const StaticUnpackOptions& options = {},
                                  const StaticUnpackCancelFn& cancelled = {},
                                  const StaticUnpackProgressFn& progress = {});

struct StaticUnpackRequest {
    // Supply exactly one source. Vector input remains useful for tests and
    // already-owned buffers. inputPath is UTF-8 and is opened/read/cap-checked
    // by the worker, avoiding a render-thread copy of a large loaded binary.
    std::vector<uint8_t> input;
    std::string inputPath;
    // Path-backed callers can bind the job to the exact bytes that were
    // inspected in the UI. The worker rejects a replaced/modified file before
    // probing, so results cannot be attributed to a stale loaded-binary hash.
    bool verifySourceIdentity = false;
    uint64_t expectedSourceSize = 0;
    uint64_t expectedSourceHash = 0; // BinaryFile-compatible FNV-1a + length
    StaticUnpackOptions options;
};

class StaticUnpackService {
public:
    StaticUnpackService();
    ~StaticUnpackService();

    StaticUnpackService(const StaticUnpackService&) = delete;
    StaticUnpackService& operator=(const StaticUnpackService&) = delete;

    // One queued/running job at a time.  A completed unpicked result is replaced
    // when a new request is accepted.
    bool request(StaticUnpackRequest request);
    bool pending() const;
    StaticUnpackProgress progress() const;
    bool tryTakeResult(StaticUnpackResult& out);
    void cancel();               // non-blocking
    void cancelAndWaitIdle();    // blocking teardown/image-lifetime barrier

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ds
