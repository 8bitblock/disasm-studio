#pragma once
//
// PeUnpack.h
// Dependency-light reconstruction of a mapped PE process image into a normal
// disk-layout image.  The live-debug/UI layer supplies the captured bytes and
// any imports it resolved while observing the process; this module performs no
// process access and is deterministic/testable on its own.

#include <cstdint>
#include <string>
#include <vector>

namespace ds {

enum class PeUnpackSeverity { Info, Warning, Error };

struct PeUnpackIssue {
    PeUnpackSeverity severity = PeUnpackSeverity::Info;
    std::string      code;
    std::string      message;
};

// A loader-resolved import observed in an IAT slot. slotVA must be inside the
// captured image. Named and ordinal imports are both supported.
struct PeUnpackImport {
    uint64_t    slotVA = 0;
    std::string dll;
    std::string name;
    uint16_t    ordinal = 0;
    bool        byOrdinal = false;
    uint64_t    resolvedVA = 0; // evidence/reporting only
};

struct PeUnpackOptions {
    uint64_t runtimeImageBase = 0;
    uint64_t oepVA = 0;
    bool     hasOep = false;              // VA zero is not a sentinel
    bool     trimZeroTails = true;
    bool     normalizeRelocations = true; // undo ASLR to the preferred base when safe
    bool     restoreIntactImports = true; // copy intact ILT entries back over resolved IAT
    bool     rebuildObservedImports = true;
    bool     repairLoadConfig = true;     // validate/fix cookie and CFG image pointers
    // Callers that already retain the mapped capture can suppress the otherwise
    // useful failure-artifact copy to avoid another image-sized allocation.
    bool     retainRawMappedImage = true;
    std::vector<PeUnpackImport> observedImports;
};

struct PeUnpackRepairs {
    uint32_t sectionsRebuilt = 0;
    uint32_t relocationEntriesNormalized = 0;
    uint32_t importSlotsRestored = 0;
    uint32_t importsRebuilt = 0;
    uint32_t importRunsRebuilt = 0;
    uint32_t loadConfigPointersRepaired = 0;
    uint32_t loadConfigPointersCleared = 0;
    bool entryPointChanged = false;
    bool imageBaseChanged = false;
    bool securityDirectoryCleared = false;
    bool checksumCleared = false;
    bool failureArtifactOnly = false;
};

struct PeUnpackResult {
    bool success = false;
    bool is64 = false;
    uint64_t preferredImageBase = 0;
    uint64_t outputImageBase = 0;
    uint32_t entryRVA = 0;
    // Always retains the bounded captured mapping, even when reconstruction
    // fails, so the caller can offer a useful failure dump.
    std::vector<uint8_t> rawMappedImage;
    std::vector<uint8_t> image;
    PeUnpackRepairs repairs;
    std::vector<PeUnpackIssue> issues;
    std::string report;
};

// mappedImage must begin at the module base and use normal loader layout
// (headers at RVA 0, section bytes at their VirtualAddress). Inputs above the
// hard capture cap or structurally hostile headers fail with a retained raw
// artifact and bounded diagnostics.
PeUnpackResult RebuildMappedPe(const std::vector<uint8_t>& mappedImage,
                               const PeUnpackOptions& options);

} // namespace ds
