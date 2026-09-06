#pragma once
//
// FirmwareSniffer.h
// Dependency-light, bounded recognition of raw PC firmware images.  The
// detector deliberately reports evidence and confidence instead of treating a
// short magic value as proof.  It has no BinaryFile, decoder, Win32, or UI
// dependency, so raw-load policy can consume the result without coupling the
// parser to the application shell.
//

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

enum class FirmwareConfidence : uint8_t {
    None = 0,
    Low,
    Medium,
    High,
};

enum class FirmwareKind : uint32_t {
    None                 = 0,
    LegacyBios           = 1u << 0,
    UefiFirmware         = 1u << 1,
    PciOptionRom         = 1u << 2,
    IntelFlashDescriptor = 1u << 3,
};

inline FirmwareKind operator|(FirmwareKind a, FirmwareKind b) {
    return static_cast<FirmwareKind>(static_cast<uint32_t>(a) |
                                     static_cast<uint32_t>(b));
}
inline FirmwareKind& operator|=(FirmwareKind& a, FirmwareKind b) {
    a = a | b;
    return a;
}
inline bool HasFirmwareKind(FirmwareKind set, FirmwareKind value) {
    return (static_cast<uint32_t>(set) & static_cast<uint32_t>(value)) != 0;
}

// This is intentionally separate from Disasm::Arch: the detector stays usable
// without a decoder dependency, then the raw-load UI maps the recommendation to
// the exact selectable instruction-set mode.
enum class FirmwareCpuMode : uint8_t {
    Unknown = 0,
    X86Real16,
    X86_32,
    X86_64,
    ARM_A32,
    ARM_Thumb,
    ARM_AArch64,
};

struct FirmwareAddress {
    bool     valid = false;
    uint64_t fileOffset = 0;
    bool     virtualAddressValid = false;
    uint64_t virtualAddress = 0;
};

struct FirmwareEvidence {
    FirmwareConfidence confidence = FirmwareConfidence::None;
    uint64_t fileOffset = 0;
    std::string summary;
};

struct FirmwareJump {
    bool recognized = false;
    bool targetResolved = false;
    FirmwareAddress source;
    FirmwareAddress target;
    uint8_t instructionLength = 0;
    // Stable, human-readable form: "short relative", "near relative", or
    // "far immediate".
    std::string form;
    std::string evidence;
};

struct FirmwareVolumeInfo {
    uint64_t fileOffset = 0;
    uint64_t length = 0;
    uint16_t headerLength = 0;
    uint8_t  revision = 0;
    bool     complete = false;
    bool     checksumValid = false;
    bool     blockMapTerminated = false;
    bool     knownFileSystemGuid = false;
    FirmwareConfidence confidence = FirmwareConfidence::None;
};

struct PciOptionRomInfo {
    uint64_t fileOffset = 0;
    uint64_t declaredSize = 0;
    uint64_t pcirOffset = 0;
    uint16_t vendorId = 0;
    uint16_t deviceId = 0;
    uint16_t pcirLength = 0;
    uint8_t  codeType = 0;
    bool     lastImage = false;
    bool     efiImage = false;
    uint16_t efiMachine = 0;
    uint16_t efiImageOffset = 0;
    uint16_t efiCompressionType = 0;
    bool     complete = false;
    bool     checksumValid = false;
    FirmwareConfidence confidence = FirmwareConfidence::None;
};

struct IntelFlashDescriptorInfo {
    uint64_t fileOffset = 0;
    uint64_t regionTableOffset = 0;
    bool     mapValid = false;
    bool     biosRegionValid = false;
    uint64_t biosRegionOffset = 0;
    uint64_t biosRegionSize = 0;
    FirmwareConfidence confidence = FirmwareConfidence::None;
};

enum class FirmwareLandmarkKind : uint8_t {
    ResetVector = 0,
    BootEntry,
    FirmwareVolume,
    PciRomHeader,
    PcirData,
    EfiImage,
    FlashDescriptor,
    BiosRegion,
};

// A landmark is directly consumable as an analysis seed/name.  `code` is false
// for structural headers and true only for locations that are reasonable code
// roots (reset vector, resolved entry, or an executable option-ROM image).
struct FirmwareLandmark {
    FirmwareLandmarkKind kind = FirmwareLandmarkKind::BootEntry;
    FirmwareAddress location;
    std::string name;
    bool code = false;
    FirmwareConfidence confidence = FirmwareConfidence::None;
    std::string evidence;
};

struct FirmwareEntryPoint {
    bool detected = false;
    FirmwareAddress location;
    FirmwareCpuMode mode = FirmwareCpuMode::Unknown;
    FirmwareConfidence confidence = FirmwareConfidence::None;
    std::string evidence;
    std::vector<FirmwareJump> jumpChain;
};

struct FirmwareArchitectureHint {
    FirmwareCpuMode mode = FirmwareCpuMode::Unknown;
    FirmwareConfidence confidence = FirmwareConfidence::None;
    std::string evidence;
};

struct FirmwareSniffOptions {
    // Signature scanning is limited to deterministic head/tail windows when an
    // input exceeds this budget. Fixed-location checks (reset vector and flash
    // descriptor at offset 0x10) still run. Zero disables signature scanning.
    size_t maxScanBytes = 64u * 1024u * 1024u;
    size_t maxFirmwareVolumes = 64;
    size_t maxOptionRoms = 64;
    size_t maxFlashDescriptors = 8;
    size_t maxLandmarks = 256;
    size_t maxEvidence = 256;
    size_t maxJumpDepth = 8;

    // Conventional raw mappings.  System firmware ending at the CPU's 4-GiB
    // boundary gets 4GiB-size; a standalone PCI ROM gets the usual C0000h
    // analysis mapping. Both are recommendations, never claims about hardware.
    bool useTopOf4GiBMapping = true;
    uint64_t optionRomBase = 0x000C0000ull;
};

struct FirmwareDetection {
    FirmwareKind kinds = FirmwareKind::None;
    FirmwareKind primaryKind = FirmwareKind::None;
    FirmwareConfidence confidence = FirmwareConfidence::None;
    bool scanTruncated = false;

    bool recommendedImageBaseValid = false;
    uint64_t recommendedImageBase = 0;
    std::string mappingEvidence;

    FirmwareArchitectureHint architecture;
    FirmwareEntryPoint entry;
    std::vector<FirmwareVolumeInfo> firmwareVolumes;
    std::vector<PciOptionRomInfo> optionRoms;
    std::vector<IntelFlashDescriptorInfo> flashDescriptors;
    std::vector<FirmwareLandmark> landmarks;
    std::vector<FirmwareEvidence> evidence;

    bool has(FirmwareKind kind) const { return HasFirmwareKind(kinds, kind); }
    bool detected() const { return kinds != FirmwareKind::None; }
};

// Resolve one common x86 firmware transfer instruction at `fileOffset`.
// Supported encodings are EB rel8, E9 rel16/rel32 (including operand-size
// override), and EA ptr16:16/ptr16:32.  A recognized but out-of-image target is
// returned as unresolved rather than wrapped or clamped.
FirmwareJump ResolveFirmwareX86Jump(const uint8_t* data,
                                    size_t size,
                                    uint64_t fileOffset,
                                    uint64_t imageBase,
                                    FirmwareCpuMode mode = FirmwareCpuMode::X86Real16);

FirmwareDetection SniffFirmware(const uint8_t* data,
                                size_t size,
                                const FirmwareSniffOptions& options = {});

inline FirmwareDetection SniffFirmware(const std::vector<uint8_t>& bytes,
                                       const FirmwareSniffOptions& options = {}) {
    return SniffFirmware(bytes.data(), bytes.size(), options);
}

const char* FirmwareConfidenceName(FirmwareConfidence confidence);
const char* FirmwareKindName(FirmwareKind kind);
const char* FirmwareCpuModeName(FirmwareCpuMode mode);

} // namespace ds
