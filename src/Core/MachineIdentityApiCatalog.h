#pragma once
//
// MachineIdentityApiCatalog.h
// Exact, bounded DLL+symbol contracts for Windows APIs that can return
// machine-identity material. Import or call presence is capability evidence
// only. A caller must prove that a successful call produced the documented
// output and that those exact bytes flow into an authorization request or
// verification decision before describing an entitlement as machine-bound.
//

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

inline constexpr size_t kMachineIdentityLookupFieldMaxBytes = 1024;
inline constexpr size_t kMachineIdentityNormalizedDllMaxBytes = 128;
inline constexpr size_t kMachineIdentityNormalizedSymbolMaxBytes = 256;
inline constexpr size_t kMachineIdentityApiCatalogHardMaxRows = 32;

enum class MachineIdentityApiFamily : uint8_t {
    ComputerName = 0,
    HardwareProfile,
    Volume,
    NetworkAdapter,
    Firmware,
};

enum class MachineIdentityReturnRule : uint8_t {
    NonzeroBoolIsSuccess = 0,
    ZeroErrorCodeIsSuccess,
    ByteCountOrRequiredSize,
};

enum class MachineIdentityResultStatus : uint8_t {
    Failure = 0,
    Success,
    Indeterminate,
};

enum class MachineIdentityEvidenceRule : uint8_t {
    CapabilityOnlyUntilOutputFlowsToAuthorization = 0,
};

enum class MachineIdentityArgumentDirection : uint8_t {
    Input = 0,
    Output,
    InputOutput,
};

enum class MachineIdentityArgumentRole : uint8_t {
    ComputerNameFormat = 0,
    ComputerNameBuffer,
    CharacterCount,
    HardwareProfileInfo,
    VolumeRootPath,
    VolumeFileHandle,
    VolumeNameBuffer,
    VolumeNameCapacity,
    VolumeSerialNumber,
    MaximumComponentLength,
    FileSystemFlags,
    FileSystemNameBuffer,
    FileSystemNameCapacity,
    AddressFamily,
    QueryFlags,
    Reserved,
    AdapterRecords,
    BufferByteCount,
    FirmwareProviderSignature,
    FirmwareTableId,
    FirmwareTableBuffer,
    FirmwareTableBufferSize,
};

enum class MachineIdentityOutputKind : uint8_t {
    ComputerNameText = 0,
    HardwareProfileGuid,
    VolumeSerialNumber,
    AdapterPhysicalAddress,
    FirmwareTableBytes,
};

enum class MachineIdentityDataEncoding : uint8_t {
    Bytes = 0,
    NarrowText,
    WideText,
    Unsigned32,
};

enum class MachineIdentityOutputExtent : uint8_t {
    NullTerminatedTextWithCountArgument = 0,
    FixedWidthScalar,
    StructureMember,
    StructureMemberWithLengthMember,
    ReturnValueByteCount,
};

const char* MachineIdentityApiFamilyText(MachineIdentityApiFamily family);
const char* MachineIdentityReturnRuleText(MachineIdentityReturnRule rule);
const char* MachineIdentityResultStatusText(MachineIdentityResultStatus status);
const char* MachineIdentityEvidenceRuleText(MachineIdentityEvidenceRule rule);
const char* MachineIdentityArgumentDirectionText(
    MachineIdentityArgumentDirection direction);
const char* MachineIdentityArgumentRoleText(MachineIdentityArgumentRole role);
const char* MachineIdentityOutputKindText(MachineIdentityOutputKind kind);
const char* MachineIdentityDataEncodingText(MachineIdentityDataEncoding encoding);
const char* MachineIdentityOutputExtentText(MachineIdentityOutputExtent extent);

struct MachineIdentityApiArgument {
    uint8_t index = 0; // zero-based ABI argument index
    MachineIdentityArgumentRole role =
        MachineIdentityArgumentRole::ComputerNameFormat;
    MachineIdentityArgumentDirection direction =
        MachineIdentityArgumentDirection::Input;
    // True only where the documented contract permits a null pointer (often a
    // size query). Identity extraction still requires a non-null completed output.
    bool mayBeNull = false;
};

struct MachineIdentityApiOutput {
    uint8_t argumentIndex = 0; // zero-based identity-bearing output argument
    MachineIdentityOutputKind kind =
        MachineIdentityOutputKind::ComputerNameText;
    MachineIdentityDataEncoding encoding =
        MachineIdentityDataEncoding::Bytes;
    MachineIdentityOutputExtent extent =
        MachineIdentityOutputExtent::FixedWidthScalar;

    // For count-bounded direct buffers, identifies the exact size/capacity
    // argument. Structure-member and return-count outputs leave this invalid.
    uint8_t extentArgumentIndex = 0;
    bool extentArgumentIndexValid = false;

    // Exact SDK member paths for identity nested inside an output structure.
    // lengthMemberPath is populated only when a sibling member bounds the bytes.
    std::string memberPath;
    std::string lengthMemberPath;
};

struct MachineIdentityApiMatch {
    std::string dll;            // normalized lower-case basename, no .dll
    std::string canonicalName;  // stable SDK spelling
    std::string normalizedName; // decoration-free lower-case exact key
    MachineIdentityApiFamily family = MachineIdentityApiFamily::ComputerName;
    MachineIdentityReturnRule returnRule =
        MachineIdentityReturnRule::NonzeroBoolIsSuccess;
    std::vector<MachineIdentityApiArgument> arguments;
    std::vector<MachineIdentityApiOutput> outputs;

    MachineIdentityEvidenceRule evidenceRule =
        MachineIdentityEvidenceRule::CapabilityOnlyUntilOutputFlowsToAuthorization;
    // Kept explicit so adapters cannot accidentally promote a matching import
    // or call to a machine-bound entitlement conclusion.
    bool requiresProvenAuthorizationDataFlow = true;
    std::string meaning;
};

// Bounded normalization removes only paths, a trailing .dll, common import/C
// decorations, and a numeric stdcall suffix. A/W suffixes remain significant.
std::string NormalizeMachineIdentityDll(std::string_view dll);
std::string NormalizeMachineIdentityApiName(std::string_view symbol);

// Exact module+symbol lookup. A single module qualifier in `symbol` may supply
// an omitted `dll`; a conflicting explicit module is rejected.
std::optional<MachineIdentityApiMatch> LookupMachineIdentityApi(
    std::string_view dll, std::string_view symbol);

// Interprets only the documented API-level result. For firmware-table calls,
// a positive return is a successful data retrieval only when a non-null output
// buffer was supplied and the returned count fits its capacity; otherwise it
// may merely be a required-size query and remains indeterminate.
MachineIdentityResultStatus EvaluateMachineIdentityApiResult(
    const MachineIdentityApiMatch& api, uint64_t rawValue,
    bool identityOutputBufferPresent = false,
    uint64_t identityOutputCapacity = 0);

std::vector<MachineIdentityApiMatch> EnumerateMachineIdentityApis();

} // namespace ds
