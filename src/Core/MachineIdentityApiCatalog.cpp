#include "MachineIdentityApiCatalog.h"

#include <algorithm>
#include <array>
#include <utility>

namespace ds {
namespace {

struct CatalogOutput {
    uint8_t argumentIndex;
    MachineIdentityOutputKind kind;
    MachineIdentityDataEncoding encoding;
    MachineIdentityOutputExtent extent;
    uint8_t extentArgumentIndex;
    bool extentArgumentIndexValid;
    std::string_view memberPath;
    std::string_view lengthMemberPath;
};

struct CatalogRow {
    std::string_view dll;
    std::string_view key;
    std::string_view canonical;
    MachineIdentityApiFamily family;
    MachineIdentityReturnRule returnRule;
    std::vector<MachineIdentityApiArgument> arguments;
    std::vector<CatalogOutput> outputs;
    std::string_view meaning;
};

constexpr MachineIdentityApiArgument In(
    uint8_t index, MachineIdentityArgumentRole role, bool mayBeNull = false) {
    return {index, role, MachineIdentityArgumentDirection::Input, mayBeNull};
}

constexpr MachineIdentityApiArgument Out(
    uint8_t index, MachineIdentityArgumentRole role, bool mayBeNull = false) {
    return {index, role, MachineIdentityArgumentDirection::Output, mayBeNull};
}

constexpr MachineIdentityApiArgument InOut(
    uint8_t index, MachineIdentityArgumentRole role, bool mayBeNull = false) {
    return {index, role, MachineIdentityArgumentDirection::InputOutput, mayBeNull};
}

constexpr CatalogOutput DirectOutput(
    uint8_t index, MachineIdentityOutputKind kind,
    MachineIdentityDataEncoding encoding, MachineIdentityOutputExtent extent,
    uint8_t extentArgumentIndex = 0, bool extentArgumentIndexValid = false) {
    return {index, kind, encoding, extent, extentArgumentIndex,
            extentArgumentIndexValid, {}, {}};
}

constexpr CatalogOutput MemberOutput(
    uint8_t index, MachineIdentityOutputKind kind,
    MachineIdentityDataEncoding encoding, MachineIdentityOutputExtent extent,
    std::string_view memberPath, std::string_view lengthMemberPath = {}) {
    return {index, kind, encoding, extent, 0, false,
            memberPath, lengthMemberPath};
}

const std::array<CatalogRow, 12> kRows = {{
    {"kernel32", "getcomputernamea", "GetComputerNameA",
     MachineIdentityApiFamily::ComputerName,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {Out(0, MachineIdentityArgumentRole::ComputerNameBuffer),
      InOut(1, MachineIdentityArgumentRole::CharacterCount)},
     {DirectOutput(0, MachineIdentityOutputKind::ComputerNameText,
                   MachineIdentityDataEncoding::NarrowText,
                   MachineIdentityOutputExtent::NullTerminatedTextWithCountArgument,
                   1, true)},
     "a successful call writes the local or cluster NetBIOS name; that name is administrator-renamable and may be cluster-scoped, so proving later authorization use is still required"},
    {"kernel32", "getcomputernamew", "GetComputerNameW",
     MachineIdentityApiFamily::ComputerName,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {Out(0, MachineIdentityArgumentRole::ComputerNameBuffer),
      InOut(1, MachineIdentityArgumentRole::CharacterCount)},
     {DirectOutput(0, MachineIdentityOutputKind::ComputerNameText,
                   MachineIdentityDataEncoding::WideText,
                   MachineIdentityOutputExtent::NullTerminatedTextWithCountArgument,
                   1, true)},
     "a successful call writes the local or cluster NetBIOS name; that name is administrator-renamable and may be cluster-scoped, so proving later authorization use is still required"},
    {"kernel32", "getcomputernameexa", "GetComputerNameExA",
     MachineIdentityApiFamily::ComputerName,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {In(0, MachineIdentityArgumentRole::ComputerNameFormat),
      Out(1, MachineIdentityArgumentRole::ComputerNameBuffer, true),
      InOut(2, MachineIdentityArgumentRole::CharacterCount)},
     {DirectOutput(1, MachineIdentityOutputKind::ComputerNameText,
                   MachineIdentityDataEncoding::NarrowText,
                   MachineIdentityOutputExtent::NullTerminatedTextWithCountArgument,
                   2, true)},
     "a successful call writes the requested NetBIOS or DNS name; the NameType value decides whether it is physical or cluster-scoped, and the name remains administrator-renamable"},
    {"kernel32", "getcomputernameexw", "GetComputerNameExW",
     MachineIdentityApiFamily::ComputerName,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {In(0, MachineIdentityArgumentRole::ComputerNameFormat),
      Out(1, MachineIdentityArgumentRole::ComputerNameBuffer, true),
      InOut(2, MachineIdentityArgumentRole::CharacterCount)},
     {DirectOutput(1, MachineIdentityOutputKind::ComputerNameText,
                   MachineIdentityDataEncoding::WideText,
                   MachineIdentityOutputExtent::NullTerminatedTextWithCountArgument,
                   2, true)},
     "a successful call writes the requested NetBIOS or DNS name; the NameType value decides whether it is physical or cluster-scoped, and the name remains administrator-renamable"},

    {"advapi32", "getcurrenthwprofilea", "GetCurrentHwProfileA",
     MachineIdentityApiFamily::HardwareProfile,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {Out(0, MachineIdentityArgumentRole::HardwareProfileInfo)},
     {MemberOutput(0, MachineIdentityOutputKind::HardwareProfileGuid,
                   MachineIdentityDataEncoding::NarrowText,
                   MachineIdentityOutputExtent::StructureMember,
                   "HW_PROFILE_INFOA.szHwProfileGuid")},
     "a successful call writes the current hardware-profile GUID; this is profile identity, not proof of immutable physical hardware"},
    {"advapi32", "getcurrenthwprofilew", "GetCurrentHwProfileW",
     MachineIdentityApiFamily::HardwareProfile,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {Out(0, MachineIdentityArgumentRole::HardwareProfileInfo)},
     {MemberOutput(0, MachineIdentityOutputKind::HardwareProfileGuid,
                   MachineIdentityDataEncoding::WideText,
                   MachineIdentityOutputExtent::StructureMember,
                   "HW_PROFILE_INFOW.szHwProfileGuid")},
     "a successful call writes the current hardware-profile GUID; this is profile identity, not proof of immutable physical hardware"},

    {"kernel32", "getvolumeinformationa", "GetVolumeInformationA",
     MachineIdentityApiFamily::Volume,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {In(0, MachineIdentityArgumentRole::VolumeRootPath, true),
      Out(1, MachineIdentityArgumentRole::VolumeNameBuffer, true),
      In(2, MachineIdentityArgumentRole::VolumeNameCapacity),
      Out(3, MachineIdentityArgumentRole::VolumeSerialNumber, true),
      Out(4, MachineIdentityArgumentRole::MaximumComponentLength, true),
      Out(5, MachineIdentityArgumentRole::FileSystemFlags, true),
      Out(6, MachineIdentityArgumentRole::FileSystemNameBuffer, true),
      In(7, MachineIdentityArgumentRole::FileSystemNameCapacity)},
     {DirectOutput(3, MachineIdentityOutputKind::VolumeSerialNumber,
                   MachineIdentityDataEncoding::Unsigned32,
                   MachineIdentityOutputExtent::FixedWidthScalar)},
     "a successful call can write the OS-assigned volume serial number; it is mutable across format/reassignment and is not the drive manufacturer's serial number"},
    {"kernel32", "getvolumeinformationw", "GetVolumeInformationW",
     MachineIdentityApiFamily::Volume,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {In(0, MachineIdentityArgumentRole::VolumeRootPath, true),
      Out(1, MachineIdentityArgumentRole::VolumeNameBuffer, true),
      In(2, MachineIdentityArgumentRole::VolumeNameCapacity),
      Out(3, MachineIdentityArgumentRole::VolumeSerialNumber, true),
      Out(4, MachineIdentityArgumentRole::MaximumComponentLength, true),
      Out(5, MachineIdentityArgumentRole::FileSystemFlags, true),
      Out(6, MachineIdentityArgumentRole::FileSystemNameBuffer, true),
      In(7, MachineIdentityArgumentRole::FileSystemNameCapacity)},
     {DirectOutput(3, MachineIdentityOutputKind::VolumeSerialNumber,
                   MachineIdentityDataEncoding::Unsigned32,
                   MachineIdentityOutputExtent::FixedWidthScalar)},
     "a successful call can write the OS-assigned volume serial number; it is mutable across format/reassignment and is not the drive manufacturer's serial number"},
    {"kernel32", "getvolumeinformationbyhandlew",
     "GetVolumeInformationByHandleW",
     MachineIdentityApiFamily::Volume,
     MachineIdentityReturnRule::NonzeroBoolIsSuccess,
     {In(0, MachineIdentityArgumentRole::VolumeFileHandle),
      Out(1, MachineIdentityArgumentRole::VolumeNameBuffer, true),
      In(2, MachineIdentityArgumentRole::VolumeNameCapacity),
      Out(3, MachineIdentityArgumentRole::VolumeSerialNumber, true),
      Out(4, MachineIdentityArgumentRole::MaximumComponentLength, true),
      Out(5, MachineIdentityArgumentRole::FileSystemFlags, true),
      Out(6, MachineIdentityArgumentRole::FileSystemNameBuffer, true),
      In(7, MachineIdentityArgumentRole::FileSystemNameCapacity)},
     {DirectOutput(3, MachineIdentityOutputKind::VolumeSerialNumber,
                   MachineIdentityDataEncoding::Unsigned32,
                   MachineIdentityOutputExtent::FixedWidthScalar)},
     "a successful call can write the OS-assigned serial number for the volume selected by the file handle; it is mutable across format/reassignment and is not a hardware serial"},

    {"iphlpapi", "getadaptersaddresses", "GetAdaptersAddresses",
     MachineIdentityApiFamily::NetworkAdapter,
     MachineIdentityReturnRule::ZeroErrorCodeIsSuccess,
     {In(0, MachineIdentityArgumentRole::AddressFamily),
      In(1, MachineIdentityArgumentRole::QueryFlags),
      In(2, MachineIdentityArgumentRole::Reserved),
      InOut(3, MachineIdentityArgumentRole::AdapterRecords, true),
      InOut(4, MachineIdentityArgumentRole::BufferByteCount)},
     {MemberOutput(3, MachineIdentityOutputKind::AdapterPhysicalAddress,
                   MachineIdentityDataEncoding::Bytes,
                   MachineIdentityOutputExtent::StructureMemberWithLengthMember,
                   "IP_ADAPTER_ADDRESSES[*].PhysicalAddress",
                   "IP_ADAPTER_ADDRESSES[*].PhysicalAddressLength")},
     "ERROR_SUCCESS fills adapter records whose per-node PhysicalAddress bytes may identify an interface; adapters can be virtual, absent, or mutable"},
    {"iphlpapi", "getadaptersinfo", "GetAdaptersInfo",
     MachineIdentityApiFamily::NetworkAdapter,
     MachineIdentityReturnRule::ZeroErrorCodeIsSuccess,
     {Out(0, MachineIdentityArgumentRole::AdapterRecords, true),
      InOut(1, MachineIdentityArgumentRole::BufferByteCount)},
     {MemberOutput(0, MachineIdentityOutputKind::AdapterPhysicalAddress,
                   MachineIdentityDataEncoding::Bytes,
                   MachineIdentityOutputExtent::StructureMemberWithLengthMember,
                   "IP_ADAPTER_INFO[*].Address",
                   "IP_ADAPTER_INFO[*].AddressLength")},
     "ERROR_SUCCESS fills IPv4 adapter records whose per-node Address bytes may identify an interface; adapters can be virtual, absent, or mutable"},

    {"kernel32", "getsystemfirmwaretable", "GetSystemFirmwareTable",
     MachineIdentityApiFamily::Firmware,
     MachineIdentityReturnRule::ByteCountOrRequiredSize,
     {In(0, MachineIdentityArgumentRole::FirmwareProviderSignature),
      In(1, MachineIdentityArgumentRole::FirmwareTableId),
      Out(2, MachineIdentityArgumentRole::FirmwareTableBuffer, true),
      In(3, MachineIdentityArgumentRole::FirmwareTableBufferSize)},
     {DirectOutput(2, MachineIdentityOutputKind::FirmwareTableBytes,
                   MachineIdentityDataEncoding::Bytes,
                   MachineIdentityOutputExtent::ReturnValueByteCount)},
     "a completed call writes the selected ACPI, raw-firmware, or SMBIOS table; identity requires parsing a specific returned record and proving its later use"},
}};

static_assert(std::tuple_size_v<decltype(kRows)> <=
              kMachineIdentityApiCatalogHardMaxRows);

constexpr char AsciiLower(char c) noexcept {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

constexpr bool IsSpace(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
           c == '\f' || c == '\v';
}

std::string_view TrimView(std::string_view value) {
    while (!value.empty() && IsSpace(value.front())) value.remove_prefix(1);
    while (!value.empty() && IsSpace(value.back())) value.remove_suffix(1);
    return value;
}

bool AllDigits(std::string_view value) {
    return !value.empty() &&
        std::all_of(value.begin(), value.end(), [](char c) {
            return c >= '0' && c <= '9';
        });
}

MachineIdentityApiMatch MakeMatch(const CatalogRow& row) {
    MachineIdentityApiMatch result;
    result.dll.assign(row.dll);
    result.canonicalName.assign(row.canonical);
    result.normalizedName.assign(row.key);
    result.family = row.family;
    result.returnRule = row.returnRule;
    result.arguments.assign(row.arguments.begin(), row.arguments.end());
    result.outputs.reserve(row.outputs.size());
    for (const CatalogOutput& output : row.outputs) {
        MachineIdentityApiOutput matchOutput;
        matchOutput.argumentIndex = output.argumentIndex;
        matchOutput.kind = output.kind;
        matchOutput.encoding = output.encoding;
        matchOutput.extent = output.extent;
        matchOutput.extentArgumentIndex = output.extentArgumentIndex;
        matchOutput.extentArgumentIndexValid = output.extentArgumentIndexValid;
        matchOutput.memberPath.assign(output.memberPath);
        matchOutput.lengthMemberPath.assign(output.lengthMemberPath);
        result.outputs.push_back(std::move(matchOutput));
    }
    result.meaning.assign(row.meaning);
    return result;
}

} // namespace

const char* MachineIdentityApiFamilyText(MachineIdentityApiFamily family) {
    switch (family) {
    case MachineIdentityApiFamily::ComputerName:    return "computer name";
    case MachineIdentityApiFamily::HardwareProfile: return "hardware profile";
    case MachineIdentityApiFamily::Volume:          return "volume";
    case MachineIdentityApiFamily::NetworkAdapter:  return "network adapter";
    case MachineIdentityApiFamily::Firmware:        return "firmware";
    }
    return "unknown";
}

const char* MachineIdentityReturnRuleText(MachineIdentityReturnRule rule) {
    switch (rule) {
    case MachineIdentityReturnRule::NonzeroBoolIsSuccess:
        return "nonzero BOOL means success";
    case MachineIdentityReturnRule::ZeroErrorCodeIsSuccess:
        return "zero error code means success";
    case MachineIdentityReturnRule::ByteCountOrRequiredSize:
        return "return is bytes written or required size";
    }
    return "unknown";
}

const char* MachineIdentityResultStatusText(MachineIdentityResultStatus status) {
    switch (status) {
    case MachineIdentityResultStatus::Failure:       return "failure";
    case MachineIdentityResultStatus::Success:       return "success";
    case MachineIdentityResultStatus::Indeterminate: return "indeterminate";
    }
    return "unknown";
}

const char* MachineIdentityEvidenceRuleText(MachineIdentityEvidenceRule rule) {
    switch (rule) {
    case MachineIdentityEvidenceRule::CapabilityOnlyUntilOutputFlowsToAuthorization:
        return "capability only until the exact output flows to authorization";
    }
    return "unknown";
}

const char* MachineIdentityArgumentDirectionText(
    MachineIdentityArgumentDirection direction) {
    switch (direction) {
    case MachineIdentityArgumentDirection::Input:       return "input";
    case MachineIdentityArgumentDirection::Output:      return "output";
    case MachineIdentityArgumentDirection::InputOutput: return "input/output";
    }
    return "unknown";
}

const char* MachineIdentityArgumentRoleText(MachineIdentityArgumentRole role) {
    switch (role) {
    case MachineIdentityArgumentRole::ComputerNameFormat:       return "computer-name format";
    case MachineIdentityArgumentRole::ComputerNameBuffer:       return "computer-name buffer";
    case MachineIdentityArgumentRole::CharacterCount:           return "character count";
    case MachineIdentityArgumentRole::HardwareProfileInfo:      return "hardware-profile info";
    case MachineIdentityArgumentRole::VolumeRootPath:           return "volume root path";
    case MachineIdentityArgumentRole::VolumeFileHandle:         return "volume file handle";
    case MachineIdentityArgumentRole::VolumeNameBuffer:         return "volume-name buffer";
    case MachineIdentityArgumentRole::VolumeNameCapacity:       return "volume-name capacity";
    case MachineIdentityArgumentRole::VolumeSerialNumber:       return "volume serial number";
    case MachineIdentityArgumentRole::MaximumComponentLength:   return "maximum component length";
    case MachineIdentityArgumentRole::FileSystemFlags:          return "file-system flags";
    case MachineIdentityArgumentRole::FileSystemNameBuffer:     return "file-system-name buffer";
    case MachineIdentityArgumentRole::FileSystemNameCapacity:   return "file-system-name capacity";
    case MachineIdentityArgumentRole::AddressFamily:            return "address family";
    case MachineIdentityArgumentRole::QueryFlags:               return "query flags";
    case MachineIdentityArgumentRole::Reserved:                 return "reserved";
    case MachineIdentityArgumentRole::AdapterRecords:           return "adapter records";
    case MachineIdentityArgumentRole::BufferByteCount:          return "buffer byte count";
    case MachineIdentityArgumentRole::FirmwareProviderSignature:return "firmware provider signature";
    case MachineIdentityArgumentRole::FirmwareTableId:          return "firmware table id";
    case MachineIdentityArgumentRole::FirmwareTableBuffer:      return "firmware-table buffer";
    case MachineIdentityArgumentRole::FirmwareTableBufferSize:  return "firmware-table buffer size";
    }
    return "unknown";
}

const char* MachineIdentityOutputKindText(MachineIdentityOutputKind kind) {
    switch (kind) {
    case MachineIdentityOutputKind::ComputerNameText:       return "computer-name text";
    case MachineIdentityOutputKind::HardwareProfileGuid:    return "hardware-profile GUID";
    case MachineIdentityOutputKind::VolumeSerialNumber:     return "volume serial number";
    case MachineIdentityOutputKind::AdapterPhysicalAddress: return "adapter physical address";
    case MachineIdentityOutputKind::FirmwareTableBytes:     return "firmware-table bytes";
    }
    return "unknown";
}

const char* MachineIdentityDataEncodingText(
    MachineIdentityDataEncoding encoding) {
    switch (encoding) {
    case MachineIdentityDataEncoding::Bytes:       return "bytes";
    case MachineIdentityDataEncoding::NarrowText:  return "narrow text";
    case MachineIdentityDataEncoding::WideText:    return "wide text";
    case MachineIdentityDataEncoding::Unsigned32:  return "unsigned 32-bit integer";
    }
    return "unknown";
}

const char* MachineIdentityOutputExtentText(MachineIdentityOutputExtent extent) {
    switch (extent) {
    case MachineIdentityOutputExtent::NullTerminatedTextWithCountArgument:
        return "NUL-terminated text bounded by count argument";
    case MachineIdentityOutputExtent::FixedWidthScalar:
        return "fixed-width scalar";
    case MachineIdentityOutputExtent::StructureMember:
        return "structure member";
    case MachineIdentityOutputExtent::StructureMemberWithLengthMember:
        return "structure member bounded by sibling length member";
    case MachineIdentityOutputExtent::ReturnValueByteCount:
        return "direct buffer bounded by return byte count";
    }
    return "unknown";
}

std::string NormalizeMachineIdentityDll(std::string_view dll) {
    if (dll.size() > kMachineIdentityLookupFieldMaxBytes) return {};
    dll = TrimView(dll);
    if (const size_t bang = dll.find('!'); bang != std::string_view::npos)
        dll = TrimView(dll.substr(0, bang));
    if (const size_t slash = dll.find_last_of("/\\");
        slash != std::string_view::npos)
        dll.remove_prefix(slash + 1);
    dll = TrimView(dll);
    if (dll.empty() || dll.size() > kMachineIdentityNormalizedDllMaxBytes)
        return {};

    std::string result;
    result.reserve(dll.size());
    for (char c : dll) result.push_back(AsciiLower(c));
    if (result.size() > 4 && result.ends_with(".dll"))
        result.resize(result.size() - 4);
    if (result.empty() || result.size() > kMachineIdentityNormalizedDllMaxBytes)
        return {};
    return result;
}

std::string NormalizeMachineIdentityApiName(std::string_view symbol) {
    if (symbol.size() > kMachineIdentityLookupFieldMaxBytes) return {};
    symbol = TrimView(symbol);
    if (const size_t bang = symbol.rfind('!'); bang != std::string_view::npos)
        symbol = TrimView(symbol.substr(bang + 1));
    if (symbol.empty() || symbol.size() > kMachineIdentityNormalizedSymbolMaxBytes)
        return {};

    std::string result;
    result.reserve(symbol.size());
    for (char c : symbol) result.push_back(AsciiLower(c));
    constexpr std::string_view prefixes[] = {
        "__imp__", "__imp_", "_imp__", "_imp_", "imp_",
    };
    for (size_t pass = 0; pass < 8; ++pass) {
        bool stripped = false;
        for (std::string_view prefix : prefixes) {
            if (result.starts_with(prefix)) {
                result.erase(0, prefix.size());
                stripped = true;
                break;
            }
        }
        if (!stripped) break;
    }
    while (!result.empty() &&
           (result.front() == '_' || result.front() == '@'))
        result.erase(result.begin());
    if (const size_t at = result.rfind('@');
        at != std::string::npos && AllDigits(std::string_view(result).substr(at + 1)))
        result.resize(at);
    if (result.empty() || result.size() > kMachineIdentityNormalizedSymbolMaxBytes)
        return {};
    return result;
}

std::optional<MachineIdentityApiMatch> LookupMachineIdentityApi(
    std::string_view dll, std::string_view symbol) {
    if (dll.size() > kMachineIdentityLookupFieldMaxBytes ||
        symbol.size() > kMachineIdentityLookupFieldMaxBytes)
        return std::nullopt;

    const std::string_view suppliedDll = TrimView(dll);
    const bool moduleSupplied = !suppliedDll.empty();
    std::string module = NormalizeMachineIdentityDll(suppliedDll);
    if (moduleSupplied && module.empty()) return std::nullopt;

    const std::string_view trimmedSymbol = TrimView(symbol);
    const size_t bang = trimmedSymbol.find('!');
    if (bang != std::string_view::npos) {
        if (trimmedSymbol.find('!', bang + 1) != std::string_view::npos)
            return std::nullopt;
        const std::string qualifiedModule =
            NormalizeMachineIdentityDll(trimmedSymbol.substr(0, bang));
        if (qualifiedModule.empty()) return std::nullopt;
        if (module.empty()) module = qualifiedModule;
        else if (module != qualifiedModule) return std::nullopt;
    }
    if (module.empty()) return std::nullopt;

    const std::string name = NormalizeMachineIdentityApiName(trimmedSymbol);
    if (name.empty()) return std::nullopt;
    for (const CatalogRow& row : kRows)
        if (row.dll == module && row.key == name) return MakeMatch(row);
    return std::nullopt;
}

MachineIdentityResultStatus EvaluateMachineIdentityApiResult(
    const MachineIdentityApiMatch& api, uint64_t rawValue,
    bool identityOutputBufferPresent, uint64_t identityOutputCapacity) {
    const uint32_t low32 = static_cast<uint32_t>(rawValue);
    switch (api.returnRule) {
    case MachineIdentityReturnRule::NonzeroBoolIsSuccess:
        return low32 != 0 ? MachineIdentityResultStatus::Success
                          : MachineIdentityResultStatus::Failure;
    case MachineIdentityReturnRule::ZeroErrorCodeIsSuccess:
        return low32 == 0 ? MachineIdentityResultStatus::Success
                          : MachineIdentityResultStatus::Failure;
    case MachineIdentityReturnRule::ByteCountOrRequiredSize:
        if (!low32) return MachineIdentityResultStatus::Failure;
        if (!identityOutputBufferPresent || !identityOutputCapacity ||
            low32 > identityOutputCapacity)
            return MachineIdentityResultStatus::Indeterminate;
        return MachineIdentityResultStatus::Success;
    }
    return MachineIdentityResultStatus::Indeterminate;
}

std::vector<MachineIdentityApiMatch> EnumerateMachineIdentityApis() {
    std::vector<MachineIdentityApiMatch> result;
    result.reserve(std::size(kRows));
    for (const CatalogRow& row : kRows) result.push_back(MakeMatch(row));
    return result;
}

} // namespace ds
