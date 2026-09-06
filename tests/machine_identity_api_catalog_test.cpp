#include "Core/MachineIdentityApiCatalog.h"

#include <cstdio>
#include <set>
#include <string>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static const MachineIdentityApiArgument* FindArgument(
    const MachineIdentityApiMatch& api, uint8_t index) {
    for (const MachineIdentityApiArgument& argument : api.arguments)
        if (argument.index == index) return &argument;
    return nullptr;
}

int main() {
    CHECK(NormalizeMachineIdentityDll(
              " C:\\Windows\\System32\\KERNEL32.DLL ") == "kernel32");
    CHECK(NormalizeMachineIdentityApiName(
              "KERNEL32.dll!__imp__GetComputerNameW@8") ==
          "getcomputernamew");
    CHECK(NormalizeMachineIdentityApiName("GetComputerNameW") !=
          NormalizeMachineIdentityApiName("GetComputerNameA"));

    const auto computer = LookupMachineIdentityApi(
        "C:\\Windows\\System32\\KERNEL32.DLL",
        "__imp__GetComputerNameW@8");
    CHECK(computer.has_value());
    CHECK(computer && computer->family == MachineIdentityApiFamily::ComputerName);
    CHECK(computer && computer->outputs.size() == 1);
    CHECK(computer && computer->outputs[0].argumentIndex == 0);
    CHECK(computer && computer->outputs[0].kind ==
                            MachineIdentityOutputKind::ComputerNameText);
    CHECK(computer && computer->outputs[0].encoding ==
                            MachineIdentityDataEncoding::WideText);
    CHECK(computer && computer->outputs[0].extentArgumentIndexValid &&
          computer->outputs[0].extentArgumentIndex == 1);
    CHECK(computer && FindArgument(*computer, 0) &&
          !FindArgument(*computer, 0)->mayBeNull);
    CHECK(computer && computer->requiresProvenAuthorizationDataFlow);
    CHECK(computer && EvaluateMachineIdentityApiResult(*computer, 1) ==
                          MachineIdentityResultStatus::Success);
    CHECK(computer && EvaluateMachineIdentityApiResult(*computer, 0) ==
                          MachineIdentityResultStatus::Failure);

    const auto computerEx = LookupMachineIdentityApi(
        "", "kernel32.dll!_GetComputerNameExA@12");
    CHECK(computerEx && computerEx->outputs[0].argumentIndex == 1);
    CHECK(computerEx && computerEx->outputs[0].extentArgumentIndex == 2);
    CHECK(computerEx && FindArgument(*computerEx, 0) &&
          FindArgument(*computerEx, 0)->role ==
              MachineIdentityArgumentRole::ComputerNameFormat);
    CHECK(computerEx && FindArgument(*computerEx, 1) &&
          FindArgument(*computerEx, 1)->mayBeNull);

    const auto profile = LookupMachineIdentityApi(
        "advapi32", "__imp_GetCurrentHwProfileW");
    CHECK(profile && profile->family == MachineIdentityApiFamily::HardwareProfile);
    CHECK(profile && profile->outputs[0].argumentIndex == 0);
    CHECK(profile && profile->outputs[0].memberPath ==
                       "HW_PROFILE_INFOW.szHwProfileGuid");
    CHECK(profile && profile->outputs[0].extent ==
                       MachineIdentityOutputExtent::StructureMember);

    const auto volume = LookupMachineIdentityApi(
        "kernel32", "GetVolumeInformationA");
    CHECK(volume && volume->family == MachineIdentityApiFamily::Volume);
    CHECK(volume && volume->arguments.size() == 8);
    CHECK(volume && volume->outputs[0].argumentIndex == 3);
    CHECK(volume && volume->outputs[0].kind ==
                      MachineIdentityOutputKind::VolumeSerialNumber);
    CHECK(volume && volume->outputs[0].encoding ==
                      MachineIdentityDataEncoding::Unsigned32);
    CHECK(volume && FindArgument(*volume, 3) &&
          FindArgument(*volume, 3)->direction ==
              MachineIdentityArgumentDirection::Output);
    CHECK(volume && FindArgument(*volume, 3) &&
          FindArgument(*volume, 3)->mayBeNull);

    const auto handleVolume = LookupMachineIdentityApi(
        "kernel32.dll", "GetVolumeInformationByHandleW");
    CHECK(handleVolume && FindArgument(*handleVolume, 0) &&
          FindArgument(*handleVolume, 0)->role ==
              MachineIdentityArgumentRole::VolumeFileHandle);
    CHECK(!LookupMachineIdentityApi(
        "kernel32.dll", "GetVolumeInformationByHandleA"));

    const auto adapters = LookupMachineIdentityApi(
        "IPHLPAPI.DLL", "GetAdaptersAddresses");
    CHECK(adapters && adapters->family ==
                        MachineIdentityApiFamily::NetworkAdapter);
    CHECK(adapters && adapters->returnRule ==
                        MachineIdentityReturnRule::ZeroErrorCodeIsSuccess);
    CHECK(adapters && adapters->outputs[0].argumentIndex == 3);
    CHECK(adapters && adapters->outputs[0].memberPath ==
                        "IP_ADAPTER_ADDRESSES[*].PhysicalAddress");
    CHECK(adapters && adapters->outputs[0].lengthMemberPath ==
                        "IP_ADAPTER_ADDRESSES[*].PhysicalAddressLength");
    CHECK(adapters && EvaluateMachineIdentityApiResult(*adapters, 0) ==
                        MachineIdentityResultStatus::Success);
    CHECK(adapters && EvaluateMachineIdentityApiResult(*adapters, 111) ==
                        MachineIdentityResultStatus::Failure);

    const auto legacyAdapters = LookupMachineIdentityApi(
        "iphlpapi", "_GetAdaptersInfo@8");
    CHECK(legacyAdapters && legacyAdapters->outputs[0].argumentIndex == 0);
    CHECK(legacyAdapters && legacyAdapters->outputs[0].memberPath ==
                              "IP_ADAPTER_INFO[*].Address");
    CHECK(legacyAdapters && legacyAdapters->outputs[0].lengthMemberPath ==
                              "IP_ADAPTER_INFO[*].AddressLength");

    const auto firmware = LookupMachineIdentityApi(
        "kernel32", "GetSystemFirmwareTable");
    CHECK(firmware && firmware->family == MachineIdentityApiFamily::Firmware);
    CHECK(firmware && firmware->outputs[0].argumentIndex == 2);
    CHECK(firmware && firmware->outputs[0].extent ==
                       MachineIdentityOutputExtent::ReturnValueByteCount);
    CHECK(firmware && EvaluateMachineIdentityApiResult(*firmware, 0, true, 4096) ==
                       MachineIdentityResultStatus::Failure);
    CHECK(firmware && EvaluateMachineIdentityApiResult(*firmware, 512) ==
                       MachineIdentityResultStatus::Indeterminate); // size query
    CHECK(firmware && EvaluateMachineIdentityApiResult(*firmware, 8192, true, 4096) ==
                       MachineIdentityResultStatus::Indeterminate); // required size
    CHECK(firmware && EvaluateMachineIdentityApiResult(*firmware, 512, true, 4096) ==
                       MachineIdentityResultStatus::Success);

    // Exact module and complete symbol identity block lookalikes and capability
    // inflation. EnumSystemFirmwareTables exposes table IDs, not table contents.
    CHECK(!LookupMachineIdentityApi("user32", "GetComputerNameW"));
    CHECK(!LookupMachineIdentityApi("kernelbase", "GetComputerNameW"));
    CHECK(!LookupMachineIdentityApi("kernel32", "GetComputerNameWorkerW"));
    CHECK(!LookupMachineIdentityApi("kernel32", "MyGetSystemFirmwareTable"));
    CHECK(!LookupMachineIdentityApi("kernel32", "EnumSystemFirmwareTables"));
    CHECK(!LookupMachineIdentityApi("iphlpapi", "GetIfTable"));
    CHECK(!LookupMachineIdentityApi("kernel32",
                                    "advapi32!GetCurrentHwProfileW"));
    CHECK(!LookupMachineIdentityApi("", "GetComputerNameW"));
    CHECK(!LookupMachineIdentityApi("kernel32",
                                    "kernel32!other!GetComputerNameW"));

    const std::string oversized(kMachineIdentityLookupFieldMaxBytes + 1, 'x');
    CHECK(NormalizeMachineIdentityDll(oversized).empty());
    CHECK(NormalizeMachineIdentityApiName(oversized).empty());
    CHECK(!LookupMachineIdentityApi(oversized, "GetComputerNameW"));

    const auto catalog = EnumerateMachineIdentityApis();
    CHECK(catalog.size() == 12);
    CHECK(catalog.size() <= kMachineIdentityApiCatalogHardMaxRows);
    std::set<std::string> uniqueKeys;
    for (const MachineIdentityApiMatch& row : catalog) {
        CHECK(!row.dll.empty());
        CHECK(!row.canonicalName.empty());
        CHECK(!row.normalizedName.empty());
        CHECK(!row.arguments.empty());
        CHECK(!row.outputs.empty());
        CHECK(!row.meaning.empty());
        CHECK(row.requiresProvenAuthorizationDataFlow);
        CHECK(row.evidenceRule == MachineIdentityEvidenceRule::
                                      CapabilityOnlyUntilOutputFlowsToAuthorization);
        CHECK(uniqueKeys.insert(row.dll + "!" + row.normalizedName).second);
        const auto roundTrip = LookupMachineIdentityApi(
            row.dll, row.canonicalName);
        CHECK(roundTrip && roundTrip->family == row.family);
        CHECK(std::string(MachineIdentityApiFamilyText(row.family)) != "unknown");
        CHECK(std::string(MachineIdentityReturnRuleText(row.returnRule)) != "unknown");
        CHECK(std::string(MachineIdentityEvidenceRuleText(row.evidenceRule)).find(
                  "capability only") != std::string::npos);
        for (const MachineIdentityApiArgument& argument : row.arguments) {
            CHECK(std::string(MachineIdentityArgumentRoleText(argument.role)) !=
                  "unknown");
            CHECK(std::string(MachineIdentityArgumentDirectionText(
                      argument.direction)) != "unknown");
        }
        for (const MachineIdentityApiOutput& output : row.outputs) {
            CHECK(std::string(MachineIdentityOutputKindText(output.kind)) !=
                  "unknown");
            CHECK(std::string(MachineIdentityDataEncodingText(output.encoding)) !=
                  "unknown");
            CHECK(std::string(MachineIdentityOutputExtentText(output.extent)) !=
                  "unknown");
        }
    }

    if (failures) return 1;
    std::puts("machine identity API catalog tests passed");
    return 0;
}
