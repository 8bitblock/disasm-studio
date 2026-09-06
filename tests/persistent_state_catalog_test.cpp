#include "Core/PersistentStateCatalog.h"

#include <cstdio>
#include <string>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static const PersistentStateApiArgument* findRole(
    const PersistentStateApiMatch& api, PersistentStateArgumentRole role) {
    for (const auto& argument : api.arguments)
        if (argument.role == role) return &argument;
    return nullptr;
}

int main() {
    CHECK(NormalizePersistentStateDll(
        "C:\\Windows\\System32\\ADVAPI32.DLL") == "advapi32");
    CHECK(NormalizePersistentStateApiName("__imp__RegQueryValueExW@24") ==
          "regqueryvalueex");
    CHECK(NormalizePersistentStateApiName("_wfopen") == "wfopen");

    const auto query = LookupPersistentStateApi(
        "ADVAPI32.dll", "__imp__RegQueryValueExW@24");
    CHECK(query && query->kind == PersistentStateKind::Registry);
    CHECK(query && query->access == PersistentStateAccess::Read);
    CHECK(query && query->consumesHandleLineage);
    CHECK(query && findRole(*query, PersistentStateArgumentRole::OutputBuffer));
    CHECK(query && findRole(*query, PersistentStateArgumentRole::OutputBuffer) &&
          findRole(*query, PersistentStateArgumentRole::OutputBuffer)->argumentIndex == 4);

    const auto set = LookupPersistentStateApi("advapi32", "RegSetValueExA");
    CHECK(set && set->access == PersistentStateAccess::Write);
    CHECK(set && findRole(*set, PersistentStateArgumentRole::DataBuffer) &&
          findRole(*set, PersistentStateArgumentRole::DataBuffer)->argumentIndex == 4);
    const auto setKey = LookupPersistentStateApi("advapi32", "RegSetKeyValueW");
    CHECK(setKey && findRole(*setKey, PersistentStateArgumentRole::DataBuffer) &&
          findRole(*setKey, PersistentStateArgumentRole::DataBuffer)->argumentIndex == 4);

    const auto getValue = LookupPersistentStateApi("advapi32", "RegGetValueW");
    CHECK(getValue && findRole(*getValue, PersistentStateArgumentRole::OutputBuffer));
    CHECK(getValue && findRole(*getValue, PersistentStateArgumentRole::OutputBuffer) &&
          findRole(*getValue, PersistentStateArgumentRole::OutputBuffer)->argumentIndex == 5);
    const auto createKey = LookupPersistentStateApi("advapi32", "RegCreateKeyExW");
    CHECK(createKey && createKey->access == PersistentStateAccess::Write);

    const auto protect = LookupPersistentStateApi("crypt32", "CryptProtectData");
    CHECK(protect && protect->kind == PersistentStateKind::DpapiTransform);
    CHECK(protect && protect->access == PersistentStateAccess::Protect);
    CHECK(protect && findRole(*protect, PersistentStateArgumentRole::OutputBuffer) &&
          findRole(*protect, PersistentStateArgumentRole::OutputBuffer)->argumentIndex == 6);

    const auto create = LookupPersistentStateApi("kernel32", "CreateFileW");
    CHECK(create && create->returnContract.successRule ==
                    PersistentStateSuccessRule::NotInvalidHandle);
    CHECK(create && create->accessDependsOnArguments);
    CHECK(create && !PersistentStateReturnIsImmediateSuccess(
                        create->returnContract, UINT64_MAX, 64));
    CHECK(create && !PersistentStateReturnIsImmediateSuccess(
                        create->returnContract, UINT64_C(0xFFFFFFFF), 32));
    CHECK(create && PersistentStateReturnIsImmediateSuccess(
                        create->returnContract, UINT64_C(0xFFFFFFFF), 64));

    CHECK(LookupPersistentStateApi("kernelbase", "ReadFile"));
    CHECK(LookupPersistentStateApi("ucrtbase", "_wfopen"));
    CHECK(LookupPersistentStateApi("ucrtbase", "fopen_s"));
    CHECK(LookupPersistentStateApi("api-ms-win-crt-lowio-l1-1-0", "_read"));
    CHECK(LookupPersistentStateApi("advapi32", "CredReadW"));
    CHECK(LookupPersistentStateApi("kernel32", "GetPrivateProfileStringA"));
    const auto profile = LookupPersistentStateApi(
        "kernel32", "GetPrivateProfileStringW");
    CHECK(profile && findRole(*profile, PersistentStateArgumentRole::ResourcePath));
    CHECK(profile && findRole(*profile, PersistentStateArgumentRole::ResourcePath) &&
          findRole(*profile, PersistentStateArgumentRole::ResourcePath)->argumentIndex == 5);
    CHECK(profile && profile->returnContract.successRule ==
                     PersistentStateSuccessRule::Indeterminate);
    const auto fread = LookupPersistentStateApi("ucrtbase", "fread");
    CHECK(fread && fread->returnContract.successRule ==
                   PersistentStateSuccessRule::Indeterminate);
    const auto attributes = LookupPersistentStateApi(
        "kernel32", "GetFileAttributesW");
    CHECK(attributes && attributes->access == PersistentStateAccess::Read);
    CHECK(attributes && !PersistentStateReturnIsImmediateSuccess(
                            attributes->returnContract, UINT64_C(0xFFFFFFFF)));

    // Exact DLL qualification prevents resemblance-based false positives.
    CHECK(!LookupPersistentStateApi("user32", "ReadFile"));
    CHECK(!LookupPersistentStateApi("kernel32", "RegQueryValueExW"));
    CHECK(!LookupPersistentStateApi("advapi32", "ReadFile"));
    CHECK(!LookupPersistentStateApi("advapi32", "kernel32!RegGetValueW"));
    CHECK(!LookupPersistentStateApi("", "RegGetValueW"));

    const auto rows = EnumeratePersistentStateApis();
    CHECK(rows.size() >= 35);
    for (const auto& row : rows) {
        const auto roundTrip = LookupPersistentStateApi(row.dll, row.canonicalName);
        CHECK(roundTrip && roundTrip->kind == row.kind);
        CHECK(roundTrip && roundTrip->access == row.access);
        CHECK(roundTrip && !roundTrip->returnContract.returnType.empty());
        CHECK(roundTrip && !roundTrip->returnContract.successMeaning.empty());
        CHECK(roundTrip && !roundTrip->returnContract.failureMeaning.empty());
        CHECK(std::string(PersistentStateReturnKindText(
                  row.returnContract.kind)) != "unknown");
        CHECK(std::string(PersistentStateSuccessRuleText(
                  row.returnContract.successRule)) != "unknown");
        for (const auto& argument : row.arguments)
            CHECK(std::string(PersistentStateArgumentRoleText(argument.role)) !=
                  "unknown");
    }

    const auto registryA = CanonicalizeRegistryIdentity(
        "HKEY_CURRENT_USER", "Software/Acme//Crackme\\", "Licensed");
    const auto registryB = CanonicalizeRegistryIdentity(
        "hkcu", "software\\acme\\crackme", "LICENSED");
    const auto registryOther = CanonicalizeRegistryIdentity(
        "hkcu", "software\\acme\\crackme", "Trial");
    CHECK(registryA.valid && registryA.exact);
    CHECK(PersistentStateIdentityEquivalentExact(registryA, registryB));
    CHECK(!PersistentStateIdentityEquivalentExact(registryA, registryOther));
    CHECK(!CanonicalizeRegistryIdentity(
        "computed-root", "software\\acme", "licensed").exact);

    const auto fileA = CanonicalizeFileIdentity(
        "C:/Users/Test/App/./state/../license.dat");
    const auto fileB = CanonicalizeFileIdentity(
        "c:\\users\\test\\app\\license.dat");
    CHECK(fileA.valid && fileA.exact);
    CHECK(PersistentStateIdentityEquivalentExact(fileA, fileB));
    CHECK(InferPersistentContentKind(fileA) ==
          PersistentContentKind::Unknown);

    const auto json = CanonicalizeFileIdentity(
        "C:\\ProgramData\\Acme\\state.JSON");
    CHECK(InferPersistentContentKind(json) == PersistentContentKind::Json);
    CHECK(std::string(PersistentContentKindText(
              InferPersistentContentKind(json))) == "JSON");
    const auto json5 = CanonicalizeFileIdentity(
        "C:\\ProgramData\\Acme\\state.json5");
    CHECK(InferPersistentContentKind(json5) == PersistentContentKind::Json);
    const auto config = CanonicalizeFileIdentity(
        "C:\\ProgramData\\Acme\\license.config");
    CHECK(InferPersistentContentKind(config) == PersistentContentKind::Text);
    CHECK(InferPersistentContentKind(registryA) ==
          PersistentContentKind::Unknown);
    const auto uncA = CanonicalizeFileIdentity(
        "\\\\?\\UNC\\Server\\Share\\state.dat");
    const auto uncB = CanonicalizeFileIdentity(
        "\\\\server\\share\\state.dat");
    CHECK(uncA.valid && uncA.exact);
    CHECK(PersistentStateIdentityEquivalentExact(uncA, uncB));
    const auto relative = CanonicalizeFileIdentity("license.dat");
    const auto environment = CanonicalizeFileIdentity("%APPDATA%\\license.dat");
    CHECK(relative.valid && !relative.exact);
    CHECK(environment.valid && !environment.exact);
    CHECK(!PersistentStateIdentityEquivalentExact(relative, relative));

    const auto iniA = CanonicalizeIniIdentity(
        "C:\\ProgramData\\Acme\\state.ini", "License", "Valid");
    const auto iniB = CanonicalizeIniIdentity(
        "c:/programdata/acme/state.ini", "license", "valid");
    CHECK(iniA.valid && iniA.exact);
    CHECK(PersistentStateIdentityEquivalentExact(iniA, iniB));
    CHECK(InferPersistentContentKind(iniA) == PersistentContentKind::Ini);

    const auto credentialA = CanonicalizeCredentialIdentity(
        "Acme/Product/Oliver", "1");
    const auto credentialB = CanonicalizeCredentialIdentity(
        "acme/product/oliver", "1");
    CHECK(PersistentStateIdentityEquivalentExact(credentialA, credentialB));
    CHECK(!CanonicalizeCredentialIdentity("Acme/Product/Oliver", "").exact);

    const auto dpapi = MakeDpapiTransformIdentity("license blob");
    CHECK(dpapi.valid && !dpapi.exact);
    CHECK(!PersistentStateIdentityEquivalentExact(dpapi, dpapi));

    if (failures) return 1;
    std::puts("persistent state catalog tests passed");
    return 0;
}
