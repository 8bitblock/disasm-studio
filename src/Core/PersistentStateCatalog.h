#pragma once
//
// PersistentStateCatalog.h
// Exact DLL+symbol contracts and pure identity normalization for common Windows
// durable state.  Similar names in an unrelated DLL never inherit a contract.
//

#include "AuthorizationAnalysis.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

enum class PersistentStateReturnKind : uint8_t {
    Bool = 0,
    Status,
    Handle,
    Pointer,
    SignedCount,
};

enum class PersistentStateSuccessRule : uint8_t {
    NonZero = 0,
    Zero,
    NonNull,
    NotInvalidHandle,
    NotInvalidValue32,
    NonNegative,
    // The return value alone cannot distinguish success from an empty/default
    // result (or requires comparison with another argument). Live watch must
    // retain the return event but leave success unknown.
    Indeterminate,
};

enum class PersistentStateArgumentRole : uint8_t {
    None = 0,
    RootHandle,
    ResourceHandle,
    ResourcePath,
    Subkey,
    ValueName,
    IniSection,
    IniKey,
    CredentialTarget,
    CredentialType,
    CredentialRecord,
    DataBuffer,
    OutputHandle,
    OutputBuffer,
    Mode,
};

// A path-derived format hint is presentation/search evidence only. It never
// changes the durable file identity and never proves that a parser consumed a
// particular field or that the application accepted its value.
enum class PersistentContentKind : uint8_t {
    Unknown = 0,
    Json,
    Ini,
    Xml,
    Yaml,
    Toml,
    Text,
};

struct PersistentStateApiArgument {
    uint8_t argumentIndex = 0; // zero-based
    PersistentStateArgumentRole role = PersistentStateArgumentRole::None;
    bool output = false;
};

struct PersistentStateReturnContract {
    PersistentStateReturnKind kind = PersistentStateReturnKind::Bool;
    PersistentStateSuccessRule successRule = PersistentStateSuccessRule::NonZero;
    std::string returnType;
    std::string successMeaning;
    std::string failureMeaning;
};

struct PersistentStateApiMatch {
    PersistentStateKind kind = PersistentStateKind::Unknown;
    PersistentStateAccess access = PersistentStateAccess::Unknown;
    std::string dll;             // normalized, lower-case, no .dll
    std::string canonicalName;   // stable SDK/CRT spelling
    std::string normalizedName;  // decoration/AW suffix removed
    std::vector<PersistentStateApiArgument> arguments;
    PersistentStateReturnContract returnContract;
    bool establishesHandleLineage = false;
    bool consumesHandleLineage = false;
    // CreateFile/fopen-style access is refined from desired-access, creation,
    // or mode arguments by the adapter; Open is the conservative catalog base.
    bool accessDependsOnArguments = false;
};

const char* PersistentStateReturnKindText(PersistentStateReturnKind kind);
const char* PersistentStateSuccessRuleText(PersistentStateSuccessRule rule);
const char* PersistentStateArgumentRoleText(PersistentStateArgumentRole role);
const char* PersistentContentKindText(PersistentContentKind kind);

PersistentContentKind InferPersistentContentKind(
    const PersistentStateIdentity& identity);

std::string NormalizePersistentStateDll(std::string_view dll);
std::string NormalizePersistentStateApiName(std::string_view symbol);

std::optional<PersistentStateApiMatch> LookupPersistentStateApi(
    std::string_view dll, std::string_view symbol);
std::vector<PersistentStateApiMatch> EnumeratePersistentStateApis();

// Returns false for Indeterminate; callers that need a known/unknown distinction
// must inspect successRule before interpreting the boolean as failure.
bool PersistentStateReturnIsImmediateSuccess(
    const PersistentStateReturnContract& contract,
    uint64_t rawValue,
    uint8_t pointerWidthBits = 64);

PersistentStateIdentity CanonicalizeRegistryIdentity(
    std::string_view rootHive, std::string_view subkey,
    std::string_view valueName);
PersistentStateIdentity CanonicalizeFileIdentity(std::string_view resolvedPath);
PersistentStateIdentity CanonicalizeIniIdentity(
    std::string_view resolvedPath, std::string_view section,
    std::string_view key);
PersistentStateIdentity CanonicalizeCredentialIdentity(
    std::string_view target, std::string_view credentialType);
PersistentStateIdentity MakeDpapiTransformIdentity(std::string_view description = {});

} // namespace ds
