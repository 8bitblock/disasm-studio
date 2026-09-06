#include "PersistentStateCatalog.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <utility>

namespace ds {
namespace {

char asciiLower(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

std::string trim(std::string_view value) {
    size_t first = 0;
    size_t last = value.size();
    while (first < last &&
           std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    while (last > first &&
           std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return std::string(value.substr(first, last - first));
}

bool allDigits(std::string_view value) {
    if (value.empty()) return false;
    for (char c : value) if (c < '0' || c > '9') return false;
    return true;
}

PersistentStateReturnContract contract(PersistentStateReturnKind kind,
                                       PersistentStateSuccessRule rule,
                                       std::string type,
                                       std::string success,
                                       std::string failure) {
    PersistentStateReturnContract result;
    result.kind = kind;
    result.successRule = rule;
    result.returnType = std::move(type);
    result.successMeaning = std::move(success);
    result.failureMeaning = std::move(failure);
    return result;
}

PersistentStateApiArgument arg(uint8_t oneBased,
                               PersistentStateArgumentRole role,
                               bool output = false) {
    PersistentStateApiArgument result;
    result.argumentIndex = oneBased ? static_cast<uint8_t>(oneBased - 1) : 0;
    result.role = role;
    result.output = output;
    return result;
}

PersistentStateApiMatch api(std::string dll, std::string key,
                            std::string canonical, PersistentStateKind kind,
                            PersistentStateAccess access,
                            PersistentStateReturnContract returnContract,
                            std::initializer_list<PersistentStateApiArgument> arguments,
                            bool establishes = false, bool consumes = false,
                            bool accessDependsOnArguments = false) {
    PersistentStateApiMatch result;
    result.kind = kind;
    result.access = access;
    result.dll = std::move(dll);
    result.canonicalName = std::move(canonical);
    result.normalizedName = std::move(key);
    result.arguments.assign(arguments.begin(), arguments.end());
    result.returnContract = std::move(returnContract);
    result.establishesHandleLineage = establishes;
    result.consumesHandleLineage = consumes;
    result.accessDependsOnArguments = accessDependsOnArguments;
    return result;
}

const std::vector<PersistentStateApiMatch>& catalog() {
    static const std::vector<PersistentStateApiMatch> rows = [] {
        std::vector<PersistentStateApiMatch> out;
        const auto status = [] {
            return contract(PersistentStateReturnKind::Status,
                            PersistentStateSuccessRule::Zero, "LSTATUS",
                            "ERROR_SUCCESS (0): operation completed",
                            "nonzero Win32 status: operation failed");
        };
        const auto boolean = [] {
            return contract(PersistentStateReturnKind::Bool,
                            PersistentStateSuccessRule::NonZero, "BOOL",
                            "nonzero: operation completed",
                            "FALSE (0): operation failed");
        };
        const auto pointer = [] {
            return contract(PersistentStateReturnKind::Pointer,
                            PersistentStateSuccessRule::NonNull, "pointer",
                            "non-NULL: resource opened",
                            "NULL: resource operation failed");
        };
        const auto nonnegative = [] {
            return contract(PersistentStateReturnKind::SignedCount,
                            PersistentStateSuccessRule::NonNegative, "integer/count",
                            "nonnegative: operation returned a count or descriptor",
                            "negative: operation failed");
        };
        const auto indeterminateCount = [] {
            return contract(PersistentStateReturnKind::SignedCount,
                            PersistentStateSuccessRule::Indeterminate,
                            "count/value",
                            "return value retained; success requires additional context",
                            "return value alone cannot distinguish failure from an empty/default or partial result");
        };

        // Registry handle lineage and direct root+subkey forms.
        out.push_back(api("advapi32", "regopenkeyex", "RegOpenKeyEx",
            PersistentStateKind::Registry, PersistentStateAccess::Open, status(),
            {arg(1, PersistentStateArgumentRole::RootHandle),
             arg(2, PersistentStateArgumentRole::Subkey),
             arg(5, PersistentStateArgumentRole::OutputHandle, true)}, true));
        out.push_back(api("advapi32", "regcreatekeyex", "RegCreateKeyEx",
            PersistentStateKind::Registry, PersistentStateAccess::Write, status(),
            {arg(1, PersistentStateArgumentRole::RootHandle),
             arg(2, PersistentStateArgumentRole::Subkey),
             arg(8, PersistentStateArgumentRole::OutputHandle, true)}, true));
        out.push_back(api("advapi32", "regqueryvalueex", "RegQueryValueEx",
            PersistentStateKind::Registry, PersistentStateAccess::Read, status(),
            {arg(1, PersistentStateArgumentRole::ResourceHandle),
             arg(2, PersistentStateArgumentRole::ValueName),
             arg(5, PersistentStateArgumentRole::OutputBuffer, true)}, false, true));
        out.push_back(api("advapi32", "reggetvalue", "RegGetValue",
            PersistentStateKind::Registry, PersistentStateAccess::Read, status(),
            {arg(1, PersistentStateArgumentRole::RootHandle),
             arg(2, PersistentStateArgumentRole::Subkey),
             arg(3, PersistentStateArgumentRole::ValueName),
             arg(6, PersistentStateArgumentRole::OutputBuffer, true)}));
        out.push_back(api("advapi32", "regsetvalueex", "RegSetValueEx",
            PersistentStateKind::Registry, PersistentStateAccess::Write, status(),
            {arg(1, PersistentStateArgumentRole::ResourceHandle),
             arg(2, PersistentStateArgumentRole::ValueName),
             arg(5, PersistentStateArgumentRole::DataBuffer)}, false, true));
        out.push_back(api("advapi32", "regsetkeyvalue", "RegSetKeyValue",
            PersistentStateKind::Registry, PersistentStateAccess::Write, status(),
            {arg(1, PersistentStateArgumentRole::RootHandle),
             arg(2, PersistentStateArgumentRole::Subkey),
             arg(3, PersistentStateArgumentRole::ValueName),
             arg(5, PersistentStateArgumentRole::DataBuffer)}));

        // Credential Manager and DPAPI.  DPAPI rows are transforms and never
        // become a durable identity without a surrounding store operation.
        out.push_back(api("advapi32", "credread", "CredRead",
            PersistentStateKind::Credential, PersistentStateAccess::Read, boolean(),
            {arg(1, PersistentStateArgumentRole::CredentialTarget),
             arg(2, PersistentStateArgumentRole::CredentialType),
             arg(4, PersistentStateArgumentRole::OutputBuffer, true)}));
        out.push_back(api("advapi32", "credwrite", "CredWrite",
            PersistentStateKind::Credential, PersistentStateAccess::Write, boolean(),
            {arg(1, PersistentStateArgumentRole::CredentialRecord)}));
        out.push_back(api("crypt32", "cryptprotectdata", "CryptProtectData",
            PersistentStateKind::DpapiTransform, PersistentStateAccess::Protect, boolean(),
            {arg(1, PersistentStateArgumentRole::DataBuffer),
             arg(7, PersistentStateArgumentRole::OutputBuffer, true)}));
        out.push_back(api("crypt32", "cryptunprotectdata", "CryptUnprotectData",
            PersistentStateKind::DpapiTransform, PersistentStateAccess::Unprotect, boolean(),
            {arg(1, PersistentStateArgumentRole::DataBuffer),
             arg(7, PersistentStateArgumentRole::OutputBuffer, true)}));

        // Kernel APIs can be imported from kernel32 or forwarded through
        // kernelbase.  Both are explicit exact modules in this catalog.
        for (const char* module : {"kernel32", "kernelbase"}) {
            out.push_back(api(module, "createfile", "CreateFile",
                PersistentStateKind::File, PersistentStateAccess::Open,
                contract(PersistentStateReturnKind::Handle,
                         PersistentStateSuccessRule::NotInvalidHandle, "HANDLE",
                         "handle other than INVALID_HANDLE_VALUE: file opened",
                         "INVALID_HANDLE_VALUE: file open failed"),
                {arg(1, PersistentStateArgumentRole::ResourcePath)}, true));
            out.back().accessDependsOnArguments = true;
            out.push_back(api(module, "readfile", "ReadFile",
                PersistentStateKind::File, PersistentStateAccess::Read, boolean(),
                {arg(1, PersistentStateArgumentRole::ResourceHandle),
                 arg(2, PersistentStateArgumentRole::OutputBuffer, true)}, false, true));
            out.push_back(api(module, "writefile", "WriteFile",
                PersistentStateKind::File, PersistentStateAccess::Write, boolean(),
                {arg(1, PersistentStateArgumentRole::ResourceHandle),
                 arg(2, PersistentStateArgumentRole::DataBuffer)}, false, true));

            out.push_back(api(module, "getprivateprofilestring", "GetPrivateProfileString",
                PersistentStateKind::Ini, PersistentStateAccess::Read, indeterminateCount(),
                {arg(1, PersistentStateArgumentRole::IniSection),
                 arg(2, PersistentStateArgumentRole::IniKey),
                 arg(4, PersistentStateArgumentRole::OutputBuffer, true),
                 arg(6, PersistentStateArgumentRole::ResourcePath)}));
            out.push_back(api(module, "getprivateprofileint", "GetPrivateProfileInt",
                PersistentStateKind::Ini, PersistentStateAccess::Read, indeterminateCount(),
                {arg(1, PersistentStateArgumentRole::IniSection),
                 arg(2, PersistentStateArgumentRole::IniKey),
                 arg(4, PersistentStateArgumentRole::ResourcePath)}));
            out.push_back(api(module, "writeprivateprofilestring", "WritePrivateProfileString",
                PersistentStateKind::Ini, PersistentStateAccess::Write, boolean(),
                {arg(1, PersistentStateArgumentRole::IniSection),
                 arg(2, PersistentStateArgumentRole::IniKey),
                 arg(3, PersistentStateArgumentRole::DataBuffer),
                 arg(4, PersistentStateArgumentRole::ResourcePath)}));
            out.push_back(api(module, "getprivateprofilesection", "GetPrivateProfileSection",
                PersistentStateKind::Ini, PersistentStateAccess::Read, indeterminateCount(),
                {arg(1, PersistentStateArgumentRole::IniSection),
                 arg(2, PersistentStateArgumentRole::OutputBuffer, true),
                 arg(4, PersistentStateArgumentRole::ResourcePath)}));
            out.push_back(api(module, "writeprivateprofilesection", "WritePrivateProfileSection",
                PersistentStateKind::Ini, PersistentStateAccess::Write, boolean(),
                {arg(1, PersistentStateArgumentRole::IniSection),
                 arg(2, PersistentStateArgumentRole::DataBuffer),
                 arg(3, PersistentStateArgumentRole::ResourcePath)}));
            out.push_back(api(module, "getfileattributes", "GetFileAttributes",
                PersistentStateKind::File, PersistentStateAccess::Read,
                contract(PersistentStateReturnKind::Status,
                         PersistentStateSuccessRule::NotInvalidValue32, "DWORD",
                         "value other than INVALID_FILE_ATTRIBUTES: path exists",
                         "INVALID_FILE_ATTRIBUTES: query failed or path is absent"),
                {arg(1, PersistentStateArgumentRole::ResourcePath)}));
        }

        out.push_back(api("shlwapi", "pathfileexists", "PathFileExists",
            PersistentStateKind::File, PersistentStateAccess::Read, boolean(),
            {arg(1, PersistentStateArgumentRole::ResourcePath)}));

        // Common CRT imports are kept module-qualified.  The same symbol in an
        // unrelated module is intentionally not recognized.
        for (const char* module : {"msvcrt", "ucrtbase",
                                   "api-ms-win-crt-stdio-l1-1-0"}) {
            out.push_back(api(module, "fopen", "fopen",
                PersistentStateKind::File, PersistentStateAccess::Open, pointer(),
                {arg(1, PersistentStateArgumentRole::ResourcePath),
                 arg(2, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "wfopen", "_wfopen",
                PersistentStateKind::File, PersistentStateAccess::Open, pointer(),
                {arg(1, PersistentStateArgumentRole::ResourcePath),
                 arg(2, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "fsopen", "_fsopen",
                PersistentStateKind::File, PersistentStateAccess::Open, pointer(),
                {arg(1, PersistentStateArgumentRole::ResourcePath),
                 arg(2, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "wfsopen", "_wfsopen",
                PersistentStateKind::File, PersistentStateAccess::Open, pointer(),
                {arg(1, PersistentStateArgumentRole::ResourcePath),
                 arg(2, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "fopen_s", "fopen_s",
                PersistentStateKind::File, PersistentStateAccess::Open, status(),
                {arg(1, PersistentStateArgumentRole::OutputHandle, true),
                 arg(2, PersistentStateArgumentRole::ResourcePath),
                 arg(3, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "wfopen_s", "_wfopen_s",
                PersistentStateKind::File, PersistentStateAccess::Open, status(),
                {arg(1, PersistentStateArgumentRole::OutputHandle, true),
                 arg(2, PersistentStateArgumentRole::ResourcePath),
                 arg(3, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "fread", "fread",
                PersistentStateKind::File, PersistentStateAccess::Read, indeterminateCount(),
                {arg(1, PersistentStateArgumentRole::OutputBuffer, true),
                 arg(4, PersistentStateArgumentRole::ResourceHandle)}, false, true));
            out.push_back(api(module, "fwrite", "fwrite",
                PersistentStateKind::File, PersistentStateAccess::Write, indeterminateCount(),
                {arg(1, PersistentStateArgumentRole::DataBuffer),
                 arg(4, PersistentStateArgumentRole::ResourceHandle)}, false, true));
        }
        for (const char* module : {"msvcrt", "ucrtbase",
                                   "api-ms-win-crt-lowio-l1-1-0"}) {
            out.push_back(api(module, "open", "_open",
                PersistentStateKind::File, PersistentStateAccess::Open, nonnegative(),
                {arg(1, PersistentStateArgumentRole::ResourcePath),
                 arg(2, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "wopen", "_wopen",
                PersistentStateKind::File, PersistentStateAccess::Open, nonnegative(),
                {arg(1, PersistentStateArgumentRole::ResourcePath),
                 arg(2, PersistentStateArgumentRole::Mode)}, true, false, true));
            out.push_back(api(module, "read", "_read",
                PersistentStateKind::File, PersistentStateAccess::Read, nonnegative(),
                {arg(1, PersistentStateArgumentRole::ResourceHandle),
                 arg(2, PersistentStateArgumentRole::OutputBuffer, true)}, false, true));
            out.push_back(api(module, "write", "_write",
                PersistentStateKind::File, PersistentStateAccess::Write, nonnegative(),
                {arg(1, PersistentStateArgumentRole::ResourceHandle),
                 arg(2, PersistentStateArgumentRole::DataBuffer)}, false, true));
        }
        return out;
    }();
    return rows;
}

bool hasCatalogKey(std::string_view key) {
    for (const auto& row : catalog())
        if (row.normalizedName == key) return true;
    return false;
}

std::string lowerTrim(std::string_view value) {
    std::string out = trim(value);
    std::transform(out.begin(), out.end(), out.begin(), asciiLower);
    return out;
}

std::string normalizeRegistryPart(std::string_view value) {
    std::string out = lowerTrim(value);
    std::replace(out.begin(), out.end(), '/', '\\');
    std::string compact;
    compact.reserve(out.size());
    bool slash = false;
    for (char c : out) {
        if (c == '\\') {
            if (!slash && !compact.empty()) compact.push_back(c);
            slash = true;
        } else {
            compact.push_back(c);
            slash = false;
        }
    }
    while (!compact.empty() && compact.back() == '\\') compact.pop_back();
    return compact;
}

std::string registryRoot(std::string_view value) {
    std::string root = lowerTrim(value);
    if (root == "hkey_current_user" || root == "hkcu") return "hkcu";
    if (root == "hkey_local_machine" || root == "hklm") return "hklm";
    if (root == "hkey_classes_root" || root == "hkcr") return "hkcr";
    if (root == "hkey_users" || root == "hku") return "hku";
    if (root == "hkey_current_config" || root == "hkcc") return "hkcc";
    return {};
}

std::string normalizeWindowsPath(std::string_view value, bool& exactOut) {
    std::string path = trim(value);
    if (path.size() >= 2 && path.front() == '"' && path.back() == '"')
        path = path.substr(1, path.size() - 2);
    std::replace(path.begin(), path.end(), '/', '\\');
    std::transform(path.begin(), path.end(), path.begin(), asciiLower);

    if (path.rfind("\\\\?\\unc\\", 0) == 0)
        path.replace(0, 8, "\\\\");
    else if (path.rfind("\\\\?\\", 0) == 0)
        path.erase(0, 4);
    const bool driveAbsolute = path.size() >= 3 &&
        std::isalpha(static_cast<unsigned char>(path[0])) &&
        path[1] == ':' && path[2] == '\\';
    const bool uncAbsolute = path.rfind("\\\\", 0) == 0;
    const bool unresolved = path.find('%') != std::string::npos ||
                            path.find("$(") != std::string::npos;
    exactOut = (driveAbsolute || uncAbsolute) && !unresolved;
    if (!driveAbsolute && !uncAbsolute) return path;

    std::string prefix;
    size_t cursor = 0;
    if (driveAbsolute) {
        prefix = path.substr(0, 3);
        cursor = 3;
    } else {
        prefix = "\\\\";
        cursor = 2;
    }
    std::vector<std::string> parts;
    while (cursor <= path.size()) {
        const size_t next = path.find('\\', cursor);
        const size_t end = next == std::string::npos ? path.size() : next;
        std::string part = path.substr(cursor, end - cursor);
        if (!part.empty() && part != ".") {
            if (part == "..") {
                if (!parts.empty()) parts.pop_back();
                else exactOut = false;
            } else {
                parts.push_back(std::move(part));
            }
        }
        if (next == std::string::npos) break;
        cursor = next + 1;
    }
    if (uncAbsolute && parts.size() < 2) exactOut = false;
    std::string normalized = prefix;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (!normalized.empty() && normalized.back() != '\\') normalized.push_back('\\');
        normalized += parts[i];
    }
    return normalized;
}

} // namespace

const char* PersistentStateReturnKindText(PersistentStateReturnKind kind) {
    switch (kind) {
    case PersistentStateReturnKind::Bool: return "BOOL";
    case PersistentStateReturnKind::Status: return "status";
    case PersistentStateReturnKind::Handle: return "handle";
    case PersistentStateReturnKind::Pointer: return "pointer";
    case PersistentStateReturnKind::SignedCount: return "count";
    }
    return "unknown";
}

const char* PersistentStateSuccessRuleText(PersistentStateSuccessRule rule) {
    switch (rule) {
    case PersistentStateSuccessRule::NonZero: return "nonzero";
    case PersistentStateSuccessRule::Zero: return "zero";
    case PersistentStateSuccessRule::NonNull: return "non-NULL";
    case PersistentStateSuccessRule::NotInvalidHandle: return "not INVALID_HANDLE_VALUE";
    case PersistentStateSuccessRule::NotInvalidValue32: return "not 0xffffffff";
    case PersistentStateSuccessRule::NonNegative: return "nonnegative";
    case PersistentStateSuccessRule::Indeterminate: return "requires additional context";
    }
    return "unknown";
}

const char* PersistentStateArgumentRoleText(PersistentStateArgumentRole role) {
    switch (role) {
    case PersistentStateArgumentRole::None: return "none";
    case PersistentStateArgumentRole::RootHandle: return "root handle";
    case PersistentStateArgumentRole::ResourceHandle: return "resource handle";
    case PersistentStateArgumentRole::ResourcePath: return "resource path";
    case PersistentStateArgumentRole::Subkey: return "registry subkey";
    case PersistentStateArgumentRole::ValueName: return "registry value";
    case PersistentStateArgumentRole::IniSection: return "INI section";
    case PersistentStateArgumentRole::IniKey: return "INI key";
    case PersistentStateArgumentRole::CredentialTarget: return "credential target";
    case PersistentStateArgumentRole::CredentialType: return "credential type";
    case PersistentStateArgumentRole::CredentialRecord: return "credential record";
    case PersistentStateArgumentRole::DataBuffer: return "input data";
    case PersistentStateArgumentRole::OutputHandle: return "output handle";
    case PersistentStateArgumentRole::OutputBuffer: return "output data";
    case PersistentStateArgumentRole::Mode: return "open mode";
    }
    return "unknown";
}

const char* PersistentContentKindText(PersistentContentKind kind) {
    switch (kind) {
    case PersistentContentKind::Json: return "JSON";
    case PersistentContentKind::Ini: return "INI";
    case PersistentContentKind::Xml: return "XML";
    case PersistentContentKind::Yaml: return "YAML";
    case PersistentContentKind::Toml: return "TOML";
    case PersistentContentKind::Text: return "text/config";
    case PersistentContentKind::Unknown: break;
    }
    return "unknown";
}

PersistentContentKind InferPersistentContentKind(
    const PersistentStateIdentity& identity) {
    if (identity.kind == PersistentStateKind::Ini)
        return PersistentContentKind::Ini;
    if (identity.kind != PersistentStateKind::File)
        return PersistentContentKind::Unknown;

    std::string path = identity.canonicalKey.empty()
        ? lowerTrim(identity.display) : lowerTrim(identity.canonicalKey);
    const size_t slash = path.find_last_of("\\/");
    const size_t dot = path.find_last_of('.');
    if (dot == std::string::npos ||
        (slash != std::string::npos && dot < slash) || dot + 1 >= path.size())
        return PersistentContentKind::Unknown;
    const std::string_view extension(path.data() + dot, path.size() - dot);
    if (extension == ".json" || extension == ".json5")
        return PersistentContentKind::Json;
    if (extension == ".ini") return PersistentContentKind::Ini;
    if (extension == ".xml") return PersistentContentKind::Xml;
    if (extension == ".yaml" || extension == ".yml")
        return PersistentContentKind::Yaml;
    if (extension == ".toml") return PersistentContentKind::Toml;
    if (extension == ".txt" || extension == ".cfg" ||
        extension == ".conf" || extension == ".config")
        return PersistentContentKind::Text;
    return PersistentContentKind::Unknown;
}

std::string NormalizePersistentStateDll(std::string_view dll) {
    std::string out = trim(dll);
    if (const size_t bang = out.find('!'); bang != std::string::npos) out.resize(bang);
    if (const size_t slash = out.find_last_of("/\\"); slash != std::string::npos)
        out.erase(0, slash + 1);
    std::transform(out.begin(), out.end(), out.begin(), asciiLower);
    if (out.size() > 4 && out.ends_with(".dll")) out.resize(out.size() - 4);
    return out;
}

std::string NormalizePersistentStateApiName(std::string_view symbol) {
    std::string out = trim(symbol);
    if (const size_t bang = out.rfind('!'); bang != std::string::npos)
        out.erase(0, bang + 1);
    std::transform(out.begin(), out.end(), out.begin(), asciiLower);
    constexpr std::string_view prefixes[] = {
        "__imp__", "__imp_", "_imp__", "_imp_", "imp_"
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (std::string_view prefix : prefixes) {
            if (out.starts_with(prefix)) {
                out.erase(0, prefix.size());
                changed = true;
                break;
            }
        }
    }
    while (!out.empty() && (out.front() == '_' || out.front() == '@'))
        out.erase(out.begin());
    if (const size_t at = out.rfind('@'); at != std::string::npos &&
        allDigits(std::string_view(out).substr(at + 1))) out.resize(at);
    if (out.size() > 1 && (out.back() == 'a' || out.back() == 'w')) {
        const std::string_view base(out.data(), out.size() - 1);
        if (hasCatalogKey(base)) out.resize(out.size() - 1);
    }
    return out;
}

std::optional<PersistentStateApiMatch> LookupPersistentStateApi(
    std::string_view dll, std::string_view symbol) {
    std::string module = NormalizePersistentStateDll(dll);
    if (const size_t bang = symbol.rfind('!'); bang != std::string_view::npos) {
        const std::string qualified = NormalizePersistentStateDll(symbol.substr(0, bang));
        if (module.empty()) module = qualified;
        else if (!qualified.empty() && qualified != module) return std::nullopt;
    }
    if (module.empty()) return std::nullopt;
    const std::string name = NormalizePersistentStateApiName(symbol);
    for (const auto& row : catalog())
        if (row.dll == module && row.normalizedName == name) return row;
    return std::nullopt;
}

std::vector<PersistentStateApiMatch> EnumeratePersistentStateApis() {
    return catalog();
}

bool PersistentStateReturnIsImmediateSuccess(
    const PersistentStateReturnContract& contract, uint64_t rawValue,
    uint8_t pointerWidthBits) {
    const uint32_t low32 = static_cast<uint32_t>(rawValue);
    const int32_t signed32 = static_cast<int32_t>(low32);
    const uint64_t pointerMask = pointerWidthBits == 32
        ? UINT64_C(0xFFFFFFFF) : UINT64_MAX;
    const uint64_t pointer = rawValue & pointerMask;
    switch (contract.successRule) {
    case PersistentStateSuccessRule::NonZero: return low32 != 0;
    case PersistentStateSuccessRule::Zero: return low32 == 0;
    case PersistentStateSuccessRule::NonNull: return pointer != 0;
    case PersistentStateSuccessRule::NotInvalidHandle: return pointer != pointerMask;
    case PersistentStateSuccessRule::NotInvalidValue32: return low32 != UINT32_MAX;
    case PersistentStateSuccessRule::NonNegative: return signed32 >= 0;
    case PersistentStateSuccessRule::Indeterminate: return false;
    }
    return false;
}

PersistentStateIdentity CanonicalizeRegistryIdentity(
    std::string_view rootHive, std::string_view subkey,
    std::string_view valueName) {
    PersistentStateIdentity result;
    result.kind = PersistentStateKind::Registry;
    result.canonicalScope = registryRoot(rootHive);
    result.canonicalKey = normalizeRegistryPart(subkey);
    result.canonicalValue = lowerTrim(valueName);
    result.valid = !result.canonicalScope.empty();
    result.exact = result.valid;
    result.display = result.valid ? result.canonicalScope : trim(rootHive);
    if (!result.canonicalKey.empty()) result.display += "\\" + result.canonicalKey;
    result.display += " [" + (result.canonicalValue.empty()
        ? std::string("(default)") : result.canonicalValue) + "]";
    return result;
}

PersistentStateIdentity CanonicalizeFileIdentity(std::string_view resolvedPath) {
    PersistentStateIdentity result;
    result.kind = PersistentStateKind::File;
    result.canonicalKey = normalizeWindowsPath(resolvedPath, result.exact);
    result.valid = !result.canonicalKey.empty();
    if (!result.valid) result.exact = false;
    if (result.canonicalKey.size() >= 2 && result.canonicalKey[1] == ':')
        result.canonicalScope = result.canonicalKey.substr(0, 2);
    else if (result.canonicalKey.rfind("\\\\", 0) == 0)
        result.canonicalScope = "unc";
    result.display = result.canonicalKey;
    return result;
}

PersistentStateIdentity CanonicalizeIniIdentity(
    std::string_view resolvedPath, std::string_view section,
    std::string_view key) {
    PersistentStateIdentity file = CanonicalizeFileIdentity(resolvedPath);
    PersistentStateIdentity result;
    result.kind = PersistentStateKind::Ini;
    result.canonicalScope = file.canonicalKey;
    result.canonicalKey = lowerTrim(section);
    result.canonicalValue = lowerTrim(key);
    result.valid = file.valid && !result.canonicalKey.empty() &&
                   !result.canonicalValue.empty();
    result.exact = result.valid && file.exact;
    result.display = file.display + " [" + result.canonicalKey + "/" +
                     result.canonicalValue + "]";
    return result;
}

PersistentStateIdentity CanonicalizeCredentialIdentity(
    std::string_view target, std::string_view credentialType) {
    PersistentStateIdentity result;
    result.kind = PersistentStateKind::Credential;
    result.canonicalScope = lowerTrim(credentialType);
    result.canonicalKey = lowerTrim(target);
    result.valid = !result.canonicalScope.empty() && !result.canonicalKey.empty();
    result.exact = result.valid;
    result.display = result.canonicalKey + " [type " + result.canonicalScope + "]";
    return result;
}

PersistentStateIdentity MakeDpapiTransformIdentity(std::string_view description) {
    PersistentStateIdentity result;
    result.kind = PersistentStateKind::DpapiTransform;
    result.canonicalKey = lowerTrim(description);
    result.display = result.canonicalKey.empty() ? "DPAPI transform" :
        "DPAPI transform: " + result.canonicalKey;
    result.valid = true;
    result.exact = false;
    return result;
}

} // namespace ds
