#include "SignatureLibrary.h"
#include "Json.h"
#include "SigMatch.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <unordered_set>
#ifdef _WIN32
#include <windows.h>
#endif

namespace ds {
namespace {
bool fail(std::string& error, const char* message) { error = message; return false; }
bool cleanText(std::string_view text, size_t cap, bool required) {
    if (text.size() > cap || (required && text.empty())) return false;
    return std::none_of(text.begin(), text.end(), [](unsigned char c) { return c < 32 || c == 127; });
}
std::string hex(uint64_t value) {
    char text[17]{};
    std::snprintf(text, sizeof(text), "%016llX", static_cast<unsigned long long>(value));
    return text;
}
bool hexValue(const json::Value* value, uint64_t& out) {
    if (!value || !value->isStr() || value->str.size() != 16) return false;
    const auto result = std::from_chars(value->str.data(), value->str.data() + 16, out, 16);
    return result.ec == std::errc{} && result.ptr == value->str.data() + 16;
}
bool field(const json::Value& value, const char* key, std::string& out, bool required) {
    const auto* item = value.find(key);
    if (!item) return !required;
    if (!item->isStr()) return false;
    out = item->str;
    return true;
}
bool sameDefinition(const LibrarySignature& a, const LibrarySignature& b) {
    return a.name == b.name && a.pattern == b.pattern &&
           a.architecture == b.architecture && a.sourceHash == b.sourceHash;
}
} // namespace

SignatureLibrary StarterSignatureLibrary() {
    return {3, {
        {1, "fn_init", "48 89 5C 24 ?? 57 48 83 EC 20", "x64", ""},
        {2, "g_world_ptr", "48 8B 05 ?? ?? ?? ?? 48 85 C0", "x64", ""},
        {3, "tick_hook", "E8 ?? ?? ?? ?? 84 C0 74", "x64", ""}
    }};
}

std::filesystem::path DefaultSignatureLibraryPath() {
#ifdef _WIN32
    const DWORD needed = GetEnvironmentVariableW(L"APPDATA", nullptr, 0);
    if (!needed || needed > 32768) return {};
    std::wstring value(needed, L'\0');
    const DWORD count = GetEnvironmentVariableW(L"APPDATA", value.data(), needed);
    if (!count || count >= needed) return {};
    value.resize(count);
    return std::filesystem::path(value) / L"DisasmStudio" / L"signatures.json";
#else
    const char* base = std::getenv("HOME");
    return base && *base ? std::filesystem::path(base) / ".disasmstudio" / "signatures.json"
                         : std::filesystem::path{};
#endif
}

bool ValidateSignatureLibrary(const SignatureLibrary& library, std::string& error) {
    error.clear();
    if (library.entries.size() > kMaxLibrarySignatures) return fail(error, "The library exceeds 1024 signatures.");
    std::unordered_set<uint64_t> ids;
    size_t total = 0;
    for (const auto& entry : library.entries) {
        if (!entry.id || entry.id > library.lastId || !ids.insert(entry.id).second)
            return fail(error, "A signature identity is zero, duplicated, or newer than lastId.");
        if (!cleanText(entry.name, kMaxLibraryNameBytes, true) || !cleanText(entry.architecture, 64, false))
            return fail(error, "Signature names and architecture labels must be bounded, non-control text.");
        if (entry.pattern.empty() || entry.pattern.size() > kMaxLibraryPatternBytes)
            return fail(error, "A signature pattern exceeds the editor's supported size.");
        SigPattern parsed;
        if (!ParseSignature(entry.pattern, parsed)) return fail(error, "A signature has an invalid byte pattern.");
        if (!entry.sourceHash.empty()) {
            const auto value = json::Value::Str(entry.sourceHash);
            uint64_t hash = 0;
            if (!hexValue(&value, hash)) return fail(error, "Source hashes must contain exactly 16 hexadecimal digits.");
        }
        total += entry.name.size() + entry.pattern.size() + entry.architecture.size() + entry.sourceHash.size();
        if (total > kMaxSignatureLibraryBytes) return fail(error, "The signature library exceeds 4 MiB.");
    }
    return true;
}

bool SerializeSignatureLibrary(const SignatureLibrary& library, std::string& text, std::string& error) {
    if (!ValidateSignatureLibrary(library, error)) return false;
    json::Value root = json::Value::Obj();
    root.set("version", json::Value::Int(1));
    root.set("lastId", json::Value::Str(hex(library.lastId)));
    auto entries = json::Value::Arr();
    for (const auto& entry : library.entries) {
        auto value = json::Value::Obj();
        value.set("id", json::Value::Str(hex(entry.id)));
        value.set("name", json::Value::Str(entry.name));
        value.set("pattern", json::Value::Str(entry.pattern));
        if (!entry.architecture.empty()) value.set("architecture", json::Value::Str(entry.architecture));
        if (!entry.sourceHash.empty()) value.set("sourceHash", json::Value::Str(entry.sourceHash));
        entries.push(std::move(value));
    }
    root.set("signatures", std::move(entries));
    std::string candidate = json::Dump(root);
    if (candidate.size() > kMaxSignatureLibraryBytes) return fail(error, "The serialized library exceeds 4 MiB.");
    text = std::move(candidate);
    return true;
}

bool ParseSignatureLibrary(std::string_view text, SignatureLibrary& out, std::string& error) {
    error.clear();
    if (text.size() > kMaxSignatureLibraryBytes) return fail(error, "The signature file exceeds 4 MiB.");
    json::JsonParseLimits limits;
    limits.maxDepth = 8; limits.maxNodes = 20000; limits.maxContainerEntries = kMaxLibrarySignatures;
    limits.maxStringBytes = kMaxSignatureLibraryBytes; limits.maxStringTokenBytes = 6 * kMaxLibraryPatternBytes;
    json::Value root;
    if (!json::Parse(std::string(text), root, limits) || !root.isObj()) return fail(error, "Invalid signature library JSON.");
    const auto* version = root.find("version");
    const auto* entries = root.find("signatures");
    SignatureLibrary candidate;
    if (!version || !version->isNum() || version->num != 1 ||
        !hexValue(root.find("lastId"), candidate.lastId) || !entries || !entries->isArr())
        return fail(error, "Expected a version-1 signature library with lastId and signatures.");
    for (const auto& value : entries->arr) {
        LibrarySignature entry;
        if (!value.isObj() || !hexValue(value.find("id"), entry.id) ||
            !field(value, "name", entry.name, true) || !field(value, "pattern", entry.pattern, true) ||
            !field(value, "architecture", entry.architecture, false) || !field(value, "sourceHash", entry.sourceHash, false))
            return fail(error, "A signature record has missing or incorrectly typed fields.");
        candidate.entries.push_back(std::move(entry));
    }
    if (!ValidateSignatureLibrary(candidate, error)) return false;
    out = std::move(candidate);
    return true;
}

bool MergeSignatureLibrary(const SignatureLibrary& current, const SignatureLibrary& imported,
                           SignatureLibrary& out, std::string& error) {
    if (!ValidateSignatureLibrary(current, error) || !ValidateSignatureLibrary(imported, error)) return false;
    SignatureLibrary candidate = current;
    for (const auto& entry : imported.entries) {
        if (std::any_of(candidate.entries.begin(), candidate.entries.end(), [&](const auto& existing) {
            return sameDefinition(existing, entry);
        })) continue;
        LibrarySignature added = entry;
        // Import identities below our allocation watermark may have belonged to
        // deleted local rows. Allocate again instead of silently reusing them.
        if (added.id <= candidate.lastId) {
            if (candidate.lastId == UINT64_MAX) return fail(error, "Signature identities are exhausted.");
            added.id = ++candidate.lastId;
        } else candidate.lastId = added.id;
        candidate.entries.push_back(std::move(added));
        if (candidate.entries.size() > kMaxLibrarySignatures) return fail(error, "The merged library exceeds 1024 signatures.");
    }
    std::string encoded;
    if (!SerializeSignatureLibrary(candidate, encoded, error)) return false;
    out = std::move(candidate);
    return true;
}

SignatureLibraryLoad LoadSignatureLibraryFile(const std::filesystem::path& path, SignatureLibrary& out) {
    SignatureLibraryLoad result;
    if (path.empty()) { result.error = "No signature library path is available."; return result; }
    std::string text;
    SignatureLibrary candidate;
    result.source = atomic_file::ReadValidated(path, text, [&](std::string_view value) {
        return ParseSignatureLibrary(value, candidate, result.error);
    }, kMaxSignatureLibraryBytes);
    if (result.source != atomic_file::ReadSource::None) {
        out = std::move(candidate);
        result.error.clear();
        return result;
    }
    std::error_code primaryError, backupError;
    const bool primary = std::filesystem::exists(path, primaryError);
    const bool backup = std::filesystem::exists(atomic_file::BackupPath(path), backupError);
    result.missing = !primary && !backup && !primaryError && !backupError;
    if (!result.missing && result.error.empty()) result.error = "Neither the signature library nor its backup could be read.";
    return result;
}

bool SaveSignatureLibraryFile(const std::filesystem::path& path, const SignatureLibrary& library, std::string& error) {
    std::string text;
    if (!SerializeSignatureLibrary(library, text, error)) return false;
    if (!atomic_file::Write(path, text)) return fail(error, "Signature library save failed; the previous file/backup remains available.");
    error.clear();
    return true;
}
} // namespace ds
