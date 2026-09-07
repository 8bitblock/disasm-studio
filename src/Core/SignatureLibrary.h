#pragma once

#include "AtomicFile.h"
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

constexpr size_t kMaxLibrarySignatures = 1024;
constexpr size_t kMaxSignatureLibraryBytes = 4u * 1024u * 1024u;
constexpr size_t kMaxLibraryPatternBytes = 32767;
constexpr size_t kMaxLibraryNameBytes = 255;

struct LibrarySignature {
    uint64_t id = 0;
    std::string name;
    std::string pattern;
    std::string architecture; // Optional descriptive provenance, not scan authority.
    std::string sourceHash;   // Optional exact 16-digit FILE content hash.
    bool operator==(const LibrarySignature&) const = default;
};

struct SignatureLibrary {
    uint64_t lastId = 0; // Never reuse a removed identity; UINT64_MAX means exhausted.
    std::vector<LibrarySignature> entries;
    bool operator==(const SignatureLibrary&) const = default;
};

struct SignatureLibraryLoad {
    atomic_file::ReadSource source = atomic_file::ReadSource::None;
    bool missing = false;
    std::string error;
};

SignatureLibrary StarterSignatureLibrary();
std::filesystem::path DefaultSignatureLibraryPath();
bool ValidateSignatureLibrary(const SignatureLibrary& library, std::string& error);
bool SerializeSignatureLibrary(const SignatureLibrary& library, std::string& text, std::string& error);
bool ParseSignatureLibrary(std::string_view text, SignatureLibrary& out, std::string& error);
// Imports are a merge: identical definitions are skipped; colliding identities
// are reassigned. Existing rows and identities are never replaced implicitly.
bool MergeSignatureLibrary(const SignatureLibrary& current, const SignatureLibrary& imported,
                           SignatureLibrary& out, std::string& error);
SignatureLibraryLoad LoadSignatureLibraryFile(const std::filesystem::path& path, SignatureLibrary& out);
bool SaveSignatureLibraryFile(const std::filesystem::path& path, const SignatureLibrary& library,
                              std::string& error);

} // namespace ds
