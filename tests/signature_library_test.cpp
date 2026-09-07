#include "Core/SignatureLibrary.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using namespace ds;
namespace fs = std::filesystem;
static int failures = 0;
#define CHECK(expression) do { if (!(expression)) { std::cerr << "Line " << __LINE__ << ": " #expression "\n"; ++failures; } } while (0)

int main() {
    std::string error, text;
    auto source = StarterSignatureLibrary();
    source.lastId = UINT64_C(0xF000000000000001);
    source.entries.push_back({source.lastId, "unicode_\xCE\xB1", "48 8B ?? ? 90", "x64", "FEDCBA9876543210"});
    SignatureLibrary parsed;
    CHECK(SerializeSignatureLibrary(source, text, error));
    CHECK(text.find("F000000000000001") != std::string::npos);
    CHECK(text.find("count") == std::string::npos && text.find("health") == std::string::npos);
    CHECK(ParseSignatureLibrary(text, parsed, error));
    CHECK(parsed == source);
    {
        std::string invalidRecord = text;
        const auto pattern = invalidRecord.find("48 8B ?? ? 90");
        CHECK(pattern != std::string::npos);
        invalidRecord.replace(pattern, std::string("48 8B ?? ? 90").size(), "ZZ");
        CHECK(!ParseSignatureLibrary(invalidRecord, parsed, error));
        CHECK(parsed == source);
    }

    // Malformed and hostile imports must leave the complete previous library
    // unchanged, including its monotonic identity allocation watermark.
    const auto retained = parsed;
    for (const std::string bad : {
        std::string("{}"),
        std::string("{\"version\":2,\"lastId\":\"0000000000000000\",\"signatures\":[]}"),
        std::string("{\"version\":1,\"version\":1,\"lastId\":\"0000000000000000\",\"signatures\":[]}"),
        std::string("{\"version\":1,\"lastId\":1,\"signatures\":[]}"),
        text + " trailing bytes", std::string(kMaxSignatureLibraryBytes + 1, ' ')
    }) {
        CHECK(!ParseSignatureLibrary(bad, parsed, error));
        CHECK(parsed == retained);
        CHECK(!error.empty());
    }
    for (int kind = 0; kind < 7; ++kind) {
        auto invalid = source;
        switch (kind) {
            case 0: invalid.entries[0].id = 0; break;
            case 1: invalid.entries[0].id = invalid.entries[1].id; break;
            case 2: invalid.entries[0].pattern = "ZZ"; break;
            case 3: invalid.entries[0].name.assign(kMaxLibraryNameBytes + 1, 'x'); break;
            case 4: invalid.entries[0].pattern.assign(kMaxLibraryPatternBytes + 1, '?'); break;
            case 5: invalid.entries[0].sourceHash = "xyz"; break;
            case 6: invalid.lastId = 2; break;
        }
        std::string output = "unchanged";
        CHECK(!SerializeSignatureLibrary(invalid, output, error));
        CHECK(output == "unchanged");
        CHECK(!MergeSignatureLibrary(retained, invalid, parsed, error));
        CHECK(parsed == retained);
    }

    // Merge identities from independent libraries without replacing a local
    // definition; repeat imports are idempotent even after collision remapping.
    const auto current = StarterSignatureLibrary();
    SignatureLibrary incoming{5, {
        current.entries[0],
        {2, "different_name", "90 C3", "x86", ""},
        {5, "new_source", "AA ??", "", "0000000000000000"}
    }};
    SignatureLibrary merged;
    CHECK(MergeSignatureLibrary(current, incoming, merged, error));
    CHECK(merged.entries.size() == 5 && merged.lastId == 5);
    CHECK(merged.entries[0] == current.entries[0]);
    CHECK(merged.entries[1] == current.entries[1]);
    CHECK(merged.entries[3].id == 4 && merged.entries[4].id == 5);
    SignatureLibrary repeated;
    CHECK(MergeSignatureLibrary(merged, incoming, repeated, error));
    CHECK(repeated == merged);
    // Removing a signature never makes its ID available for import reuse.
    auto deleted = merged;
    deleted.entries.pop_back();
    CHECK(MergeSignatureLibrary(deleted, incoming, repeated, error));
    CHECK(repeated.lastId == 6 && repeated.entries.back().id == 6);
    SignatureLibrary exhausted{UINT64_MAX, {}};
    CHECK(!MergeSignatureLibrary(exhausted, incoming, parsed, error));
    CHECK(parsed == retained);

    SignatureLibrary full;
    for (size_t i = 0; i < kMaxLibrarySignatures; ++i)
        full.entries.push_back({++full.lastId, "sig_" + std::to_string(i), "90", "", ""});
    CHECK(ValidateSignatureLibrary(full, error));
    CHECK(!MergeSignatureLibrary(full, incoming, parsed, error));
    CHECK(parsed == retained);

    // Real disk roundtrip, restart-style independent load, stable backup
    // recovery, malformed selected import rejection, and failed write retention.
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = fs::temp_directory_path() / ("disasmstudio_signature_test_" + std::to_string(tick));
    fs::create_directories(root);
    const auto path = root / "signatures.json";
    auto load = LoadSignatureLibraryFile(path, parsed);
    CHECK(load.missing && load.source == atomic_file::ReadSource::None && parsed == retained);
    CHECK(SaveSignatureLibraryFile(path, current, error));
    load = LoadSignatureLibraryFile(path, parsed);
    CHECK(load.source == atomic_file::ReadSource::Primary && parsed == current);
    CHECK(SaveSignatureLibraryFile(path, merged, error));
    load = LoadSignatureLibraryFile(path, parsed);
    CHECK(load.source == atomic_file::ReadSource::Primary && parsed == merged);
    {
        auto invalid = merged;
        invalid.entries.front().pattern = "GG";
        CHECK(!SaveSignatureLibraryFile(path, invalid, error));
        load = LoadSignatureLibraryFile(path, parsed);
        CHECK(load.source == atomic_file::ReadSource::Primary && parsed == merged);
    }
    { std::ofstream corrupt(path, std::ios::binary | std::ios::trunc); corrupt << "broken"; }
    SignatureLibrary recovered;
    load = LoadSignatureLibraryFile(path, recovered);
    CHECK(load.source == atomic_file::ReadSource::Backup && recovered == current);
    CHECK(load.error.empty());
    std::string badImport;
    CHECK(atomic_file::Read(path, badImport, kMaxSignatureLibraryBytes));
    CHECK(!ParseSignatureLibrary(badImport, parsed, error));
    CHECK(parsed == merged); // selected corrupt import must not use its backup
    const auto blocked = root / "ordinary_file";
    { std::ofstream file(blocked); file << "keep"; }
    CHECK(!SaveSignatureLibraryFile(blocked / "signatures.json", current, error));
    CHECK(!error.empty());
    CHECK(SaveSignatureLibraryFile(root / "empty.json", SignatureLibrary{}, error));
    load = LoadSignatureLibraryFile(root / "empty.json", parsed);
    CHECK(load.source == atomic_file::ReadSource::Primary && parsed.entries.empty());
    CHECK(!load.missing); // empty saved library must not regrow starter examples
    {
        std::ofstream corruptBackup(atomic_file::BackupPath(path), std::ios::binary | std::ios::trunc);
        corruptBackup << "also broken";
    }
    const auto previous = parsed;
    load = LoadSignatureLibraryFile(path, parsed);
    CHECK(load.source == atomic_file::ReadSource::None && !load.missing && !load.error.empty());
    CHECK(parsed == previous);
    fs::remove_all(root);
    std::cout << "signature_library_test: " << failures << " failures\n";
    return failures ? 1 : 0;
}
