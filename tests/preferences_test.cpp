#include "Core/Preferences.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
using namespace ds;

static int failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
    std::cerr << "CHECK failed at line " << __LINE__ << ": " #expr "\n"; \
    ++failures; } } while (0)

static fs::path uniqueRoot() {
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
#ifdef _WIN32
    const unsigned long pid = GetCurrentProcessId();
#else
    const unsigned long pid = 0;
#endif
    return fs::temp_directory_path() /
        ("disasmstudio_prefs_test_" + std::to_string(pid) + "_" +
         std::to_string(tick));
}

static PreferencesData sample(int theme, std::string query) {
    PreferencesData data;
    data.theme = theme;
    data.density = 1;
    data.symbolNetwork = false;
    data.symbolCache = "C:\\symbols";
    data.symbolServer = "https://symbols.example.test";
    data.investigationRecent.push_back({PreferenceIdentity::File, std::move(query)});
    data.investigationRecent.push_back({PreferenceIdentity::Live, "0"});
    return data;
}

int main() {
    const PreferencesBounds bounds{9, 0, 2};
    const PreferencesData defaults = sample(8, "default");

    // Pure codec: round-trip every persisted class, including FILE/LIVE identity.
    {
        PreferencesData expected = sample(3, "CreateFileW");
        expected.symbolNetwork = true;
        std::string text;
        CHECK(SerializePreferences(expected, bounds, text));
        PreferencesData parsed;
        CHECK(ParsePreferences(text, defaults, bounds, parsed));
        CHECK(parsed.theme == 3);
        CHECK(parsed.density == 1);
        CHECK(parsed.symbolNetwork);
        CHECK(parsed.symbolCache == "C:\\symbols");
        CHECK(parsed.investigationRecent.size() == 2);
        CHECK(parsed.investigationRecent[0].identity == PreferenceIdentity::File);
        CHECK(parsed.investigationRecent[0].query == "CreateFileW");
        CHECK(parsed.investigationRecent[1].identity == PreferenceIdentity::Live);
        CHECK(parsed.investigationRecent[1].query == "0");
    }

    // Known malformed fields invalidate the whole copy instead of being silently
    // ignored or reinterpreted. Missing old-version fields retain safe defaults.
    {
        PreferencesData parsed;
        CHECK(ParsePreferences("theme=2\ndensity=0\n", defaults, bounds, parsed));
        CHECK(!parsed.symbolNetwork);
        CHECK(parsed.symbolServer == defaults.symbolServer);
        CHECK(!ParsePreferences("theme=99\n", defaults, bounds, parsed));
        CHECK(!ParsePreferences("theme=2\nsymbol_network=yes\n", defaults, bounds, parsed));
        CHECK(!ParsePreferences("theme=2\ninvestigation_recent=F:0G\n",
                                defaults, bounds, parsed));
        CHECK(!ParsePreferences("theme=2\nsymbol_cache=\\\\remote\\cache\n",
                                defaults, bounds, parsed));
        CHECK(!ParsePreferences("theme=2\nsymbol_network=1\nsymbol_cache=relative\n"
                                "symbol_server=https://server\n",
                                defaults, bounds, parsed));
        CHECK(!ParsePreferences(std::string(kMaxPreferencesBytes + 1, 'x'),
                                defaults, bounds, parsed));
        PreferencesData invalidSave = defaults;
        invalidSave.symbolCache = "\\\\remote\\cache";
        std::string text;
        CHECK(!SerializePreferences(invalidSave, bounds, text));
    }

    const fs::path root = uniqueRoot();
    const fs::path path = root / "prefs.ini";
    std::error_code ec;
    fs::create_directories(root, ec);
    CHECK(!ec);

    // The second durable write preserves the first complete primary as .bak.
    PreferencesData first = sample(1, "first");
    PreferencesData second = sample(2, "second");
    CHECK(SavePreferencesFile(path, first, bounds));
    CHECK(SavePreferencesFile(path, second, bounds));
    CHECK(fs::is_regular_file(atomic_file::BackupPath(path)));

    PreferencesData loaded;
    CHECK(LoadPreferencesFile(path, defaults, bounds, loaded) ==
          atomic_file::ReadSource::Primary);
    CHECK(loaded.theme == 2);
    CHECK(loaded.investigationRecent[0].query == "second");

    // A syntactically malformed primary recovers the last known-good backup.
    {
        std::ofstream corrupt(path, std::ios::binary | std::ios::trunc);
        corrupt << "theme=not-an-int\nsymbol_network=1\n";
    }
    loaded = defaults;
    CHECK(LoadPreferencesFile(path, defaults, bounds, loaded) ==
          atomic_file::ReadSource::Backup);
    CHECK(loaded.theme == 1);
    CHECK(loaded.investigationRecent[0].query == "first");
    CHECK(!loaded.symbolNetwork);

    // Oversized primaries are rejected before parsing and also trigger recovery.
    {
        std::ofstream huge(path, std::ios::binary | std::ios::trunc);
        huge << std::string(kMaxPreferencesBytes + 1, 'x');
    }
    loaded = defaults;
    CHECK(LoadPreferencesFile(path, defaults, bounds, loaded) ==
          atomic_file::ReadSource::Backup);
    CHECK(loaded.theme == 1);

    // A failed install never treats a directory as a replaceable prefs file.
    const fs::path directoryTarget = root / "not_a_file";
    fs::create_directory(directoryTarget, ec);
    CHECK(!ec);
    CHECK(!SavePreferencesFile(directoryTarget, first, bounds));
    CHECK(fs::is_directory(directoryTarget));

    fs::remove_all(root, ec);
    CHECK(!ec);

    if (failures) {
        std::cerr << failures << " preference test(s) failed\n";
        return 1;
    }
    std::cout << "preferences_test: all checks passed\n";
    return 0;
}
