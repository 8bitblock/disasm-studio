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
        expected.uiZoomPercent = 110;
        expected.symbolNetwork = true;
        expected.navigatorOptionalMask = 85;
        expected.analysisQueueCollapsed = true;
        std::string text;
        CHECK(SerializePreferences(expected, bounds, text));
        CHECK(text.find("ui_zoom=110\n") != std::string::npos);
        PreferencesData parsed;
        CHECK(ParsePreferences(text, defaults, bounds, parsed));
        CHECK(parsed.theme == 3);
        CHECK(parsed.density == 1);
        CHECK(parsed.uiZoomPercent == 110);
        CHECK(parsed.symbolNetwork);
        CHECK(parsed.navigatorOptionalMask == 85);
        CHECK(parsed.analysisQueueCollapsed);
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
        CHECK(parsed.uiZoomPercent == kDefaultUiZoomPercent);
        CHECK(!parsed.symbolNetwork);
        CHECK(parsed.navigatorOptionalMask == 0);
        CHECK(!parsed.analysisQueueCollapsed);
        CHECK(!ParsePreferences("theme=2\nnavigator_optional=128\n", defaults, bounds, parsed));
        CHECK(!ParsePreferences("theme=2\nnavigator_optional=-1\n", defaults, bounds, parsed));
        CHECK(!ParsePreferences("theme=2\nanalysis_queue_collapsed=yes\n", defaults, bounds, parsed));
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

    // Zoom accepts its inclusive limits and retains caller defaults for legacy
    // files. Invalid numbers reject the complete copy without changing output.
    {
        CHECK(PreferencesData{}.uiZoomPercent == 90);
        for (const int zoom : {75, 90, 100, 150}) {
            PreferencesData parsed;
            CHECK(ParsePreferences("ui_zoom=" + std::to_string(zoom) + "\n",
                                   defaults, bounds, parsed));
            CHECK(parsed.uiZoomPercent == zoom);
            std::string text;
            CHECK(SerializePreferences(parsed, bounds, text));
            PreferencesData roundTrip;
            CHECK(ParsePreferences(text, defaults, bounds, roundTrip));
            CHECK(roundTrip.uiZoomPercent == zoom);
        }

        PreferencesData customDefaults = defaults;
        customDefaults.uiZoomPercent = 115;
        PreferencesData parsed;
        CHECK(ParsePreferences("theme=2\n", customDefaults, bounds, parsed));
        CHECK(parsed.uiZoomPercent == 115);
        std::string original;
        CHECK(SerializePreferences(parsed, bounds, original));
        for (const char* value : {"", "small", "90%", "90.0", "+90", " 90",
                                  "90 ", "74", "151", "0", "-90",
                                  "2147483648", "-2147483649",
                                  "999999999999999999999999"}) {
            CHECK(!ParsePreferences(std::string("theme=1\nui_zoom=") + value + "\n",
                                    defaults, bounds, parsed));
            std::string unchanged;
            CHECK(SerializePreferences(parsed, bounds, unchanged));
            CHECK(unchanged == original);
        }
        for (const int zoom : {74, 151}) {
            PreferencesData invalidSave = defaults;
            invalidSave.uiZoomPercent = zoom;
            std::string text = "unchanged";
            CHECK(!SerializePreferences(invalidSave, bounds, text));
            CHECK(text == "unchanged");
        }
    }

    const fs::path root = uniqueRoot();
    const fs::path path = root / "prefs.ini";
    std::error_code ec;
    fs::create_directories(root, ec);
    CHECK(!ec);

    // The second durable write preserves the first complete primary as .bak.
    PreferencesData first = sample(1, "first");
    PreferencesData second = sample(2, "second");
    first.uiZoomPercent = 80;
    second.uiZoomPercent = 125;
    CHECK(SavePreferencesFile(path, first, bounds));
    CHECK(SavePreferencesFile(path, second, bounds));
    CHECK(fs::is_regular_file(atomic_file::BackupPath(path)));

    PreferencesData loaded;
    CHECK(LoadPreferencesFile(path, defaults, bounds, loaded) ==
          atomic_file::ReadSource::Primary);
    CHECK(loaded.theme == 2);
    CHECK(loaded.uiZoomPercent == 125);
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
    CHECK(loaded.uiZoomPercent == 80);
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
