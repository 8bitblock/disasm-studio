#pragma once

#include "AtomicFile.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

constexpr int kMinUiZoomPercent = 75;
constexpr int kMaxUiZoomPercent = 150;
constexpr int kDefaultUiZoomPercent = 90;

enum class PreferenceIdentity {
    File,
    Live,
};

struct PreferenceRecentQuery {
    PreferenceIdentity identity = PreferenceIdentity::File;
    std::string query;
};

struct PreferencesData {
    int theme = 0;
    int density = 0;
    int uiZoomPercent = kDefaultUiZoomPercent;
    int navigatorOptionalMask = 0;
    bool analysisQueueCollapsed = false;
    bool symbolNetwork = false;
    std::string symbolCache;
    std::string symbolServer = "https://msdl.microsoft.com/download/symbols";
    bool symbolSource = true;
    bool symbolTypes = true;
    bool symbolLocals = true;
    std::vector<PreferenceRecentQuery> investigationRecent;
};

struct PreferencesBounds {
    int themeCount = 1;
    int densityMin = 0;
    int densityMax = 0;
};

constexpr size_t kMaxPreferencesBytes = 64u * 1024u;
constexpr size_t kMaxPreferenceRecentQueries = 32;
constexpr size_t kMaxPreferenceQueryBytes = 512;
constexpr size_t kMaxSymbolCacheBytes = 4095;
constexpr size_t kMaxSymbolServerBytes = 2047;

// Strict for known fields (bad numeric/boolean/hex/path values reject the whole
// copy) while ignoring well-formed unknown key=value records for forward
// compatibility. `defaults` supplies fields absent from older prefs files.
bool ParsePreferences(std::string_view text, const PreferencesData& defaults,
                      const PreferencesBounds& bounds, PreferencesData& out);
bool SerializePreferences(const PreferencesData& data,
                          const PreferencesBounds& bounds, std::string& out);

// Loads a fully valid primary, otherwise the last known-good .bak. The output is
// unchanged when neither exists or validates.
atomic_file::ReadSource LoadPreferencesFile(
    const std::filesystem::path& path,
    const PreferencesData& defaults,
    const PreferencesBounds& bounds,
    PreferencesData& out);

bool SavePreferencesFile(const std::filesystem::path& path,
                         const PreferencesData& data,
                         const PreferencesBounds& bounds);

} // namespace ds
