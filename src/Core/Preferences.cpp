#include "Preferences.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <system_error>
#include <unordered_set>

namespace ds {
namespace {

bool parseInt(std::string_view value, int& out) {
    if (value.empty()) return false;
    int candidate = 0;
    const char* first = value.data();
    const char* last = first + value.size();
    const auto parsed = std::from_chars(first, last, candidate, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != last) return false;
    out = candidate;
    return true;
}

bool parseBool(std::string_view value, bool& out) {
    if (value == "0") { out = false; return true; }
    if (value == "1") { out = true; return true; }
    return false;
}

bool invalidLineValue(std::string_view value, size_t maxBytes,
                      bool rejectSymbolSeparators) {
    if (value.size() > maxBytes) return true;
    for (const unsigned char c : value) {
        if (c == 0 || c == '\r' || c == '\n' || c < 0x20 || c == 0x7f)
            return true;
        if (rejectSymbolSeparators && (c == ';' || c == '*')) return true;
    }
    return false;
}

bool remoteCachePath(std::string_view value) {
    return value.starts_with("\\\\") || value.starts_with("//") ||
           value.find("://") != std::string_view::npos;
}

bool localAbsolutePath(std::string_view value) {
    if (value.empty() || remoteCachePath(value)) return false;
    try {
        return std::filesystem::path(std::string(value)).is_absolute();
    } catch (...) {
        return false;
    }
}

char hexDigit(unsigned value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    return digits[value & 0x0f];
}

int fromHex(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

bool decodeQuery(std::string_view encoded, std::string& out) {
    out.clear();
    if (encoded.empty() || (encoded.size() & 1u) ||
        encoded.size() > kMaxPreferenceQueryBytes * 2)
        return false;
    out.reserve(encoded.size() / 2);
    for (size_t i = 0; i < encoded.size(); i += 2) {
        const int high = fromHex(encoded[i]);
        const int low = fromHex(encoded[i + 1]);
        if (high < 0 || low < 0) { out.clear(); return false; }
        const unsigned char byte = static_cast<unsigned char>((high << 4) | low);
        if (byte == 0 || byte == '\r' || byte == '\n' || byte < 0x20 || byte == 0x7f) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<char>(byte));
    }
    return !out.empty();
}

std::string encodeQuery(std::string_view query) {
    std::string encoded;
    encoded.reserve(query.size() * 2);
    for (const unsigned char byte : query) {
        encoded.push_back(hexDigit(byte >> 4));
        encoded.push_back(hexDigit(byte));
    }
    return encoded;
}

std::string insensitiveKey(PreferenceIdentity identity, std::string_view query) {
    std::string key;
    key.reserve(query.size() + 1);
    key.push_back(identity == PreferenceIdentity::Live ? 'L' : 'F');
    for (unsigned char c : query) {
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
        key.push_back(static_cast<char>(c));
    }
    return key;
}

bool validateData(const PreferencesData& data, const PreferencesBounds& bounds) {
    if (bounds.themeCount <= 0 || bounds.densityMin > bounds.densityMax ||
        data.theme < 0 || data.theme >= bounds.themeCount ||
        data.density < bounds.densityMin || data.density > bounds.densityMax ||
        data.uiZoomPercent < kMinUiZoomPercent ||
        data.uiZoomPercent > kMaxUiZoomPercent ||
        data.navigatorOptionalMask < 0 || data.navigatorOptionalMask > 127 ||
        invalidLineValue(data.symbolCache, kMaxSymbolCacheBytes, true) ||
        remoteCachePath(data.symbolCache) ||
        invalidLineValue(data.symbolServer, kMaxSymbolServerBytes, true) ||
        data.investigationRecent.size() > kMaxPreferenceRecentQueries)
        return false;
    if (data.symbolNetwork &&
        (!localAbsolutePath(data.symbolCache) || data.symbolServer.empty()))
        return false;

    std::unordered_set<std::string> seen;
    for (const PreferenceRecentQuery& recent : data.investigationRecent) {
        if (recent.query.empty() || recent.query.size() > kMaxPreferenceQueryBytes ||
            invalidLineValue(recent.query, kMaxPreferenceQueryBytes, false) ||
            !seen.insert(insensitiveKey(recent.identity, recent.query)).second)
            return false;
    }
    return true;
}

} // namespace

bool ParsePreferences(std::string_view text, const PreferencesData& defaults,
                      const PreferencesBounds& bounds, PreferencesData& out) {
    if (text.empty() || text.size() > kMaxPreferencesBytes ||
        text.find('\0') != std::string_view::npos)
        return false;

    PreferencesData parsed = defaults;
    parsed.investigationRecent.clear();
    bool recognized = false;
    std::unordered_set<std::string> seenRecent;

    size_t offset = 0;
    while (offset < text.size()) {
        const size_t newline = text.find('\n', offset);
        const size_t end = newline == std::string_view::npos ? text.size() : newline;
        std::string_view line = text.substr(offset, end - offset);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        offset = newline == std::string_view::npos ? text.size() : newline + 1;

        if (line.empty() || line.starts_with('#')) continue;
        const size_t equals = line.find('=');
        if (equals == std::string_view::npos || equals == 0) return false;
        const std::string_view key = line.substr(0, equals);
        const std::string_view value = line.substr(equals + 1);

        if (key == "theme") {
            recognized = parseInt(value, parsed.theme);
            if (!recognized || parsed.theme < 0 || parsed.theme >= bounds.themeCount)
                return false;
        } else if (key == "density") {
            recognized = parseInt(value, parsed.density);
            if (!recognized || parsed.density < bounds.densityMin ||
                parsed.density > bounds.densityMax)
                return false;
        } else if (key == "ui_zoom") {
            if (!parseInt(value, parsed.uiZoomPercent) ||
                parsed.uiZoomPercent < kMinUiZoomPercent ||
                parsed.uiZoomPercent > kMaxUiZoomPercent)
                return false;
            recognized = true;
        } else if (key == "navigator_optional") {
            if (!parseInt(value, parsed.navigatorOptionalMask) ||
                parsed.navigatorOptionalMask < 0 || parsed.navigatorOptionalMask > 127)
                return false;
            recognized = true;
        } else if (key == "analysis_queue_collapsed") {
            if (!parseBool(value, parsed.analysisQueueCollapsed)) return false;
            recognized = true;
        } else if (key == "symbol_network") {
            if (!parseBool(value, parsed.symbolNetwork)) return false;
            recognized = true;
        } else if (key == "symbol_cache") {
            if (invalidLineValue(value, kMaxSymbolCacheBytes, true) ||
                remoteCachePath(value))
                return false;
            parsed.symbolCache.assign(value);
            recognized = true;
        } else if (key == "symbol_server") {
            if (invalidLineValue(value, kMaxSymbolServerBytes, true)) return false;
            parsed.symbolServer.assign(value);
            recognized = true;
        } else if (key == "symbol_source") {
            if (!parseBool(value, parsed.symbolSource)) return false;
            recognized = true;
        } else if (key == "symbol_types") {
            if (!parseBool(value, parsed.symbolTypes)) return false;
            recognized = true;
        } else if (key == "symbol_locals") {
            if (!parseBool(value, parsed.symbolLocals)) return false;
            recognized = true;
        } else if (key == "investigation_recent") {
            if (value.size() < 3 || value[1] != ':' ||
                (value[0] != 'F' && value[0] != 'L') ||
                parsed.investigationRecent.size() >= kMaxPreferenceRecentQueries)
                return false;
            PreferenceRecentQuery recent;
            recent.identity = value[0] == 'L' ? PreferenceIdentity::Live
                                               : PreferenceIdentity::File;
            if (!decodeQuery(value.substr(2), recent.query)) return false;
            if (!seenRecent.insert(insensitiveKey(recent.identity, recent.query)).second)
                return false;
            parsed.investigationRecent.push_back(std::move(recent));
            recognized = true;
        } else {
            // Unknown key=value records are reserved for future versions, but
            // remain bounded and line-safe like every known value.
            if (key.size() > 128 || invalidLineValue(key, 128, false) ||
                invalidLineValue(value, 4096, false))
                return false;
        }
    }

    if (!recognized || !validateData(parsed, bounds)) return false;
    out = std::move(parsed);
    return true;
}

bool SerializePreferences(const PreferencesData& data,
                          const PreferencesBounds& bounds, std::string& out) {
    if (!validateData(data, bounds)) return false;
    std::string encoded;
    encoded.reserve(512 + data.symbolCache.size() + data.symbolServer.size() +
                    data.investigationRecent.size() * 64);
    encoded += "theme=" + std::to_string(data.theme) + "\n";
    encoded += "density=" + std::to_string(data.density) + "\n";
    encoded += "ui_zoom=" + std::to_string(data.uiZoomPercent) + "\n";
    encoded += "navigator_optional=" + std::to_string(data.navigatorOptionalMask) + "\n";
    encoded += std::string("analysis_queue_collapsed=") + (data.analysisQueueCollapsed ? "1\n" : "0\n");
    encoded += std::string("symbol_network=") + (data.symbolNetwork ? "1\n" : "0\n");
    encoded += "symbol_cache=" + data.symbolCache + "\n";
    encoded += "symbol_server=" + data.symbolServer + "\n";
    encoded += std::string("symbol_source=") + (data.symbolSource ? "1\n" : "0\n");
    encoded += std::string("symbol_types=") + (data.symbolTypes ? "1\n" : "0\n");
    encoded += std::string("symbol_locals=") + (data.symbolLocals ? "1\n" : "0\n");
    for (const PreferenceRecentQuery& recent : data.investigationRecent) {
        encoded += "investigation_recent=";
        encoded.push_back(recent.identity == PreferenceIdentity::Live ? 'L' : 'F');
        encoded += ':';
        encoded += encodeQuery(recent.query);
        encoded += '\n';
    }
    if (encoded.size() > kMaxPreferencesBytes) return false;
    out = std::move(encoded);
    return true;
}

atomic_file::ReadSource LoadPreferencesFile(
    const std::filesystem::path& path, const PreferencesData& defaults,
    const PreferencesBounds& bounds, PreferencesData& out) {
    PreferencesData parsed;
    std::string text;
    const atomic_file::ReadSource source = atomic_file::ReadValidated(
        path, text,
        [&](std::string_view candidate) {
            PreferencesData attempt;
            if (!ParsePreferences(candidate, defaults, bounds, attempt)) return false;
            parsed = std::move(attempt);
            return true;
        },
        kMaxPreferencesBytes);
    if (source != atomic_file::ReadSource::None) out = std::move(parsed);
    return source;
}

bool SavePreferencesFile(const std::filesystem::path& path,
                         const PreferencesData& data,
                         const PreferencesBounds& bounds) {
    std::string text;
    return SerializePreferences(data, bounds, text) && atomic_file::Write(path, text);
}

} // namespace ds
