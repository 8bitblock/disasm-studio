// CrackmeTriage.cpp — see CrackmeTriage.h.
#include "CrackmeTriage.h"

#include "XrefIndex.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ds {
namespace {

struct ExtractedString {
    uint64_t fileOffset = 0;
    std::string text;
    CrackmeLiteralEncoding encoding = CrackmeLiteralEncoding::Ascii;
    bool truncated = false;
};

struct ParsedEndpoint {
    std::string host;
    std::string scheme;
    std::string path;
    uint16_t port = 0;
    bool portValid = false;
    CrackmeEndpointKind kind = CrackmeEndpointKind::Domain;
    size_t offset = 0;
    size_t length = 0;
    CrackmeLiteralRole role = CrackmeLiteralRole::Host;
};

struct ParsedHeader {
    std::string name;
    std::string value;
    size_t offset = 0;
    size_t valueOffset = 0;
    size_t length = 0;
};

struct OwnedReference {
    uint64_t source = 0;
    size_t function = (std::numeric_limits<size_t>::max)();
};

static constexpr size_t kNoIndex = (std::numeric_limits<size_t>::max)();

static char asciiLower(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

static std::string lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(), asciiLower);
    return out;
}

static bool isAsciiPrintable(uint8_t c) { return c >= 0x20 && c <= 0x7e; }
static bool isHostChar(char c) {
    const unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '.' || c == '-' || c == ':' || c == '[' || c == ']';
}

static bool checkedEnd(uint64_t start, uint64_t size, uint64_t& end) {
    if (size > (std::numeric_limits<uint64_t>::max)() - start) return false;
    end = start + size;
    return true;
}

static bool inOverlay(const CrackmeTriageInput& input, uint64_t offset) {
    return input.overlaySize && offset >= input.overlayOffset &&
           offset - input.overlayOffset < input.overlaySize;
}

static void markIncomplete(CrackmeTriageCompleteness& completeness,
                           CrackmeTriageStopReason reason,
                           std::string_view text) {
    completeness.complete = false;
    if (completeness.stopReason == CrackmeTriageStopReason::None)
        completeness.stopReason = reason;
    if (completeness.reason.empty()) completeness.reason.assign(text);
}

static bool cancelled(const CrackmeTriageInput& input) {
    return input.cancelled && input.cancelled();
}

static bool cancellationCheckpoint(const CrackmeTriageInput& input,
                                   uint64_t position, uint64_t& nextCheck) {
    if (!input.cancelled) return false;
    const uint64_t interval = input.limits.cancellationCheckBytes;
    if (interval && position < nextCheck) return false;
    if (interval) {
        nextCheck = position > (std::numeric_limits<uint64_t>::max)() - interval
                  ? (std::numeric_limits<uint64_t>::max)() : position + interval;
    }
    return input.cancelled();
}

static void setCancelled(CrackmeTriageCompleteness& completeness) {
    completeness.cancelled = true;
    markIncomplete(completeness, CrackmeTriageStopReason::Cancelled,
                   "offline crackme triage was cancelled; findings are partial");
}

static std::vector<ExtractedString>
extractStrings(const CrackmeTriageInput& input, CrackmeTriageCompleteness& completeness) {
    std::vector<ExtractedString> out;
    completeness.bytesTotal = input.size;
    if (!input.bytes && input.size) {
        markIncomplete(completeness, CrackmeTriageStopReason::InvalidInput,
                       "nonzero file size was supplied without file bytes");
        return out;
    }

    const uint64_t scan64 = (std::min<uint64_t>)(input.size, input.limits.maxBytes);
    const size_t scanSize = static_cast<size_t>(scan64);
    completeness.bytesExamined = scan64;
    if (scan64 < input.size) {
        completeness.bytesTruncated = true;
        markIncomplete(completeness, CrackmeTriageStopReason::ByteLimit,
                       "file byte budget was reached; later literals may be absent");
    }
    if (!scanSize || !input.limits.maxStrings || !input.limits.maxStringBytes)
        return out;
    out.reserve((std::min<size_t>)(input.limits.maxStrings, 4096));

    auto retain = [&](uint64_t offset, std::string text,
                      CrackmeLiteralEncoding encoding, bool textTruncated) {
        if (out.size() >= input.limits.maxStrings) {
            completeness.stringsTruncated = true;
            markIncomplete(completeness, CrackmeTriageStopReason::StringLimit,
                           "string finding cap was reached; endpoint extraction is partial");
            return false;
        }
        out.push_back({ offset, std::move(text), encoding, textTruncated });
        if (textTruncated) {
            completeness.stringsTruncated = true;
            markIncomplete(completeness, CrackmeTriageStopReason::StringLimit,
                           "one or more string literals exceeded the per-string byte cap");
        }
        return true;
    };

    uint64_t nextCheck = 0;
    for (size_t i = 0; i < scanSize;) {
        if (cancellationCheckpoint(input, i, nextCheck)) {
            completeness.bytesExamined = i;
            setCancelled(completeness);
            return out;
        }
        if (!isAsciiPrintable(input.bytes[i])) { ++i; continue; }
        const size_t start = i;
        while (i < scanSize && isAsciiPrintable(input.bytes[i])) ++i;
        const size_t chars = i - start;
        if (chars < 4) continue;
        const size_t kept = (std::min)(chars, input.limits.maxStringBytes);
        if (!retain(start,
                    std::string(reinterpret_cast<const char*>(input.bytes + start), kept),
                    CrackmeLiteralEncoding::Ascii, kept != chars))
            return out;
    }

    // Search both possible byte alignments.  A UTF-16LE string in an overlay is
    // file data, not guaranteed to inherit the PE section alignment.
    for (size_t alignment = 0; alignment < 2 && alignment < scanSize; ++alignment) {
        nextCheck = alignment;
        for (size_t i = alignment; i + 1 < scanSize;) {
            if (cancellationCheckpoint(input, i, nextCheck)) {
                completeness.bytesExamined = i;
                setCancelled(completeness);
                return out;
            }
            if (!isAsciiPrintable(input.bytes[i]) || input.bytes[i + 1] != 0) {
                i += 2;
                continue;
            }
            const size_t start = i;
            std::string text;
            text.reserve((std::min<size_t>)(input.limits.maxStringBytes, 128));
            size_t chars = 0;
            while (i + 1 < scanSize && isAsciiPrintable(input.bytes[i]) &&
                   input.bytes[i + 1] == 0) {
                if (text.size() < input.limits.maxStringBytes)
                    text.push_back(static_cast<char>(input.bytes[i]));
                ++chars;
                i += 2;
            }
            if (chars < 4) continue;
            if (!retain(start, std::move(text), CrackmeLiteralEncoding::Utf16Le,
                        chars > input.limits.maxStringBytes))
                return out;
        }
    }
    return out;
}

static bool parseDecimalPort(std::string_view value, uint16_t& port) {
    if (value.empty() || value.size() > 5) return false;
    uint32_t n = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        n = n * 10u + static_cast<unsigned>(c - '0');
        if (n > 65535) return false;
    }
    if (!n) return false;
    port = static_cast<uint16_t>(n);
    return true;
}

static bool parseIPv4(std::string_view value, std::array<uint8_t, 4>* octets = nullptr) {
    std::array<uint8_t, 4> parsed{};
    size_t pos = 0;
    for (size_t part = 0; part < parsed.size(); ++part) {
        const size_t dot = value.find('.', pos);
        const size_t end = dot == std::string_view::npos ? value.size() : dot;
        if (end == pos || end - pos > 3) return false;
        unsigned n = 0;
        for (size_t i = pos; i < end; ++i) {
            if (value[i] < '0' || value[i] > '9') return false;
            n = n * 10 + static_cast<unsigned>(value[i] - '0');
        }
        if (n > 255 || (end - pos > 1 && value[pos] == '0')) return false;
        parsed[part] = static_cast<uint8_t>(n);
        if (part + 1 == parsed.size()) {
            // The fourth octet must consume the token.  Without this check a
            // five-part value such as 1.2.3.4.5 was accepted after the fourth
            // part and the unconsumed tail was silently ignored.
            if (dot != std::string_view::npos) return false;
            pos = end;
            continue;
        }
        if (dot == std::string_view::npos) return false;
        pos = dot + 1;
    }
    if (pos != value.size()) return false;
    if (octets) *octets = parsed;
    return true;
}

static bool isHexGroup(std::string_view group) {
    if (group.empty() || group.size() > 4) return false;
    for (char c : group)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

// Parse one non-compressed side of an IPv6 address. An embedded dotted IPv4
// value is two 16-bit units and is valid only as the final token of the complete
// address. The caller supplies that permission only for the rightmost side.
static bool parseIPv6Side(std::string_view side, bool allowIPv4Tail,
                          std::vector<uint16_t>& units, bool& usedIPv4Tail) {
    if (side.empty()) return true;
    size_t pos = 0;
    while (pos < side.size()) {
        const size_t colon = side.find(':', pos);
        const size_t end = colon == std::string_view::npos ? side.size() : colon;
        const std::string_view group = side.substr(pos, end - pos);
        if (group.empty()) return false; // only the central `::` may be empty
        if (group.find('.') != std::string_view::npos) {
            std::array<uint8_t, 4> octets{};
            if (!allowIPv4Tail || usedIPv4Tail || end != side.size() ||
                !parseIPv4(group, &octets))
                return false;
            usedIPv4Tail = true;
            units.push_back(static_cast<uint16_t>(
                (static_cast<uint16_t>(octets[0]) << 8) | octets[1]));
            units.push_back(static_cast<uint16_t>(
                (static_cast<uint16_t>(octets[2]) << 8) | octets[3]));
        } else {
            if (!isHexGroup(group)) return false;
            uint16_t word = 0;
            for (char c : group) {
                word = static_cast<uint16_t>(word << 4);
                if (c >= '0' && c <= '9') word |= static_cast<uint16_t>(c - '0');
                else if (c >= 'a' && c <= 'f') word |= static_cast<uint16_t>(c - 'a' + 10);
                else word |= static_cast<uint16_t>(c - 'A' + 10);
            }
            units.push_back(word);
        }
        if (units.size() > 8) return false;
        if (colon == std::string_view::npos) break;
        pos = colon + 1;
        if (pos == side.size()) return false; // stray single trailing ':'
    }
    return true;
}

static bool parseIPv6(std::string_view value,
                      std::array<uint16_t, 8>* words = nullptr) {
    // 45 is the longest conventional form: six four-digit h16 groups plus a
    // maximal dotted-quad tail. Keeping the input bounded also bounds all scans.
    if (value.empty() || value.size() > 45 ||
        value.find(':') == std::string_view::npos)
        return false;
    const size_t compression = value.find("::");
    if (compression != std::string_view::npos &&
        value.find("::", compression + 2) != std::string_view::npos) return false;

    bool usedIPv4Tail = false;
    if (compression == std::string_view::npos) {
        // Without compression, leading/trailing colons and every empty group
        // are invalid, and the address must encode exactly eight 16-bit units.
        if (value.front() == ':' || value.back() == ':') return false;
        std::vector<uint16_t> explicitUnits;
        if (!parseIPv6Side(value, true, explicitUnits, usedIPv4Tail) ||
            explicitUnits.size() != 8)
            return false;
        if (words) std::copy(explicitUnits.begin(), explicitUnits.end(), words->begin());
        return true;
    }

    // Reject a third colon adjacent to the sole `::`; searching for another
    // non-overlapping `::` alone would miss malformed values such as `:::`.
    if ((compression > 0 && value[compression - 1] == ':') ||
        (compression + 2 < value.size() && value[compression + 2] == ':'))
        return false;

    const std::string_view left = value.substr(0, compression);
    const std::string_view right = value.substr(compression + 2);
    // A dotted tail cannot occur to the left of compression because it would no
    // longer be the final 32 bits of the address.
    std::vector<uint16_t> leftUnits, rightUnits;
    if (!parseIPv6Side(left, false, leftUnits, usedIPv4Tail) ||
        !parseIPv6Side(right, true, rightUnits, usedIPv4Tail))
        return false;
    // `::` must replace at least one 16-bit unit; eight explicit units plus
    // compression is an overlong address rather than an alternative spelling.
    if (leftUnits.size() + rightUnits.size() >= 8) return false;
    if (words) {
        words->fill(0);
        std::copy(leftUnits.begin(), leftUnits.end(), words->begin());
        std::copy(rightUnits.begin(), rightUnits.end(),
                  words->end() - static_cast<ptrdiff_t>(rightUnits.size()));
    }
    return true;
}

static bool parseDomain(std::string_view value) {
    if (value.empty() || value.size() > 253 || value == "localhost") return false;
    if (value.front() == '.' || value.back() == '.' || value.find('.') == std::string_view::npos)
        return false;
    size_t labels = 0, pos = 0;
    std::string_view last;
    while (pos < value.size()) {
        const size_t dot = value.find('.', pos);
        const size_t end = dot == std::string_view::npos ? value.size() : dot;
        const std::string_view label = value.substr(pos, end - pos);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-')
            return false;
        for (char c : label) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (!std::isalnum(u) && c != '-') return false;
        }
        last = label;
        ++labels;
        if (dot == std::string_view::npos) break;
        pos = dot + 1;
    }
    if (labels < 2 || last.size() < 2) return false;
    for (char c : last)
        if (!std::isalpha(static_cast<unsigned char>(c))) return false;
    return true;
}

static bool metadataHost(std::string_view value) {
    const std::string host = lower(value);
    constexpr std::string_view exact[] = {
        "w3.org", "www.w3.org", "schemas.microsoft.com", "schema.org",
        "ns.adobe.com", "www.adobe.com", "purl.org", "xml.org",
        "docs.microsoft.com", "learn.microsoft.com", "github.com",
        "www.github.com", "raw.githubusercontent.com", "readthedocs.io",
        "dearimgui.com", "www.dearimgui.com"
    };
    for (const std::string_view item : exact)
        if (host == item) return true;
    return false;
}

static bool looksLikeDottedFilename(std::string_view value) {
    const size_t dot = value.rfind('.');
    if (dot == std::string_view::npos || dot + 1 >= value.size()) return false;
    const std::string extension = lower(value.substr(dot + 1));
    constexpr std::string_view extensions[] = {
        "json", "xml", "properties", "ini", "cfg", "config", "manifest",
        "pdb", "dll", "exe", "sys", "dat", "txt", "html", "htm", "css",
        "js", "map", "yaml", "yml", "toml", "md"
    };
    for (const std::string_view item : extensions)
        if (extension == item) return true;
    return false;
}

static std::optional<ParsedHeader> parseHttpHeader(std::string_view text) {
    size_t first = 0, last = text.size();
    while (first < last && std::isspace(static_cast<unsigned char>(text[first]))) ++first;
    while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1]))) --last;
    if (first == last) return std::nullopt;
    const size_t colon = text.find(':', first);
    if (colon == std::string_view::npos || colon >= last) return std::nullopt;
    std::string name = lower(text.substr(first, colon - first));
    constexpr std::string_view allowed[] = {
        "host", "content-type", "content-length", "user-agent", "accept",
        "accept-language", "accept-encoding", "authorization",
        "proxy-authorization", "cookie", "set-cookie", "referer", "origin",
        "connection", "cache-control", "if-none-match", "if-modified-since",
        "transfer-encoding", "x-api-key"
    };
    bool recognized = false;
    for (const std::string_view candidate : allowed) {
        if (name == candidate) { recognized = true; break; }
    }
    if (!recognized) return std::nullopt;
    size_t valueFirst = colon + 1;
    while (valueFirst < last &&
           std::isspace(static_cast<unsigned char>(text[valueFirst]))) ++valueFirst;
    if (valueFirst == last) return std::nullopt;
    ParsedHeader header;
    header.name = std::move(name);
    header.value.assign(text.substr(valueFirst, last - valueFirst));
    header.offset = first;
    header.valueOffset = valueFirst;
    header.length = last - first;
    return header;
}

static CrackmeEndpointScope classifyIPv4Scope(const std::array<uint8_t, 4>& o) {
    if (o[0] == 127) return CrackmeEndpointScope::Loopback;
    if (o[0] == 10 || (o[0] == 172 && o[1] >= 16 && o[1] <= 31) ||
        (o[0] == 192 && o[1] == 168) || (o[0] == 169 && o[1] == 254))
        return CrackmeEndpointScope::PrivateNetwork;
    return CrackmeEndpointScope::PublicNetwork;
}

static CrackmeEndpointScope classifyScope(std::string_view host,
                                          CrackmeEndpointKind kind) {
    if (kind == CrackmeEndpointKind::IPv4) {
        std::array<uint8_t, 4> o{};
        if (!parseIPv4(host, &o)) return CrackmeEndpointScope::Unknown;
        return classifyIPv4Scope(o);
    }
    if (kind == CrackmeEndpointKind::IPv6) {
        std::array<uint16_t, 8> words{};
        if (!parseIPv6(host, &words)) return CrackmeEndpointScope::Unknown;
        const bool leadingLoopbackZeros =
            std::all_of(words.begin(), words.end() - 1,
                        [](uint16_t word) { return word == 0; });
        if (leadingLoopbackZeros && words.back() == 1)
            return CrackmeEndpointScope::Loopback;

        // IPv4-mapped IPv6 is ::ffff:0:0/96. Its effective remote scope is the
        // embedded IPv4 address, including loopback and private/link-local ranges.
        const bool ipv4Mapped =
            words[0] == 0 && words[1] == 0 && words[2] == 0 &&
            words[3] == 0 && words[4] == 0 && words[5] == 0xffff;
        if (ipv4Mapped) {
            const std::array<uint8_t, 4> octets = {
                static_cast<uint8_t>(words[6] >> 8),
                static_cast<uint8_t>(words[6]),
                static_cast<uint8_t>(words[7] >> 8),
                static_cast<uint8_t>(words[7]),
            };
            return classifyIPv4Scope(octets);
        }

        if ((words[0] & 0xfe00u) == 0xfc00u || // fc00::/7 unique-local
            (words[0] & 0xffc0u) == 0xfe80u)   // fe80::/10 link-local
            return CrackmeEndpointScope::PrivateNetwork;
        return CrackmeEndpointScope::PublicNetwork;
    }
    const std::string h = lower(host);
    if (h == "localhost" || h.size() > 10 && h.ends_with(".localhost"))
        return CrackmeEndpointScope::Loopback;
    if (h.ends_with(".local") || h.ends_with(".lan") || h.ends_with(".internal"))
        return CrackmeEndpointScope::PrivateNetwork;
    // A DNS name can resolve to public, private, or loopback addresses.  Static
    // bytes alone cannot honestly choose among them.
    return CrackmeEndpointScope::Unknown;
}

static bool parseHostPort(std::string_view authority, std::string& host,
                          uint16_t& port, bool& portValid,
                          CrackmeEndpointKind& kind) {
    portValid = false;
    if (authority.empty()) return false;
    if (const size_t at = authority.rfind('@'); at != std::string_view::npos)
        authority.remove_prefix(at + 1);

    std::string_view hostPart = authority;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos) return false;
        hostPart = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':' ||
                !parseDecimalPort(authority.substr(close + 2), port)) return false;
            portValid = true;
        }
        if (!parseIPv6(hostPart)) return false;
        kind = CrackmeEndpointKind::IPv6;
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos && authority.find(':') != colon) {
            // Multiple colons are an unbracketed IPv6 literal.  Do not guess
            // that the final group is a port; RFC-style host:port must use [].
            if (!parseIPv6(authority)) return false;
            hostPart = authority;
            kind = CrackmeEndpointKind::IPv6;
            host = lower(hostPart);
            return true;
        }
        if (colon != std::string_view::npos && authority.find(':') == colon) {
            uint16_t parsed = 0;
            if (parseDecimalPort(authority.substr(colon + 1), parsed)) {
                hostPart = authority.substr(0, colon);
                port = parsed;
                portValid = true;
            }
        }
        if (parseIPv4(hostPart)) kind = CrackmeEndpointKind::IPv4;
        else if (parseDomain(hostPart)) kind = CrackmeEndpointKind::Domain;
        else if (lower(hostPart) == "localhost") kind = CrackmeEndpointKind::Domain;
        else return false;
    }
    host = lower(hostPart);
    return true;
}

static bool urlTerminator(char c) {
    return std::isspace(static_cast<unsigned char>(c)) || c == '"' || c == '\'' ||
           c == '<' || c == '>' || c == '\\' || c == ')' || c == ']' || c == '}';
}

static std::string cleanPath(std::string_view path) {
    while (!path.empty() && (path.back() == '.' || path.back() == ',' ||
           path.back() == ';' || path.back() == ':')) path.remove_suffix(1);
    if (path.empty() || path.front() != '/') return {};
    return std::string(path);
}

static std::vector<ParsedEndpoint> parseEndpoints(std::string_view text) {
    std::vector<ParsedEndpoint> out;
    struct UrlAuthority {
        size_t start = 0, end = 0;
        std::string host;
        std::string scheme;
        uint16_t port = 0;
        bool portValid = false;
    };
    std::vector<UrlAuthority> urlAuthorities;
    const std::string folded = lower(text);
    constexpr std::string_view schemes[] = { "https://", "http://", "wss://", "ws://" };

    for (const std::string_view prefix : schemes) {
        size_t pos = 0;
        while ((pos = folded.find(prefix, pos)) != std::string::npos) {
            const size_t authorityStart = pos + prefix.size();
            size_t end = authorityStart;
            bool insideIpv6Brackets = false;
            while (end < text.size()) {
                const char c = text[end];
                if (end == authorityStart && c == '[') {
                    insideIpv6Brackets = true;
                    ++end;
                    continue;
                }
                if (insideIpv6Brackets && c == ']') {
                    insideIpv6Brackets = false;
                    ++end;
                    continue;
                }
                if (urlTerminator(c)) break;
                ++end;
            }
            size_t authorityEnd = authorityStart;
            while (authorityEnd < end && text[authorityEnd] != '/' &&
                   text[authorityEnd] != '?' && text[authorityEnd] != '#') ++authorityEnd;
            ParsedEndpoint parsed;
            parsed.scheme = std::string(prefix.substr(0, prefix.size() - 3));
            parsed.offset = pos;
            parsed.length = end - pos;
            parsed.role = CrackmeLiteralRole::Url;
            if (parseHostPort(text.substr(authorityStart, authorityEnd - authorityStart),
                              parsed.host, parsed.port, parsed.portValid, parsed.kind)) {
                if (metadataHost(parsed.host)) {
                    pos = end > pos ? end : pos + prefix.size();
                    continue;
                }
                if (authorityEnd < end) {
                    std::string_view tail = text.substr(authorityEnd, end - authorityEnd);
                    if (!tail.empty() && tail.front() == '/') parsed.path = cleanPath(tail);
                }
                urlAuthorities.push_back({ authorityStart, authorityEnd,
                                           parsed.host, parsed.scheme,
                                           parsed.port, parsed.portValid });
                out.push_back(std::move(parsed));
            }
            pos = end > pos ? end : pos + prefix.size();
        }
    }

    // Bare domains/IPs/host:port literals.  URL hosts are intentionally found a
    // second time and folded into the URL record by endpoint de-duplication.
    for (size_t pos = 0; pos < text.size();) {
        if (!isHostChar(text[pos])) { ++pos; continue; }
        const size_t start = pos;
        while (pos < text.size() && isHostChar(text[pos])) ++pos;
        std::string_view token = text.substr(start, pos - start);
        while (!token.empty() && (token.back() == '.' || token.back() == '-'))
            token.remove_suffix(1);
        while (!token.empty() && (token.front() == '.' || token.front() == '-')) {
            token.remove_prefix(1);
        }
        if (token.empty()) continue;
        ParsedEndpoint parsed;
        parsed.offset = start;
        parsed.length = token.size();
        parsed.role = CrackmeLiteralRole::Host;
        if (looksLikeDottedFilename(token) ||
            !parseHostPort(token, parsed.host, parsed.port, parsed.portValid, parsed.kind) ||
            metadataHost(parsed.host))
            continue;
        const auto authority = std::find_if(
            urlAuthorities.begin(), urlAuthorities.end(), [&](const UrlAuthority& range) {
                return start >= range.start && start < range.end;
            });
        if (authority != urlAuthorities.end()) {
            // Preserve the precise authority-host source/xref while folding it
            // into the URL identity. Ignore userinfo or other interior tokens.
            if (authority->host != parsed.host) continue;
            parsed.scheme = authority->scheme;
            parsed.port = authority->port;
            parsed.portValid = authority->portValid;
        }
        out.push_back(std::move(parsed));
    }
    return out;
}

static std::vector<NetworkArtifactKind> semanticArtifactKinds(std::string_view text) {
    const std::string value = lower(text);
    std::vector<NetworkArtifactKind> out;
    auto containsAny = [&](std::initializer_list<std::string_view> cues) {
        for (const std::string_view cue : cues)
            if (value.find(cue) != std::string::npos) return true;
        return false;
    };
    if (containsAny({ "authenticate", "authorization", "credential", "login", "auth token" }))
        out.push_back(NetworkArtifactKind::Authentication);
    const bool productProTitle =
        containsAny({ "task manager", "product", "edition" }) &&
        (value.ends_with(" pro") || value.find(" pro ") != std::string::npos);
    if (containsAny({ "license", "licence", "serial", "activation", "activate",
                      "deactivate", "entitlement" }) || productProTitle)
        out.push_back(NetworkArtifactKind::License);
    if (containsAny({ "validate", "validation", "verify", "invalid", "signature",
                      "checksum", "compare", "isvalid", "valid=", " valid" }))
        out.push_back(NetworkArtifactKind::Validation);
    if (containsAny({ "success", "accepted", "activated", "valid license", "valid key" }))
        out.push_back(NetworkArtifactKind::Success);
    if (containsAny({ "failed", "failure", "denied", "rejected", "invalid",
                      "unauthorized", "not recognised", "not recognized" }))
        out.push_back(NetworkArtifactKind::Failure);
    if (containsAny({ "server response", "response body", "reply", "http status",
                      "responsecode", "status code" }))
        out.push_back(NetworkArtifactKind::ReplyMarker);
    std::sort(out.begin(), out.end(), [](auto a, auto b) {
        return static_cast<unsigned>(a) < static_cast<unsigned>(b);
    });
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static bool interestingRoute(std::string_view path) {
    const std::string p = lower(path);
    constexpr std::string_view cues[] = {
        "activate", "deactivate", "license", "licence", "register", "verify",
        "validation", "authenticate", "authorization", "heartbeat", "keepalive",
        "serial", "token", "entitlement"
    };
    for (const std::string_view cue : cues)
        if (p.find(cue) != std::string::npos) return true;
    return false;
}

static std::vector<std::pair<std::string, size_t>> parseRoutes(std::string_view text) {
    std::vector<std::pair<std::string, size_t>> out;
    for (size_t pos = 0; pos < text.size();) {
        const size_t slash = text.find('/', pos);
        if (slash == std::string_view::npos) break;
        // Do not reinterpret the authority portion of scheme://host/path as a
        // route.  Advance directly to the first path slash so URL-only input
        // yields /path, never the synthetic /host/path.
        if (slash > 0 && text[slash - 1] == ':' && slash + 1 < text.size() &&
            text[slash + 1] == '/') {
            size_t path = slash + 2;
            while (path < text.size() && text[path] != '/' &&
                   !urlTerminator(text[path]))
                ++path;
            if (path >= text.size()) break;
            if (text[path] != '/') {
                pos = path + 1;
                continue;
            }
            pos = path;
            continue;
        }
        if (slash + 1 >= text.size() || text[slash + 1] == '/' ||
            !std::isalnum(static_cast<unsigned char>(text[slash + 1]))) {
            pos = slash + 1;
            continue;
        }
        size_t end = slash + 1;
        while (end < text.size() && !urlTerminator(text[end])) ++end;
        const std::string path = cleanPath(text.substr(slash, end - slash));
        if (interestingRoute(path)) out.emplace_back(path, slash);
        pos = end > slash ? end : slash + 1;
    }
    return out;
}

static CrackmeTriageLiteralSource makeSource(const CrackmeTriageInput& input,
                                             const ExtractedString& text,
                                             CrackmeLiteralRole role,
                                             std::string literal,
                                             size_t characterOffset) {
    CrackmeTriageLiteralSource source;
    source.role = role;
    source.encoding = text.encoding;
    source.literal = std::move(literal);
    source.fileOffset = text.fileOffset;
    const uint64_t stride = text.encoding == CrackmeLiteralEncoding::Utf16Le ? 2 : 1;
    const uint64_t delta = characterOffset > (std::numeric_limits<uint64_t>::max)() / stride
                         ? (std::numeric_limits<uint64_t>::max)()
                         : static_cast<uint64_t>(characterOffset) * stride;
    source.literalFileOffset = delta > (std::numeric_limits<uint64_t>::max)() - text.fileOffset
                             ? text.fileOffset : text.fileOffset + delta;
    source.textTruncated = text.truncated;
    if (input.offsetToVA) {
        source.addressValid = input.offsetToVA(source.fileOffset, source.address);
        source.literalAddressValid = input.offsetToVA(source.literalFileOffset,
                                                       source.literalAddress);
    }
    source.location = inOverlay(input, source.literalFileOffset)
                    ? CrackmeLiteralLocation::Overlay
                    : (source.literalAddressValid ? CrackmeLiteralLocation::Mapped
                                                  : CrackmeLiteralLocation::FileOnly);
    return source;
}

static CrackmeTriageLiteralSource makeTypedArgumentSource(
    const CrackmeTriageApiArgumentInput& argument,
    CrackmeLiteralRole role, std::string literal, size_t characterOffset) {
    CrackmeTriageLiteralSource source;
    source.role = role;
    source.encoding = argument.encodingValid ? argument.encoding
                                             : CrackmeLiteralEncoding::Ascii;
    source.literal = std::move(literal);
    source.address = argument.address;
    source.addressValid = argument.addressValid;
    source.fileOffset = argument.fileOffset;
    source.fileOffsetValid = false;

    const bool exactOffsetProvable = characterOffset == 0 || argument.encodingValid;
    if (exactOffsetProvable) {
        const uint64_t stride = argument.encoding == CrackmeLiteralEncoding::Utf16Le ? 2 : 1;
        if (characterOffset <= (std::numeric_limits<uint64_t>::max)() / stride) {
            const uint64_t delta = static_cast<uint64_t>(characterOffset) * stride;
            if (argument.addressValid &&
                delta <= (std::numeric_limits<uint64_t>::max)() - argument.address) {
                source.literalAddress = argument.address + delta;
                source.literalAddressValid = true;
            }
            if (argument.fileOffsetValid &&
                delta <= (std::numeric_limits<uint64_t>::max)() - argument.fileOffset) {
                source.literalFileOffset = argument.fileOffset + delta;
                source.fileOffsetValid = true;
            }
        }
    }
    source.location = argument.addressValid ? CrackmeLiteralLocation::Mapped
                                            : CrackmeLiteralLocation::FileOnly;
    return source;
}

static std::string endpointDisplay(const CrackmeTriageEndpoint& endpoint) {
    std::string host = endpoint.kind == CrackmeEndpointKind::IPv6
                     ? "[" + endpoint.host + "]" : endpoint.host;
    if (endpoint.portValid) host += ":" + std::to_string(endpoint.port);
    return endpoint.scheme.empty() ? host : endpoint.scheme + "://" + host;
}

static bool endpointEffectivePort(std::string_view scheme, uint16_t explicitPort,
                                  bool explicitPortValid, uint16_t& port) {
    if (explicitPortValid) {
        port = explicitPort;
        return true;
    }
    const std::string normalized = lower(scheme);
    if (normalized == "http" || normalized == "ws") {
        port = 80;
        return true;
    }
    if (normalized == "https" || normalized == "wss") {
        port = 443;
        return true;
    }
    return false;
}

static std::string endpointIdentity(std::string_view host, std::string_view scheme,
                                    uint16_t port, bool portValid) {
    std::string key(host);
    key.push_back('|');
    key += lower(scheme); // protocol remains identity even when ports coincide
    key.push_back('|');
    uint16_t effectivePort = 0;
    if (endpointEffectivePort(scheme, port, portValid, effectivePort))
        key += std::to_string(effectivePort);
    return key;
}

static std::string endpointIdentity(const CrackmeTriageEndpoint& endpoint) {
    return endpointIdentity(endpoint.host, endpoint.scheme,
                            endpoint.port, endpoint.portValid);
}

static bool pathPresent(const std::vector<std::string>& paths, std::string_view path) {
    const std::string folded = lower(path);
    for (const std::string& existing : paths)
        if (lower(existing) == folded) return true;
    return false;
}

static int confidenceRank(CrackmeTriageConfidence confidence) {
    return static_cast<int>(confidence);
}

static int relevanceCue(const CrackmeTriageEndpoint& endpoint) {
    int score = 0;
    const std::string h = lower(endpoint.host);
    constexpr std::string_view cues[] = {
        "license", "licence", "activate", "auth", "serial", "entitlement", "verify"
    };
    for (const std::string_view cue : cues)
        if (h.find(cue) != std::string::npos) score += 8;
    for (const std::string& path : endpoint.paths)
        if (interestingRoute(path)) score += 5;
    return score;
}

static void setEndpointLabels(CrackmeTriageEndpoint& endpoint,
                              bool codeReferenced, bool correlated) {
    if (correlated) endpoint.confidence = CrackmeTriageConfidence::High;
    else if (codeReferenced && endpoint.confidence == CrackmeTriageConfidence::Low)
        endpoint.confidence = CrackmeTriageConfidence::Medium;
    endpoint.confidenceLabel = CrackmeTriageConfidenceText(endpoint.confidence);
    if (correlated) {
        endpoint.honestyLabel =
            "bounded static correlation links this endpoint to an exact network API; "
            "individual rows distinguish same-function, call-neighborhood, and typed-argument evidence, "
            "and runtime contact is not proven";
    } else if (codeReferenced) {
        endpoint.honestyLabel =
            "the endpoint literal is referenced by code, but no network API was correlated; "
            "runtime contact is not proven";
    } else {
        endpoint.honestyLabel =
            "embedded literal only; it may be documentation or unused data and runtime contact is not proven";
    }
}

class FunctionOwnershipIndex {
public:
    bool build(const CrackmeTriageInput& input,
               CrackmeTriageCompleteness& completeness) {
        struct UnsortedRange { uint64_t start, end, size; size_t function; };
        const size_t count = (std::min)(input.functions.size(),
                                        input.limits.maxOwnershipFunctions);
        size_t retainedRanges = 0;
        bool rangeLimitNoted = false;
        auto noteRangeLimit = [&] {
            if (rangeLimitNoted) return;
            rangeLimitNoted = true;
            completeness.sourcesTruncated = true;
            markIncomplete(completeness, CrackmeTriageStopReason::SourceLimit,
                           "function-range ownership cap was reached; correlations are partial");
        };
        for (size_t i = 0; i < count; ++i) {
            if ((i & 0xffu) == 0 && cancelled(input)) return false;
            const auto& function = input.functions[i];
            auto add = [&](uint64_t start, uint64_t size) {
                if (retainedRanges >= input.limits.maxOwnershipRanges) {
                    noteRangeLimit();
                    return false;
                }
                uint64_t end = 0;
                if (size && checkedEnd(start, size, end)) {
                    ranges_.push_back({ start, end, size, i });
                    ++retainedRanges;
                }
                return true;
            };
            if (function.ranges.empty()) {
                if (!add(function.address, function.size)) break;
            } else {
                const size_t rangeCount = (std::min)(function.ranges.size(),
                                                      input.limits.maxRangesPerFunction);
                if (rangeCount != function.ranges.size()) noteRangeLimit();
                for (size_t rangeIndex = 0; rangeIndex < rangeCount; ++rangeIndex) {
                    if (!add(function.ranges[rangeIndex].address,
                             function.ranges[rangeIndex].size)) break;
                }
                if (retainedRanges >= input.limits.maxOwnershipRanges) break;
            }
        }
        std::sort(ranges_.begin(), ranges_.end(), [](const Range& a, const Range& b) {
            if (a.start != b.start) return a.start < b.start;
            if (a.size != b.size) return a.size < b.size;
            return a.function < b.function;
        });
        prefixMaxEnd_.resize(ranges_.size());
        uint64_t maxEnd = 0;
        for (size_t i = 0; i < ranges_.size(); ++i) {
            if ((i & 0x3ffu) == 0 && cancelled(input)) return false;
            maxEnd = (std::max)(maxEnd, ranges_[i].end);
            prefixMaxEnd_[i] = maxEnd;
        }
        return true;
    }

    size_t owner(uint64_t address) const {
        size_t pos = static_cast<size_t>(std::upper_bound(
            ranges_.begin(), ranges_.end(), address,
            [](uint64_t value, const Range& range) { return value < range.start; }) -
            ranges_.begin());
        size_t best = kNoIndex;
        uint64_t bestSize = (std::numeric_limits<uint64_t>::max)();
        while (pos) {
            --pos;
            const Range& range = ranges_[pos];
            if (range.start <= address && address < range.end &&
                (range.size < bestSize ||
                 (range.size == bestSize && range.function < best))) {
                best = range.function;
                bestSize = range.size;
            }
            if (!pos || prefixMaxEnd_[pos - 1] <= address) break;
        }
        return best;
    }

private:
    struct Range {
        uint64_t start = 0, end = 0, size = 0;
        size_t function = 0;
    };
    std::vector<Range> ranges_;
    std::vector<uint64_t> prefixMaxEnd_;
};

class BoundedCallAdjacency {
public:
    bool build(const CrackmeTriageInput& input) {
        maxDepth_ = input.limits.maxCallGraphDepth;
        const size_t count = (std::min)(input.callEdges.size(),
                                        input.limits.maxCallEdges);
        for (size_t i = 0; i < count; ++i) {
            if ((i & 0xffu) == 0 && cancelled(input)) return false;
            const auto& edge = input.callEdges[i];
            adjacency_[edge.caller].push_back(edge.callee);
            adjacency_[edge.callee].push_back(edge.caller);
        }
        for (auto& item : adjacency_) {
            auto& neighbors = item.second;
            std::sort(neighbors.begin(), neighbors.end());
            neighbors.erase(std::unique(neighbors.begin(), neighbors.end()),
                            neighbors.end());
        }
        return true;
    }

    bool distancesFrom(uint64_t from, const CrackmeTriageInput& input,
                       std::vector<std::pair<uint64_t, size_t>>& out) const {
        out.clear();
        out.push_back({ from, 0 });
        if (!maxDepth_) return true;
        std::vector<uint64_t> frontier{ from };
        std::unordered_set<uint64_t> visited{ from };
        for (size_t depth = 1; depth <= maxDepth_; ++depth) {
            std::vector<uint64_t> next;
            for (uint64_t node : frontier) {
                if (cancelled(input)) return false;
                const auto found = adjacency_.find(node);
                if (found == adjacency_.end()) continue;
                for (uint64_t neighbor : found->second) {
                    if (!visited.insert(neighbor).second) continue;
                    out.push_back({ neighbor, depth });
                    next.push_back(neighbor);
                }
            }
            if (next.empty()) break;
            frontier = std::move(next);
        }
        return true;
    }

    size_t distance(uint64_t from, uint64_t to,
                    const CrackmeTriageInput& input, bool& wasCancelled) const {
        std::vector<std::pair<uint64_t, size_t>> distances;
        if (!distancesFrom(from, input, distances)) {
            wasCancelled = true;
            return kNoIndex;
        }
        for (const auto& item : distances)
            if (item.first == to) return item.second;
        return kNoIndex;
    }

private:
    size_t maxDepth_ = 0;
    std::unordered_map<uint64_t, std::vector<uint64_t>> adjacency_;
};

static std::vector<uint64_t> sourcesFor(const CrackmeTriageInput& input,
                                        uint64_t target,
                                        CrackmeTriageCompleteness& completeness) {
    std::vector<uint64_t> out;
    if (!input.xrefs) return out;
    const std::vector<uint64_t>* sources = input.xrefs->sources(target);
    if (!sources) return out;
    const size_t kept = (std::min)(sources->size(), input.limits.maxXrefsPerTarget);
    out.assign(sources->begin(), sources->begin() + kept);
    if (kept != sources->size()) {
        completeness.sourcesTruncated = true;
        markIncomplete(completeness, CrackmeTriageStopReason::SourceLimit,
                       "per-target xref cap was reached; correlations are partial");
    }
    return out;
}

static void appendUnique(std::vector<uint64_t>& into, const std::vector<uint64_t>& values) {
    into.insert(into.end(), values.begin(), values.end());
    std::sort(into.begin(), into.end());
    into.erase(std::unique(into.begin(), into.end()), into.end());
}

static std::vector<OwnedReference>
findingReferences(const CrackmeTriageInput& input,
                  const std::vector<CrackmeTriageLiteralSource>& sources,
                  CrackmeTriageCompleteness& completeness,
                  const FunctionOwnershipIndex& ownership) {
    std::vector<uint64_t> references;
    for (const auto& source : sources) {
        if (cancelled(input)) { setCancelled(completeness); return {}; }
        if (source.addressValid)
            appendUnique(references, sourcesFor(input, source.address, completeness));
        if (source.literalAddressValid &&
            (!source.addressValid || source.literalAddress != source.address))
            appendUnique(references, sourcesFor(input, source.literalAddress, completeness));
    }
    std::vector<OwnedReference> out;
    out.reserve(references.size());
    for (uint64_t source : references) {
        if (cancelled(input)) { setCancelled(completeness); return out; }
        out.push_back({ source, ownership.owner(source) });
    }
    return out;
}

static void initializeStages(CrackmeTriageResult& result) {
    for (size_t i = 0; i < result.stages.size(); ++i) {
        auto& stage = result.stages[i];
        stage.stage = static_cast<NetworkTrailStage>(i);
        stage.confidence = CrackmeTriageConfidence::Low;
        stage.confidenceLabel = CrackmeTriageConfidenceText(stage.confidence);
        stage.honestyLabel = "no exact static API evidence was found for this stage";
    }
}

} // namespace

const char* CrackmeTriageConfidenceText(CrackmeTriageConfidence confidence) {
    switch (confidence) {
    case CrackmeTriageConfidence::Low:    return "Low";
    case CrackmeTriageConfidence::Medium: return "Medium";
    case CrackmeTriageConfidence::High:   return "High";
    }
    return "Unknown";
}

const char* CrackmeEndpointKindText(CrackmeEndpointKind kind) {
    switch (kind) {
    case CrackmeEndpointKind::Domain: return "Domain";
    case CrackmeEndpointKind::IPv4:   return "IPv4";
    case CrackmeEndpointKind::IPv6:   return "IPv6";
    }
    return "Unknown";
}

const char* CrackmeEndpointScopeText(CrackmeEndpointScope scope) {
    switch (scope) {
    case CrackmeEndpointScope::Unknown:        return "Unknown";
    case CrackmeEndpointScope::Loopback:       return "Loopback";
    case CrackmeEndpointScope::PrivateNetwork: return "Private";
    case CrackmeEndpointScope::PublicNetwork:  return "Public";
    }
    return "Unknown";
}

const char* CrackmeLiteralLocationText(CrackmeLiteralLocation location) {
    switch (location) {
    case CrackmeLiteralLocation::Mapped:   return "Mapped";
    case CrackmeLiteralLocation::FileOnly: return "File-only";
    case CrackmeLiteralLocation::Overlay:  return "Overlay";
    }
    return "Unknown";
}

const char* NetworkTrailStageText(NetworkTrailStage stage) {
    switch (stage) {
    case NetworkTrailStage::Endpoint: return "Endpoint";
    case NetworkTrailStage::Connect:  return "Connect";
    case NetworkTrailStage::Request:  return "Request";
    case NetworkTrailStage::Reply:    return "Reply";
    case NetworkTrailStage::Decision: return "Decision";
    case NetworkTrailStage::Count:    break;
    }
    return "Unknown";
}

const char* NetworkArtifactKindText(NetworkArtifactKind kind) {
    switch (kind) {
    case NetworkArtifactKind::Endpoint:       return "Endpoint";
    case NetworkArtifactKind::Route:          return "Route";
    case NetworkArtifactKind::Header:         return "HTTP header";
    case NetworkArtifactKind::Authentication: return "Authentication";
    case NetworkArtifactKind::License:        return "License";
    case NetworkArtifactKind::Validation:     return "Validation";
    case NetworkArtifactKind::Success:        return "Success";
    case NetworkArtifactKind::Failure:        return "Failure";
    case NetworkArtifactKind::ReplyMarker:    return "Reply marker";
    case NetworkArtifactKind::Algorithm:      return "Algorithm";
    }
    return "Unknown";
}

const char* NetworkReplyDecisionKindText(NetworkReplyDecisionKind kind) {
    switch (kind) {
    case NetworkReplyDecisionKind::DirectComparison: return "direct reply comparison";
    case NetworkReplyDecisionKind::ComparisonCall:   return "reply comparison call";
    }
    return "unknown";
}

NetworkTrailStage NetworkTrailStageForApi(NetworkStage stage) {
    switch (stage) {
    case NetworkStage::Resolve:
    case NetworkStage::Connect: return NetworkTrailStage::Connect;
    case NetworkStage::Request:
    case NetworkStage::Write:   return NetworkTrailStage::Request;
    case NetworkStage::Read:    return NetworkTrailStage::Reply;
    case NetworkStage::Count:   break;
    }
    return NetworkTrailStage::Connect;
}

const char* CrackmeTriageStopReasonText(CrackmeTriageStopReason reason) {
    switch (reason) {
    case CrackmeTriageStopReason::None:             return "complete";
    case CrackmeTriageStopReason::InvalidInput:     return "invalid input";
    case CrackmeTriageStopReason::Cancelled:        return "cancelled";
    case CrackmeTriageStopReason::ByteLimit:        return "byte limit";
    case CrackmeTriageStopReason::StringLimit:      return "string limit";
    case CrackmeTriageStopReason::EndpointLimit:    return "endpoint limit";
    case CrackmeTriageStopReason::RouteLimit:       return "route limit";
    case CrackmeTriageStopReason::ApiLimit:         return "API limit";
    case CrackmeTriageStopReason::CorrelationLimit: return "correlation limit";
    case CrackmeTriageStopReason::SourceLimit:      return "source/xref limit";
    }
    return "unknown";
}

CrackmeTriageResult RunCrackmeTriage(const CrackmeTriageInput& input) {
    CrackmeTriageResult result;
    initializeStages(result);
    auto stopNow = [&]() {
        if (!cancelled(input)) return false;
        setCancelled(result.completeness);
        return true;
    };

    std::vector<ExtractedString> strings = extractStrings(input, result.completeness);
    result.completeness.stringsExamined = strings.size();
    if (result.completeness.cancelled) return result;

    // host+port is the endpoint identity.  Schemes and routes are evidence on
    // that server rather than separate duplicate rows.
    std::unordered_map<std::string, size_t> endpointByKey;
    std::vector<bool> endpointPreReferenced;
    std::unordered_map<std::string, size_t> routeByKey;
    std::vector<NetworkArtifact> semanticArtifacts;
    auto automaticArtifactPriority = [](const NetworkArtifact& artifact) {
        switch (artifact.kind) {
        case NetworkArtifactKind::ReplyMarker: return 90;
        case NetworkArtifactKind::Validation:  return 80;
        case NetworkArtifactKind::Success:
        case NetworkArtifactKind::Failure:     return 70;
        case NetworkArtifactKind::Header:
            return lower(artifact.value).rfind("host:", 0) == 0 ? 65 : 55;
        case NetworkArtifactKind::Authentication: return 50;
        case NetworkArtifactKind::License:        return 45;
        default:                                  return 10;
        }
    };
    auto retainSemanticArtifact = [&](NetworkArtifact artifact) {
        const size_t cap = input.limits.maxArtifacts;
        if (semanticArtifacts.size() < cap) {
            semanticArtifacts.push_back(std::move(artifact));
            return;
        }
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "automatic semantic/header artifact candidate cap was reached");
        if (!cap) return;
        size_t victim = 0;
        int victimPriority = automaticArtifactPriority(semanticArtifacts[0]);
        for (size_t i = 1; i < semanticArtifacts.size(); ++i) {
            const int priority = automaticArtifactPriority(semanticArtifacts[i]);
            if (priority < victimPriority) {
                victim = i;
                victimPriority = priority;
            }
        }
        if (automaticArtifactPriority(artifact) > victimPriority)
            semanticArtifacts[victim] = std::move(artifact);
    };
    auto endpointKey = [](const CrackmeTriageEndpoint& endpoint) {
        return endpointIdentity(endpoint);
    };
    auto sourceHasCodeReference = [&](const CrackmeTriageLiteralSource& source) {
        if (!input.xrefs) return false;
        auto has = [&](bool valid, uint64_t address) {
            if (!valid) return false;
            const std::vector<uint64_t>* refs = input.xrefs->sources(address);
            return refs && !refs->empty();
        };
        return has(source.addressValid, source.address) ||
               has(source.literalAddressValid, source.literalAddress);
    };
    auto retainEndpointCandidate = [&](std::string key,
                                       CrackmeTriageEndpoint endpoint,
                                       bool codeReferenced) {
        if (result.endpoints.size() < input.limits.maxEndpointCandidates) {
            const size_t index = result.endpoints.size();
            result.endpoints.push_back(std::move(endpoint));
            endpointPreReferenced.push_back(codeReferenced);
            endpointByKey.emplace(std::move(key), index);
            return index;
        }

        result.completeness.endpointsTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::EndpointLimit,
                       "endpoint candidate cap was reached; lower-priority candidates were omitted");
        if (!codeReferenced) return kNoIndex;

        // Preserve code-referenced candidates over embedded-only strings even
        // when the referenced host appears after the hard candidate cap.
        size_t victim = kNoIndex;
        for (size_t i = 0; i < result.endpoints.size(); ++i) {
            if (endpointPreReferenced[i]) continue;
            if (victim == kNoIndex) { victim = i; continue; }
            const auto& candidate = result.endpoints[i];
            const auto& current = result.endpoints[victim];
            const int candidateCue = relevanceCue(candidate);
            const int currentCue = relevanceCue(current);
            if (candidateCue < currentCue ||
                (candidateCue == currentCue &&
                 confidenceRank(candidate.confidence) < confidenceRank(current.confidence)) ||
                (candidateCue == currentCue && candidate.confidence == current.confidence &&
                 candidate.display > current.display))
                victim = i;
        }
        if (victim == kNoIndex) return kNoIndex;
        endpointByKey.erase(endpointKey(result.endpoints[victim]));
        result.endpoints[victim] = std::move(endpoint);
        endpointPreReferenced[victim] = true;
        endpointByKey.emplace(std::move(key), victim);
        return victim;
    };
    for (size_t stringIndex = 0; stringIndex < strings.size(); ++stringIndex) {
        if ((stringIndex & 0x3ffu) == 0 && cancelled(input)) {
            setCancelled(result.completeness);
            return result;
        }
        const ExtractedString& text = strings[stringIndex];
        for (NetworkArtifactKind kind : semanticArtifactKinds(text.text)) {
            NetworkArtifact artifact;
            artifact.kind = kind;
            artifact.value = text.text;
            artifact.sources.push_back(makeSource(input, text, CrackmeLiteralRole::Evidence,
                                                  text.text, 0));
            artifact.confidence = CrackmeTriageConfidence::Low;
            // Authentication/license words can describe request material just
            // as easily as a validation result.  A separate validation,
            // success/failure, reply-marker, or explicit typed decision row is
            // required before this automatic text evidence may support the
            // Decision stage.
            artifact.decisionEligible =
                kind != NetworkArtifactKind::Authentication &&
                kind != NetworkArtifactKind::License;
            artifact.confidenceLabel = CrackmeTriageConfidenceText(artifact.confidence);
            artifact.honestyLabel =
                "embedded validation/authentication text; execution and relation to a server reply are unproven";
            retainSemanticArtifact(std::move(artifact));
        }
        const std::optional<ParsedHeader> header = parseHttpHeader(text.text);
        if (header) {
            NetworkArtifact artifact;
            artifact.kind = NetworkArtifactKind::Header;
            artifact.value = header->name + ": " + header->value;
            artifact.sources.push_back(makeSource(
                input, text, CrackmeLiteralRole::Evidence,
                text.text.substr(header->offset, header->length), header->offset));
            artifact.decisionEligible = false;
            artifact.confidence = CrackmeTriageConfidence::Medium;
            artifact.confidenceLabel = CrackmeTriageConfidenceText(artifact.confidence);
            artifact.honestyLabel =
                "embedded HTTP header literal; request construction and runtime transmission are unproven";
            retainSemanticArtifact(std::move(artifact));
        }

        std::vector<ParsedEndpoint> parsedEndpoints = parseEndpoints(text.text);
        if (header && header->name == "host") {
            ParsedEndpoint parsed;
            parsed.offset = header->valueOffset;
            parsed.length = header->value.size();
            parsed.role = CrackmeLiteralRole::Host;
            if (parseHostPort(header->value, parsed.host, parsed.port,
                              parsed.portValid, parsed.kind) &&
                !metadataHost(parsed.host))
                parsedEndpoints.push_back(std::move(parsed));
        }
        for (ParsedEndpoint& parsed : parsedEndpoints) {
            CrackmeTriageLiteralSource parsedSource = makeSource(
                input, text, parsed.role,
                text.text.substr(parsed.offset, parsed.length), parsed.offset);
            const bool sourceReferenced = sourceHasCodeReference(parsedSource);
            std::string key = endpointIdentity(parsed.host, parsed.scheme,
                                               parsed.port, parsed.portValid);
            auto found = endpointByKey.find(key);
            size_t index = kNoIndex;
            if (found == endpointByKey.end()) {
                CrackmeTriageEndpoint endpoint;
                endpoint.host = parsed.host;
                endpoint.scheme = parsed.scheme;
                endpoint.port = parsed.port;
                endpoint.portValid = parsed.portValid;
                endpoint.kind = parsed.kind;
                endpoint.scope = classifyScope(endpoint.host, endpoint.kind);
                if (!parsed.path.empty()) endpoint.paths.push_back(parsed.path);
                endpoint.confidence = parsed.role == CrackmeLiteralRole::Url
                                    ? CrackmeTriageConfidence::Medium
                                    : CrackmeTriageConfidence::Low;
                if (relevanceCue(endpoint) > 0)
                    endpoint.confidence = CrackmeTriageConfidence::Medium;
                setEndpointLabels(endpoint, false, false);
                endpoint.display = endpointDisplay(endpoint);
                index = retainEndpointCandidate(std::move(key), std::move(endpoint),
                                                sourceReferenced);
            } else {
                index = found->second;
                auto& endpoint = result.endpoints[index];
                if (endpoint.scheme.empty() && !parsed.scheme.empty()) endpoint.scheme = parsed.scheme;
                if (!parsed.path.empty() && !pathPresent(endpoint.paths, parsed.path))
                    endpoint.paths.push_back(parsed.path);
                if (parsed.role == CrackmeLiteralRole::Url &&
                    endpoint.confidence == CrackmeTriageConfidence::Low)
                    endpoint.confidence = CrackmeTriageConfidence::Medium;
                endpoint.display = endpointDisplay(endpoint);
                setEndpointLabels(endpoint, false, false);
                endpointPreReferenced[index] = endpointPreReferenced[index] ||
                                               sourceReferenced;
            }
            if (index != kNoIndex) {
                auto& sources = result.endpoints[index].sources;
                if (sources.size() < input.limits.maxSourcesPerFinding) {
                    sources.push_back(std::move(parsedSource));
                } else {
                    result.completeness.sourcesTruncated = true;
                    markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                                   "per-endpoint source cap was reached");
                }
            }
        }

        for (auto& parsedRoute : parseRoutes(text.text)) {
            const std::string key = lower(parsedRoute.first);
            auto found = routeByKey.find(key);
            size_t index = kNoIndex;
            if (found == routeByKey.end()) {
                if (result.routes.size() >= input.limits.maxRoutes) {
                    result.completeness.routesTruncated = true;
                    markIncomplete(result.completeness, CrackmeTriageStopReason::RouteLimit,
                                   "route cap was reached; later route literals were omitted");
                    continue;
                }
                index = result.routes.size();
                CrackmeTriageRoute route;
                route.path = parsedRoute.first;
                result.routes.push_back(std::move(route));
                routeByKey.emplace(key, index);
            } else index = found->second;
            auto& sources = result.routes[index].sources;
            if (sources.size() < input.limits.maxSourcesPerFinding) {
                sources.push_back(makeSource(input, text, CrackmeLiteralRole::Route,
                                             parsedRoute.first, parsedRoute.second));
            } else {
                result.completeness.sourcesTruncated = true;
                markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                               "per-route source cap was reached");
            }
        }
    }

    struct DirectArgumentLink {
        std::string endpointKey;
        size_t callInputIndex = 0;
        uint64_t argumentAddress = 0;
        bool argumentAddressValid = false;
    };
    std::vector<DirectArgumentLink> directArgumentLinks;
    std::vector<NetworkArtifact> typedRequestArtifacts;
    const size_t typedCallCount = (std::min)(input.apiCalls.size(),
                                             input.limits.maxTypedCalls);
    if (!input.apiCallsComplete) {
        result.completeness.returnFlowsTruncated = true;
        result.completeness.replyDecisionFlowsTruncated = true;
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "typed API-call adapter input was truncated");
    }
    if (typedCallCount != input.apiCalls.size()) {
        result.completeness.returnFlowsTruncated = true;
        result.completeness.replyDecisionFlowsTruncated = true;
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "typed API-call input cap was reached");
    }
    for (size_t callIndex = 0; callIndex < typedCallCount; ++callIndex) {
        if (stopNow()) return result;
        const auto& call = input.apiCalls[callIndex];
        const auto match = LookupNetworkApi(call.dll, call.name);
        if (!match) continue;
        if (call.replyDecisionAnalysisAttempted && !call.replyDecisionsComplete) {
            result.completeness.replyDecisionFlowsTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                call.replyDecisionIncompleteReason.empty()
                    ? "bounded reply-content comparison analysis was incomplete"
                    : call.replyDecisionIncompleteReason);
        }
        auto isEndpointArgument = [&](size_t ordinal) {
            const std::string& api = match->normalizedName;
            if ((api == "winhttpconnect" || api == "internetconnect") && ordinal == 1)
                return true;
            if ((api == "getaddrinfo" || api == "getaddrinfoex" ||
                 api == "gethostbyname" || api == "dnsquery") && ordinal == 0)
                return true;
            if ((api == "winhttpgetproxyforurl" || api == "internetopenurl" ||
                 api == "urldownloadtofile" || api == "urldownloadtocachefile" ||
                 api == "urlopenstream" || api == "urlopenpullstream" ||
                 api == "urlopenblockingstream") && ordinal == 1)
                return true;
            return false;
        };
        auto retainTypedRequestArtifact = [&](NetworkArtifact artifact) {
            if (typedRequestArtifacts.size() < input.limits.maxArtifacts) {
                typedRequestArtifacts.push_back(std::move(artifact));
                return;
            }
            result.completeness.sourcesTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "typed request-artifact candidate cap was reached");
        };
        const size_t argumentCount = (std::min)(call.arguments.size(),
                                                 input.limits.maxArgumentsPerCall);
        if (argumentCount != call.arguments.size()) {
            result.completeness.sourcesTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "per-call typed argument cap was reached");
        }
        uint16_t connectPort = 0;
        bool connectPortValid = false;
        if (match->normalizedName == "winhttpconnect" ||
            match->normalizedName == "internetconnect") {
            for (size_t i = 0; i < argumentCount; ++i) {
                const auto& candidate = call.arguments[i];
                if (candidate.ordinal != 2 || !candidate.immediateValid ||
                    candidate.immediate > 0xffffu)
                    continue;
                connectPort = static_cast<uint16_t>(candidate.immediate);
                connectPortValid = true; // zero is a validity-bearing typed value
                break;
            }
        }
        for (size_t argumentIndex = 0; argumentIndex < argumentCount; ++argumentIndex) {
            if (stopNow()) return result;
            const auto& argument = call.arguments[argumentIndex];
            const size_t literalBytes = (std::min)(argument.literal.size(),
                                                   input.limits.maxStringBytes);
            if (literalBytes != argument.literal.size()) {
                result.completeness.sourcesTruncated = true;
                markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                               "typed argument literal byte cap was reached");
            }
            const std::string_view literal(argument.literal.data(), literalBytes);
            if (!isEndpointArgument(argument.ordinal)) {
                const std::string& api = match->normalizedName;
                const bool routeArgument =
                    (api == "winhttpopenrequest" || api == "httpopenrequest") &&
                    argument.ordinal == 2;
                const bool headerArgument =
                    ((api == "winhttpaddrequestheaders" ||
                      api == "httpaddrequestheaders") && argument.ordinal == 1) ||
                    ((api == "winhttpsendrequest" || api == "httpsendrequest") &&
                     argument.ordinal == 1) ||
                    (api == "internetopenurl" && argument.ordinal == 2);
                const bool userAgentArgument =
                    (api == "winhttpopen" || api == "internetopen") &&
                    argument.ordinal == 0;
                if (routeArgument) {
                    for (const auto& route : parseRoutes(literal)) {
                        NetworkArtifact artifact;
                        artifact.kind = NetworkArtifactKind::Route;
                        artifact.value = route.first;
                        artifact.sources.push_back(makeTypedArgumentSource(
                            argument, CrackmeLiteralRole::Route,
                            route.first, route.second));
                        artifact.functionAddress = call.functionAddress;
                        artifact.functionAddressValid = call.functionAddressValid;
                        artifact.decisionEligible = false;
                        artifact.confidence = CrackmeTriageConfidence::High;
                        artifact.confidenceLabel =
                            CrackmeTriageConfidenceText(artifact.confidence);
                        artifact.honestyLabel =
                            "typed request-path argument; server association and runtime transmission are unproven";
                        retainTypedRequestArtifact(std::move(artifact));
                    }
                }
                if (headerArgument || userAgentArgument) {
                    const std::optional<ParsedHeader> header =
                        headerArgument ? parseHttpHeader(literal) : std::nullopt;
                    if (header || userAgentArgument) {
                        NetworkArtifact artifact;
                        artifact.kind = NetworkArtifactKind::Header;
                        artifact.value = header
                            ? header->name + ": " + header->value
                            : "user-agent: " + std::string(literal);
                        artifact.sources.push_back(makeTypedArgumentSource(
                            argument, CrackmeLiteralRole::Evidence,
                            header ? std::string(literal.substr(header->offset,
                                                                 header->length))
                                   : std::string(literal),
                            header ? header->offset : 0));
                        artifact.functionAddress = call.functionAddress;
                        artifact.functionAddressValid = call.functionAddressValid;
                        artifact.decisionEligible = false;
                        artifact.confidence = CrackmeTriageConfidence::High;
                        artifact.confidenceLabel =
                            CrackmeTriageConfidenceText(artifact.confidence);
                        artifact.honestyLabel =
                            "typed request-header argument; target host and runtime transmission are unproven";
                        retainTypedRequestArtifact(std::move(artifact));
                    }
                }
                continue;
            }
            for (ParsedEndpoint parsed : parseEndpoints(literal)) {
                if (metadataHost(parsed.host)) continue;
                if (!parsed.portValid && connectPortValid &&
                    (match->normalizedName == "winhttpconnect" ||
                     match->normalizedName == "internetconnect")) {
                    parsed.port = connectPort;
                    parsed.portValid = true;
                }
                std::string key = endpointIdentity(parsed.host, parsed.scheme,
                                                   parsed.port, parsed.portValid);
                size_t endpointIndex = kNoIndex;
                if (const auto found = endpointByKey.find(key); found != endpointByKey.end()) {
                    endpointIndex = found->second;
                    endpointPreReferenced[endpointIndex] = true;
                } else {
                    // A Connect API has transport coordinates but no URL scheme.
                    // Upgrade the matching bare literal first; the cheap byte
                    // scan necessarily saw that same hostname before typed CFG
                    // annotation recovered its port.
                    if (parsed.scheme.empty() && parsed.portValid) {
                        for (size_t i = 0; i < result.endpoints.size(); ++i) {
                            CrackmeTriageEndpoint& candidate = result.endpoints[i];
                            if (candidate.host == parsed.host &&
                                candidate.scheme.empty() && !candidate.portValid) {
                                endpointByKey.erase(endpointIdentity(candidate));
                                candidate.port = parsed.port;
                                candidate.portValid = true;
                                candidate.display = endpointDisplay(candidate);
                                endpointByKey[endpointIdentity(candidate)] = i;
                                endpointIndex = i;
                                endpointPreReferenced[i] = true;
                                break;
                            }
                        }
                    }
                    // Otherwise prefer an already discovered URL authority with
                    // the same effective transport before creating a bare row.
                    if (endpointIndex == kNoIndex &&
                        parsed.scheme.empty() && parsed.portValid) {
                        for (size_t i = 0; i < result.endpoints.size(); ++i) {
                            uint16_t effective = 0;
                            if (result.endpoints[i].host == parsed.host &&
                                endpointEffectivePort(result.endpoints[i].scheme,
                                                      result.endpoints[i].port,
                                                      result.endpoints[i].portValid,
                                                      effective) &&
                                effective == parsed.port) {
                                endpointIndex = i;
                                endpointPreReferenced[i] = true;
                                break;
                            }
                        }
                    }
                }
                if (endpointIndex == kNoIndex &&
                    endpointByKey.find(key) == endpointByKey.end()) {
                    CrackmeTriageEndpoint endpoint;
                    endpoint.host = parsed.host;
                    endpoint.scheme = parsed.scheme;
                    endpoint.port = parsed.port;
                    endpoint.portValid = parsed.portValid;
                    endpoint.kind = parsed.kind;
                    endpoint.scope = classifyScope(endpoint.host, endpoint.kind);
                    endpoint.confidence = CrackmeTriageConfidence::High;
                    if (!parsed.path.empty()) endpoint.paths.push_back(parsed.path);
                    endpoint.display = endpointDisplay(endpoint);
                    setEndpointLabels(endpoint, true, true);
                    endpointIndex = retainEndpointCandidate(
                        std::move(key), std::move(endpoint), true);
                }
                if (endpointIndex == kNoIndex) continue;
                auto& endpoint = result.endpoints[endpointIndex];
                if (!parsed.path.empty() && !pathPresent(endpoint.paths, parsed.path))
                    endpoint.paths.push_back(parsed.path);
                if (endpoint.sources.size() < input.limits.maxSourcesPerFinding) {
                    endpoint.sources.push_back(makeTypedArgumentSource(
                        argument, parsed.role,
                        std::string(literal.substr(parsed.offset, parsed.length)),
                        parsed.offset));
                }
                directArgumentLinks.push_back({ endpointIdentity(endpoint),
                                                callIndex, argument.address,
                                                argument.addressValid });
            }
        }
    }

    auto appendArtifact = [&](NetworkArtifact artifact) {
        if (result.artifacts.size() >= input.limits.maxArtifacts) {
            result.completeness.sourcesTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "network artifact evidence row cap was reached");
            return false;
        }
        result.artifacts.push_back(std::move(artifact));
        return true;
    };
    // Explicit typed evidence is appended first.  Automatic string/header rows
    // are held in a bounded priority reservoir until typed decisions,
    // algorithms, and API-result observations have claimed their budget.
    const size_t decisionCount = (std::min)(input.decisions.size(),
                                            input.limits.maxDecisionInputs);
    if (!input.decisionsComplete) {
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "typed decision adapter input was truncated");
    }
    if (decisionCount != input.decisions.size()) {
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "decision evidence input cap was reached");
    }
    for (size_t i = 0; i < decisionCount; ++i) {
        if (stopNow()) return result;
        const auto& decision = input.decisions[i];
        NetworkArtifact artifact;
        artifact.kind = decision.kind;
        artifact.value = decision.text;
        artifact.functionAddress = decision.functionAddress;
        artifact.functionAddressValid = decision.functionAddressValid;
        artifact.replyLinked = decision.consumesNetworkReply;
        artifact.confidence = decision.consumesNetworkReply
                            ? CrackmeTriageConfidence::High
                            : CrackmeTriageConfidence::Medium;
        artifact.confidenceLabel = CrackmeTriageConfidenceText(artifact.confidence);
        artifact.honestyLabel = decision.consumesNetworkReply
            ? "typed evidence reports that this decision consumes a network reply; runtime execution is unproven"
            : "typed validation evidence; relation to a network reply is not proven";
        if (decision.addressValid) {
            CrackmeTriageLiteralSource source;
            source.role = CrackmeLiteralRole::Evidence;
            source.literal = decision.text;
            source.location = CrackmeLiteralLocation::Mapped;
            source.address = decision.address;
            source.literalAddress = decision.address;
            source.addressValid = true;
            source.literalAddressValid = true;
            source.fileOffsetValid = false;
            artifact.sources.push_back(std::move(source));
        }
        if (!appendArtifact(std::move(artifact))) break;
    }
    const size_t algorithmCount = (std::min)(input.algorithms.size(),
                                             input.limits.maxAlgorithmInputs);
    if (!input.algorithmsComplete) {
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "algorithm adapter input was truncated");
    }
    if (algorithmCount != input.algorithms.size()) {
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "algorithm evidence input cap was reached");
    }
    for (size_t i = 0; i < algorithmCount; ++i) {
        if (stopNow()) return result;
        const auto& algorithm = input.algorithms[i];
        NetworkArtifact artifact;
        artifact.kind = NetworkArtifactKind::Algorithm;
        artifact.value = algorithm.name;
        if (!algorithm.category.empty()) artifact.value += " (" + algorithm.category + ")";
        artifact.functionAddress = algorithm.functionAddress;
        artifact.functionAddressValid = algorithm.functionAddressValid;
        artifact.confidence = CrackmeTriageConfidence::Medium;
        artifact.confidenceLabel = CrackmeTriageConfidenceText(artifact.confidence);
        artifact.honestyLabel = algorithm.evidence.empty()
            ? "algorithm finding near validation code; reply-to-decision flow is unproven"
            : algorithm.evidence;
        if (algorithm.addressValid || algorithm.fileOffsetValid) {
            CrackmeTriageLiteralSource source;
            source.role = CrackmeLiteralRole::Evidence;
            source.literal = artifact.value;
            source.address = algorithm.address;
            source.literalAddress = algorithm.address;
            source.addressValid = algorithm.addressValid;
            source.literalAddressValid = algorithm.addressValid;
            source.fileOffset = algorithm.fileOffset;
            source.literalFileOffset = algorithm.fileOffset;
            source.fileOffsetValid = algorithm.fileOffsetValid;
            source.location = algorithm.addressValid
                            ? CrackmeLiteralLocation::Mapped
                            : CrackmeLiteralLocation::FileOnly;
            artifact.sources.push_back(std::move(source));
        }
        if (!appendArtifact(std::move(artifact))) break;
    }
    std::vector<NetworkArtifact> routeArtifacts;
    routeArtifacts.reserve(result.routes.size());
    for (const auto& route : result.routes) {
        if (stopNow()) return result;
        NetworkArtifact artifact;
        artifact.kind = NetworkArtifactKind::Route;
        artifact.value = route.path;
        artifact.sources = route.sources;
        if (artifact.sources.size() > input.limits.maxReferencesPerArtifact) {
            artifact.sources.resize(input.limits.maxReferencesPerArtifact);
            result.completeness.sourcesTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "artifact reference cap was reached");
        }
        artifact.confidence = CrackmeTriageConfidence::Low;
        artifact.confidenceLabel = CrackmeTriageConfidenceText(artifact.confidence);
        artifact.honestyLabel =
            "embedded request-route literal; its server and runtime use are unproven";
        routeArtifacts.push_back(std::move(artifact));
    }

    const size_t importCount = (std::min)(input.imports.size(), input.limits.maxImports);
    if (!input.importsComplete) {
        result.completeness.apisTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::ApiLimit,
                       "import adapter input was truncated; API-stage evidence is partial");
    }
    if (importCount != input.imports.size()) {
        result.completeness.apisTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::ApiLimit,
                       "import input cap was reached; API-stage evidence is partial");
    }
    for (size_t i = 0; i < importCount; ++i) {
        if ((i & 0x3ffu) == 0 && cancelled(input)) {
            setCancelled(result.completeness);
            return result;
        }
        const auto match = LookupNetworkApi(input.imports[i].dll, input.imports[i].name);
        if (!match) continue;
        if (result.apis.size() >= input.limits.maxApis) {
            result.completeness.apisTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::ApiLimit,
                           "recognized network API cap was reached");
            break;
        }
        CrackmeTriageApiEvidence api;
        api.dll = match->dll;
        api.importName = input.imports[i].name;
        api.canonicalName = match->canonicalName;
        api.family = match->family;
        api.stage = match->stage;
        api.lifecycle = match->lifecycle;
        api.address = input.imports[i].address;
        api.addressValid = input.imports[i].addressValid;
        if (api.addressValid)
            api.callsites = sourcesFor(input, api.address, result.completeness);
        result.apis.push_back(std::move(api));
    }

    // Typed observations supplement (and can exist without) an import-table
    // address.  Fold identical APIs together while retaining bounded callsites.
    std::vector<size_t> typedCallApiIndex(typedCallCount, kNoIndex);
    for (size_t callIndex = 0; callIndex < typedCallCount; ++callIndex) {
        if (stopNow()) return result;
        const auto& call = input.apiCalls[callIndex];
        const auto match = LookupNetworkApi(call.dll, call.name);
        if (!match) continue;
        size_t apiIndex = kNoIndex;
        for (size_t i = 0; i < result.apis.size(); ++i) {
            if (result.apis[i].dll == match->dll &&
                result.apis[i].canonicalName == match->canonicalName) {
                apiIndex = i;
                break;
            }
        }
        if (apiIndex == kNoIndex) {
            if (result.apis.size() >= input.limits.maxApis) {
                result.completeness.apisTruncated = true;
                markIncomplete(result.completeness, CrackmeTriageStopReason::ApiLimit,
                               "typed network API evidence exceeded the API cap");
                break;
            }
            CrackmeTriageApiEvidence api;
            api.dll = match->dll;
            api.importName = call.name;
            api.canonicalName = match->canonicalName;
            api.family = match->family;
            api.stage = match->stage;
            api.lifecycle = match->lifecycle;
            apiIndex = result.apis.size();
            result.apis.push_back(std::move(api));
        }
        typedCallApiIndex[callIndex] = apiIndex;
        if (call.callsiteValid) {
            auto& sites = result.apis[apiIndex].callsites;
            if (sites.size() < input.limits.maxXrefsPerTarget)
                sites.push_back(call.callsite);
            else {
                result.completeness.sourcesTruncated = true;
                markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                               "typed API callsite cap was reached");
            }
            std::sort(sites.begin(), sites.end());
            sites.erase(std::unique(sites.begin(), sites.end()), sites.end());
        }
        if (result.returnFlows.size() < input.limits.maxReturnFlows) {
            NetworkReturnFlow flow;
            flow.apiIndex = apiIndex;
            flow.apiIndexValid = true;
            flow.callsite = call.callsite;
            flow.callsiteValid = call.callsiteValid;
            flow.functionAddress = call.functionAddress;
            flow.functionAddressValid = call.functionAddressValid;
            flow.functionName = call.functionName;
            flow.returnValueUseKnown = call.returnValueUseKnown;
            flow.returnValueUsed = call.returnValueUsed;
            flow.useKind = call.returnUseKind;
            flow.useAddress = call.returnUseAddress;
            flow.useAddressValid = call.returnUseAddressValid;
            flow.useInstruction = call.returnUseInstruction;
            flow.useSummary = call.returnUseSummary;
            flow.resultInfluencesDecision = call.resultInfluencesDecision;
            flow.decisionAddress = call.decisionAddress;
            flow.decisionAddressValid = call.decisionAddressValid;
            flow.decisionTarget = call.decisionTarget;
            flow.decisionTargetValid = call.decisionTargetValid;
            flow.decisionInstruction = call.decisionInstruction;
            flow.evidence = call.returnUseEvidence;
            flow.continuationAddress = call.continuationAddress;
            flow.continuationAddressValid = call.continuationAddressValid;
            flow.continuationSignature = call.continuationSignature;
            flow.continuationFileOffset = call.continuationFileOffset;
            flow.continuationFileOffsetValid =
                call.continuationFileOffsetValid;
            flow.lineageAnalysisAttempted =
                call.returnLineageAnalysisAttempted;
            flow.lineageComplete = call.returnLineageComplete;
            flow.lineageIncompleteReason =
                call.returnLineageIncompleteReason;
            auto markLineageTruncated = [&](std::string_view reason) {
                flow.lineageComplete = false;
                if (flow.lineageIncompleteReason.empty())
                    flow.lineageIncompleteReason.assign(reason);
                else if (flow.lineageIncompleteReason.find(reason) ==
                         std::string::npos)
                    flow.lineageIncompleteReason += "; " +
                        std::string(reason);
                result.completeness.returnLineageTruncated = true;
                result.completeness.sourcesTruncated = true;
                markIncomplete(result.completeness,
                    CrackmeTriageStopReason::SourceLimit,
                    "network return-lineage decision/hop cap was reached");
            };
            const size_t decisionCount = (std::min)(
                call.returnDecisions.size(),
                input.limits.maxReturnDecisionsPerFlow);
            flow.decisions.reserve(decisionCount);
            for (size_t decisionIndex = 0;
                 decisionIndex < decisionCount; ++decisionIndex) {
                CrackmeTriageReturnDecisionInput decision =
                    call.returnDecisions[decisionIndex];
                if (decision.hops.size() >
                    input.limits.maxReturnProvenanceHops) {
                    decision.hops.resize(
                        input.limits.maxReturnProvenanceHops);
                    markLineageTruncated(
                        "return provenance hop cap retained the earliest hops");
                }
                flow.decisions.push_back(std::move(decision));
            }
            if (decisionCount < call.returnDecisions.size())
                markLineageTruncated(
                    "return decision cap retained the earliest terminal checks");
            float retainedConfidence = call.returnUseConfidence;
            for (const CrackmeTriageReturnDecisionInput& decision :
                 flow.decisions)
                retainedConfidence = (std::max)(retainedConfidence,
                                                 decision.confidence);
            flow.confidence = retainedConfidence >= 0.75f
                            ? CrackmeTriageConfidence::High
                            : retainedConfidence >= 0.5f
                            ? CrackmeTriageConfidence::Medium
                            : CrackmeTriageConfidence::Low;
            flow.confidenceLabel = CrackmeTriageConfidenceText(flow.confidence);
            if (!flow.decisions.empty()) {
                flow.honestyLabel = flow.lineageComplete
                    ? "bounded scalar provenance follows the documented API status/value through copies, direct helpers, and returns to a comparison branch; reply content and runtime execution remain unproven"
                    : "partial bounded scalar provenance reaches a comparison branch; omitted aliases/helpers are disclosed and reply content remains unproven";
            } else if (flow.lineageAnalysisAttempted) {
                flow.honestyLabel = flow.lineageComplete
                    ? "bounded scalar provenance found no terminal comparison branch; this does not prove the API status/value is unused"
                    : "partial bounded scalar provenance found no retained terminal branch before a disclosed alias/helper/state cap";
            } else if (!flow.returnValueUseKnown) {
                flow.honestyLabel =
                    "no return-register use was established inside the bounded annotation window; absence is not proven";
            } else if (flow.resultInfluencesDecision) {
                flow.honestyLabel =
                    "bounded local evidence links the API status/value to this branch; it does not prove that reply-buffer content was validated";
            } else {
                flow.honestyLabel =
                    "bounded local first-use evidence; copied values, output buffers, and interprocedural uses are not followed";
            }
            result.returnFlows.push_back(std::move(flow));
        } else {
            result.completeness.returnFlowsTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "network return-flow result cap was reached");
        }

        // Reply-content comparisons are separate from transport-status return
        // handling.  Accept only exact Read APIs and catalog-declared payload or
        // header output arguments so an adapter cannot promote an arbitrary
        // branch to a Decision stage.
        const auto returnContract = LookupNetworkApiReturnContract(
            match->dll, match->canonicalName);
        for (const CrackmeTriageReplyDecisionInput& reply : call.replyDecisions) {
            bool catalogedContentOutput = false;
            if (match->stage == NetworkStage::Read && returnContract) {
                for (uint8_t outputIndex = 0;
                     outputIndex < returnContract->outParameterCount; ++outputIndex) {
                    const NetworkApiOutParameter& output =
                        returnContract->outParameters[outputIndex];
                    if (output.argumentIndex == reply.outputArgumentIndex &&
                        (output.role == NetworkOutParameterRole::PayloadBuffer ||
                         output.role == NetworkOutParameterRole::HeaderBuffer)) {
                        catalogedContentOutput = true;
                        break;
                    }
                }
            }
            if (!catalogedContentOutput || !reply.comparisonAddressValid) continue;
            if (result.replyDecisionFlows.size() >=
                input.limits.maxReplyDecisionFlows) {
                result.completeness.replyDecisionFlowsTruncated = true;
                markIncomplete(result.completeness,
                    CrackmeTriageStopReason::SourceLimit,
                    "reply-content comparison flow cap was reached");
                break;
            }
            NetworkReplyDecisionFlow flow;
            flow.apiIndex = apiIndex;
            flow.apiIndexValid = true;
            flow.callsite = call.callsite;
            flow.callsiteValid = call.callsiteValid;
            flow.functionAddress = call.functionAddress;
            flow.functionAddressValid = call.functionAddressValid;
            flow.functionName = call.functionName;
            flow.kind = reply.kind;
            flow.outputArgumentIndex = reply.outputArgumentIndex;
            flow.outputRole = reply.outputRole;
            flow.outputExpression = reply.outputExpression;
            flow.comparisonAddress = reply.comparisonAddress;
            flow.comparisonAddressValid = reply.comparisonAddressValid;
            flow.comparisonInstruction = reply.comparisonInstruction;
            flow.comparisonSignature = reply.comparisonSignature;
            flow.comparisonSummary = reply.comparisonSummary;
            flow.expectedValue = reply.expectedValue;
            flow.decisionAddress = reply.decisionAddress;
            flow.decisionAddressValid = reply.decisionAddressValid;
            flow.decisionTarget = reply.decisionTarget;
            flow.decisionTargetValid = reply.decisionTargetValid;
            flow.fallthroughAddress = reply.fallthroughAddress;
            flow.fallthroughAddressValid = reply.fallthroughAddressValid;
            flow.decisionInstruction = reply.decisionInstruction;
            flow.decisionSignature = reply.decisionSignature;
            flow.takenPathSummary = reply.takenPathSummary;
            flow.fallthroughPathSummary = reply.fallthroughPathSummary;
            flow.matchAddress = reply.matchAddress;
            flow.matchAddressValid = reply.matchAddressValid;
            flow.mismatchAddress = reply.mismatchAddress;
            flow.mismatchAddressValid = reply.mismatchAddressValid;
            flow.evidence = reply.evidence;
            flow.confidence = reply.confidence >= 0.85f
                            ? CrackmeTriageConfidence::High
                            : reply.confidence >= 0.6f
                            ? CrackmeTriageConfidence::Medium
                            : CrackmeTriageConfidence::Low;
            flow.confidenceLabel = CrackmeTriageConfidenceText(flow.confidence);
            flow.honestyLabel = flow.decisionAddressValid
                ? "bounded same-function data flow links a cataloged reply output to this comparison and branch; match/mismatch paths are static, while execution and business acceptance remain unproven"
                : "bounded same-function data flow links a cataloged reply output to this comparison; no flag-preserving decision branch was recovered";
            result.replyDecisionFlows.push_back(std::move(flow));
        }

        if (call.resultInfluencesDecision) {
            NetworkArtifact artifact;
            artifact.kind = NetworkArtifactKind::Validation;
            artifact.value = match->canonicalName + " API status/value controls a branch";
            artifact.functionAddress = call.functionAddress;
            artifact.functionAddressValid = call.functionAddressValid;
            // A checked BOOL/byte count from a Read API proves only transport
            // status or quantity. It is not evidence that the returned body or
            // headers were parsed and accepted.
            artifact.replyLinked = false;
            artifact.decisionEligible = false;
            artifact.confidence = CrackmeTriageConfidence::Medium;
            artifact.confidenceLabel = CrackmeTriageConfidenceText(artifact.confidence);
            artifact.honestyLabel =
                "typed call observation checks an API result; reply-buffer content validation and runtime execution are unproven";
            appendArtifact(std::move(artifact));
        }
    }

    // Routes and the strongest automatic semantic/header candidates follow
    // typed evidence.  Stable priority sorting makes cap behavior independent
    // of irrelevant string order.
    for (NetworkArtifact& artifact : typedRequestArtifacts) {
        if (stopNow()) return result;
        if (!appendArtifact(std::move(artifact))) break;
    }
    for (NetworkArtifact& artifact : routeArtifacts) {
        if (stopNow()) return result;
        if (!appendArtifact(std::move(artifact))) break;
    }
    std::stable_sort(semanticArtifacts.begin(), semanticArtifacts.end(),
        [&](const NetworkArtifact& left, const NetworkArtifact& right) {
            return automaticArtifactPriority(left) > automaticArtifactPriority(right);
        });
    for (NetworkArtifact& artifact : semanticArtifacts) {
        if (stopNow()) return result;
        if (!appendArtifact(std::move(artifact))) break;
    }

    if (input.functions.size() > input.limits.maxOwnershipFunctions ||
        !input.functionOwnershipComplete) {
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "function ownership input cap was reached; correlations are partial");
    }
    if (!input.callEdgesComplete ||
        input.callEdges.size() > input.limits.maxCallEdges) {
        result.completeness.sourcesTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       input.callEdgesComplete
                           ? "call-edge cap was reached; bounded-neighborhood correlations are partial"
                           : "call-edge adapter input was truncated; bounded-neighborhood correlations are partial");
    }
    result.completeness.xrefsComplete = input.xrefs && input.xrefs->complete;
    if (!input.xrefs) {
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                       "cross-reference input was unavailable; endpoint/API correlation was skipped");
    } else if (!input.xrefs->complete) {
        std::string reason = "cross-reference input is partial";
        if (*input.xrefs->incompleteReason()) {
            reason += ": ";
            reason += input.xrefs->incompleteReason();
        }
        markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit, reason);
    }

    FunctionOwnershipIndex ownership;
    if (!ownership.build(input, result.completeness)) {
        setCancelled(result.completeness);
        return result;
    }
    BoundedCallAdjacency callGraph;
    if (!callGraph.build(input)) {
        setCancelled(result.completeness);
        return result;
    }

    std::vector<std::vector<OwnedReference>> endpointRefs(result.endpoints.size());
    std::vector<std::vector<OwnedReference>> routeRefs(result.routes.size());
    for (size_t i = 0; i < result.endpoints.size(); ++i) {
        endpointRefs[i] = findingReferences(input, result.endpoints[i].sources,
                                            result.completeness, ownership);
        if (result.completeness.cancelled) return result;
    }
    for (size_t i = 0; i < result.routes.size(); ++i) {
        routeRefs[i] = findingReferences(input, result.routes[i].sources,
                                         result.completeness, ownership);
        if (result.completeness.cancelled) return result;
    }

    std::vector<std::vector<OwnedReference>> artifactRefs(result.artifacts.size());
    for (size_t i = 0; i < result.artifacts.size(); ++i) {
        artifactRefs[i] = findingReferences(input, result.artifacts[i].sources,
                                             result.completeness, ownership);
        if (result.completeness.cancelled) return result;
        if (result.artifacts[i].functionAddressValid)
            result.artifacts[i].functionAddresses.push_back(
                result.artifacts[i].functionAddress);
        for (const OwnedReference& ref : artifactRefs[i]) {
            if (ref.function == kNoIndex) continue;
            result.artifacts[i].functionAddresses.push_back(
                input.functions[ref.function].address);
        }
        auto& artifactOwners = result.artifacts[i].functionAddresses;
        std::sort(artifactOwners.begin(), artifactOwners.end());
        artifactOwners.erase(std::unique(artifactOwners.begin(), artifactOwners.end()),
                             artifactOwners.end());
        if (artifactOwners.size() > input.limits.maxReferencesPerArtifact) {
            artifactOwners.resize(input.limits.maxReferencesPerArtifact);
            result.completeness.sourcesTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "artifact owner-reference cap was reached");
        }
        if (!result.artifacts[i].functionAddressValid) {
            if (!artifactOwners.empty()) {
                result.artifacts[i].functionAddress = artifactOwners.front();
                result.artifacts[i].functionAddressValid = true;
                if (result.artifacts[i].confidence == CrackmeTriageConfidence::Low)
                    result.artifacts[i].confidence = CrackmeTriageConfidence::Medium;
                result.artifacts[i].confidenceLabel =
                    CrackmeTriageConfidenceText(result.artifacts[i].confidence);
                result.artifacts[i].honestyLabel =
                    "semantic string is referenced by code; relation to a network reply is not proven";
            }
        }
    }

    struct OwnedApiCallsite {
        size_t apiIndex = 0;
        size_t function = kNoIndex;
        uint64_t callsite = 0;
    };
    auto stageCorrelationPriority = [](NetworkStage stage) {
        switch (stage) {
        case NetworkStage::Read:    return 500;
        case NetworkStage::Write:   return 400;
        case NetworkStage::Request: return 300;
        case NetworkStage::Connect: return 200;
        case NetworkStage::Resolve: return 100;
        case NetworkStage::Count:   break;
        }
        return 0;
    };
    std::unordered_map<uint64_t, std::vector<OwnedApiCallsite>> apiCallsByOwner;
    for (size_t apiIndex = 0; apiIndex < result.apis.size(); ++apiIndex) {
        if (cancelled(input)) {
            setCancelled(result.completeness);
            return result;
        }
        const auto& api = result.apis[apiIndex];
        if (api.lifecycle) continue;
        for (uint64_t callsite : api.callsites) {
            if (stopNow()) return result;
            const size_t apiOwner = ownership.owner(callsite);
            if (apiOwner == kNoIndex) continue;
            apiCallsByOwner[input.functions[apiOwner].address].push_back(
                { apiIndex, apiOwner, callsite });
        }
    }
    for (auto& item : apiCallsByOwner) {
        auto& calls = item.second;
        std::sort(calls.begin(), calls.end(), [&](const OwnedApiCallsite& a,
                                                  const OwnedApiCallsite& b) {
            const int stageA = stageCorrelationPriority(result.apis[a.apiIndex].stage);
            const int stageB = stageCorrelationPriority(result.apis[b.apiIndex].stage);
            if (stageA != stageB) return stageA > stageB;
            if (a.apiIndex != b.apiIndex) return a.apiIndex < b.apiIndex;
            if (a.callsite != b.callsite) return a.callsite < b.callsite;
            return a.function < b.function;
        });
    }

    // Index route owners once.  This avoids an endpoint x route x reference
    // product while retaining the exact same-function association rule.
    std::unordered_map<size_t, std::vector<size_t>> routesByOwner;
    for (size_t routeIndex = 0; routeIndex < routeRefs.size(); ++routeIndex) {
        if (cancelled(input)) {
            setCancelled(result.completeness);
            return result;
        }
        for (const OwnedReference& ref : routeRefs[routeIndex]) {
            if (ref.function != kNoIndex)
                routesByOwner[ref.function].push_back(routeIndex);
        }
    }
    for (auto& item : routesByOwner) {
        auto& routes = item.second;
        std::sort(routes.begin(), routes.end());
        routes.erase(std::unique(routes.begin(), routes.end()), routes.end());
    }

    std::unordered_map<std::string, std::vector<size_t>> directLinksByEndpoint;
    for (size_t i = 0; i < directArgumentLinks.size(); ++i) {
        directLinksByEndpoint[directArgumentLinks[i].endpointKey].push_back(i);
    }

    std::unordered_set<std::string> correlationKeys;
    const size_t fairCorrelationShare = result.endpoints.empty() ||
                                        !input.limits.maxCorrelations
        ? 0
        : (std::max<size_t>)(1, input.limits.maxCorrelations /
                                result.endpoints.size());
    const size_t perEndpointCorrelationCap =
        (std::min)(input.limits.maxEvidenceRows, fairCorrelationShare);
    for (size_t endpointIndex = 0; endpointIndex < result.endpoints.size(); ++endpointIndex) {
        if (cancelled(input)) {
            setCancelled(result.completeness);
            return result;
        }
        auto& endpoint = result.endpoints[endpointIndex];
        bool codeReferenced = !endpointRefs[endpointIndex].empty();
        bool correlated = false;
        auto correlationPriority = [&](const CrackmeTriageCorrelation& correlation) {
            int priority = stageCorrelationPriority(correlation.stage);
            if (correlation.directArgument) priority += 1000;
            if (correlation.replyToDecision) priority += 300;
            if (correlation.confidence == CrackmeTriageConfidence::High) priority += 20;
            if (correlation.graphDepth <= input.limits.maxCallGraphDepth)
                priority += static_cast<int>(input.limits.maxCallGraphDepth -
                                             correlation.graphDepth);
            return priority;
        };
        auto noteCorrelationLimit = [&] {
            result.completeness.correlationsTruncated = true;
            markIncomplete(result.completeness,
                           CrackmeTriageStopReason::CorrelationLimit,
                           "fair per-endpoint correlation cap was reached; strongest bounded evidence was retained");
        };
        auto retainCorrelation = [&](CrackmeTriageCorrelation correlation) {
            auto& indices = endpoint.correlationIndices;
            if (!perEndpointCorrelationCap || !input.limits.maxCorrelations) {
                noteCorrelationLimit();
                return false;
            }
            if (indices.size() < perEndpointCorrelationCap &&
                result.correlations.size() < input.limits.maxCorrelations) {
                const size_t index = result.correlations.size();
                result.correlations.push_back(std::move(correlation));
                indices.push_back(index);
                return true;
            }
            noteCorrelationLimit();
            if (indices.empty()) return false;
            size_t victimPosition = 0;
            int victimPriority = correlationPriority(
                result.correlations[indices.front()]);
            for (size_t i = 1; i < indices.size(); ++i) {
                const int priority = correlationPriority(
                    result.correlations[indices[i]]);
                if (priority < victimPriority) {
                    victimPriority = priority;
                    victimPosition = i;
                }
            }
            if (correlationPriority(correlation) <= victimPriority) return false;
            result.correlations[indices[victimPosition]] = std::move(correlation);
            return true;
        };
        const size_t multipliedCandidateCap =
            input.limits.maxEvidenceRows > (std::numeric_limits<size_t>::max)() / 4
            ? (std::numeric_limits<size_t>::max)()
            : input.limits.maxEvidenceRows * 4;
        const size_t staticCandidateCap = (std::max<size_t>)(
            perEndpointCorrelationCap,
            (std::min)(input.limits.maxCorrelations, multipliedCandidateCap));
        size_t staticCandidatesExamined = 0;
        bool staticCandidateLimitReached = false;
        std::vector<OwnedReference> endpointOwners;
        std::unordered_set<size_t> seenEndpointOwners;
        for (const OwnedReference& endpointRef : endpointRefs[endpointIndex]) {
            if (endpointRef.function != kNoIndex &&
                seenEndpointOwners.insert(endpointRef.function).second)
                endpointOwners.push_back(endpointRef);
        }
        std::sort(endpointOwners.begin(), endpointOwners.end(),
                  [](const OwnedReference& a, const OwnedReference& b) {
            if (a.function != b.function) return a.function < b.function;
            return a.source < b.source;
        });

        for (const OwnedReference& endpointRef : endpointOwners) {
            std::vector<std::pair<uint64_t, size_t>> reachable;
            const uint64_t endpointOwnerAddress =
                input.functions[endpointRef.function].address;
            if (!callGraph.distancesFrom(endpointOwnerAddress, input, reachable)) {
                setCancelled(result.completeness);
                return result;
            }
            for (const auto& reachableOwner : reachable) {
                if (stopNow()) return result;
                const auto foundCalls = apiCallsByOwner.find(reachableOwner.first);
                if (foundCalls == apiCallsByOwner.end()) continue;
                for (const OwnedApiCallsite& ownedCall : foundCalls->second) {
                    if (stopNow()) return result;
                    const size_t apiIndex = ownedCall.apiIndex;
                    const size_t apiOwner = ownedCall.function;
                    const uint64_t callsite = ownedCall.callsite;
                    const auto& api = result.apis[apiIndex];
                    const std::string key = std::to_string(endpointIndex) + ":" +
                                            std::to_string(apiIndex) + ":" +
                                            std::to_string(endpointRef.function) + ":" +
                                            std::to_string(apiOwner) + ":" +
                                            std::to_string(callsite);
                    if (!correlationKeys.insert(key).second) continue;
                    if (staticCandidatesExamined >= staticCandidateCap) {
                        noteCorrelationLimit();
                        staticCandidateLimitReached = true;
                        break;
                    }
                    ++staticCandidatesExamined;
                    CrackmeTriageCorrelation correlation;
                    correlation.endpointIndex = endpointIndex;
                    correlation.apiIndex = apiIndex;
                    correlation.stage = api.stage;
                    correlation.trailStage = NetworkTrailStageForApi(api.stage);
                    correlation.endpointReference = endpointRef.source;
                    correlation.apiCallsite = callsite;
                    correlation.apiCallsiteValid = true;
                    correlation.graphDepth = reachableOwner.second;
                    correlation.functionAddressValid = true;
                    correlation.functionAddress = input.functions[apiOwner].address;
                    correlation.functionName = input.functions[apiOwner].name;
                    correlation.endpointFunctionAddressValid = true;
                    correlation.endpointFunctionAddress = endpointOwnerAddress;
                    correlation.endpointFunctionName = input.functions[endpointRef.function].name;
                    correlation.confidence = reachableOwner.second == 0
                                           ? CrackmeTriageConfidence::High
                                           : CrackmeTriageConfidence::Medium;
                    correlation.confidenceLabel = CrackmeTriageConfidenceText(correlation.confidence);
                    correlation.honestyLabel = reachableOwner.second == 0
                        ? "same-function static xref correlation; argument flow and runtime contact are not proven"
                        : "bounded call-neighborhood correlation; argument flow and runtime contact are not proven";
                    retainCorrelation(std::move(correlation));
                    result.endpoints[endpointIndex].stages |= NetworkStageBit(api.stage);
                    correlated = true;
                }
                if (staticCandidateLimitReached) break;
            }
            if (staticCandidateLimitReached) break;
        }

        const std::string identity = endpointIdentity(endpoint);
        const auto foundDirectLinks = directLinksByEndpoint.find(identity);
        const std::vector<size_t>* endpointDirectLinks =
            foundDirectLinks == directLinksByEndpoint.end() ? nullptr
                                                             : &foundDirectLinks->second;
        if (endpointDirectLinks) for (size_t directLinkIndex : *endpointDirectLinks) {
            if (cancelled(input)) {
                setCancelled(result.completeness);
                return result;
            }
            const DirectArgumentLink& link = directArgumentLinks[directLinkIndex];
            if (link.callInputIndex >= typedCallApiIndex.size()) continue;
            const size_t apiIndex = typedCallApiIndex[link.callInputIndex];
            if (apiIndex == kNoIndex || result.apis[apiIndex].lifecycle) continue;
            const auto& call = input.apiCalls[link.callInputIndex];
            const std::string key = std::to_string(endpointIndex) + ":direct:" +
                                    std::to_string(link.callInputIndex);
            if (!correlationKeys.insert(key).second) continue;
            CrackmeTriageCorrelation correlation;
            correlation.endpointIndex = endpointIndex;
            correlation.apiIndex = apiIndex;
            correlation.stage = result.apis[apiIndex].stage;
            correlation.trailStage = NetworkTrailStageForApi(correlation.stage);
            correlation.endpointReference = link.argumentAddress;
            correlation.apiCallsite = call.callsite;
            correlation.apiCallsiteValid = call.callsiteValid;
            correlation.directArgument = true;
            // A branch on a read API's BOOL/byte-count result is transport
            // status handling, not proof that response content was accepted.
            // Reply-linked Decision evidence is attached separately from typed
            // buffer/header/parsed-field findings.
            correlation.replyToDecision = false;
            correlation.functionAddressValid = call.functionAddressValid;
            correlation.functionAddress = call.functionAddress;
            correlation.functionName = call.functionName;
            if (!correlation.functionAddressValid && call.callsiteValid) {
                const size_t apiOwner = ownership.owner(call.callsite);
                if (apiOwner != kNoIndex) {
                    correlation.functionAddressValid = true;
                    correlation.functionAddress = input.functions[apiOwner].address;
                    correlation.functionName = input.functions[apiOwner].name;
                }
            }
            // A typed literal argument is consumed by the observed API owner.
            // Keep that association distinct from the API navigation fields.
            correlation.endpointFunctionAddressValid = correlation.functionAddressValid;
            correlation.endpointFunctionAddress = correlation.functionAddress;
            correlation.endpointFunctionName = correlation.functionName;
            correlation.confidence = CrackmeTriageConfidence::High;
            correlation.confidenceLabel = CrackmeTriageConfidenceText(correlation.confidence);
            correlation.honestyLabel =
                "typed call observation recovered this literal argument; runtime contact is still not proven";
            retainCorrelation(std::move(correlation));
            endpoint.stages |= NetworkStageBit(result.apis[apiIndex].stage);
            codeReferenced = true;
            correlated = true;
        }

        // Associate standalone routes only through a shared owner.  File
        // adjacency is intentionally not treated as evidence.
        std::vector<size_t> matchingRoutes;
        for (const OwnedReference& endpointRef : endpointOwners) {
            const auto foundRoutes = routesByOwner.find(endpointRef.function);
            if (foundRoutes != routesByOwner.end())
                matchingRoutes.insert(matchingRoutes.end(), foundRoutes->second.begin(),
                                      foundRoutes->second.end());
        }
        std::sort(matchingRoutes.begin(), matchingRoutes.end());
        matchingRoutes.erase(std::unique(matchingRoutes.begin(), matchingRoutes.end()),
                             matchingRoutes.end());
        for (size_t routeIndex : matchingRoutes) {
            if (stopNow()) return result;
            if (!pathPresent(endpoint.paths, result.routes[routeIndex].path))
                endpoint.paths.push_back(result.routes[routeIndex].path);
        }
        setEndpointLabels(endpoint, codeReferenced, correlated);
    }

    // Rank only after the bounded static correlation pass.  Textual crackme
    // cues are useful, but must never evict a generic host with exact code/API
    // evidence before that evidence has a chance to promote it.
    std::vector<size_t> endpointOrder;
    endpointOrder.reserve(result.endpoints.size());
    for (size_t i = 0; i < result.endpoints.size(); ++i) endpointOrder.push_back(i);
    std::stable_sort(endpointOrder.begin(), endpointOrder.end(),
        [&](size_t left, size_t right) {
            const auto& a = result.endpoints[left];
            const auto& b = result.endpoints[right];
            const bool correlatedA = !a.correlationIndices.empty();
            const bool correlatedB = !b.correlationIndices.empty();
            if (correlatedA != correlatedB) return correlatedA > correlatedB;
            auto exactCorrelationScore = [&](const CrackmeTriageEndpoint& endpoint) {
                int score = 0;
                if (endpoint.stages & NetworkStageBit(NetworkStage::Read)) score += 100;
                if (endpoint.stages & NetworkStageBit(NetworkStage::Write)) score += 80;
                if (endpoint.stages & NetworkStageBit(NetworkStage::Request)) score += 30;
                if (endpoint.stages & NetworkStageBit(NetworkStage::Connect)) score += 20;
                if (endpoint.stages & NetworkStageBit(NetworkStage::Resolve)) score += 10;
                for (size_t correlationIndex : endpoint.correlationIndices) {
                    if (correlationIndex >= result.correlations.size()) continue;
                    const auto& correlation = result.correlations[correlationIndex];
                    if (correlation.directArgument) score += 200;
                    if (correlation.replyToDecision) score += 100;
                    if (correlation.graphDepth == 0) score += 2;
                }
                return score;
            };
            const int exactA = exactCorrelationScore(a);
            const int exactB = exactCorrelationScore(b);
            if (exactA != exactB) return exactA > exactB;
            const int cueA = relevanceCue(a), cueB = relevanceCue(b);
            if (cueA != cueB) return cueA > cueB;
            if (confidenceRank(a.confidence) != confidenceRank(b.confidence))
                return confidenceRank(a.confidence) > confidenceRank(b.confidence);
            return a.display < b.display;
        });

    const size_t retainedEndpoints =
        (std::min)(endpointOrder.size(), input.limits.maxEndpoints);
    if (retainedEndpoints != endpointOrder.size()) {
        result.completeness.endpointsTruncated = true;
        markIncomplete(result.completeness, CrackmeTriageStopReason::EndpointLimit,
                       "ranked endpoint result cap was reached; lower-ranked candidates were omitted");
    }
    std::vector<size_t> endpointRemap(result.endpoints.size(), kNoIndex);
    std::vector<CrackmeTriageEndpoint> rankedEndpoints;
    rankedEndpoints.reserve(retainedEndpoints);
    for (size_t newIndex = 0; newIndex < retainedEndpoints; ++newIndex) {
        if (stopNow()) return result;
        const size_t oldIndex = endpointOrder[newIndex];
        endpointRemap[oldIndex] = newIndex;
        rankedEndpoints.push_back(std::move(result.endpoints[oldIndex]));
        rankedEndpoints.back().correlationIndices.clear();
    }
    result.endpoints = std::move(rankedEndpoints);

    std::vector<CrackmeTriageCorrelation> retainedCorrelations;
    retainedCorrelations.reserve(result.correlations.size());
    for (CrackmeTriageCorrelation& correlation : result.correlations) {
        if (stopNow()) return result;
        if (correlation.endpointIndex >= endpointRemap.size()) continue;
        const size_t newEndpoint = endpointRemap[correlation.endpointIndex];
        if (newEndpoint == kNoIndex) continue;
        correlation.endpointIndex = newEndpoint;
        const size_t newCorrelation = retainedCorrelations.size();
        retainedCorrelations.push_back(std::move(correlation));
        result.endpoints[newEndpoint].correlationIndices.push_back(newCorrelation);
    }
    result.correlations = std::move(retainedCorrelations);

    // Scope Host header artifacts to the matching final endpoint.  Other
    // request headers remain report-level until code ownership correlates them
    // with a Request API; a functionless User-Agent/Cookie must not be sprayed
    // across every discovered server.
    for (NetworkArtifact& artifact : result.artifacts) {
        if (stopNow()) return result;
        if (artifact.kind != NetworkArtifactKind::Header) continue;
        const std::optional<ParsedHeader> header = parseHttpHeader(artifact.value);
        if (!header || header->name != "host") continue;
        CrackmeTriageEndpoint parsed;
        if (!parseHostPort(header->value, parsed.host, parsed.port,
                           parsed.portValid, parsed.kind))
            continue;
        size_t matchedEndpoint = kNoIndex;
        for (size_t i = 0; i < result.endpoints.size(); ++i) {
            const CrackmeTriageEndpoint& endpoint = result.endpoints[i];
            if (endpoint.host != parsed.host) continue;
            if (parsed.portValid) {
                uint16_t effectivePort = 0;
                if (!endpointEffectivePort(endpoint.scheme, endpoint.port,
                                           endpoint.portValid, effectivePort) ||
                    effectivePort != parsed.port)
                    continue;
            }
            matchedEndpoint = i; // ranked order provides deterministic ambiguity handling
            break;
        }
        if (matchedEndpoint == kNoIndex) continue;
        artifact.endpointIndex = matchedEndpoint;
        artifact.endpointIndexValid = true;
    }

    // Endpoint artifacts use the final ranked indices.  Their source reference
    // list is independently capped even though report.endpoints retains the
    // complete per-endpoint evidence budget.
    for (size_t i = 0; i < result.endpoints.size(); ++i) {
        if (stopNow()) return result;
        NetworkArtifact artifact;
        artifact.kind = NetworkArtifactKind::Endpoint;
        artifact.value = result.endpoints[i].display;
        artifact.sources = result.endpoints[i].sources;
        if (artifact.sources.size() > input.limits.maxReferencesPerArtifact) {
            artifact.sources.resize(input.limits.maxReferencesPerArtifact);
            result.completeness.sourcesTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "artifact reference cap was reached");
        }
        artifact.endpointIndex = i;
        artifact.endpointIndexValid = true;
        artifact.confidence = result.endpoints[i].confidence;
        artifact.confidenceLabel = result.endpoints[i].confidenceLabel;
        artifact.honestyLabel = result.endpoints[i].honestyLabel;
        if (!appendArtifact(std::move(artifact))) break;
    }

    auto initializeTrailStages = [](auto& stages) {
        for (size_t i = 0; i < stages.size(); ++i) {
            stages[i].stage = static_cast<NetworkTrailStage>(i);
            stages[i].confidence = CrackmeTriageConfidence::Low;
            stages[i].confidenceLabel = CrackmeTriageConfidenceText(stages[i].confidence);
            stages[i].honestyLabel = "no static evidence for this trail stage";
        }
    };

    result.trails.reserve(result.endpoints.size());
    for (size_t endpointIndex = 0; endpointIndex < result.endpoints.size(); ++endpointIndex) {
        if (stopNow()) return result;
        CrackmeTrail trail;
        trail.endpointIndex = endpointIndex;
        initializeTrailStages(trail.stages);
        auto& endpointStage = trail.stages[static_cast<size_t>(NetworkTrailStage::Endpoint)];
        endpointStage.correlationCount = result.endpoints[endpointIndex].sources.size();
        endpointStage.confidence = result.endpoints[endpointIndex].confidence;
        endpointStage.confidenceLabel = result.endpoints[endpointIndex].confidenceLabel;
        endpointStage.honestyLabel = result.endpoints[endpointIndex].honestyLabel;

        size_t retainedEvidenceRows = 0;
        bool evidenceRowsTruncated = false;
        auto noteEvidenceRowLimit = [&] {
            if (evidenceRowsTruncated) return;
            evidenceRowsTruncated = true;
            result.completeness.sourcesTruncated = true;
            markIncomplete(result.completeness, CrackmeTriageStopReason::SourceLimit,
                           "combined per-trail correlation/artifact evidence row cap was reached");
        };

        for (size_t correlationIndex : result.endpoints[endpointIndex].correlationIndices) {
            if (stopNow()) return result;
            if (correlationIndex >= result.correlations.size()) continue;
            if (retainedEvidenceRows < input.limits.maxEvidenceRows) {
                trail.correlationIndices.push_back(correlationIndex);
                ++retainedEvidenceRows;
            } else noteEvidenceRowLimit();
            const auto& correlation = result.correlations[correlationIndex];
            auto& stage = trail.stages[static_cast<size_t>(correlation.trailStage)];
            ++stage.apiCount;
            ++stage.correlationCount;
            if (confidenceRank(correlation.confidence) > confidenceRank(stage.confidence))
                stage.confidence = correlation.confidence;
            stage.confidenceLabel = CrackmeTriageConfidenceText(stage.confidence);
            stage.honestyLabel = correlation.honestyLabel;
            if (correlation.replyToDecision) {
                auto& decision = trail.stages[static_cast<size_t>(NetworkTrailStage::Decision)];
                ++decision.correlationCount;
                decision.confidence = CrackmeTriageConfidence::High;
                decision.confidenceLabel = CrackmeTriageConfidenceText(decision.confidence);
                decision.honestyLabel =
                    "typed network-call evidence says the returned result influences a decision; runtime execution is unproven";
            }
        }

        // Return handling is detail attached to already-retained API evidence,
        // not an extra claim about endpoint contact. Prefer an exact callsite;
        // fall back to exact API + owning function only when both owners are
        // validity-bearing. This keeps unrelated uses of the same imported API
        // from appearing under every endpoint.
        for (size_t correlationIndex : trail.correlationIndices) {
            if (correlationIndex >= result.correlations.size()) continue;
            const CrackmeTriageCorrelation& correlation =
                result.correlations[correlationIndex];
            for (size_t flowIndex = 0; flowIndex < result.returnFlows.size(); ++flowIndex) {
                const NetworkReturnFlow& flow = result.returnFlows[flowIndex];
                if (!flow.apiIndexValid || flow.apiIndex != correlation.apiIndex) continue;
                const bool exactCallsite = flow.callsiteValid &&
                    correlation.apiCallsiteValid &&
                    flow.callsite == correlation.apiCallsite;
                const bool exactOwner = !flow.callsiteValid &&
                    !correlation.apiCallsiteValid &&
                    flow.functionAddressValid && correlation.functionAddressValid &&
                    flow.functionAddress == correlation.functionAddress;
                if (!exactCallsite && !exactOwner) continue;
                if (std::find(trail.returnFlowIndices.begin(),
                              trail.returnFlowIndices.end(), flowIndex) ==
                    trail.returnFlowIndices.end())
                    trail.returnFlowIndices.push_back(flowIndex);
            }
        }

        // Attach reply-content comparisons by the same exact API+callsite rule.
        // Unlike NetworkReturnFlow, a flag-preserving branch here is genuine
        // Decision-stage evidence because the traced value came from the
        // cataloged payload/header output argument.
        for (size_t correlationIndex : trail.correlationIndices) {
            if (correlationIndex >= result.correlations.size()) continue;
            const CrackmeTriageCorrelation& correlation =
                result.correlations[correlationIndex];
            for (size_t flowIndex = 0;
                 flowIndex < result.replyDecisionFlows.size(); ++flowIndex) {
                const NetworkReplyDecisionFlow& flow =
                    result.replyDecisionFlows[flowIndex];
                if (!flow.apiIndexValid || flow.apiIndex != correlation.apiIndex)
                    continue;
                const bool exactCallsite = flow.callsiteValid &&
                    correlation.apiCallsiteValid &&
                    flow.callsite == correlation.apiCallsite;
                const bool exactOwner = !flow.callsiteValid &&
                    !correlation.apiCallsiteValid &&
                    flow.functionAddressValid && correlation.functionAddressValid &&
                    flow.functionAddress == correlation.functionAddress;
                if (!exactCallsite && !exactOwner) continue;
                if (std::find(trail.replyDecisionFlowIndices.begin(),
                              trail.replyDecisionFlowIndices.end(), flowIndex) !=
                    trail.replyDecisionFlowIndices.end())
                    continue;
                trail.replyDecisionFlowIndices.push_back(flowIndex);
                if (flow.decisionAddressValid) {
                    auto& decision =
                        trail.stages[static_cast<size_t>(NetworkTrailStage::Decision)];
                    ++decision.correlationCount;
                    if (confidenceRank(flow.confidence) >
                        confidenceRank(decision.confidence))
                        decision.confidence = flow.confidence;
                    decision.confidenceLabel =
                        CrackmeTriageConfidenceText(decision.confidence);
                    decision.honestyLabel =
                        "bounded reply-buffer data flow reaches a comparison and conditional branch; match/mismatch paths are static and runtime acceptance remains unproven";
                }
            }
        }

        // Attach compact artifacts.  Endpoint and route artifacts are direct.
        // Header/auth/license evidence may support Request only through a Host
        // scope or a bounded Request-API neighborhood.  Validation evidence may
        // support Decision only through a bounded Reply-API neighborhood.
        for (size_t artifactIndex = 0; artifactIndex < result.artifacts.size(); ++artifactIndex) {
            if (stopNow()) return result;
            const auto& artifact = result.artifacts[artifactIndex];
            bool attach = artifact.endpointIndexValid && artifact.endpointIndex == endpointIndex;
            if (!attach && artifact.kind == NetworkArtifactKind::Route)
                attach = pathPresent(result.endpoints[endpointIndex].paths, artifact.value);

            std::vector<uint64_t> artifactOwners = artifact.functionAddresses;
            if (artifactOwners.empty() && artifact.functionAddressValid)
                artifactOwners.push_back(artifact.functionAddress);

            auto nearestStageDepth = [&](NetworkTrailStage wanted) {
                size_t nearest = kNoIndex;
                for (uint64_t artifactOwner : artifactOwners) {
                    if (stopNow()) return kNoIndex;
                    for (size_t correlationIndex :
                         result.endpoints[endpointIndex].correlationIndices) {
                        if (stopNow()) return kNoIndex;
                        if (correlationIndex >= result.correlations.size()) continue;
                        const auto& correlation = result.correlations[correlationIndex];
                        if (correlation.trailStage != wanted ||
                            !correlation.functionAddressValid)
                            continue;
                        bool graphCancelled = false;
                        const size_t distance = callGraph.distance(
                            artifactOwner, correlation.functionAddress,
                            input, graphCancelled);
                        if (graphCancelled) {
                            setCancelled(result.completeness);
                            return kNoIndex;
                        }
                        if (distance != kNoIndex &&
                            (nearest == kNoIndex || distance < nearest))
                            nearest = distance;
                        if (nearest == 0) return nearest;
                    }
                }
                return nearest;
            };

            const bool requestArtifact =
                artifact.kind == NetworkArtifactKind::Header ||
                artifact.kind == NetworkArtifactKind::Authentication ||
                artifact.kind == NetworkArtifactKind::License;
            const size_t requestDepth = requestArtifact && !artifactOwners.empty()
                                      ? nearestStageDepth(NetworkTrailStage::Request)
                                      : kNoIndex;
            if (result.completeness.cancelled) return result;
            const bool requestLink = requestDepth != kNoIndex;

            bool decisionLink = false;
            size_t decisionDepth = kNoIndex;
            if (artifact.decisionEligible && artifact.replyLinked &&
                artifactOwners.empty()) {
                // Functionless reply evidence is report-level.  It may support
                // one endpoint only when an upstream producer explicitly
                // scoped the artifact to that endpoint.
                if (artifact.endpointIndexValid && artifact.endpointIndex == endpointIndex) {
                    decisionLink = true;
                    decisionDepth = 0;
                }
            } else if (artifact.decisionEligible && !artifactOwners.empty() &&
                       artifact.kind != NetworkArtifactKind::Endpoint &&
                       artifact.kind != NetworkArtifactKind::Route) {
                decisionDepth = nearestStageDepth(NetworkTrailStage::Reply);
                if (result.completeness.cancelled) return result;
                decisionLink = decisionDepth != kNoIndex;
            }
            attach = attach || requestLink || decisionLink;
            bool retainedArtifact = false;
            if (attach) {
                if (retainedEvidenceRows < input.limits.maxEvidenceRows) {
                    trail.artifactIndices.push_back(artifactIndex);
                    ++retainedEvidenceRows;
                    retainedArtifact = true;
                } else noteEvidenceRowLimit();
            }
            if (requestLink && retainedArtifact) {
                auto& request = trail.stages[static_cast<size_t>(NetworkTrailStage::Request)];
                ++request.correlationCount;
                const CrackmeTriageConfidence confidence = requestDepth == 0
                    ? CrackmeTriageConfidence::High : CrackmeTriageConfidence::Medium;
                if (confidenceRank(confidence) > confidenceRank(request.confidence))
                    request.confidence = confidence;
                request.confidenceLabel = CrackmeTriageConfidenceText(request.confidence);
                request.honestyLabel = requestDepth == 0
                    ? "request API and header/auth/license evidence share a function; argument flow and transmission are unproven"
                    : "request API and header/auth/license evidence share a bounded call neighborhood; argument flow and transmission are unproven";
            }
            if (decisionLink && retainedArtifact) {
                auto& decision = trail.stages[static_cast<size_t>(NetworkTrailStage::Decision)];
                ++decision.correlationCount;
                const CrackmeTriageConfidence confidence =
                    artifact.replyLinked || decisionDepth == 0
                    ? CrackmeTriageConfidence::High : CrackmeTriageConfidence::Medium;
                if (confidenceRank(confidence) > confidenceRank(decision.confidence))
                    decision.confidence = confidence;
                decision.confidenceLabel = CrackmeTriageConfidenceText(decision.confidence);
                decision.honestyLabel = artifact.replyLinked
                    ? "typed evidence links a reply to validation/decision logic; runtime execution is unproven"
                    : "reply API and validation evidence share a bounded call neighborhood; data flow is unproven";
            }
        }

        trail.confidence = result.endpoints[endpointIndex].confidence;
        for (const auto& stage : trail.stages)
            if (confidenceRank(stage.confidence) > confidenceRank(trail.confidence))
                trail.confidence = stage.confidence;
        trail.confidenceLabel = CrackmeTriageConfidenceText(trail.confidence);
        const bool hasReply = trail.stages[static_cast<size_t>(NetworkTrailStage::Reply)].correlationCount != 0;
        const bool hasDecision = trail.stages[static_cast<size_t>(NetworkTrailStage::Decision)].correlationCount != 0;
        bool hasOutboundWrite = false;
        for (size_t correlationIndex : result.endpoints[endpointIndex].correlationIndices) {
            if (correlationIndex < result.correlations.size() &&
                result.correlations[correlationIndex].stage == NetworkStage::Write) {
                hasOutboundWrite = true;
                break;
            }
        }
        const bool nonLoopback = result.endpoints[endpointIndex].scope != CrackmeEndpointScope::Loopback;
        if (nonLoopback && hasOutboundWrite && (hasReply || hasDecision))
            trail.label = "Hosted reply-server path";
        else if (!result.endpoints[endpointIndex].correlationIndices.empty())
            trail.label = "Remote endpoint candidate";
        else
            trail.label = "Unreferenced endpoint string";
        trail.honestyLabel = hasReply && hasDecision
            ? "offline endpoint-to-decision trail; execution and server contact remain unproven"
            : "partial offline trail; absent stages are unknown, not proof that the behavior is absent";
        result.trails.push_back(std::move(trail));
    }

    for (const CrackmeTrail& trail : result.trails) {
        if (stopNow()) return result;
        if (trail.label == "Hosted reply-server path") {
            result.label = trail.label;
            break;
        }
        if (trail.label == "Remote endpoint candidate")
            result.label = trail.label;
        else if (result.label.empty()) result.label = trail.label;
    }
    if (result.endpoints.empty() && !result.apis.empty())
        result.label = "Network APIs found; host unknown";

    initializeTrailStages(result.stages);
    result.stages[static_cast<size_t>(NetworkTrailStage::Endpoint)].apiCount =
        result.endpoints.size();
    if (!result.endpoints.empty()) {
        auto& endpoint = result.stages[static_cast<size_t>(NetworkTrailStage::Endpoint)];
        endpoint.confidence = result.endpoints.front().confidence;
        endpoint.confidenceLabel = CrackmeTriageConfidenceText(endpoint.confidence);
        endpoint.honestyLabel = "embedded endpoint candidates; runtime use is unproven";
    }
    for (const auto& api : result.apis) {
        if (stopNow()) return result;
        if (api.lifecycle) continue;
        ++result.stages[static_cast<size_t>(NetworkTrailStageForApi(api.stage))].apiCount;
    }
    for (const auto& correlation : result.correlations) {
        if (stopNow()) return result;
        auto& stage = result.stages[static_cast<size_t>(correlation.trailStage)];
        ++stage.correlationCount;
        if (confidenceRank(correlation.confidence) > confidenceRank(stage.confidence))
            stage.confidence = correlation.confidence;
    }
    for (const auto& trail : result.trails) {
        if (stopNow()) return result;
        const auto& decision = trail.stages[static_cast<size_t>(NetworkTrailStage::Decision)];
        auto& aggregate = result.stages[static_cast<size_t>(NetworkTrailStage::Decision)];
        if (decision.correlationCount) {
            aggregate.correlationCount += decision.correlationCount;
            if (confidenceRank(decision.confidence) > confidenceRank(aggregate.confidence))
                aggregate.confidence = decision.confidence;
            aggregate.honestyLabel = decision.honestyLabel;
        }
    }
    for (auto& stage : result.stages) {
        stage.confidenceLabel = CrackmeTriageConfidenceText(stage.confidence);
        if (stage.correlationCount && stage.honestyLabel == "no static evidence for this trail stage")
            stage.honestyLabel =
                "bounded static correlation; argument/data flow and runtime execution are unproven";
        else if (stage.apiCount && !stage.correlationCount &&
                 stage.honestyLabel == "no static evidence for this trail stage")
            stage.honestyLabel =
                "exact API import/observation only; execution and endpoint association are unproven";
    }
    return result;
}

CrackmeTriageCandidateSelection SelectCrackmeTriageAnnotationCandidates(
    const CrackmeTriageReport& report,
    const std::vector<CrackmeTriageFunctionInput>& functions,
    size_t maxCandidates,
    size_t maxOwnershipFunctions,
    size_t maxRangesPerFunction,
    size_t maxOwnershipRanges) {
    CrackmeTriageCandidateSelection selection;
    std::vector<uint64_t> primary;
    std::vector<uint64_t> secondary;
    std::unordered_set<uint64_t> seen;
    const size_t functionCount = (std::min)(functions.size(), maxOwnershipFunctions);
    std::unordered_set<uint64_t> functionStarts;
    functionStarts.reserve(functionCount);
    for (size_t i = 0; i < functionCount; ++i)
        functionStarts.insert(functions[i].address);

    struct IndexedRange {
        uint64_t start = 0;
        uint64_t end = 0;
        uint64_t size = 0;
        size_t function = 0;
    };
    std::vector<IndexedRange> ranges;
    size_t retainedRanges = 0;
    for (size_t i = 0; i < functionCount; ++i) {
        const auto& function = functions[i];
        auto addRange = [&](uint64_t start, uint64_t size) {
            if (retainedRanges >= maxOwnershipRanges) return false;
            uint64_t end = 0;
            if (size && checkedEnd(start, size, end)) {
                ranges.push_back({ start, end, size, i });
                ++retainedRanges;
            }
            return true;
        };
        if (function.ranges.empty()) {
            if (!addRange(function.address, function.size)) break;
        } else {
            const size_t rangeCount = (std::min)(function.ranges.size(),
                                                  maxRangesPerFunction);
            for (size_t rangeIndex = 0; rangeIndex < rangeCount; ++rangeIndex)
                if (!addRange(function.ranges[rangeIndex].address,
                              function.ranges[rangeIndex].size)) break;
            if (retainedRanges >= maxOwnershipRanges) break;
        }
    }
    std::sort(ranges.begin(), ranges.end(), [](const IndexedRange& a,
                                                const IndexedRange& b) {
        if (a.start != b.start) return a.start < b.start;
        if (a.size != b.size) return a.size < b.size;
        return a.function < b.function;
    });
    std::vector<uint64_t> prefixMaxEnd(ranges.size());
    uint64_t maxEnd = 0;
    for (size_t i = 0; i < ranges.size(); ++i) {
        maxEnd = (std::max)(maxEnd, ranges[i].end);
        prefixMaxEnd[i] = maxEnd;
    }
    auto ownerAddress = [&](uint64_t address) -> std::optional<uint64_t> {
        size_t pos = static_cast<size_t>(std::upper_bound(
            ranges.begin(), ranges.end(), address,
            [](uint64_t value, const IndexedRange& range) {
                return value < range.start;
            }) - ranges.begin());
        size_t best = kNoIndex;
        uint64_t bestSize = (std::numeric_limits<uint64_t>::max)();
        while (pos) {
            --pos;
            const IndexedRange& range = ranges[pos];
            if (range.start <= address && address < range.end &&
                (range.size < bestSize ||
                 (range.size == bestSize && range.function < best))) {
                best = range.function;
                bestSize = range.size;
            }
            if (!pos || prefixMaxEnd[pos - 1] <= address) break;
        }
        return best == kNoIndex ? std::nullopt
                                : std::optional<uint64_t>(functions[best].address);
    };
    auto append = [&](std::vector<uint64_t>& tier, uint64_t address) {
        if (seen.insert(address).second) tier.push_back(address);
    };

    // Primary tier: retain the endpoint/literal owner first and the API
    // callsite owner second, before any semantic/validation artifact owner.
    // Exact network-import callsites remain candidates even when a target
    // builds its endpoint dynamically and therefore has no endpoint literal or
    // endpoint correlation yet.
    for (const CrackmeTriageApiEvidence& api : report.apis) {
        for (uint64_t callsite : api.callsites) {
            if (const auto owner = ownerAddress(callsite)) append(primary, *owner);
        }
    }
    for (const CrackmeTriageCorrelation& correlation : report.correlations) {
        if (correlation.endpointFunctionAddressValid) {
            if (functionStarts.count(correlation.endpointFunctionAddress))
                append(primary, correlation.endpointFunctionAddress);
        } else if (const auto owner = ownerAddress(correlation.endpointReference)) {
            append(primary, *owner);
        }
        if (correlation.functionAddressValid) {
            if (functionStarts.count(correlation.functionAddress))
                append(primary, correlation.functionAddress);
        } else if (correlation.apiCallsiteValid) {
            if (const auto owner = ownerAddress(correlation.apiCallsite))
                append(primary, *owner);
        }
    }
    for (const NetworkArtifact& artifact : report.artifacts) {
        if (!artifact.functionAddresses.empty()) {
            for (uint64_t address : artifact.functionAddresses)
                if (functionStarts.count(address)) append(secondary, address);
        } else if (artifact.functionAddressValid &&
                   functionStarts.count(artifact.functionAddress)) {
            append(secondary, artifact.functionAddress);
        }
    }

    selection.availableFunctions = primary.size() + secondary.size();
    selection.functionAddresses.reserve(
        (std::min)(selection.availableFunctions, maxCandidates));
    auto retainTier = [&](const std::vector<uint64_t>& tier) {
        for (uint64_t address : tier) {
            if (selection.functionAddresses.size() >= maxCandidates) break;
            selection.functionAddresses.push_back(address);
        }
    };
    retainTier(primary);
    retainTier(secondary);
    selection.truncated = selection.functionAddresses.size() <
                          selection.availableFunctions;
    return selection;
}

} // namespace ds
