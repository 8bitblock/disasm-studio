#include "NetworkEndpoint.h"

#include <algorithm>
#include <array>
#include <cstdio>

namespace ds {

std::string FormatIpv4Address(const uint8_t address[4]) {
    if (!address) return {};
    char out[16];
    std::snprintf(out, sizeof(out), "%u.%u.%u.%u",
                  (unsigned)address[0], (unsigned)address[1],
                  (unsigned)address[2], (unsigned)address[3]);
    return out;
}

std::string FormatIpv6Address(const uint8_t address[16], uint32_t scopeId) {
    if (!address) return {};

    // Render IPv4-mapped addresses in the familiar ::ffff:a.b.c.d form.
    bool mapped = true;
    for (int i = 0; i < 10; ++i) mapped = mapped && address[i] == 0;
    mapped = mapped && address[10] == 0xff && address[11] == 0xff;
    if (mapped) {
        std::string out = "::ffff:" + FormatIpv4Address(address + 12);
        if (scopeId) out += "%" + std::to_string(scopeId);
        return out;
    }

    std::array<uint16_t, 8> words{};
    for (size_t i = 0; i < words.size(); ++i)
        words[i] = (uint16_t)((uint16_t)address[i * 2] << 8 | address[i * 2 + 1]);

    // RFC 5952: compress the first longest run of at least two zero words.
    size_t bestStart = words.size(), bestLength = 0;
    for (size_t i = 0; i < words.size();) {
        if (words[i]) { ++i; continue; }
        size_t end = i + 1;
        while (end < words.size() && words[end] == 0) ++end;
        if (end - i > bestLength && end - i >= 2) {
            bestStart = i;
            bestLength = end - i;
        }
        i = end;
    }

    std::string out;
    char word[5];
    for (size_t i = 0; i < words.size();) {
        if (i == bestStart) {
            out += "::";
            i += bestLength;
            if (i == words.size()) break;
            continue;
        }
        if (!out.empty() && out.back() != ':') out.push_back(':');
        std::snprintf(word, sizeof(word), "%x", (unsigned)words[i]);
        out += word;
        ++i;
    }
    if (out.empty()) out = "::";
    if (scopeId) out += "%" + std::to_string(scopeId);
    return out;
}

std::string FormatIpv4Endpoint(const uint8_t address[4], uint16_t hostPort) {
    return FormatIpv4Address(address) + ":" + std::to_string(hostPort);
}

std::string FormatIpv6Endpoint(const uint8_t address[16], uint16_t hostPort,
                               uint32_t scopeId) {
    return "[" + FormatIpv6Address(address, scopeId) + "]:" + std::to_string(hostPort);
}

} // namespace ds
