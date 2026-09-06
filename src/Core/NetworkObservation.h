#pragma once
//
// NetworkObservation.h
// Pure, bounded contracts and state helpers for guided live network observation.
// No Win32 types are used here: Debugger translates stopped-thread registers and
// ReadProcessMemory into NetworkCallContext/NetworkMemoryReader.

#include "NetworkEndpoint.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ds {

inline constexpr size_t kNetworkObservationEventCap = 2000;
inline constexpr size_t kNetworkObservationPayloadCap = 64u * 1024u;
inline constexpr size_t kNetworkObservationRetainedPayloadCap = 32u * 1024u * 1024u;
inline constexpr size_t kNetworkObservationTextCap = 1024;
inline constexpr size_t kNetworkObservationPendingCap = 512;
inline constexpr size_t kNetworkObservationPerThreadDepth = 16;
inline constexpr size_t kNetworkObservationHandleCap = 4096;
inline constexpr uint64_t kNetworkHttpAsyncFlag = 0x10000000u; // WinHTTP/WinINet

inline constexpr bool NetworkHttpSessionIsAsync(uint64_t flags) {
    return (flags & kNetworkHttpAsyncFlag) != 0;
}

enum class NetworkProbeApi : uint8_t {
    Unknown = 0,
    ResolveAddrInfoA, ResolveAddrInfoW, GetAddrInfoExA, GetAddrInfoExW,
    GetHostByName, GetNameInfoA, GetNameInfoW,
    DnsQueryA, DnsQueryW, DnsQueryUtf8,
    Connect, WSAConnect,
    Send, Recv, WSASend, WSARecv, SendTo, RecvFrom, WSASendTo, WSARecvFrom, CloseSocket,
    WinHttpOpen, WinHttpConnect, WinHttpOpenRequest, WinHttpAddRequestHeaders,
    WinHttpSendRequest, WinHttpReceiveResponse,
    WinHttpWriteData, WinHttpReadData, WinHttpQueryHeaders, WinHttpCloseHandle,
    InternetOpenA, InternetOpenW, InternetConnectA, InternetConnectW,
    HttpOpenRequestA, HttpOpenRequestW, HttpAddRequestHeadersA, HttpAddRequestHeadersW,
    HttpSendRequestA, HttpSendRequestW, InternetOpenUrlA, InternetOpenUrlW,
    HttpSendRequestExA, HttpSendRequestExW, HttpEndRequestA, HttpEndRequestW,
    InternetWriteFile, InternetReadFile, InternetReadFileExA, InternetReadFileExW,
    HttpQueryInfoA, HttpQueryInfoW,
    InternetCloseHandle, UrlDownloadToFileA, UrlDownloadToFileW,
    UrlDownloadToCacheFileA, UrlDownloadToCacheFileW,
    UrlOpenStreamA, UrlOpenStreamW, UrlOpenBlockingStreamA, UrlOpenBlockingStreamW,
    Count,
};

// One authoritative identity for every live probe.  The debugger uses this for
// export resolution and display, so a probe cannot silently acquire a different
// DLL/name spelling in those two paths.  Unknown/Count deliberately have no
// descriptor and can never be armed.
struct NetworkProbeDescriptor {
    NetworkProbeApi api = NetworkProbeApi::Unknown;
    const char* dll = "";
    const char* symbol = "";
};

inline constexpr std::array<NetworkProbeDescriptor,
                            static_cast<size_t>(NetworkProbeApi::Count)>
    kNetworkProbeDescriptors{{
        {NetworkProbeApi::Unknown, "", ""},
        {NetworkProbeApi::ResolveAddrInfoA, "ws2_32.dll", "getaddrinfo"},
        {NetworkProbeApi::ResolveAddrInfoW, "ws2_32.dll", "GetAddrInfoW"},
        {NetworkProbeApi::GetAddrInfoExA, "ws2_32.dll", "GetAddrInfoExA"},
        {NetworkProbeApi::GetAddrInfoExW, "ws2_32.dll", "GetAddrInfoExW"},
        {NetworkProbeApi::GetHostByName, "ws2_32.dll", "gethostbyname"},
        {NetworkProbeApi::GetNameInfoA, "ws2_32.dll", "getnameinfo"},
        {NetworkProbeApi::GetNameInfoW, "ws2_32.dll", "GetNameInfoW"},
        {NetworkProbeApi::DnsQueryA, "dnsapi.dll", "DnsQuery_A"},
        {NetworkProbeApi::DnsQueryW, "dnsapi.dll", "DnsQuery_W"},
        {NetworkProbeApi::DnsQueryUtf8, "dnsapi.dll", "DnsQuery_UTF8"},
        {NetworkProbeApi::Connect, "ws2_32.dll", "connect"},
        {NetworkProbeApi::WSAConnect, "ws2_32.dll", "WSAConnect"},
        {NetworkProbeApi::Send, "ws2_32.dll", "send"},
        {NetworkProbeApi::Recv, "ws2_32.dll", "recv"},
        {NetworkProbeApi::WSASend, "ws2_32.dll", "WSASend"},
        {NetworkProbeApi::WSARecv, "ws2_32.dll", "WSARecv"},
        {NetworkProbeApi::SendTo, "ws2_32.dll", "sendto"},
        {NetworkProbeApi::RecvFrom, "ws2_32.dll", "recvfrom"},
        {NetworkProbeApi::WSASendTo, "ws2_32.dll", "WSASendTo"},
        {NetworkProbeApi::WSARecvFrom, "ws2_32.dll", "WSARecvFrom"},
        {NetworkProbeApi::CloseSocket, "ws2_32.dll", "closesocket"},
        {NetworkProbeApi::WinHttpOpen, "winhttp.dll", "WinHttpOpen"},
        {NetworkProbeApi::WinHttpConnect, "winhttp.dll", "WinHttpConnect"},
        {NetworkProbeApi::WinHttpOpenRequest, "winhttp.dll", "WinHttpOpenRequest"},
        {NetworkProbeApi::WinHttpAddRequestHeaders, "winhttp.dll", "WinHttpAddRequestHeaders"},
        {NetworkProbeApi::WinHttpSendRequest, "winhttp.dll", "WinHttpSendRequest"},
        {NetworkProbeApi::WinHttpReceiveResponse, "winhttp.dll", "WinHttpReceiveResponse"},
        {NetworkProbeApi::WinHttpWriteData, "winhttp.dll", "WinHttpWriteData"},
        {NetworkProbeApi::WinHttpReadData, "winhttp.dll", "WinHttpReadData"},
        {NetworkProbeApi::WinHttpQueryHeaders, "winhttp.dll", "WinHttpQueryHeaders"},
        {NetworkProbeApi::WinHttpCloseHandle, "winhttp.dll", "WinHttpCloseHandle"},
        {NetworkProbeApi::InternetOpenA, "wininet.dll", "InternetOpenA"},
        {NetworkProbeApi::InternetOpenW, "wininet.dll", "InternetOpenW"},
        {NetworkProbeApi::InternetConnectA, "wininet.dll", "InternetConnectA"},
        {NetworkProbeApi::InternetConnectW, "wininet.dll", "InternetConnectW"},
        {NetworkProbeApi::HttpOpenRequestA, "wininet.dll", "HttpOpenRequestA"},
        {NetworkProbeApi::HttpOpenRequestW, "wininet.dll", "HttpOpenRequestW"},
        {NetworkProbeApi::HttpAddRequestHeadersA, "wininet.dll", "HttpAddRequestHeadersA"},
        {NetworkProbeApi::HttpAddRequestHeadersW, "wininet.dll", "HttpAddRequestHeadersW"},
        {NetworkProbeApi::HttpSendRequestA, "wininet.dll", "HttpSendRequestA"},
        {NetworkProbeApi::HttpSendRequestW, "wininet.dll", "HttpSendRequestW"},
        {NetworkProbeApi::InternetOpenUrlA, "wininet.dll", "InternetOpenUrlA"},
        {NetworkProbeApi::InternetOpenUrlW, "wininet.dll", "InternetOpenUrlW"},
        {NetworkProbeApi::HttpSendRequestExA, "wininet.dll", "HttpSendRequestExA"},
        {NetworkProbeApi::HttpSendRequestExW, "wininet.dll", "HttpSendRequestExW"},
        {NetworkProbeApi::HttpEndRequestA, "wininet.dll", "HttpEndRequestA"},
        {NetworkProbeApi::HttpEndRequestW, "wininet.dll", "HttpEndRequestW"},
        {NetworkProbeApi::InternetWriteFile, "wininet.dll", "InternetWriteFile"},
        {NetworkProbeApi::InternetReadFile, "wininet.dll", "InternetReadFile"},
        {NetworkProbeApi::InternetReadFileExA, "wininet.dll", "InternetReadFileExA"},
        {NetworkProbeApi::InternetReadFileExW, "wininet.dll", "InternetReadFileExW"},
        {NetworkProbeApi::HttpQueryInfoA, "wininet.dll", "HttpQueryInfoA"},
        {NetworkProbeApi::HttpQueryInfoW, "wininet.dll", "HttpQueryInfoW"},
        {NetworkProbeApi::InternetCloseHandle, "wininet.dll", "InternetCloseHandle"},
        {NetworkProbeApi::UrlDownloadToFileA, "urlmon.dll", "URLDownloadToFileA"},
        {NetworkProbeApi::UrlDownloadToFileW, "urlmon.dll", "URLDownloadToFileW"},
        {NetworkProbeApi::UrlDownloadToCacheFileA, "urlmon.dll", "URLDownloadToCacheFileA"},
        {NetworkProbeApi::UrlDownloadToCacheFileW, "urlmon.dll", "URLDownloadToCacheFileW"},
        {NetworkProbeApi::UrlOpenStreamA, "urlmon.dll", "URLOpenStreamA"},
        {NetworkProbeApi::UrlOpenStreamW, "urlmon.dll", "URLOpenStreamW"},
        {NetworkProbeApi::UrlOpenBlockingStreamA, "urlmon.dll", "URLOpenBlockingStreamA"},
        {NetworkProbeApi::UrlOpenBlockingStreamW, "urlmon.dll", "URLOpenBlockingStreamW"},
    }};

inline constexpr const NetworkProbeDescriptor*
NetworkProbeDescriptorFor(NetworkProbeApi api) {
    const size_t index = static_cast<size_t>(api);
    if (api == NetworkProbeApi::Unknown || index >= kNetworkProbeDescriptors.size())
        return nullptr;
    const NetworkProbeDescriptor& descriptor = kNetworkProbeDescriptors[index];
    return descriptor.api == api && descriptor.dll[0] && descriptor.symbol[0]
         ? &descriptor : nullptr;
}

inline constexpr bool NetworkProbeDescriptorsAreIndexed() {
    if (kNetworkProbeDescriptors[0].api != NetworkProbeApi::Unknown) return false;
    for (size_t i = 1; i < kNetworkProbeDescriptors.size(); ++i) {
        if (static_cast<size_t>(kNetworkProbeDescriptors[i].api) != i ||
            !kNetworkProbeDescriptors[i].dll[0] ||
            !kNetworkProbeDescriptors[i].symbol[0])
            return false;
    }
    return true;
}
static_assert(NetworkProbeDescriptorsAreIndexed(),
              "live network probe descriptors must exactly cover the enum");

enum class NetworkDirection : uint8_t { None = 0, Outbound, Inbound };
enum class NetworkEvidenceQuality : uint8_t { Unknown = 0, Heuristic, Observed, Proven };

enum class NetworkObservationStage : uint8_t {
    ProbeStatus = 0,
    NameResolution,
    Connect,
    Request,
    Response,
    Send,
    Receive,
    HandleClosed,
    Limitation,
};

inline constexpr size_t NetworkOverlappedArgumentIndex(NetworkProbeApi api) {
    switch (api) {
        case NetworkProbeApi::WSASend: return 5;
        case NetworkProbeApi::WSASendTo: return 7;
        case NetworkProbeApi::WSARecv: return 5;
        case NetworkProbeApi::WSARecvFrom: return 7;
        default: return static_cast<size_t>(-1);
    }
}

struct NetworkObservationEvent {
    uint64_t sequence = 0;
    uint64_t sessionGeneration = 0;
    uint32_t tickMs = 0;
    uint32_t pid = 0;
    uint32_t tid = 0;
    NetworkProbeApi api = NetworkProbeApi::Unknown;
    NetworkObservationStage stage = NetworkObservationStage::ProbeStatus;
    NetworkDirection direction = NetworkDirection::None;
    NetworkEvidenceQuality evidenceQuality = NetworkEvidenceQuality::Observed;
    uint64_t caller = 0;       // return address at the probed API entry
    std::string runtimeModule;
    uint64_t runtimeModuleBase = 0;
    // Monotone within one debugger session. A DLL may unload and a replacement
    // mapping may reuse the same base/path/size, so those coordinates alone do
    // not authorize navigation or static correlation for a retained event.
    uint64_t runtimeModuleLoadGeneration = 0;
    bool fileOffsetValid = false;
    uint64_t fileOffset = 0;   // offset projected from observed live PE headers
    std::string mappingEvidence;
    uint64_t handle = 0;       // socket/HINTERNET when applicable
    int64_t result = 0;        // legacy signed projection; prefer rawResult + resultValid
    uint64_t rawResult = 0;    // exact EAX/RAX return register, including valid zero
    bool resultValid = false;
    uint8_t pointerWidthBits = 0; // 32 for WOW64, 64 for a native x64 observation
    std::string hostname;
    std::string ip;            // canonical numeric address, without port/brackets
    uint16_t port = 0;
    bool portValid = false;    // preserves a valid observed port value of zero
    std::string endpoint;
    std::string method;
    std::string path;          // request path/query; URL object remains below for compatibility
    std::string object;
    std::string detail;
    uint64_t requestedBytes = 0; // caller-provided input/body size, not completion evidence
    bool requestedBytesValid = false;
    uint32_t transferred = 0;  // API/out-parameter reported bytes, including valid zero
    bool transferredValid = false;
    bool truncated = false;
    bool payloadOpaque = false; // encrypted/custom TLS or otherwise not decoded
    bool asyncPartial = false;  // async/overlapped completion may outlive API return
    std::vector<uint8_t> payload;
};

// Fail closed when correlating a retained observation with a currently loaded
// module. Zero remains "unproven" for both generations and for image extent.
inline constexpr bool NetworkObservationEventMatchesMapping(
    const NetworkObservationEvent& event,
    uint32_t pid,
    uint64_t sessionGeneration,
    uint64_t moduleBase,
    uint64_t moduleSize,
    uint64_t moduleLoadGeneration) {
    return pid != 0 && event.pid == pid &&
           sessionGeneration != 0 &&
           event.sessionGeneration == sessionGeneration &&
           moduleBase != 0 && event.runtimeModuleBase == moduleBase &&
           moduleSize != 0 && event.caller >= moduleBase &&
           event.caller - moduleBase < moduleSize &&
           moduleLoadGeneration != 0 &&
           event.runtimeModuleLoadGeneration == moduleLoadGeneration;
}

// Capture the architectural return register without using zero as an
// unavailable sentinel.  WOW64 observations intentionally discard the stale
// upper half of RAX; native x64 pointer/handle returns retain all 64 bits.
inline constexpr void SetNetworkObservedRawResult(NetworkObservationEvent& event,
                                                  uint64_t registerValue,
                                                  bool wow64) {
    event.rawResult = wow64 ? static_cast<uint32_t>(registerValue) : registerValue;
    event.resultValid = true;
    event.pointerWidthBits = wow64 ? 32u : 64u;
}

struct NetworkProbeCoverage {
    uint64_t sessionGeneration = 0;
    uint32_t pid = 0;
    bool requested = false;
    bool active = false;
    bool wow64 = false;
    uint32_t probesAvailable = 0;
    uint32_t probesArmed = 0;
    uint32_t probesSharedWithUserBreakpoints = 0;
    uint32_t probesSkipped = 0;
    uint32_t eventsDropped = 0;
    uint64_t retainedPayloadBytes = 0;
    uint64_t payloadBytesDropped = 0;
    uint32_t pendingReturnsDropped = 0;
    uint32_t handleStatesDropped = 0;
    bool winsock = false;
    bool nameResolution = false;
    bool winHttp = false;
    bool winInet = false;
    bool urlMon = false;
    bool payloads = false;
    bool asyncPartial = true;
    bool customTlsOpaque = true;
    std::vector<std::string> limitations;
};

struct NetworkObservation {
    NetworkProbeCoverage coverage;
    std::vector<NetworkObservationEvent> events; // oldest -> newest, bounded
};

using NetworkMemoryReader = std::function<bool(uint64_t, void*, size_t)>;

// At an x64 Windows call entry the first four arguments are in RCX/RDX/R8/R9;
// argument five starts at [RSP+0x28]. At an x86 call entry every argument starts
// at [ESP+4]. registerArgs carries the x64 register quartet.
struct NetworkCallContext {
    bool wow64 = false;
    uint64_t stackPointer = 0;
    std::array<uint64_t, 4> registerArgs{};
};

inline bool ReadNetworkPointer(const NetworkCallContext& context,
                               const NetworkMemoryReader& read,
                               uint64_t address, uint64_t& value) {
    value = 0;
    if (!read || !address) return false;
    if (context.wow64) {
        uint32_t narrow = 0;
        if (!read(address, &narrow, sizeof(narrow))) return false;
        value = narrow;
        return true;
    }
    return read(address, &value, sizeof(value));
}

inline bool ReadNetworkReturnAddress(const NetworkCallContext& context,
                                     const NetworkMemoryReader& read,
                                     uint64_t& value) {
    return ReadNetworkPointer(context, read, context.stackPointer, value);
}

inline bool ReadNetworkArgument(const NetworkCallContext& context, size_t index,
                                const NetworkMemoryReader& read, uint64_t& value) {
    value = 0;
    if (!context.wow64 && index < context.registerArgs.size()) {
        value = context.registerArgs[index];
        return true;
    }
    const uint64_t pointerSize = context.wow64 ? 4u : 8u;
    // Both ABIs keep the return address in slot zero. On x64 this path is
    // reached only for index >= 4, after the four-register home area, so
    // index+1 maps argument five to [RSP+0x28].
    const uint64_t slot = index + 1u;
    if (slot > (UINT64_MAX - context.stackPointer) / pointerSize) return false;
    return ReadNetworkPointer(context, read,
                              context.stackPointer + slot * pointerSize, value);
}

inline std::string BoundNetworkText(std::string value,
                                    size_t cap = kNetworkObservationTextCap) {
    if (value.size() > cap) value.resize(cap);
    return value;
}

inline bool NetworkLooksLikeIpv4(std::string_view value) {
    if (value.empty()) return false;
    size_t start = 0;
    unsigned parts = 0;
    while (start <= value.size()) {
        const size_t end = value.find('.', start);
        const size_t stop = end == std::string_view::npos ? value.size() : end;
        if (stop == start || stop - start > 3 || parts == 4) return false;
        unsigned number = 0;
        for (size_t i = start; i < stop; ++i) {
            if (value[i] < '0' || value[i] > '9') return false;
            number = number * 10u + static_cast<unsigned>(value[i] - '0');
        }
        if (number > 255) return false;
        ++parts;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return parts == 4;
}

inline bool NetworkLooksLikeIpv6(std::string_view value) {
    if (value.empty() || value.size() > 128) return false;
    if (value.size() >= 2 && value.front() == '[' && value.back() == ']')
        value = value.substr(1, value.size() - 2);
    if (const size_t scope = value.find('%'); scope != std::string_view::npos) {
        if (scope + 1 == value.size()) return false;
        for (char ch : value.substr(scope + 1)) {
            const bool allowed = (ch >= '0' && ch <= '9') ||
                                 (ch >= 'a' && ch <= 'z') ||
                                 (ch >= 'A' && ch <= 'Z') ||
                                 ch == '_' || ch == '-' || ch == '.';
            if (!allowed) return false;
        }
        value = value.substr(0, scope);
    }
    if (value.empty()) return false;

    if (value.find(":::") != std::string_view::npos) return false;
    const size_t compressed = value.find("::");
    if (compressed != std::string_view::npos &&
        value.find("::", compressed + 2) != std::string_view::npos)
        return false;
    if (compressed == std::string_view::npos &&
        (value.front() == ':' || value.back() == ':'))
        return false;

    size_t units = 0;
    bool ipv4Tail = false;
    auto parsePart = [&](std::string_view part, bool finalPart) {
        if (part.empty()) return false;
        if (part.find('.') != std::string_view::npos) {
            if (!finalPart || ipv4Tail || !NetworkLooksLikeIpv4(part)) return false;
            ipv4Tail = true;
            units += 2;
            return units <= 8;
        }
        if (part.size() > 4) return false;
        for (char ch : part) {
            const bool hex = (ch >= '0' && ch <= '9') ||
                             (ch >= 'a' && ch <= 'f') ||
                             (ch >= 'A' && ch <= 'F');
            if (!hex) return false;
        }
        ++units;
        return units <= 8;
    };
    auto parseRange = [&](size_t begin, size_t end) {
        size_t cursor = begin;
        while (cursor < end) {
            const size_t colon = value.find(':', cursor);
            const size_t stop = colon == std::string_view::npos || colon > end ? end : colon;
            if (!parsePart(value.substr(cursor, stop - cursor), stop == value.size()))
                return false;
            cursor = stop;
            if (cursor < end) ++cursor;
        }
        return true;
    };

    if (compressed == std::string_view::npos)
        return parseRange(0, value.size()) && units == 8;
    if (!parseRange(0, compressed) ||
        !parseRange(compressed + 2, value.size()))
        return false;
    return units < 8; // `::` must compress at least one 16-bit unit.
}

inline bool NetworkLooksLikeIp(std::string_view value) {
    return NetworkLooksLikeIpv4(value) || NetworkLooksLikeIpv6(value);
}

struct NetworkUrlParts {
    std::string hostname;
    std::string ip;
    uint16_t port = 0;
    bool portValid = false;
    std::string path;
};

// Bounded, allocation-light parsing for the HTTP(S) URLs passed to WinINet and
// URLMon. It intentionally extracts only fields used by observation/search.
inline bool ParseNetworkUrl(std::string_view url, NetworkUrlParts& parts) {
    parts = {};
    const size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string_view::npos || !schemeEnd) return false;
    std::string scheme(url.substr(0, schemeEnd));
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char ch) {
        return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch);
    });
    const bool http = scheme == "http";
    const bool https = scheme == "https";
    if (!http && !https) return false;
    const size_t authorityStart = schemeEnd + 3;
    const size_t suffix = url.find_first_of("/?#", authorityStart);
    std::string_view authority = url.substr(
        authorityStart, suffix == std::string_view::npos ? std::string_view::npos
                                                         : suffix - authorityStart);
    if (const size_t user = authority.rfind('@'); user != std::string_view::npos)
        authority.remove_prefix(user + 1);
    if (authority.empty()) return false;

    std::string_view host;
    std::string_view portText;
    bool bracketedIpv6 = false;
    if (authority.front() == '[') {
        bracketedIpv6 = true;
        const size_t close = authority.find(']');
        if (close == std::string_view::npos || close == 1) return false;
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return false;
            portText = authority.substr(close + 2);
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos && authority.find(':') == colon) {
            host = authority.substr(0, colon);
            portText = authority.substr(colon + 1);
        } else {
            host = authority;
        }
    }
    if (host.empty()) return false;
    if (bracketedIpv6 && !NetworkLooksLikeIpv6(host)) return false;
    parts.hostname = BoundNetworkText(std::string(host));
    if (NetworkLooksLikeIp(host)) parts.ip = parts.hostname;

    if (!portText.empty()) {
        uint32_t value = 0;
        for (char ch : portText) {
            if (ch < '0' || ch > '9') return false;
            value = value * 10u + static_cast<uint32_t>(ch - '0');
            if (value > 65535u) return false;
        }
        parts.port = static_cast<uint16_t>(value);
        parts.portValid = true;
    } else {
        parts.port = static_cast<uint16_t>(https ? 443u : 80u);
        parts.portValid = true;
    }

    if (suffix == std::string_view::npos) parts.path = "/";
    else if (url[suffix] == '/') parts.path = std::string(url.substr(suffix));
    else parts.path = "/" + std::string(url.substr(suffix));
    parts.path = BoundNetworkText(std::move(parts.path));
    return true;
}

struct NetworkEndpointParts {
    std::string endpoint;
    std::string ip;
    uint16_t port = 0;
    bool portValid = false;
};

inline bool DecodeNetworkSockaddr(const uint8_t* bytes, size_t size,
                                  NetworkEndpointParts& parts) {
    parts = {};
    if (!bytes || size < 2) return false;
    const uint16_t family = static_cast<uint16_t>(bytes[0]) |
                            (static_cast<uint16_t>(bytes[1]) << 8);
    if (family == 2 && size >= 8) { // sockaddr_in
        const uint16_t port = static_cast<uint16_t>(bytes[2] << 8) | bytes[3];
        parts.ip = FormatIpv4Address(bytes + 4);
        parts.port = port;
        parts.portValid = true;
        parts.endpoint = FormatIpv4Endpoint(bytes + 4, port);
        return true;
    }
    if (family == 23 && size >= 28) { // sockaddr_in6
        const uint16_t port = static_cast<uint16_t>(bytes[2] << 8) | bytes[3];
        const uint32_t scope = static_cast<uint32_t>(bytes[24]) |
                               (static_cast<uint32_t>(bytes[25]) << 8) |
                               (static_cast<uint32_t>(bytes[26]) << 16) |
                               (static_cast<uint32_t>(bytes[27]) << 24);
        parts.ip = FormatIpv6Address(bytes + 8, scope);
        parts.port = port;
        parts.portValid = true;
        parts.endpoint = FormatIpv6Endpoint(bytes + 8, port, scope);
        return true;
    }
    return false;
}

inline bool DecodeNetworkSockaddr(const uint8_t* bytes, size_t size,
                                  std::string& endpoint) {
    NetworkEndpointParts parts;
    const bool decoded = DecodeNetworkSockaddr(bytes, size, parts);
    endpoint = std::move(parts.endpoint);
    return decoded;
}

enum class NetworkHandleKind : uint8_t { Session, Connection, Request, Socket };

struct NetworkHandleRecord {
    NetworkHandleKind kind = NetworkHandleKind::Session;
    uint64_t parent = 0;
    std::string hostname;
    std::string ip;
    uint16_t port = 0;
    bool portValid = false;
    std::string method;
    std::string path;
    std::string object;
    std::string endpoint;
    bool async = false; // inherited WINHTTP_FLAG_ASYNC / INTERNET_FLAG_ASYNC
};

class NetworkHandleLineage {
public:
    bool put(uint64_t handle, NetworkHandleRecord record) {
        if (!handle) return false;
        if (!records_.count(handle) && records_.size() >= kNetworkObservationHandleCap) {
            if (rejected_ != UINT64_MAX) ++rejected_;
            return false;
        }
        record.hostname = BoundNetworkText(std::move(record.hostname));
        record.ip = BoundNetworkText(std::move(record.ip));
        record.method = BoundNetworkText(std::move(record.method));
        record.path = BoundNetworkText(std::move(record.path));
        record.object = BoundNetworkText(std::move(record.object));
        record.endpoint = BoundNetworkText(std::move(record.endpoint));
        records_[handle] = std::move(record);
        return true;
    }

    const NetworkHandleRecord* find(uint64_t handle) const {
        auto it = records_.find(handle);
        return it == records_.end() ? nullptr : &it->second;
    }

    NetworkHandleRecord resolve(uint64_t handle) const {
        NetworkHandleRecord result;
        std::array<uint64_t, 8> seen{};
        size_t depth = 0;
        while (handle && depth < seen.size()) {
            if (std::find(seen.begin(), seen.begin() + depth, handle) !=
                seen.begin() + depth) break;
            seen[depth++] = handle;
            const NetworkHandleRecord* record = find(handle);
            if (!record) break;
            if (result.hostname.empty()) result.hostname = record->hostname;
            if (result.ip.empty()) result.ip = record->ip;
            if (!result.portValid && record->portValid) {
                result.port = record->port;
                result.portValid = true;
            }
            if (result.method.empty()) result.method = record->method;
            if (result.path.empty()) result.path = record->path;
            if (result.object.empty()) result.object = record->object;
            if (result.endpoint.empty()) result.endpoint = record->endpoint;
            result.async = result.async || record->async;
            result.kind = record->kind;
            handle = record->parent;
        }
        return result;
    }

    void erase(uint64_t handle) {
        if (!handle) return;
        std::vector<uint64_t> pending{handle};
        std::unordered_set<uint64_t> doomed;
        doomed.reserve(records_.size() + 1);
        for (size_t cursor = 0;
             cursor < pending.size() && cursor <= kNetworkObservationHandleCap;
             ++cursor) {
            const uint64_t parent = pending[cursor];
            if (!doomed.insert(parent).second) continue;
            for (const auto& [child, record] : records_)
                if (record.parent == parent && !doomed.count(child))
                    pending.push_back(child);
        }
        for (uint64_t doomedHandle : doomed) records_.erase(doomedHandle);
    }
    void clear() { records_.clear(); rejected_ = 0; }
    size_t size() const { return records_.size(); }
    uint64_t rejected() const { return rejected_; }

private:
    std::unordered_map<uint64_t, NetworkHandleRecord> records_;
    uint64_t rejected_ = 0;
};

inline uint32_t NetworkHandleStatesDropped(const NetworkHandleLineage& lineage) {
    return static_cast<uint32_t>((std::min<uint64_t>)(lineage.rejected(), UINT32_MAX));
}

// Pure nesting/refcount state. Physical INT3 ownership remains in Debugger.
template <class Frame>
class NetworkReturnTracker {
public:
    bool push(uint32_t tid, uint64_t returnAddress, Frame frame) {
        if (!tid || !returnAddress || total_ >= kNetworkObservationPendingCap) return false;
        auto& stack = perThread_[tid];
        if (stack.size() >= kNetworkObservationPerThreadDepth) return false;
        frame.returnAddress = returnAddress;
        stack.push_back(std::move(frame));
        ++references_[returnAddress];
        ++total_;
        return true;
    }

    bool pop(uint32_t tid, uint64_t returnAddress, Frame& frame) {
        auto it = perThread_.find(tid);
        if (it == perThread_.end() || it->second.empty() ||
            it->second.back().returnAddress != returnAddress) return false;
        frame = std::move(it->second.back());
        it->second.pop_back();
        if (it->second.empty()) perThread_.erase(it);
        auto ref = references_.find(returnAddress);
        if (ref != references_.end() && --ref->second == 0) references_.erase(ref);
        --total_;
        return true;
    }

    size_t references(uint64_t address) const {
        auto it = references_.find(address);
        return it == references_.end() ? 0 : it->second;
    }
    std::vector<uint64_t> eraseThread(uint32_t tid) {
        return eraseThread(tid, [](const Frame&) {});
    }
    template <class OnErase>
    std::vector<uint64_t> eraseThread(uint32_t tid, OnErase&& onErase) {
        std::vector<uint64_t> exhausted;
        auto it = perThread_.find(tid);
        if (it == perThread_.end()) return exhausted;
        exhausted.reserve(it->second.size());
        for (const Frame& frame : it->second) {
            onErase(frame);
            auto ref = references_.find(frame.returnAddress);
            if (ref != references_.end() && --ref->second == 0) {
                exhausted.push_back(frame.returnAddress);
                references_.erase(ref);
            }
            --total_;
        }
        perThread_.erase(it);
        return exhausted;
    }
    size_t eraseAddress(uint64_t address) {
        return eraseAddress(address, [](const Frame&) {});
    }
    template <class OnErase>
    size_t eraseAddress(uint64_t address, OnErase&& onErase) {
        size_t erased = 0;
        for (auto thread = perThread_.begin(); thread != perThread_.end(); ) {
            auto& frames = thread->second;
            const size_t before = frames.size();
            frames.erase(std::remove_if(frames.begin(), frames.end(),
                                        [address, &onErase](const Frame& frame) {
                                            if (frame.returnAddress != address) return false;
                                            onErase(frame);
                                            return true;
                                        }),
                         frames.end());
            erased += before - frames.size();
            if (frames.empty()) thread = perThread_.erase(thread);
            else ++thread;
        }
        if (erased) {
            references_.erase(address);
            total_ -= erased;
        }
        return erased;
    }
    size_t total() const { return total_; }
    void clear() { perThread_.clear(); references_.clear(); total_ = 0; }

private:
    std::unordered_map<uint32_t, std::vector<Frame>> perThread_;
    std::unordered_map<uint64_t, size_t> references_;
    size_t total_ = 0;
};

} // namespace ds
