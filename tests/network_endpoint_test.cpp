#include "Core/NetworkEndpoint.h"
#include "Core/NetworkObservation.h"

#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>

using namespace ds;

static int failures = 0;
static void check(const std::string& got, const char* expected) {
    if (got != expected) {
        std::cerr << "expected " << expected << ", got " << got << "\n";
        ++failures;
    }
}

static void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << "\n";
        ++failures;
    }
}

struct ReturnFrame {
    uint64_t returnAddress = 0;
    int tag = 0;
    size_t retained = 0;
};

int main() {
    const uint8_t v4[] = {127, 0, 0, 1};
    check(FormatIpv4Address(v4), "127.0.0.1");
    check(FormatIpv4Endpoint(v4, 443), "127.0.0.1:443");

    const uint8_t any[16] = {};
    check(FormatIpv6Address(any), "::");
    check(FormatIpv6Endpoint(any, 0), "[::]:0");

    const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    check(FormatIpv6Address(loopback), "::1");
    check(FormatIpv6Endpoint(loopback, 5005), "[::1]:5005");

    const uint8_t documentation[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    check(FormatIpv6Address(documentation), "2001:db8::1");

    // Equal zero runs compress the first; a single zero word is not compressed.
    const uint8_t ties[16] = {0x20,1,0,0,0,0,0x12,0x34,0,0,0,0,0x56,0x78,0,1};
    check(FormatIpv6Address(ties), "2001::1234:0:0:5678:1");
    const uint8_t single[16] = {0x20,1,0x0d,0xb8,0,0,0,1,0,2,0,3,0,4,0,5};
    check(FormatIpv6Address(single), "2001:db8:0:1:2:3:4:5");

    const uint8_t linkLocal[16] = {0xfe,0x80,0,0,0,0,0,0,0x12,0x34,0,0,0,0,0,1};
    check(FormatIpv6Address(linkLocal, 17), "fe80::1234:0:0:1%17");
    check(FormatIpv6Endpoint(linkLocal, 5353, 17), "[fe80::1234:0:0:1%17]:5353");

    const uint8_t mapped[16] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff,192,0,2,128};
    check(FormatIpv6Address(mapped), "::ffff:192.0.2.128");

    require(kNetworkObservationEventCap == 2000, "network event cap must remain exactly 2,000");
    require(kNetworkObservationRetainedPayloadCap == 32u * 1024u * 1024u,
            "network retained-payload cap must remain exactly 32 MiB");
    require(!NetworkHttpSessionIsAsync(0) &&
            NetworkHttpSessionIsAsync(kNetworkHttpAsyncFlag),
            "WinHTTP/WinINet async-session flag decode failed");
    require(NetworkOverlappedArgumentIndex(NetworkProbeApi::WSASend) == 5 &&
            NetworkOverlappedArgumentIndex(NetworkProbeApi::WSASendTo) == 7 &&
            NetworkOverlappedArgumentIndex(NetworkProbeApi::WSARecv) == 5 &&
            NetworkOverlappedArgumentIndex(NetworkProbeApi::WSARecvFrom) == 7,
            "Winsock overlapped-argument ABI indices regressed");

    require(NetworkProbeDescriptorFor(NetworkProbeApi::Unknown) == nullptr &&
            NetworkProbeDescriptorFor(NetworkProbeApi::Count) == nullptr,
            "non-probe enum values unexpectedly acquired an export descriptor");
    bool exactProbeDescriptors = true;
    for (size_t i = 1; i < kNetworkProbeDescriptors.size(); ++i) {
        const NetworkProbeApi api = static_cast<NetworkProbeApi>(i);
        const NetworkProbeDescriptor* descriptor = NetworkProbeDescriptorFor(api);
        exactProbeDescriptors &= descriptor && descriptor->api == api &&
                                 descriptor->dll[0] && descriptor->symbol[0];
    }
    require(exactProbeDescriptors,
            "live probe descriptor table does not exactly cover NetworkProbeApi");
    const NetworkProbeDescriptor* sendProbe =
        NetworkProbeDescriptorFor(NetworkProbeApi::Send);
    const NetworkProbeDescriptor* httpProbe =
        NetworkProbeDescriptorFor(NetworkProbeApi::WinHttpReadData);
    require(sendProbe && std::string(sendProbe->dll) == "ws2_32.dll" &&
            std::string(sendProbe->symbol) == "send" && httpProbe &&
            std::string(httpProbe->dll) == "winhttp.dll" &&
            std::string(httpProbe->symbol) == "WinHttpReadData",
            "live probe DLL/symbol identity mapping regressed");

    NetworkObservationEvent observedReturn;
    SetNetworkObservedRawResult(observedReturn, 0, false);
    require(observedReturn.resultValid && observedReturn.rawResult == 0 &&
            observedReturn.pointerWidthBits == 64,
            "a valid zero native return was confused with unavailable evidence");
    constexpr uint64_t fullWidthHandle = 0xFEDCBA9876543210ull;
    SetNetworkObservedRawResult(observedReturn, fullWidthHandle, false);
    require(observedReturn.resultValid &&
            observedReturn.rawResult == fullWidthHandle &&
            observedReturn.pointerWidthBits == 64,
            "a native 64-bit handle return was truncated or sign-projected");
    SetNetworkObservedRawResult(observedReturn, fullWidthHandle, true);
    require(observedReturn.resultValid && observedReturn.rawResult == 0x76543210u &&
            observedReturn.pointerWidthBits == 32,
            "a WOW64 return retained non-architectural upper RAX bits");
    observedReturn.requestedBytes = 0;
    observedReturn.requestedBytesValid = true;
    observedReturn.transferred = 0;
    observedReturn.transferredValid = true;
    require(observedReturn.requestedBytesValid && observedReturn.transferredValid,
            "valid zero byte counts lost their independent validity bits");

    std::unordered_map<uint64_t, uint8_t> memory;
    auto put = [&](uint64_t address, const auto& value) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(&value);
        for (size_t i = 0; i < sizeof(value); ++i) memory[address + i] = bytes[i];
    };
    const NetworkMemoryReader read = [&](uint64_t address, void* out, size_t size) {
        auto* bytes = static_cast<uint8_t*>(out);
        for (size_t i = 0; i < size; ++i) {
            auto found = memory.find(address + i);
            if (found == memory.end()) return false;
            bytes[i] = found->second;
        }
        return true;
    };

    NetworkCallContext x64;
    x64.stackPointer = 0x1000;
    x64.registerArgs = { 0x11, 0x22, 0x33, 0x44 };
    const uint64_t x64Return = 0x140001234;
    const uint64_t x64Arg5 = 0x5566778899AABBCCull;
    put(x64.stackPointer, x64Return);
    put(x64.stackPointer + 0x28, x64Arg5);
    uint64_t decoded = 0;
    require(ReadNetworkReturnAddress(x64, read, decoded) && decoded == x64Return,
            "x64 return-address decode failed");
    require(ReadNetworkArgument(x64, 0, read, decoded) && decoded == 0x11,
            "x64 register argument decode failed");
    require(ReadNetworkArgument(x64, 4, read, decoded) && decoded == x64Arg5,
            "x64 stack argument decode failed");

    NetworkCallContext x86;
    x86.wow64 = true;
    x86.stackPointer = 0x2000;
    const uint32_t x86Return = 0x401234;
    const uint32_t x86Arg1 = 0x12345678;
    const uint32_t x86Arg2 = 0x87654321;
    put(x86.stackPointer, x86Return);
    put(x86.stackPointer + 4, x86Arg1);
    put(x86.stackPointer + 8, x86Arg2);
    require(ReadNetworkReturnAddress(x86, read, decoded) && decoded == x86Return,
            "WOW64 return-address decode failed");
    require(ReadNetworkArgument(x86, 0, read, decoded) && decoded == x86Arg1,
            "WOW64 first stack argument decode failed");
    require(ReadNetworkArgument(x86, 1, read, decoded) && decoded == x86Arg2,
            "WOW64 second stack argument decode failed");

    const uint8_t sockaddr4[] = {2, 0, 0x01, 0xBB, 203, 0, 113, 9,
                                 0, 0, 0, 0, 0, 0, 0, 0};
    std::string endpoint;
    require(DecodeNetworkSockaddr(sockaddr4, sizeof(sockaddr4), endpoint) &&
            endpoint == "203.0.113.9:443", "sockaddr_in decode failed");
    NetworkEndpointParts endpointParts;
    require(DecodeNetworkSockaddr(sockaddr4, sizeof(sockaddr4), endpointParts) &&
            endpointParts.ip == "203.0.113.9" && endpointParts.portValid &&
            endpointParts.port == 443 && endpointParts.endpoint == endpoint,
            "sockaddr_in structured fields failed");
    uint8_t sockaddrPortZero[sizeof(sockaddr4)]{};
    std::memcpy(sockaddrPortZero, sockaddr4, sizeof(sockaddr4));
    sockaddrPortZero[2] = sockaddrPortZero[3] = 0;
    require(DecodeNetworkSockaddr(sockaddrPortZero, sizeof(sockaddrPortZero), endpointParts) &&
            endpointParts.portValid && endpointParts.port == 0,
            "valid observed port zero lost its validity bit");
    uint8_t sockaddr6[28] = {23, 0, 0x14, 0xE9, 0, 0, 0, 0};
    std::memcpy(sockaddr6 + 8, linkLocal, 16);
    sockaddr6[24] = 17;
    require(DecodeNetworkSockaddr(sockaddr6, sizeof(sockaddr6), endpoint) &&
            endpoint == "[fe80::1234:0:0:1%17]:5353", "sockaddr_in6 decode failed");
    require(DecodeNetworkSockaddr(sockaddr6, sizeof(sockaddr6), endpointParts) &&
            endpointParts.ip == "fe80::1234:0:0:1%17" &&
            endpointParts.portValid && endpointParts.port == 5353,
            "sockaddr_in6 structured fields failed");

    NetworkUrlParts url;
    require(ParseNetworkUrl("https://[2001:db8::1]:8443/check?id=7", url) &&
            url.hostname == "2001:db8::1" && url.ip == "2001:db8::1" &&
            url.portValid && url.port == 8443 && url.path == "/check?id=7",
            "structured IPv6 HTTPS URL parsing failed");
    require(ParseNetworkUrl("http://reply.example/serial-check", url) &&
            url.hostname == "reply.example" && url.ip.empty() &&
            url.portValid && url.port == 80 && url.path == "/serial-check",
            "structured hostname HTTP URL parsing failed");
    require(NetworkLooksLikeIpv6("::") && NetworkLooksLikeIpv6("2001:db8::1") &&
            NetworkLooksLikeIpv6("::ffff:192.0.2.128") &&
            NetworkLooksLikeIpv6("fe80::1%17"),
            "strict IPv6 validator rejected valid bounded forms");
    require(!NetworkLooksLikeIpv6("::::") &&
            !NetworkLooksLikeIpv6("dead::beef::1") &&
            !NetworkLooksLikeIpv6("1:::2") &&
            !NetworkLooksLikeIpv6("2001:db8:1") &&
            !NetworkLooksLikeIpv6("gggg::1"),
            "strict IPv6 validator accepted malformed forms");
    require(!ParseNetworkUrl("https://[::::]/bad", url) &&
            !ParseNetworkUrl("https://[dead::beef::1]/bad", url),
            "URL parser accepted malformed IPv6 authorities");

    NetworkHandleLineage lineage;
    NetworkHandleRecord session;
    session.kind = NetworkHandleKind::Session;
    session.async = true;
    require(lineage.put(1, session), "session lineage insert failed");
    NetworkHandleRecord connection;
    connection.kind = NetworkHandleKind::Connection;
    connection.parent = 1;
    connection.hostname = "reply.example";
    connection.ip = "203.0.113.9";
    connection.port = 443;
    connection.portValid = true;
    connection.endpoint = "203.0.113.9:443";
    require(lineage.put(2, connection), "connection lineage insert failed");
    NetworkHandleRecord request;
    request.kind = NetworkHandleKind::Request;
    request.parent = 2;
    request.method = "POST";
    request.path = "/check";
    request.object = "/check";
    require(lineage.put(3, request), "request lineage insert failed");
    const NetworkHandleRecord resolved = lineage.resolve(3);
    require(resolved.hostname == "reply.example" && resolved.ip == "203.0.113.9" &&
            resolved.portValid && resolved.port == 443 && resolved.method == "POST" &&
            resolved.path == "/check" && resolved.object == "/check" && resolved.async,
            "request ancestry did not resolve connection metadata");
    require(resolved.endpoint == "203.0.113.9:443",
            "request ancestry did not resolve socket/connection endpoint metadata");
    NetworkHandleRecord zeroPortConnection;
    zeroPortConnection.kind = NetworkHandleKind::Connection;
    zeroPortConnection.parent = 1;
    zeroPortConnection.hostname = "default-port.example";
    zeroPortConnection.port = 0;
    zeroPortConnection.portValid = true;
    require(lineage.put(4, zeroPortConnection) && lineage.resolve(4).portValid &&
            lineage.resolve(4).port == 0,
            "HTTP connection lineage lost an explicitly valid zero port");
    lineage.erase(1);
    require(lineage.find(1) == nullptr && lineage.find(2) == nullptr &&
            lineage.find(3) == nullptr && lineage.find(4) == nullptr,
            "session close did not retire transitive connection/request descendants");

    NetworkHandleLineage cappedLineage;
    bool allHandleStatesInserted = true;
    for (uint64_t handle = 1; handle <= kNetworkObservationHandleCap; ++handle)
        allHandleStatesInserted &= cappedLineage.put(handle, NetworkHandleRecord{});
    require(allHandleStatesInserted && cappedLineage.size() == kNetworkObservationHandleCap,
            "handle-lineage cap rejected an in-budget record");
    require(!cappedLineage.put(kNetworkObservationHandleCap + 1,
                               NetworkHandleRecord{}) &&
            cappedLineage.rejected() == 1 &&
            NetworkHandleStatesDropped(cappedLineage) == 1,
            "handle-lineage cap did not account the 4,097th record");
    require(cappedLineage.put(kNetworkObservationHandleCap, NetworkHandleRecord{}) &&
            cappedLineage.rejected() == 1,
            "bounded handle-lineage update was incorrectly rejected/accounted");

    NetworkReturnTracker<ReturnFrame> returns;
    require(returns.push(10, 0x5000, {0, 1}), "first nested return push failed");
    require(returns.push(10, 0x6000, {0, 2}), "second nested return push failed");
    ReturnFrame frame;
    require(!returns.pop(10, 0x5000, frame), "return tracker accepted a non-LIFO return");
    require(returns.pop(10, 0x6000, frame) && frame.tag == 2,
            "nested return tracker did not pop the top frame");
    require(returns.pop(10, 0x5000, frame) && frame.tag == 1,
            "nested return tracker lost the outer frame");
    require(returns.push(11, 0x7000, {0, 3}) && returns.push(12, 0x7000, {0, 4}) &&
            returns.references(0x7000) == 2, "shared return-site refcount failed");
    const std::vector<uint64_t> firstExit = returns.eraseThread(11);
    require(firstExit.empty() && returns.references(0x7000) == 1,
            "first shared-site thread exit retired a live peer reference");
    const std::vector<uint64_t> lastExit = returns.eraseThread(12);
    require(lastExit.size() == 1 && lastExit[0] == 0x7000 && returns.total() == 0,
            "last shared-site thread exit did not report the exhausted address");

    size_t retiredPayload = 0;
    require(returns.push(20, 0x8000, {0, 5, 17}) &&
            returns.push(21, 0x9000, {0, 6, 23}),
            "payload-accounting return setup failed");
    const std::vector<uint64_t> retiredThread = returns.eraseThread(
        20, [&](const ReturnFrame& retired) { retiredPayload += retired.retained; });
    require(retiredThread.size() == 1 && retiredThread[0] == 0x8000 &&
            retiredPayload == 17,
            "thread retirement did not report payload-bearing pending frames");
    require(returns.eraseAddress(
                0x9000, [&](const ReturnFrame& retired) {
                    retiredPayload += retired.retained;
                }) == 1 && retiredPayload == 40 && returns.total() == 0,
            "module/address retirement did not report payload-bearing pending frames");

    if (failures) return 1;
    std::cout << "network endpoint/observation tests passed\n";
    return 0;
}
