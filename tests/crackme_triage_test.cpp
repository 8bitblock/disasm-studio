#include "Core/CrackmeTriage.h"
#include "Core/AnalysisService.h"
#include "Core/BinaryFile.h"
#include "Core/XrefIndex.h"
#include "Disasm/ZydisDisassembler.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static size_t appendAscii(std::vector<uint8_t>& bytes, const std::string& value) {
    const size_t at = bytes.size();
    bytes.insert(bytes.end(), value.begin(), value.end());
    bytes.push_back(0);
    return at;
}

static size_t appendWide(std::vector<uint8_t>& bytes, const std::string& value) {
    const size_t at = bytes.size();
    for (unsigned char c : value) { bytes.push_back(c); bytes.push_back(0); }
    bytes.push_back(0); bytes.push_back(0);
    return at;
}

static const CrackmeTriageEndpoint* endpoint(const CrackmeTriageReport& report,
                                              const std::string& host) {
    for (const auto& item : report.endpoints) if (item.host == host) return &item;
    return nullptr;
}

static bool hasPath(const CrackmeTriageEndpoint& item, const char* path) {
    return std::find(item.paths.begin(), item.paths.end(), path) != item.paths.end();
}

static bool hasArtifact(const CrackmeTriageReport& report, NetworkArtifactKind kind) {
    for (const auto& item : report.artifacts) if (item.kind == kind) return true;
    return false;
}

static const CrackmeTrail* trailFor(const CrackmeTriageReport& report,
                                    const std::string& host) {
    for (const auto& trail : report.trails) {
        if (trail.endpointIndex < report.endpoints.size() &&
            report.endpoints[trail.endpointIndex].host == host)
            return &trail;
    }
    return nullptr;
}

static void realTargetAcceptance(const char* path) {
    BinaryFile binary;
    CHECK(binary.load(path));
    if (!binary.loaded()) return;

    Arch arch = Arch::X64;
    if (binary.machine() == MachineArch::X86) arch = Arch::X86;
    else if (binary.machine() != MachineArch::X64) {
        CHECK(false); // this acceptance uses the real x86/x64 Zydis pipeline
        return;
    }

    AnalysisService service(AnalysisService::DecoderFactory{
        [](const DecoderConfig& config) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<ZydisDisassembler>(config);
        }}, 1);
    const uint64_t epoch = service.epoch();
    const auto started = std::chrono::steady_clock::now();
    service.requestBulk(&binary, Engine::Zydis, arch,
                        K_CrackmeTriage, false, epoch);

    AnalysisResult analysis;
    const auto deadline = started + std::chrono::seconds(120);
    while (std::chrono::steady_clock::now() < deadline &&
           !analysis.crackmeTriageValid) {
        AnalysisResult next;
        while (service.tryTakeBulk(next)) {
            if (next.epoch != epoch) continue;
            if (next.failureValid)
                std::printf("real target analysis failure: %s\n", next.failure.c_str());
            if (next.crackmeTriageValid) {
                analysis = std::move(next);
                break;
            }
        }
        if (!analysis.crackmeTriageValid)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    service.cancelAndWaitIdle();
    CHECK(analysis.crackmeTriageValid);
    if (!analysis.crackmeTriageValid) return;

    const CrackmeTriageReport& report = analysis.crackmeTriage;
    size_t endpointIndex = report.endpoints.size();
    for (size_t i = 0; i < report.endpoints.size(); ++i)
        if (report.endpoints[i].host == "pro.license-tmog.com") {
            endpointIndex = i;
            break;
        }
    CHECK(endpointIndex < report.endpoints.size());
    CHECK(!report.endpoints.empty() &&
          report.endpoints.front().host == "pro.license-tmog.com");

    if (endpointIndex < report.endpoints.size()) {
        const CrackmeTriageEndpoint& host = report.endpoints[endpointIndex];
        CHECK(hasPath(host, "/activate") ||
              std::any_of(report.routes.begin(), report.routes.end(),
                          [](const auto& route) { return route.path == "/activate"; }));
        CHECK(hasPath(host, "/deactivate") ||
              std::any_of(report.routes.begin(), report.routes.end(),
                          [](const auto& route) { return route.path == "/deactivate"; }));
    }

    for (const char* required : { "WinHttpConnect", "WinHttpOpenRequest",
                                  "WinHttpSendRequest", "WinHttpReceiveResponse",
                                  "WinHttpReadData" }) {
        bool found = false;
        for (const auto& api : report.apis)
            if (api.canonicalName == required) { found = true; break; }
        CHECK(found);
    }

    bool requestCorrelation = false;
    bool replyCorrelation = false;
    if (endpointIndex < report.endpoints.size()) {
        for (const CrackmeTriageCorrelation& correlation : report.correlations) {
            if (correlation.endpointIndex != endpointIndex ||
                correlation.apiIndex >= report.apis.size())
                continue;
            const CrackmeTriageApiEvidence& api = report.apis[correlation.apiIndex];
            requestCorrelation |= correlation.stage == NetworkStage::Write &&
                                  api.family == NetworkApiFamily::WinHttp;
            replyCorrelation |= correlation.stage == NetworkStage::Read &&
                                api.family == NetworkApiFamily::WinHttp;
        }
    }
    CHECK(requestCorrelation);
    CHECK(replyCorrelation);

    const CrackmeTrail* trail = trailFor(report, "pro.license-tmog.com");
    CHECK(trail != nullptr);
    bool decisionProof = false;
    if (trail) {
        CHECK(trail->stages[(size_t)NetworkTrailStage::Request].correlationCount != 0);
        CHECK(trail->stages[(size_t)NetworkTrailStage::Reply].correlationCount != 0);
        decisionProof =
            trail->stages[(size_t)NetworkTrailStage::Decision].correlationCount != 0;
    }

    // Request+Reply is the required static acceptance.  Do not manufacture a
    // Decision requirement or force a Hosted label when the binary does not
    // provide validation/return-use proof; report the pass's honest label.
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    std::printf("read-only AnalysisService target acceptance: %zu bytes, %lld ms, "
                "label=%s, decision=%s, completeness=%s, path=%s\n",
                binary.bytes().size(), static_cast<long long>(elapsed),
                report.label.c_str(), decisionProof ? "present" : "absent",
                report.completeness.reason.c_str(), path);
}

int main(int argc, char** argv) {
    std::vector<uint8_t> bytes;
    const size_t irrelevant = appendAscii(bytes, "https://dearimgui.com/faq");
    (void)irrelevant;
    appendAscii(bytes, "config.json");
    appendAscii(bytes, "foo.properties");
    appendAscii(bytes, "https://www.w3.org/2001/XMLSchema");
    appendAscii(bytes, "https://ns.adobe.com/xap/1.0/");
    const size_t hostOff = appendAscii(bytes, "pro.license-tmog.com");
    const size_t activateOff = appendAscii(bytes, "/activate");
    const size_t deactivateOff = appendAscii(bytes, "/deactivate");
    const size_t decisionOff = appendAscii(bytes, "license activation success; server response valid");
    const size_t productTitleOff = appendAscii(bytes, "Task Manager TMOG PRO");
    const size_t notRecognisedOff = appendAscii(bytes, "not recognised");
    const size_t fileOnlyOff = appendAscii(bytes, "fileonly.example.net");
    const size_t ipv6Off = appendAscii(bytes, "2001:db8::7");
    (void)ipv6Off;
    const size_t overlayOff = bytes.size();
    const size_t overlayHost = appendWide(bytes, "https://overlay.example.test/activate");

    XrefIndex xrefs;
    auto va = [](size_t off) { return 0x1000ull + off; };
    xrefs.toTarget[va(hostOff)] = { 0x5010 };
    xrefs.toTarget[va(activateOff)] = { 0x5018 };
    xrefs.toTarget[va(deactivateOff)] = { 0x5020 };
    xrefs.toTarget[va(decisionOff)] = { 0x5070 };
    xrefs.toTarget[va(productTitleOff)] = { 0x5071 };
    xrefs.toTarget[va(notRecognisedOff)] = { 0x5072 };
    const uint64_t iatResolve = 0x7000, iatConnect = 0x7008, iatRequest = 0x7010,
                   iatWrite = 0x7018, iatRead = 0x7020;
    xrefs.toTarget[iatResolve] = { 0x5030 };
    xrefs.toTarget[iatConnect] = { 0x5038 };
    xrefs.toTarget[iatRequest] = { 0x5040 };
    xrefs.toTarget[iatWrite] = { 0x5048 };
    xrefs.toTarget[iatRead] = { 0x5050 };
    FinalizeXrefIndex(xrefs);

    CrackmeTriageInput input;
    input.bytes = bytes.data(); input.size = bytes.size();
    input.overlayOffset = overlayOff; input.overlaySize = bytes.size() - overlayOff;
    input.offsetToVA = [fileOnlyOff, overlayOff](uint64_t offset, uint64_t& out) {
        if (offset == fileOnlyOff || offset >= overlayOff) return false;
        out = 0x1000 + offset;
        return true;
    };
    input.imports = {
        { "dnsapi.dll", "DnsQuery_W", iatResolve, true },
        { "wininet.dll", "InternetConnectA", iatConnect, true },
        { "wininet.dll", "HttpOpenRequestW", iatRequest, true },
        { "wininet.dll", "HttpSendRequestW", iatWrite, true },
        { "wininet.dll", "InternetReadFile", iatRead, true },
        { "user32.dll", "SendMessageW", 0x7030, true },
    };
    // More than 256 whole-image functions: relevant ownership deliberately sits
    // after the annotation-candidate default cap.
    for (size_t i = 0; i < 300; ++i)
        input.functions.push_back({ 0x100000 + i * 0x20, "filler", 0x10, {} });
    input.functions.push_back({ 0x5000, "check_license_reply", 0x100, {} });
    input.xrefs = &xrefs;

    CrackmeTriageReport report = RunCrackmeTriage(input);
    CHECK(report.completeness.complete);
    CHECK(report.label == "Hosted reply-server path");
    CHECK(!report.endpoints.empty());
    CHECK(report.endpoints.front().host == "pro.license-tmog.com");
    const CrackmeTriageEndpoint* pro = endpoint(report, "pro.license-tmog.com");
    CHECK(pro != nullptr);
    if (pro) {
        CHECK(pro->confidence == CrackmeTriageConfidence::High);
        CHECK(hasPath(*pro, "/activate"));
        CHECK(hasPath(*pro, "/deactivate"));
        CHECK(pro->stages & NetworkStageBit(NetworkStage::Read));
    }
    CHECK(endpoint(report, "config.json") == nullptr);
    CHECK(endpoint(report, "foo.properties") == nullptr);
    CHECK(endpoint(report, "dearimgui.com") == nullptr);
    CHECK(endpoint(report, "www.w3.org") == nullptr);
    CHECK(endpoint(report, "ns.adobe.com") == nullptr);
    CHECK(endpoint(report, "2001:db8::7") != nullptr);
    CHECK(report.apis.size() == 5); // SendMessageW is not network evidence.
    CHECK(hasArtifact(report, NetworkArtifactKind::License));
    CHECK(hasArtifact(report, NetworkArtifactKind::Success));
    CHECK(hasArtifact(report, NetworkArtifactKind::ReplyMarker));
    CHECK(hasArtifact(report, NetworkArtifactKind::Validation));
    bool proTitleLicense = false;
    bool notRecognisedFailure = false;
    for (const NetworkArtifact& artifact : report.artifacts) {
        proTitleLicense |= artifact.kind == NetworkArtifactKind::License &&
                           artifact.value == "Task Manager TMOG PRO";
        notRecognisedFailure |= artifact.kind == NetworkArtifactKind::Failure &&
                                artifact.value == "not recognised";
    }
    CHECK(proTitleLicense);
    CHECK(notRecognisedFailure);
    CHECK(report.stages[(size_t)NetworkTrailStage::Endpoint].apiCount != 0);
    CHECK(report.stages[(size_t)NetworkTrailStage::Connect].correlationCount != 0);
    CHECK(report.stages[(size_t)NetworkTrailStage::Request].correlationCount != 0);
    CHECK(report.stages[(size_t)NetworkTrailStage::Reply].correlationCount != 0);
    CHECK(report.stages[(size_t)NetworkTrailStage::Decision].correlationCount != 0);

    const CrackmeTriageEndpoint* overlay = endpoint(report, "overlay.example.test");
    CHECK(overlay != nullptr);
    if (overlay) {
        CHECK(!overlay->sources.empty());
        CHECK(overlay->sources.front().location == CrackmeLiteralLocation::Overlay);
        CHECK(overlay->sources.front().encoding == CrackmeLiteralEncoding::Utf16Le);
        CHECK(overlayHost >= overlayOff);
    }
    const CrackmeTriageEndpoint* fileOnly = endpoint(report, "fileonly.example.net");
    CHECK(fileOnly != nullptr);
    if (fileOnly) CHECK(fileOnly->sources.front().location == CrackmeLiteralLocation::FileOnly);

    // A containing printable string may start in mapped bytes while the exact
    // endpoint literal begins in file-only data. Location follows the literal
    // mapping result, never the containing string's address validity.
    {
        std::vector<uint8_t> boundaryBytes;
        appendAscii(boundaryBytes,
                    "mapped-prefix https://boundary.example.net/activate");
        CrackmeTriageInput boundary;
        boundary.bytes = boundaryBytes.data();
        boundary.size = boundaryBytes.size();
        boundary.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x9000 + off;
            return off == 0; // containing string mapped; endpoint literal is not
        };
        const CrackmeTriageReport boundaryReport = RunCrackmeTriage(boundary);
        const CrackmeTriageEndpoint* boundaryHost =
            endpoint(boundaryReport, "boundary.example.net");
        CHECK(boundaryHost != nullptr);
        if (boundaryHost && !boundaryHost->sources.empty()) {
            const auto& source = boundaryHost->sources.front();
            CHECK(source.addressValid);
            CHECK(!source.literalAddressValid);
            CHECK(source.location == CrackmeLiteralLocation::FileOnly);
        }
    }

    // Exact weaker report labels.
    {
        const char onlyHost[] = "remote.example.net\0";
        CrackmeTriageInput weak;
        weak.bytes = reinterpret_cast<const uint8_t*>(onlyHost);
        weak.size = sizeof(onlyHost);
        XrefIndex empty; weak.xrefs = &empty;
        CHECK(RunCrackmeTriage(weak).label == "Unreferenced endpoint string");
    }
    {
        CrackmeTriageInput unknown;
        const uint8_t noStrings[4] = {};
        unknown.bytes = noStrings; unknown.size = sizeof(noStrings);
        unknown.imports.push_back({ "ws2_32.dll", "connect", 0, false });
        XrefIndex empty; unknown.xrefs = &empty;
        CHECK(RunCrackmeTriage(unknown).label == "Network APIs found; host unknown");
    }
    {
        std::vector<uint8_t> remoteBytes;
        const size_t remoteOff = appendAscii(remoteBytes, "remote.example.net");
        XrefIndex refs;
        refs.toTarget[0x2000 + remoteOff] = { 0x9000 };
        refs.toTarget[0xA000] = { 0x9008 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput remote;
        remote.bytes = remoteBytes.data(); remote.size = remoteBytes.size();
        remote.offsetToVA = [](uint64_t off, uint64_t& out) { out = 0x2000 + off; return true; };
        remote.imports.push_back({ "winhttp", "WinHttpConnect", 0xA000, true });
        remote.functions.push_back({ 0x9000, "remote_candidate", 0x20, {} });
        remote.xrefs = &refs;
        CHECK(RunCrackmeTriage(remote).label == "Remote endpoint candidate");
    }

    // A mapped VA of zero remains valid evidence and can own correlations.
    {
        std::vector<uint8_t> zeroBytes;
        const size_t zeroOff = appendAscii(zeroBytes, "zero.example.net");
        CHECK(zeroOff == 0);
        XrefIndex refs;
        refs.toTarget[0] = { 0x10 };
        refs.toTarget[0x200] = { 0x18 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput zero;
        zero.bytes = zeroBytes.data(); zero.size = zeroBytes.size();
        zero.offsetToVA = [](uint64_t off, uint64_t& out) { out = off; return true; };
        zero.imports.push_back({ "winhttp", "WinHttpConnect", 0x200, true });
        zero.functions.push_back({ 0, "zero_owner", 0x40, {} });
        zero.xrefs = &refs;
        CrackmeTriageReport zeroReport = RunCrackmeTriage(zero);
        const CrackmeTriageEndpoint* zeroHost = endpoint(zeroReport, "zero.example.net");
        CHECK(zeroHost != nullptr);
        if (zeroHost) {
            CHECK(!zeroHost->sources.empty());
            CHECK(zeroHost->sources.front().addressValid);
            CHECK(zeroHost->sources.front().literalAddressValid);
            CHECK(zeroHost->sources.front().address == 0);
            CHECK(zeroHost->sources.front().literalAddress == 0);
            CHECK(!zeroHost->correlationIndices.empty());
        }
    }

    // Malformed authorities, IPv4 shapes, and ports are rejected without a
    // broad TLD allow-list that would discard an unusual but valid endpoint.
    {
        std::vector<uint8_t> malformed;
        appendAscii(malformed, "http://999.1.1.1/activate");
        appendAscii(malformed, "1.2.3.4.5");
        appendAscii(malformed, "01.2.3.4");
        appendAscii(malformed, "http://example.com:70000/activate");
        appendAscii(malformed, "http://example.com:12x/activate");
        appendAscii(malformed, "http://[2001:db8::1/activate");
        appendAscii(malformed, "http://[:::]/activate");
        appendAscii(malformed, "http://[1:::]/activate");
        appendAscii(malformed, "http://[::1:]/activate");
        appendAscii(malformed, "http://[:1::]/activate");
        appendAscii(malformed, "http://[1:2:3:4:5:192.0.2.1]/activate");
        appendAscii(malformed, "http://[1:2:3:4:5:6:7:192.0.2.1]/activate");
        appendAscii(malformed, "http://[2001:db8::2]:8080/activate");
        appendAscii(malformed, "http://[::ffff:192.0.2.128]:8443/activate");
        appendAscii(malformed, "2001:db8::192.0.2.33");
        appendAscii(malformed, "0:0:0:0:0:ffff:192.0.2.129");
        appendAscii(malformed, "https://good.example.museum:65535/activate");
        CrackmeTriageInput bad;
        bad.bytes = malformed.data(); bad.size = malformed.size();
        XrefIndex empty; bad.xrefs = &empty;
        CrackmeTriageReport parsed = RunCrackmeTriage(bad);
        CHECK(endpoint(parsed, "999.1.1.1") == nullptr);
        CHECK(endpoint(parsed, "1.2.3.4.5") == nullptr);
        CHECK(endpoint(parsed, "01.2.3.4") == nullptr);
        CHECK(endpoint(parsed, "example.com") == nullptr);
        CHECK(endpoint(parsed, "2001:db8::1") == nullptr);
        CHECK(endpoint(parsed, ":::") == nullptr);
        CHECK(endpoint(parsed, "1:::") == nullptr);
        CHECK(endpoint(parsed, "::1:") == nullptr);
        CHECK(endpoint(parsed, ":1::") == nullptr);
        CHECK(endpoint(parsed, "1:2:3:4:5:192.0.2.1") == nullptr);
        CHECK(endpoint(parsed, "1:2:3:4:5:6:7:192.0.2.1") == nullptr);
        const CrackmeTriageEndpoint* bracketed = endpoint(parsed, "2001:db8::2");
        CHECK(bracketed && bracketed->scheme == "http" &&
              bracketed->portValid && bracketed->port == 8080 &&
              hasPath(*bracketed, "/activate"));
        bool ipv6UrlSource = false;
        if (bracketed) for (const auto& source : bracketed->sources)
            ipv6UrlSource |= source.role == CrackmeLiteralRole::Url;
        CHECK(ipv6UrlSource);
        const CrackmeTriageEndpoint* ipv4TailUrl =
            endpoint(parsed, "::ffff:192.0.2.128");
        CHECK(ipv4TailUrl && ipv4TailUrl->kind == CrackmeEndpointKind::IPv6 &&
              ipv4TailUrl->portValid && ipv4TailUrl->port == 8443 &&
              hasPath(*ipv4TailUrl, "/activate"));
        const CrackmeTriageEndpoint* ipv4TailCompressed =
            endpoint(parsed, "2001:db8::192.0.2.33");
        CHECK(ipv4TailCompressed &&
              ipv4TailCompressed->kind == CrackmeEndpointKind::IPv6);
        const CrackmeTriageEndpoint* ipv4TailFull =
            endpoint(parsed, "0:0:0:0:0:ffff:192.0.2.129");
        CHECK(ipv4TailFull && ipv4TailFull->kind == CrackmeEndpointKind::IPv6);
        const CrackmeTriageEndpoint* unusual = endpoint(parsed, "good.example.museum");
        CHECK(unusual && unusual->portValid && unusual->port == 65535);
    }

    // IPv4-mapped IPv6 inherits the embedded IPv4 scope. In particular,
    // mapped 127/8 must never pass the non-loopback Hosted gate.
    {
        std::vector<uint8_t> mappedBytes;
        const size_t loopbackOff = appendAscii(
            mappedBytes, "http://[::ffff:127.0.0.1]/activate");
        appendAscii(mappedBytes, "http://[::ffff:10.2.3.4]/activate");
        appendAscii(mappedBytes, "http://[::ffff:8.8.8.8]/activate");
        appendAscii(mappedBytes, "http://[::ffff:7f00:1]/activate");
        XrefIndex refs;
        refs.toTarget[0x22000 + loopbackOff] = { 0x23010 };
        refs.toTarget[0x24000] = { 0x23020 };
        refs.toTarget[0x24008] = { 0x23028 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput mapped;
        mapped.bytes = mappedBytes.data(); mapped.size = mappedBytes.size();
        mapped.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x22000 + off; return true;
        };
        mapped.imports = {
            { "winhttp", "WinHttpSendRequest", 0x24000, true },
            { "winhttp", "WinHttpReadData", 0x24008, true },
        };
        mapped.functions.push_back({ 0x23000, "mapped_loopback_flow", 0x80, {} });
        mapped.xrefs = &refs;
        CrackmeTriageReport mappedReport = RunCrackmeTriage(mapped);
        const CrackmeTriageEndpoint* loopback =
            endpoint(mappedReport, "::ffff:127.0.0.1");
        const CrackmeTriageEndpoint* privateMapped =
            endpoint(mappedReport, "::ffff:10.2.3.4");
        const CrackmeTriageEndpoint* publicMapped =
            endpoint(mappedReport, "::ffff:8.8.8.8");
        const CrackmeTriageEndpoint* hexLoopback =
            endpoint(mappedReport, "::ffff:7f00:1");
        CHECK(loopback && loopback->scope == CrackmeEndpointScope::Loopback);
        CHECK(privateMapped &&
              privateMapped->scope == CrackmeEndpointScope::PrivateNetwork);
        CHECK(publicMapped &&
              publicMapped->scope == CrackmeEndpointScope::PublicNetwork);
        CHECK(hexLoopback && hexLoopback->scope == CrackmeEndpointScope::Loopback);
        const CrackmeTrail* loopbackTrail =
            trailFor(mappedReport, "::ffff:127.0.0.1");
        CHECK(loopbackTrail && loopbackTrail->label != "Hosted reply-server path");
    }

    // Canonical identity includes each URL scheme's effective default port.
    // Explicit :80 folds into omitted HTTP while the displayed spelling keeps
    // the first source's explicitness; protocol-distinct authorities stay apart.
    {
        std::vector<uint8_t> defaultsBytes;
        appendAscii(defaultsBytes, "http://defaults.example.net/activate");
        appendAscii(defaultsBytes, "http://defaults.example.net:80/deactivate");
        appendAscii(defaultsBytes, "https://defaults.example.net/secure");
        appendAscii(defaultsBytes, "ws://socket.example.net/connect");
        appendAscii(defaultsBytes, "wss://socket.example.net/connect");
        appendAscii(defaultsBytes, "http://mixed.example.net:443/plain");
        appendAscii(defaultsBytes, "https://mixed.example.net/secure");
        CrackmeTriageInput defaults;
        defaults.bytes = defaultsBytes.data(); defaults.size = defaultsBytes.size();
        XrefIndex empty; defaults.xrefs = &empty;
        CrackmeTriageReport defaultReport = RunCrackmeTriage(defaults);
        size_t defaultHostRows = 0, socketRows = 0, mixedRows = 0;
        const CrackmeTriageEndpoint* httpDefault = nullptr;
        for (const auto& item : defaultReport.endpoints) {
            if (item.host == "defaults.example.net") {
                ++defaultHostRows;
                if (item.scheme == "http") httpDefault = &item;
            }
            if (item.host == "socket.example.net") ++socketRows;
            if (item.host == "mixed.example.net") ++mixedRows;
        }
        CHECK(defaultHostRows == 2); // HTTP:80 and HTTPS:443
        CHECK(socketRows == 2);      // WS:80 and WSS:443
        CHECK(mixedRows == 2);       // explicit HTTP:443 still differs from HTTPS
        CHECK(httpDefault && !httpDefault->portValid &&
              httpDefault->display == "http://defaults.example.net" &&
              hasPath(*httpDefault, "/activate") &&
              hasPath(*httpDefault, "/deactivate") &&
              httpDefault->sources.size() >= 4);
    }

    // A URL contributes its real path to the route table; the scheme authority
    // is never misparsed as /host/path.
    {
        const char routeBytes[] =
            "https://route-only.example.net/activate\0";
        CrackmeTriageInput routeInput;
        routeInput.bytes = reinterpret_cast<const uint8_t*>(routeBytes);
        routeInput.size = sizeof(routeBytes);
        XrefIndex empty; routeInput.xrefs = &empty;
        CrackmeTriageReport routeReport = RunCrackmeTriage(routeInput);
        CHECK(routeReport.routes.size() == 1);
        CHECK(routeReport.routes.size() == 1 &&
              routeReport.routes[0].path == "/activate");
        const CrackmeTrail* routeTrail =
            trailFor(routeReport, "route-only.example.net");
        bool attachedRoute = false;
        if (routeTrail) for (size_t artifactIndex : routeTrail->artifactIndices) {
            if (artifactIndex < routeReport.artifacts.size())
                attachedRoute |=
                    routeReport.artifacts[artifactIndex].kind ==
                        NetworkArtifactKind::Route &&
                    routeReport.artifacts[artifactIndex].value == "/activate";
        }
        CHECK(attachedRoute);
    }
    {
        const char routeAfterBareUrl[] =
            "https://no-path.example.net /activate\0";
        CrackmeTriageInput routeInput;
        routeInput.bytes =
            reinterpret_cast<const uint8_t*>(routeAfterBareUrl);
        routeInput.size = sizeof(routeAfterBareUrl);
        XrefIndex empty; routeInput.xrefs = &empty;
        CrackmeTriageReport routeReport = RunCrackmeTriage(routeInput);
        CHECK(std::any_of(routeReport.routes.begin(), routeReport.routes.end(),
                          [](const CrackmeTriageRoute& route) {
                              return route.path == "/activate";
                          }));
    }

    // Bounded generic HTTP-header extraction retains ordinary request metadata,
    // and a Host header contributes a normalized host:port endpoint.
    {
        std::vector<uint8_t> headerBytes;
        appendAscii(headerBytes, "Host: headers.example.test:8443");
        appendAscii(headerBytes, "Content-Type: application/json");
        appendAscii(headerBytes, "User-Agent: CrackmeClient/1.0");
        appendAscii(headerBytes, "Accept: application/json");
        appendAscii(headerBytes, "Cookie: session=abc123");
        CrackmeTriageInput headers;
        headers.bytes = headerBytes.data(); headers.size = headerBytes.size();
        XrefIndex empty; headers.xrefs = &empty;
        CrackmeTriageReport headerReport = RunCrackmeTriage(headers);
        const CrackmeTriageEndpoint* host = endpoint(headerReport, "headers.example.test");
        CHECK(host && host->portValid && host->port == 8443);
        size_t headerCount = 0;
        size_t hostHeader = (std::numeric_limits<size_t>::max)();
        size_t contentTypeHeader = (std::numeric_limits<size_t>::max)();
        bool contentType = false, userAgent = false, accept = false, cookie = false;
        for (size_t i = 0; i < headerReport.artifacts.size(); ++i) {
            const auto& artifact = headerReport.artifacts[i];
            if (artifact.kind != NetworkArtifactKind::Header) continue;
            ++headerCount;
            contentType |= artifact.value == "content-type: application/json";
            userAgent |= artifact.value == "user-agent: CrackmeClient/1.0";
            accept |= artifact.value == "accept: application/json";
            cookie |= artifact.value == "cookie: session=abc123";
            if (artifact.value == "host: headers.example.test:8443")
                hostHeader = i;
            if (artifact.value == "content-type: application/json")
                contentTypeHeader = i;
            CHECK(!artifact.decisionEligible);
        }
        CHECK(headerCount == 5);
        CHECK(contentType && userAgent && accept && cookie);
        const CrackmeTrail* headerTrail = trailFor(headerReport, "headers.example.test");
        CHECK(headerTrail != nullptr);
        if (headerTrail) {
            CHECK(std::find(headerTrail->artifactIndices.begin(),
                            headerTrail->artifactIndices.end(), hostHeader) !=
                  headerTrail->artifactIndices.end());
            CHECK(std::find(headerTrail->artifactIndices.begin(),
                            headerTrail->artifactIndices.end(), contentTypeHeader) ==
                  headerTrail->artifactIndices.end());
            CHECK(headerTrail->stages[(size_t)NetworkTrailStage::Decision]
                      .correlationCount == 0);
        }
    }

    // Request-owned headers/auth/license evidence is scoped to the endpoint's
    // Request stage without being promoted to reply validation.
    {
        std::vector<uint8_t> requestBytes;
        const size_t hostHeaderOff =
            appendAscii(requestBytes, "Host: request-evidence.example.net:9443");
        const size_t authHeaderOff =
            appendAscii(requestBytes, "Authorization: Bearer static-token");
        const size_t agentHeaderOff =
            appendAscii(requestBytes, "User-Agent: CrackmeClient/2.0");
        const size_t licenseOff =
            appendAscii(requestBytes, "license token request payload");
        XrefIndex refs;
        refs.toTarget[0x18000 + hostHeaderOff + 6] = { 0x19010 };
        refs.toTarget[0x18000 + authHeaderOff] = { 0x19018 };
        refs.toTarget[0x18000 + agentHeaderOff] = { 0x19020 };
        refs.toTarget[0x18000 + licenseOff] = { 0x19028 };
        refs.toTarget[0x1A000] = { 0x19030 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput request;
        request.bytes = requestBytes.data(); request.size = requestBytes.size();
        request.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x18000 + off; return true;
        };
        request.imports.push_back(
            { "winhttp", "WinHttpSendRequest", 0x1A000, true });
        request.functions.push_back(
            { 0x19000, "build_license_request", 0x80, {} });
        request.xrefs = &refs;
        CrackmeTriageReport requestReport = RunCrackmeTriage(request);
        const CrackmeTrail* requestTrail =
            trailFor(requestReport, "request-evidence.example.net");
        CHECK(requestTrail != nullptr);
        bool attachedAuth = false, attachedAgent = false, attachedLicense = false;
        if (requestTrail) {
            for (size_t artifactIndex : requestTrail->artifactIndices) {
                if (artifactIndex >= requestReport.artifacts.size()) continue;
                const NetworkArtifact& artifact = requestReport.artifacts[artifactIndex];
                attachedAuth |= artifact.value ==
                                "authorization: Bearer static-token";
                attachedAgent |= artifact.value ==
                                 "user-agent: CrackmeClient/2.0";
                attachedLicense |= artifact.kind == NetworkArtifactKind::License &&
                                   artifact.value == "license token request payload";
            }
            CHECK(requestTrail->stages[(size_t)NetworkTrailStage::Request]
                      .correlationCount > 1);
            CHECK(requestTrail->stages[(size_t)NetworkTrailStage::Decision]
                      .correlationCount == 0);
        }
        CHECK(attachedAuth && attachedAgent && attachedLicense);
        CHECK(requestReport.label == "Remote endpoint candidate");
    }

    // Scope classification is explicit.  The exact Hosted gate rejects a
    // loopback trail but permits private-network evidence because the approved
    // condition is non-loopback, not necessarily Internet-routable.
    {
        std::vector<uint8_t> scopedBytes;
        const size_t loopOff = appendAscii(scopedBytes, "127.0.0.1");
        const size_t privateOff = appendAscii(scopedBytes, "10.1.2.3");
        XrefIndex refs;
        refs.toTarget[0x4000 + loopOff] = { 0xA010 };
        refs.toTarget[0x4000 + privateOff] = { 0xA018 };
        refs.toTarget[0xB000] = { 0xA020 };
        refs.toTarget[0xB008] = { 0xA028 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput scoped;
        scoped.bytes = scopedBytes.data(); scoped.size = scopedBytes.size();
        scoped.offsetToVA = [](uint64_t off, uint64_t& out) { out = 0x4000 + off; return true; };
        scoped.imports = {
            { "winhttp", "WinHttpSendRequest", 0xB000, true },
            { "winhttp", "WinHttpReadData", 0xB008, true },
        };
        scoped.functions.push_back({ 0xA000, "scoped_reply", 0x80, {} });
        scoped.xrefs = &refs;
        CrackmeTriageReport scopedReport = RunCrackmeTriage(scoped);
        const CrackmeTriageEndpoint* loop = endpoint(scopedReport, "127.0.0.1");
        const CrackmeTriageEndpoint* privateHost = endpoint(scopedReport, "10.1.2.3");
        CHECK(loop && loop->scope == CrackmeEndpointScope::Loopback);
        CHECK(privateHost && privateHost->scope == CrackmeEndpointScope::PrivateNetwork);
        const CrackmeTrail* loopTrail = trailFor(scopedReport, "127.0.0.1");
        const CrackmeTrail* privateTrail = trailFor(scopedReport, "10.1.2.3");
        CHECK(loopTrail && loopTrail->label != "Hosted reply-server path");
        CHECK(privateTrail && privateTrail->label == "Hosted reply-server path");
    }

    // WinHttpOpenRequest remains visible in the Request stage but is not actual
    // outbound send/write evidence for the Hosted honesty label.
    {
        std::vector<uint8_t> requestBytes;
        const size_t requestHostOff = appendAscii(requestBytes, "open-only.example.net");
        XrefIndex refs;
        refs.toTarget[0x8000 + requestHostOff] = { 0xD010 };
        refs.toTarget[0xE000] = { 0xD020 };
        refs.toTarget[0xE008] = { 0xD028 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput requestOnly;
        requestOnly.bytes = requestBytes.data(); requestOnly.size = requestBytes.size();
        requestOnly.offsetToVA = [](uint64_t off, uint64_t& out) { out = 0x8000 + off; return true; };
        requestOnly.imports = {
            { "winhttp", "WinHttpOpenRequest", 0xE000, true },
            { "winhttp", "WinHttpReadData", 0xE008, true },
        };
        requestOnly.functions.push_back({ 0xD000, "open_without_send", 0x80, {} });
        requestOnly.xrefs = &refs;
        CrackmeTriageReport requestReport = RunCrackmeTriage(requestOnly);
        const CrackmeTrail* requestTrail = trailFor(requestReport, "open-only.example.net");
        CHECK(requestTrail != nullptr);
        if (requestTrail) {
            CHECK(requestTrail->stages[(size_t)NetworkTrailStage::Request].correlationCount != 0);
            CHECK(requestTrail->stages[(size_t)NetworkTrailStage::Reply].correlationCount != 0);
            CHECK(requestTrail->label == "Remote endpoint candidate");
        }
        CHECK(requestReport.label != "Hosted reply-server path");
    }

    // A partial xref index never makes missing correlations look definitive.
    {
        const char partialBytes[] = "partial.example.net\0";
        XrefIndex partialXrefs;
        partialXrefs.complete = false;
        partialXrefs.stopReason = XrefStopReason::EdgeBudget;
        CrackmeTriageInput partial;
        partial.bytes = reinterpret_cast<const uint8_t*>(partialBytes);
        partial.size = sizeof(partialBytes);
        partial.xrefs = &partialXrefs;
        CrackmeTriageReport partialReport = RunCrackmeTriage(partial);
        CHECK(!partialReport.completeness.complete);
        CHECK(!partialReport.completeness.xrefsComplete);
        CHECK(partialReport.completeness.reason.find("cross-reference input is partial") !=
              std::string::npos);
        CHECK(partialReport.completeness.reason.find("edge budget") != std::string::npos);
        CHECK(partialReport.label == "Unreferenced endpoint string");
    }

    // Function ownership honors non-contiguous chunks; the endpoint and both
    // APIs live only in the second chunk of the owning function.
    {
        std::vector<uint8_t> chunkBytes;
        const size_t chunkHostOff = appendAscii(chunkBytes, "chunks.example.net");
        XrefIndex refs;
        refs.toTarget[0x2000 + chunkHostOff] = { 0x6010 };
        refs.toTarget[0xB100] = { 0x6020 };
        refs.toTarget[0xB108] = { 0x6030 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput chunked;
        chunked.bytes = chunkBytes.data(); chunked.size = chunkBytes.size();
        chunked.offsetToVA = [](uint64_t off, uint64_t& out) { out = 0x2000 + off; return true; };
        chunked.imports = {
            { "winhttp", "WinHttpSendRequest", 0xB100, true },
            { "winhttp", "WinHttpReadData", 0xB108, true },
        };
        chunked.functions.push_back({
            0x5000, "chunked_reply", 0x10,
            { { 0x5000, 0x10 }, { 0x6000, 0x40 } }
        });
        chunked.xrefs = &refs;
        CrackmeTriageReport chunkReport = RunCrackmeTriage(chunked);
        CHECK(chunkReport.label == "Hosted reply-server path");
        bool ownedSecondChunk = false;
        for (const auto& correlation : chunkReport.correlations)
            ownedSecondChunk |= correlation.functionAddressValid &&
                                correlation.functionAddress == 0x5000;
        CHECK(ownedSecondChunk);
    }

    // Call edges, typed arguments/return use, decisions, and algorithms all feed
    // the trail.  The static endpoint-to-API path is exactly two calls deep.
    {
        std::vector<uint8_t> flowBytes;
        const size_t flowHostOff = appendAscii(flowBytes, "flow.example.net");
        const size_t replyOff = appendAscii(flowBytes, "server reply accepted; license valid");
        XrefIndex refs;
        refs.toTarget[0x3000 + flowHostOff] = { 0x4010 };
        refs.toTarget[0x3000 + replyOff] = { 0x6010 };
        refs.toTarget[0xC000] = { 0x6020 };
        refs.toTarget[0xC008] = { 0x6030 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput flow;
        flow.bytes = flowBytes.data(); flow.size = flowBytes.size();
        flow.offsetToVA = [](uint64_t off, uint64_t& out) { out = 0x3000 + off; return true; };
        flow.imports = {
            { "winhttp", "WinHttpSendRequest", 0xC000, true },
            { "winhttp", "WinHttpReadData", 0xC008, true },
        };
        flow.functions = {
            { 0x4000, "endpoint_owner", 0x40, {} },
            { 0x5000, "flow_bridge", 0x40, {} },
            { 0x6000, "reply_decision", 0x80, {} },
        };
        flow.callEdges = { { 0x4000, 0x5000 }, { 0x5000, 0x6000 } };
        CrackmeTriageApiCallInput typedEndpoint;
        typedEndpoint.dll = "winhttp";
        typedEndpoint.name = "WinHttpConnect";
        typedEndpoint.callsite = 0x6028; typedEndpoint.callsiteValid = true;
        typedEndpoint.functionAddress = 0x6000;
        typedEndpoint.functionAddressValid = true;
        typedEndpoint.functionName = "reply_decision";
        typedEndpoint.arguments.push_back(
            { 1, "serverName", "flow.example.net", 0x3000 + flowHostOff, true });
        flow.apiCalls.push_back(std::move(typedEndpoint));
        CrackmeTriageApiCallInput typedReply;
        typedReply.dll = "winhttp";
        typedReply.name = "WinHttpReadData";
        typedReply.callsite = 0x6030; typedReply.callsiteValid = true;
        typedReply.functionAddress = 0x6000; typedReply.functionAddressValid = true;
        typedReply.functionName = "reply_decision";
        typedReply.returnValueUsed = true;
        typedReply.resultInfluencesDecision = true;
        flow.apiCalls.push_back(std::move(typedReply));
        flow.decisions.push_back({ 0x6010, true, 0x6000, true,
                                   NetworkArtifactKind::Validation,
                                   "license reply accepted", true });
        flow.algorithms.push_back({ 0, false, 0x5000, true,
                                    "SHA-256", "hash", "bounded algorithm evidence" });
        flow.xrefs = &refs;
        CrackmeTriageReport flowReport = RunCrackmeTriage(flow);
        bool depthTwo = false, directArgument = false;
        bool ownerSemantics = false;
        for (const auto& correlation : flowReport.correlations) {
            depthTwo |= !correlation.directArgument && correlation.graphDepth == 2;
            directArgument |= correlation.directArgument;
            ownerSemantics |= !correlation.directArgument &&
                correlation.graphDepth == 2 &&
                correlation.functionAddressValid &&
                correlation.functionAddress == 0x6000 &&
                correlation.endpointFunctionAddressValid &&
                correlation.endpointFunctionAddress == 0x4000;
        }
        CHECK(depthTwo);
        CHECK(directArgument);
        CHECK(ownerSemantics);
        CHECK(hasArtifact(flowReport, NetworkArtifactKind::Algorithm));
        CHECK(flowReport.stages[(size_t)NetworkTrailStage::Decision].correlationCount != 0);
        CHECK(flowReport.label == "Hosted reply-server path");
        const CrackmeTriageEndpoint* flowEndpoint = endpoint(flowReport, "flow.example.net");
        CHECK(flowEndpoint &&
              flowEndpoint->honestyLabel.find("bounded static correlation") != std::string::npos &&
              flowEndpoint->honestyLabel.find("in the same function") == std::string::npos);
    }

    // Typed string arguments are endpoint evidence only for exact endpoint-
    // bearing parameters. User agents, Referer/header URLs, and request-body
    // URLs remain request artifacts and never become contacted hosts.
    {
        CrackmeTriageInput typedNoise;
        XrefIndex empty; typedNoise.xrefs = &empty;
        auto addCall = [&](const char* api,
                           std::initializer_list<CrackmeTriageApiArgumentInput> args) {
            CrackmeTriageApiCallInput call;
            call.dll = "winhttp"; call.name = api;
            call.functionAddress = 0x88000; call.functionAddressValid = true;
            call.arguments.assign(args.begin(), args.end());
            typedNoise.apiCalls.push_back(std::move(call));
        };
        addCall("WinHttpOpen", {
            { 0, "userAgent", "client.example.com", 0, false },
        });
        addCall("WinHttpAddRequestHeaders", {
            { 1, "headers", "Referer: https://docs.example.com/help", 0, false },
        });
        addCall("WinHttpSendRequest", {
            { 1, "headers", "Content-Type: https://header.example.com/json", 0, false },
            { 3, "optionalData", "https://body.example.com/activate", 0, false },
        });
        typedNoise.functions.push_back(
            { 0x88000, "build_request_without_endpoint", 0x100, {} });
        CrackmeTriageReport typedNoiseReport = RunCrackmeTriage(typedNoise);
        CHECK(typedNoiseReport.endpoints.empty());
        CHECK(typedNoiseReport.correlations.empty());
        bool refererArtifact = false, agentArtifact = false;
        for (const NetworkArtifact& artifact : typedNoiseReport.artifacts) {
            refererArtifact |= artifact.kind == NetworkArtifactKind::Header &&
                               artifact.value.find("referer:") == 0;
            agentArtifact |= artifact.kind == NetworkArtifactKind::Header &&
                             artifact.value == "user-agent: client.example.com";
        }
        CHECK(refererArtifact && agentArtifact);
    }

    // Typed Connect observations pair the server-name string (ordinal 1) with
    // the validity-bearing numeric INTERNET_PORT (ordinal 2). Zero is retained;
    // an absent or out-of-range immediate is not invented as a port.
    {
        auto portReport = [](const char* api, const char* host,
                             uint64_t immediate, bool immediateValid) {
            CrackmeTriageInput input;
            CrackmeTriageApiCallInput call;
            call.dll = std::string(api).find("InternetConnect") != std::string::npos
                     ? "wininet" : "winhttp";
            call.name = api;
            call.callsite = 0; call.callsiteValid = true;
            call.functionAddress = 0; call.functionAddressValid = true;
            CrackmeTriageApiArgumentInput server;
            server.ordinal = 1; server.name = "serverName";
            server.literal = host;
            server.address = 0; server.addressValid = true;
            server.fileOffset = 0; server.fileOffsetValid = true;
            server.encoding = CrackmeLiteralEncoding::Ascii;
            server.encodingValid = true;
            call.arguments.push_back(std::move(server));
            CrackmeTriageApiArgumentInput port;
            port.ordinal = 2; port.name = "serverPort";
            port.immediate = immediate; port.immediateValid = immediateValid;
            call.arguments.push_back(std::move(port));
            input.apiCalls.push_back(std::move(call));
            input.functions.push_back({ 0, "typed_connect", 0x40, {} });
            return RunCrackmeTriage(input);
        };

        CrackmeTriageReport nondefault =
            portReport("WinHttpConnect", "port8443.example.net", 8443, true);
        const CrackmeTriageEndpoint* p8443 =
            endpoint(nondefault, "port8443.example.net");
        CHECK(p8443 && p8443->portValid && p8443->port == 8443 &&
              p8443->display == "port8443.example.net:8443");

        CrackmeTriageReport zero =
            portReport("InternetConnectW", "portzero.example.net", 0, true);
        const CrackmeTriageEndpoint* pzero = endpoint(zero, "portzero.example.net");
        CHECK(pzero && pzero->portValid && pzero->port == 0 &&
              pzero->display == "portzero.example.net:0");

        CrackmeTriageReport unknown =
            portReport("WinHttpConnect", "portunknown.example.net", 443, false);
        const CrackmeTriageEndpoint* punknown =
            endpoint(unknown, "portunknown.example.net");
        CHECK(punknown && !punknown->portValid);

        CrackmeTriageReport invalid =
            portReport("WinHttpConnect", "portinvalid.example.net", 70000, true);
        const CrackmeTriageEndpoint* pinvalid =
            endpoint(invalid, "portinvalid.example.net");
        CHECK(pinvalid && !pinvalid->portValid);
    }

    // Typed request and algorithm evidence retains one bounded, validity-bearing
    // source with exact VA/file navigation when the adapter proves encoding.
    // VA and file offset zero remain valid coordinates.
    {
        CrackmeTriageInput provenance;
        CrackmeTriageApiCallInput routeCall;
        routeCall.dll = "winhttp"; routeCall.name = "WinHttpOpenRequest";
        CrackmeTriageApiArgumentInput route;
        route.ordinal = 2; route.name = "objectName";
        route.literal = "prefix /activate";
        route.address = 0; route.addressValid = true;
        route.fileOffset = 0; route.fileOffsetValid = true;
        route.encoding = CrackmeLiteralEncoding::Ascii;
        route.encodingValid = true;
        routeCall.arguments.push_back(std::move(route));
        provenance.apiCalls.push_back(std::move(routeCall));

        CrackmeTriageApiCallInput headerCall;
        headerCall.dll = "winhttp";
        headerCall.name = "WinHttpAddRequestHeadersW";
        CrackmeTriageApiArgumentInput header;
        header.ordinal = 1; header.name = "headers";
        header.literal = "  Authorization: Bearer zero";
        header.address = 0; header.addressValid = true;
        header.fileOffset = 200; header.fileOffsetValid = true;
        header.encoding = CrackmeLiteralEncoding::Utf16Le;
        header.encodingValid = true;
        headerCall.arguments.push_back(std::move(header));
        provenance.apiCalls.push_back(std::move(headerCall));

        CrackmeTriageAlgorithmInput algorithm;
        algorithm.address = 0; algorithm.addressValid = true;
        algorithm.name = "SHA-256"; algorithm.category = "hash";
        algorithm.evidence = "typed algorithm provenance";
        algorithm.fileOffset = 0; algorithm.fileOffsetValid = true;
        provenance.algorithms.push_back(std::move(algorithm));

        CrackmeTriageReport provenanceReport = RunCrackmeTriage(provenance);
        bool routeSource = false, headerSource = false, algorithmSource = false;
        for (const NetworkArtifact& artifact : provenanceReport.artifacts) {
            if (artifact.sources.size() != 1) continue;
            const CrackmeTriageLiteralSource& source = artifact.sources.front();
            if (artifact.kind == NetworkArtifactKind::Route &&
                artifact.value == "/activate") {
                routeSource = source.addressValid && source.address == 0 &&
                              source.literalAddressValid && source.literalAddress == 7 &&
                              source.fileOffsetValid && source.literalFileOffset == 7;
            }
            if (artifact.kind == NetworkArtifactKind::Header &&
                artifact.value == "authorization: Bearer zero") {
                headerSource = source.addressValid && source.address == 0 &&
                               source.literalAddressValid && source.literalAddress == 4 &&
                               source.fileOffsetValid && source.literalFileOffset == 204 &&
                               source.encoding == CrackmeLiteralEncoding::Utf16Le;
            }
            if (artifact.kind == NetworkArtifactKind::Algorithm) {
                algorithmSource = source.addressValid && source.literalAddressValid &&
                                  source.address == 0 && source.literalAddress == 0 &&
                                  source.fileOffsetValid && source.literalFileOffset == 0;
            }
        }
        CHECK(routeSource && headerSource && algorithmSource);
    }

    // Checking any API return value is status/quantity handling, not reply
    // content validation. A Read-stage BOOL must therefore remain visible as a
    // return flow without directly creating Decision evidence.
    {
        for (const char* api : { "WinHttpConnect", "WinHttpOpenRequest",
                                 "WinHttpSendRequest" }) {
            const char noReplyBytes[] = "typed-nonreply.example.net\0";
            CrackmeTriageInput nonReply;
            nonReply.bytes = reinterpret_cast<const uint8_t*>(noReplyBytes);
            nonReply.size = sizeof(noReplyBytes);
            XrefIndex empty; nonReply.xrefs = &empty;
            CrackmeTriageApiCallInput call;
            call.dll = "winhttp"; call.name = api;
            call.callsite = 0x9100; call.callsiteValid = true;
            call.functionAddress = 0x9000; call.functionAddressValid = true;
            call.functionName = "typed_nonreply";
            call.resultInfluencesDecision = true;
            call.arguments.push_back({ std::string(api) == "WinHttpConnect" ? 1u : 0u,
                                       "argument", "typed-nonreply.example.net", 0, false });
            nonReply.apiCalls.push_back(std::move(call));
            nonReply.functions.push_back({ 0x9000, "typed_nonreply", 0x200, {} });
            CrackmeTriageReport nonReplyReport = RunCrackmeTriage(nonReply);
            CHECK(nonReplyReport.stages[(size_t)NetworkTrailStage::Decision].correlationCount == 0);
            CHECK(nonReplyReport.label != "Hosted reply-server path");
        }

        std::vector<uint8_t> readBytes;
        const size_t readHostOff = appendAscii(readBytes, "typed-read.example.net");
        CrackmeTriageInput read;
        read.bytes = readBytes.data(); read.size = readBytes.size();
        read.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0xB0000 + off; return true;
        };
        XrefIndex refs;
        refs.toTarget[0xB0000 + readHostOff] = { 0xA010 };
        refs.toTarget[0xC0000] = { 0xA100 };
        FinalizeXrefIndex(refs);
        read.xrefs = &refs;
        read.imports.push_back(
            { "winhttp", "WinHttpReadData", 0xC0000, true });
        CrackmeTriageApiCallInput call;
        call.dll = "winhttp"; call.name = "WinHttpReadData";
        call.callsite = 0xA100; call.callsiteValid = true;
        call.functionAddress = 0xA000; call.functionAddressValid = true;
        call.returnValueUseKnown = true;
        call.returnValueUsed = true;
        call.returnUseKind = NetworkReturnUseKind::Branched;
        call.returnUseAddress = 0xA105; call.returnUseAddressValid = true;
        call.returnUseInstruction = "test eax, eax";
        call.returnUseSummary = "checked and used by jne";
        call.resultInfluencesDecision = true;
        call.decisionAddress = 0xA107; call.decisionAddressValid = true;
        call.decisionTarget = 0xA150; call.decisionTargetValid = true;
        call.decisionInstruction = "jne 0xA150";
        call.returnUseEvidence = "bounded local status check";
        call.returnUseConfidence = 0.75f;
        read.apiCalls.push_back(std::move(call));
        read.functions.push_back({ 0xA000, "typed_read", 0x200, {} });
        CrackmeTriageReport readReport = RunCrackmeTriage(read);
        CHECK(readReport.stages[(size_t)NetworkTrailStage::Decision].correlationCount == 0);
        CHECK(readReport.trails.size() == 1 &&
              readReport.stages[(size_t)NetworkTrailStage::Decision].correlationCount ==
              readReport.trails[0].stages[(size_t)NetworkTrailStage::Decision].correlationCount);
        CHECK(readReport.returnFlows.size() == 1);
        CHECK(readReport.returnFlows.size() == 1 &&
              readReport.returnFlows[0].useKind == NetworkReturnUseKind::Branched &&
              readReport.returnFlows[0].decisionAddressValid &&
              readReport.returnFlows[0].decisionTargetValid &&
              readReport.returnFlows[0].honestyLabel.find("does not prove") != std::string::npos);
        CHECK(readReport.trails.size() == 1 &&
              readReport.trails[0].returnFlowIndices.size() == 1);
        CHECK(readReport.label != "Hosted reply-server path"); // no outbound Write stage
    }

    // Cross-helper terminal lineage takes precedence over the legacy local
    // first-use window, and its own confidence drives the rendered flow.
    {
        CrackmeTriageInput traced;
        CrackmeTriageApiCallInput call;
        call.dll = "winhttp";
        call.name = "WinHttpReadData";
        call.callsite = 0xAB100;
        call.callsiteValid = true;
        call.functionAddress = 0xAB000;
        call.functionAddressValid = true;
        call.returnValueUseKnown = false;
        call.returnLineageAnalysisAttempted = true;
        call.returnLineageComplete = true;
        CrackmeTriageReturnDecisionInput decision;
        decision.comparisonAddress = 0xAC020;
        decision.comparisonAddressValid = true;
        decision.decisionAddress = 0xAC024;
        decision.decisionAddressValid = true;
        decision.comparisonInstruction = "test ebx, ebx";
        decision.decisionInstruction = "je 0xAC080";
        decision.confidence = 0.91f;
        call.returnDecisions.push_back(std::move(decision));
        traced.apiCalls.push_back(std::move(call));
        const CrackmeTriageReport tracedReport = RunCrackmeTriage(traced);
        CHECK(tracedReport.returnFlows.size() == 1);
        if (tracedReport.returnFlows.size() == 1) {
            const NetworkReturnFlow& flow = tracedReport.returnFlows.front();
            CHECK(flow.decisions.size() == 1);
            CHECK(flow.confidence == CrackmeTriageConfidence::High);
            CHECK(flow.honestyLabel.find("bounded scalar provenance") !=
                  std::string::npos);
            CHECK(flow.honestyLabel.find("no return-register use") ==
                  std::string::npos);
        }
    }

    // Adapter-supplied lineage is bounded independently of the production
    // tracer so hostile/buggy callers cannot copy unbounded sinks or hops into
    // the immutable report.
    {
        CrackmeTriageInput bounded;
        bounded.limits.maxReturnDecisionsPerFlow = 2;
        bounded.limits.maxReturnProvenanceHops = 3;
        CrackmeTriageApiCallInput call;
        call.dll = "winhttp";
        call.name = "WinHttpReadData";
        call.returnLineageAnalysisAttempted = true;
        for (size_t decisionIndex = 0; decisionIndex < 8; ++decisionIndex) {
            CrackmeTriageReturnDecisionInput decision;
            decision.comparisonAddress = 0xB000 + decisionIndex * 0x10;
            decision.comparisonAddressValid = true;
            decision.decisionAddress = decision.comparisonAddress + 4;
            decision.decisionAddressValid = true;
            for (size_t hopIndex = 0; hopIndex < 12; ++hopIndex) {
                ValueProvenanceHop hop;
                hop.kind = hopIndex == 0 ? ValueProvenanceHopKind::Origin
                                         : ValueProvenanceHopKind::Copy;
                hop.address = decision.comparisonAddress + hopIndex;
                hop.addressValid = true;
                decision.hops.push_back(std::move(hop));
            }
            call.returnDecisions.push_back(std::move(decision));
        }
        bounded.apiCalls.push_back(std::move(call));
        const CrackmeTriageReport report = RunCrackmeTriage(bounded);
        CHECK(report.returnFlows.size() == 1);
        if (report.returnFlows.size() == 1) {
            const NetworkReturnFlow& flow = report.returnFlows.front();
            CHECK(flow.decisions.size() == 2);
            CHECK(std::all_of(flow.decisions.begin(), flow.decisions.end(),
                [](const CrackmeTriageReturnDecisionInput& decision) {
                    return decision.hops.size() == 3;
                }));
            CHECK(!flow.lineageComplete);
            CHECK(flow.lineageIncompleteReason.find("hop cap") !=
                  std::string::npos);
            CHECK(flow.lineageIncompleteReason.find("decision cap") !=
                  std::string::npos);
        }
        CHECK(report.completeness.returnLineageTruncated);
        CHECK(!report.completeness.complete);
    }

    // A cataloged reply-buffer comparison is a separate, navigable flow.  It
    // may create Decision-stage evidence, while its two successors remain
    // honestly labelled match/mismatch rather than guessed accept/reject.
    {
        std::vector<uint8_t> decisionBytes;
        const size_t host = appendAscii(
            decisionBytes, "reply-compare.example.net");
        XrefIndex refs;
        refs.toTarget[0xD0000 + host] = { 0xE010 };
        refs.toTarget[0xF0000] = { 0xE060 };
        refs.toTarget[0xF0008] = { 0xE100 };
        FinalizeXrefIndex(refs);

        CrackmeTriageInput input;
        input.bytes = decisionBytes.data();
        input.size = decisionBytes.size();
        input.offsetToVA = [](uint64_t offset, uint64_t& address) {
            address = 0xD0000 + offset;
            return true;
        };
        input.imports = {
            { "winhttp", "WinHttpSendRequest", 0xF0000, true },
            { "winhttp", "WinHttpReadData", 0xF0008, true },
        };
        input.functions.push_back(
            { 0xE000, "compare_server_reply", 0x300, {} });
        input.xrefs = &refs;

        CrackmeTriageApiCallInput read;
        read.dll = "winhttp";
        read.name = "WinHttpReadData";
        read.callsite = 0xE100;
        read.callsiteValid = true;
        read.functionAddress = 0xE000;
        read.functionAddressValid = true;
        read.functionName = "compare_server_reply";
        read.replyDecisionAnalysisAttempted = true;
        CrackmeTriageReplyDecisionInput comparison;
        comparison.kind = NetworkReplyDecisionKind::ComparisonCall;
        comparison.outputArgumentIndex = 1; // WinHttpReadData payload buffer
        comparison.outputRole = "payload buffer";
        comparison.outputExpression = "[rbp - 0x80]";
        comparison.comparisonAddress = 0xE130;
        comparison.comparisonAddressValid = true;
        comparison.comparisonInstruction = "call msvcrt!strcmp";
        comparison.comparisonSummary =
            "reply payload buffer is compared with \"MAGIC42\"";
        comparison.expectedValue = "\"MAGIC42\"";
        comparison.decisionAddress = 0xE137;
        comparison.decisionAddressValid = true;
        comparison.decisionTarget = 0xE180;
        comparison.decisionTargetValid = true;
        comparison.fallthroughAddress = 0xE139;
        comparison.fallthroughAddressValid = true;
        comparison.decisionInstruction = "jne 0xE180";
        comparison.takenPathSummary =
            "reply content differs from the compared value";
        comparison.fallthroughPathSummary =
            "reply content matches the compared value";
        comparison.matchAddress = 0xE139;
        comparison.matchAddressValid = true;
        comparison.mismatchAddress = 0xE180;
        comparison.mismatchAddressValid = true;
        comparison.evidence =
            "WinHttpReadData payload buffer reaches strcmp and jne";
        comparison.confidence = 0.92f;
        read.replyDecisions.push_back(std::move(comparison));
        input.apiCalls.push_back(std::move(read));

        const CrackmeTriageReport report = RunCrackmeTriage(input);
        CHECK(report.replyDecisionFlows.size() == 1);
        if (report.replyDecisionFlows.size() == 1) {
            const NetworkReplyDecisionFlow& flow =
                report.replyDecisionFlows.front();
            CHECK(flow.kind == NetworkReplyDecisionKind::ComparisonCall);
            CHECK(flow.comparisonAddressValid &&
                  flow.comparisonAddress == 0xE130);
            CHECK(flow.decisionAddressValid && flow.decisionAddress == 0xE137);
            CHECK(flow.matchAddressValid && flow.matchAddress == 0xE139);
            CHECK(flow.mismatchAddressValid && flow.mismatchAddress == 0xE180);
            CHECK(flow.expectedValue == "\"MAGIC42\"");
            CHECK(flow.honestyLabel.find("acceptance remain unproven") !=
                  std::string::npos);
        }
        const CrackmeTrail* trail =
            trailFor(report, "reply-compare.example.net");
        CHECK(trail != nullptr);
        if (trail) {
            CHECK(trail->replyDecisionFlowIndices.size() == 1);
            CHECK(trail->stages[(size_t)NetworkTrailStage::Decision]
                      .correlationCount != 0);
        }

        // An adapter cannot claim an arbitrary parameter as reply content: the
        // ordinal must match the exact API catalog's payload/header output.
        CrackmeTriageInput forged;
        CrackmeTriageApiCallInput forgedRead;
        forgedRead.dll = "winhttp";
        forgedRead.name = "WinHttpReadData";
        CrackmeTriageReplyDecisionInput wrongOutput;
        wrongOutput.outputArgumentIndex = 0;
        wrongOutput.comparisonAddress = 0x1234;
        wrongOutput.comparisonAddressValid = true;
        forgedRead.replyDecisions.push_back(std::move(wrongOutput));
        forged.apiCalls.push_back(std::move(forgedRead));
        CHECK(RunCrackmeTriage(forged).replyDecisionFlows.empty());
    }

    // Preserve every bounded semantic-artifact owner.  An unrelated first xref
    // must not hide a later validation owner next to the Reply API.
    {
        std::vector<uint8_t> ownerBytes;
        const size_t ownerHostOff = appendAscii(ownerBytes, "owners.example.net");
        const size_t ownerDecisionOff =
            appendAscii(ownerBytes, "server reply accepted; license valid");
        XrefIndex refs;
        refs.toTarget[0x1B000 + ownerHostOff] = { 0x1D010 };
        refs.toTarget[0x1B000 + ownerDecisionOff] = { 0x1C010, 0x1D018 };
        refs.toTarget[0x1E000] = { 0x1D020 };
        refs.toTarget[0x1E008] = { 0x1D028 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput owners;
        owners.bytes = ownerBytes.data(); owners.size = ownerBytes.size();
        owners.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x1B000 + off; return true;
        };
        owners.imports = {
            { "winhttp", "WinHttpSendRequest", 0x1E000, true },
            { "winhttp", "WinHttpReadData", 0x1E008, true },
        };
        owners.functions = {
            { 0x1C000, "unrelated_ui_message", 0x40, {} },
            { 0x1D000, "actual_reply_validation", 0x80, {} },
        };
        owners.xrefs = &refs;
        CrackmeTriageReport first = RunCrackmeTriage(owners);
        CrackmeTriageReport second = RunCrackmeTriage(owners);
        const CrackmeTrail* firstTrail = trailFor(first, "owners.example.net");
        const CrackmeTrail* secondTrail = trailFor(second, "owners.example.net");
        CHECK(firstTrail && secondTrail);
        if (firstTrail && secondTrail) {
            const size_t firstDecisions =
                firstTrail->stages[(size_t)NetworkTrailStage::Decision].correlationCount;
            CHECK(firstDecisions != 0);
            CHECK(firstDecisions ==
                  secondTrail->stages[(size_t)NetworkTrailStage::Decision].correlationCount);
        }
        bool sawBothOwners = false, attachedValidation = false;
        for (size_t i = 0; i < first.artifacts.size(); ++i) {
            const NetworkArtifact& artifact = first.artifacts[i];
            if (artifact.kind != NetworkArtifactKind::Validation ||
                artifact.value != "server reply accepted; license valid")
                continue;
            sawBothOwners = artifact.functionAddressValid &&
                            artifact.functionAddress == 0x1C000 &&
                            artifact.functionAddresses.size() == 2 &&
                            artifact.functionAddresses[0] == 0x1C000 &&
                            artifact.functionAddresses[1] == 0x1D000;
            if (firstTrail)
                attachedValidation = std::find(firstTrail->artifactIndices.begin(),
                                               firstTrail->artifactIndices.end(), i) !=
                                     firstTrail->artifactIndices.end();
        }
        CHECK(sawBothOwners);
        CHECK(attachedValidation);
        CHECK(first.label == "Hosted reply-server path");
    }

    // Endpoint result capping is relevance-ranked and deterministic even when
    // the actionable crackme server occurs after hundreds of unrelated hosts.
    {
        std::vector<uint8_t> rankedBytes;
        for (int i = 0; i < 300; ++i) {
            char host[64]{};
            std::snprintf(host, sizeof(host), "node%03d.example.net", i);
            appendAscii(rankedBytes, host);
        }
        appendAscii(rankedBytes, "https://pro.license-tmog.com/activate");
        CrackmeTriageInput ranked;
        ranked.bytes = rankedBytes.data(); ranked.size = rankedBytes.size();
        ranked.limits.maxEndpoints = 3;
        ranked.limits.maxEndpointCandidates = 400;
        XrefIndex empty; ranked.xrefs = &empty;
        CrackmeTriageReport first = RunCrackmeTriage(ranked);
        CrackmeTriageReport second = RunCrackmeTriage(ranked);
        CHECK(first.endpoints.size() == 3);
        CHECK(first.endpoints.front().host == "pro.license-tmog.com");
        CHECK(first.completeness.endpointsTruncated);
        CHECK(!first.completeness.complete);
        CHECK(first.endpoints.size() == second.endpoints.size());
        for (size_t i = 0; i < first.endpoints.size() && i < second.endpoints.size(); ++i)
            CHECK(first.endpoints[i].display == second.endpoints[i].display);
    }

    // Correlation evidence is ranked before textual crackme cues.  A generic
    // but code/API-linked host appearing after 1,200 license-shaped decoys must
    // survive both the 1,024 candidate safety cap and 256-result report cap.
    {
        std::vector<uint8_t> correlatedRankBytes;
        for (int i = 0; i < 1200; ++i) {
            char host[80]{};
            std::snprintf(host, sizeof(host),
                          "license-decoy%03d.example.net", i);
            appendAscii(correlatedRankBytes, host);
        }
        const size_t genericOff =
            appendAscii(correlatedRankBytes, "generic-server.example.net");
        XrefIndex refs;
        refs.toTarget[0x21000 + genericOff] = { 0x22010 };
        refs.toTarget[0x31000] = { 0x22020 };
        refs.toTarget[0x31008] = { 0x22028 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput correlatedRank;
        correlatedRank.bytes = correlatedRankBytes.data();
        correlatedRank.size = correlatedRankBytes.size();
        correlatedRank.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x21000 + off; return true;
        };
        correlatedRank.imports = {
            { "winhttp", "WinHttpSendRequest", 0x31000, true },
            { "winhttp", "WinHttpReadData", 0x31008, true },
        };
        correlatedRank.functions.push_back(
            { 0x22000, "generic_network_owner", 0x100, {} });
        correlatedRank.limits.maxEndpoints = 256;
        correlatedRank.limits.maxEndpointCandidates = 1024;
        correlatedRank.xrefs = &refs;
        CrackmeTriageReport ranked = RunCrackmeTriage(correlatedRank);
        CHECK(ranked.endpoints.size() == 256);
        CHECK(ranked.endpoints.front().host == "generic-server.example.net");
        CHECK(!ranked.endpoints.front().correlationIndices.empty());
        CHECK(ranked.label == "Hosted reply-server path");
        CHECK(ranked.completeness.endpointsTruncated);
    }

    // Public typed-call and non-contiguous ownership inputs have explicit
    // per-call/per-function bounds; omitted evidence is surfaced as partial.
    {
        CrackmeTriageInput boundedArguments;
        XrefIndex empty; boundedArguments.xrefs = &empty;
        CrackmeTriageApiCallInput call;
        call.dll = "winhttp"; call.name = "WinHttpConnect";
        for (size_t i = 0; i < 32; ++i)
            call.arguments.push_back({ i, "arg", "not-an-endpoint", 0, false });
        call.arguments.push_back({ 32, "server", "omitted.example.net", 0, false });
        boundedArguments.apiCalls.push_back(std::move(call));
        boundedArguments.limits.maxArgumentsPerCall = 32;
        CrackmeTriageReport argumentReport = RunCrackmeTriage(boundedArguments);
        CHECK(argumentReport.endpoints.empty());
        CHECK(argumentReport.label == "Network APIs found; host unknown");
        CHECK(argumentReport.completeness.sourcesTruncated);
        CHECK(!argumentReport.completeness.complete);

        std::vector<uint8_t> rangeBytes;
        const size_t rangeHostOff = appendAscii(rangeBytes, "range-cap.example.net");
        XrefIndex refs;
        refs.toTarget[0x7000 + rangeHostOff] = { 0x9010 };
        refs.toTarget[0xA000] = { 0x9020 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput boundedRanges;
        boundedRanges.bytes = rangeBytes.data(); boundedRanges.size = rangeBytes.size();
        boundedRanges.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x7000 + off; return true;
        };
        boundedRanges.imports.push_back(
            { "winhttp", "WinHttpConnect", 0xA000, true });
        boundedRanges.functions.push_back(
            { 0x8000, "split_owner", 0x10,
              { { 0x8000, 0x10 }, { 0x9000, 0x40 } } });
        boundedRanges.limits.maxRangesPerFunction = 1;
        boundedRanges.xrefs = &refs;
        CrackmeTriageReport rangeReport = RunCrackmeTriage(boundedRanges);
        const CrackmeTriageEndpoint* rangeHost = endpoint(rangeReport, "range-cap.example.net");
        CHECK(rangeHost && rangeHost->correlationIndices.empty());
        CHECK(rangeReport.completeness.sourcesTruncated);
        CHECK(!rangeReport.completeness.complete);
    }

    // Correlation retention is fair per endpoint and stage-prioritized.  Many
    // early Connect-only crackme-shaped decoys cannot consume the global budget
    // before a late generic endpoint's stronger Write+Reply evidence is seen.
    {
        std::vector<uint8_t> fairBytes;
        std::vector<size_t> decoyOffsets;
        for (int i = 0; i < 39; ++i) {
            char host[80]{};
            std::snprintf(host, sizeof(host),
                          "license-heavy-decoy%02d.example.net", i);
            decoyOffsets.push_back(appendAscii(fairBytes, host));
        }
        const size_t lateOff = appendAscii(fairBytes, "late-generic.example.net");
        XrefIndex refs;
        for (size_t off : decoyOffsets)
            refs.toTarget[0x40000 + off] = { 0x50010 };
        refs.toTarget[0x40000 + lateOff] = { 0x52010 };
        CrackmeTriageInput fair;
        fair.bytes = fairBytes.data(); fair.size = fairBytes.size();
        fair.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x40000 + off; return true;
        };
        for (size_t i = 0; i < 100; ++i) {
            const uint64_t iat = 0x60000 + i * 8;
            refs.toTarget[iat] = { 0x50100 + i * 4 };
            fair.imports.push_back(
                { "winhttp", "WinHttpConnect", iat, true });
        }
        refs.toTarget[0x61000] = { 0x52020 };
        refs.toTarget[0x61008] = { 0x52028 };
        fair.imports.push_back(
            { "winhttp", "WinHttpSendRequest", 0x61000, true });
        fair.imports.push_back(
            { "winhttp", "WinHttpReadData", 0x61008, true });
        fair.functions = {
            { 0x50000, "connect_heavy_decoys", 0x1000, {} },
            { 0x52000, "late_reply_owner", 0x100, {} },
        };
        FinalizeXrefIndex(refs);
        fair.xrefs = &refs;
        CrackmeTriageReport fairReport = RunCrackmeTriage(fair);
        CHECK(!fairReport.endpoints.empty());
        CHECK(!fairReport.endpoints.empty() &&
              fairReport.endpoints.front().host == "late-generic.example.net");
        const CrackmeTriageEndpoint* late =
            endpoint(fairReport, "late-generic.example.net");
        CHECK(late && (late->stages & NetworkStageBit(NetworkStage::Write)) &&
              (late->stages & NetworkStageBit(NetworkStage::Read)));
        CHECK(fairReport.label == "Hosted reply-server path");
        CHECK(fairReport.completeness.correlationsTruncated);
    }

    // Explicit typed decision/algorithm/API-status artifacts outrank earlier
    // automatic semantic noise when the report artifact budget is tiny.
    {
        std::vector<uint8_t> priorityBytes;
        for (int i = 0; i < 12; ++i)
            appendAscii(priorityBytes, "license token semantic noise");
        CrackmeTriageInput priority;
        priority.bytes = priorityBytes.data(); priority.size = priorityBytes.size();
        priority.limits.maxArtifacts = 3;
        priority.decisions.push_back({ 0, false, 0x70000, true,
                                       NetworkArtifactKind::Validation,
                                       "typed decision evidence", true });
        priority.algorithms.push_back({ 0, false, 0x70000, true,
                                        "SHA-256", "hash", "typed algorithm evidence" });
        CrackmeTriageApiCallInput typed;
        typed.dll = "winhttp"; typed.name = "WinHttpReadData";
        typed.functionAddress = 0x70000; typed.functionAddressValid = true;
        typed.resultInfluencesDecision = true;
        priority.apiCalls.push_back(std::move(typed));
        XrefIndex empty; priority.xrefs = &empty;
        CrackmeTriageReport priorityReport = RunCrackmeTriage(priority);
        CHECK(priorityReport.artifacts.size() == 3);
        bool typedDecision = false, typedAlgorithm = false, typedResult = false;
        for (const NetworkArtifact& artifact : priorityReport.artifacts) {
            typedDecision |= artifact.value == "typed decision evidence";
            typedAlgorithm |= artifact.kind == NetworkArtifactKind::Algorithm &&
                              artifact.value.find("SHA-256") != std::string::npos;
            typedResult |= artifact.value ==
                           "WinHttpReadData API status/value controls a branch";
        }
        CHECK(typedDecision && typedAlgorithm && typedResult);
        CHECK(priorityReport.completeness.sourcesTruncated);
        CHECK(!priorityReport.completeness.complete);
    }

    // Bounded adapters can explicitly report source-side truncation even when
    // the retained vectors themselves are at or below the public caps.
    {
        CrackmeTriageInput adapterPartial;
        adapterPartial.importsComplete = false;
        adapterPartial.callEdgesComplete = false;
        adapterPartial.apiCallsComplete = false;
        adapterPartial.decisionsComplete = false;
        adapterPartial.algorithmsComplete = false;
        XrefIndex empty; adapterPartial.xrefs = &empty;
        CrackmeTriageReport partial = RunCrackmeTriage(adapterPartial);
        CHECK(!partial.completeness.complete);
        CHECK(partial.completeness.apisTruncated);
        CHECK(partial.completeness.sourcesTruncated);
        CHECK(partial.completeness.reason.find("adapter") != std::string::npos);
    }

    // Per-artifact references cap at 32 while per-endpoint evidence remains 64.
    {
        std::vector<uint8_t> many;
        for (int i = 0; i < 40; ++i) appendAscii(many, "many.example.net");
        CrackmeTriageInput bounded;
        bounded.bytes = many.data(); bounded.size = many.size();
        bounded.offsetToVA = [](uint64_t off, uint64_t& out) { out = 0x3000 + off; return true; };
        XrefIndex empty; bounded.xrefs = &empty;
        CrackmeTriageReport limited = RunCrackmeTriage(bounded);
        const CrackmeTriageEndpoint* manyHost = endpoint(limited, "many.example.net");
        CHECK(manyHost && manyHost->sources.size() == 40);
        bool sawEndpointArtifact = false;
        for (const auto& artifact : limited.artifacts) {
            if (artifact.kind == NetworkArtifactKind::Endpoint &&
                artifact.value.find("many.example.net") != std::string::npos) {
                sawEndpointArtifact = true;
                CHECK(artifact.sources.size() == 32);
            }
        }
        CHECK(sawEndpointArtifact);
        CHECK(limited.completeness.sourcesTruncated);
    }

    // The 64 evidence/source bound is per endpoint, and maxEvidenceRows is per
    // endpoint trail rather than one report-global bucket.
    {
        std::vector<uint8_t> manyTwo;
        for (int i = 0; i < 70; ++i) appendAscii(manyTwo, "first-many.example.net");
        for (int i = 0; i < 70; ++i) appendAscii(manyTwo, "second-many.example.net");
        CrackmeTriageInput bounded;
        bounded.bytes = manyTwo.data(); bounded.size = manyTwo.size();
        bounded.limits.maxEvidenceRows = 1;
        XrefIndex empty; bounded.xrefs = &empty;
        CrackmeTriageReport limited = RunCrackmeTriage(bounded);
        const CrackmeTriageEndpoint* firstMany = endpoint(limited, "first-many.example.net");
        const CrackmeTriageEndpoint* secondMany = endpoint(limited, "second-many.example.net");
        CHECK(firstMany && firstMany->sources.size() == 64);
        CHECK(secondMany && secondMany->sources.size() == 64);
        const CrackmeTrail* firstTrail = trailFor(limited, "first-many.example.net");
        const CrackmeTrail* secondTrail = trailFor(limited, "second-many.example.net");
        CHECK(firstTrail && firstTrail->artifactIndices.size() == 1);
        CHECK(secondTrail && secondTrail->artifactIndices.size() == 1);
    }

    // Correlations and artifacts share one combined per-trail evidence budget.
    {
        std::vector<uint8_t> combinedBytes;
        const size_t combinedHostOff = appendAscii(combinedBytes, "combined.example.net");
        const size_t combinedEvidenceOff =
            appendAscii(combinedBytes, "server reply accepted; license valid");
        XrefIndex refs;
        refs.toTarget[0xB000 + combinedHostOff] = { 0xC010 };
        refs.toTarget[0xB000 + combinedEvidenceOff] = { 0xC018 };
        refs.toTarget[0xD000] = { 0xC020 };
        refs.toTarget[0xD008] = { 0xC028 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput combined;
        combined.bytes = combinedBytes.data(); combined.size = combinedBytes.size();
        combined.offsetToVA = [](uint64_t off, uint64_t& out) { out = 0xB000 + off; return true; };
        combined.imports = {
            { "winhttp", "WinHttpSendRequest", 0xD000, true },
            { "winhttp", "WinHttpReadData", 0xD008, true },
        };
        combined.functions.push_back({ 0xC000, "combined_rows", 0x80, {} });
        combined.limits.maxEvidenceRows = 3;
        combined.xrefs = &refs;
        CrackmeTriageReport combinedReport = RunCrackmeTriage(combined);
        const CrackmeTrail* combinedTrail = trailFor(combinedReport, "combined.example.net");
        CHECK(combinedTrail != nullptr);
        if (combinedTrail) {
            CHECK(combinedTrail->correlationIndices.size() == 2);
            CHECK(combinedTrail->artifactIndices.size() == 1);
            CHECK(combinedTrail->correlationIndices.size() +
                  combinedTrail->artifactIndices.size() == 3);
        }
        CHECK(combinedReport.completeness.sourcesTruncated);
        CHECK(!combinedReport.completeness.complete);
    }

    // Candidate planning gives endpoint and API-callsite owners priority over
    // every semantic artifact owner and exposes deterministic truncation.
    {
        CrackmeTriageReport candidateReport;
        CrackmeTriageCorrelation correlation;
        correlation.endpointFunctionAddress = 0x1000;
        correlation.endpointFunctionAddressValid = true;
        correlation.functionAddress = 0x2000;
        correlation.functionAddressValid = true;
        correlation.apiCallsite = 0x2008;
        correlation.apiCallsiteValid = true;
        candidateReport.correlations.push_back(correlation);
        std::vector<CrackmeTriageFunctionInput> candidateFunctions = {
            { 0x1000, "endpoint_owner", 0x20, {} },
            { 0x2000, "api_owner", 0x20, {} },
        };
        for (size_t i = 0; i < 300; ++i) {
            const uint64_t address = 0x3000 + i * 0x20;
            candidateFunctions.push_back({ address, "semantic", 0x10, {} });
            NetworkArtifact artifact;
            artifact.kind = NetworkArtifactKind::Validation;
            artifact.functionAddress = address;
            artifact.functionAddressValid = true;
            candidateReport.artifacts.push_back(std::move(artifact));
        }
        CrackmeTriageCandidateSelection selection =
            SelectCrackmeTriageAnnotationCandidates(candidateReport,
                                                     candidateFunctions, 2, 1000);
        CHECK(selection.truncated);
        CHECK(selection.availableFunctions == 302);
        CHECK(selection.functionAddresses.size() == 2);
        CHECK(selection.functionAddresses[0] == 0x1000);
        CHECK(selection.functionAddresses[1] == 0x2000);

        // Dynamically constructed endpoints have no literal owner/correlation.
        // The exact cataloged import callsite must still seed its containing
        // function so status-return provenance can run there.
        CrackmeTriageReport apiOnlyReport;
        CrackmeTriageApiEvidence exactRead;
        exactRead.dll = "winhttp";
        exactRead.importName = "WinHttpReadData";
        exactRead.canonicalName = "WinHttpReadData";
        exactRead.stage = NetworkStage::Read;
        exactRead.callsites.push_back(0x5018);
        apiOnlyReport.apis.push_back(std::move(exactRead));
        const std::vector<CrackmeTriageFunctionInput> apiOnlyFunctions = {
            { 0x5000, "dynamic_endpoint_reader", 0x40, {} },
            { 0x6000, "unrelated", 0x40, {} },
        };
        const CrackmeTriageCandidateSelection apiOnlySelection =
            SelectCrackmeTriageAnnotationCandidates(
                apiOnlyReport, apiOnlyFunctions, 8, 1000);
        CHECK(apiOnlySelection.availableFunctions == 1);
        CHECK(apiOnlySelection.functionAddresses.size() == 1);
        CHECK(apiOnlySelection.functionAddresses.front() == 0x5000);
    }

    // A typed reply marker without an owning function is report-level evidence.
    // It must not be sprayed across every endpoint merely because each endpoint
    // has a Read-stage correlation.
    {
        std::vector<uint8_t> unscopedBytes;
        const size_t firstOff = appendAscii(unscopedBytes, "first-unscoped.example.net");
        const size_t secondOff = appendAscii(unscopedBytes, "second-unscoped.example.net");
        XrefIndex refs;
        refs.toTarget[0xE000 + firstOff] = { 0xF010 };
        refs.toTarget[0xE000 + secondOff] = { 0xF018 };
        refs.toTarget[0x11000] = { 0xF020 };
        refs.toTarget[0x11008] = { 0xF028 };
        FinalizeXrefIndex(refs);
        CrackmeTriageInput unscoped;
        unscoped.bytes = unscopedBytes.data(); unscoped.size = unscopedBytes.size();
        unscoped.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0xE000 + off; return true;
        };
        unscoped.imports = {
            { "winhttp", "WinHttpSendRequest", 0x11000, true },
            { "winhttp", "WinHttpReadData", 0x11008, true },
        };
        unscoped.functions.push_back({ 0xF000, "shared_network_owner", 0x100, {} });
        unscoped.decisions.push_back({ 0, false, 0, false,
                                      NetworkArtifactKind::Validation,
                                      "unscoped reply accepted", true });
        unscoped.xrefs = &refs;
        CrackmeTriageReport unscopedReport = RunCrackmeTriage(unscoped);
        size_t unscopedArtifact = (std::numeric_limits<size_t>::max)();
        for (size_t i = 0; i < unscopedReport.artifacts.size(); ++i)
            if (unscopedReport.artifacts[i].value == "unscoped reply accepted")
                unscopedArtifact = i;
        CHECK(unscopedArtifact != (std::numeric_limits<size_t>::max)());
        CHECK(unscopedReport.trails.size() == 2);
        for (const CrackmeTrail& trail : unscopedReport.trails) {
            CHECK(trail.stages[(size_t)NetworkTrailStage::Reply].correlationCount != 0);
            CHECK(trail.stages[(size_t)NetworkTrailStage::Decision].correlationCount == 0);
            CHECK(std::find(trail.artifactIndices.begin(), trail.artifactIndices.end(),
                            unscopedArtifact) == trail.artifactIndices.end());
        }
    }

    // Cancellation after byte extraction remains responsive during the indexed
    // ownership/API-correlation phase and returns an explicit partial report.
    {
        std::vector<uint8_t> midBytes;
        const size_t midHostOff = appendAscii(midBytes, "midpass.example.net");
        XrefIndex refs;
        refs.toTarget[0x10000 + midHostOff] = { 0x12010 };
        CrackmeTriageInput mid;
        mid.bytes = midBytes.data(); mid.size = midBytes.size();
        mid.offsetToVA = [](uint64_t off, uint64_t& out) {
            out = 0x10000 + off; return true;
        };
        for (size_t i = 0; i < 64; ++i) {
            const uint64_t iat = 0x20000 + i * 8;
            refs.toTarget[iat] = { 0x12100 + i };
            mid.imports.push_back({ "winhttp", "WinHttpReadData", iat, true });
        }
        FinalizeXrefIndex(refs);
        mid.functions.push_back({ 0x12000, "many_api_calls", 0x1000, {} });
        mid.xrefs = &refs;
        mid.limits.cancellationCheckBytes =
            (std::numeric_limits<uint64_t>::max)();
        size_t cancellationChecks = 0;
        mid.cancelled = [&] { return ++cancellationChecks > 40; };
        CrackmeTriageReport midReport = RunCrackmeTriage(mid);
        CHECK(midReport.completeness.cancelled);
        CHECK(!midReport.completeness.complete);
        CHECK(midReport.completeness.bytesExamined == midBytes.size());
        CHECK(!midReport.endpoints.empty() && !midReport.apis.empty());
        CHECK(cancellationChecks > 40);
    }

    // Cancellation is explicit and partial.
    {
        CrackmeTriageInput stopped;
        stopped.bytes = bytes.data(); stopped.size = bytes.size();
        stopped.cancelled = [] { return true; };
        CrackmeTriageReport partial = RunCrackmeTriage(stopped);
        CHECK(partial.completeness.cancelled);
        CHECK(!partial.completeness.complete);
    }

    const char* realPath = argc > 1 ? argv[1] : std::getenv("DS_CRACKME_ACCEPTANCE_TARGET");
    if (realPath && *realPath) realTargetAcceptance(realPath);

    if (failures) return 1;
    std::puts("crackme triage tests passed");
    return 0;
}
