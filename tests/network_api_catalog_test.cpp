#include "Core/NetworkApiCatalog.h"

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

int main() {
    CHECK(NormalizeNetworkDll("C:\\Windows\\System32\\WINHTTP.DLL") == "winhttp");
    CHECK(NormalizeNetworkApiName("__imp__WinHttpConnectW@16") == "winhttpconnect");

    auto connect = LookupNetworkApi("WINHTTP.dll", "__imp__WinHttpConnectW@16");
    CHECK(connect && connect->family == NetworkApiFamily::WinHttp);
    CHECK(connect && connect->stage == NetworkStage::Connect);
    CHECK(connect && connect->canonicalName == "WinHttpConnect");

    auto send = LookupNetworkApi("ws2_32.dll", "__imp__send@16");
    CHECK(send && send->stage == NetworkStage::Write);
    CHECK(!LookupNetworkApi("user32.dll", "SendMessageW"));
    CHECK(!LookupNetworkApi("ws2_32.dll", "SendMessageW"));
    CHECK(!LookupNetworkApi("user32.dll", "send"));
    CHECK(!LookupNetworkApi("", "send"));

    for (const char* name : { "DnsQuery_A", "DnsQuery_W", "DnsQuery_UTF8" }) {
        auto dns = LookupNetworkApi("dnsapi.dll", name);
        CHECK(dns && dns->family == NetworkApiFamily::DnsApi);
        CHECK(dns && dns->stage == NetworkStage::Resolve);
        CHECK(dns && dns->canonicalName == "DnsQuery");
    }

    auto closeHttp = LookupNetworkApi("winhttp", "WinHttpCloseHandle");
    auto closeInet = LookupNetworkApi("wininet", "InternetCloseHandle");
    CHECK(closeHttp && closeHttp->lifecycle);
    CHECK(closeInet && closeInet->lifecycle);
    CHECK(!LookupNetworkApi("winhttp", "WinHttpCrackUrl"));

    // Return contracts remain exact too: a family/name resemblance must never
    // inherit expected-return semantics from a catalogued API.
    CHECK(!LookupNetworkApiReturnContract("user32", "SendMessageW"));
    CHECK(!LookupNetworkApiReturnContract("kernel32", "ConnectNamedPipe"));

    auto connectContract = LookupNetworkApiReturnContract("ws2_32", "connect");
    CHECK(connectContract);
    CHECK(connectContract && connectContract->returnKind == NetworkReturnKind::IntStatus);
    CHECK(connectContract && connectContract->successRule == NetworkReturnSuccessRule::Zero);
    CHECK(connectContract && connectContract->failureSentinel == NetworkFailureSentinel::SocketError);
    CHECK(connectContract && connectContract->asyncPendingPossible);
    CHECK(connectContract && connectContract->pendingRule ==
                               NetworkAsyncPendingRule::LastErrorNonblockingConnect);
    CHECK(connectContract && NetworkReturnIsImmediateSuccess(*connectContract, 0));
    CHECK(connectContract && !NetworkReturnIsImmediateSuccess(*connectContract, UINT64_C(0xFFFFFFFF)));
    CHECK(connectContract && InterpretNetworkApiReturn(*connectContract, UINT64_C(0xFFFFFFFF)) ==
                               NetworkReturnDisposition::Indeterminate);
    CHECK(connectContract && InterpretNetworkApiReturn(*connectContract, UINT64_C(0xFFFFFFFF), 10035) ==
                               NetworkReturnDisposition::Indeterminate);
    CHECK(connectContract && InterpretNetworkApiReturn(*connectContract, UINT64_C(0xFFFFFFFF), 10061) ==
                               NetworkReturnDisposition::Failure);
    CHECK(connectContract && InterpretNetworkApiReturn(*connectContract, UINT64_C(0xFFFFFFFF), 997) ==
                               NetworkReturnDisposition::Failure);

    auto sendContract = LookupNetworkApiReturnContract("ws2_32", "send");
    CHECK(sendContract && sendContract->returnKind == NetworkReturnKind::SignedByteCount);
    CHECK(sendContract && NetworkReturnIsImmediateSuccess(*sendContract, 0));
    CHECK(sendContract && NetworkReturnIsImmediateSuccess(*sendContract, 123));
    CHECK(sendContract && !NetworkReturnIsImmediateSuccess(*sendContract, UINT64_C(0xFFFFFFFF)));
    CHECK(sendContract && InterpretNetworkApiReturn(*sendContract, UINT64_C(0xFFFFFFFF)) ==
                            NetworkReturnDisposition::Failure);

    auto recvContract = LookupNetworkApiReturnContract("ws2_32", "recv");
    CHECK(recvContract && recvContract->zeroResultMeaning ==
                          NetworkZeroResultMeaning::EndOfStreamOrEmptyMessage);
    CHECK(recvContract && recvContract->outParameterCount == 1);
    CHECK(recvContract && recvContract->outParameters[0].argumentIndex == 1);
    CHECK(recvContract && recvContract->outParameters[0].oneBasedOrdinal() == 2);
    CHECK(recvContract && recvContract->outParameters[0].role == NetworkOutParameterRole::PayloadBuffer);

    auto socketContract = LookupNetworkApiReturnContract("ws2_32", "socket");
    CHECK(socketContract && socketContract->returnKind == NetworkReturnKind::SocketHandle);
    CHECK(socketContract && !NetworkReturnIsImmediateSuccess(*socketContract, UINT64_MAX, 64));
    CHECK(socketContract && !NetworkReturnIsImmediateSuccess(*socketContract, UINT64_C(0xFFFFFFFF), 32));
    CHECK(socketContract && NetworkReturnIsImmediateSuccess(*socketContract, UINT64_C(0xFFFFFFFF), 64));

    auto openContract = LookupNetworkApiReturnContract("winhttp", "WinHttpOpen");
    CHECK(openContract && openContract->returnKind == NetworkReturnKind::InternetHandle);
    CHECK(openContract && !NetworkReturnIsImmediateSuccess(*openContract, 0));
    CHECK(openContract && NetworkReturnIsImmediateSuccess(*openContract, 0x1234));

    auto writeContract = LookupNetworkApiReturnContract("winhttp", "WinHttpWriteData");
    CHECK(writeContract && writeContract->returnKind == NetworkReturnKind::Bool);
    CHECK(writeContract && writeContract->outParameterCount == 1);
    CHECK(writeContract && writeContract->outParameters[0].argumentIndex == 3);
    CHECK(writeContract && writeContract->outParameters[0].role == NetworkOutParameterRole::ByteCount);
    CHECK(writeContract && writeContract->outParameters[0].validity ==
                           NetworkOutParameterValidity::OnSuccessOrAsyncCompletion);
    CHECK(writeContract && InterpretNetworkApiReturn(*writeContract, 0) ==
                           NetworkReturnDisposition::Indeterminate);
    CHECK(writeContract && InterpretNetworkApiReturn(*writeContract, 0, 997) ==
                           NetworkReturnDisposition::Indeterminate);
    CHECK(writeContract && InterpretNetworkApiReturn(*writeContract, 0, 5) ==
                           NetworkReturnDisposition::Failure);
    CHECK(writeContract && InterpretNetworkApiReturn(*writeContract, 0, 10035) ==
                           NetworkReturnDisposition::Failure);
    CHECK(writeContract && InterpretNetworkApiReturn(*writeContract, 1) ==
                           NetworkReturnDisposition::Success);

    auto readContract = LookupNetworkApiReturnContract("winhttp", "WinHttpReadData");
    CHECK(readContract && readContract->zeroResultMeaning == NetworkZeroResultMeaning::EndOfBody);
    CHECK(readContract && readContract->outParameterCount == 2);
    CHECK(readContract && readContract->outParameters[1].argumentIndex == 3);
    CHECK(readContract && readContract->outParameters[1].role == NetworkOutParameterRole::ByteCount);

    auto queryContract = LookupNetworkApiReturnContract("winhttp", "WinHttpQueryHeaders");
    CHECK(queryContract && queryContract->outParameterCount == 3);
    CHECK(queryContract && queryContract->outParameters[1].role == NetworkOutParameterRole::BufferSize);
    CHECK(queryContract && queryContract->outParameters[1].validity ==
                           NetworkOutParameterValidity::OnSuccessOrRequiredSize);
    CHECK(queryContract && queryContract->outParameters[1].inOut);

    auto dnsContract = LookupNetworkApiReturnContract("dnsapi", "DnsQuery_W");
    CHECK(dnsContract && dnsContract->returnKind == NetworkReturnKind::IntStatus);
    CHECK(dnsContract && dnsContract->failureSentinel == NetworkFailureSentinel::NonZeroStatus);
    CHECK(dnsContract && dnsContract->outParameterCount == 1);
    CHECK(dnsContract && dnsContract->outParameters[0].argumentIndex == 5);
    CHECK(dnsContract && dnsContract->outParameters[0].role == NetworkOutParameterRole::DnsRecordList);

    auto gaiExContract = LookupNetworkApiReturnContract("ws2_32", "GetAddrInfoExW");
    CHECK(gaiExContract && InterpretNetworkApiReturn(*gaiExContract, 997) ==
                           NetworkReturnDisposition::Indeterminate);
    CHECK(gaiExContract && InterpretNetworkApiReturn(*gaiExContract, 11001) ==
                           NetworkReturnDisposition::Failure);
    CHECK(gaiExContract && InterpretNetworkApiReturn(*gaiExContract, 10035) ==
                           NetworkReturnDisposition::Failure);

    auto closeContract = LookupNetworkApiReturnContract("wininet", "InternetCloseHandle");
    CHECK(closeContract && closeContract->closesResourceOnSuccess);

    auto urlContract = LookupNetworkApiReturnContract("urlmon", "URLDownloadToFileW");
    CHECK(urlContract && urlContract->returnKind == NetworkReturnKind::HResult);
    CHECK(urlContract && NetworkReturnIsImmediateSuccess(*urlContract, 0));       // S_OK
    CHECK(urlContract && NetworkReturnIsImmediateSuccess(*urlContract, 1));       // S_FALSE/SUCCEEDED
    CHECK(urlContract && !NetworkReturnIsImmediateSuccess(*urlContract, 0x80004005)); // E_FAIL

    const std::pair<const char*, const char*> requiredLiveRows[] = {
        {"ws2_32", "getaddrinfo"}, {"ws2_32", "GetAddrInfoW"},
        {"ws2_32", "GetAddrInfoExA"}, {"ws2_32", "GetAddrInfoExW"},
        {"ws2_32", "gethostbyname"}, {"ws2_32", "getnameinfo"},
        {"ws2_32", "GetNameInfoW"}, {"ws2_32", "closesocket"},
        {"dnsapi", "DnsQuery_A"}, {"dnsapi", "DnsQuery_W"},
        {"dnsapi", "DnsQuery_UTF8"},
        {"winhttp", "WinHttpOpen"}, {"winhttp", "WinHttpAddRequestHeaders"},
        {"wininet", "InternetOpenA"}, {"wininet", "InternetOpenW"},
        {"wininet", "HttpAddRequestHeadersA"}, {"wininet", "HttpSendRequestExW"},
        {"wininet", "HttpEndRequestA"}, {"wininet", "InternetReadFileExW"},
        {"urlmon", "URLDownloadToCacheFileW"}, {"urlmon", "URLOpenStreamA"},
        {"urlmon", "URLOpenPullStreamW"}, {"urlmon", "URLOpenBlockingStreamW"},
    };
    for (const auto& [module, symbol] : requiredLiveRows)
        CHECK(LookupNetworkApi(module, symbol).has_value());

    const std::vector<NetworkApiMatch> catalog = EnumerateNetworkApis();
    CHECK(catalog.size() >= 60);
    for (const NetworkApiMatch& row : catalog) {
        auto roundTrip = LookupNetworkApi(row.dll, row.canonicalName);
        CHECK(roundTrip && roundTrip->normalizedName == row.normalizedName &&
              roundTrip->family == row.family && roundTrip->stage == row.stage &&
              roundTrip->lifecycle == row.lifecycle);
        auto contract = LookupNetworkApiReturnContract(row.dll, row.canonicalName);
        CHECK(contract.has_value());
        CHECK(contract && !contract->returnType.empty());
        CHECK(contract && !contract->successMeaning.empty());
        CHECK(contract && !contract->failureMeaning.empty());
        CHECK(contract && contract->outParameterCount <= kMaxNetworkContractOutParameters);
        CHECK(contract && std::string(NetworkZeroResultMeaningText(contract->zeroResultMeaning)) != "unknown");
        CHECK(contract && std::string(NetworkAsyncPendingRuleText(contract->pendingRule)) != "unknown");
        CHECK(contract && contract->asyncPendingPossible ==
                           (contract->pendingRule != NetworkAsyncPendingRule::None));
        if (contract) {
            CHECK(std::string(NetworkReturnKindText(contract->returnKind)) != "unknown");
            CHECK(std::string(NetworkReturnSuccessRuleText(contract->successRule)) != "unknown");
            CHECK(std::string(NetworkFailureSentinelText(contract->failureSentinel)) != "unknown");
            for (uint8_t i = 0; i < contract->outParameterCount; ++i) {
                CHECK(contract->outParameters[i].oneBasedOrdinal() != 0);
                CHECK(!contract->outParameters[i].meaning.empty());
                CHECK(std::string(NetworkOutParameterRoleText(contract->outParameters[i].role)) != "unknown");
                CHECK(std::string(NetworkOutParameterValidityText(contract->outParameters[i].validity)) != "unknown");
            }
        }
    }

    CHECK(std::string(NetworkReturnDispositionText(NetworkReturnDisposition::Success)) == "success");

    if (failures) return 1;
    std::puts("network API catalog tests passed");
    return 0;
}
